#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Bugfix<tanjelly@gmail.com
Created: 2019-12-11
MOdified: 2019-12-11
'''

import base64
import sys
import os
import json
import traceback
import re
import time
import html
import optparse
import threading
import copy

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, ConflictError
from cacheout import Cache
from plugins import Plugin

threadLock = None
threadExit = False
debug = False
cache = None
pluginInstances = []

class MsgState:
    """消息状态"""
    # 处理中
    PROGRESSING = 0
    # 已完成
    COMPLETED = 1

def output(msg, level='INFO'):
    """
    输出信息
    """
    global debug
    if level == 'ERROR':
        print('[-] ' + str(msg))
    elif level == 'DEBUG':
        if debug: print('[D] ' + str(msg))
    else:
        print('[!] ' + str(msg))

def search(es, index, last_time='15m', size=10):
    """
    从 ES 上搜索符合条件的数据
    :param es: ES 连接对象
    :param index: ES 索引名
    :param last_time: 查询时间范围，实例：15m 表示最近15分钟
    :return: 搜索结果列表
    """
    query = {
        'size': size,
        'query': {
            'bool': {
                # 查询最近7天没有指纹的数据
                'must': [
                    {'range': {'@timestamp': {'gte': 'now-{}'.format(last_time)}}}
                ],
                # 没有处理状态字段
                'must_not': [
                    {'exists': {'field': 'state'}}
                ]
            }
        },
        "sort": {
            "@timestamp": {
                "order": "desc"
            }
        }
    }
    try:
        ret = es.search(index=index, body=query)
        output(ret, 'DEBUG')
        return ret['hits']['hits']
    except ConnectionError:
        output("ES connect error.", 'ERROR')
        sys.exit(1)
    except Exception as e:
        output(e, 'ERROR')

    return []

def update(es, index, id, info):
    """
    更新指定的 ES 数据
    :param es: ES 连接对象
    :param id: 数据 ID
    :param info: 要更新的数据项字典
    :return: True | False
    """
    output('Update {}. Data: {}'.format(id, str(info)), 'DEBUG')
    try:
        ret = es.update(index=index, id=id, body={"doc": info})
        output(ret, 'DEBUG')
        if ret and 'result' in ret and ret['result'] == 'updated':
            return True
    except ConnectionError:
        output("ES connect error.", 'ERROR')
        sys.exit(1)
    except ConflictError:
        output("ES doc update conflict.", 'ERROR')
    except Exception as e:
        output(e, 'ERROR')
    return False

def updateState(es, index, id, state):
    """
    更新指定的 ES 数据
    :param es: ES 连接对象
    :param id: 数据 ID
    :param state: 目标数据状态
    :return: True | False
    """
    query = {
        'size': 10,
        'query': {
            'bool': {
                'must': {
                    'term':{ '_id': id }
                },
                'must_not': [
                    {'exists': {'field': 'state'}}
                ]
            }
        },
        'script': {
            'inline': 'ctx._source.state = params.state',
            'params':  {
                'state': state
            },
            'lang': 'painless'
        }
    }
    try:
        output(query, 'DEBUG')
        ret = es.update_by_query(index=index, body=query)
        output(ret, 'DEBUG')
        if ret and 'updated' in ret and ret['updated'] > 0:
            return True
    except ConnectionError:
        output("ES connect error.", 'ERROR')
        sys.exit(1)
    except ConflictError:
        output("ES doc update conflict.", 'ERROR')
    except Exception as e:
        output(e, 'ERROR')
    return False

def filter(pos, options, msg_id, host_flag, msg, plugins):
    """
    数据处理线程
    :param options: 命令行参数对象
    :param msg_id: 消息ID
    :param host_flag: 应用缓存标识
    :param msg: 要过滤的数据
    :param plugins: 过滤插件列表
    """
    global cache, threadLock

    output('Starting thread {} ...'.format(pos), 'DEBUG')

    msg_update = {}
    es = Elasticsearch(hosts=options.hosts)

    # 先将数据更新为正在处理状态，避免被其它节点重复处理
    # state: 0-处理中， 1-已完成，若无此参数表示尚未处理
    ret = updateState(es, options.index, msg_id, MsgState.PROGRESSING)
    if not ret:
        output('Processed by other instance, _id={}, exit.'.format(msg_id))
        return
    
    # 按插件顺序对数据进行处理（插件顺序在配置文件中定义）
    for i in sorted(plugins.keys()):
        (pluginName, plugin) = plugins[i]
        output('Plugin {} processing ...'.format(pluginName), 'DEBUG')

        try:
            ret = plugin.execute(msg)
            if ret:
                msg_update = dict(msg_update, **ret)
                msg = dict(msg, **ret)
        except:
            output(traceback.format_exc(), 'ERROR')
        
        output('Plugin {} completed.'.format(pluginName), 'DEBUG')
    
    # 更新数据
    msg_update['state'] = MsgState.COMPLETED

    ret = update(es, options.index, msg_id, msg_update)
    if ret:
        # 插入缓存
        try:
            threadLock.acquire()
            cache.set(host_flag, msg_update)
        except Exception as e:
            output(str(e), 'ERROR')
            output(traceback.format_exc(), 'ERROR')
        finally:
            threadLock.release()
    else:
        output('Failed to update {}.'.format(msg_id), 'ERROR')

    output('Thread {} exited.'.format(pos), 'DEBUG')

def main(options):
    """
    主函数
    :param options: 命令行传入参数对象
    """
    global es, cache, threadLock, debug
    
    debug = options.debug
    es = Elasticsearch(hosts=options.hosts)
    cache = Cache(maxsize=options.cache_size, ttl=600, timer=time.time, default=None)

    startTime = time.time()
    threadLock = threading.RLock()
    threadList = [None for i in range(options.threads)]

    # 每个线程生成独立的插件实例
    pluginInstances = []
    for i in range(options.threads):
        pluginInstances.append(Plugin.loadPlugins(options.rootdir, options.debug))

    if (len(pluginInstances[0]) == 0):
        print('No plugin loaded, exit.')
        exit(1)
    
    print('[!] Loaded Plugins:')
    for i in pluginInstances[0]:
        print('[!] - {}'.format(pluginInstances[0][i][0]))
    
    processCount = 0
    data = []
    while True:
        try:
            if not data:
                data = search(es, options.index, last_time='2m', size=options.threads * 2)
                if not data:
                    print('[!] No new msg, waiting 10 seconds ...')
                    time.sleep(10)
                    continue

            for i in range(options.threads):
                if threadList[i] and threadList[i].isAlive(): continue
                if not data: break

                processCount += 1
                item = data.pop()
                msg_id = item['_id']
                msg = item['_source']

                if 'ip' not in msg or 'port' not in msg or 'pro' not in msg:
                    continue

                # 通过 Cache 降低插件的处理频率
                host_flag = '{}:{}'.format(msg['ip'], msg['port'])
                if msg['pro'] == 'HTTP':
                    host_flag = msg['url']

                cacheMsg = cache.get(host_flag)
                if cacheMsg:
                    update(es, options.index, msg_id, cacheMsg)
                    output('Use cached result, key={}'.format(host_flag), 'DEBUG')
                    continue

                # 使用单独的插件调用插件
                threadList[i] = threading.Thread(target=filter, args=(i, options, msg_id, host_flag, msg, pluginInstances[i]))
                threadList[i].setDaemon(True)
                threadList[i].start()
                
            time.sleep(0.2)
        except KeyboardInterrupt:
            print('[!] Ctrl+C, Exiting ...')
            break

    for i in range(options.threads):
        if threadList[i] and threadList[i].isAlive():
            print('Thread {} waiting to exit...'.format(i))
            threadList[i].join()
    
    eclipseTime = time.time() - startTime
    print('Total: {} second, {} document.'.format(eclipseTime, processCount))
    print('Exited.')

def usage():
    """
    获取命令行参数
    """
    parser = optparse.OptionParser(usage="python3 %prog [OPTIONS] ARG", version='%prog 1.0.1')
    parser.add_option('-H', '--hosts', action='store', dest='hosts', type='string', help='Elasticsearch server address:port list, like localhost:9200,...')
    parser.add_option('-i', '--index', action='store', dest='index', type='string', default='passets', help='Elasticsearch index name')
    parser.add_option('-t', '--threads', action='store', dest='threads', type='int', default=10, help='Number of concurrent threads')
    parser.add_option('-c', '--cache-size', action='store', dest='cache_size', type='int', default=1024, help='Process cache size')
    parser.add_option('-d', '--debug', action='store', dest='debug', type='int', default=0, help='Print debug info')

    options, args = parser.parse_args()
    options.rootdir = os.path.split(os.path.abspath(sys.argv[0]))[0]
    options.hosts = options.hosts.split(',')
    for i in range(len(options.hosts)):
        if not options.hosts[i]:
            del(options.hosts[i])
    
    if not options.hosts:
        parser.error('Please specify elasticsearch address by entering the -H/--host parameter.')
    
    if options.threads < 1 or options.threads > 500:
        parser.error('Please specify valid thread count, the valid range is 1-500. Default is 10.')

    if options.cache_size < 1 or options.cache_size > 65535:
        parser.error('Please specify valid thread count, the valid range is 1-65535. Default is 1024.')

    return options

if __name__ == '__main__':
    options = usage()
    print('[!] Home: {}'.format(options.rootdir))

    main(options)
