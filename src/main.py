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
from cacheout import Cache
from plugins import Plugin

threadLock = None
threadExit = False
es = None

class MsgState:
    """消息状态"""
    # 处理中
    PROGRESSING = 0
    # 已完成
    COMPLETED = 1

def search(es, index, query, debug=False):
    """
    从 ES 上搜索符合条件的数据
    :param es: ES 连接对象
    :param index: ES 索引名
    :param query: 查询条件字典
    :return: 搜索结果列表
    """
    try:
        ret = es.search(index=index, body=query)
        #if debug: print('[!] ' + str(ret))
        return ret['hits']['hits']
    except Exception as e:
        if debug: print('[-] Error: ' + str(e))

    return []

def update(es, index, id, info, debug=False):
    """
    更新指定的 ES 数据
    :param es: ES 连接对象
    :param id: 数据 ID
    :param info: 要更新的数据项字典
    :return: True | False
    """
    try:
        ret = es.update(index=index, id=id, body={"doc": info})
        if debug: print('[!] ' + str(ret))
        if ret and 'result' in ret and ret['result'] == 'updated':
            return True
    except Exception as e:
        if debug: print('[-] Error: ' + str(e))
    return False

def filter(index, data, plugins, cache, debug=False):
    """
    数据处理线程
    :param index: ES 索引名
    :param data: 数据列表
    :param plugins: 过滤插件列表
    :param cache: 缓存对象
    :param debug: 调试开关
    """
    global es, threadExit, threadLock

    for _ in data:
        # 检测退出
        if threadExit: break

        msg = _['_source']

        if 'host' not in msg or 'pro' not in msg:
            continue

        msg_flag = msg['host']
        if msg['pro'] == 'HTTP':
            msg_flag = msg['url']

        # 检查缓存，缓存里面有的不重复处理
        threadLock.acquire()
        cacheMsg = cache.get(msg_flag)
        threadLock.release()
        if cacheMsg:
            print(cacheMsg)
            threadLock.acquire()
            ret = update(es, index, _['_id'], cacheMsg, debug)
            threadLock.release()
            if options.debug: print('[-] Use cached result.')
            continue
        
        # 先将数据更新为正在处理状态，避免被其它节点重复处理
        threadLock.acquire()
        ret = update(es, index, _['_id'], {'state': MsgState.PROGRESSING}, debug)
        threadLock.release()

        if not ret:
            if options.debug: print('[-] Failed to update progress.')
            continue
        
        msg_update = {}
        # 按插件顺序对数据进行处理（插件顺序在配置文件中定义）
        for i in sorted(plugins.keys()):
            (pluginName, plugin) = plugins[i]
            if options.debug: print('[!] Plugin {} processing ...'.format(pluginName))

            try:
                ret = plugin.execute(msg)
                if options.debug: print('[!] DATA: ' + str(ret))

                if ret:
                    msg_update = dict(msg_update, **ret)
                    msg = dict(msg, **ret)
            except:
                if options.debug: print('[-] ERROR:\n' + traceback.format_exc())
            
            if options.debug: print('[!] Plugin {} completed.'.format(pluginName))
        
        # 更新数据
        msg_update['state'] = MsgState.COMPLETED

        threadLock.acquire()
        cache.set(msg_flag, msg_update)
        ret = update(es, index, _['_id'], msg_update, debug)
        threadLock.release()

        if not ret:
            if options.debug: print('[+] Failed to update {}.'.format(_['_id']))

def main(options):
    """
    主函数
    :param options: 命令行传入参数对象
    """
    global es, threadLock, threadExit
    
    es = Elasticsearch(hosts=[{'host': options.host, 'port': options.port}])
    plugins = Plugin.loadPlugins(options.rootdir, options.debug)
    cache = Cache(maxsize=options.cache_size, ttl=300, timer=time.time, default=None)
    if (len(plugins) == 0):
        print('No plugin loaded, exit.')
        exit()
    
    #query = {'query': {'match_all': {}}}
    # 查询最近7天没有指纹的数据
    # state: 0-处理中， 1-已完成，无参数表示尚未处理
    query = {
        'size': 10,
        'query': {
            'bool': {
                'must': [
                    {'range': {'@timestamp': {'gte': 'now-15m'}}}
                ],
                'must_not': [
                    {'exists': {'field': 'state'}}
                ]
            }
        }
    }
    
    threadLock = threading.Lock()
    threadList = [None for i in range(options.threads)]
    while True:
        try:
            for i in range(options.threads):
                if threadList[i] and threadList[i].isAlive():
                    continue

                threadLock.acquire()
                data = search(es, options.index, query, options.debug)
                threadLock.release()

                if not data:
                    if options.debug: print('[!] No new msg, waiting 5 seconds ...')
                    break

                if options.debug: print('[!] Starting thread {} ...'.format(i))
                threadList[i] = threading.Thread(target=filter, args=(options.index, data, copy.deepcopy(plugins), cache, options.debug))
                threadList[i].setDaemon(True)
                threadList[i].start()
            
            time.sleep(5)
        except KeyboardInterrupt:
            if options.debug: print('[!] Find Ctrl+C, exiting ...')
            threadLock.acquire()
            threadExit = True
            threadLock.release()
            break

    for i in range(options.threads):
        if threadList[i] and threadList[i].isAlive():
            threadList[i].join()

    print('Exited.')

def usage():
    """
    获取命令行参数
    """
    parser = optparse.OptionParser(usage="python3 %prog [OPTIONS] ARG", version='%prog 1.0.1')
    parser.add_option('-H', '--host', action='store', dest='host', type='string', help='Elasticsearch server address/address:port')
    parser.add_option('-i', '--index', action='store', dest='index', type='string', default='passets', help='Elasticsearch index name')
    parser.add_option('-t', '--threads', action='store', dest='threads', type='int', default=10, help='Number of concurrent threads')
    parser.add_option('-c', '--cache-size', action='store', dest='cache_size', type='int', default=1024, help='Process cache size')
    parser.add_option('-d', '--debug', action='store', dest='debug', type='int', default=0, help='Print debug info')

    options, args = parser.parse_args()
    options.rootdir = os.path.split(os.path.abspath(sys.argv[0]))[0]
    
    if not options.host:
        parser.error('Please specify elasticsearch address by entering the -H/--host parameter.')
  
    if options.threads < 1 or options.threads > 500:
        parser.error('Please specify valid thread count, the valid range is 1-500. Default is 10.')

    if options.cache_size < 1 or options.cache_size > 65535:
        parser.error('Please specify valid thread count, the valid range is 1-65535. Default is 1024.')

    options.port = 9200
    m = re.match(r'^([^:]*?):(\d{1,5})$', options.host)
    if m:
        options.host = m.group(1)
        options.port = int(m.group(2))
    
    return options

if __name__ == '__main__':
    options = usage()
    print('[!] Home: {}'.format(options.rootdir))

    main(options)
