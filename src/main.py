#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Bugfix<tanjelly@gmail.com
Created: 2019-12-11
Modified: 2020-01-19
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
import logging

from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from elasticsearch.helpers import BulkIndexError
from elasticsearch.exceptions import ConnectionError, ConflictError, ConnectionTimeout, NotFoundError, TransportError
from cacheout import Cache
from plugins import Plugin, LogLevel

debug = False
logger= None
es = None
# Search params
scrollId = None
# Cache
cacheIds = None
cache = None
# Thread
threadLock = None
threadExit = False
# Result
processCount = 0
startTime = time.time()

class MsgState:
    """消息状态"""
    # 处理中
    PROGRESSING = 0
    # 已完成
    COMPLETED = 1

def get_datetime(time_str):
    """
    时间字符串转时间对象
    :param time_str: 时间字符串
    """
    try:
        return datetime.strptime(time_str, '%Y-%m-%dT%H:%M:%S.%fZ')
    except:
        return None

def output(msg, level=LogLevel.INFO):
    """
    输出信息
    :param msg: 消息内容
    :param level: 消息级别
    """
    global debug, logger

    if level > debug: return

    if logger:
        if level == LogLevel.ERROR:
            logger.error(str(msg))
        elif level == LogLevel.WARN:
            logger.warn(str(msg))
        elif level == LogLevel.INFO:
            logger.info(str(msg))
        else:
            logger.debug(str(msg))
    else:
        timeStr = datetime.now().strftime('%H:%M:%S.%f')
        if level == LogLevel.ERROR:
            print('[E][{}] {}'.format(timeStr, str(msg)))
        elif level == LogLevel.WARN:
            print('[W][{}] {}'.format(timeStr, str(msg)))
        elif level == LogLevel.INFO:
            print('[I][{}] {}'.format(timeStr, str(msg)))
        else:
            print('[D][{}] {}'.format(timeStr, str(msg)))

def index_template(es):
    """
    上传索引模板
    :param es: ES 对象
    """
    body = {
        "index_patterns": ".passets-filter",
        "settings": { "refresh_interval": "5s", "number_of_shards": 1, "auto_expand_replicas": "0-1" },
        "mappings": {
            "properties": {
                "scroll_id": { "type": "text"}
            }
        }
    }

    try:
        ret = es.indices.put_template(name="passets-config", body=body, create=False)
        output(ret, LogLevel.DEBUG)
    except ConnectionError:
        output("ES connect error.", LogLevel.ERROR)
        quit(1)
    except:
        output(traceback.format_exc(), LogLevel.ERROR)

def set_scroll(es, scroll_id):
    """
    将Scroll和最后一次查询时间记录到ES上，方便不同实例间共享
    :param scroll_id: Scroll ID
    """
    body = {
        'scroll_id': scroll_id
    }
    try:
        es.index(index='.passets-filter', id='SearchPosition', body=body, refresh=True)
    except:
        traceback.print_exc()

def get_scroll(es):
    """
    从ES上获取数据搜索的相关参数
    """
    try:
        ret = es.get(index='.passets-filter', id="SearchPosition", _source=True)
        if 'found' in ret and ret['found']:
            if 'scroll_id' in ret['_source']:
                return ret['_source']['scroll_id']
    except:
        traceback.print_exc()
    return None

def search_by_time(es, index, time_range=15, size=10, mode=0):
    """
    从 ES 上搜索符合条件的数据
    :param es: ES 连接对象
    :param index: ES 索引名
    :param time_range: 默认时间节点（当前时间往前分钟数）
    :param size: 搜索分页大小
    :param mode: 实例工作模式
    :return: 搜索结果列表
    """
    global scrollId, threadLock, processCount

    # 有 Scroll 的先走 Scroll
    scroll_reloaded = False
    if scrollId:
        try:
            ret = es.scroll(scroll='3m', scroll_id=scrollId, body={ "scroll_id": scrollId })
            # 处理几种常见错误
            if ret['_shards']['failed'] > 0:
                error_info = json.dumps(ret['_shards']['failures'])
                if 'search_context_missing_exception' in error_info:    # Scroll 失效
                    if mode:
                        es.clear_scroll(scroll_id=scrollId)
                        raise NotFoundError('Search scroll context missing.')
                elif 'search.max_open_scroll_context' in error_info:    # Scroll 太多，清除后重新生成
                    if mode:
                        es.clear_scroll(scroll_id='_all')
                        raise NotFoundError('Search scroll context peaked, cleaning ...')
                elif 'null_pointer_exception' in error_info:
                    # https://github.com/elastic/elasticsearch/issues/35860
                    raise NotFoundError('Trigger a elasticsearch scroll null pointer exception.')
                else:
                    output(error_info, LogLevel.INFO)
                    return []
            else:
                if len(ret['hits']['hits']) > 0:
                    return ret['hits']['hits']
                else:
                    # 没有数据的情况下等待2秒
                    time.sleep(2)
            
            if mode:
                es.clear_scroll(scroll_id=scrollId)
                scroll_reloaded = True
            
            raise Exception('Scroll result is empty.')

        except NotFoundError:
            scroll_reloaded = True
        except Exception as e:
            output(e, LogLevel.WARN)
            #output(traceback.format_exc(), LogLevel.DEBUG)
    else:
        if mode: scroll_reloaded = True

    # 从节点不主动创建 Scroll，只从 ES 上获取
    if not mode:
        time.sleep(2)
        output('Fetch new scroll...', LogLevel.DEBUG)
        scrollId = get_scroll(es)
        return []

    # 意外导致的无结果直接返回
    if not scroll_reloaded: return []

    # 默认查询最近x分钟的数据
    lastTime = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() - time_range * 60))
    
    query = {
        "size": size,
        "query": {
            "bool": {
                # "must": [
                #     {"range": {"@timestamp": {"gte": lastTime}}} # 查询某个时间点之后的数据，默认为当前时间前15分钟
                # ],
                "must_not": [
                    {"exists": {"field": "state"}} # 只处理没有处理状态字段的数据
                ]
            }
        },
        "sort": {
            "@timestamp": { "order": "desc" }
        }
    }
    
    try:
        output('Start new search context...', LogLevel.DEBUG)
        output(query, LogLevel.DEBUG)
        ret = es.search(index=index, body=query, scroll='3m')
        if '_scroll_id' in ret:
            output('Use new scroll id', LogLevel.DEBUG)
            scrollId = ret['_scroll_id']
        
            # 保存 scroll_id 供其它实例使用
            set_scroll(es, scrollId)

        output('Search {} documents.'.format(len(ret['hits']['hits'])), LogLevel.DEBUG)
        return ret['hits']['hits']
    except ConnectionError:
        output("ES connect error.", LogLevel.ERROR)
        time.sleep(2)
    except Exception as e:
        output(e, LogLevel.ERROR)
        traceback.print_exc()

    return []

def batch_update(es, docs, max_retry=3):
    """
    批量文档操作
    :param es: ES 对象
    :param docs: 批量操作的数据对象
    :param max_retry: 重试次数
    """
    ret = []
    try:
        output(docs, LogLevel.DEBUG)
        resp = bulk(es, docs)
        output(resp, LogLevel.DEBUG)
    except BulkIndexError as e:
        for _ in e.errors:
            if 'update' in _ and '_id' in _['update']:
                ret.append(_['update']['_id'])

        output(e.args[0], LogLevel.DEBUG)
    except ConnectionTimeout as ce:
        # 重试三次
        if max_retry > 0:
            time.sleep(0.1)
            return batch_update(es, docs, max_retry - 1)
        else:
            output(ce, LogLevel.ERROR)
    except:
        output(traceback.print_exc(), LogLevel.INFO)

    return ret

def filter_thread(threadId, options):
    """
    数据清洗线程
    :param threadId: 线程序号
    :param options: 程序参数
    """
    global es, cacheIds, cache, threadExit, threadLock, processCount

    # 加载插件列表
    plugins = Plugin.loadPlugins(options.rootdir, options.debug)
    output('Thread {}: Plugins loaded.'.format(threadId), LogLevel.INFO)

    if len(plugins) == 0: return

    #es = Elasticsearch(hosts=options.hosts)
    while True:
        if threadExit: break

        try:
            threadLock.acquire()
            data = search_by_time(es, options.index + '*', time_range=options.range, size=options.batch_size, mode=options.mode)
            threadLock.release()

            if not data:
                output('Thread {}: No new msg, waiting 2s ...'.format(threadId), LogLevel.INFO)
                time.sleep(2)
                if threadExit: break
                continue

            # 更新ES文档中的内容为正在处理状态
            actions = []
            for i in range(len(data)-1, -1, -1):
                # 处理过的ID缓存下来，避免在多个线程间重复处理数据
                existed = cacheIds.get(data[i]['_id'])
                if existed:
                    del(data[i])
                    continue

                cacheIds.set(data[i]['_id'], True)

                if 'ip' not in data[i]['_source'] or 'port' not in data[i]['_source'] or 'pro' not in data[i]['_source']:
                    del(data[i])
                    continue

                actions.append({
                    '_op_type': 'update', 
                    '_index': data[i]['_index'],
                    '_type': data[i]['_type'],
                    '_id': data[i]['_id'],
                    'doc': { 'state': MsgState.PROGRESSING }
                })
            
            if len(actions) == 0:
                time.sleep(1)
                if threadExit: break
                continue

            conflict_list = batch_update(es, actions)
            threadLock.acquire()
            processCount += len(data)
            threadLock.release()
            
            actions = []
            while True:
                if not data: break
                item = data.pop()
                # 冲突或已处理的直接跳过
                if item['_id'] in conflict_list: continue
                
                msg = item['_source']
                # 通过 Cache 降低插件的处理频率
                cache_key = '{}:{}'.format(msg['ip'], msg['port'])
                if msg['pro'] == 'HTTP' or msg['pro'] == 'HTTPS':
                    cache_key = msg['url']

                cacheMsg = cache.get(cache_key)
                if cacheMsg:
                    output('Thread {}: Use cached result, key={}'.format(threadId, cache_key), LogLevel.DEBUG)
                    actions.append({
                        '_type': item['_type'],
                        '_op_type': 'update', 
                        '_index': item['_index'],
                        '_id': item['_id'],
                        'doc': cacheMsg
                    })
                    continue

                msg_update = {}
                # 按插件顺序对数据进行处理（插件顺序在配置文件中定义）
                for i in sorted(plugins.keys()):
                    (pluginName, plugin) = plugins[i]
                    output('Thread {}: Plugin {} processing ...'.format(threadId, pluginName), LogLevel.DEBUG)

                    try:
                        ret = plugin.execute(msg)
                        if ret:
                            msg_update = dict(msg_update, **ret)
                            msg = dict(msg, **ret)
                    except:
                        output(traceback.format_exc(), LogLevel.ERROR)
                    
                    output('Thread {}: Plugin {} completed.'.format(threadId, pluginName), LogLevel.DEBUG)
                
                # 更新数据
                msg_update['state'] = MsgState.COMPLETED
                cache.set(cache_key, msg_update)

                actions.append({
                    '_type': item['_type'],
                    '_op_type': 'update', 
                    '_index': item['_index'],
                    '_id': item['_id'],
                    'doc': msg_update
                })

            # 提交到 ES
            if len(actions) > 0:
                output('Thread {}: Batch update {} document.'.format(threadId, len(actions)), LogLevel.DEBUG)
                output('Thread {}: {}'.format(threadId, json.dumps(actions)), LogLevel.DEBUG)
                batch_update(es, actions)
                actions = []

        except:
            output(traceback.format_exc(), LogLevel.ERROR)


def main(options):
    """
    主函数
    :param options: 命令行传入参数对象
    """
    global es, cacheIds, cache, threadLock, debug, processCount, threadExit, startTime, scrollId
    
    debug = options.debug
    cacheIds = Cache(maxsize=512, ttl=60, timer=time.time, default=None)
    cache = Cache(maxsize=options.cache_size, ttl=options.cache_ttl, timer=time.time, default=None)

    threadLock = threading.RLock()
    threadList = [None for i in range(options.threads)]

    es = Elasticsearch(hosts=options.hosts)
    # 更新索引模板
    index_template(es)
    # 获取搜索位置信息
    scrollId = get_scroll(es)

    try:
        for i in range(options.threads):
            threadList[i] = threading.Thread(target=filter_thread, args=(i, options))
            threadList[i].setDaemon(True)
            threadList[i].start()
            time.sleep(1)

        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print('Ctrl+C, exiting ...')
        threadLock.acquire()
        threadExit = True
        threadLock.release()

    for i in range(options.threads):
        if threadList[i] and threadList[i].isAlive():
            print('Thread {} waiting to exit...'.format(i))
            threadList[i].join()
    
    quit(0)

def quit(status):
    """
    退出程序
    :param status: 退出状态
    """
    global startTime, processCount

    eclipseTime = time.time() - startTime
    print('Total: {} second, {} document.'.format(eclipseTime, processCount))
    print('Exited.')
    exit(status)

def usage():
    """
    获取命令行参数
    """
    parser = optparse.OptionParser(usage="python3 %prog [OPTIONS] ARG", version='%prog 1.0.1')
    parser.add_option('-H', '--hosts', action='store', dest='hosts', type='string', help='Elasticsearch server address:port list, like localhost:9200,...')
    parser.add_option('-i', '--index', action='store', dest='index', type='string', default='logstash-passets', help='Elasticsearch index name')
    parser.add_option('-r', '--range', action='store', dest='range', type='int', default=15, help='Elasticsearch search time range, unit is minute, default is 15 minutes.')
    parser.add_option('-t', '--threads', action='store', dest='threads', type='int', default=10, help='Number of concurrent threads, default is 10')
    parser.add_option('-b', '--batch-size', action='store', dest='batch_size', type='int', default=20, help='The data item number of each batch per thread, default is 20.')
    parser.add_option('-c', '--cache-size', action='store', dest='cache_size', type='int', default=1024, help='Process cache size, default is 1024.')
    parser.add_option('-T', '--cache-ttl', action='store', dest='cache_ttl', type='int', default=600, help='Process cache time to live(TTL), default is 600 seconds.')
    parser.add_option('-m', '--mode', action='store', dest='mode', type='int', default=1, help='Work mode: 1-master, 0-slave, default is 1.')
    parser.add_option('-d', '--debug', action='store', dest='debug', type='int', default=2, help='Print debug info, 1-error, 2-warning, 3-info, 4-debug, default is 2.')

    options, args = parser.parse_args()
    options.rootdir = os.path.split(os.path.abspath(sys.argv[0]))[0]
    if not options.hosts:
        parser.error('Please specify elasticsearch address by entering the -H/--host parameter.')
    
    if options.threads < 1 or options.threads > 50:
        parser.error('Please specify valid thread count, the valid range is 1-50. Default is 10.')

    if options.batch_size < 5 or options.batch_size > 200:
        parser.error('Please specify valid thread count, the valid range is 5-200. Default is 20.')

    if options.cache_size < 1 or options.cache_size > 4096:
        parser.error('Please specify valid thread count, the valid range is 1-4096. Default is 1024.')

    if options.cache_ttl < 60 or options.cache_ttl > 24 * 60 * 60:
        parser.error('Please specify valid thread count, the valid range is 1 minutes to 1 days. Default is 600(5 minutes).')

    if options.range <= 0 or options.range > 24 * 60:
        parser.error('Please specify valid time, format is [number]，like: 15, max is 10080(7 days).')

    if options.mode not in [0, 1]:
        parser.error('Please specify valid mode: 1-master, 0-slave.')

    if options.debug < 0: options.debug = 2

    options.hosts = options.hosts.split(',')
    for i in range(len(options.hosts)):
        if not options.hosts[i]:
            del(options.hosts[i])

    if not options.hosts:
        parser.error('Please specify elasticsearch address by entering the -H/--host parameter.')
    
    return options

if __name__ == '__main__':
    options = usage()
    print('Home: {}'.format(options.rootdir))

    main(options)
