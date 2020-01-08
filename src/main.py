#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Bugfix<tanjelly@gmail.com
Created: 2019-12-11
Modified: 2019-12-30
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
from elasticsearch.exceptions import ConnectionError, ConflictError, ConnectionTimeout
from cacheout import Cache
from plugins import Plugin

debug = False
logger= None
# Search params
lastTime = None
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

class LogLevel:
    """日志级别"""
    ERROR = 1
    WARN = 2
    INFO = 3
    NOTICE = 4
    DEBUG = 5

def get_datetime(time_str):
    try:
        return datetime.strptime(time_str, '%Y-%m-%dT%H:%M:%S.%fZ')
    except:
        return None

def output(msg, level=LogLevel.INFO):
    """
    输出信息
    """
    global debug, logger
    if logger:
        if level == LogLevel.DEBUG:
            logger.debug(str(msg))
        elif level == LogLevel.WARN:
            logger.warn(str(msg))
        elif level == LogLevel.ERROR:
            logger.error(str(msg))
        else:
            logger.info(str(msg))
    else:
        if level == LogLevel.ERROR:
            print('[-][{}] {}'.format(datetime.now().strftime('%H:%M:%S.%f'), str(msg)))
        elif level == LogLevel.DEBUG:
            if debug:
                print('[D][{}] {}'.format(datetime.now().strftime('%H:%M:%S.%f'), str(msg)))
        else:
            print('[!][{}] {}'.format(datetime.now().strftime('%H:%M:%S.%f'), str(msg)))

def index_template(es, name):
    """
    上传索引模板
    :param es: ES 对象
    :param name: 模板名称
    """
    body = {
        "index_patterns": "logstash-*",
        "settings": { "index.refresh_interval": "5s", "number_of_shards": 1 },
        "mappings": {
            "dynamic_templates": [
                {
                    "string_fields": {
                        "match": "*",
                        "match_mapping_type": "string", 
                        "mapping": {
                            "type": "text",
                            "norms": False,
                            "fields": {
                                "keyword": { "type": "keyword", "ignore_above": 256 }
                            }
                        }
                    }
                }
            ],
            "properties": {
                "@timestamp": { "type": "date"},
                "@version": {"type": "keyword"},
                "geoip": {
                    "dynamic": True,
                    "properties": {
                        "ip": {"type": "ip"},
                        "location": {"type": "geo_point"},
                        "country_name": {"type": "keyword"},
                        "city_name": {"type": "keyword"}
                    }
                },
                "ip": { "type": "ip"},
                "ip_num": { "type": "long"},
                "inner": {"type": "boolean"},
                "host": {"type": "keyword"},
                "port": {"type": "integer"},
                "id": {"type": "keyword"},
                "apps": {
                    "dynamic": True,
                    "properties": {
                        "name": {"type": "keyword"},
                        "confidence": {"type": "integer"},
                        "version": {"type": "text"},
                        "categories": {
                            "dynamic": True,
                            "properties": {
                                "id": {"type": "integer"},
                                "name": {"type": "keyword"}
                            }
                        }
                    }
                },
                "url": {"type": "keyword"},
                "url_tpl": {"type": "keyword"},
                "path": {"type": "keyword"},
                "site": {"type": "keyword"}
            }
        }
    }

    try:
        output(body, LogLevel.INFO)
        ret = es.indices.put_template(name=name, body=body, create=False)
        output(ret, LogLevel.DEBUG)
    except ConnectionError:
        output("ES connect error.", LogLevel.ERROR)
        quit(1)
    except Exception as e:
        output(e, LogLevel.ERROR)

def set_scroll(es, scroll_id, last_time):
    """
    将Scroll和最后一次查询时间记录到ES上，方便不同实例间共享
    :param scroll_id: Scroll ID
    :param last_time: 已处理最后一条数据的时间戳
    """
    body = {
        'scroll_id': scroll_id,
        'last_time': last_time
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
            scrollId = lastTime = None
            if 'scroll_id' in ret['_source']: scrollId = ret['_source']['scroll_id']
            if 'last_time' in ret['_source']: lastTime = ret['_source']['last_time']
            return (scrollId, lastTime)
    except:
        traceback.print_exc()
        return (None, None)

def search_by_time(es, index, time_range=15, size=10):
    """
    从 ES 上搜索符合条件的数据
    :param es: ES 连接对象
    :param index: ES 索引名
    :return: 搜索结果列表
    """
    global scrollId, lastTime, threadLock

    # 有 Scroll 的先走 Scroll
    if scrollId:
        try:
            ret = es.scroll(scroll='5m', scroll_id=scrollId, body={ "scroll_id": scrollId })
            if '_scroll_id' in ret and ret['_scroll_id'] != scrollId:
                print('Update scroll id')
                scrollId = ret['_scroll_id']

            count = len(ret['hits']['hits'])
            if count > 0:
                try:
                    ctime = get_datetime(ret['hits']['hits'][-1]['_source']['@timestamp'])
                    if ctime:
                        ctime -= timedelta(microseconds=1000)
                        # 更新查询截至时间
                        lastTime = ctime.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                except:
                    pass
            else:
                print('Scroll result is null.')
                if ret['_shards']['failed'] > 0:
                    error_info = json.dumps(ret['_shards']['failures'])
                    if 'search_context_missing_exception' in error_info:
                        scrollId = None
                        raise Exception('Scroll id missing.')

            return ret['hits']['hits']
        except Exception as e:
            output(e, LogLevel.ERROR)
            try:
                es.clear_scroll(scroll_id=scrollId, body={ "scroll_id": scrollId })
            except:
                pass

    # 默认查询最近x分钟的数据
    if not lastTime:
        lastTime = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - time_range * 60))
    
    query = {
        "size": size,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gt": lastTime}}} # 查询某个时间点之后的数据，默认为当前时间前15分钟
                ],
                "must_not": [
                    {"exists": {"field": "state"}} # 只处理没有处理状态字段的数据
                ]
            }
        },
        "sort": {
            "@timestamp": { "order": "asc" }
        }
    }
    
    try:
        output('Start new search context...', LogLevel.DEBUG)
        #output(query, LogLevel.DEBUG)
        ret = es.search(index=index, body=query, scroll='5m')
        if len(ret['hits']['hits']) > 0:
            ctime = None
            try:
                ctime = datetime.strptime(ret['hits']['hits'][-1]['_source']['@timestamp'],'%Y-%m-%dT%H:%M:%S.%fZ') - timedelta(microseconds=1000)
            except:
                pass

            if ctime:
                # 更新查询截至时间
                lastTime = ctime.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        
        if '_scroll_id' in ret:
            print('[Search]New scroll id: {}'.format(ret['_scroll_id']))
            scrollId = ret['_scroll_id']
        
        set_scroll(es, scrollId, lastTime)

        output('Search {} documents.'.format(len(ret['hits']['hits'])), LogLevel.DEBUG)
        return ret['hits']['hits']
    except ConnectionError:
        output("ES connect error.", LogLevel.ERROR)
        time.sleep(2)
    except Exception as e:
        output(e, LogLevel.ERROR)

    return []

def batch_update(es, docs, max_retry=3):
    """
    批量文档操作
    :param es: ES 对象
    :param docs: 批量操作的数据对象
    :param max_retry: 重试次数
    """
    ret = []
    #ctime = time.time()
    try:
        output(docs, LogLevel.DEBUG)
        resp = bulk(es, docs)
        output(resp, LogLevel.DEBUG)
    except BulkIndexError as e:
        for _ in e.errors:
            if 'update' in _ and '_id' in _['update']:
                ret.append(_['update']['_id'])

        output(e.args[0], LogLevel.ERROR)
    except ConnectionTimeout as ce:
        # 重试三次
        if max_retry > 0:
            time.sleep(0.1)
            return batch_update(es, docs, max_retry - 1)
        else:
            output(ce, LogLevel.ERROR)
    except:
        traceback.print_exc()

    #output('Batch update time: {}'.format(time.time() - ctime), LogLevel.DEBUG)
    return ret

def filter_thread(threadId, options):
    """
    数据清洗线程
    :param threadId: 线程序号
    :param options: 程序参数
    """
    global cacheIds, cache, threadExit, threadLock, processCount

    # 加载插件列表
    plugins = Plugin.loadPlugins(options.rootdir, options.debug)
    print('Thread {}: Plugins loaded.'.format(threadId))

    if len(plugins) == 0: return

    es = Elasticsearch(hosts=options.hosts)
    while True:
        if threadExit: break

        try:
            threadLock.acquire()
            data = search_by_time(es, options.index + '*', time_range=options.range, size=options.batch_size)
            threadLock.release()

            if not data:
                print('[!] Thread {}: No new msg, waiting 2 seconds ...'.format(threadId))
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
                    'doc': { 'state': 1 }
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
                
                #print('[!] Thread {}: id={}'.format(threadId, item['_id']))
                msg = item['_source']
                # 通过 Cache 降低插件的处理频率
                cache_key = '{}:{}'.format(msg['ip'], msg['port'])
                if msg['pro'] == 'HTTP' or msg['pro'] == 'HTTPS':
                    cache_key = msg['url']

                cacheMsg = cache.get(cache_key)
                if cacheMsg:
                    #output('[!] Thread {}: Use cached result, key={}'.format(threadId, cache_key), LogLevel.DEBUG)
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
                    output('[!] Thread {}: Plugin {} processing ...'.format(threadId, pluginName), LogLevel.DEBUG)

                    try:
                        ret = plugin.execute(msg)
                        if ret:
                            msg_update = dict(msg_update, **ret)
                            msg = dict(msg, **ret)
                    except:
                        output(traceback.format_exc(), LogLevel.ERROR)
                    
                    output('[!] Thread {}: Plugin {} completed.'.format(threadId, pluginName), LogLevel.DEBUG)
                
                # 更新数据
                msg_update['state'] = MsgState.COMPLETED
                #threadLock.acquire()
                cache.set(cache_key, msg_update)
                #threadLock.release()

                actions.append({
                    '_type': item['_type'],
                    '_op_type': 'update', 
                    '_index': item['_index'],
                    '_id': item['_id'],
                    'doc': msg_update
                })

            # 提交到 ES
            if len(actions) > 0:
                output('[!] Thread {}: Batch update {} document.'.format(threadId, len(actions)), LogLevel.INFO)
                output('[!] Thread {}: {}'.format(threadId, json.dumps(actions)), LogLevel.DEBUG)
                batch_update(es, actions)
                actions = []

        except:
            traceback.print_exc()


def main(options):
    """
    主函数
    :param options: 命令行传入参数对象
    """
    global cacheIds, cache, threadLock, debug, processCount, threadExit, startTime, scrollId, lastTime
    
    debug = options.debug
    cacheIds = Cache(maxsize=512, ttl=60, timer=time.time, default=None)
    cache = Cache(maxsize=options.cache_size, ttl=600, timer=time.time, default=None)

    threadLock = threading.RLock()
    threadList = [None for i in range(options.threads)]

    es = Elasticsearch(hosts=options.hosts)
    # 更新索引模板
    index_template(es, 'passets')
    # 获取搜索位置信息
    (scrollId, lastTime) = get_scroll(es)
    if lastTime:
        tmpTime = datetime.utcnow() - timedelta(minutes=options.range)
        tmpLastTime = get_datetime(lastTime)
        if not tmpLastTime or tmpLastTime < tmpTime:
            lastTime = tmpTime.strftime('%Y-%m-%dT%H:%M:%S.%fZ')

        print('Last Time Position: {}'.format(lastTime))
    
    startTime = time.time()
    
    try:
        for i in range(options.threads):
            threadList[i] = threading.Thread(target=filter_thread, args=(i, options))
            threadList[i].setDaemon(True)
            threadList[i].start()
            time.sleep(1)

        while True:
            time.sleep(5)    
    except KeyboardInterrupt:
        print('[!] Ctrl+C, exiting ...')
        threadLock.acquire()
        threadExit = True
        threadLock.release()

    for i in range(options.threads):
        if threadList[i] and threadList[i].isAlive():
            print('Thread {} waiting to exit...'.format(i))
            threadList[i].join()
    
    # 存储最后一次的搜索信息
    set_scroll(es, scrollId, lastTime)
    
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
    parser.add_option('-H', '--hosts', action='store', dest='hosts', type='string', default='10.87.222.222:9200', help='Elasticsearch server address:port list, like localhost:9200,...')
    parser.add_option('-i', '--index', action='store', dest='index', type='string', default='logstash-passets', help='Elasticsearch index name')
    parser.add_option('-r', '--range', action='store', dest='range', type='int', default=60, help='Elasticsearch search time range, unit is minute')
    parser.add_option('-t', '--threads', action='store', dest='threads', type='int', default=1, help='Number of concurrent threads')
    parser.add_option('-s', '--batch-size', action='store', dest='batch_size', type='int', default=20, help='The data item number of each batch per thread')
    parser.add_option('-c', '--cache-size', action='store', dest='cache_size', type='int', default=1024, help='Process cache size')
    parser.add_option('-d', '--debug', action='store', dest='debug', type='int', default=0, help='Print debug info')

    options, args = parser.parse_args()
    options.rootdir = os.path.split(os.path.abspath(sys.argv[0]))[0]
    if not options.hosts:
        parser.error('Please specify elasticsearch address by entering the -H/--host parameter.')
    
    if options.threads < 1 or options.threads > 50:
        parser.error('Please specify valid thread count, the valid range is 1-50. Default is 10.')

    if options.batch_size < 5 or options.batch_size > 200:
        parser.error('Please specify valid thread count, the valid range is 5-200. Default is 20.')

    if options.cache_size < 1 or options.cache_size > 65535:
        parser.error('Please specify valid thread count, the valid range is 1-65535. Default is 1024.')

    if options.range <= 0 or options.range > 24 * 60:
        parser.error('Please specify valid time, format is [number]，like: 15, max is 10080(7 days).')

    options.hosts = options.hosts.split(',')
    for i in range(len(options.hosts)):
        if not options.hosts[i]:
            del(options.hosts[i])

    if not options.hosts:
        parser.error('Please specify elasticsearch address by entering the -H/--host parameter.')
    
    return options

if __name__ == '__main__':
    options = usage()
    print('[!] Home: {}'.format(options.rootdir))

    main(options)
