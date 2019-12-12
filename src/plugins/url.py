#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Bugfix<tanjelly@gmail.com
Created: 2019-12-11
MOdified: 2019-12-11
'''

import os
import sys
import re
import html
import json
import base64
import traceback

from urllib import parse
from plugin import Plugin

class FilterPlugin(Plugin):
    """
    URL 处理插件
    """
    
    def execute(self, msg):
        """
        插件入口函数，根据插件的功能对 msg 进行处理
        :param msg: 需要处理的消息
        :return: 返回需要更新的消息字典（不含原始消息）
        """
        if 'pro' not in msg or msg['pro'] != 'HTTP':
            self.log('Not http message.', 'DEBUG')
            return None

        if 'url' not in msg and not isinstance(msg['url'], str):
            self.log('url not found or not a string.')
            return None
        
        info = {
            'site': '',
            'path': '',
            'url_tpl': ''
        }
        try:
            url_parts = parse.urlsplit(msg['url'])
            
            if not url_parts.scheme:
                url_parts.scheme = 'http'
            if url_parts.netloc:
                info['site'] = '{}://{}'.format(url_parts.scheme, url_parts.netloc)
            path = '/' if not url_parts.path else url_parts.path
            path_tpl = path
            if url_parts.query:
                path += '?' + url_parts.query
                path_tpl += '?'
                params = parse.parse_qs(url_parts.query)
                for _ in sorted(params):
                    path_tpl += '&{}={{}}'.format(_)
                path_tpl = path_tpl.rstrip('&')
            if url_parts.fragment:
                path += '#' + url_parts.fragment
                path_tpl += '#{}'
            info['path'] = path
            info['url_tpl'] = info['site'] + path_tpl
        except:
            self.log(traceback.format_exc(), 'ERROR')

        return info

if __name__ == '__main__':
    plugins = Plugin.loadPlugins(os.path.join(os.path.dirname(__file__), ".."), True)
    msg = {
        "ip_num": 1875787536,
        "ip": "111.206.63.16",
        "host": "111.206.63.16:80",
        "header": "HTTP/1.1 200 OK\r\nServer: nginx\r\nDate: Fri, 06 Dec 2019 01:51:24 GMT\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nCache-Control: no-cache\r\npragma: no-cache",
        "@version": "1",
        "inner": False,
        "port": "80",
        "tags": [],
        "type": "text/html",
        "server": "nginx",
        "pro": "TCP",
        "@timestamp": "2019-12-06T01:51:25.024Z",
        "body": "<html><head><title>登录</title></head></html>",
        "code": 200,
        "url": "http://111.206.63.16/hello.jsp?zone=public&service=80&protocol=tcp#main",
        "tag": "sensor-ens160"
    }
    msg_update = {}
    for i in sorted(plugins.keys()):
        (pluginName, plugin) = plugins[i]
        if pluginName == 'url':
            print('[!] Plugin {} processing ...'.format(pluginName))
            ret = plugin.execute(msg)
            print(ret)
            if ret:
                msg_update = dict(msg_update, **ret)

                msg = dict(msg, **ret)
            print('[!] Plugin {} completed.'.format(pluginName))
        
    print(msg_update)