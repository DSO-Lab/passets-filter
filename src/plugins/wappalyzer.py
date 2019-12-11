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

from plugin import Plugin

class FilterPlugin(Plugin):
    """
    Web 指纹识别插件
    """
    
    def __init__(self, rootdir, debug = False):
        """
        构造函数
        :param rootdir: 应用根目录
        :param debug: 调式开关
        """
        super().__init__(rootdir, debug)

        # 初始化指纹相关路径
        self._nodejs = 'node'
        self._wappalyzer = os.path.join(rootdir, 'wappalyzer', 'cli.js')
        self._rules = os.path.join(rootdir, 'rules', 'apps.json')
    
    def analyze(self, url, header, body):
        """
        分析获取指纹
        :param url: 请求URL
        :param header: 响应头
        :param body: 响应正文
        """
        if not body:
            body = 'NULL'
        if not header:
            header = ''
        
        header_encoded = base64.b64encode(bytes(header, 'utf-8', 'ignore')).decode('utf-8', 'ignore')
        body_encoded = base64.b64encode(bytes(body, 'utf-8', 'ignore')).decode('utf-8', 'ignore')
        url_encoded = self.cmd_encode(url)

        cmd = '{} --no-warnings "{}" "{}" "{}" {} '.format(self._nodejs, self._wappalyzer, self._rules, url_encoded, header_encoded)
        remain_len = self.remain_cmd_len(cmd)
        if remain_len > 0:
            cmd += body_encoded[:self.remain_cmd_len(cmd)]
        else:
            cmd += '""'
        #print(cmd)
        self.log('CMD: ' + cmd)

        try:
            fd = os.popen(cmd)
            data = fd.read()

            try:
                result = json.loads(data)
                self.log(result)
                if 'applications' in result:
                    for i in range(len(result['applications'])):
                        if 'product' in result['applications'][i]:
                            if result['applications'][i]['product']:
                                result['applications'][i]['name'] = result['applications'][i]['product']
                            del(result['applications'][i]['product'])
                    return result['applications']
            except:
                self.log(traceback.format_exc(), level='ERROR')
            
            fd.close()
        except Exception as e:
            self.log(str(e), "ERROR")
            pass
        
        return []

    def generate_header(self, msg):
        """
        根据消息生成一个HTTP头信息
        :param msg: 原始消息 JSON
        :return: 生成的原始响应头
        """
        header = ''
        if 'server' in msg and msg['server']:
            header += '\r\nServer: {}'.format(msg['server'])
        if 'type' in msg and msg['type']:
            header += '\r\nContent-Type: {}'.format(msg['type'])
        
        if header:
            header = 'HTTP/1.1 {}{}'.format(
                '0' if 'code' not in msg or not msg['code'] else msg['code'],
                header
            )
        return header

    def execute(self, msg):
        """
        插件入口函数，根据插件的功能对 msg 进行处理
        :param msg: 需要处理的消息
        :return: 返回需要更新的消息字典（不含原始消息）
        """
        if 'pro' not in msg or msg['pro'] != 'HTTP':
            self.log('Not http message.')
            return

        info = {}
        # 更新HTTP头
        if 'header' not in msg or not msg['header']:
            new_header = self.generate_header(msg)
            if new_header:
                msg['header'] = new_header
                info['header'] = new_header
            else:
                msg['header'] = 'HTTP/1.1 000 Unkown'
        
        if 'body' not in msg or not msg['body']:
            msg['body'] = ''

        # 指纹识别
        apps = self.analyze(msg['url'], msg['header'], msg['body'])
        info['apps'] = apps

        # 标题提取
        if 'type' in msg and msg['type'].find('text/html') != -1:
            m = re.search(r'<title>([^<]*?)</title>', msg['body'], re.I)
            if m:
                info['title'] = html.unescape(m.group(1))

        return info

if __name__ == '__main__':
    import time

    plugins = Plugin.loadPlugins(os.path.join(os.path.dirname(__file__), ".."), True)
    print(plugins)
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
        "pro": "HTTP",
        "@timestamp": "2019-12-06T01:51:25.024Z",
        "body": "<html><head><title>登录</title></head></html>",
        "code": 200,
        "url": "http://111.206.63.16/",
        "tag": "sensor-ens160"
    }
    msg_update = {}
    for pluginName in sorted(plugins.keys()):
        if pluginName == 'wappalyzer':
            ctime = time.time()
            ret = plugins[pluginName].execute(msg)
            etime = time.time()
            print('Eclipse time: {}'.format(etime-ctime))
            print(ret)
