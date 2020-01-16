#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Bugfix<tanjelly@gmail.com
Created: 2019-12-11
Modified: 2019-12-30
'''

import os
import sys
import re
import html
import json
import base64
import traceback
import logging

from plugin import Plugin

class Wappalyzer():
    _rules = None
    _apps = {}
    _categories = {}
    _logger = None
    _statusRegex = re.compile(r'^HTTP/\d\.\d (\d{3}) ')
    _titleRegex = re.compile(r'<title\s*>(.*?)</title>', re.I)
    _scriptRegex = re.compile(r'<script[^>]+?src=[\'"]([^\'"]+)[\'"]', re.I)
    _linkRegex = re.compile(r'<(?:a|iframe|link)[^>]+?(?:href|src)=[\'"]*?([^\'"]+)[\'"]*?', re.I)
    _metaRegex1 = re.compile(r'<meta\s+(?:name|http-equiv)=[\'"]([^\'"]+)[\'"]\s+content=[\'"]([^>]*?)[\'"]', re.I)
    _metaRegex2 = re.compile(r'<meta\s+content=[\'"]([^>]*?)[\'"]\s+(?:name|http-equiv)=[\'"]([^\'"]+)[\'"]', re.I)
    
    def __init__(self, rule_file, wapp_path=None, logger=None):
        """
        构造函数
        :param rule_file: wappalyzer 规则库文件路径
        :param wapp_path: 修改版 wappalyzer 程序路径(非必填)
        :param logger: 日志处理对象
        """
        self._logger = logger
        self._wapp_path = wapp_path
        self._rule_file = rule_file

        if not os.path.exists(rule_file):
            raise Exception('Wappalyzer rule file not found.')

        if not self.loadRules(rule_file):
            raise Exception('Wappalyzer rules load failed.')

    def log(self, msg, level='INFO'):
        if self._logger:
            if level == 'ERROR':
                self._logger.debug(str(msg))
            elif level == 'DEBUG':
                self._logger.error(str(msg))
            else:
                self._logger.info(str(msg))
        else:
            if level == 'ERROR':
                print('[-]' + str(msg))
            elif level == 'DEBUG':
                print('[^]' + str(msg))
            else:
                print('[!]' + str(msg))

    def unchunk_body(self, body):
        """
        还原被 Chunked 响应正文
        :param body: 被 Chunked 的 HTTP 响应正文
        :return: 恢复的原始响应正文
        """
        data = ""
        pos = body.find('\r\n')
        while pos > 0:
            try:
                size = int(body[:pos], 16)
                if size > 0:
                    data = body[pos+2:pos+2+size]
                    body = body[pos+2+size+2:]
                else:
                    body = body[pos+2+size+2:]
                    break
            except:
                break

            pos = body.find('\r\n')
        
        data += body
        return data

    def unzip(self, body):
        pass

    def analyze(self, url, raw_headers, body):
        """
        根据URL、HTTP响应头、正文分析应用指纹
        :param url: URL
        :param raw_headers: 原始HTTP头
        :param body: 原始页面内容
        :return: 指纹列表 [{name,version,confidence,product},...]
        """
        matchList = []

        #status = self.parseStatus(raw_headers)
        headers = self.parseHeaders(raw_headers)
        if 'transfer-encoding' in headers and 'chunked' in headers['transfer-encoding']:
            body = self.unchunk_body(body)
        # if 'content-encoding' in headers and 'gzip' in headers['content-encoding']:
        #     body = self.unzip(body)
        
        cookies = self.parseCookies(headers)
        scripts = self.parseScripts(body)
        metas = self.parseMetas(body)
        #js = self.parseJs(body)

        matchList += self.analyzeUrl(url)
        matchList += self.analyzeHeaders(headers)
        matchList += self.analyzeCookies(cookies)
        matchList += self.analyzeScripts(scripts)
        matchList += self.analyzeMetas(metas)
        #matchList += self.analyzeJs(js)
        matchList += self.analyzeHtml(body)

        result = {}
        for _ in matchList:
            if _['name'] not in result:
                result[_['name']] = _
                continue

            if not result[_['name']]['version'] and _['version']:
                result[_['name']]['version'] = _['version']

            if not result[_['name']]['product'] and _['product']:
                result[_['name']]['product'] = _['product']
            
            if result[_['name']]['confidence'] < 100:
                result[_['name']]['confidence'] = result[_['name']]['confidence'] + _['confidence']
                if result[_['name']]['confidence'] > 100:
                    result[_['name']]['confidence'] = 100
        
        confidenceRegex = re.compile(r'^confidence:([\d\.]+)$')
        # 填充关联指纹和分类
        appNames = list(result.keys())
        while len(appNames) > 0:
            appName = appNames.pop()
            # 合并产品属性到应用属性中
            if 'product' in result[appName]:
                if result[appName]['product']:
                    result[appName]['name'] += result[appName]['product']
            
                del(result[appName]['product'])
            
            result[appName]['categories'] = self.analyzeCategory(self._apps[appName]['cats'])

            if not self._apps[appName]['implies']: continue
            
            for parentName in self._apps[appName]['implies']:
                confidence = 0
                pos = parentName.find(r'\;')
                if pos > 0:
                    rightName = parentName[pos+2:]
                    parentName = parentName[:pos]
                    m = confidenceRegex.match(rightName)
                    if m:
                        tmp_c = float(m.group(1))
                        if tmp_c > 1:
                            confidence = abs(int(tmp_c))
                        else:
                            confidence = abs(int(tmp_c * 100))
                
                if parentName in self._apps and parentName not in result:
                    result[parentName] = {
                        'name': parentName,
                        'confidence': 100 if confidence > 100 else confidence,
                        'version': None,
                        'categories': self.analyzeCategory(self._apps[parentName]['cats'])
                    }
                    appNames.append(parentName)

        return list(result.values())

    def analyzeCategory(self, cat_ids):
        """
        根据分类ID列表提取指纹分类列表
        :param cat_ids: 分类ID列表
        """
        categories = []
        for cat_id in cat_ids:
            cat_id = str(cat_id)
            if cat_id in self._categories:
                categories.append({
                    'id': int(cat_id),
                    'name': self._categories[cat_id]['name']
                })
        
        return categories

    def analyzeHtml(self, body):
        """
        分析页面中的指纹信息
        :param body: 页面源码
        :return: 指纹列表
        """
        if not body: return []

        result = []
        for _ in self._rules['html']:
            match = _['regex'].search(body)
            if match:
                result.append(self.makeDetected(match, _))
        
        return result

    def analyzeJs(self, js):
        """
        分析页面加载的JS变量中的指纹信息
        :param js: js 变量字典
        :return: 指纹列表
        """
        if not js: return []

        result = []
        for _ in self._rules['js']:
            if _['keyword'] not in js: continue

            if not _['regex']:
                result.append({
                    "name": _['name'],
                    "confidence": _['confidence'],
                    "version": _['version'],
                    "product": _['product']
                })
            else:
                match = _['regex'].search(js[_['keyword']])
                if match:
                    result.append(self.makeDetected(match, _))
        
        return result

    def analyzeMetas(self, metas):
        """
        分析页面中元数据标签中的指纹信息
        :param cookies: Cookie 字典
        :return: 指纹列表
        """
        if not metas: return []

        result = []
        for _ in self._rules['meta']:
            if _['keyword'] not in metas: continue

            if not _['regex']:
                result.append({
                    "name": _['name'],
                    "confidence": _['confidence'],
                    "version": _['version'],
                    "product": _['product']
                })
            else:
                for item in metas[_['keyword']]:
                    match = _['regex'].search(item)
                    if match:
                        result.append(self.makeDetected(match, _))
        
        return result

    def analyzeScripts(self, scripts):
        """
        分析引用脚本路径中的指纹信息
        :param scripts: scripts 列表
        :return: 指纹列表
        """
        if not scripts: return []

        result = []
        for _ in self._rules['script']:
            for item in scripts:
                match = _['regex'].search(item)
                if match:
                    result.append(self.makeDetected(match, _))
        
        return result

    def analyzeCookies(self, cookies):
        """
        分析URL指纹信息
        :param cookies: Cookie 字典
        :return: 指纹列表
        """
        if not cookies: return []

        result = []
        for _ in self._rules['cookies']:
            if _['keyword'] not in cookies: continue

            if not _['regex']:
                result.append({
                    "name": _['name'],
                    "confidence": _['confidence'],
                    "version": _['version'],
                    "product": _['product']
                })
            else:
                match = _['regex'].search(cookies[_['keyword']])
                if match:
                    result.append(self.makeDetected(match, _))
        
        return result

    def analyzeHeaders(self, headers):
        """
        分析URL指纹信息
        :param headers: HTTP头
        :return: 指纹列表
        """
        if not headers: return []

        result = []
        for _ in self._rules['headers']:
            if _['keyword'] not in headers: continue

            if not _['regex']:
                result.append({
                    "name": _['name'],
                    "confidence": _['confidence'],
                    "version": _['version'],
                    "product": _['product']
                })
            else:
                for headValue in headers[_['keyword']]:
                    match = _['regex'].search(headValue)
                    if match:
                        result.append(self.makeDetected(match, _))
                        break
        
        return result

    def analyzeUrl(self, url):
        """
        分析URL指纹信息
        :param url: URL
        :return: 指纹列表
        """
        if not url: return []

        result = []
        for _ in self._rules['url']:
            match = _['regex'].search(url)
            if match:
                result.append(self.makeDetected(match, _))
        return result

    def makeDetected(self, match, rule):
        """
        根据匹配结果生成一条应用信息
        :param match: 正则匹配结果
        :param rule: 匹配规则
        :return: {name,confidence,version,product}
        """
        result = { "name": rule['name'], "confidence": rule['confidence'], "version": rule['version'], "product": None }

        if match.lastindex:
            for k in ['version', 'product']:
                if rule[k]:
                    for i in range(1, match.lastindex + 1):
                        result[k] = result[k].replace(r'\{}'.format(i), match.group(i))
        
        for k in ['version', 'product']:
            if rule[k]:
                patterns = re.findall(r'\\\d', rule[k])
                for _ in patterns:
                    result[k] = result[k].replace(_, '')

        return result
        
    def loadRules(self, rule_file):
        """
        根据文件名载入 Wappalyzer 规则库
        :param rule_file: 规则文件名
        :return: True-成功， False-失败
        """
        fp = None
        try:
            fp = open(rule_file, encoding='utf-8')
            rules = json.loads(fp.read())
            if not rules or 'apps' not in rules or 'categories' not in rules:
                raise Exception('Wappalyzer rule file is null or format error.')
            if not isinstance(rules['apps'], dict) or len(rules['apps']) == 0:
                raise Exception('Wappalyzer rules is null or format error.')
            
            self._categories = rules['categories']
            self._rules = {
                'cookies':[],
                'headers':[],
                'script': [],
                'html': [],
                'url': [],
                'js': [],
                'meta': []
            }
            for appName in rules['apps']:
                website = '' if 'website' not in rules['apps'][appName] else rules['apps'][appName]['website']
                cats = [] if 'cats' not in rules['apps'][appName] else rules['apps'][appName]['cats']
                implies = [] if 'implies' not in rules['apps'][appName] else rules['apps'][appName]['implies']
                self._apps[appName] = {
                    'website': website,
                    'cats': cats,
                    'implies': implies
                }
                if not isinstance(self._apps[appName]['implies'], list):
                    self._apps[appName]['implies'] = [ self._apps[appName]['implies'] ]

                for t in rules['apps'][appName]:
                    if t in ['icon', 'implies', 'website', 'cats']: continue

                    if t == 'headers':
                        for k in rules['apps'][appName][t]:
                            if not isinstance(rules['apps'][appName][t][k], list):
                                rules['apps'][appName][t][k] = [ rules['apps'][appName][t][k] ]
                            
                            for headerValue in rules['apps'][appName][t][k]:
                                rule = self.parseRule(headerValue)
                                if rule:
                                    rule['name'] = appName
                                    rule['keyword'] = k.lower()
                                    self._rules[t].append(rule)

                    elif t in ['js', 'meta']:
                        for k in rules['apps'][appName][t]:
                            if not isinstance(rules['apps'][appName][t][k], list):
                                rules['apps'][appName][t][k] = [ rules['apps'][appName][t][k] ]
                            
                            for v in rules['apps'][appName][t][k]:
                                rule = self.parseRule(v)
                                if rule:
                                    rule['name'] = appName
                                    rule['keyword'] = k.lower()
                                    self._rules[t].append(rule)
                    
                    elif t in ['html', 'script', 'url']:
                        if not isinstance(rules['apps'][appName][t], list):
                            rules['apps'][appName][t] = [ str(rules['apps'][appName][t]) ]
                    
                        for item in rules['apps'][appName][t]:
                            rule = self.parseRule(item)
                            if rule:
                                rule['name'] = appName
                                rule['keyword'] = ''
                                self._rules[t].append(rule)

            return True
        except Exception as e:
            self.log(str(e), 'ERROR')
            self.log(traceback.format_exc(), 'ERROR')
            return False
        finally:
            if fp: fp.close()

    def parseRule(self, rule):
        """
        解析规则库中的单条规则
        @param rule: 规则文本
        @return: {'regex': Regex, 'version': string, 'confidence': int}
        """
        if not rule:
            return { 'regex': None, 'version': None, 'confidence': 100 }
        
        try:
            parts = rule.split(r'\;')
            result = {
                'regex': re.compile(parts[0], re.I),
                'version': None,
                'product': None,
                'confidence': 100
            }
            for item in parts[1:]:
                pos = item.find(':')
                if pos == -1: continue

                if item[:pos] == 'version':
                    result['version'] = item[pos+1:]
                elif item[:pos] == 'confidence':
                    confidence = float(item[pos+1:])
                    if confidence <= 1:
                        confidence *= 100
                    result['confidence'] = abs(int(confidence))
                elif item[:pos] == 'product':
                    result['product'] = item[pos+1:]
            return result
        except Exception as e:
            self.log(str(e), 'ERROR')
            self.log(traceback.format_exc(), 'ERROR')
            return None

    def parseStatus(self, rawHeaders):
        """
        识别原始HTTP头中的请求状态
        :param rawHeaders: 原始头信息
        :return: HTTP响应状态码
        """
        if rawHeaders:
            match = self._statusRegex.search(rawHeaders)
            if match:
                return int(match.group(1))
        return None

    def parseHeaders(self, rawHeaders):
        """
        将原始HTTP头解析为字典格式
        :param rawHeaders: 原始头信息
        :return: 请求头字典
        """
        if not rawHeaders: return {}

        lines = rawHeaders.split('\r\n')
        result = {}
        for i in range(1, len(lines)): # 跳过第一行
            pos = lines[i].find(':')
            if pos == -1: continue
            
            header_name = lines[i][:pos].strip().lower()
            header_value = lines[i][pos+1:].strip()
            if header_name not in result: result[header_name] = []

            result[header_name].append(header_value)
        
        return result

    def parseCookies(self, headers):
        """
        获取HTTP响应头中的Cookie列表
        :param headers: HTTP头字典对象
        """
        if 'set-cookie' not in headers: return {}

        cookies = {}
        for item in headers['set-cookie']:
            parts = item.split(';')
            for _ in parts:
                pos = _.find('=')
                if pos == -1: continue

                name = _[:pos]
                if name not in ['domain', 'path']:
                    cookies[name] = _[pos+1].strip()
                    break

        return cookies

    def parseScripts(self, html):
        """
        获取页面中的脚本列表
        :param html: 页面源代码
        """
        return self._scriptRegex.findall(html)

    def parseLinks(self, html):
        """
        获取页面中的链接列表
        :param html: 页面源代码
        """
        return self._linkRegex.findall(html)

    def parseMetas(self, html):
        """
        获取页面中的元数据
        :param html: 页面源代码
        """
        metas1 = self._metaRegex1.findall(html)
        metas2 = self._metaRegex2.findall(html)

        result = {}
        for _ in metas1 + metas2:
            if _[0] not in result:
                result[_[0]] = [ _[1] ]
            else:
                result[_[0]].append(_[1])
        
        return result

    def parseJs(self, html):
        """
        获取页面执行过程中的JS变量（未实现）
        :param html: 页面源代码
        """
        return {}

    def analyzeByNode(self, url, headers, body):
        """
        通过原生 Node 版 Wappalyzer 分析指纹（必须安装Node，必须部署修改过的 node 版 wappalyzer）
        :param url: 网站URL
        :param headers: HTTP响应头
        :param body: HTTP响应页面内容
        :return: 指纹列表
        """
        if not os.path.exists(self._wapp_path):
            self.log(self._wapp_path + ' not found.', 'ERROR')
            raise Exception('Wappalyzer not exists.')
        
        url_encoded = url.replace('\\', '\\\\').replace('"', '\"')
        header_encoded = str(base64.b64encode(bytes(headers, 'utf-8', 'ignore')), 'utf-8', 'ignore')
        body_encoded = str(base64.b64encode(bytes(body, 'utf-8', 'ignore')), 'utf-8', 'ignore')
        cmd = 'node --no-warnings "{}" "{}" "{}" {} '.format(self._wapp_path, self._rule_file, url_encoded, header_encoded)
        remain_len = self.remain_cmd_len(cmd)
        if remain_len > 0:
            cmd += body_encoded[:self.remain_cmd_len(cmd)]
        else:
            cmd += '""'
        
        try:
            fd = os.popen(cmd)
            data = fd.read()
            if not data:
                raise Exception('Wappalyzer result is empty.')

            try:
                result = json.loads(data)
                if 'applications' in result:
                    for i in range(len(result['applications'])):
                        if 'product' in result['applications'][i]:
                            if result['applications'][i]['product']:
                                result['applications'][i]['name'] = result['applications'][i]['product']
                            del(result['applications'][i]['product'])
                    return result['applications']
            except Exception as e:
                self.log(str(e), 'ERROR')
                self.log(traceback.format_exc(), 'ERROR')
                self.log(data, 'DEBUG')
            
            fd.close()
        except Exception as e:
            self.log('CMD: ' + cmd, 'ERROR')
            self.log(traceback.format_exc(), 'ERROR')
        
        return []

    def remain_cmd_len(self, cmd):
        """
        获取剩余的命令行长度
        :param cmd: 命令行片段
        :return: 剩余可用命令行字符串长度
        """
        if os.name == 'nt': # Windows
            return 4096 - len(cmd)
        else: # CentOS/Ubuntu
            return 2097136 - len(cmd)

class FilterPlugin(Plugin):
    _wappalyzer = None
    """
    Web 指纹识别插件
    src: url, header, body
    dst:
    - apps: 应用指纹，格式：[{name,version,confidence},...]
    - title: 网页标题

    """
    
    def __init__(self, rootdir, debug = False, logger=None):
        """
        构造函数
        :param rootdir: 应用根目录
        :param debug: 调式开关
        """
        super().__init__(rootdir, debug)

        # 初始化指纹相关路径
        rule_file = os.path.join(rootdir, 'rules', 'apps.json')
        if not os.path.exists(rule_file):
            raise Exception('Wappalyzer rule file not found.')

        wapp_path = os.path.join(rootdir, 'wappalyzer', 'cli.js')

        self._wappalyzer = Wappalyzer(os.path.join(rootdir, 'rules', 'apps.json'), wapp_path, logger)
    
    def analyze(self, url, headers, body, mode):
        """
        分析获取指纹
        :param url: 请求URL
        :param headers: 响应头
        :param body: 响应正文
        :param mode: 识别方法：1-使用内置Python引擎，2-使用Node版本Wappalyzer引擎
        """
        if mode == 2:
            return self._wappalyzer.analyzeByNode(url, headers, body)
        else:
            return self._wappalyzer.analyze(url, headers, body)

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

    def execute(self, msg, mode=1):
        """
        插件入口函数，根据插件的功能对 msg 进行处理
        :param msg: 需要处理的消息
        :param mode: 识别方法：1-使用内置Python引擎，2-使用Node版本Wappalyzer引擎
        :return: 返回需要更新的消息字典（不含原始消息）
        """
        if 'pro' not in msg or msg['pro'] != 'HTTP':
            self.log('Not http message.', 'DEBUG')
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
        apps = self.analyze(msg['url'], msg['header'], msg['body'], mode)
        info['apps'] = apps

        # 标题提取
        if 'type' in msg and msg['type'].find('text/html') != -1:
            m = re.search(r'<title>([^<]*?)</title>', msg['body'], re.I)
            if m:
                info['title'] = html.unescape(m.group(1))

        return info

if __name__ == '__main__':
    import time

    #'''
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
        "body": "a\r\n\u001f\b\u0000\u0000\u0000\u0000\u0000\u0000\u0003\r\n",
        "code": 200,
        "url": "http://111.206.63.16/",
        "tag": "sensor-ens160"
    }
    msg_update = {}
    for i in sorted(plugins.keys()):
        (pluginName, plugin) = plugins[i]
        if pluginName == 'wappalyzer':
            print('[!] Plugin {} processing ...'.format(pluginName))
            ctime = time.time()
            ret = plugin.execute(msg, 1)
            etime = time.time()
            print('Eclipse time: {}'.format(etime-ctime))
            print(ret)
    #'''

    # # Test python engine
    # url = 'http://www.baidu.com/'
    # stime = time.time()
    # rawHeaders = base64.b64decode(bytes(headers, 'utf-8', 'ignore')).decode('utf-8', 'ignore')
    # rawBody = base64.b64decode(bytes(body, 'utf-8', 'ignore')).decode('utf-8', 'ignore')

    # wapp = Wappalyzer(r'E:\Code\passets-github\passets-filter\src\wappalyzer\apps.json')
    # result = wapp.analyze(url, rawHeaders, rawBody)
    # print(json.dumps(result))
    # print(time.time() - stime)

    # # Test nodejs engine
    # stime = time.time()
    # wapp = Wappalyzer(
    #     rule_file=r'E:\Code\passets-github\passets-filter\src\wappalyzer\apps.json', 
    #     wapp_path=r'E:\Code\passets-github\passets-filter\src\wappalyzer\cli.js')
    # result = wapp.analyzeByNode(url, headers, body)
    # print(json.dumps(result))
    # print(time.time() - stime)

