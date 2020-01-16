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
import time
import base64
import hashlib
import copy
import traceback
import threading

from plugin import Plugin

class FilterPlugin(Plugin):
    """
    TCP 指纹识别插件
    src: data
    dst:
    - apps: 指纹信息，格式: [{name,version,os,device,info,service},...]
    """
    os_white_list = []
    name_regex = None
    
    def __init__(self, rootdir, debug=False, logger=None):
        """
        构造函数
        :param rootdir: 工作目录
        :param debug: 调式信息输出开关
        :param logger: 日志处理对象
        """
        super().__init__(rootdir, debug)

        # 初始化指纹相关路径
        self.loadRules(os.path.join(rootdir, 'rules', 'nmap-service-probes'))
        self.name_regex = re.compile(r'[^\x20-\x7e]')

    def _readfile(self, filepath):
        """
        读取文件内容
        :param filepath: 文件路径
        """
        try:
            fp = open(filepath, encoding='utf-8')
            data = fp.read()
            fp.close()
            return data
        except:
            self.log(traceback.format_exc(), 'ERROR')
        return None

    def _writefile(self, filepath, filecontent):
        """
        写入文件内容
        :param filepath: 要写入的文件路径
        :param filecontent: 要写入的文件内容
        """
        try:
            fp = open(filepath, encoding='utf-8', mode='w')
            fp.write(filecontent)
        except:
            self.log(traceback.format_exc(), 'ERROR')
        finally:
            fp.close()

    def loadRuleJson(self, rule_file):
        """
        加载 NMAP 规则库（JSON格式）
        :param rule_file: Json 格式规则库文件
        """
        try:
            data = self._readfile(rule_file)
            if data:
                return json.loads(data)
        except:
            self.log(traceback.format_exc(), 'ERROR')
        
        return None
    
    def loadRules(self, rule_file):
        """
        加载 NMAP 规则库
        :param rule_file: NAMP 指纹规则库文件
        """
        self.rules = []

        converted_rule_path = rule_file[:rule_file.rfind(os.sep) + 1] + 'nmap.json'
        data = None
        if os.path.isfile(converted_rule_path):
            data = self.loadRuleJson(converted_rule_path)
        
        file_data = self._readfile(rule_file)
        if not file_data:
            raise Exception('NMAP rule file not found.')

        file_hash = hashlib.md5(file_data.encode('utf-8')).hexdigest()
        if data and data['hash'] == file_hash:
            self.rules = data['apps']
            # 预加载正则表达式
            for i in range(len(self.rules)):
                if self.rules[i]['o']:
                    os_prefix = self.rules[i]['o'].split('$')[0].rstrip().lower()
                    if len(os_prefix) > 0: self.os_white_list.append(os_prefix)
                self.rules[i]['r'] = re.compile(self.rules[i]['m'], self.rules[i]['mf'])
            return
        
        data = file_data.split('\n')

        regex_attr = re.compile(r'\s+([pviodh])(?:/([^/]*?)/|\|([^\|]*?)\|)$')
        regex_cpe = re.compile(r'\s+cpe:/.*?$')
        regex_main = re.compile(r'^(?:soft)?match\s+([^\s]+)\s+m[\|=%](.*?)[\|=%]([ismg]*?)$')
        regex_flags = {'i':re.I, 's':re.S, 'm':re.M, 'u':re.U, 'l':re.L, 'a':re.A, 't':re.T, 'x':re.X}
        is_tcp = False
        tmp_rules = []
        for _ in data:
            _ = _.strip()

            if _[:6] == 'Probe ':
                if _[:10] == 'Probe TCP ':
                    is_tcp = True
                else:
                    is_tcp = False
            
            if not is_tcp:
                continue
            
            if not (_[:5] == 'match' or _[:9] == 'softmatch'):
                continue

            m = regex_cpe.search(_)
            cpe = []
            if m:
                _ = _[:0-len(m.group(0))]
                cpe = m.group(0).strip().split(' ')
            
            rule = {
                'm': None, 'mf': 0, 's': None, 'p': None, 'v': None, 'i': None, 'o': None, 'd': None, 'h': None, 'cpe': cpe, 'r': None
            }
            while True:
                m = regex_attr.search(_)
                if not m:
                    break

                rule[m.group(1)] = m.group(2)
                _ = _[:0-len(m.group(0))]
                if m.group(1) == 'o' and m.group(2):
                    os_prefix = m.group(2).split('$')[0].rstrip().lower()
                    if len(os_prefix) > 0: self.os_white_list.append(os_prefix)

            m = regex_main.match(_)
            if not m:
                self.log(_, 'ERROR')
                continue

            rule['s'] = m.group(1)
            rule['m'] = m.group(2)
            if m.group(3):
                for f in m.group(3):
                    if f in regex_flags:
                        rule['mf'] |= regex_flags[f]
            
            # 一些太短或特征不明显的规则，直接丢弃
            if len(rule['m']) <= 1: continue
            if rule['m'] in [
                '^\\t$', '^\\0$', '^ok$', '^OK$', '^\\x05', '^ \\r\\n$', '^\\|$', '^00$', '^01$', '^02$', '^ $', '^1$',
                '^\\xff$', '^1\\0$', '^A$', '^Q$', '^x0$', '^\\0\\0$', '^\\x01$', '^0\\0$']:
                continue
                
            tmp_rules.append(rule)

            new_rule = copy.deepcopy(rule)
            # 预加载正则表达式
            new_rule['r'] = re.compile(new_rule['m'], new_rule['mf'])
            self.rules.append(new_rule)
        
        self._ruleCount = len(self.rules)
        self._writefile(converted_rule_path, json.dumps({'hash': file_hash, 'apps': tmp_rules}, indent=2, sort_keys=True))

    def analyze(self, data):
        """
        分析获取指纹
        :param data: TCP响应数据包
        :return: 指纹列表，例如：[{'name':'XXX','version':'XXX',...}]
        """
        result = []
        for rule in self.rules:
            try:
                m = rule['r'].match(data)
                if m:
                    app = {
                        'name': rule['p'],
                        'version': rule['v'],
                        'info': rule['i'],
                        'os': rule['o'],
                        'device': rule['d'],
                        'service': rule['s']
                    }
                    if m.lastindex:
                        for i in range(m.lastindex + 1):
                            skey = '${}'.format(i)
                            for k in app:
                                if not app[k]: continue

                                if skey in app[k]:
                                    app[k] = app[k].replace(skey, m.group(i))
                    
                    available = False
                    if app['os']:
                        # 太长或者是存在不可见字符的，说明获取的数据不对
                        if len(app['os']) > 30 or self.name_regex.search(app['os']): continue
                        tmpOS = app['os'].lower()
                        for _ in self.os_white_list:
                            print('{} - {}'.format(tmpOS, _))
                            if tmpOS.find(_) == 0 or _.find(tmpOS) == 0:
                                available = True
                                break
                    else:
                        available = True
                    
                    if available:
                        result.append(app)
                        break
            except Exception as e:
                self.log(e, 'ERROR')
                self.log(traceback.format_exc(), 'ERROR')
        
        return result

    def execute(self, msg):
        """
        插件入口函数，根据插件的功能对 msg 进行处理
        :param msg: 需要处理的消息
        :return: 返回需要更新的消息字典（不含原始消息）
        """
        if 'pro' not in msg or msg['pro'] != 'TCP':
            self.log('Not tcp message.', 'DEBUG')
            return

        info = {}
        if 'data' not in msg or not msg['data']:
            self.log('data field not found.')
            return
        
        info['apps'] = self.analyze(str(bytes.fromhex(msg['data']), 'utf-8', 'ignore'))

        return info

if __name__ == '__main__':
    plugins = Plugin.loadPlugins(os.path.join(os.path.dirname(__file__), ".."), True)
    print(plugins)
    msg = {
        "ip_num": 1875787536,
        "ip": "111.206.63.16",
        "port": 80,
        "pro": "TCP",
        "host": "111.206.63.16:80",
        #'data': '00',
        # Example: 554 SMTP synchronization error\r\n
        #"data": "35353420534d54502073796e6368726f6e697a6174696f6e206572726f720d0a",

        # Example: >INFO:OpenVPN Management Interface Version 1.0.1 -- type 'help' for more info\r\n>
        #"data": "3e494e464f3a4f70656e56504e204d616e6167656d656e7420496e746572666163652056657273696f6e20312e302e31202d2d2074797065202768656c702720666f72206d6f726520696e666f0d0a3e",

        # Example: get_info: plugins\nRPRT 0\nasfdsafasfsafas
        #"data": "6765745f696e666f3a20706c7567696e730a5250525420300a617366647361666173667361666173",

        #"data": '16030300d0010000cc03035df0c691b795581015d570c868b701ed1784528e488e9aeec4b37dad521e2de4202332000016299b175b8f0ad21daeb83a03eb5d47b57bb60ecfbd10bcd67a101d0026c02cc02bc030c02fc024c023c028c027c00ac009c014c013009d009c003d003c0035002f000a0100005d00000019001700001461637469766974792e77696e646f77732e636f6d000500050100000000000a00080006001d00170018000b00020100000d001400120401050102010403050302030202060106030023000000170000ff01000100',
        "data": "004a56978183000100000000000013616c6572746d616e616765722d6d61696e2d3115616c6572746d616e616765722d6f706572617465640a6d6f6e69746f72696e67037376630000ff0001",

        "inner": False,
        "tag": "sensor-ens160"
    }
    msg_update = {}
    for i in sorted(plugins.keys()):
        (pluginName, plugin) = plugins[i]
        if pluginName == 'nmap':
            print('[!] Plugin {} processing ...'.format(pluginName))
            ctime = time.time()
            ret = plugin.execute(msg)
            etime = time.time()
            print('Eclipse time: {}'.format(etime-ctime))
            print(ret)
            break
