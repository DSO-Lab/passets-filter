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
import time
import base64
import traceback
import threading

from plugin import Plugin

nmapLock = None
nmapFinger = None

class NmapThread(threading.Thread):
    """
    TCP 指纹识别线程
    """
    def __init__(self, data, rules, debug):
        """
        构造函数
        :param data: 要识别的TCP响应报文原始数据
        :param rules: 指纹规则集
        :param debug: 调试信息输出开关
        """
        super().__init__()
        self._data = data
        self._rules = rules
        self._debug = debug
    
    def run(self):
        """线程主函数"""
        global nmapFinger

        for rule in self._rules:
            if nmapFinger: return
            try:
                m = re.match(rule['m'], self._data, rule['mf'])
                if m:
                    result = {
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
                            for k in result:
                                if not result[k]: continue

                                if skey in result[k]:
                                    result[k] = result[k].replace(skey, m.group(i))
                    
                    nmapLock.acquire()
                    nmapFinger = result
                    nmapLock.release()
                    break
            except:
                if self._debug: print('[-] ERROR:\n' + traceback.format_exc())



class FilterPlugin(Plugin):
    """
    TCP 指纹识别插件
    """
    
    def __init__(self, rootdir, debug = False):
        """
        构造函数
        :param rootdir: 工作目录
        :param debug: 调式信息输出开关
        """
        super().__init__(rootdir, debug)

        # 初始化指纹相关路径
        self.loadRules(os.path.join(rootdir, 'rules', 'nmap-service-probes'))
    
    def loadRules(self, rule_file):
        """
        加载 NMAP 规则库
        :param rule_file: NAMP 指纹规则库文件
        """
        self.rules = []

        data = []
        try:
            fp = open(rule_file, encoding='utf-8')
            data = fp.readlines()
            fp.close()
        except:
            self.log(traceback.format_exc(), 'ERROR')

        regex_attr = re.compile(r'\s+([pviodh])(?:/([^/]*?)/|\|([^\|]*?)\|)$')
        regex_cpe = re.compile(r'\s+cpe:/.*?$')
        regex_main = re.compile(r'^(?:soft)?match\s+([^\s]+)\s+m[\|=%](.*?)[\|=%]([ismg]*?)$')
        regex_flags = {'i':re.I, 's':re.S, 'm':re.M, 'u':re.U, 'l':re.L, 'a':re.A, 't':re.T, 'x':re.X}
        is_tcp = False
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
                'm': None, 'mf': 0, 's': None, 'p': None, 'v': None, 'i': None, 'o': None, 'd': None, 'h': None, 'cpe': cpe
            }
            while True:
                m = regex_attr.search(_)
                if not m:
                    break

                rule[m.group(1)] = m.group(2)
                _ = _[:0-len(m.group(0))]

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
            
            self.rules.append(rule)

        self.log('{} rules loaded.'.format(len(self.rules)))
   
    def analyze(self, data):
        """
        分析获取指纹
        :param data: TCP响应数据包
        :return: 指纹列表，例如：[{'name':'XXX','version':'XXX',...}]
        """
        global nmapFinger, nmapLock
        nmapFinger = None
        nmapLock = threading.Lock()

        pos = 0
        # 由于任务处理以CPU运算为主，多线程反而会更慢，故将线程调整为1，单批规则数量最大
        maxThreadCount = 1
        maxBatchRuleCount = 50000

        threadList = [None for i in range(maxThreadCount)]
        while True:
            isBreak = False
            for i in range(maxThreadCount):
                if threadList[i] and threadList[i].isAlive():
                    continue

                thread_rules = self.rules[pos: pos + maxBatchRuleCount]
                threadList[i] = NmapThread(data, thread_rules, self._debug)
                threadList[i].start()

                if len(thread_rules) < maxBatchRuleCount:
                    isBreak = True
                    break

                pos += maxBatchRuleCount
            
            if isBreak: break

            time.sleep(0.02)
        
        for i in range(maxThreadCount):
            if threadList[i] and threadList[i].isAlive():
                threadList[i].join()

        if nmapFinger: return [ nmapFinger ]

        return []

    def execute(self, msg):
        """
        插件入口函数，根据插件的功能对 msg 进行处理
        :param msg: 需要处理的消息
        :return: 返回需要更新的消息字典（不含原始消息）
        """
        if 'pro' not in msg or msg['pro'] != 'TCP':
            self.log('Not tcp message.')
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

        # Example: 554 SMTP synchronization error\r\n
        #"data": "35353420534d54502073796e6368726f6e697a6174696f6e206572726f720d0a",

        # Example: >INFO:OpenVPN Management Interface Version 1.0.1 -- type 'help' for more info\r\n>
        #"data": "3e494e464f3a4f70656e56504e204d616e6167656d656e7420496e746572666163652056657273696f6e20312e302e31202d2d2074797065202768656c702720666f72206d6f726520696e666f0d0a3e",

        # Example: get_info: plugins\nRPRT 0\nasfdsafasfsafas
        "data": "6765745f696e666f3a20706c7567696e730a5250525420300a617366647361666173667361666173",

        "inner": False,
        "tag": "sensor-ens160"
    }
    msg_update = {}
    for pluginName in sorted(plugins.keys()):
        if pluginName == 'nmap':
            ctime = time.time()
            ret = plugins[pluginName].execute(msg)
            etime = time.time()
            print('Eclipse time: {}'.format(etime-ctime))
            print(ret)
            break
