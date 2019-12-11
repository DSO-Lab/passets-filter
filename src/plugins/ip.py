#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Bugfix<tanjelly@gmail.com
Created: 2019-12-11
MOdified: 2019-12-11
'''

import os
import sys
import json
import socket
import time
import traceback

from plugin import Plugin

class FilterPlugin(Plugin):
    """
    IP 处理插件
    """
    
    def ip2num(self, ip):
        """
        IP字符串转长整数
        :param ip: IP字符串
        :return: IP数值
        """
        try:
            return int.from_bytes(socket.inet_aton(ip), 'big')
        except:
            return 0

    def execute(self, msg):
        """
        插件入口函数，根据插件的功能对 msg 进行处理
        :param msg: 需要处理的消息
        :return: 返回需要更新的消息字典（不含原始消息）
        """
        if 'ip' not in msg or not msg['ip']:
            self.log('ip field not found.')
            return None

        info = {
            'ip_num': 0, 'inner': False
        }
        # 计算IP的数值
        ip_num = self.ip2num(msg['ip'])
        if ip_num <= 0:
            return info
        info['ip_num'] = ip_num

        # 判断内网IP
        inner_ip_ranges = [
            '10.0.0.0-10.255.255.255',
            '172.16.0.0-172.31.255.255',
            '192.168.0.0-192.168.255.255',
            '169.254.0.0-169.254.255.255',
            '127.0.0.0-127.0.0.255'
        ]

        if self._config and 'inner_ips' in self._config and isinstance(self._config['inner_ips'], list):
            inner_ip_ranges = self._config['inner_ips']
        
        inner = False
        for _ in inner_ip_ranges:
            _ = _.split('-')
            if len(_) != 2: continue

            ip_start = self.ip2num(_[0])
            ip_end = self.ip2num(_[1])
            
            if ip_num >= ip_start and ip_num <= ip_end:
                inner = True
                break
        
        info['inner'] = inner
        return info

if __name__ == '__main__':
    plugins = Plugin.loadPlugins(os.path.join(os.path.dirname(__file__), ".."), True)
    msg = {
        #"ip": "202.106.0.20",
        "ip": "192.168.1.20",
        "port": 80,
        "pro": "TCP",
        "host": "111.206.63.16:80",
        # Example: 554 SMTP synchronization error\r\n
        #"data": "35353420534d54502073796e6368726f6e697a6174696f6e206572726f720d0a",
        # Example: >INFO:OpenVPN Management Interface Version 1.0.1 -- type 'help' for more info\r\n>
        #"data": "3e494e464f3a4f70656e56504e204d616e6167656d656e7420496e746572666163652056657273696f6e20312e302e31202d2d2074797065202768656c702720666f72206d6f726520696e666f0d0a3e",
        # Example: get_info: plugins\nRPRT 0\nasfdsafasfsafas
        "data": "6765745f696e666f3a20706c7567696e730a5250525420300a617366647361666173667361666173",
        "tag": "sensor-ens160"
    }
    msg_update = {}
    for pluginName in sorted(plugins.keys()):
        if pluginName == 'ip':
            ctime = time.time()
            ret = plugins[pluginName].execute(msg)
            etime = time.time()
            print('Eclipse time: {}'.format(etime-ctime))
            print(ret)
            break