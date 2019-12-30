#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Bugfix<tanjelly@gmail.com
Created: 2019-12-12
Modified: 2019-12-30
'''

import os
import time
import geoip2.database
import traceback

from plugin import Plugin

class FilterPlugin(Plugin):
    _geoip = None
    """
    IP归属地识别插件
    src: ip
    dst: 
    - country: 国家
    - city: 城市
    - location: 位置
      - lon: 经度
      - lat: 纬度
    """
    def __init__(self, rootdir, debug=False, logger=None):
        """
        构造函数
        :param rootdir: 工作目录
        :param debug: 调式信息输出开关
        :param logger: 日志处理对象
        """
        super().__init__(rootdir, debug)

        db_file = os.path.join(rootdir, 'rules', 'GeoLite2-City.mmdb')
        if os.path.exists(db_file):
            self._geoip = geoip2.database.Reader(db_file, locales=['zh-CN'])
        else:
            raise Exception('GEOIP2 database not found.')
    
    def execute(self, msg):
        """
        插件入口函数，根据插件的功能对 msg 进行处理
        :param msg: 需要处理的消息
        :return: 返回需要更新的消息字典（不含原始消息）
        """
        if 'ip' not in msg or not msg['ip']:
            self.log('ip field not found.', 'DEBUG')
            return None

        info = { 'geo': {} }
        try:
            resp = self._geoip.city(msg['ip'])
            info['geo']['city'] = resp.city.name
            info['geo']['country'] = resp.country.name
            if info['geo']['country'] in ['香港', '澳门', '台湾']:
                info['geo']['country'] = '中国' + info['geo']['country']
            if info['geo']['country'] == '中华民国':
                info['geo']['country'] = '中国台湾'

            info['geo']['location'] = {
                'lat': resp.location.latitude,
                'lon': resp.location.longitude
            }
        except Exception as e:
            self.log(e, 'DEBUG')
        
        return info

if __name__ == '__main__':
    plugins = Plugin.loadPlugins(os.path.join(os.path.dirname(__file__), ".."), True)
    msg = {
        "ip": "202.106.0.20",
        "port": 80,
        "pro": "TCP",
        "host": "111.206.63.16:80",
        "data": "6765745f696e666f3a20706c7567696e730a5250525420300a617366647361666173667361666173",
        "tag": "sensor-ens160"
    }
    msg_update = {}
    for i in sorted(plugins.keys()):
        (pluginName, plugin) = plugins[i]
        if pluginName == 'geoip':
            ctime = time.time()
            ret = plugin.execute(msg)
            etime = time.time()
            print('Eclipse time: {}'.format(etime-ctime))
            print(ret)
            break