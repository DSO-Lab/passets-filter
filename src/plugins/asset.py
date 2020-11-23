#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Author: Bugfix<tanjelly@gmail.com
Created: 2019-12-11
Modified: 2020-01-19
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

from urllib import parse
from plugin import Plugin, LogLevel

class FilterPlugin(Plugin):
    """
    资产分类插件
    src: data
    dst:
    - asset_type: 资产类型，字符串数组类型
    - device: 设备类型，字符串数组类型
    - vendor: 厂商，字符串数组
    - service: 服务名，字符串数组
    - info: 设备信息，字符串数组
    """
    ignore_vendors = []
    
    def __init__(self, rootdir, debug=False, logger=None):
        """
        构造函数
        :param rootdir: 工作目录
        :param debug: 调式信息输出开关
        :param logger: 日志处理对象
        """
        super().__init__(rootdir, debug, logger)

        # 载入资产类型、设备类型、厂商映射关系
        tcp_asset_type_file = os.path.join(rootdir, 'rules', 'tcp_asset_types.json')
        if not os.path.exists(tcp_asset_type_file) or not self.loadTcpAssetTypes(tcp_asset_type_file):
            self.log('Load tcp asset type file failed.', LogLevel.ERROR)
            self.tcp_asset_types = {}

        tcp_device_type_file = os.path.join(rootdir, 'rules', 'tcp_device_types.json')
        if not os.path.exists(tcp_device_type_file) or not self.loadTcpDeviceTypes(tcp_device_type_file):
            self.log('Load tcp device type file failed.', LogLevel.ERROR)
            self.tcp_device_types = {}

        http_asset_type_file = os.path.join(rootdir, 'rules', 'http_asset_types.json')
        if not os.path.exists(http_asset_type_file) or not self.loadHttpAssetTypes(http_asset_type_file):
            self.log('Load http asset type file failed.', LogLevel.ERROR)
            self.http_asset_types = {}

        http_device_type_file = os.path.join(rootdir, 'rules', 'http_device_types.json')
        if not os.path.exists(http_device_type_file) or not self.loadHttpDeviceTypes(http_device_type_file):
            self.log('Load http device type file failed.', LogLevel.ERROR)
            self.http_device_types = {}

        vendor_file = os.path.join(rootdir, 'rules', 'vendors.json')
        if not os.path.exists(vendor_file) or not self.loadVendors(vendor_file):
            self.log('Load vendor file failed.', LogLevel.ERROR)
            self.vendors = []

    def set_config(self, config):
        """
        配置初始化函数
        :param config: 插件配置
        """
        super().set_config(config)

        # 来自插件配置的忽略厂商关键词列表
        self.ignore_vendors = []
        if self._config:
            if 'ignore_vendors' in self._config and isinstance(self._config['ignore_vendors'], list):
                self.ignore_vendors = self._config['ignore_vendors']
    
    def loadTcpAssetTypes(self, rule_file):
        """
        根据文件名读取TCP资产类型映射关系
        :param rule_file: 资产类型映射关系表
        :return True-成功，False-失败
        """
        self.tcp_asset_types = {}
        fp = None
        try:
            fp = open(rule_file, encoding='utf-8')
            data = json.loads(fp.read())
            for key in data:
                if not isinstance(data[key], list):
                    continue
                
                for _ in data[key]:
                    self.tcp_asset_types[_] = key
            return True
        except Exception as e:
            self.log(str(e), LogLevel.ERROR)
            return False
        finally:
            if fp: fp.close()

    def loadTcpDeviceTypes(self, rule_file):
        """
        根据文件名读取TCP设备类型映射关系
        :param rule_file: 资产类型映射关系表
        :return True-成功，False-失败
        """
        self.tcp_device_types = {}
        fp = None
        try:
            fp = open(rule_file, encoding='utf-8')
            data = json.loads(fp.read())
            for key in data:
                if not isinstance(data[key], list):
                    continue
                
                for _ in data[key]:
                    self.tcp_device_types[_] = key
            return True
        except Exception as e:
            self.log(str(e), LogLevel.ERROR)
            return False
        finally:
            if fp: fp.close()

    def loadHttpAssetTypes(self, rule_file):
        """
        根据文件名读取HTTP资产类型映射关系
        :param rule_file: 资产类型映射关系表
        :return True-成功，False-失败
        """
        self.http_asset_types = {}
        fp = None
        try:
            fp = open(rule_file, encoding='utf-8')
            data = json.loads(fp.read())
            for key in data:
                if not isinstance(data[key], list):
                    continue
                
                for _ in data[key]:
                    self.http_asset_types[_] = key
            return True
        except Exception as e:
            self.log(str(e), LogLevel.ERROR)
            return False
        finally:
            if fp: fp.close()

    def loadHttpDeviceTypes(self, rule_file):
        """
        根据文件名读取HTTP设备类型映射关系
        :param rule_file: 资产类型映射关系表
        :return True-成功，False-失败
        """
        self.http_device_types = {}
        fp = None
        try:
            fp = open(rule_file, encoding='utf-8')
            data = json.loads(fp.read())
            for key in data:
                if not isinstance(data[key], list):
                    continue
                
                for _ in data[key]:
                    self.http_device_types[_] = key
            return True
        except Exception as e:
            self.log(str(e), LogLevel.ERROR)
            return False
        finally:
            if fp: fp.close()

    def loadVendors(self, rule_file):
        """
        根据文件名读取设备厂商列表
        :param rule_file: 厂商列表文件
        :return True-成功，False-失败
        """
        fp = None
        try:
            fp = open(rule_file, encoding='utf-8')
            self.vendors = json.loads(fp.read())
            return True
        except Exception as e:
            self.log(str(e), LogLevel.ERROR)
            return False
        finally:
            if fp: fp.close()

    def parseTcpAssetType(self, name, info, device):
        """
        从指纹名称、信息、设备类型中识别资产类型
        """
        result = []
        parts = "{} {} {}".format(name, info, device).lower().split(' ')
        for _ in  parts:
            if not _: continue
            for key in self.tcp_asset_types:
                if key == _:
                    result.append(self.tcp_asset_types[key])

        return result

    def parseTcpDeviceType(self, name, info, device):
        """
        从指纹名称、信息、设备信息中提取设备类型
        """
        # 优先根据既有设备类型来识别类型
        result = []
        if device:
            device = device.lower()
            for key in self.tcp_device_types:
                if key in device:
                    result.append(self.tcp_device_types[key])
        
        parts = "{} {}".format(name, info).lower().split(' ')
        for _ in  parts:
            if not _: continue
            for key in self.tcp_device_types:
                if key == _:
                    result.append(self.tcp_device_types[key])

        return result

    def parseTcpVendor(self, name, info):
        """
        从指纹名称、信息中识别厂商
        """
        data = "{} {}".format(name, info)
        for _ in self.vendors:
            if _ in data and _.lower() not in self.ignore_vendors:
                return _
        
        return ''

    def parseHttpAssetType(self, categorie_ids):
        """
        根据分类 ID 确定资产类型
        """
        result = []
        for _ in categorie_ids:
            if 'id' in _ and _['id'] in self.http_asset_types:
                result.append(self.http_asset_types[_['id']])
        
        return result

    def parseHttpDeviceType(self, appName):
        """
        根据指纹名称关键词确定设备类型
        """
        result = []
        appName = appName.lower()
        for _ in self.http_device_types:
            if _ in appName:
                result.append(self.http_device_types[_])
        
        return result

    def parseHttpVendor(self, url):
        """
        从URL中解析提取厂商名称
        """
        url = url.lower()
        if url.find('http://') != 0 and url.find('https://') != 0:
            return ''
        
        try:
            parts = parse.urlsplit(url).netloc.split(':')[0].split('.')[:-1]
            if parts[0] in ['www']:
                parts = parts[1:]
            if parts[-1] in ['org', 'com', 'edu', 'gov', 'biz']:
                parts = parts[:-1]
            
            vendor = ''
            if len(parts[-1]) < 3 and len(parts) > 1:
                vendor = parts[-2].upper()
            else:
                if len(parts[-1]) < 4:
                    vendor = parts[-1].upper()
                else:
                    vendor = parts[-1].capitalize()
            
            if vendor.lower() not in self.ignore_vendors:
                return vendor
            
            return ''
        except:
            return ''

    def analyzeTcp(self, apps):
        """
        分析HTTP指纹获取资产类型
        :param apps: 指纹列表
        :return: 资产相关信息，例如：{ 'asset_type': ["Network Device"], 'vendor': ["Huawei"], 'device': ["Router"], 'service': ["telnet"], 'info': ["Huawei AR5102"] }
        """
        info = { 'asset_type': [], 'vendor': [], 'device': [], 'service': [], 'info': [] }
        for i in range(len(apps)):
            app = apps[i]
            devices = self.parseTcpDeviceType(app['name'], app['info'], app['device'])
            if devices:
                for _ in devices:
                    if _ not in info['device']:
                        info['device'].append(_)

            asset_types = self.parseTcpAssetType(app['name'], app['info'], ' '.join(devices))
            if asset_types:
                for _ in asset_types:
                    if _ not in info['asset_type']:
                        info['asset_type'].append(_)

            vendor = self.parseTcpVendor(app['name'], app['info'])
            if vendor and vendor not in info['vendor']:
                info['vendor'].append(vendor)

            if app['service'] and app['service'] not in info['service']:
                info['service'].append(app['service'])
            
            # 设备信息不存在则用 os 属性代替
            if app['info']:
                if app['info'] not in info['info']:
                    info['info'].append(app['info'])
            else:
                if app['os'] and app['os'] not in info['info']:
                    info['info'].append(app['os'])

            del(apps[i]['device'], apps[i]['service'], apps[i]['info'])
        
        info['apps'] = apps

        return info

    def analyzeHttp(self, apps):
        """
        分析HTTP指纹获取资产类型
        :param apps: 指纹列表
        :return: 资产相关信息，例如：{ 'asset_type': ["Web Server"], 'vendor': ["Apache"], 'device': [], 'service': ["http"], 'info': ["Apache tomcat 9.0.28"] }
        """
        info = { 'asset_type': [], 'vendor': [], 'device': [], 'service': ['http'], 'info': [] }
        for i in range(len(apps)):
            app = apps[i]
            # 识别设备产品型号/版本（用3-5层的指纹名称填充，使用 lastLayer 来控制只取一个指纹的父级）
            # print("Level: {}, appName: {}, implies: {}".format(self._apps[appName]['layer'], appName, self._apps[appName]['implies']))
            if app['layer'] in [2, 3, 4, 5]:
                name = app['name']
                if app['version']: name += "/" + app['version']
                if info not in info['info']:
                    info['info'].append(name)
            
            # 识别厂商
            vendor = self.parseHttpVendor(app['website'])
            if vendor and len(vendor) > 2 and vendor not in info['vendor']:
                info['vendor'].append(vendor)

            # 识别资产类型
            asset_types = self.parseHttpAssetType(app['categories'])
            if asset_types:
                for _ in asset_types:
                    if _ not in info['asset_type']:
                        info['asset_type'].append(_)

            # 识别设备类型
            devices = self.parseHttpDeviceType(app['name'])
            if devices:
                for _ in devices:
                    if _ not in info['device']:
                        info['device'].append(_)

            # 删除 Wappalyzer 插件传递过来的中间属性
            del(apps[i]['layer'], apps[i]['website'])

        info['apps'] = apps

        return info

    def execute(self, msg):
        """
        插件入口函数，根据插件的功能对 msg 进行处理
        :param msg: 需要处理的消息
        :return: 返回需要更新的消息字典（不含原始消息）
        """
        if 'pro' not in msg or msg['pro'].upper() not in ['TCP', 'HTTP']:
            self.log('Not TCP/HTTP message.', LogLevel.DEBUG)
            return

        info = {}
        if 'apps' not in msg:
            self.log('Fingerprint property "apps" not found.', LogLevel.ERROR)
            return

        if not msg['apps']:
            return
        
        # 识别资产分类
        apps = {}
        pro = msg['pro'].upper()
        if pro == 'HTTP':
            apps = self.analyzeHttp(msg['apps'])
        elif pro == 'TCP':
            apps = self.analyzeTcp(msg['apps'])
        
        info.update(apps)

        return info

if __name__ == '__main__':
    plugins = Plugin.loadPlugins(os.path.join(os.path.dirname(__file__), ".."), True)
    print(plugins)
    # msg = {
    #     "tag": "eno2",
    #     "method": "GET",
    #     "type": "text/plain; charset=utf-8",
    #     "header": "Server: nginx\r\nDate: Mon, 23 Nov 2020 06:08:26 GMT\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 26\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nWWW-Authenticate: Basic realm=\"GitLab\"\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nX-Request-Id: 7a5ad814-b10f-4a2e-8035-4f0436e2dd1a\r\nX-Runtime: 0.015255\r\nX-Ua-Compatible: IE=edge\r\nX-Xss-Protection: 1; mode=block",
    #     "url": "http://www.gitlab.com/omni/chinaz-sdk.git/info/refs?service=git-upload-pack",
    #     "@version": "1",
    #     "ip_str": "192.168.199.23",
    #     "tags": [
    #         "_geoip_lookup_failure"
    #     ],
    #     "url_tpl": "http://www.gitlab.com/omni/chinaz-sdk.git/info/refs?service=%7B%7D",
    #     "server": "nginx",
    #     "inner": True,
    #     "ip": "192.168.199.23",
    #     "host": "192.168.199.23:80",
    #     "pro": "HTTP",
    #     "code": "401",
    #     "body": "HTTP Basic: Access denied\n",
    #     "port": 80,
    #     "site": "http://www.gitlab.com",
    #     "apps": [
    #         {
    #             "confidence": 100,
    #             "name": "Nginx",
    #             "categories": [
    #             {
    #                 "name": "Web Servers",
    #                 "id": 22
    #             }
    #             ],
    #             "version": ""
    #         }
    #     ]
    # }
    msg = {
        "tag": "eno2",
        "@version": "1",
        "ip_str": "47.92.139.186",
        "inner": False,
        "ip": "47.92.139.186",
        "data": "590000000a352e352e352d31302e312e32342d4d6172696144420042bd00007b7b7661603e536700fff72102003fa015000000000000000000002e4b6f6e5c615258452d4f29006d7973716c5f6e61746976655f70617373776f726400",
        "host": "47.92.139.186:3306",
        "geoip": {
            "location": {
                "lon": 120.1619,
                "lat": 30.294
            },
            "city_name": "杭州",
            "country_name": "中国"
        },
        "pro": "TCP",
        "port": 3306,
        "state": 1,
        "apps": [
        {
            "os": "",
            "confidence": 100,
            "name": "MySQL",
            "version": "5.5.5-10.1.24-MariaDB"
        }
        ]
    }
    msg_update = {}
    for i in sorted(plugins.keys()):
        (pluginName, plugin) = plugins[i]
        print('[!] Plugin {} processing ...'.format(pluginName))
        ctime = time.time()
        ret = plugin.execute(msg)
        if ret:
            msg.update(ret)
        etime = time.time()
        print('Eclipse time: {}'.format(etime-ctime))
        print(json.dumps(ret, indent=2))
        print('[!] Plugin {} process completd.'.format(pluginName))
    