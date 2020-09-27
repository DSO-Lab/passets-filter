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

from plugin import Plugin, LogLevel

class FilterPlugin(Plugin):
    """
    TCP 指纹识别插件
    src: data
    dst:
    - apps: 指纹信息，格式: [{name,version,os,device,info,service},...]
    """
    os_white_list = []
    ignore_rules = []
    name_regex = None
    
    def __init__(self, rootdir, debug=False, logger=None):
        """
        构造函数
        :param rootdir: 工作目录
        :param debug: 调式信息输出开关
        :param logger: 日志处理对象
        """
        super().__init__(rootdir, debug, logger)

        # 初始化指纹相关路径
        self.loadRules(os.path.join(rootdir, 'rules', 'nmap-service-probes'))
        self.name_regex = re.compile(r'[^\x20-\x7e]')

    def set_config(self, config):
        """
        配置初始化函数
        :param config: 插件配置
        """
        super().set_config(config)

        self.ignore_rules = []
        self.ssl_portmap = {}
        if self._config:
            if 'ignore_rules' in self._config and isinstance(self._config['ignore_rules'], list):
                self.ignore_rules = self._config['ignore_rules']
            
            if 'ssl_portmap' in self._config and isinstance(self._config['ssl_portmap'], list):
                for _ in self._config['ssl_portmap']:
                    try:
                        parts = _.split(':')
                        self.ssl_portmap[int(parts[0])] = parts[-1].strip()
                    except:
                        self.log('[E] ssl_portmap config error! Data is "{}".'.format(_))
                        continue
    
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
            self.log(traceback.format_exc(), LogLevel.ERROR)
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
            self.log(traceback.format_exc(), LogLevel.ERROR)
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
            self.log(traceback.format_exc(), LogLevel.ERROR)
        
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
                self.rules[i]['r'] = re.compile(bytes(self.rules[i]['m'], encoding="utf-8"), self.rules[i]['mf'])
                self.rules[i]['ports'] = self.parsePorts(self.rules[i]['ports'])
            return
        
        data = file_data.split('\n')

        regex_flags = {'i':re.I, 's':re.S, 'm':re.M, 'u':re.U, 'l':re.L, 'a':re.A, 't':re.T, 'x':re.X}
        is_tcp = False
        ports = ''
        tmp_rules = []
        for _ in data:
            _ = _.strip()

            if _[:6] == 'Probe ':
                if _[:10] == 'Probe TCP ':
                    is_tcp = True
                else:
                    is_tcp = False

            # 不处理 UDP 指纹
            if not is_tcp:
                continue
            
            if _[:6] == 'ports ':
                ports += _[6:].strip() + ','
            
            if _[:9] == 'sslports ':
                ports += _[9:].strip() + ','
            
            if not (_[:6] == 'match ' or _[:10] == 'softmatch '):
                continue

            rule = {
                'm': None, 'mf': 0, 's': None, 'p': None, 'v': None, 'i': None, 'o': None, 
                'd': None, 'h': None, 'cpe': '', 'r': None, 'ports': ports.strip(',')
            }

            line = _[_.find('match ') + 6:].strip()

            pos = line.find(' ')
            if pos == -1:
                continue

            rule['s'] = line[:pos]
            line = line[pos + 1:].strip()
            regex_type = re.compile(r'([mpviodh]|cpe:)([/\|=%@])')
            while True:
                m = regex_type.search(line)
                if not m:
                    break

                key = m.group(1).replace(':', '')
                # 属性的边界符号是根据内容变的，通常为/，但内容中如果有/则使用|，暂时未发现其它符号
                end_pos = line.find(m.group(2), len(m.group(0)))
                val = None
                if end_pos > 0:
                    val = line[len(m.group(0)): end_pos]
                    line = line[end_pos+1:]
                else:
                    val = line[len(m.group(0)): ]
                    line = ''

                if key == 'cpe': # CPE可能出现多次
                    if rule['cpe']:
                        rule['cpe'] += '\n' + val
                else:
                    rule[key] = val
                
                if line.find(' ') > 0:
                    flags = line[: line.find(' ')]
                    # 识别匹配表达式的模式
                    if key == 'm':
                        for flag in flags:
                            if flag in regex_flags:
                                rule['mf'] |= regex_flags[flag]
                            else:
                                print('[E] Find a unrecognized flag. Data: ' + flag)
                    
                    line = line[line.find(' ')+1:].strip()
                else:
                    line = line.strip()
                    
                if not line:
                    break

            # 一些太短或特征不明显的规则，直接丢弃
            if not rule['m'] or len(rule['m']) <= 1: continue
            if rule['m'] in [
                '^\\t$', '^\\0$', '^ok$', '^OK$', '^\\x05', '^ \\r\\n$', '^\\|$', '^00$', '^01$', '^02$', '^ $', '^1$',
                '^\\xff$', '^1\\0$', '^A$', '^Q$', '^x0$', '^\\0\\0$', '^\\x01$', '^0\\0$']:
                continue

            # 人工配置为忽略的规则，直接丢弃
            if rule['m'] in self.ignore_rules:
                continue
                
            tmp_rules.append(rule)

            new_rule = copy.deepcopy(rule)
            # 预加载正则表达式
            try:
                new_rule['r'] = re.compile(bytes(new_rule['m'], encoding="utf-8"), new_rule['mf'])
                new_rule['ports'] = self.parsePorts(new_rule['ports'])                
            except:
                self.log('Match rule parse error:', LogLevel.ERROR)
                self.log(new_rule['m'], LogLevel.ERROR)

            self.rules.append(new_rule)
        
        self._ruleCount = len(self.rules)
        self._writefile(converted_rule_path, json.dumps({'hash': file_hash, 'apps': tmp_rules}, indent=2, sort_keys=True))

    def parsePorts(self, ports):
        """
        解析指纹匹配的端口列表，方便后面匹配
        :param ports: 端口列表
        """
        results = {}
        for _ in ports.split(','):
            try:
                parts = _.split('-')
                portStart = int(parts[0])
                portEnd = int(parts[-1])
                for i in range(portStart, portEnd + 1):
                    results[i] = None
            except:
                continue

        return list(results.keys())

    def analyze(self, data):
        """
        分析获取指纹
        :param data: TCP响应数据包
        :return: 指纹列表，例如：[{'name':'XXX','version':'XXX',...}]
        """
        result = []
        for rule in self.rules:
            try:
                m = rule['r'].search(data)
                if m:
                    app = {
                        'name': rule['p'],
                        'version': rule['v'],
                        'info': rule['i'],
                        'os': rule['o'],
                        'device': rule['d'],
                        'service': rule['s'],
                        'ports': rule['ports']
                    }
                    if m.lastindex:
                        for i in range(m.lastindex + 1):
                            skey = '${}'.format(i)
                            for k in app:
                                if not app[k]: continue

                                if skey in app[k]:
                                    app[k] = app[k].replace(skey, str(m.group(i), 'utf-8', 'ignore'))
                    
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
                self.log(e, LogLevel.ERROR)
                self.log(traceback.format_exc(), LogLevel.ERROR)
                self.log('[!] Hited Rule: ' + str(rule), LogLevel.ERROR)
        
        return result

    def execute(self, msg):
        """
        插件入口函数，根据插件的功能对 msg 进行处理
        :param msg: 需要处理的消息
        :return: 返回需要更新的消息字典（不含原始消息）
        """
        if 'pro' not in msg or msg['pro'] != 'TCP':
            self.log('Not tcp message.', LogLevel.DEBUG)
            return

        info = {}
        if 'data' not in msg or not msg['data']:
            self.log('data field not found.')
            return
        
        # 识别指纹
        apps = self.analyze(bytes.fromhex(msg['data']))
        
        # 识别端口匹配度，匹配的可信度为空，不匹配的可信度为50
        for i in range(len(apps)):
            confidence = 50

            ports = apps[i].pop('ports', [])
            if len(ports) == 0:
                confidence = 100
            elif msg['port'] in ports:
                confidence = 100
            
            apps[i]['confidence'] = confidence
            
            # SSL 协议映射处理
            if apps[i]['service'] == 'ssl' and msg['port'] in self.ssl_portmap:
                apps[i]['service'] = self.ssl_portmap[msg['port']]

        info['apps'] = apps

        return info

if __name__ == '__main__':
    plugins = Plugin.loadPlugins(os.path.join(os.path.dirname(__file__), ".."), True)
    print(plugins)
    msg = {
        "ip_num": 1875787536,
        "ip": "111.206.63.16",
        "port": 443,
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
        #"data": "004a56978183000100000000000013616c6572746d616e616765722d6d61696e2d3115616c6572746d616e616765722d6f706572617465640a6d6f6e69746f72696e67037376630000ff0001",

        # Example: SMTP
        #"data": '32323020736d74702e71712e636f6d2045736d7470205151204d61696c205365727665720d0a',
        
        # Example: RDP
        #"data": "030000130ed000001234000209080002000000",

        # Example:HTTPS
        "data": "1603030ce50200005b03035f6d463e6b8d09d43230d15d3e64ab61fb9e54317099b2c53c9dafd30e509297206abe5bc2265b6d09710c81877859d85a1218e5a27e5805fa0d9d47b2dbfe9f69009c000013000000000010000b000908687474702f312e310b000c7e000c7b0008313082082d30820715a0030201020210644a68f011861931192823728fbe1545300d06092a864886f70d01010b05003062311c301a060355040313134170706c65204953542043412032202d2047313120301e060355040b131743657274696669636174696f6e20417574686f7269747931133011060355040a130a4170706c6520496e632e310b3009060355040613025553301e170d3139303331353233313732395a170d3231303431333233313732395a30773117301506035504030c0e2a2e6c732e6170706c652e636f6d31253023060355040b0c1c6d616e6167656d656e743a69646d732e67726f75702e35373634383631133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e6961310b300906035504061302555330820122300d06092a864886f70d01010105000382010f003082010a0282010100cf9390dba34c1b7fb02fb550891bd89849747501fecbb8c6df45ead2ccf00341e11d43a5b6d78054493bb92095efbd2f19df07e18ae81f8cda4c7b996722ff99eb68a3e7ce9d967ccae05128040498b93493a717ce2e367a647750ec5523194005a6f6d1c98c8e28181021b3d5d1971741158e13d8d658272de9ddf2c211e8e2fbfce6e7a116270301d492bff6dcc26157ff562dd596a1a3b4a385d63cfaa1988dcea8365ff006e9bbf2bb9fbc9de954ca41ec6ac4706a1c8ea3962b97930a7cad1e63da24ce2e871999ed2f7ab354b603dfd09dc1edf11226d79caa6a509b0fce9004ea346f5351cb0967b7a5c079bf4299ea3b954709359303a90aa028f51f0203010001a38204c8308204c4300c0603551d130101ff04023000301f0603551d23041830168014d87a94447c907090169edd179c01440386d62a29307e06082b0601050507010104723070303406082b060105050730028628687474703a2f2f63657274732e6170706c652e636f6d2f6170706c6569737463613267312e646572303806082b06010505073001862c687474703a2f2f6f6373702e6170706c652e636f6d2f6f63737030332d6170706c656973746361326731323030190603551d1104123010820e2a2e6c732e6170706c652e636f6d3081ff0603551d200481f73081f43081f1060a2a864886f76364050b043081e23081a406082b060105050702023081970c819452656c69616e6365206f6e207468697320636572746966696361746520627920616e7920706172747920617373756d657320616363657074616e6365206f6620616e79206170706c696361626c65207465726d7320616e6420636f6e646974696f6e73206f662075736520616e642f6f722063657274696669636174696f6e2070726163746963652073746174656d656e74732e303906082b06010505070201162d687474703a2f2f7777772e6170706c652e636f6d2f6365727469666963617465617574686f726974792f727061301d0603551d250416301406082b0601050507030206082b0601050507030130370603551d1f0430302e302ca02aa0288626687474703a2f2f63726c2e6170706c652e636f6d2f6170706c6569737463613267312e63726c301d0603551d0e041604143fc6bb3b828a044930a9813a6824cc0d7388e597300e0603551d0f0101ff0404030205a03082026d060a2b06010401d6790204020482025d048202590257007600bbd9dfbc1f8a71b593942397aa927b473857950aab52e81a909664368e1ed1850000016983ae8f950000040300473045022100baa8d2a6d8f3b68959c063775735c8cffd1450afe792c79efb6225258f41de10022076f6fbf8f9bea11ace1c596f5c39f35804e036329e4fb831298f8901927f668a007500a4b90990b4",

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
