# Passets 被动资产识别框架数据清洗模块插件开发说明

### 插件工作原理

```
              原始数据
[ElasticSearch] ---→ [passets-filter]
    ↑                      ↓
    |                   Plugin 1
    │                      ↓
    │                   Plugin 2
    │                      ↓
    │                   ... ...
    │                      |
    ╰----------------------╯
       处理后产生的新数据        
```

### 插件配置文件说明

插件按照配置文件中定义的顺序来进行数据处理，通过配置文件，使用者可以仅开启部分必须的插件，以提交处理效率。
插件配置文件为 config/plugin.yml，配置文件的结构如下：
```
xxxx:                  # 插件名，同时也是插件文件名
  enable: true         # 插件开关：true - 启用，false - 停用
  index: 1             # 插件的执行顺序，使用0以上的整数，数据越小越优先
  xxxxx:               # 当前插件的自定义参数，在初始化的时候传入插件
```

ip 插件的配置实例：

```
ip:                                 # 插件名称
  enable: true                      # 启用该插件
  index: 1                          # 插件处理顺序为 1
  inner_ips:                        # 内部IP地址范围定义
    - 10.0.0.0-10.255.255.255
    - 172.16.0.0-172.31.255.255
    - 192.168.0.0-192.168.255.255
    - 169.254.0.0-169.254.255.255
    - 127.0.0.1-127.0.0.255
```

### 文件说明

插件必须放置于应用路径下的 `plugins` 目录下，该目录下的 `__init__.py` 和 `plugin.py` 必须保留，并且不建议用户修改。
```
src                      # 代码目录
  plugins                # 插件存放目录
    __init__.py          # 模块初始化脚本
    plugin.py            # 数据清洗插件基类，所有插件均需继承此类
```

### 插件的代码结构

```
from plugin import Plugin

class FilterPlugin(Plugin):

    def __init__(self, rootdir, debug=False):
        """
        构造函数
        :param rootdir: 应用根目录
        :param debug: 调试开关
        """
        super().__init__(rootdir, debug)

        # 此处编写本插件的初始化代码
        # 注：如果插件没有额外的初始化操作，可以无需实现 __init__() 方法。
        ... ...
    
    def execute(self, msg):
        """
        插件入口函数，根据插件的功能对 msg 进行处理
        :param msg: 需要处理的消息(字典类型)
        """
        # 此处编写本插件的业务处理代码
        ... ...
        
        # 返回插件产生的新数据字典（不含原数据），没有产生数据则返回 None
        return new_msg

```

插件执行过程中，可以调用 `self.log(msg, level)` 来输出必要的信息，消息分为以下三类：

| 消息标识 |  输出前缀  | 说明
|----------|------------|--------------------------------|
|  INFO    |  [!]       | 普通信息
|  ERROR   |  [-]       | 错误信息
|  DEBUG   |  [D]       | 调试信息，只有开启调试后才会输出



### 插件测试

开发者可以在插件脚本的 __main__ 代码块来编写插件的测试代码，实例如下：

```
if __name__ == '__main__':

    # 应用根目录（通常为plugins目录的上层目录）
    rootdir = '/opt/filter/'
    
    # 是否开启调试模式
    debug = True
    
    # 初始化插件
    plugin = FilterPlugin(rootdir, debug)
    
    # 测试输入数据
    msg = {
        'pro': 'TCP',
        'ip': '192.168.1.121',
        'port': 80,
        'data': 'AAAAAAAAAAAAAAAAAAAA'
    }
    
    # 执行插件
    new_msg = plugin.execute(msg)
    
    # 判断插件返回结果
    if new_msg:
        print(u'插件返回了数据！')
    else:
        print(u'插件没有返回数据！')
```

然后，直接在 IDE（集成开发工具）或者是命令上下直接运行该插件脚本：

在命令行下执行插件脚本的方法：
```
$ cd plugins
$ python3 xxxx.py
```