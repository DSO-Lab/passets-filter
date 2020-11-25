# Passets 被动资产识别框架数据清洗模块

## 简介

本模块主要用于对收集的被动资产原始数据进行二次加工，Elasticsearch 中经过清洗的合法数据（至少包含ip和port字段）会添加 state 字段。state=0表示正在清洗，state=1表示已完成清洗。所有的清洗操作都采用插件的方式进行，目前已支持以下插件。

### Wappalyzer 插件

基于数据中的 URL、HTTP 响应头、HTTP响应正文来识别站点指纹信息。

指纹库及识别引擎基于 [Wappalyzer](https://github.com/AliasIO/Wappalyzer/) 修改。

配置参数：

| 插件参数   | 用途说明
|------------|------------------------------------|
| enable     | 插件开关，true-启用，false-不启用
| index      | 在所有插件中的处理顺序，值越小越优先处理

相关配置文件（指纹规则）：

```
# rules/apps.json
```

### NMAP 插件

基于数据中的 TCP 响应报文来识别目标服务的指纹信息。

指纹库基于 [NMAP](https://github.com/nmap/nmap/) 项目中的 `nmap-service-probes` 指纹库。

配置参数：

| 插件参数   | 用途说明
|------------|------------------------------------|
| enable     | 插件开关，true-启用，false-不启用
| index      | 在所有插件中的处理顺序，值越小越优先处理
| ignore_rules | 忽略的 TCP 指纹规则列表，用 `nmap-service-probes` 中的 `m` 参数值表示，必须完全匹配。
| ssl_portmap  | 指定 ssl 协议数据的端口对应关系列表，例如：`443:https` 表示检测到 ssl 服务时，如果端口为 443 则认定其为 https 服务，过滤后的用 https 覆盖 ssl。

相关配置文件（指纹规则）：

```
# rules/nmap-service-probes
```

### Assets 分类插件

基于指纹识别的结果对目标进行资产分类。

配置参数：

| 插件参数   | 用途说明
|------------|------------------------------------|
| enable     | 插件开关，true-启用，false-不启用
| index      | 在所有插件中的处理顺序，值越小越优先处理，此插件必须在 Wapplayzer、Nmap 插件的后面执行。
| ignore_vendors | 忽略的厂商名称（小写），用于排除一些不想要的厂商名称。

相关配置文件：

#### 资产类型配置文件

```
# rules/http_asset_types.json
{
    "<资产类型名>":[
        <分类编号>, ...
    ]
}
```
用于识别 `pro` 为 `HTTP` 类的流量资产类型。

工作原理：根据指纹分类来确定资产类型。

```
# rules/tcp_asset_types.json
{
    "<资产类型名>":[
        "<关键词>", ...
    ]
}
```
用于识别 `pro` 为 `TCP` 类的流量资产类型。

工作原理：根据指纹设备类型、指纹名称、指纹描述、服务名中的单词来确定设备类型。关键词不区分大小写。

#### 设备类型配置文件

```
# rules/http_device_types.json
{
    "<设备类型名>":[
        "<关键词>", ...
    ]
}
```
用于识别 `pro` 为 `HTTP` 类的流量设备类型。

工作原理：根据指纹名称中的关键词来确定设备类型。

```
# rules/tcp_device_types.json
{
    "<设备类型名>":[
        "<关键词>", ...
    ]
}
```

用于识别 `pro` 为 `TCP` 类的流量设备类型。

工作原理：根据指纹设备类型以及指纹名称、指纹描述中的单词来确定设备类型。关键词不区分大小写。

#### 设备厂商配置文件

```
# rules/vendors.json
[
    "<关键词>", ...
]
```

厂商信息获取有两种方式：

- 对于 `pro` 为 `HTTP` 的流量，可以通过指纹的 `website` 属性提取域名关键词获得，也可以根据指纹名称中的关键词获得；
- 对于 `pro` 为 `TCP` 的流量，仅通过指纹中的 `name`、`info` 和 `device`来获取。关键词区分大小写。

## 运行环境

- Python 3.x
- Nodejs 8.x 及以上

## 文件说明

```
Dockerfile                 # 容器环境配置文件
docker-compose.yml         # 容器启动配置文件
src                        # 核心代码文件
  config/plugin.yml        # 数据清洗插件配置文件
  plugins                  # 数据清洗插件存放路径
    plugin.py              # 数据清洗插件基类，所有插件均需继承此类
    ... ...
  rules                    # 插件相关配置文件存放路径
    ... ...
  main.py                  # 主程序
  requirements.txt         # 程序依赖库清单
```

[最新Web应用指纹库下载](https://github.com/AliasIO/Wappalyzer/raw/master/src/apps.json)

[最新端口服务指纹库下载](https://github.com/nmap/nmap/raw/master/nmap-service-probes)

## 清洗程序执行说明
 
清洗程序是一个基于 Python3 开发的脚本应用程序。

命令行参数如下：
```
用法: python3 main.py [OPTIONS] arg

OPTIONS:
  --version                             输出版本信息
  -h,           --help                  显示命令行帮助信息
  -H HOST,      --host=HOST             设置 Elasticsearch 服务器地址/地址:端口
  -i INDEX,     --index=INDEX           设置 ES 索引名，默认为logstash-passets
  -r RANGE,     --range=RANGE           设置 ES 搜索的时间偏移量，单位为分钟，默认 15 分钟
  -t THREADS,   --threads=THREADS       设置并发线程数量，默认为 10 个线程
  -b BATCH_SIZE --batch-size=BATCH_SIZE 每线程单批处理的数据数量，默认为 20 条。
  -c CACHE_SIZE --cache-size=CACHE_SIZE 设置处理缓存的大小
  -T CACHE_TTL  --cache-ttl=CACHE_TTL   设置处理缓存的过期时间，单位为秒，默认 120 秒
  -m MODE       --mode=MODE             设置工作模式，默认为 1（主），可选值有 0（从）。
  -d DEBUG, --debug=DEBUG               调试信息开关，0-关闭，1-开启
```

**使用示例：**

```
# 并发10个线程处理 192.168.1.2:9200 中 logstash-passets* 索引下的数据，执行过程输出调试信息

# 主节点模式
python3 main.py -H 192.168.1.2:9200 -i logstash-passets -r 5 -t 10 -m 1 -d 1

# 从节点模式
python3 main.py -H 192.168.1.2:9200 -i logstash-passets -r 5 -t 10 -m 0 -d 1
```

在设备性能允许的情况下尽量选用单节点多线程模式，综合对比来看单节点比多节点性能上更优（节点数*线程数）。多节点部署时只能、并且必须有一个主节点。

## 清洗程序配置说明

配置文件路径为 `config/plugin.yml`。

**配置示例：**
```
wappalyzer:
  enable: true
  index: 1

nmap:
  enable: true
  index: 2
  ignore_rules:     # 不处理的规则列表（列表中的规则将不会处理）
    - ^OK$
  ssl_portmap:      # ssl 协议端口映射表
    - 443:https

asset:
  enable: true
  index: 3
  ignore_vendors:   # 要忽略的厂商名称（小写）
    - asp
```


## 容器化部署说明

### 容器构建

配置文件：
[Dockerfile](./Dockerfile)

[docker-compose.yml](./docker-compose.yml)

```
# 使用 docker 命令构建
docker build -t dsolab/passets-filter:<ver> .

# 使用 docker-compose 命令构建
docker-compose build
```

### 容器启动

> 使用 docker 命令启动：

```
# 基本命令：
docker run -it dsolab/passets-filter:<ver>

# 使用新的配置文件、指纹规则启动：
docker run -it passets-filter:<ver> -v $(PWD)/src/config/plugin.yml:/opt/filter/config/plugin.yml -v $(PWD)/src/rules/apps.json:/opt/filter/rules/apps.json -v $(PWD)/src/rules/nmap-service-probes:/opt/filter/rules/nmap-service-probes -e ELASTICSEARCH_URL=<elasticsearch>:9200
# 注：其它参数均使用默认设置
```

> 使用 docker-compose 启动：

```
docker-compose up -d
```

## 自定义数据清洗插件

详见 [插件开发说明](PLUGIN_DEVELOP.md) 。