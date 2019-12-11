# Passets 被动资产识别框架数据清洗模块

### 简介

本模块主要用于对收集的被动资产原始数据进行二次加工，所有的加工都采用插件的方式进行，目前已经完善了以下插件。

| 插件名     | 功能简介                           | 配置项
|------------|------------------------------------|----------------------------------|
| ip         | 计算IP数值，识别内网IP             | enable, index, inner_ips
| wappalyzer | 识别HTTP类数据中的资产指纹信息     | enable, index
| nmap       | 识别TCP类数据中的资产指纹信息      | enable, index
| urlparse   | 拆分URL，识别站点、路径、路径模板  | enable, index

> Wappalyzer 插件

基于 URL、HTTP 响应头、HTTP响应正文来识别站点指纹信息。

指纹库及识别引擎基于 [Wappalyzer](https://github.com/AliasIO/Wappalyzer/) 修改。

> NMAP 插件

基于 TCP 响应报文来识别目标服务的指纹信息。

指纹库基于 [NMAP](https://github.com/nmap/nmap/) 项目中的 `nmap-service-probes` 指纹库。

### 文件说明

```
Dockerfile               # 容器环境配置文件
docker-compose.yml       # 容器启动配置文件
src                      # 核心代码文件
  config/plugin.yml      # 数据清洗插件配置文件
  plugins                # 数据清洗插件存放路径
    plugin.py            # 数据清洗插件基类，所有插件均需继承此类
    ... ...
  rules                  # 指纹规则库存放路径
    apps.json            # Wappalyzer Web 应用指纹库
    nmap-service-probes  # NMAP 端口服务指纹库
  wappalyzer             # Wappalyzer 主程序目录（基于 5.8.4 版本修改）
    ... ...
  main.py                # 主程序
  requirements.txt       # 程序依赖库清单
```

[最新Web应用指纹库下载](https://github.com/AliasIO/Wappalyzer/raw/master/src/apps.json)

[最新端口服务指纹库下载](https://github.com/nmap/nmap/raw/master/nmap-service-probes)

### 清洗程序执行说明
 
清洗程序是一个基于 Python3 开发的脚本应用程序。

命令行参数如下：
```
用法: python3 main.py [OPTIONS] arg

OPTIONS:
  --version                     输出版本信息
  -h, --help                    显示命令行帮助信息
  -H HOST, --host=HOST          设置 Elasticsearch 服务器地址/地址:端口
  -i INDEX, --index=INDEX       设置 Elasticsearch 索引名，默认为passets
  -t THREADS, --threads=THREADS 设置并发线程数量，默认为1个线程
  -c CACHE_SIZE --cache-size=CACHE_SIZE 设置处理缓存的大小
  -d DEBUG, --debug=DEBUG       调试信息开关，0-关闭，1-开启
```

使用示例：

```
# 并发10个线程处理 192.168.1.2:9200 中 passets 索引下的数据，执行过程输出调试信息
python3 main.py -H 192.168.1.2:9200 -i passets -t 10 -d 1
```

### 清洗程序配置说明

配置文件路径为 `config/plugin.yml`。

配置实例：
```
ip:                                 # 插件名称（必须跟插件脚本文件名一致）
  enable: true                      # 插件是否启用，true为启用
  index: 1                          # 插件处理顺序号（0及以上整数，不可重复，数值越小越优先）
  inner_ips:                        # 内部IP地址定义（默认使用RFC定义的私有地址范围）
    - 10.0.0.0-10.255.255.255
    - 172.16.0.0-172.31.255.255
    - 192.168.0.0-192.168.255.255
    - 169.254.0.0-169.254.255.255
    - 127.0.0.1-127.0.0.255

url:
  enable: false                     # 插件是否启用，false为停用
  index: 2

wappalyzer:
  enable: false
  index: 3

nmap:
  enable: false
  index: 4
```


### 容器化部署说明

#### 容器构建

Dockerfile:
```
FROM rackspacedot/python37:latest

LABEL maintainer="tanjelly@gmail.com" version="1.0.0"

USER root

ENV TZ="Asia/Shanghai" ELASTICSEARCH_HOST="localhost:9200" ELASTICSEARCH_INDEX="passets" THREADS=10 CACHE_SIZE=1024 DEBUG=0

COPY src/ /opt/filter/

WORKDIR /opt/

RUN curl https://nodejs.org/dist/v8.16.2/node-v8.16.2-linux-x64.tar.xz -o node.tar.xz && \
    mkdir /opt/node && tar -C /opt/node --strip-components=1 -xf node.tar.xz && rm -f node.tar.xz && \
    ln -s /opt/node/bin/node /usr/bin/node && \
    ln -s /opt/node/bin/npm /usr/bin/npm && \
    ln -s /opt/node/bin/npx /usr/bin/npx && \
    cd /opt/filter/ && pip3 install -r requirements.txt && \
    cd /opt/filter/wappalyzer/ && /usr/bin/npm install && \
    apt-get clean all && \
    apt-get autoclean && \
    apt-get autoremove

ENTRYPOINT ["sh", "-c", "python3 /opt/filter/main.py -H $ELASTICSEARCH_HOST -i $ELASTICSEARCH_INDEX -t $THREADS -c $CACHE_SIZE -d $DEBUG"]
```

docker-compose.yml

```
version: "3"

services:
  filter:
    build: .
    image: passets-filter:<tag>
    container_name: passets-filter
    environment:
      - ELASTICSEARCH_HOST=<elasticsearch-host>:9200
      - ELASTICSEARCH_INDEX=passets
      - THREADS=20
      - CACHE_SIZE=1024
      - DEBUG=0
```

构建命令：

```
docker build -t passets-filter:<tag> .
或者
docker-compose build
```

### 容器启动

> 使用 docker 命令启动：

```
# 基本命令：
docker run -it passets-filter:<tag>

# 使用新的配置文件启动：
docker run -it passets-filter:<tag> -v ./config/plugin.yml:/opt/filter/config/plugin.yml -e $ELASTICSEARCH_HOST=<elasticsearch>:9200 -e ELASTICSEARCH_INDEX=passets
```

使用 docker-compose 启动：

```
docker-compose up -d
```

