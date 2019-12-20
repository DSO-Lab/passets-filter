FROM rackspacedot/python37:latest

LABEL maintainer="tanjelly@gmail.com" version="1.0.0"

USER root

ENV TZ="Asia/Shanghai" ELASTICSEARCH_URL="localhost:9200" ELASTICSEARCH_INDEX="logstash-passets" RANGE="2m" THREADS=10 CACHE_SIZE=1024 DEBUG=0

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

ENTRYPOINT ["sh", "-c", "python3 /opt/filter/main.py -H $ELASTICSEARCH_URL -i $ELASTICSEARCH_INDEX -r $RANGE -c $CACHE_SIZE -t $THREADS -d $DEBUG"]
