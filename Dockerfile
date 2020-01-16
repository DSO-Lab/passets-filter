FROM docker.io/ubuntu:18.04

LABEL maintainer="tanjelly@gmail.com" version="1.0.0"

USER root

ENV TZ="Asia/Shanghai" ELASTICSEARCH_URL="localhost:9200" ELASTICSEARCH_INDEX="logstash-passets" RANGE=15 THREADS=10 BATCH_SIZE=20 CACHE_SIZE=1024 SHARD_SIZE=1 REPLICA_SIZE=0 MODE=1 DEBUG=0

COPY src/ /opt/filter/

WORKDIR /opt/filter/

RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    pip3 install -r requirements.txt && \
    apt-get clean all && \
    apt-get autoclean && \
    apt-get autoremove

ENTRYPOINT ["sh", "-c", "python3 /opt/filter/main.py -H $ELASTICSEARCH_URL -i $ELASTICSEARCH_INDEX -t $THREADS -r $RANGE -b $BATCH_SIZE -c $CACHE_SIZE -m $MODE -R $REPLICA_SIZE -s $SHARD_SIZE -d $DEBUG"]