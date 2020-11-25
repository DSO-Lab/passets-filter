FROM docker.io/ubuntu:18.04

LABEL maintainer="tanjelly@gmail.com" version="1.0.0"

USER root

ENV TZ="CST-8" ELASTICSEARCH_URL="localhost:9200" ELASTICSEARCH_INDEX="logstash-passets" THREADS=5 BATCH_SIZE=20 CACHE_SIZE=1024 CACHE_TTL=120 MODE=1 DEBUG=1

COPY src/ /opt/filter/

WORKDIR /opt/filter/

RUN apt-get update && \
    apt-get install -y python3 python3-pip && \
    pip3 install -r requirements.txt && \
    apt-get clean all && \
    apt-get autoclean && \
    apt-get autoremove

ENTRYPOINT ["sh", "-c", "python3 /opt/filter/main.py -H $ELASTICSEARCH_URL -i $ELASTICSEARCH_INDEX -t $THREADS -b $BATCH_SIZE -c $CACHE_SIZE -T $CACHE_TTL -m $MODE -d $DEBUG"]