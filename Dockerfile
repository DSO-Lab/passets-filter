FROM rackspacedot/python37:latest

LABEL maintainer="tanjelly@gmail.com" version="1.0.0"

USER root

ENV TZ="Asia/Shanghai" ELASTICSEARCH_URL="localhost:9200" ELASTICSEARCH_INDEX="logstash-passets" RANGE="2m" THREADS=10 CACHE_SIZE=1024 DEBUG=0

COPY src/ /opt/filter/

WORKDIR /opt/filter/

RUN pip3 install -r requirements.txt && \
    apt-get clean all && \
    apt-get autoclean && \
    apt-get autoremove

ENTRYPOINT ["sh", "-c", "python3 /opt/filter/main.py -H $ELASTICSEARCH_URL -i $ELASTICSEARCH_INDEX -r $RANGE -c $CACHE_SIZE -t $THREADS -d $DEBUG"]
