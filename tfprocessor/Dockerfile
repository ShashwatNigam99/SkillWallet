# sudo docker build -f tfprocessor/Dockerfile -t dockersub30/sawtooth-digital-id:digitalid_tp .
# sudo docker run -it -d  --name digitalid3  digitalid_tp /bin/bash
# sudo docker exec -it digitalid3 python3 ./tfprocessor/digitalid_tp.py
# sudo docker container stop digitalid3
# sudo docker container rm digitalid3

FROM dockersub30/sawtooth-digital-id:bionic_bsddb

RUN \
 apt-get update; \
 apt-get install gnupg -y; \
 apt-get update; \
 apt-get install software-properties-common -y; \
 apt-get update; \
 apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 8AA7AF1F1091A5FD \
 && apt-add-repository "deb [arch=amd64] http://repo.sawtooth.me/ubuntu/chime/stable bionic universe"

RUN apt-get update; \
    apt-get install -y -qq \
    apt-transport-https \
    build-essential \
    ca-certificates \
    python3-requests\
    python3-cbor; \
 apt-get update; \
 apt-get install -y -q sawtooth

RUN apt-get update; \
  apt-get install -y -q sawtooth sawtooth-pbft-engine; \
  apt-get update; \
  apt-get clean \
  && rm -rf /var/lib/apt/lists/*

EXPOSE 4004/tcp
EXPOSE 8008/tcp

ENV PATH "$PATH:/project:/usr/lib/python3/dist-packages:/usr/lib/python2.7/dist-packages:/usr/lib/python3.6"


COPY . /project
WORKDIR /project

CMD echo "----build successful: digitalid_tp----"
	
