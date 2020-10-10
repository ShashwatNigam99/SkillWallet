# sudo docker build -f certifier/Dockerfile -t dockersub30/sawtooth-digital-id:certifier-cli .
# sudo docker run -it -d  --name certifierwallet  dockersub30/sawtooth-digital-id:certifier-cli /bin/bash
# sudo docker exec -it certifierwallet ./certifier/certifier_wallet.py process_request -a ajlkfjaldfj412343akjra
# sudo docker exec -it certifierevent ./certifier/certifier_events_cli.py certifier1
# sudo docker container stop certifierevent
# sudo docker container rm certifierevent

FROM dockersub30/sawtooth-digital-id:bionic_bsddb

RUN \
 apt-get update; \
 apt-get install software-properties-common -y; \
 apt-get update; \
 apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 8AA7AF1F1091A5FD \
 && apt-add-repository "deb [arch=amd64] http://repo.sawtooth.me/ubuntu/chime/stable bionic universe"\
 && apt-get update \
 && apt-get install -y -qq \
    apt-transport-https \
    ca-certificates \
    python3-requests\
    python3-cbor; \
 apt-get update; \
 apt-get install -y -q python3-sawtooth-sdk \
                       python3-sawtooth-cli \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

EXPOSE 8008

ENV PATH "$PATH:/project:/usr/lib/python3/dist-packages:/usr/lib/python2.7/dist-packages"


COPY . /project
WORKDIR /project

CMD echo "----building certifier-cli----"
