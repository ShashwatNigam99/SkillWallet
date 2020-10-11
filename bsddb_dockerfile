# sudo docker build -f Dockerfile -t dockersub30/sawtooth-digital-id:bionic_bsddb .

FROM ubuntu:bionic

RUN apt-get update \
 && apt-get install -y build-essential \
		       cmake \
		       python3-pip

RUN pip3 install protobuf

COPY . /bsddb
WORKDIR /bsddb

RUN \
 cd db-6.2.32/build_unix \
 && ../dist/configure --prefix=/usr \
		      --enable-compat185 \
		      --enable-dbm \
		      --disable-static \
		      --enable-cxx \
 && make
 
RUN \
 cd db-6.2.32/build_unix \
 && make docdir=/usr/share/doc/db-6.2.32 install

RUN YES_I_HAVE_THE_RIGHT_TO_USE_THIS_BERKELEY_DB_VERSION=1 pip3 install bsddb3

RUN \
  apt-get clean \
  && rm -rf /var/lib/apt/lists/*

CMD bash -c 'echo bsddb installed' \
    && cd db-6.2.32 \
    && rm -rf ./*
	
