FROM ubuntu:bionic

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=US/Pacific

RUN apt -y update
RUN apt -y upgrade

RUN apt -y install build-essential
RUN apt -y install git
RUN apt -y install wget

RUN apt -y install python
RUN apt -y install python-setuptools
RUN apt -y install python-pip
RUN apt -y install python-tk
RUN apt -y install tk
RUN apt -y install tcl
RUN apt -y install tclx8.4
RUN apt -y install tcllib
RUN apt -y install tcl-tls


RUN apt -y install iputils-ping
RUN apt -y install snmp
RUN apt -y install snmptrapd

COPY . /keysight
WORKDIR /keysight

RUN pip install --no-cache-dir -r ./spytest.txt

# https://downloads.ixiacom.com/support/downloads_and_updates/public/ixnetwork/9.10/IxNetworkAPI9.10.2007.7Linux64.bin.tgz
RUN bash ./IxNetworkAPI9.10.2007.7Linux64.bin -i silent

RUN pip install --no-cache-dir -r /opt/ixia/ixnetwork/9.10.2007.7/lib/PythonApi/requirements.txt

ENV SCID_TGEN_PATH=/opt
ENV SCID_TCL85_BIN=/opt
ENV IXNETWORK_VERSION=9.10.2007.7
ENV HLAPI_VERSION=9.10.2007.43

LABEL author="Mircea Dan Gheorghe"
LABEL version="1.0"
LABEL description="SpyTest with Keysight traffic generator"
