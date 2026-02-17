FROM ubuntu:jammy

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=US/Pacific

RUN apt -y update \
    && apt -y upgrade \
    && apt -y install build-essential \
    && apt -y install git \
    && apt -y install wget \
    && apt -y install python3 \
    && apt -y install python-is-python3 \
    && apt -y install python3-setuptools \
    && apt -y install python3-pip \
    && apt -y install python3-tk \
    && apt -y install tk \
    && apt -y install tcl \
    && apt -y install tclx8.4 \
    && apt -y install tcllib \
    && apt -y install tcl-tls \
    && apt -y install iputils-ping \
    && apt -y install snmp \
    && apt -y install snmptrapd
COPY . /keysight
WORKDIR /keysight

RUN pip install --no-cache-dir -r ./spytest.txt

# https://downloads.ixiacom.com/support/downloads_and_updates/public/IxNetwork/11.00-Update1/11.00.2407.67/IxNetworkAPI11.00.2407.37Linux64.bin.tgz
RUN bash ./IxNetworkAPI11.00.2407.37Linux64.bin -i silent \
    && pip install --no-cache-dir -r /opt/ixia/ixnetwork/11.00.2407.37/lib/PythonApi/requirements.txt
ENV SCID_TGEN_PATH=/opt
ENV SCID_TCL85_BIN=/opt
ENV IXNETWORK_VERSION=11.00.2407.37
ENV HLAPI_VERSION=11.00.2407.37

LABEL author="Theresa Kong and Seung Yeop Yang"
LABEL version="11.00.2407"
LABEL description="SpyTest with Keysight traffic generator"
