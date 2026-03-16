FROM ubuntu:jammy

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=US/Pacific

RUN apt -y update \
    && apt -y upgrade \
    && apt -y install build-essential \
    && apt -y install git \
    && apt -y install wget \
    && apt -y install python3 \
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
    && apt -y install snmptrapd \
    && apt -y install default-jre unzip zip curl
COPY . /keysight
WORKDIR /keysight

RUN pip install --no-cache-dir -r ./spytest.txt

# https://downloads.ixiacom.com/support/downloads_and_updates/public/ixnetwork/9.30/IxNetworkAPI9.30.2212.7Linux64.bin.tgz
RUN bash ./IxNetworkAPI9.30.2212.7Linux64.bin -i silent \
    && pip install --no-cache-dir -r /opt/ixia/ixnetwork/9.30.2212.7/lib/PythonApi/requirements.txt
ENV SCID_TGEN_PATH=/opt
ENV SCID_TCL85_BIN=/opt
ENV IXNETWORK_VERSION=9.30.2212.7
ENV HLAPI_VERSION=9.30.2212.6

RUN pip install allure-pytest requests monotonic ixnetwork_restpy
ENV ALLURE_VERSION=2.27.0
# ADD https://github.com/allure-framework/allure2/releases/download/${ALLURE_VERSION}/allure-${ALLURE_VERSION}.tgz  /opt/
RUN wget -qO- https://github.com/allure-framework/allure2/releases/download/${ALLURE_VERSION}/allure-${ALLURE_VERSION}.tgz | tar -xz -C /opt
RUN ln -sf "/opt/allure-${ALLURE_VERSION}/bin/allure" /usr/bin/allure
RUN pip install -U pytest

LABEL author="Mircea Dan Gheorghe"
LABEL version="1.0"
LABEL description="SpyTest with Keysight traffic generator"
