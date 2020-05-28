FROM ubuntu:18.04

ENV TERM=vt100
ENV GOLANG_VERSION 1.13.8

RUN apt-get update && apt-get install -y wget && \
  rm -rf /var/lib/apt/lists/*

ENV http_proxy=http://proxy.esl.cisco.com:80
ENV HTTP_PROXY=http://proxy.esl.cisco.com:80
ENV https_proxy=http://proxy.esl.cisco.com:80
ENV HTTPS_PROXY=http://proxy.esl.cisco.com:80
ENV GO111MODULE="off"
RUN wget "https://storage.googleapis.com/golang/go$GOLANG_VERSION.linux-amd64.tar.gz"
RUN ls

RUN tar -C /usr/local -xzf *go*.gz

RUN apt-get update && apt-get install \
  -y python3 build-essential libffi-dev python-dev \
  libxml2-dev libxslt-dev libmysqlclient-dev \
  openssh-server python3-dev git python3-pip vim unzip curl

RUN apt-get update && apt-get install \
  -y libssl1.0

RUN mkdir -p /root/gperf/src /go/bin && chmod -R 777 /root/gperf
ENV GOROOT /usr/local/go
ENV GOPATH /root/gperf
ENV GOBIN /usr/local/go/bin/
WORKDIR /root/gperf
ENV PATH /usr/local/go/bin:$PATH:$GOROOT:$GOPATH

RUN pip3 install --upgrade pip
RUN pip3 install grpcio-tools
RUN curl -OL https://github.com/google/protobuf/releases/download/v3.2.0/protoc-3.2.0-linux-x86_64.zip
RUN unzip protoc-3.2.0-linux-x86_64.zip -d protoc3
RUN mv protoc3/bin/* /usr/local/bin/
RUN mv protoc3/include/* /usr/local/include/

# Install dependencies:
COPY docker_startup_env /root/gperf/
COPY create_go_repos.sh /root/gperf/src/
RUN mkdir -p /root/gperf/src/github.com/openconfig/
COPY gnmitest /root/gperf/src/github.com/openconfig/gnmitest
RUN /root/gperf/src/create_go_repos.sh

ENV no_proxy = .cisco.com
ENV PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION='python'
	
CMD tail -f /dev/null
