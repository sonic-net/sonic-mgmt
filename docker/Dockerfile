FROM ubuntu:18.04

ARG http_proxy
ARG https_proxy
ARG no_proxy

ENV TERM=vt100

RUN apt-get update && apt-get install \
  -y python3 build-essential libffi-dev python-dev \
  libxml2-dev libxslt-dev libmysqlclient-dev \
  openssh-server python3-dev git python3-pip \
  iproute2 vim apt-utils

RUN apt-get update && apt-get install \
  -y libssl1.0

# copy SSH credentials to the root directory in container
#COPY keys/* /root/.ssh/

WORKDIR /root/gd_test 

ENV HTTP_PROXY=$http_proxy
ENV HTTPS_PROXY=$https_proxy
ENV NO_PROXY=$no_proxy

# Install dependencies:
COPY current-req.txt .
COPY docker_startup_env .
RUN pip3 install --upgrade pip
RUN pip3 install wheel
RUN pip3 install setuptools --upgrade
RUN pip3 install -r current-req.txt

# setup cafykit library python path
RUN echo "export PYTHONPATH=/godiva-test:/godiva-test/cafykit/lib" >> ~/.bashrc
RUN echo "export GIT_REPO=/godiva-test/cafykit" >> ~/.bashrc

# Run the application:
ENV PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION='python'
