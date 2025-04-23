FROM debian:bullseye

# Install basic system tools, Go, and Python dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-subnettree \
    iproute2 \
    iputils-ping \
    net-tools \
    tcpdump \
    procps \
    curl \
    bash \
    vim \
    git \
    sshpass \
    sudo \
    python3-setuptools \
    openssh-client \
    wget \
    tar \
    && apt-get clean

# Install Python libraries for PTF testing
RUN pip3 install --upgrade pip && \
    pip3 install \
    ptf \
    scapy \
    pytest \
    six \
    paramiko \
    retrying \
    PyYAML

# Link python3 to python
RUN ln -s /usr/bin/python3 /usr/bin/python

# Install Go
RUN wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz && \
    rm go1.22.0.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/go"

# Clone and build gnmi_cli from openconfig/gnmi
# Clone and build gnmi_cli from openconfig/gnmi
RUN git clone https://github.com/openconfig/gnmi.git /root/gnmi && \
    cd /root/gnmi && \
    go mod tidy && \
    go build -o /usr/bin/gnmi_cli ./cmd/gnmi_cli

# Copy ptftests (your tests) into the container
COPY . /root/ptftests
RUN touch /root/ptftests/__init__.py

WORKDIR /root/ptftests
