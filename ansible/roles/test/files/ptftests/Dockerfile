FROM debian:bullseye

# Install system tools and dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    iproute2 \
    iputils-ping \
    net-tools \
    procps \
    tcpdump \
    curl \
    bash \
    vim \
    wget \
    tar \
    make \
    gcc \
    unzip \
    ca-certificates \
    && apt-get clean

# Make `python` point to `python3`
RUN ln -s /usr/bin/python3 /usr/bin/python

# Install Go 1.23.4 manually
RUN wget https://go.dev/dl/go1.23.4.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz && \
    rm go1.23.4.linux-amd64.tar.gz

# Set Go environment variables
ENV PATH="/usr/local/go/bin:$PATH"
ENV GOPATH="/go"

# Install Python packages including grpcio-tools for proto compilation
RUN pip3 install --upgrade pip && \
    pip3 install pygnmi scapy pytest netmiko paramiko grpcio grpcio-tools

# Copy pre-cloned gnxi directory into the image
COPY ../gnxi /root/gnxi

# Compile gNMI protos for py_gnmicli
RUN python3 -m grpc_tools.protoc \
    -I/root/gnxi/oc_config_validate/oc_config_validate/gnmi \
    --python_out=/root/gnxi/gnmi_cli_py \
    --grpc_python_out=/root/gnxi/gnmi_cli_py \
    gnmi.proto gnmi_ext.proto

# Copy your PTF test files into the container
COPY . /root/ptftests

# Set working directory for tests
WORKDIR /root/ptftests

# Keep container running
CMD [ "bash" ]

