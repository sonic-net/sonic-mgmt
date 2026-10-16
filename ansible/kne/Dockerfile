FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    qemu-system-x86 \
    bridge-utils \
    iproute2 \
    procps \
    socat \
    telnet \
    net-tools \
    inetutils-ping \
    iptables \
    dnsmasq \
    && rm -rf /var/lib/apt/lists/*
COPY sonic-vs.img /sonic.qcow2
COPY startup.sh /startup.sh
RUN chmod +x /startup.sh
ENTRYPOINT ["/bin/bash", "-c", "/startup.sh"]
