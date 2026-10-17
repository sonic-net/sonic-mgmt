ARG CSONIC_BASE_IMAGE=docker-sonic-vs
FROM ${CSONIC_BASE_IMAGE}

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openvswitch-switch \
    && rm -rf /var/lib/apt/lists/*
