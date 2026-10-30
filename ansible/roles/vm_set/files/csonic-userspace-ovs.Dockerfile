ARG CSONIC_BASE_IMAGE=docker-sonic-vs
FROM debian:bookworm AS ovs-builder

RUN sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        devscripts \
        dpkg-dev \
        equivs \
        fakeroot \
    && DEBIAN_FRONTEND=noninteractive apt-get build-dep -y openvswitch \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN apt-get update \
    && apt-get source openvswitch \
    && rm -rf /var/lib/apt/lists/*
COPY openvswitch-lacp-rx-multiplier.patch /tmp/
RUN ovs_src="$(find /build -mindepth 1 -maxdepth 1 -type d -name 'openvswitch-*' | head -1)" \
    && cd "${ovs_src}" \
    && patch -p1 < /tmp/openvswitch-lacp-rx-multiplier.patch \
    && DEB_BUILD_OPTIONS="nocheck nodoc parallel=$(nproc)" \
        dpkg-buildpackage -b -uc -us \
    && mkdir /ovs-debs \
    && cp ../openvswitch-common_*.deb \
          ../openvswitch-switch_*.deb \
          ../python3-openvswitch_*.deb \
          /ovs-debs/

ARG CSONIC_BASE_IMAGE=docker-sonic-vs
FROM ${CSONIC_BASE_IMAGE}

COPY --from=ovs-builder /ovs-debs /tmp/ovs-debs
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        /tmp/ovs-debs/*.deb \
    && rm -rf /tmp/ovs-debs /var/lib/apt/lists/*
