ARG CSONIC_BASE_IMAGE=docker-sonic-vs
FROM ${CSONIC_BASE_IMAGE} AS csonic-base

FROM debian:bookworm AS wpa-builder
ARG SONIC_WPA_SUPPLICANT_REV=6ca19c73b9c868782b59a0d7adc6ff34de5bbdba
ARG SONIC_SWSS_COMMON_REV=10d14ae58ae73899a52a2447d1e791a2b7bd1a34

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        libboost-dev \
        libhiredis-dev \
        libnl-3-dev \
        libnl-genl-3-dev \
        libnl-route-3-dev \
        libreadline-dev \
        libssl-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Build SONiC's supplicant against the cSONiC image's libswsscommon and exact
# runtime libraries. Debian's wpasupplicant does not contain macsec_sonic.
COPY --from=csonic-base /lib/x86_64-linux-gnu/ /runtime-libs/
RUN ln -s /runtime-libs/libswsscommon.so.0.0.0 \
        /usr/lib/x86_64-linux-gnu/libswsscommon.so.0 \
    && ln -s libswsscommon.so.0 \
        /usr/lib/x86_64-linux-gnu/libswsscommon.so \
    && for library in libnl-3 libnl-genl-3 libnl-route-3 libnl-nf-3; do \
        ln -s /runtime-libs/${library}.so.200 /runtime-libs/${library}.so; \
    done \
    && git init -q /src/wpa \
    && git -C /src/wpa remote add origin \
        https://github.com/sonic-net/sonic-wpa-supplicant.git \
    && git -C /src/wpa fetch -q --depth 1 origin "${SONIC_WPA_SUPPLICANT_REV}" \
    && git -C /src/wpa checkout -q FETCH_HEAD \
    && git init -q /src/swsscommon \
    && git -C /src/swsscommon remote add origin \
        https://github.com/sonic-net/sonic-swss-common.git \
    && git -C /src/swsscommon fetch -q --depth 1 origin "${SONIC_SWSS_COMMON_REV}" \
    && git -C /src/swsscommon checkout -q FETCH_HEAD \
    && printf '#ifndef CFG_SCHEMA_H\n#define CFG_SCHEMA_H\n#endif\n' \
        > /src/swsscommon/common/cfg_schema.h \
    && printf '#ifndef SWSS_CONFIG_H\n#define SWSS_CONFIG_H\n#endif\n' \
        > /usr/include/config.h \
    && ln -s /src/swsscommon/common /usr/include/swss \
    && printf '%s\n' \
        'CONFIG_DRIVER_WIRED=y' \
        'CONFIG_DRIVER_MACSEC_LINUX=y' \
        'CONFIG_DRIVER_MACSEC_SONIC=y' \
        'CONFIG_IEEE8021X_EAPOL=y' \
        'CONFIG_MACSEC=y' \
        'CONFIG_CTRL_IFACE=y' \
        'CONFIG_READLINE=y' \
        'CONFIG_BACKEND=file' \
        'CONFIG_MAIN=main' \
        'CONFIG_OS=unix' \
        'CONFIG_ELOOP=eloop' \
        'CONFIG_L2_PACKET=linux' \
        'CONFIG_TLS=openssl' \
        'CONFIG_DEBUG_SYSLOG=y' \
        'CONFIG_GETRANDOM=y' \
        'CFLAGS += -Wno-error=use-after-free -Wno-error=deprecated-declarations' \
        'LDFLAGS += -Wl,-rpath-link,/runtime-libs -L/runtime-libs' \
        > /src/wpa/wpa_supplicant/.config \
    && LIBRARY_PATH=/runtime-libs make -C /src/wpa/wpa_supplicant -j2

FROM csonic-base
COPY --from=wpa-builder /src/wpa/wpa_supplicant/wpa_supplicant /sbin/wpa_supplicant
COPY --from=wpa-builder /src/wpa/wpa_supplicant/wpa_cli /sbin/wpa_cli

RUN printf 'eapol_version=3\nap_scan=0\nfast_reauth=1\n' \
        > /etc/wpa_supplicant.conf \
    && printf '%s\n' \
        '[program:macsecmgrd]' \
        'command=/usr/bin/macsecmgrd' \
        'priority=2' \
        'autostart=false' \
        'autorestart=false' \
        'stdout_logfile=NONE' \
        'stdout_syslog=true' \
        'stderr_logfile=NONE' \
        'stderr_syslog=true' \
        > /etc/supervisor/conf.d/sonic-mgmt-macsec.conf \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openvswitch-switch \
    && rm -rf /var/lib/apt/lists/*
