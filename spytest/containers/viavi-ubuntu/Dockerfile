FROM ubuntu:24.04

LABEL maintainer="VIAVI TestCenter Team"
LABEL version="1.0"
LABEL description="SPyTest sonic-mgmt tester image with VIAVI TestCenter (STC) on Ubuntu 24.04"

ARG DEBIAN_FRONTEND=noninteractive
ARG stc_version=5.62

ENV TZ=UTC \
    STC_TCL=/usr/bin/tclsh \
    TCLLIBPATH=/projects/scid/tgen/stc/Spirent_TestCenter_${stc_version}/Spirent_TestCenter_Application_Linux/ \
    PYTHONPATH=/projects/scid/tgen/stc/Spirent_TestCenter_${stc_version}/Spirent_TestCenter_Application_Linux/API/Python:/projects/scid/tgen/stc/Spirent_TestCenter_${stc_version}/Spirent_TestCenter_Application_Linux/HltAPI/SourceCode/hltapiForPython \
    STC_PRIVATE_INSTALL_DIR=/projects/scid/tgen/stc/Spirent_TestCenter_${stc_version}/Spirent_TestCenter_Application_Linux \
    PATH=$PATH:/testcenter

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python-is-python3 \
        python3-setuptools \
        tcl \
        tclx \
        tdom \
        tcllib \
        iputils-ping \
        sudo \
        gnupg \
        wget \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Use uv instead of system pip to avoid Ubuntu 24.04 PEP 668 restriction.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Create Python virtual environment for test dependencies.
RUN uv venv --system-site-packages /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN mkdir -p /projects/scid/tools/ActivTcl/current && \
    ln -sf /usr/bin /projects/scid/tools/ActivTcl/current/bin

COPY spytest.txt /tmp/spytest.txt
RUN uv pip install --no-cache -r /tmp/spytest.txt && \
    rm /tmp/spytest.txt

ARG stc_installer=install_Spirent_TestCenter_Auto_Linux64_${stc_version}.sh
COPY $stc_installer /projects/scid/tgen/stc/$stc_installer
RUN chmod +x /projects/scid/tgen/stc/$stc_installer && \
    /projects/scid/tgen/stc/$stc_installer -d /projects/scid/tgen/stc -t No -p spirent && \
    rm /projects/scid/tgen/stc/$stc_installer

WORKDIR /testcenter
