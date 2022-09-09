#!/bin/bash

declare -r http_proxy="http://azureproxy.msft.net:8080"
declare -r no_proxy="no_proxy=localhost,127.0.0.1,.phx.gbl,.portal.gbl,osdinfra.net,.ap.gbl,ngstest.trafficmanager.net,dev.networkpolicymanager.radar.core.windows.net,10.3.145.30,10.3.145.55"
declare -r index_url="http://pypi.phx.gbl/root/prod2/+simple/"
declare -r trusted_host="pypi.phx.gbl"
declare -r EXIT_SUCCESS="0"
declare -r EXIT_FAILURE="1"

function log_info() {
    if [[ "${VERBOSE_LEVEL}" -ge "${VERBOSE_INFO}" ]]; then
        echo "INFO: $*"
    fi
}

function log_error() {
    if [[ "${VERBOSE_LEVEL}" -ge "${VERBOSE_ERROR}" ]]; then
        echo "ERROR: $*"
    fi
}

function exit_failure() {
    if [[ "${VERBOSE_LEVEL}" -ge "${VERBOSE_ERROR}" ]]; then
        echo
        log_error "$@"
        echo
    fi

    exit "${EXIT_FAILURE}"
}

function exit_success() {
    if [[ "${VERBOSE_LEVEL}" -ge "${VERBOSE_INFO}" ]]; then
        echo
        log_info "$@"
        echo
    fi

    exit "${EXIT_SUCCESS}"
}

function install_packages_and_dependences() {
    log_info "Start install wan-interops-test packages and dependences ..."
    sudo apt --fix-broken install -y
    sudo apt-get install -y libsnmp-dev --option Acquire::HTTP::Proxy=${http_proxy}
    pip3 install pip==20.2.4 --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install wheel==0.35.1 --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install setuptools==57.4.0 --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install ncclient
    pip3 install libsnmp
    pip3 install hardwareproxyapi --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install hardwareproxy --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install icm-connector --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install kusto-proxy --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install kusto-logging --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install kusto-ingest-client --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install ndm-proxy --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install network-graph-service --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install network-state-service --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install ngs-proxy --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install nss-proxy --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install net-devices2 --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install snmpproxy --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install starlab --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install phynet-credentials --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install flower tornado==5.1.1 --index-url ${index_url} --trusted-host ${trusted_host}
    pip3 install --force-reinstall texttable --index-url ${index_url} --trusted-host ${trusted_host}
    wget https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb
    sudo dpkg -i packages-microsoft-prod.deb
    sudo apt update --option Acquire::HTTP::Proxy=${http_proxy}
    sudo apt install -y dotnet-host --option Acquire::HTTP::Proxy=${http_proxy}
    sudo apt install -y dotnet-runtime-3.1 --option Acquire::HTTP::Proxy=${http_proxy}
    sudo apt install -y dotnet-runtime-deps-3.1 --option Acquire::HTTP::Proxy=${http_proxy}
    sudo apt install -y dotnet-hostfxr-3.1 --option Acquire::HTTP::Proxy=${http_proxy}
}

function verify_packages_cmd() {
   pip3 list | egrep -E "hardwareproxyapi|hardwareproxy|kusto-proxy|kusto-logging|kusto-ingest-client|net-devices2|snmpproxy|ncclient|starlab" | wc -l
}

function verify_packages() {
    if [[ $(verify_packages_cmd) -eq 9 ]]; then
        log_info "All of packages and dependences installed"
    else
        exit_failure "Some of packages missing, please check!!"
    fi
}

function start_service() {
    log_info "Starting kusto_proxy, snmpproxy, icm_proxy and hardwareroxy service ..."
    python3 -m kusto_proxy.proxy &
    python3 -m snmpproxy-proxy --proxied-host snmpproxy.network-prod-mw1p.mw1p.ap.gbl --server-port 9443 &
    python3 -m icm.proxy --certificate /etc/ssl/certs/phynet-icm.pem --private-key /etc/ssl/private/phynet-icm.pem &
    python3 -m hardwareproxy.proxy --proxied-host hardwareproxy.Network-Prod-BL2P.BL2P.ap.gbl &

}

install_packages_and_dependences
verify_packages
start_service

exit_success "Sonic-mgmt wan-interops-test envirnment setup is done!"