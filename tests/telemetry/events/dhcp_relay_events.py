#! /usr/bin/env python3

import logging
from run_events_test import run_test
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)
tag = "sonic-events-dhcp-relay"

INTERFACE = "Vlan1000"
IPV4_ADDRESS = ""
IPV6_ADDRESS = ""


def test_event(duthost, gnxi_path, ptfhost, ptfadapter, data_dir, validate_yang):
    logger.info("Beginning to test dhcp-relay events")
    backup_ip_address(duthost)
    try:
        run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, invoke_dhcp_relay_bind_failure,
                 "dhcp_relay_bind_failure.json", "sonic-events-dhcp-relay:dhcp-relay-bind-failure", tag)

    finally:
        restart_dhcp_container(duthost)


def restart_dhcp_container(duthost):
    duthost.shell("systemctl reset-failed dhcp_relay")
    duthost.shell("systemctl restart dhcp_relay")
    is_dhcp_relay_running = wait_until(100, 10, 0, duthost.is_service_fully_started, "dhcp_relay")
    assert is_dhcp_relay_running, "DHCP RELAY not running"


def backup_ip_address(duthost):
    # grab ip_addresses with subnet mask
    interface_facts = duthost.interface_facts()['ansible_facts']['ansible_interface_facts']
    global IPV4_ADDRESS, IPV6_ADDRESS
    IPV4_ADDRESS = interface_facts[INTERFACE]['ipv4']['address']
    IPV6_ADDRESS = interface_facts[INTERFACE]['ipv6']['address']
    assert IPV4_ADDRESS is not "" and IPV6_ADDRESS is not ""


def flush_ip_address(duthost):
    duthost.shell("ip address flush dev {}".format(INTERFACE))


def restore_ip_address(duthost):
    duthost.shell("ip address add {} dev {}".format(IPV4_ADDRESS, INTERFACE))
    duthost.shell("ip address add {} dev {}".format(IPV6_ADDRESS, INTERFACE))


def invoke_dhcp_relay_bind_failure(duthost):
    flush_ip_address(duthost)
    restart_dhcp_container(duthost)
    time.sleep(30)  # dhcp retries to bind to socket 6 times with 5 sec after each retry
    # src: https://github.com/sonic-net/sonic-dhcp-relay/blob/2b33d76dbac69d3d9ad9e9f2d37252db525f07b9/src/relay.cpp#L714
    restore_ip_address(duthost)
