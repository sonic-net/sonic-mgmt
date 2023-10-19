#! /usr/bin/env python3

import logging
import time
from run_events_test import run_test
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)
tag = "sonic-events-dhcp-relay"


def test_event(duthost, gnxi_path, ptfhost, data_dir, validate_yang):
    logger.info("Beginning to test dhcp-relay events")
    try:
        ipv4_address, ipv6_address, interface = backup_ip_address(duthost)
    except Exception:
        logger.info("Skipping test, no Vlan interface")
        return

    try:
        run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, invoke_dhcp_relay_bind_failure,
                 "dhcp_relay_bind_failure.json", "sonic-events-dhcp-relay:dhcp-relay-bind-failure", tag,
                 False, 30, (ipv4_address, ipv6_address, interface))
    finally:
        restart_dhcp_container(duthost)


def backup_ip_address(duthost):
    # grab ip_addresses with subnet mask
    interface_facts = duthost.show_ip_interface()['ansible_facts']['ip_interfaces']
    # grab first Vlan interface
    interface = next((key for key in interface_facts.keys() if 'Vlan' in key), None)
    ipv4_interface_facts = interface_facts[interface]
    logger.info("ALL IP ADDRESSES: {}".format(duthost.interface_facts()['ansible_facts']['ansible_interface_ips']))
    ipv6_interface_facts = duthost.interface_facts()['ansible_facts']['ansible_interface_facts'][interface]['ipv6'][0]

    ipv4_address = ipv4_interface_facts['ipv4']
    ipv4_prefix_len = ipv4_interface_facts['prefix_len']
    ipv4_address += "/{}".format(ipv4_prefix_len)

    ipv6_address = ipv6_interface_facts['address']
    ipv6_prefix_len = ipv6_interface_facts['prefix']
    ipv6_address += "/{}".format(ipv6_prefix_len)

    assert ipv4_address != "" and ipv6_address != ""
    return ipv4_address, ipv6_address, interface


def restart_dhcp_container(duthost):
    duthost.shell("systemctl reset-failed dhcp_relay")
    duthost.shell("systemctl restart dhcp_relay")
    is_dhcp_relay_running = wait_until(100, 10, 0, duthost.is_service_fully_started, "dhcp_relay")
    assert is_dhcp_relay_running, "DHCP RELAY not running"


def flush_ip_address(duthost, interface):
    duthost.shell("ip address flush dev {}".format(interface))


def restore_ip_address(duthost, ipv4_address, ipv6_address, interface):
    duthost.shell("ip address add {} dev {}".format(ipv4_address, interface))
    duthost.shell("ip address add {} dev {}".format(ipv6_address, interface))


def configure_auto_restart(duthost, state):
    ret = duthost.shell("config feature autorestart dhcp_relay {}".format(state))
    assert ret['rc'] == 0, "Not able to change autorestart of dhcp_relay"


def restart_dhcp_process(duthost, process):
    pid = duthost.shell(r"pgrep {}".format(process), module_ignore_errors=True)['stdout']
    duthost.shell("kill {} || true".format(pid), module_ignore_errors=True)
    duthost.shell("docker exec -d dhcp_relay {}".format(process))


def invoke_dhcp_relay_bind_failure(duthost, ipv4_address, ipv6_address, interface):
    configure_auto_restart(duthost, "disabled")
    flush_ip_address(duthost, interface)
    try:
        restart_dhcp_process(duthost, "/usr/sbin/dhcp6relay")
        time.sleep(30)  # dhcp retries to bind to socket 6 times with 5 sec after each retry
        # src: github.com/sonic-net/sonic-dhcp-relay/blob/2b33d76dbac69d3d9ad9e9f2d37252db525f07b9/src/relay.cpp#L714
    finally:
        restore_ip_address(duthost, ipv4_address, ipv6_address, interface)
        configure_auto_restart(duthost, "enabled")
