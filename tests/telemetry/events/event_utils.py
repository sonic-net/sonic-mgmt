import logging
import os
import pytest
import json
import re

import ptf.packet as scapy
import ptf.testutils as testutils

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

EVENT_COUNTER_KEYS = ["missed_to_cache", "published"]
PUBLISHED = 1


def add_test_watchdog_timeout_service(duthost):
    logger.info("Adding mock watchdog.service to systemd")
    duthost.copy(src="telemetry/events/events_data/test-watchdog-timeout.service", dest="/etc/systemd/system/")
    duthost.shell("systemctl daemon-reload")
    duthost.shell("systemctl start test-watchdog-timeout.service")


def delete_test_watchdog_timeout_service(duthost):
    logger.info("Deleting mock test-watchdog-timeout.service")
    duthost.shell("systemctl stop test-watchdog-timeout.service", module_ignore_errors=True)
    duthost.shell("rm /etc/systemd/system/test-watchdog-timeout.service", module_ignore_errors=True)
    duthost.shell("systemctl daemon-reload")
    duthost.shell("systemctl reset-failed")


def backup_monit_config(duthost):
    logger.info("Backing up monit config files")
    duthost.shell("cp -f /etc/monit/monitrc ~/")
    duthost.shell("cp -f /etc/monit/conf.d/sonic-host ~/")


def restore_monit_config(duthost):
    logger.info("Restoring monit config files")
    duthost.shell("mv -f ~/monitrc /etc/monit/monitrc")
    duthost.shell("mv -f ~/sonic-host /etc/monit/conf.d/sonic-host")
    duthost.shell("systemctl restart monit")


def customize_monit_config(duthost, regex_pair):
    logger.info("Customizing monit files")
    # Modifying monitrc to reduce monit start delay time
    logger.info("Modifying monit config to eliminate start delay")
    duthost.replace(path="/etc/monit/monitrc", regexp='set daemon 60', replace='set daemon 10')
    duthost.replace(path="/etc/monit/monitrc", regexp='with start delay 300')
    original_line = regex_pair[0]
    new_line = regex_pair[1]
    if original_line != "":
        duthost.replace(path="/etc/monit/conf.d/sonic-host", regexp=original_line, replace=new_line)
    restart_monit(duthost)


def restart_monit(duthost):
    duthost.shell("systemctl restart monit")
    is_monit_running = wait_until(320,
                                  5,
                                  0,
                                  check_monit_running,
                                  duthost)
    pytest_assert(is_monit_running, "Monit is not running after restarted!")


def check_monit_running(duthost):
    monit_services_status = duthost.get_monit_services_status()
    return monit_services_status


def create_ip_file(duthost, data_dir, json_file, start_idx, end_idx):
    ip_file = os.path.join(data_dir, json_file)
    with open(ip_file, "w") as f:
        for i in range(start_idx, end_idx + 1):
            json_string = f'{{"test-event-source:test": {{"test_key": "test_val_{i}"}}}}'
            f.write(json_string + '\n')
    dest = "~/" + json_file
    duthost.copy(src=ip_file, dest=dest)
    duthost.shell("docker cp {} eventd:/".format(dest))


def event_publish_tool(duthost, json_file='', count=1):
    cmd = "docker exec eventd python /usr/bin/events_publish_tool.py"
    if json_file == '':
        cmd += " -c {}".format(count)
    else:
        cmd += " -f /{}".format(json_file)
    ret = duthost.shell(cmd)
    assert ret["rc"] == 0, "Unable to publish events via events_publish_tool.py"


def verify_received_output(received_file, N):
    key = "test_key"
    with open(received_file, 'r') as file:
        json_array = json.load(file)
        pytest_assert(len(json_array) == N, "Expected {} events, but found {}".format(N, len(json_array)))
        for i in range(0, len(json_array)):
            block = json_array[i]["test-event-source:test"]
            pytest_assert(key in block and len(re.findall('test_val_{}'.format(i + 1), block[key])) > 0,
                          "Missing key or incorrect value")


def restart_eventd(duthost):
    if duthost.is_multi_asic:
        pytest.skip("Skip eventd testing on multi-asic")
    features_dict, succeeded = duthost.get_feature_status()
    if succeeded and ('eventd' not in features_dict or features_dict['eventd'] == 'disabled'):
        pytest.skip("eventd is disabled on the system")

    duthost.shell("systemctl reset-failed eventd")
    duthost.service(name="eventd", state="restarted")
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, "eventd"), "eventd not started")
    pytest_assert(wait_until(300, 10, 0, verify_counter_increase, duthost, 0, 2, PUBLISHED),
                  "events_monit_test has not published")


def reset_event_counters(duthost):
    for key in EVENT_COUNTER_KEYS:
        cmd = "sonic-db-cli COUNTERS_DB HSET COUNTERS_EVENTS:{} value 0".format(key)
        duthost.shell(cmd, module_ignore_errors=True)


def read_event_counters(duthost):
    stats = []
    for key in EVENT_COUNTER_KEYS:
        cmd = "sonic-db-cli COUNTERS_DB HGET COUNTERS_EVENTS:{} value".format(key)
        output = duthost.shell(cmd)['stdout']
        stats.append(int(output))
    return stats


def verify_counter_increase(duthost, current_value, increase, stat):
    current_counters = read_event_counters(duthost)
    current_stat_counter = current_counters[stat]
    return current_stat_counter >= current_value + increase


def find_test_vlan(duthost):
    """Returns vlan information for dhcp_relay tests
    Returns dictionary of vlan port name, dhcrelay process name, ipv4 address,
    dhc6relay process name, ipv6 address, and member interfaces
    """
    vlan_brief = duthost.get_vlan_brief()
    for vlan in vlan_brief:
        # Find dhcrelay process
        dhcrelay_process = duthost.shell("docker exec dhcp_relay supervisorctl status \
                                         | grep isc-dhcpv4-relay-%s | awk '{print $1}'" % vlan)['stdout']
        dhcp6relay_process = duthost.shell("docker exec dhcp_relay supervisorctl status \
                                           | grep dhcp6relay | awk '{print $1}'")['stdout']
        interface_ipv4 = vlan_brief[vlan]['interface_ipv4']
        interface_ipv6 = vlan_brief[vlan]['interface_ipv6']
        members = vlan_brief[vlan]['members']

        # Check all returning fields are non empty
        results = [dhcrelay_process, interface_ipv4, dhcp6relay_process, interface_ipv6, members]
        if all(result for result in results):
            return {
                "vlan": vlan,
                "dhcrelay_process": dhcrelay_process,
                "ipv4_address": interface_ipv4[0],
                "dhcp6relay_process": dhcp6relay_process,
                "ipv6_address": interface_ipv6[0],
                "member_interface": members
            }
    return {}


def find_test_port_and_mac(duthost, members, count):
    # Will return up to count many up ports with their port index and mac address
    results = []
    interf_status = duthost.show_interface(command="status")['ansible_facts']['int_status']
    for member_interface in members:
        if len(results) == count:
            return results
        if interf_status[member_interface]['admin_state'] == "up":
            mac = duthost.get_dut_iface_mac(member_interface)
            minigraph_info = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
            port_index = minigraph_info['minigraph_port_indices'][member_interface]
            if mac != "" and port_index != "":
                results.append([int(port_index), mac])
    return results


def create_dhcp_discover_packet(client_mac):
    dst_mac = 'ff:ff:ff:ff:ff:ff'
    dhcp_client_port = 68
    discover_packet = testutils.dhcp_discover_packet(eth_client=client_mac, set_broadcast_bit=True)
    discover_packet[scapy.Ether].dst = dst_mac
    discover_packet[scapy.IP].sport = dhcp_client_port
    return discover_packet
