import datetime
import logging
import ipaddress
import pytest
import ptf.testutils as testutils
import random
import re
import time
from tests.common.helpers.assertions import pytest_assert
from dhcp_server_test_common import create_common_config_patch, DHCP_MESSAGE_TYPE_DISCOVER_NUM, \
    apply_dhcp_server_config_gcu, create_dhcp_client_packet


pytestmark = [
    pytest.mark.topology('mx'),
]


@pytest.fixture(scope="module", autouse=True)
def dhcp_client_setup_teardown_on_ptf(ptfhost, creds):
    http_proxy = creds.get("proxy_env", {}).get("http_proxy", "")
    http_param = "-o Acquire::http::proxy='{}'".format(http_proxy) if http_proxy != "" else ""
    ptfhost.shell("apt-get {} update".format(http_param), module_ignore_errors=True)
    ptfhost.shell("apt-get {} install isc-dhcp-client -y".format(http_param))

    yield

    ptfhost.shell("apt-get remove isc-dhcp-client -y", module_ignore_errors=True)


@pytest.fixture(scope="module")
def parse_vlan_setting_from_running_config(duthost, tbinfo):
    vlan_brief = duthost.get_vlan_brief()
    first_vlan_name = list(vlan_brief.keys())[0]
    first_vlan_info = list(vlan_brief.values())[0]
    first_vlan_prefix = first_vlan_info['interface_ipv4'][0]
    disabled_host_interfaces = tbinfo['topo']['properties']['topology'].get('disabled_host_interfaces', [])
    connected_ptf_ports_idx = [interface for interface in
                               tbinfo['topo']['properties']['topology'].get('host_interfaces', [])
                               if interface not in disabled_host_interfaces]
    dut_intf_to_ptf_index = duthost.get_extended_minigraph_facts(tbinfo)['minigraph_ptf_indices']
    connected_dut_intf_to_ptf_index = {k: v for k, v in dut_intf_to_ptf_index.items() if v in connected_ptf_ports_idx}
    vlan_members = first_vlan_info['members']
    vlan_member_with_ptf_idx = [(member, connected_dut_intf_to_ptf_index[member])
                                for member in vlan_members if member in connected_dut_intf_to_ptf_index]
    pytest_assert(len(vlan_member_with_ptf_idx) >= 2, 'Vlan members is too little for testing')
    vlan_net = ipaddress.ip_network(address=first_vlan_prefix, strict=False)
    vlan_gateway = first_vlan_prefix.split('/')[0]
    vlan_hosts = [str(host) for host in vlan_net.hosts()]
    # to avoid configurate an range contains gateway ip, simply ignore all ip before gateway and gateway itself
    vlan_hosts_after_gateway = vlan_hosts[vlan_hosts.index(vlan_gateway) + 1:]
    pytest_assert(len(vlan_hosts_after_gateway) >= 2, 'Vlan size is too small for testing')
    vlan_setting = {
        'vlan_name': first_vlan_name,
        'vlan_gateway': vlan_gateway,
        'vlan_subnet_mask': str(vlan_net.netmask),
        'vlan_hosts': vlan_hosts_after_gateway,
        'vlan_member_with_ptf_idx': vlan_member_with_ptf_idx,
    }

    logging.info("The vlan_setting before test is %s" % vlan_setting)
    return vlan_setting['vlan_name'], \
        vlan_setting['vlan_gateway'], \
        vlan_setting['vlan_subnet_mask'], \
        vlan_setting['vlan_hosts'], \
        vlan_setting['vlan_member_with_ptf_idx']


def test_dhcp_server_with_large_number_discover(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config
):
    """
        Verify configured interface with client mac not in FDB table can successfully get IP
    """
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    expected_assigned_ip = random.choice(vlan_hosts)
    dut_port, ptf_port_index = random.choice(vlan_members_with_ptf_idx)
    logging.info("expected assigned ip is %s, dut_port is %s, ptf_port_index is %s" %
                 (expected_assigned_ip, dut_port, ptf_port_index))
    config_to_apply = create_common_config_patch(vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip]])

    apply_dhcp_server_config_gcu(duthost, config_to_apply)
    client_mac = ptfadapter.dataplane.get_mac(0, ptf_port_index).decode('utf-8')

    # put stress on the dhcp server
    stress_start_time = datetime.datetime.now()
    stress_duration_seconds = 1
    count_per_second = 200
    for i in range(stress_duration_seconds):
        time.sleep(1)
        for j in range(count_per_second):
            discover_pkt = create_dhcp_client_packet(
                src_mac=client_mac,
                message_type=DHCP_MESSAGE_TYPE_DISCOVER_NUM,
                client_options=[],
                xid=i*count_per_second+j
            )
            testutils.send_packet(ptfadapter, ptf_port_index, discover_pkt)
    stress_end_time = datetime.datetime.now()
    stress_duration = stress_end_time - stress_start_time
    pytest_assert(stress_duration.total_seconds() < 0.3 + stress_duration_seconds * 1.2,
                  "It tooks too long to finish sending packets, \
                    elasped seconds is %s" % stress_duration.total_seconds())

    # verify client can get IP from dhcp server within 10 seconds
    try:
        time_output = ptfhost.shell('bash -c "time dhclient eth%s"' % ptf_port_index)
        ip_addr_output = ptfhost.shell("ip addr show eth%s" % ptf_port_index)['stdout']
        logging.info("Output of ip addr show eth%s is %s" % (ptf_port_index, ip_addr_output))
        pytest_assert(expected_assigned_ip in ip_addr_output,
                      "Client didn't get expected IP from dhcp server")
        pattern = r'(\d+.?\d*)m(\d+.?\d*)s'
        real_time = [o for o in time_output['stderr_lines'] if 'real' in o][0]
        match = re.search(pattern, real_time)
        if match:
            minutes_str, seconds_str = match.groups()
            elasped_seconds = float(minutes_str) * 60 + float(seconds_str)
            pytest_assert(elasped_seconds < 10,
                          "It tooks too long for dhcp server offering packet, total seconds is %s" % elasped_seconds)
    finally:
        ptfhost.shell("dhclient -r eth%s" % ptf_port_index, module_ignore_errors=True)
        ptfhost.shell("killall dhclient", module_ignore_errors=True)
