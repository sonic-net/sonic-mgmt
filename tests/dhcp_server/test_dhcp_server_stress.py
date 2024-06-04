import datetime
import logging
import ipaddress
import pytest
import ptf.testutils as testutils
import random
import re
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from dhcp_server_test_common import DHCP_MESSAGE_TYPE_DISCOVER_NUM, \
    apply_dhcp_server_config_gcu, create_dhcp_client_packet, empty_config_patch, append_common_config_patch


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


def test_dhcp_server_with_multiple_dhcp_clients(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config
):
    """
        Make sure all ports can get assigend ip when all ports request ip at same time
    """
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    start_command = " && ".join(["dhclient -nw eth%s" % ptf_index for _, ptf_index in vlan_members_with_ptf_idx])
    end_command = " ; ".join(["dhclient -r eth%s" % ptf_index for _, ptf_index in vlan_members_with_ptf_idx])
    try:
        config_to_apply = empty_config_patch()
        dut_ports, _ = zip(*vlan_members_with_ptf_idx)
        exp_assigned_ip_ranges = [[ip] for ip in vlan_hosts[:len(vlan_members_with_ptf_idx)]]
        append_common_config_patch(
            config_to_apply,
            vlan_name,
            gateway,
            net_mask,
            dut_ports,
            exp_assigned_ip_ranges
        )
        apply_dhcp_server_config_gcu(duthost, config_to_apply)
        ptfhost.shell(start_command)

        def all_ip_shown_up(ptfhost, expected_assigned_ips):
            ip_addr_output = ptfhost.shell("ip addr")['stdout']
            for expected_ip in expected_assigned_ips:
                if expected_ip not in ip_addr_output:
                    return False
            return True
        expected_assigned_ips = [range[0] for range in exp_assigned_ip_ranges]
        pytest_assert(
            wait_until(120, 1, 1,
                       all_ip_shown_up,
                       ptfhost,
                       expected_assigned_ips),
            'Not all configurated IP shown up on ptf interfaces'
        )
    finally:
        ptfhost.shell(end_command, module_ignore_errors=True)
        ptfhost.shell("killall dhclient", module_ignore_errors=True)


def test_dhcp_server_with_large_number_of_discover(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config
):
    temp_file = "/tmp/dhcp_sever_stress_test.log"
    config_to_apply = empty_config_patch()
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    exp_assigned_ip_ranges = [[ip] for ip in vlan_hosts[:len(vlan_members_with_ptf_idx)]]
    dut_ports, ptf_port_indexs = zip(*vlan_members_with_ptf_idx)
    logging.info("expected_assigned_ip_rangs is %s, dut_ports is %s, ptf_port_indexs is %s" %
                 (exp_assigned_ip_ranges, dut_ports, ptf_port_indexs))
    append_common_config_patch(
        config_to_apply,
        vlan_name,
        gateway,
        net_mask,
        dut_ports,
        exp_assigned_ip_ranges
    )
    configurated_ports = []
    for index in range(len(dut_ports)):
        test_xid = index
        configurated_ports.append((vlan_name, gateway, net_mask, dut_ports[index], ptf_port_indexs[index],
                                   exp_assigned_ip_ranges[index], test_xid))
    random_one_port = random.choice(configurated_ports)
    dut_port, ptf_port_index, expected_assigned_ip = random_one_port[3], random_one_port[4], random_one_port[5][0]
    logging.info("expected assigned ip is %s, dut_port is %s, ptf_port_index is %s" %
                 (expected_assigned_ip, dut_port, ptf_port_index))
    apply_dhcp_server_config_gcu(duthost, config_to_apply)
    # put stress on the dhcp server
    stress_start_time = datetime.datetime.now()
    concurrency_count = 200
    pkts_ports = []
    for idx in range(concurrency_count):
        rand_one_port = random.choice(configurated_ports)
        rand_ptf_port_index = rand_one_port[4]
        rand_client_mac = ptfadapter.dataplane.get_mac(0, rand_ptf_port_index).decode('utf-8')
        pkts_ports.append(
            (
                create_dhcp_client_packet(
                    src_mac=rand_client_mac,
                    message_type=DHCP_MESSAGE_TYPE_DISCOVER_NUM,
                    client_options=[],
                    xid=idx
                ),
                rand_ptf_port_index
            )
        )
    for idx in range(len(pkts_ports)):
        if idx == concurrency_count//2:
            ptfhost.shell("bash -c 'time dhclient eth%s' >%s 2>&1 &" % (ptf_port_index, temp_file))
        testutils.send_packet(ptfadapter, pkts_ports[idx][1], pkts_ports[idx][0])

    stress_end_time = datetime.datetime.now()
    stress_duration = stress_end_time - stress_start_time
    pytest_assert(stress_duration.total_seconds() < 3,
                  "It tooks too long to finish sending packets, \
                    elasped seconds is %s" % stress_duration.total_seconds())

    # verify client can get IP from dhcp server within threshold
    try:
        def has_expected_ip_assigned(ptfhost, ptf_port_index, expected_assigned_ip):
            ip_addr_output = ptfhost.shell("ip addr show eth%s" % ptf_port_index)['stdout']
            logging.info("Output of ip addr show eth%s is %s" % (ptf_port_index, ip_addr_output))
            return expected_assigned_ip in ip_addr_output
        pytest_assert(
            wait_until(10, 1, 1,
                       has_expected_ip_assigned,
                       ptfhost,
                       ptf_port_index,
                       expected_assigned_ip),
            'client didnt get expected IP from dhcp server'
        )
        time_output = ptfhost.shell("cat %s" % temp_file)['stdout_lines']
        pattern = r'(\d+.?\d*)m(\d+.?\d*)s'
        real_time = [o for o in time_output if 'real' in o][0]
        match = re.search(pattern, real_time)
        if not match:
            pytest.fail("Failed to parse real time from %s" % real_time)
        minutes_str, seconds_str = match.groups()
        elasped_seconds = float(minutes_str) * 60 + float(seconds_str)
        pytest_assert(elasped_seconds < 10,
                      "It tooks too long for dhcp server offering packet, total seconds is %s" % elasped_seconds)
    finally:
        ptfhost.shell("dhclient -r eth%s" % ptf_port_index, module_ignore_errors=True)
        ptfhost.shell("killall dhclient", module_ignore_errors=True)
