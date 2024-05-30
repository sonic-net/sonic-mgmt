import datetime
import logging
import ipaddress
import pytest
import ptf.testutils as testutils
import random
import re
import time
import uuid
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from dhcp_server_test_common import create_common_config_patch, DHCP_MESSAGE_TYPE_DISCOVER_NUM, \
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


def test_dhcp_server_with_large_number_discover(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config
):
    """
        Verify configured interface with client mac not in FDB table can successfully get IP
    """
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

    test_pkts_count = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 130, 160, 200, 300, 400, 600, 800, 1000, 2000]
    test_uuid = str(uuid.uuid4())
    for count in test_pkts_count:
        test_once_and_dump_pcap(ptfadapter, duthost, configurated_ports, count, test_uuid)
        time.sleep(60)
    raise Exception("Test failed")


    temp_file = "/tmp/duration_for_assign_ip.log"
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

    # stress_end_time = datetime.datetime.now()
    # stress_duration = stress_end_time - stress_start_time
    # pytest_assert(stress_duration.total_seconds() < 3,
    #               "It tooks too long to finish sending packets, \
    #                 elasped seconds is %s" % stress_duration.total_seconds())

    # verify client can get IP from dhcp server within 10 seconds
    try:
        def has_expected_ip_assigned(ptfhost, ptf_port_index, expected_assigned_ip):
            ip_addr_output = ptfhost.shell("ip addr show eth%s" % ptf_port_index)['stdout']
            logging.info("Output of ip addr show eth%s is %s" % (ptf_port_index, ip_addr_output))
            return expected_assigned_ip in ip_addr_output
        pytest_assert(
            wait_until(30, 1, 1,
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
        if match:
            minutes_str, seconds_str = match.groups()
            elasped_seconds = float(minutes_str) * 60 + float(seconds_str)
            pytest_assert(elasped_seconds < 10,
                          "It tooks too long for dhcp server offering packet, total seconds is %s" % elasped_seconds)
    finally:
        ptfhost.shell("dhclient -r eth%s" % ptf_port_index, module_ignore_errors=True)
        ptfhost.shell("killall dhclient", module_ignore_errors=True)

    raise Exception("Test failed")


def test_once_and_dump_pcap(ptfadapter, duthost, configurated_ports, N, test_uuid):
    pkts_ports = []
    for idx in range(N):
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
    pcap_save_path = "/tmp/stress_test_%s_%s.pcap" % (str(N), test_uuid)
    pkts_filter = "udp portrange 67-68"
    cmd_capture_pkts = "sudo nohup tcpdump --immediate-mode -U -i any -w %s >/dev/null 2>&1 %s & echo $!" \
        % (pcap_save_path, pkts_filter)
    tcpdump_pid = duthost.shell(cmd_capture_pkts)["stdout"]
    cmd_check_if_process_running = "ps -p %s | grep %s |grep -v grep | wc -l" % (tcpdump_pid, tcpdump_pid)
    pytest_assert(duthost.shell(cmd_check_if_process_running)["stdout"] == "1",
                  "Failed to start tcpdump on DUT")
    logging.info("Start to capture packet on DUT, tcpdump pid: %s, pcap save path: %s, with command: %s"
                 % (tcpdump_pid, pcap_save_path, cmd_capture_pkts))
    stress_start_time = datetime.datetime.now()
    for idx in range(N):
        testutils.send_packet(ptfadapter, pkts_ports[idx][1], pkts_ports[idx][0])
    time.sleep(60) #  wait some time for dhcp server to handle all packets
    duthost.shell("kill -s 2 %s" % tcpdump_pid)
    stress_end_time = datetime.datetime.now()
    stress_duration = stress_end_time - stress_start_time
    logging.info("When pkts count==%s, the stress duration seconds==%s" % (N, stress_duration.total_seconds()))
