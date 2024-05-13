from conftest import DHCP_SERVER_CONTAINER_NAME, DHCP_RELAY_CONTAINER_NAME
import logging
import ipaddress
import pytest
import random
import time
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from dhcp_server_test_common import DHCP_SERVER_CONFIG_TOOL_GCU, DHCP_SERVER_CONFIG_TOOL_CLI, \
    create_common_config_patch, generate_common_config_cli_commands, dhcp_server_config, \
    validate_dhcp_server_pkts_custom_option, \
    verify_discover_and_request_then_release, send_and_verify, DHCP_MESSAGE_TYPE_DISCOVER_NUM, \
    DHCP_SERVER_SUPPORTED_OPTION_ID, DHCP_MESSAGE_TYPE_REQUEST_NUM, DHCP_DEFAULT_LEASE_TIME, \
    clean_dhcp_server_config, apply_dhcp_server_config_gcu, \
    create_dhcp_client_packet, get_running_critical_processes


pytestmark = [
    pytest.mark.topology('mx'),
]


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


@pytest.mark.parametrize("config_tool", [DHCP_SERVER_CONFIG_TOOL_GCU, DHCP_SERVER_CONFIG_TOOL_CLI])
def test_dhcp_server_port_based_assignment_single_ip_tc1(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config,
    config_tool
):
    """
        Verify configured interface with client mac not in FDB table can successfully get IP
    """
    test_xid = 1
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    expected_assigned_ip = random.choice(vlan_hosts)
    dut_port, ptf_port_index = random.choice(vlan_members_with_ptf_idx)
    logging.info("expected assigned ip is %s, dut_port is %s, ptf_port_index is %s" %
                 (expected_assigned_ip, dut_port, ptf_port_index))
    config_cli = generate_common_config_cli_commands(vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip]])
    config_gcu = create_common_config_patch(vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip]])
    config_to_apply = None
    if config_tool == DHCP_SERVER_CONFIG_TOOL_CLI:
        config_to_apply = config_cli
    elif config_tool == DHCP_SERVER_CONFIG_TOOL_GCU:
        config_to_apply = config_gcu
    with dhcp_server_config(duthost, config_tool, config_to_apply):
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port,
            ptf_port_index=ptf_port_index,
            ptf_mac_port_index=ptf_port_index,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip,
            exp_gateway=gateway,
            net_mask=net_mask
        )


@pytest.mark.parametrize("config_tool", [DHCP_SERVER_CONFIG_TOOL_GCU, DHCP_SERVER_CONFIG_TOOL_CLI])
def test_dhcp_server_port_based_assignment_single_ip_tc2(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config,
    config_tool,
):
    """
        Verify configured interface with client mac in FDB table can successfully get IP
    """
    test_xid = 2
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    expected_assigned_ip = random.choice(vlan_hosts)
    dut_port, ptf_port_index = random.choice(vlan_members_with_ptf_idx)
    logging.info("expected assigned ip is %s, dut_port is %s, ptf_port_index is %s" %
                 (expected_assigned_ip, dut_port, ptf_port_index))
    config_cli = generate_common_config_cli_commands(vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip]])
    config_gcu = create_common_config_patch(vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip]])
    config_to_apply = None
    if config_tool == DHCP_SERVER_CONFIG_TOOL_CLI:
        config_to_apply = config_cli
    elif config_tool == DHCP_SERVER_CONFIG_TOOL_GCU:
        config_to_apply = config_gcu
    with dhcp_server_config(duthost, config_tool, config_to_apply):
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port,
            ptf_port_index=ptf_port_index,
            ptf_mac_port_index=ptf_port_index,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip,
            exp_gateway=gateway,
            net_mask=net_mask,
            refresh_fdb_ptf_port='eth'+str(ptf_port_index)
        )


@pytest.mark.parametrize("config_tool", [DHCP_SERVER_CONFIG_TOOL_GCU, DHCP_SERVER_CONFIG_TOOL_CLI])
def test_dhcp_server_port_based_assignment_single_ip_tc3(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config,
    config_tool
):
    """
        Verify configured interface with client mac in FDB table
        but mac was learnt from another interface successfully get IP.
    """
    test_xid = 3
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    expected_assigned_ip = random.choice(vlan_hosts)
    dut_port, ptf_port_index = random.choice(vlan_members_with_ptf_idx)
    config_cli = generate_common_config_cli_commands(vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip]])
    _, ptf_mac_port_index = random.choice([m for m in vlan_members_with_ptf_idx if m[0] != dut_port])
    logging.info("expected assigned ip is %s, dut_port is %s, ptf_port_index is %s, ptf_mac_port_index is %s" %
                 (expected_assigned_ip, dut_port, ptf_port_index, ptf_mac_port_index))
    config_gcu = create_common_config_patch(vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip]])
    config_to_apply = None
    if config_tool == DHCP_SERVER_CONFIG_TOOL_CLI:
        config_to_apply = config_cli
    elif config_tool == DHCP_SERVER_CONFIG_TOOL_GCU:
        config_to_apply = config_gcu
    with dhcp_server_config(duthost, config_tool, config_to_apply):
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port,
            ptf_port_index=ptf_port_index,
            ptf_mac_port_index=ptf_mac_port_index,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip,
            exp_gateway=gateway,
            net_mask=net_mask,
            refresh_fdb_ptf_port='eth'+str(ptf_mac_port_index)
        )


@pytest.mark.parametrize("config_tool", [DHCP_SERVER_CONFIG_TOOL_GCU, DHCP_SERVER_CONFIG_TOOL_CLI])
def test_dhcp_server_port_based_assignment_single_ip_tc4(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config,
    config_tool
):
    """
        Verify no-configured interface cannot get IP
    """
    test_xid = 4
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    assigned_ip = random.choice(vlan_hosts)
    unconfigured_dut_port, unconfigured_ptf_port_index = random.choice(vlan_members_with_ptf_idx)
    configured_dut_port, _ = random.choice([m for m in vlan_members_with_ptf_idx if m[0] != unconfigured_dut_port])
    logging.info(
        "assigned ip is %s, unconfigured_dut_port is %s, unconfigured_ptf_port_index is %s, configured_dut_port is %s" %
        (assigned_ip, unconfigured_dut_port, unconfigured_ptf_port_index, configured_dut_port)
    )
    config_cli = generate_common_config_cli_commands(
        vlan_name, gateway, net_mask, [configured_dut_port], [[assigned_ip]])
    config_gcu = create_common_config_patch(
        vlan_name, gateway, net_mask, [configured_dut_port], [[assigned_ip]])
    config_to_apply = None
    if config_tool == DHCP_SERVER_CONFIG_TOOL_CLI:
        config_to_apply = config_cli
    elif config_tool == DHCP_SERVER_CONFIG_TOOL_GCU:
        config_to_apply = config_gcu
    with dhcp_server_config(duthost, config_tool, config_to_apply):
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=unconfigured_dut_port,
            ptf_port_index=unconfigured_ptf_port_index,
            ptf_mac_port_index=unconfigured_ptf_port_index,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=None,
            exp_gateway=gateway,
            net_mask=net_mask,
            refresh_fdb_ptf_port='eth'+str(unconfigured_ptf_port_index)
        )


@pytest.mark.parametrize("config_tool", [DHCP_SERVER_CONFIG_TOOL_GCU, DHCP_SERVER_CONFIG_TOOL_CLI])
def test_dhcp_server_port_based_assignment_range_ip(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config,
    config_tool
):
    """
        Verify configured interface can successfully get IP from an IP range
    """
    test_xid = 5
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    expected_assigned_ip = random.choice(vlan_hosts[:-1])
    last_ip_in_range = random.choice(vlan_hosts[vlan_hosts.index(expected_assigned_ip) + 1:])
    dut_port, ptf_port_index = random.choice(vlan_members_with_ptf_idx)
    logging.info("expected assigned ip is %s, last_ip_in_range is %s, dut_port is %s, ptf_port_index is %s" %
                 (expected_assigned_ip, last_ip_in_range, dut_port, ptf_port_index))
    config_cli = generate_common_config_cli_commands(
        vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip, last_ip_in_range]])
    config_gcu = create_common_config_patch(
        vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip, last_ip_in_range]])
    config_to_apply = None
    if config_tool == DHCP_SERVER_CONFIG_TOOL_CLI:
        config_to_apply = config_cli
    elif config_tool == DHCP_SERVER_CONFIG_TOOL_GCU:
        config_to_apply = config_gcu
    with dhcp_server_config(duthost, config_tool, config_to_apply):
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port,
            ptf_port_index=ptf_port_index,
            ptf_mac_port_index=ptf_port_index,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip,
            exp_gateway=gateway,
            net_mask=net_mask,
            refresh_fdb_ptf_port='eth'+str(ptf_port_index)
        )


@pytest.mark.parametrize("config_tool", [DHCP_SERVER_CONFIG_TOOL_GCU, DHCP_SERVER_CONFIG_TOOL_CLI])
def test_dhcp_server_port_based_assigenment_single_ip_mac_move(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config,
    config_tool
):
    """
        To test port based single ip assignment with client move to an interface has free IP to assign.
    """
    test_xid = 6
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    expected_assigned_ip_0 = random.choice(vlan_hosts)
    dut_port_0, ptf_port_index_0 = random.choice(vlan_members_with_ptf_idx)
    expected_assigned_ip_1 = random.choice([v for v in vlan_hosts if v != expected_assigned_ip_0])
    dut_port_1, ptf_port_index_1 = random.choice([m for m in vlan_members_with_ptf_idx if m[0] != dut_port_0])
    logging.info("expected assigned ip_0 is %s, dut_port_0 is %s, ptf_port_index_0 is %s" %
                 (expected_assigned_ip_0, dut_port_0, ptf_port_index_0))
    logging.info("expected assigned ip_1 is %s, dut_port_1 is %s, ptf_port_index_1 is %s" %
                 (expected_assigned_ip_1, dut_port_1, ptf_port_index_1))
    config_cli = generate_common_config_cli_commands(
        vlan_name, gateway, net_mask, [dut_port_0, dut_port_1], [[expected_assigned_ip_0], [expected_assigned_ip_1]])
    config_gcu = create_common_config_patch(
        vlan_name, gateway, net_mask, [dut_port_0, dut_port_1], [[expected_assigned_ip_0], [expected_assigned_ip_1]])
    config_to_apply = None
    if config_tool == DHCP_SERVER_CONFIG_TOOL_CLI:
        config_to_apply = config_cli
    elif config_tool == DHCP_SERVER_CONFIG_TOOL_GCU:
        config_to_apply = config_gcu
    with dhcp_server_config(duthost, config_tool, config_to_apply):
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port_0,
            ptf_port_index=ptf_port_index_0,
            ptf_mac_port_index=ptf_port_index_0,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip_0,
            exp_gateway=gateway,
            net_mask=net_mask
        )
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port_1,
            ptf_port_index=ptf_port_index_1,
            ptf_mac_port_index=ptf_port_index_0,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip_1,
            exp_gateway=gateway,
            net_mask=net_mask
        )


@pytest.mark.parametrize("config_tool", [DHCP_SERVER_CONFIG_TOOL_GCU, DHCP_SERVER_CONFIG_TOOL_CLI])
def test_dhcp_server_port_based_assigenment_single_ip_mac_swap(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config,
    config_tool
):
    """
        To test port based single ip assignment with two clients swap their interfaces.
    """
    test_xid = 7
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    expected_assigned_ip_0 = random.choice(vlan_hosts)
    dut_port_0, ptf_port_index_0 = random.choice(vlan_members_with_ptf_idx)
    expected_assigned_ip_1 = random.choice([v for v in vlan_hosts if v != expected_assigned_ip_0])
    dut_port_1, ptf_port_index_1 = random.choice([m for m in vlan_members_with_ptf_idx if m[0] != dut_port_0])
    logging.info("expected assigned ip_0 is %s, dut_port_0 is %s, ptf_port_index_0 is %s" %
                 (expected_assigned_ip_0, dut_port_0, ptf_port_index_0))
    logging.info("expected assigned ip_1 is %s, dut_port_1 is %s, ptf_port_index_1 is %s" %
                 (expected_assigned_ip_1, dut_port_1, ptf_port_index_1))
    config_cli = generate_common_config_cli_commands(
        vlan_name, gateway, net_mask, [dut_port_0, dut_port_1], [[expected_assigned_ip_0], [expected_assigned_ip_1]])
    config_gcu = create_common_config_patch(
        vlan_name, gateway, net_mask, [dut_port_0, dut_port_1], [[expected_assigned_ip_0], [expected_assigned_ip_1]])
    config_to_apply = None
    if config_tool == DHCP_SERVER_CONFIG_TOOL_CLI:
        config_to_apply = config_cli
    elif config_tool == DHCP_SERVER_CONFIG_TOOL_GCU:
        config_to_apply = config_gcu
    with dhcp_server_config(duthost, config_tool, config_to_apply):
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port_0,
            ptf_port_index=ptf_port_index_0,
            ptf_mac_port_index=ptf_port_index_0,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip_0,
            exp_gateway=gateway,
            net_mask=net_mask
        )
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port_1,
            ptf_port_index=ptf_port_index_1,
            ptf_mac_port_index=ptf_port_index_1,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip_1,
            exp_gateway=gateway,
            net_mask=net_mask
        )
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port_1,
            ptf_port_index=ptf_port_index_1,
            ptf_mac_port_index=ptf_port_index_0,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip_1,
            exp_gateway=gateway,
            net_mask=net_mask
        )
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port_0,
            ptf_port_index=ptf_port_index_0,
            ptf_mac_port_index=ptf_port_index_1,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=expected_assigned_ip_0,
            exp_gateway=gateway,
            net_mask=net_mask
        )


@pytest.mark.parametrize("option_info", [["string", "#hello, i'm dhcp_server!"]])
def test_dhcp_server_port_based_customize_options(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config,
    option_info
):
    """
        Test dhcp server packets if carry the customized options as expected
    """
    test_xid = 8
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    expected_assigned_ip = random.choice(vlan_hosts)
    dut_port, ptf_port_index = random.choice(vlan_members_with_ptf_idx)
    client_mac = ptfadapter.dataplane.get_mac(0, ptf_port_index).decode('utf-8')
    random_option_id = random.choice(DHCP_SERVER_SUPPORTED_OPTION_ID)
    customized_options = {
        "test_customized_option_1": {
            "id": random_option_id,
            "type": option_info[0],
            "value": option_info[1]
        }
    }
    logging.info("expected assigned ip is %s, dut_port is %s, ptf_port_index is %s, random_option_id is %s" %
                 (expected_assigned_ip, dut_port, ptf_port_index, random_option_id))
    config_patch = create_common_config_patch(
        vlan_name,
        gateway,
        net_mask,
        [dut_port],
        [[expected_assigned_ip]],
        customized_options
    )
    with dhcp_server_config(duthost, DHCP_SERVER_CONFIG_TOOL_GCU, config_patch):
        pkts_validator = validate_dhcp_server_pkts_custom_option
        pkts_validator_args = [test_xid]
        pkts_validator_kwargs = {"%s" % random_option_id: option_info[1].encode('ascii')}
        discover_pkt = create_dhcp_client_packet(
            src_mac=client_mac,
            message_type=DHCP_MESSAGE_TYPE_DISCOVER_NUM,
            client_options=[],
            xid=test_xid
        )
        send_and_verify(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            test_pkt=discover_pkt,
            dut_port_to_capture_pkt=dut_port,
            ptf_port_index=ptf_port_index,
            pkts_validator=pkts_validator,
            pkts_validator_args=pkts_validator_args,
            pkts_validator_kwargs=pkts_validator_kwargs,
            refresh_fdb_ptf_port='eth'+str(ptf_port_index)
        )
        request_pkt = create_dhcp_client_packet(
            src_mac=client_mac,
            message_type=DHCP_MESSAGE_TYPE_REQUEST_NUM,
            client_options=[("requested_addr", expected_assigned_ip), ("server_id", gateway)],
            xid=test_xid
        )
        send_and_verify(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port,
            ptf_port_index=ptf_port_index,
            test_pkt=request_pkt,
            pkts_validator=pkts_validator,
            pkts_validator_args=pkts_validator_args,
            pkts_validator_kwargs=pkts_validator_kwargs,
            refresh_fdb_ptf_port='eth'+str(ptf_port_index)
        )


def test_dhcp_server_config_change_dhcp_interface(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config
):
    """
        Test if config change on dhcp interface status can take effect
    """
    test_xid = 9
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    expected_assigned_ip = random.choice(vlan_hosts)
    dut_port, ptf_port_index = random.choice(vlan_members_with_ptf_idx)
    logging.info("expected assigned ip is %s, dut_port is %s, ptf_port_index is %s" %
                 (expected_assigned_ip, dut_port, ptf_port_index))
    config_to_apply = create_common_config_patch(vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip]])
    apply_dhcp_server_config_gcu(duthost, config_to_apply)
    verify_discover_and_request_then_release(
        duthost=duthost,
        ptfhost=ptfhost,
        ptfadapter=ptfadapter,
        dut_port_to_capture_pkt=dut_port,
        ptf_port_index=ptf_port_index,
        ptf_mac_port_index=ptf_port_index,
        test_xid=test_xid,
        dhcp_interface=vlan_name,
        expected_assigned_ip=expected_assigned_ip,
        exp_gateway=gateway,
        net_mask=net_mask
    )
    # disable dhcp interface and validate no packet can be received
    config_to_apply = [
        {
            "op": "replace",
            "path": "/DHCP_SERVER_IPV4/%s/state" % vlan_name,
            "value": "disabled"
        }
    ]
    apply_dhcp_server_config_gcu(duthost, config_to_apply)
    verify_discover_and_request_then_release(
        duthost=duthost,
        ptfhost=ptfhost,
        ptfadapter=ptfadapter,
        dut_port_to_capture_pkt=dut_port,
        ptf_port_index=ptf_port_index,
        ptf_mac_port_index=ptf_port_index,
        test_xid=test_xid,
        dhcp_interface=vlan_name,
        expected_assigned_ip=None,
        exp_gateway=gateway,
        net_mask=net_mask
    )
    clean_dhcp_server_config(duthost)


def test_dhcp_server_config_change_common(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config
):
    """
        Test if config change on dhcp interface status can take effect
    """
    test_xid = 10
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    expected_assigned_ip = random.choice(vlan_hosts)
    dut_port, ptf_port_index = random.choice(vlan_members_with_ptf_idx)
    logging.info("expected assigned ip is %s, dut_port is %s, ptf_port_index is %s" %
                 (expected_assigned_ip, dut_port, ptf_port_index))
    config_to_apply = create_common_config_patch(vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip]])
    apply_dhcp_server_config_gcu(duthost, config_to_apply)
    verify_discover_and_request_then_release(
        duthost=duthost,
        ptfhost=ptfhost,
        ptfadapter=ptfadapter,
        dut_port_to_capture_pkt=dut_port,
        ptf_port_index=ptf_port_index,
        ptf_mac_port_index=ptf_port_index,
        test_xid=test_xid,
        dhcp_interface=vlan_name,
        expected_assigned_ip=expected_assigned_ip,
        exp_gateway=gateway,
        net_mask=net_mask
    )
    # change config on dhcp interface and validate the change can take effect
    changed_expected_assigned_ip = random.choice([v for v in vlan_hosts if v != expected_assigned_ip])
    changed_gateway = random.choice([v for v in vlan_hosts
                                     if v != expected_assigned_ip and v != changed_expected_assigned_ip])
    changed_lease_time = random.randint(DHCP_DEFAULT_LEASE_TIME, 1000)
    logging.info("changed expected assigned ip is %s, changed_gateway is %s, changed_lease_time is %s" %
                 (changed_expected_assigned_ip, changed_gateway, changed_lease_time))
    change_to_apply = [
        {
            "op": "replace",
            "path": "/DHCP_SERVER_IPV4_RANGE/%s/range/0" % ("range_" + expected_assigned_ip),
            "value": "%s" % changed_expected_assigned_ip
        },
        {
            "op": "replace",
            "path": "/DHCP_SERVER_IPV4/%s/lease_time" % vlan_name,
            "value": "%s" % changed_lease_time
        },
        {
            "op": "replace",
            "path": "/DHCP_SERVER_IPV4/%s/gateway" % vlan_name,
            "value": "%s" % changed_gateway
        }
    ]
    apply_dhcp_server_config_gcu(duthost, change_to_apply)
    verify_discover_and_request_then_release(
        duthost=duthost,
        ptfhost=ptfhost,
        ptfadapter=ptfadapter,
        dut_port_to_capture_pkt=dut_port,
        ptf_port_index=ptf_port_index,
        ptf_mac_port_index=ptf_port_index,
        test_xid=test_xid,
        dhcp_interface=vlan_name,
        expected_assigned_ip=changed_expected_assigned_ip,
        exp_gateway=changed_gateway,
        net_mask=net_mask,
        exp_lease_time=changed_lease_time
    )
    clean_dhcp_server_config(duthost)


def test_dhcp_server_config_vlan_member_change(
    duthost,
    ptfhost,
    ptfadapter,
    parse_vlan_setting_from_running_config
):
    """
        Test if config change on dhcp interface status can take effect
    """
    test_xid = 11
    vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = parse_vlan_setting_from_running_config
    expected_assigned_ip = random.choice(vlan_hosts)
    dut_port, ptf_port_index = random.choice(vlan_members_with_ptf_idx)
    logging.info("expected assigned ip is %s, dut_port is %s, ptf_port_index is %s" %
                 (expected_assigned_ip, dut_port, ptf_port_index))
    config_to_apply = create_common_config_patch(vlan_name, gateway, net_mask, [dut_port], [[expected_assigned_ip]])
    apply_dhcp_server_config_gcu(duthost, config_to_apply)
    # delete member
    config_to_apply = [
        {
            "op": "remove",
            "path": "/VLAN_MEMBER/%s|%s" % (vlan_name, dut_port)
        }
    ]
    apply_dhcp_server_config_gcu(duthost, config_to_apply)
    verify_discover_and_request_then_release(
        duthost=duthost,
        ptfhost=ptfhost,
        ptfadapter=ptfadapter,
        dut_port_to_capture_pkt=dut_port,
        ptf_port_index=ptf_port_index,
        ptf_mac_port_index=ptf_port_index,
        test_xid=test_xid,
        dhcp_interface=vlan_name,
        expected_assigned_ip=None,
        exp_gateway=gateway,
        net_mask=net_mask
    )
    # restore deleted member
    config_to_apply = [
        {
            "op": "add",
            "path": "/VLAN_MEMBER/%s|%s" % (vlan_name, dut_port),
            "value": {
                "tagging_mode": "untagged"
            }
        }
    ]
    apply_dhcp_server_config_gcu(duthost, config_to_apply)
    time.sleep(3)  # wait for vlan member change take effect
    verify_discover_and_request_then_release(
        duthost=duthost,
        ptfhost=ptfhost,
        ptfadapter=ptfadapter,
        dut_port_to_capture_pkt=dut_port,
        ptf_port_index=ptf_port_index,
        ptf_mac_port_index=ptf_port_index,
        test_xid=test_xid,
        dhcp_interface=vlan_name,
        expected_assigned_ip=expected_assigned_ip,
        exp_gateway=gateway,
        net_mask=net_mask
    )
    clean_dhcp_server_config(duthost)


@pytest.mark.parametrize("container_name", [DHCP_SERVER_CONTAINER_NAME, DHCP_RELAY_CONTAINER_NAME])
def test_dhcp_server_critical_process_crush(
    duthost,
    container_name
):
    """
        Test if dhcp server can recover from critical process crush
    """
    running_critical_process_before_kill = get_running_critical_processes(duthost, container_name)
    pytest_assert(running_critical_process_before_kill, "No critical process found")

    critical_process = random.choice(running_critical_process_before_kill)
    logging.info("The random one critical process is %s" % critical_process)
    pid = duthost.shell("docker exec %s supervisorctl pid %s" % (container_name, critical_process))['stdout']
    pytest_assert(pid, "No pid found for critical process %s" % critical_process)

    duthost.shell("docker exec {} kill -SIGKILL {}".format(container_name, pid))
    pytest_assert(
        wait_until(
            10,
            1,
            1,
            lambda: 'Exited' in duthost.shell('docker ps -a | grep %s' % container_name)['stdout']
        ),
        "Container %s is not exited when critical process was killed" % DHCP_SERVER_CONTAINER_NAME
    )

    pytest_assert(
        wait_until(
            90,
            10,
            1,
            lambda: len(running_critical_process_before_kill) ==
            len(get_running_critical_processes(duthost, container_name))
        ),
        "Running critical process count of container %s changed after restart" % DHCP_SERVER_CONTAINER_NAME
    )
