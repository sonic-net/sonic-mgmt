import logging
import ipaddress
import pytest
import random
from tests.common.helpers.assertions import pytest_assert
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success, generate_tmpfile, delete_tmpfile
from dhcp_server_test_common import create_common_config_patch, append_common_config_patch, \
    verify_discover_and_request_then_release, clean_dhcp_server_config, apply_dhcp_server_config_gcu

pytestmark = [
    pytest.mark.topology('mx'),
]


@pytest.fixture(scope="module", autouse=True)
def setup_multiple_vlans_and_teardown(duthost, tbinfo):
    vlan_brief = duthost.get_vlan_brief()
    first_vlan_name = list(vlan_brief.keys())[0]
    first_vlan_info = list(vlan_brief.values())[0]
    first_vlan_ipv4_prefix = first_vlan_info['interface_ipv4'][0]
    disabled_host_interfaces = tbinfo['topo']['properties']['topology'].get('disabled_host_interfaces', [])
    connected_ptf_ports_idx = [interface for interface in
                               tbinfo['topo']['properties']['topology'].get('host_interfaces', [])
                               if interface not in disabled_host_interfaces]
    dut_intf_to_ptf_index = duthost.get_extended_minigraph_facts(tbinfo)['minigraph_ptf_indices']
    connected_dut_intf_to_ptf_index = {k: v for k, v in dut_intf_to_ptf_index.items() if v in connected_ptf_ports_idx}
    vlan_members = first_vlan_info['members']
    vlan_member_with_ptf_idx = [(member, connected_dut_intf_to_ptf_index[member])
                                for member in vlan_members if member in connected_dut_intf_to_ptf_index]
    pytest_assert(len(vlan_member_with_ptf_idx) >= 8, 'Vlan size is too small for testing')
    vlan_net = ipaddress.ip_network(address=first_vlan_ipv4_prefix, strict=False)
    pytest_assert(vlan_net.num_addresses >= 8, 'Vlan size is too small for testing')

    vlan_setting = {
        'vlan_name': first_vlan_name,
        'vlan_info': first_vlan_info,
        'vlan_member_with_ptf_idx': vlan_member_with_ptf_idx,
    }

    logging.info("The vlan_setting before test is %s" % vlan_setting)
    four_vlans_info, patch_setup, patch_restore = generate_four_vlans_config_patch(
        first_vlan_name,
        first_vlan_info,
        vlan_member_with_ptf_idx
    )

    logging.info("The patch for setup is %s" % patch_setup)
    apply_vlan_config_patch(duthost, patch_setup)
    # import pdb; pdb.set_trace()

    logging.info("The four_vlans_info after setup is %s" % four_vlans_info)
    yield four_vlans_info

    logging.info("The patch for restore is %s" % patch_restore)
    apply_vlan_config_patch(duthost, patch_restore)
    # import pdb; pdb.set_trace()


def generate_four_vlans_config_patch(vlan_name, vlan_info, vlan_member_with_ptf_idx):
    four_vlans_info, patch_setup, patch_restore = [], [], []
    patch_setup += remove_vlan_patch(vlan_name) \
        + [remove_vlan_ip_patch(vlan_name, ip)[0] for ip in vlan_info['interface_ipv4']] \
        + [remove_vlan_ip_patch(vlan_name, ip)[0] for ip in vlan_info['interface_ipv6']] \
        + [remove_vlan_member_patch(vlan_name, member)[0] for member in vlan_info['members']]

    patch_restore += add_vlan_patch(vlan_name) \
        + [add_vlan_ip_patch(vlan_name, ip)[0] for ip in vlan_info['interface_ipv4']] \
        + [add_vlan_ip_patch(vlan_name, ip)[0] for ip in vlan_info['interface_ipv6']] \
        + [add_vlan_member_patch(vlan_name, member)[0] for member in vlan_info['members']]

    # split single vlan into two vlans
    vlan_prefix = vlan_info['interface_ipv4'][0]
    vlan_net = ipaddress.ip_network(address=vlan_prefix, strict=False)
    vlan_nets = list(vlan_net.subnets(prefixlen_diff=2))
    member_count = len(vlan_member_with_ptf_idx)//4
    for i in range(4):
        four_vlans_info.append(
            {
                'vlan_name': 'Vlan40%s' % i,
                'vlan_gateway': str(list(vlan_nets[i].hosts())[0]),
                'interface_ipv4': str(list(vlan_nets[i].hosts())[0]) + '/' + str(vlan_nets[i].prefixlen),
                'vlan_subnet_mask': str(vlan_nets[i].netmask),
                'vlan_hosts': [str(host) for host in list(vlan_nets[i].hosts())[1:]],
                'members_with_ptf_idx': [(member, ptf_idx) for member, ptf_idx
                                         in vlan_member_with_ptf_idx[member_count*i:member_count*(i+1)]]
            }
        )

    for info in four_vlans_info:
        new_vlan_name = info['vlan_name']
        new_interface_ipv4 = info['interface_ipv4']
        new_members_with_ptf_idx = info['members_with_ptf_idx']
        patch_setup += add_vlan_patch(new_vlan_name) \
            + add_vlan_ip_patch(new_vlan_name, new_interface_ipv4) \
            + [add_vlan_member_patch(new_vlan_name, member)[0] for member, _ in new_members_with_ptf_idx]
        patch_restore += remove_vlan_patch(new_vlan_name) \
            + remove_vlan_ip_patch(new_vlan_name, new_interface_ipv4) \
            + [remove_vlan_member_patch(new_vlan_name, member)[0] for member, _ in new_members_with_ptf_idx]

    return four_vlans_info, patch_setup, patch_restore


def apply_vlan_config_patch(duthost, config_patch_to_apply):
    logging.info("The vlan config patch for dhcp_server test: %s" % config_patch_to_apply)
    tmpfile = generate_tmpfile(duthost)
    try:
        output = apply_patch(duthost, json_data=config_patch_to_apply, dest_file=tmpfile)
        expect_op_success(duthost, output)
    finally:
        delete_tmpfile(duthost, tmpfile)


def vlan_i2n(vlan_id):
    """
        Convert vlan id to vlan name
    """
    return "Vlan%s" % vlan_id


def vlan_n2i(vlan_name):
    """
        Convert vlan name to vlan id
    """
    return vlan_name.replace("Vlan", "")


def add_vlan_patch(vlan_name):
    patch = [
        {
            "op": "add",
            "path": "/VLAN/%s" % vlan_name,
            "value": {
                "vlanid": vlan_n2i(vlan_name)
            }
        },
        {
            "op": "add",
            "path": "/VLAN_INTERFACE/%s" % vlan_name,
            "value": {}
        }
    ]
    return patch


def remove_vlan_patch(vlan_name):
    patch = [
        {
            "op": "remove",
            "path": "/VLAN/%s" % vlan_name
        },
        {
            "op": "remove",
            "path": "/VLAN_INTERFACE/%s" % vlan_name
        }
    ]
    return patch


def add_vlan_member_patch(vlan_name, member_name):
    patch = [{
        "op": "add",
        "path": "/VLAN_MEMBER/%s|%s" % (vlan_name, member_name),
        "value": {
            "tagging_mode": "untagged"
        }
    }]
    return patch


def remove_vlan_member_patch(vlan_name, member_name):
    patch = [{
        "op": "remove",
        "path": "/VLAN_MEMBER/%s|%s" % (vlan_name, member_name)
    }]
    return patch


def add_vlan_ip_patch(vlan_name, ip):
    patch = [{
        "op": "add",
        "path": "/VLAN_INTERFACE/%s|%s" % (vlan_name, ip.replace('/', '~1')),
        "value": {}
    }]
    return patch


def remove_vlan_ip_patch(vlan_name, ip):
    patch = [{
        "op": "remove",
        "path": "/VLAN_INTERFACE/%s|%s" % (vlan_name, ip.replace('/', '~1'))
    }]
    return patch


def test_single_ip_assignment(
    duthost,
    ptfhost,
    ptfadapter,
    setup_multiple_vlans_and_teardown
):
    """
        Verify configured interface can successfully get IP
    """

    four_vlans_info = setup_multiple_vlans_and_teardown

    test_xid_1 = 111
    vlan_info_1, vlan_info_2 = random.sample(four_vlans_info, 2)
    vlan_name_1, gateway_1, net_mask_1, vlan_hosts_1, vlan_members_with_ptf_idx_1 = vlan_info_1['vlan_name'], \
        vlan_info_1['vlan_gateway'], vlan_info_1['vlan_subnet_mask'], vlan_info_1['vlan_hosts'], \
        vlan_info_1['members_with_ptf_idx']
    expected_assigned_ip_1 = random.choice(vlan_hosts_1)
    dut_port_1, ptf_port_index_1 = random.choice(vlan_members_with_ptf_idx_1)

    test_xid_2 = 112
    vlan_name_2, gateway_2, net_mask_2, vlan_hosts_2, vlan_members_with_ptf_idx_2 = vlan_info_2['vlan_name'], \
        vlan_info_2['vlan_gateway'], vlan_info_2['vlan_subnet_mask'], vlan_info_2['vlan_hosts'], \
        vlan_info_2['members_with_ptf_idx']
    expected_assigned_ip_2 = random.choice(vlan_hosts_2)
    dut_port_2, ptf_port_index_2 = random.choice(vlan_members_with_ptf_idx_2)
    config_to_apply = create_common_config_patch(
        vlan_name_1,
        gateway_1,
        net_mask_1,
        [dut_port_1],
        [[expected_assigned_ip_1]]
    )
    append_common_config_patch(
        config_to_apply,
        vlan_name_2,
        gateway_2,
        net_mask_2,
        [dut_port_2],
        [[expected_assigned_ip_2]]
    )

    apply_dhcp_server_config_gcu(duthost, config_to_apply)
    verify_discover_and_request_then_release(
        duthost=duthost,
        ptfhost=ptfhost,
        ptfadapter=ptfadapter,
        dut_port_to_capture_pkt=dut_port_1,
        ptf_port_index=ptf_port_index_1,
        ptf_mac_port_index=ptf_port_index_1,
        test_xid=test_xid_1,
        dhcp_interface=vlan_name_1,
        expected_assigned_ip=expected_assigned_ip_1,
        exp_gateway=gateway_1,
        net_mask=net_mask_1
    )
    verify_discover_and_request_then_release(
        duthost=duthost,
        ptfhost=ptfhost,
        ptfadapter=ptfadapter,
        dut_port_to_capture_pkt=dut_port_2,
        ptf_port_index=ptf_port_index_2,
        ptf_mac_port_index=ptf_port_index_2,
        test_xid=test_xid_2,
        dhcp_interface=vlan_name_2,
        expected_assigned_ip=expected_assigned_ip_2,
        exp_gateway=gateway_2,
        net_mask=net_mask_2
    )
    clean_dhcp_server_config(duthost)


def test_range_ip_assignment(
    duthost,
    ptfhost,
    ptfadapter,
    setup_multiple_vlans_and_teardown
):
    """
        Verify configured interface can successfully get IP from an IP range
    """

    four_vlans_info = setup_multiple_vlans_and_teardown

    test_xid_1 = 113
    vlan_info_1, vlan_info_2 = random.sample(four_vlans_info, 2)
    vlan_name_1, gateway_1, net_mask_1, vlan_hosts_1, vlan_members_with_ptf_idx_1 = vlan_info_1['vlan_name'], \
        vlan_info_1['vlan_gateway'], vlan_info_1['vlan_subnet_mask'], vlan_info_1['vlan_hosts'], \
        vlan_info_1['members_with_ptf_idx']
    expected_assigned_ip_1 = random.choice(vlan_hosts_1)
    last_ip_in_range_1 = random.choice(vlan_hosts_1[vlan_hosts_1.index(expected_assigned_ip_1) + 1:])
    dut_port_1, ptf_port_index_1 = random.choice(vlan_members_with_ptf_idx_1)

    test_xid_2 = 114
    vlan_name_2, gateway_2, net_mask_2, vlan_hosts_2, vlan_members_with_ptf_idx_2 = vlan_info_2['vlan_name'], \
        vlan_info_2['vlan_gateway'], vlan_info_2['vlan_subnet_mask'], vlan_info_2['vlan_hosts'], \
        vlan_info_2['members_with_ptf_idx']
    expected_assigned_ip_2 = random.choice(vlan_hosts_2)
    last_ip_in_range_2 = random.choice(vlan_hosts_2[vlan_hosts_2.index(expected_assigned_ip_2) + 1:])
    dut_port_2, ptf_port_index_2 = random.choice(vlan_members_with_ptf_idx_2)
    config_to_apply = create_common_config_patch(
        vlan_name_1,
        gateway_1,
        net_mask_1,
        [dut_port_1],
        [[expected_assigned_ip_1, last_ip_in_range_1]]
    )
    append_common_config_patch(
        config_to_apply,
        vlan_name_2,
        gateway_2,
        net_mask_2,
        [dut_port_2],
        [[expected_assigned_ip_2, last_ip_in_range_2]]
    )

    apply_dhcp_server_config_gcu(duthost, config_to_apply)
    verify_discover_and_request_then_release(
        duthost=duthost,
        ptfhost=ptfhost,
        ptfadapter=ptfadapter,
        dut_port_to_capture_pkt=dut_port_1,
        ptf_port_index=ptf_port_index_1,
        ptf_mac_port_index=ptf_port_index_1,
        test_xid=test_xid_1,
        dhcp_interface=vlan_name_1,
        expected_assigned_ip=expected_assigned_ip_1,
        exp_gateway=gateway_1,
        net_mask=net_mask_1
    )
    verify_discover_and_request_then_release(
        duthost=duthost,
        ptfhost=ptfhost,
        ptfadapter=ptfadapter,
        dut_port_to_capture_pkt=dut_port_2,
        ptf_port_index=ptf_port_index_2,
        ptf_mac_port_index=ptf_port_index_2,
        test_xid=test_xid_2,
        dhcp_interface=vlan_name_2,
        expected_assigned_ip=expected_assigned_ip_2,
        exp_gateway=gateway_2,
        net_mask=net_mask_2
    )
    clean_dhcp_server_config(duthost)


def test_dhcp_server_config_vlan_intf_change(
    duthost,
    ptfhost,
    ptfadapter,
    setup_multiple_vlans_and_teardown
):
    """
        When dhcp server congifurate a subnet not belong to current VLAN,
        the dhcp server should assign IP from the subnet
    """

    four_vlans_info = setup_multiple_vlans_and_teardown

    test_xid_1 = 115
    vlan_info_1, vlan_info_2 = random.sample(four_vlans_info, 2)
    vlan_name_1, gateway_1, net_mask_1, vlan_hosts_1, vlan_members_with_ptf_idx_1 = vlan_info_1['vlan_name'], \
        vlan_info_1['vlan_gateway'], vlan_info_1['vlan_subnet_mask'], vlan_info_1['vlan_hosts'], \
        vlan_info_1['members_with_ptf_idx']
    expected_assigned_ip_1 = random.choice(vlan_hosts_1)
    dut_port_1, ptf_port_index_1 = random.choice(vlan_members_with_ptf_idx_1)

    _, gateway_2, net_mask_2, vlan_hosts_2, _ = vlan_info_2['vlan_name'], vlan_info_2['vlan_gateway'], \
        vlan_info_2['vlan_subnet_mask'], vlan_info_2['vlan_hosts'], vlan_info_2['members_with_ptf_idx']
    expected_assigned_ip_2 = random.choice(vlan_hosts_2)
    config_to_apply = create_common_config_patch(
        vlan_name_1,
        gateway_2,
        net_mask_2,
        [dut_port_1],
        [[expected_assigned_ip_2]]
    )

    # when the subnet not match to VLAN, client won't get IP
    apply_dhcp_server_config_gcu(duthost, config_to_apply)
    verify_discover_and_request_then_release(
        duthost=duthost,
        ptfhost=ptfhost,
        ptfadapter=ptfadapter,
        dut_port_to_capture_pkt=dut_port_1,
        ptf_port_index=ptf_port_index_1,
        ptf_mac_port_index=ptf_port_index_1,
        test_xid=test_xid_1,
        dhcp_interface=None,
        expected_assigned_ip=None,
        exp_gateway=None,
        net_mask=None
    )
    # When the subnet is changed to match VLAN, client can get IP
    patch_subnet = [
        {
            "op": "replace",
            "path": "/DHCP_SERVER_IPV4_RANGE/range_%s/range/0" % expected_assigned_ip_2,
            "value": expected_assigned_ip_1
        },
        {
            "op": "replace",
            "path": "/DHCP_SERVER_IPV4/%s/netmask" % vlan_name_1,
            "value": net_mask_1
        },
        {
            "op": "replace",
            "path": "/DHCP_SERVER_IPV4/%s/gateway" % vlan_name_1,
            "value": gateway_1
        }
    ]
    apply_dhcp_server_config_gcu(duthost, patch_subnet)
    verify_discover_and_request_then_release(
        duthost=duthost,
        ptfhost=ptfhost,
        ptfadapter=ptfadapter,
        dut_port_to_capture_pkt=dut_port_1,
        ptf_port_index=ptf_port_index_1,
        ptf_mac_port_index=ptf_port_index_1,
        test_xid=test_xid_1,
        dhcp_interface=vlan_name_1,
        expected_assigned_ip=expected_assigned_ip_1,
        exp_gateway=gateway_1,
        net_mask=net_mask_1
    )
    clean_dhcp_server_config(duthost)
