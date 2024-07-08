import logging
import ipaddress
import pytest
import random
from tests.common.helpers.assertions import pytest_assert
from dhcp_server_test_common import create_common_config_patch, append_common_config_patch, \
    verify_discover_and_request_then_release, apply_dhcp_server_config_gcu, empty_config_patch, \
    vlan_n2i


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
    pytest_assert(len(vlan_member_with_ptf_idx) >= 8, 'Vlan member is too litte for testing')
    random.shuffle(vlan_member_with_ptf_idx)
    vlan_net = ipaddress.ip_network(address=first_vlan_ipv4_prefix, strict=False)
    pytest_assert(vlan_net.num_addresses >= 12, 'Vlan size is too small for testing')

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
    apply_dhcp_server_config_gcu(duthost, patch_setup)

    logging.info("The four_vlans_info after setup is %s" % four_vlans_info)
    yield four_vlans_info

    logging.info("The patch for restore is %s" % patch_restore)
    apply_dhcp_server_config_gcu(duthost, patch_restore)


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
        if i == 3:
            # change the fourth vlan to a smaller subnet
            smaller_prefix_length = 30
            smaller_subnet = list(vlan_nets[i].subnets(new_prefix=smaller_prefix_length))[0]
            four_vlans_info.append(
                {
                    'vlan_name': 'Vlan40%s' % i,
                    'vlan_gateway': str(list(smaller_subnet.hosts())[0]),
                    'interface_ipv4': str(list(smaller_subnet.hosts())[0]) + '/' + str(smaller_prefix_length),
                    'vlan_subnet_mask': str(smaller_subnet.netmask),
                    'vlan_hosts': [str(host) for host in list(smaller_subnet.hosts())[1:]],
                    'members_with_ptf_idx': [(member, ptf_idx) for member, ptf_idx
                                             in vlan_member_with_ptf_idx[member_count*i:member_count*i+1]]
                }
            )
        else:
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

    test_sets = []
    config_to_apply = empty_config_patch()
    for vlan_info in four_vlans_info:
        vlan_name, gateway, net_mask, vlan_hosts, vlan_members_with_ptf_idx = vlan_info['vlan_name'], \
            vlan_info['vlan_gateway'], vlan_info['vlan_subnet_mask'], vlan_info['vlan_hosts'], \
            vlan_info['members_with_ptf_idx']
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
        for index in range(len(dut_ports)):
            test_xid = 1000 + index
            test_sets.append((vlan_name, gateway, net_mask, dut_ports[index], ptf_port_indexs[index],
                              exp_assigned_ip_ranges[index], test_xid))

    apply_dhcp_server_config_gcu(duthost, config_to_apply)
    for vlan_name, gateway, net_mask, dut_port, ptf_port_index, exp_assigned_ip_range, test_xid in test_sets:
        logging.info("Testing for vlan %s, gateway %s, net_mask %s dut_port %s, ptf_port_index %s, \
                     expected_assigned_ip %s, test_xid %s" % (vlan_name, gateway, net_mask, dut_port,
                                                              ptf_port_index, exp_assigned_ip_range, test_xid))
        verify_discover_and_request_then_release(
            duthost=duthost,
            ptfhost=ptfhost,
            ptfadapter=ptfadapter,
            dut_port_to_capture_pkt=dut_port,
            ptf_port_index=ptf_port_index,
            ptf_mac_port_index=ptf_port_index,
            test_xid=test_xid,
            dhcp_interface=vlan_name,
            expected_assigned_ip=exp_assigned_ip_range[0],
            exp_gateway=gateway,
            server_id=gateway,
            net_mask=net_mask
        )


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
    # exclude the fourth vlan which has a smaller subnet
    vlan_info_1, vlan_info_2 = random.sample(four_vlans_info[:3], 2)
    logging.info("vlan_info_1 is %s, vlan_info_2 is %s" % (vlan_info_1, vlan_info_2))
    vlan_name_1, gateway_1, net_mask_1, vlan_hosts_1, vlan_members_with_ptf_idx_1 = vlan_info_1['vlan_name'], \
        vlan_info_1['vlan_gateway'], vlan_info_1['vlan_subnet_mask'], vlan_info_1['vlan_hosts'], \
        vlan_info_1['members_with_ptf_idx']
    expected_assigned_ip_1 = random.choice(vlan_hosts_1)
    last_ip_in_range_1 = random.choice(vlan_hosts_1[vlan_hosts_1.index(expected_assigned_ip_1) + 1:])
    dut_port_1, ptf_port_index_1 = random.choice(vlan_members_with_ptf_idx_1)
    logging.info("expected_assigned_ip_1 is %s, last_ip_in_range_1 is %s, dut_port_1 is %s, ptf_port_index_1 is %s" %
                 (expected_assigned_ip_1, last_ip_in_range_1, dut_port_1, ptf_port_index_1))

    test_xid_2 = 114
    vlan_name_2, gateway_2, net_mask_2, vlan_hosts_2, vlan_members_with_ptf_idx_2 = vlan_info_2['vlan_name'], \
        vlan_info_2['vlan_gateway'], vlan_info_2['vlan_subnet_mask'], vlan_info_2['vlan_hosts'], \
        vlan_info_2['members_with_ptf_idx']
    expected_assigned_ip_2 = random.choice(vlan_hosts_2)
    last_ip_in_range_2 = random.choice(vlan_hosts_2[vlan_hosts_2.index(expected_assigned_ip_2) + 1:])
    dut_port_2, ptf_port_index_2 = random.choice(vlan_members_with_ptf_idx_2)
    logging.info("expected_assigned_ip_2 is %s, last_ip_in_range_2 is %s, dut_port_2 is %s, ptf_port_index_2 is %s" %
                 (expected_assigned_ip_2, last_ip_in_range_2, dut_port_2, ptf_port_index_2))
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
        server_id=gateway_1,
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
        server_id=gateway_2,
        net_mask=net_mask_2
    )
