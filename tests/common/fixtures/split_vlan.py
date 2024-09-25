import pytest
import logging
import ipaddress
import json
from math import log, ceil
from tests.common.helpers.assertions import pytest_assert
from tests.common.gcu_utils import create_checkpoint, rollback_or_reload, delete_checkpoint


@pytest.fixture(scope="module")
def setup_multiple_vlans_and_teardown(duthost, tbinfo):
    vlan_brief = duthost.get_vlan_brief()
    first_vlan_name = list(vlan_brief.keys())[0]
    first_vlan_info = list(vlan_brief.values())[0]
    running_config = duthost.get_running_config_facts()
    first_vlan_info['dhcp_servers'] = running_config['VLAN'][first_vlan_name].get('dhcp_servers', [])
    first_vlan_info['dhcp_relay'] = running_config['DHCP_RELAY'].get(first_vlan_name, {}).get('dhcp_servers', [])
    first_vlan_info['dhcpv6_servers'] = running_config['VLAN'][first_vlan_name].get('dhcpv6_servers', [])
    first_vlan_info['dhcpv6_relay'] = running_config['DHCP_RELAY'].get(first_vlan_name, {}).get('dhcpv6_servers', [])
    disabled_host_interfaces = tbinfo['topo']['properties']['topology'].get('disabled_host_interfaces', [])
    connected_ptf_ports_idx = [interface for interface in
                               tbinfo['topo']['properties']['topology'].get('host_interfaces', [])
                               if interface not in disabled_host_interfaces]
    dut_intf_to_ptf_index = duthost.get_extended_minigraph_facts(tbinfo)['minigraph_ptf_indices']
    connected_dut_intf_to_ptf_index = {k: v for k, v in dut_intf_to_ptf_index.items() if v in connected_ptf_ports_idx}
    vlan_members = first_vlan_info['members']
    vlan_member_with_ptf_idx = [(member, connected_dut_intf_to_ptf_index[member])
                                for member in vlan_members if member in connected_dut_intf_to_ptf_index]
    logging.info("The first_vlan_info before test is %s" % first_vlan_info)
    sub_vlans_info, config_patch = generate_sub_vlans_config_patch(
        first_vlan_name,
        first_vlan_info,
        vlan_member_with_ptf_idx
    )
    try:
        checkpoint_name = 'mutiple_vlans_test'
        create_checkpoint(duthost, checkpoint_name)

        logging.info("The patch for setup is %s" % config_patch)
        apply_config_patch(duthost, config_patch)
        logging.info("The sub_vlans_info after setup is %s" % sub_vlans_info)

        yield sub_vlans_info
    finally:
        rollback_or_reload(duthost, checkpoint_name)
        delete_checkpoint(duthost, checkpoint_name)


def generate_sub_vlans_config_patch(vlan_name, vlan_info, vlan_member_with_ptf_idx, count=2):
    pytest_assert(len(vlan_info['interface_ipv4']) > 0, "Expected at least one ipv4 address prefix")
    pytest_assert(len(vlan_info['interface_ipv6']) > 0, "Expected at least one ipv6 address prefix")
    pytest_assert(len(vlan_member_with_ptf_idx) > count, "Expected vlan member count more than sub vlan count")

    sub_vlans_info, config_patch = [], []
    config_patch += remove_vlan_patch(vlan_name) \
        + remove_vlan_relay_patch(vlan_name) \
        + [remove_vlan_ip_patch(vlan_name, ip)[0] for ip in vlan_info['interface_ipv4']] \
        + [remove_vlan_ip_patch(vlan_name, ip)[0] for ip in vlan_info['interface_ipv6']] \
        + [remove_vlan_member_patch(vlan_name, member)[0] for member in vlan_info['members']]

    vlan_prefix_v4 = vlan_info['interface_ipv4'][0]
    vlan_net_v4 = ipaddress.ip_network(address=vlan_prefix_v4, strict=False)
    vlan_nets_v4 = list(vlan_net_v4.subnets(prefixlen_diff=int(ceil(log(count, 2)))))
    vlan_prefix_v6 = vlan_info['interface_ipv6'][0]
    vlan_net_v6 = ipaddress.ip_network(address=vlan_prefix_v6, strict=False)
    vlan_nets_v6 = list(vlan_net_v6.subnets(prefixlen_diff=int(ceil(log(count, 2)))))
    member_count = len(vlan_member_with_ptf_idx)//count
    for i in range(count):
        sub_vlans_info.append(
            {
                'vlan_name': 'Vlan90%s' % i,
                'interface_ipv4': str(next(vlan_nets_v4[i].hosts())) + '/' + str(vlan_nets_v4[i].prefixlen),
                'interface_ipv6': str(next(vlan_nets_v6[i].hosts())) + '/' + str(vlan_nets_v6[i].prefixlen),
                'members_with_ptf_idx': [(member, ptf_idx) for member, ptf_idx
                                         in vlan_member_with_ptf_idx[member_count*i:member_count*(i+1)]]
            }
        )

    for info in sub_vlans_info:
        new_vlan_name = info['vlan_name']
        new_interface_ipv4 = info['interface_ipv4']
        new_interface_ipv6 = info['interface_ipv6']
        new_members_with_ptf_idx = info['members_with_ptf_idx']
        config_patch += add_vlan_patch(new_vlan_name, vlan_info['dhcp_servers'], vlan_info['dhcpv6_servers']) \
            + add_vlan_relay_patch(new_vlan_name, vlan_info['dhcp_relay'], vlan_info['dhcpv6_relay']) \
            + add_vlan_ip_patch(new_vlan_name, new_interface_ipv4) \
            + add_vlan_ip_patch(new_vlan_name, new_interface_ipv6) \
            + [add_vlan_member_patch(new_vlan_name, member)[0] for member, _ in new_members_with_ptf_idx]

    return sub_vlans_info, config_patch


def vlan_n2i(vlan_name):
    """
        Convert vlan name to vlan id
    """
    return vlan_name.replace("Vlan", "")


def add_vlan_patch(vlan_name, dhcp_servers, dhcpv6_servers):
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
    if dhcp_servers:
        patch[0]["value"]["dhcp_servers"] = dhcp_servers
    if dhcpv6_servers:
        patch[0]["value"]["dhcpv6_servers"] = dhcpv6_servers
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


def add_vlan_relay_patch(vlan_name, dhcp_servers, dhcpv6_servers):
    patch = [{
        "op": "add",
        "path": "/DHCP_RELAY/%s" % vlan_name,
        "value": {}
    }]
    if dhcp_servers:
        patch[0]["value"]["dhcp_servers"] = dhcp_servers
    if dhcpv6_servers:
        patch[0]["value"]["dhcpv6_servers"] = dhcpv6_servers
    return patch


def remove_vlan_relay_patch(vlan_name):
    patch = [{
        "op": "remove",
        "path": "/DHCP_RELAY/%s" % vlan_name
    }]
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


def apply_config_patch(duthost, config_to_apply):
    logging.info("The config patch: %s" % config_to_apply)
    tmpfile = duthost.shell('mktemp')['stdout']
    try:
        duthost.copy(content=json.dumps(config_to_apply, indent=4), dest=tmpfile)
        output = duthost.shell('config apply-patch {}'.format(tmpfile), module_ignore_errors=True)
        pytest_assert(not output['rc'], "Command is not running successfully")
        pytest_assert(
            "Patch applied successfully" in output['stdout'],
            "Please check if json file is validate"
        )
    finally:
        duthost.file(path=tmpfile, state='absent')
