from tests.common.helpers.assertions import pytest_require


def create_vlan(duthost, vlan_config, dut_port_map):
    """
    Create vlans by vlan_config
    """
    intf_count = 0
    for vlan_id, config in vlan_config.items():
        duthost.shell("config vlan add {}".format(vlan_id))
        vlan_interface_ipv4 = config.get("interface_ipv4", None)
        if vlan_interface_ipv4 is not None:
            duthost.shell("config interface ip add Vlan{} {}".format(vlan_id, vlan_interface_ipv4))
        vlan_interface_ipv6 = config.get("interface_ipv6", None)
        if vlan_interface_ipv6 is not None:
            duthost.shell("config interface ip add Vlan{} {}".format(vlan_id, vlan_interface_ipv6))
        for member in config["members"]:
            duthost.add_member_to_vlan(vlan_id, dut_port_map[member], False)

            if len(config["members"]) != 1:
                intf_count += 1

    return intf_count


def remove_vlan(duthost, vlan_config, dut_port_map):
    """
    Remove vlan by vlan_config
    """
    for vlan_id, config in vlan_config.items():
        vlan_interface_ipv4 = config.get("interface_ipv4", None)
        if vlan_interface_ipv4 is not None:
            duthost.remove_ip_from_port("Vlan{}".format(vlan_id), vlan_interface_ipv4)
        vlan_interface_ipv6 = config.get("interface_ipv6", None)
        if vlan_interface_ipv6 is not None:
            duthost.remove_ip_from_port("Vlan{}".format(vlan_id), vlan_interface_ipv6)
        for member in config["members"]:
            duthost.del_member_from_vlan(vlan_id, dut_port_map[member])
        duthost.remove_vlan(vlan_id)


def get_vlan_config(vlan_configs, vlan_number):
    """
    Get vlan_config by number of vlans
    """
    vlan_config = vlan_configs.get(str(vlan_number), None)
    pytest_require(vlan_config is not None, "Can't get {} vlan config".format(vlan_number))
    return vlan_config


def check_dnsmasq(duthost, intf_count):
    """
    Check whether dhcp ip pool is OK
    """
    command_output = duthost.shell("docker exec -i dhcp_relay wc -l /etc/dnsmasq.hosts", module_ignore_errors=True)
    if command_output['rc'] != 0:
        return False

    dnsmasq_count = int("".join([i for i in command_output['stdout'] if i.isdigit()]))
    return dnsmasq_count >= intf_count


def refresh_dut_mac_table(ptfhost, vlan_config, ptf_index_port):
    """
    ping from peer interface of DUT on ptf to refresh DUT mac table
    """
    for _, config in vlan_config.items():
        vlan_member = config["members"]
        vlan_ip = config["interface_ipv4"].split("/")[0]
        ping_commands = []
        for member in vlan_member:
            ptf_port_index = ptf_index_port[member]
            ping_commands.append("timeout 1 ping -c 1 -w 1 -I eth{} {}".format(ptf_port_index, vlan_ip))
        ptfhost.shell(" & ".join(ping_commands), module_ignore_errors=True)


def remove_all_vlans(duthost):
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"]
    if "VLAN_INTERFACE" in cfg_facts:
        vlan_intfs = cfg_facts["VLAN_INTERFACE"]
        for intf, prefixs in vlan_intfs.items():
            for prefix in prefixs.keys():
                duthost.remove_ip_from_port(intf, prefix)

    if "VLAN_MEMBER" in cfg_facts:
        vlan_members = cfg_facts["VLAN_MEMBER"]
        for vlan_name, members in vlan_members.items():
            vlan_id = int(''.join([i for i in vlan_name if i.isdigit()]))
            for member in members.keys():
                duthost.del_member_from_vlan(vlan_id, member)

            duthost.remove_vlan(vlan_id)
