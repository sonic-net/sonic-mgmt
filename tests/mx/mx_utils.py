from tests.common.helpers.assertions import pytest_require


def create_vlan(duthost, vlan_config, dut_port_map):
    """
    Create vlans by vlan_config
    """
    intf_count = 0
    for vlan_id, config in vlan_config.items():
        duthost.shell("config vlan add {}".format(vlan_id))
        duthost.shell("config interface ip add Vlan{} {}".format(vlan_id, config["prefix"]))
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
        duthost.remove_ip_from_port("Vlan{}".format(vlan_id), config["prefix"])
        for member in config["members"]:
            duthost.del_member_from_vlan(vlan_id, dut_port_map[member])

        duthost.remove_vlan(vlan_id)


def get_vlan_config(vlan_configs, vlan_number):
    """
    Get vlan_config by number of vlans
    """
    vlan_config = None
    for config in vlan_configs:
        if len(config.keys()) == vlan_number:
            vlan_config = config
            break
    pytest_require(vlan_config is not None, "Can't get {} vlan config".format(vlan_number))
    return vlan_config
