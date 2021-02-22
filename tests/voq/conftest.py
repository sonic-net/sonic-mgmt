import pytest


@pytest.fixture(scope="module", autouse=True)
def chassis_facts(duthosts):
    """
    Fixture to add some items to host facts from inventory file.
    """
    for a_host in duthosts.nodes:

        if len(duthosts.supervisor_nodes) > 0:
            slot_num = a_host.command(
                "python3 -c 'import platform_ndk.nokia_common; print(platform_ndk.nokia_common._get_my_slot())'")[
                'stdout']
            a_host.facts['slot_num'] = int(slot_num)


@pytest.fixture(scope="module")
def all_cfg_facts(duthosts):
    # { 'ixr_vdk_boar10' : [ asic0_results, asic1_results ] }
    #   asic0_results['ansible_facts']
    # result = duthosts.config_facts(source='persistent', asic_index='all')
    # return result
    # work around https://github.com/Azure/sonic-mgmt/issues/3020
    results = {}
    for node in duthosts.nodes:
        results[node.hostname] = node.config_facts(source='persistent', asic_index='all')
    return results


@pytest.fixture(scope="module", autouse=True)
def bgp_redistribute_route_lo(duthosts, all_cfg_facts):
    for a_host in duthosts.frontend_nodes:
        for a_asic in a_host.asics:
            asic_asn = all_cfg_facts[a_host.hostname][a_asic.asic_index]['ansible_facts']['DEVICE_METADATA']['localhost']['bgp_asn']
            send_command = a_asic.get_docker_cmd(
                "vtysh -c 'configure terminal' -c 'router bgp " + asic_asn + "' -c 'address-family ipv4 unicast' -c 'redistribute connected'",
                "bgp")
            send_command_ipv6 = a_asic.get_docker_cmd(
                "vtysh -c 'configure terminal' -c 'router bgp " + asic_asn + "' -c 'address-family ipv6 unicast' -c 'redistribute connected'",
                "bgp")
            a_host.command(send_command)
            a_host.command(send_command_ipv6)
