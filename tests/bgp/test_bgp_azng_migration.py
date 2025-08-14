import ipaddress
import json
import pytest
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common import config_reload
from tests.common.utilities import get_image_type
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('t2')
]


def test_bgp_azng_migration(duthosts, enum_upstream_dut_hostname):

    duthost = duthosts[enum_upstream_dut_hostname]

    if get_image_type(duthost) == "public":
        pytest.skip("AZNG Migration is not supported on public image")

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']

    peer_device_namespace = DEFAULT_NAMESPACE
    peer_device_ip_set = set()

    for peer_device, peer_device_info in config_facts['DEVICE_NEIGHBOR_METADATA'].items():
        if peer_device_info['type'] == "AZNGHub":
            for peer_device_ip, peer_device_bgp_data in config_facts['BGP_NEIGHBOR'].items():
                if peer_device_bgp_data["name"] == peer_device:
                    peer_device_ip_set.add(peer_device_ip)
            break

    if not len(peer_device_ip_set):
        pytest.skip("No AZNG Neighbors found")

    assert len(peer_device_ip_set) == 2, (
        "The number of AZNGHub peer device IPs found is not equal to 2. "
        "Expected 2 AZNGHub neighbors, but found {}: {}."
    ).format(
        len(peer_device_ip_set),
        list(peer_device_ip_set)
    )

    if duthost.is_multi_asic:
        bgp_name_to_ns_mapping = duthost.get_bgp_name_to_ns_mapping()
        peer_device_namespace = bgp_name_to_ns_mapping[peer_device]

    asichost = duthost.asic_instance_from_namespace(peer_device_namespace)

    bgp_fact_info = asichost.bgp_facts()

    for ip in peer_device_ip_set:
        assert bgp_fact_info['ansible_facts']['bgp_neighbors'][ip]['state'] == 'established', (
            "BGP session state mismatch for neighbor '{}'. Expected: 'established', got: '{}'."
        ).format(
            ip,
            bgp_fact_info['ansible_facts']['bgp_neighbors'][ip]['state']
        )

    adv_cmd_list = []
    recv_cmd_list = []

    for ip in peer_device_ip_set:
        if ipaddress.IPNetwork(ip).version == 4:
            bgp_nbr_recv_cmd = "sudo vtysh -c 'show ip bgp neighbors {} received-routes json'".format(
                ip)
            recv_cmd_list.append(bgp_nbr_recv_cmd)

            bgp_nbr_advertise_cmd = "sudo vtysh -c 'show ip bgp neighbors {} advertised-routes json'".format(
                ip)

            adv_cmd_list.append(bgp_nbr_advertise_cmd)
        else:
            bgp_nbr_recv_cmd = "sudo vtysh -c 'show bgp ipv6 neighbors {} received-routes json'".format(
                ip)
            recv_cmd_list.append(bgp_nbr_recv_cmd)

            bgp_nbr_advertise_cmd = "sudo vtysh -c 'show bgp ipv6 neighbors {} advertised-routes json'".format(
                ip)
            adv_cmd_list.append(bgp_nbr_advertise_cmd)

    original_ipv4_route_recv_count = 0
    original_ipv6_route_recv_count = 0
    original_ipv4_route_adv_count = 0
    original_ipv6_route_adv_count = 0
    original_ipv4_route_recv_filter_count = 0
    original_ipv6_route_recv_filter_count = 0
    original_ipv4_route_adv_filter_count = 0
    original_ipv6_route_adv_filter_count = 0
    success = False
    recover_via_minigraph = False

    try:
        for bgp_nbr_recv_cmd in recv_cmd_list:
            res = duthost.shell(duthost.get_vtysh_cmd_for_namespace(bgp_nbr_recv_cmd, peer_device_namespace))
            routes_json = json.loads(res['stdout'])

            if "ipv6" in bgp_nbr_recv_cmd:
                original_ipv6_route_recv_count = routes_json['totalPrefixCounter']
                original_ipv6_route_recv_filter_count = routes_json['filteredPrefixCounter']
            else:
                original_ipv4_route_recv_count = routes_json['totalPrefixCounter']
                original_ipv4_route_recv_filter_count = routes_json['filteredPrefixCounter']

            assert routes_json['totalPrefixCounter'] > 0, (
                "No BGP routes were found. totalPrefixCounter = {} (expected > 0).\n"
                "- Command: {}\n"
            ).format(
                routes_json['totalPrefixCounter'],
                bgp_nbr_recv_cmd if 'bgp_nbr_recv_cmd' in locals() else 'N/A'
            )

            assert routes_json['filteredPrefixCounter'] < routes_json['totalPrefixCounter'], (
                "Filtered prefix counter is not less than total prefix counter. "
                "Got filteredPrefixCounter: {}, totalPrefixCounter: {}."
            ).format(
                routes_json['filteredPrefixCounter'],
                routes_json['totalPrefixCounter']
            )

        for bgp_nbr_adv_cmd in adv_cmd_list:
            res = duthost.shell(duthost.get_vtysh_cmd_for_namespace(bgp_nbr_adv_cmd, peer_device_namespace))
            routes_json = json.loads(res['stdout'])

            if "ipv6" in bgp_nbr_adv_cmd:
                original_ipv6_route_adv_count = routes_json['totalPrefixCounter']
                original_ipv6_route_adv_filter_count = routes_json['filteredPrefixCounter']
            else:
                original_ipv4_route_adv_count = routes_json['totalPrefixCounter']
                original_ipv4_route_adv_filter_count = routes_json['filteredPrefixCounter']

            assert routes_json['totalPrefixCounter'] > 0, (
                "No BGP routes were found. totalPrefixCounter = {} (expected > 0).\n"
                "- Command: {}\n"
            ).format(
                routes_json['totalPrefixCounter'],
                bgp_nbr_recv_cmd if 'bgp_nbr_recv_cmd' in locals() else 'N/A'
            )

            assert routes_json['filteredPrefixCounter'] == 0, (
                "Filtered prefix counter is not zero after AZNG migration rollback. "
                "Expected filteredPrefixCounter == 0, but got {}. "
                "- Command: {}\n"
            ).format(
                routes_json['filteredPrefixCounter'],
                bgp_nbr_adv_cmd if 'bgp_nbr_adv_cmd' in locals() else 'N/A'
            )

        rc = duthost.shell('sudo azng_migration -r')
        pytest_assert(
            not rc['failed'],
            (
                "AZNG Migration Rollback failed. "
                "Return code: {}, Output: {}"
            ).format(
                rc.get('rc', 'N/A'),
                rc.get('stdout', 'N/A')
            )
        )

        for bgp_nbr_recv_cmd in recv_cmd_list:
            res = duthost.shell(duthost.get_vtysh_cmd_for_namespace(bgp_nbr_recv_cmd, peer_device_namespace))
            routes_json = json.loads(res['stdout'])
            assert routes_json['totalPrefixCounter'] > 0, (
                "No BGP routes were found. totalPrefixCounter = {} (expected > 0).\n"
                "- Command: {}\n"
            ).format(
                routes_json['totalPrefixCounter'],
                bgp_nbr_recv_cmd if 'bgp_nbr_recv_cmd' in locals() else 'N/A'
            )

            assert routes_json['filteredPrefixCounter'] == routes_json['totalPrefixCounter'], (
                "Filtered prefix counter does not match total prefix counter after AZNG migration step. "
                "Expected filteredPrefixCounter == totalPrefixCounter, but got filteredPrefixCounter: {}, "
                "totalPrefixCounter: {}. "
                "Command: {}\n"
            ).format(
                routes_json['filteredPrefixCounter'],
                routes_json['totalPrefixCounter'],
                bgp_nbr_recv_cmd
            )

        for bgp_nbr_adv_cmd in adv_cmd_list:
            res = duthost.shell(duthost.get_vtysh_cmd_for_namespace(bgp_nbr_adv_cmd, peer_device_namespace))
            routes_json = json.loads(res['stdout'])
            assert routes_json['totalPrefixCounter'] == len(duthosts), (
                "Mismatch in total advertised route count after AZNG migration rollback. "
                "Expected totalPrefixCounter to equal the number of DUT hosts ({}), but got {}. "
                "Command: {}\n"
            ).format(
                len(duthosts),
                routes_json['totalPrefixCounter'],
                bgp_nbr_adv_cmd
            )

            assert routes_json['filteredPrefixCounter'] == 0, (
                "Filtered prefix counter is not zero after AZNG migration rollback. "
                "Expected filteredPrefixCounter == 0, but got {}. "
                "- Command: {}\n"
            ).format(
                routes_json['filteredPrefixCounter'],
                bgp_nbr_adv_cmd if 'bgp_nbr_adv_cmd' in locals() else 'N/A'
            )

        rc = duthost.shell('sudo azng_migration -d')

        pytest_assert(
            not rc['failed'],
            (
                "AZNG Migration Deny Route-map apply failed. "
                "Return code: {}, Output: {}"
            ).format(
                rc.get('rc', 'N/A'),
                rc.get('stdout', 'N/A')
            )
        )

        for bgp_nbr_recv_cmd in recv_cmd_list:
            res = duthost.shell(duthost.get_vtysh_cmd_for_namespace(bgp_nbr_recv_cmd, peer_device_namespace))
            routes_json = json.loads(res['stdout'])
            assert routes_json['totalPrefixCounter'] > 0, (
                "No BGP routes were found. totalPrefixCounter = {} (expected > 0).\n"
                "- Command: {}\n"
            ).format(
                routes_json['totalPrefixCounter'],
                bgp_nbr_recv_cmd if 'bgp_nbr_recv_cmd' in locals() else 'N/A'
            )

            assert routes_json['filteredPrefixCounter'] == routes_json['totalPrefixCounter'], (
                "Filtered prefix counter does not match total prefix counter after AZNG migration step. "
                "Expected filteredPrefixCounter == totalPrefixCounter, but got filteredPrefixCounter: {}, "
                "totalPrefixCounter: {}. "
                "Command: {}\n"
            ).format(
                routes_json['filteredPrefixCounter'],
                routes_json['totalPrefixCounter'],
                bgp_nbr_recv_cmd
            )

        for bgp_nbr_adv_cmd in adv_cmd_list:
            res = duthost.shell(duthost.get_vtysh_cmd_for_namespace(bgp_nbr_adv_cmd, peer_device_namespace))
            routes_json = json.loads(res['stdout'])
            assert routes_json['totalPrefixCounter'] == 0, (
                "Total prefix counter is not zero after AZNG migration step. "
                "Expected totalPrefixCounter == 0, but got {}. "
                "- Command: {}\n"
            ).format(
                routes_json['totalPrefixCounter'],
                bgp_nbr_adv_cmd if 'bgp_nbr_adv_cmd' in locals() else 'N/A'
            )

            assert routes_json['filteredPrefixCounter'] == routes_json['totalPrefixCounter'], (
                "Filtered prefix counter does not match total prefix counter after AZNG migration step. "
                "Expected filteredPrefixCounter == totalPrefixCounter, but got filteredPrefixCounter: {}, "
                "totalPrefixCounter: {}. "
                "Command: {}\n"
            ).format(
                routes_json['filteredPrefixCounter'],
                routes_json['totalPrefixCounter'],
                bgp_nbr_recv_cmd
            )

        rc = duthost.shell('sudo azng_migration -i')
        pytest_assert(
            not rc['failed'],
            (
                "AZNG Migration Outbound Route-map permit apply failed. "
                "Return code: {}, Output: {}"
            ).format(
                rc.get('rc', 'N/A'),
                rc.get('stdout', 'N/A')
            )
        )

        for bgp_nbr_recv_cmd in recv_cmd_list:
            res = duthost.shell(duthost.get_vtysh_cmd_for_namespace(bgp_nbr_recv_cmd, peer_device_namespace))
            routes_json = json.loads(res['stdout'])
            assert routes_json['totalPrefixCounter'] > 0, (
                "No BGP routes were found. totalPrefixCounter = {} (expected > 0).\n"
                "- Command: {}\n"
            ).format(
                routes_json['totalPrefixCounter'],
                bgp_nbr_recv_cmd if 'bgp_nbr_recv_cmd' in locals() else 'N/A'
            )

            assert routes_json['filteredPrefixCounter'] == routes_json['totalPrefixCounter'], (
                "Filtered prefix counter does not match total prefix counter after AZNG migration step. "
                "Expected filteredPrefixCounter == totalPrefixCounter, but got filteredPrefixCounter: {}, "
                "totalPrefixCounter: {}. "
                "Command: {}\n"
            ).format(
                routes_json['filteredPrefixCounter'],
                routes_json['totalPrefixCounter'],
                bgp_nbr_recv_cmd
            )

        for bgp_nbr_adv_cmd in adv_cmd_list:
            res = duthost.shell(duthost.get_vtysh_cmd_for_namespace(bgp_nbr_adv_cmd, peer_device_namespace))
            routes_json = json.loads(res['stdout'])
            assert routes_json['totalPrefixCounter'] > 0, (
                "No BGP routes were found. totalPrefixCounter = {} (expected > 0).\n"
                "- Command: {}\n"
            ).format(
                routes_json['totalPrefixCounter'],
                bgp_nbr_recv_cmd if 'bgp_nbr_recv_cmd' in locals() else 'N/A'
            )

            assert routes_json['filteredPrefixCounter'] == 0, (
                "Filtered prefix counter is not zero after AZNG migration rollback. "
                "Expected filteredPrefixCounter == 0, but got {}. "
                "- Command: {}\n"
            ).format(
                routes_json['filteredPrefixCounter'],
                bgp_nbr_adv_cmd
            )

            if "ipv6" in bgp_nbr_adv_cmd:
                assert routes_json['totalPrefixCounter'] == original_ipv6_route_adv_count, (
                    "Mismatch in total advertised IPv6 route count after AZNG migration. "
                    "Expected: {}, Actual: {}. "
                    "- Command: {}\n"
                ).format(
                    original_ipv6_route_adv_count,
                    routes_json['totalPrefixCounter'],
                    bgp_nbr_adv_cmd
                )
                assert routes_json['filteredPrefixCounter'] == original_ipv6_route_adv_filter_count, (
                    "Mismatch in filtered advertised IPv6 route count after AZNG migration. "
                    "Expected: {}, Actual: {}. "
                    "- Command: {}\n"
                ).format(
                    original_ipv6_route_adv_filter_count,
                    routes_json['filteredPrefixCounter'],
                    bgp_nbr_adv_cmd
                )
            else:
                assert routes_json['totalPrefixCounter'] == original_ipv4_route_adv_count, (
                    "Mismatch in total advertised IPv4 route count after AZNG migration. "
                    "Expected: {}, Actual: {}. "
                    "- Command: {}\n"
                ).format(
                  original_ipv4_route_adv_count,
                  routes_json['totalPrefixCounter'],
                  bgp_nbr_adv_cmd
                )
                assert routes_json['filteredPrefixCounter'] == original_ipv4_route_adv_filter_count, (
                    "Mismatch in filtered advertised IPv4 route count after AZNG migration. "
                    "Expected: {}, Actual: {}. "
                    "- Command: {}\n"
                ).format(
                    original_ipv4_route_adv_filter_count,
                    routes_json['filteredPrefixCounter'],
                    bgp_nbr_adv_cmd
                )

        rc = duthost.shell('sudo azng_migration -o')
        pytest_assert(
            not rc['failed'],
            (
                "AZNG Migration Inbound Route-map permit apply failed. "
                "Return code: {}, Output: {}"
            ).format(
                rc.get('rc', 'N/A'),
                rc.get('stdout', 'N/A')
            )
        )

        for bgp_nbr_recv_cmd in recv_cmd_list:
            res = duthost.shell(duthost.get_vtysh_cmd_for_namespace(bgp_nbr_recv_cmd, peer_device_namespace))
            routes_json = json.loads(res['stdout'])
            assert routes_json['totalPrefixCounter'] > 0, (
                "No BGP routes were found. totalPrefixCounter = {} (expected > 0).\n"
                "- Command: {}\n"
            ).format(
                routes_json['totalPrefixCounter'],
                bgp_nbr_recv_cmd if 'bgp_nbr_recv_cmd' in locals() else 'N/A'
            )
            assert routes_json['filteredPrefixCounter'] < routes_json['totalPrefixCounter'], (
                "AZNG migration validation failed: filteredPrefixCounter ({}) is not less than totalPrefixCounter ({})."
            ).format(
                routes_json['filteredPrefixCounter'],
                routes_json['totalPrefixCounter']
            )

            if "ipv6" in bgp_nbr_recv_cmd:
                assert routes_json['totalPrefixCounter'] == original_ipv6_route_recv_count, (
                    "Total received IPv6 route count mismatch after AZNG migration. "
                    "Expected: {}, Got: {}."
                ).format(
                    original_ipv6_route_recv_count,
                    routes_json['totalPrefixCounter']
                )

                assert routes_json['filteredPrefixCounter'] == original_ipv6_route_recv_filter_count, (
                    "Filtered received IPv6 route count mismatch after AZNG migration. "
                    "Expected: {}, Got: {}."
                ).format(
                    original_ipv6_route_recv_filter_count,
                    routes_json['filteredPrefixCounter']
                )

            else:
                assert routes_json['totalPrefixCounter'] == original_ipv4_route_recv_count, (
                    "Total received IPv4 route count mismatch after AZNG migration. "
                    "Expected: {}, Got: {}."
                ).format(
                    original_ipv4_route_recv_count,
                    routes_json['totalPrefixCounter']
                )

                assert routes_json['filteredPrefixCounter'] == original_ipv4_route_recv_filter_count, (
                    "Filtered received IPv4 route count mismatch after AZNG migration. "
                    "Expected: {}, Got: {}."
                ).format(
                    original_ipv4_route_recv_filter_count,
                    routes_json['filteredPrefixCounter']
                )

        for bgp_nbr_adv_cmd in adv_cmd_list:
            res = duthost.shell(duthost.get_vtysh_cmd_for_namespace(bgp_nbr_adv_cmd, peer_device_namespace))
            routes_json = json.loads(res['stdout'])
            assert routes_json['totalPrefixCounter'] > 0, (
                "No BGP routes were found. totalPrefixCounter = {} (expected > 0).\n"
                "- Command: {}\n"
            ).format(
                routes_json['totalPrefixCounter'],
                bgp_nbr_recv_cmd if 'bgp_nbr_recv_cmd' in locals() else 'N/A'
            )
            assert routes_json['filteredPrefixCounter'] == 0, (
                "Filtered prefix counter is not zero after AZNG migration rollback. "
                "Expected filteredPrefixCounter == 0, but got {}. "
                "- Command: {}\n"
            ).format(
                routes_json['filteredPrefixCounter'],
                bgp_nbr_adv_cmd if 'bgp_nbr_adv_cmd' in locals() else 'N/A'
            )

        rc = duthost.shell('sudo azng_migration -p')
        if rc['failed']:
            recover_via_minigraph = True

        pytest_assert(
            not recover_via_minigraph,
            (
                "AZNG Migration Production set failed"
            )
        )

        success = True
    finally:
        if not success:
            if recover_via_minigraph:
                config_reload(duthost, config_source='minigraph')
            else:
                config_reload(duthost, config_source='config_db')
