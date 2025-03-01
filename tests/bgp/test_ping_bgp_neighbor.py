import pytest
import logging

pytestmark = [
    pytest.mark.topology('any', 't0-sonic', 't1-multi-asic'),
    pytest.mark.device_type('vs')
]


def test_ping_bgp_neighbor(duthosts, enum_frontend_dut_hostname, enum_asic_index):
    """Check ping connectivity to all BGP neighbors across all ASICs of the given DUT"""

    duthost = duthosts[enum_frontend_dut_hostname]
    bgp_facts = duthost.bgp_facts(instance_id=enum_asic_index)['ansible_facts']
    namespace = duthost.get_namespace_from_asic_id(enum_asic_index)
    is_multi_asic = namespace is not None

    for neighbor_ip, neighbor_data in bgp_facts['bgp_neighbors'].items():
        # Verify that the BGP session is established
        error_msg = f"BGP session with {neighbor_ip} is not 'established'"
        assert neighbor_data['state'] == 'established', error_msg
        logging.info(f"Pinging BGP neighbor {neighbor_ip} from {duthost.hostname} (ASIC {enum_asic_index})")
        if is_multi_asic:
            ping_cmd = f"sudo ip netns exec {namespace} ping -c 3 {neighbor_ip}"
        else:
            ping_cmd = f"ping -c 3 {neighbor_ip}"

        result = duthost.shell(ping_cmd, module_ignore_errors=True)
        # Checking if the ping was successful
        if result['rc'] != 0:
            logging.error(f"Ping failed to BGP neighbor {neighbor_ip} from {duthost.hostname} (ASIC {enum_asic_index})")
            raise AssertionError(
                f"Ping failed to BGP neighbor {neighbor_ip} from {duthost.hostname} "
                f"(ASIC {enum_asic_index})"
            )
        logging.info(f"Ping to BGP neighbor {neighbor_ip} successful from {duthost.hostname} (ASIC {enum_asic_index})")

    logging.info(f"All BGP neighbors on {duthost.hostname} (ASIC {enum_asic_index}) are reachable via ping.")
