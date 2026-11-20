import pytest
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer globally
    pytest.mark.topology('any')
]


def generate_expected_rules(duthost):
    ebtables_rules = []
    # Default policies
    ebtables_rules.append("-d BGA -j DROP")
    ebtables_rules.append("-p ARP -j DROP")
    ebtables_rules.append("-p 802_1Q --vlan-encap ARP -j DROP")
    ebtables_rules.append("-d Multicast -j DROP")
    return ebtables_rules


def generate_optional_rules():
    # Images built before these drops were added do not have them
    return [
        "-p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type neighbour-solicitation -j DROP",
        "-p IPv6 --ip6-proto ipv6-icmp --ip6-icmp-type neighbour-advertisement -j DROP",
        "-p 802_1Q --vlan-encap IPv6 -j DROP",
    ]


def test_ebtables_application(duthosts, enum_rand_one_per_hwsku_hostname, enum_asic_index):
    """
    Test case to ensure ebtables rules are applied are correctly on DUT during init

    This is done by generating our own set of expected ebtables
    rules based on the DuT's configuration and comparing them against the
    actual ebtables rules on the DuT.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    expected_ebtables_rules = generate_expected_rules(duthost)

    stdout = duthost.asic_instance(enum_asic_index).command("sudo ebtables -L FORWARD")["stdout"]
    ebtables_rules = stdout.strip().split("\n")
    # ebtables -L prints the ethertype behind --vlan-encap as a number
    actual_ebtables_rules = [rule.strip().replace("0806", "ARP").replace("86DD", "IPv6")
                             for rule in ebtables_rules if rule.startswith('-')]

    # Ensure all expected ebtables rules are present on the DuT
    missing_ebtables_rules = set(expected_ebtables_rules) - set(actual_ebtables_rules)
    pytest_assert(len(missing_ebtables_rules) == 0, "Missing expected ebtables rules: {}"
                  .format(repr(missing_ebtables_rules)))

    # Ensure there are no unexpected ebtables rules present on the DuT
    unexpected_ebtables_rules = (set(actual_ebtables_rules) - set(expected_ebtables_rules)
                                 - set(generate_optional_rules()))
    pytest_assert(len(unexpected_ebtables_rules) == 0, "Unexpected ebtables rules: {}"
                  .format(repr(unexpected_ebtables_rules)))
