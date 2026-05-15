import ipaddress
import logging
import pytest

from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor  # noqa: F401
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host                  # noqa: F401
from tests.common.helpers.assertions import pytest_assert


logger = logging.getLogger(__name__)


pytestmark = [
        pytest.mark.topology("dualtor"),
        pytest.mark.disable_loganalyzer,
        ]


def verify_mux_port_iptables_entries(duthost):
    expected_iptables_rules, expected_ip6tables_rules = \
         generate_nat_expected_rules(duthost)
    stdout = duthost.command("sudo iptables -t nat -S")["stdout"]
    actual_iptables_rules = stdout.strip().split("\n")

    # Ensure all expected iptables rules are present on the DuT
    missing_iptables_rules = set(expected_iptables_rules) - set(actual_iptables_rules)
    pytest_assert(len(missing_iptables_rules) == 0, "Missing expected iptables nat rules: {}"
                  .format(repr(missing_iptables_rules)))

    # Ensure there are no unexpected iptables rules present on the DuT
    unexpected_iptables_rules = set(actual_iptables_rules) - set(expected_iptables_rules)
    pytest_assert(len(unexpected_iptables_rules) == 0, "Unexpected iptables nat rules: {}"
                  .format(repr(unexpected_iptables_rules)))

    stdout = duthost.command("sudo ip6tables -t nat -S")["stdout"]
    actual_ip6tables_rules = stdout.strip().split("\n")

    # Ensure all expected ip6tables rules are present on the DuT
    missing_ip6tables_rules = set(expected_ip6tables_rules) - set(actual_ip6tables_rules)
    pytest_assert(len(missing_ip6tables_rules) == 0, "Missing expected ip6tables nat rules: {}"
                  .format(repr(missing_ip6tables_rules)))

    # Ensure there are no unexpected ip6tables rules present on the DuT
    unexpected_ip6tables_rules = set(actual_ip6tables_rules) - set(expected_ip6tables_rules)
    pytest_assert(len(unexpected_ip6tables_rules) == 0, "Unexpected ip6tables nat rules: {}"
                  .format(repr(unexpected_ip6tables_rules)))


def generate_nat_expected_rules(duthost):
    iptables_natrules = []
    ip6tables_natrules = []

    # Default policies
    iptables_natrules.append("-P PREROUTING ACCEPT")
    iptables_natrules.append("-P INPUT ACCEPT")
    iptables_natrules.append("-P OUTPUT ACCEPT")
    iptables_natrules.append("-P POSTROUTING ACCEPT")
    ip6tables_natrules.append("-P PREROUTING ACCEPT")
    ip6tables_natrules.append("-P INPUT ACCEPT")
    ip6tables_natrules.append("-P OUTPUT ACCEPT")
    ip6tables_natrules.append("-P POSTROUTING ACCEPT")

    debian_version = duthost.command("grep VERSION_CODENAME /etc/os-release")['stdout'].lower()
    if "trixie" in debian_version:
        ip6tables_natrules.append("-N DOCKER")
        ip6tables_natrules.append("-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER")
        ip6tables_natrules.append("-A OUTPUT ! -d ::1/128 -m addrtype --dst-type LOCAL -j DOCKER")

    config_facts = duthost.get_running_config_facts()

    vlan_table = config_facts['VLAN_INTERFACE']
    vlan_intfs_ipv4 = []
    vlan_intfs_ipv6 = []
    for val in vlan_table.values():
        for key in val.keys():
            try:
                intf = ipaddress.ip_interface(key)
                if intf.version == 4:
                    vlan_intfs_ipv4.append(intf)
                elif intf.version == 6:
                    vlan_intfs_ipv6.append(intf)
            except Exception:
                pass

    loopback_table = config_facts["LOOPBACK_INTERFACE"]
    for key in loopback_table["Loopback3"].keys():
        intf = ipaddress.ip_interface(key)
        if intf.version == 4:
            loopback3_ipv4 = intf.ip
        elif intf.version == 6:
            loopback3_ipv6 = intf.ip

    mux_cable_table = config_facts['MUX_CABLE']
    rule_template_ipv4 = "-A POSTROUTING -s {}/32 -d {} -j SNAT --to-source {}"
    rule_template_ipv6 = "-A POSTROUTING -s {}/128 -d {} -j SNAT --to-source {}"
    for _, config in mux_cable_table.items():
        if "soc_ipv4" in config:
            soc_ipv4 = ipaddress.ip_interface(config["soc_ipv4"])
            for vlan_intf in filter(lambda vlan_intf: soc_ipv4 in vlan_intf.network, vlan_intfs_ipv4):
                iptables_natrules.append(rule_template_ipv4.format(vlan_intf.ip, soc_ipv4, loopback3_ipv4))
        if "soc_ipv6" in config:
            soc_ipv6 = ipaddress.ip_interface(config["soc_ipv6"])
            for vlan_intf in filter(lambda vlan_intf: soc_ipv6 in vlan_intf.network, vlan_intfs_ipv6):
                ip6tables_natrules.append(rule_template_ipv6.format(vlan_intf.ip, soc_ipv6, loopback3_ipv6))
    return iptables_natrules, ip6tables_natrules


def test_mux_port_iptables_entries(duthost):
    verify_mux_port_iptables_entries(duthost)


# Multivlan variant: the legacy `setup_multiple_vlans` fixture
# (jinja+regex rewriting `/etc/sonic/minigraph.xml`) has been replaced by
# the unified `parametrize_vlan_config_from_topo` mechanism from
# `tests/common/fixtures/vlan_config_swap.py`, which patches CONFIG_DB
# directly (VLAN, VLAN_INTERFACE, VLAN_MEMBER, DHCP_RELAY, and MUX_CABLE
# on dualtor topologies). Pinned to `four_vlan_a` to match the original
# fixture's behavior; remove the `indirect=True` parametrize below to
# auto-run across every variant the topo defines (one/two/four_vlan_a).
@pytest.mark.parametrize(
    "parametrize_vlan_config_from_topo", ["four_vlan_a"], indirect=True
)
def test_multivlan_mux_port_iptables_entries(parametrize_vlan_config_from_topo, duthost):
    verify_mux_port_iptables_entries(duthost)
