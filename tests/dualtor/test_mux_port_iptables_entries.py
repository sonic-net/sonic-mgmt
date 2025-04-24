import ipaddress
import logging
import pytest
import jinja2
import re
from ansible_collections.ansible.utils.plugins.filter.ipaddr import ipaddr

from tests.common.config_reload import config_reload
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor  # noqa F401
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host                  # noqa F401
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
        pytest.mark.topology("dualtor"),
        pytest.mark.disable_loganalyzer,
        ]


# This is only supposed to be run on tor
@pytest.fixture(scope="function")
def setup_multiple_vlans(request, duthost, localhost, tbinfo):
    hostname = duthost.hostname
    # inventory = tbinfo["inv_name"]
    topo = tbinfo["topo"]["name"]
    hwsku = duthost.facts["hwsku"]
    testbed_name = tbinfo["conf-name"]
    testbed_file = request.config.option.testbed_file
    vm_topo_config = localhost.topo_facts(topo=topo,
                                          hwsku=hwsku,
                                          testbed_name=testbed_name,
                                          asics_present=[],
                                          card_type="fixed",
                                          )["ansible_facts"]["vm_topo_config"]
    testbed_facts = localhost.test_facts(testbed_name=testbed_name,
                                         testbed_file=testbed_file,
                                         )["ansible_facts"]["testbed_facts"]
    hostvars = duthost.host.options['variable_manager']._hostvars
    hostvars = {hostname: dict(hostvars[hostname]) for hostname in tbinfo["duts"]}
    port_alias = duthost.port_alias(hwsku=hwsku,
                                    card_type="fixed",
                                    hostname=hostname,
                                    switchids=[],
                                    )["ansible_facts"]["port_alias"]
    dut_index = int(testbed_facts["duts_map"][hostname])
    vlan_intfs = [port_alias[item] for item in vm_topo_config["host_interfaces_by_dut"][dut_index]
                  if item not in vm_topo_config["disabled_host_interfaces_by_dut"][dut_index]]
    vlan_cfgs = tbinfo["topo"]["properties"]["topology"]["DUT"]["vlan_configs"]
    vlan_config = "four_vlan_a"
    pytest_assert(vlan_config in vlan_cfgs, "device does not support {} vlan config".format(vlan_config))
    vlan_configs = duthost.vlan_config(vm_topo_config=vm_topo_config,
                                       port_alias=port_alias,
                                       vlan_config=vlan_config,
                                       )["ansible_facts"]["vlan_configs"]
    if "dualtor" in topo:
        dual_tor_facts = localhost.dual_tor_facts(hostname=hostname,
                                                  testbed_facts=testbed_facts,
                                                  hostvars=hostvars,
                                                  vm_config=vm_topo_config,
                                                  port_alias=port_alias,
                                                  vlan_intfs=vlan_intfs,
                                                  )["ansible_facts"]["dual_tor_facts"]
        mux_cable_facts = localhost.mux_cable_facts(topo_name=topo,
                                                    vlan_config=vlan_config,
                                                    )["ansible_facts"]["mux_cable_facts"]
    else:
        dual_tor_facts = {}
        mux_cable_facts = {}
    variables = {
            "vm_topo_config": vm_topo_config,
            "port_alias": port_alias,
            "dual_tor_facts": dual_tor_facts,
            "mux_cable_facts": mux_cable_facts,
            "vlan_configs": vlan_configs,
            "testbed_facts": testbed_facts,
            "inventory_hostname": hostname,
            }
    templates_loader = jinja2.FileSystemLoader(searchpath="dualtor/templates")
    templates_env = jinja2.Environment(loader=templates_loader)
    templates_env.filters["ipaddr"] = ipaddr
    multivlan_xml = templates_env.get_template("multivlan_template.j2").render(variables)
    multivlan_ip_xml = templates_env.get_template("multivlan_ip_template.j2").render(variables)
    multivlan_mux_config_xml = templates_env.get_template("multivlan_mux_config_template.j2").render(variables)
    minigraph_xml = duthost.command("cat /etc/sonic/minigraph.xml")["stdout"]
    minigraph_xml = re.sub("[ \t]*<VlanInterfaces>(.|\n)*</VlanInterfaces>[ \t]*", multivlan_xml, minigraph_xml)
    minigraph_xml = re.sub("[ \t]*<IPInterfaces>(.|\n)*</IPInterfaces>[ \t]*", multivlan_ip_xml, minigraph_xml)
    # the first match is not about mux config
    first_match = re.search("[ \t]*<DeviceDataPlaneInfo>(.|\n)*?</DeviceDataPlaneInfo>[ \t]*",
                            minigraph_xml).group(0)
    minigraph_xml = minigraph_xml.replace(first_match, "PLACEHOLDER")
    minigraph_xml = re.sub("[ \t]*<DeviceDataPlaneInfo>(.|\n)*</DeviceDataPlaneInfo>[ \t]*",
                           multivlan_mux_config_xml, minigraph_xml)
    minigraph_xml = minigraph_xml.replace("PLACEHOLDER", first_match)
    duthost.command("cp /etc/sonic/minigraph.xml /etc/sonic/minigraph.xml.bak")
    duthost.copy(content=minigraph_xml, dest="/etc/sonic/minigraph.xml")
    config_reload(duthost, config_source='minigraph')
    config_facts = duthost.get_running_config_facts()
    pytest_assert(len(config_facts['VLAN_INTERFACE']) == 4, "Configuring multivlan is not successful")

    yield

    duthost.command("cp /etc/sonic/minigraph.xml.bak /etc/sonic/minigraph.xml")
    config_reload(duthost, config_source='minigraph')


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


def test_multivlan_mux_port_iptables_entries(setup_multiple_vlans, duthost):
    verify_mux_port_iptables_entries(duthost)
