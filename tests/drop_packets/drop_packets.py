import os
import netaddr
import pytest
import random
import time
import logging
import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet

from tests.common.fixtures.conn_graph_facts import enum_fanout_graph_facts  # noqa F401
from tests.common.errors import RunAnsibleModuleFail
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.platform.device_utils import fanout_switch_port_lookup
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common import config_reload

RX_DRP = "RX_DRP"
RX_ERR = "RX_ERR"
L2_COL_KEY = RX_DRP
L3_COL_KEY = RX_ERR

pytest.SKIP_COUNTERS_FOR_MLNX = False
MELLANOX_MAC_UPDATE_SCRIPT = os.path.join(os.path.dirname(__file__), "fanout/mellanox/mlnx_update_mac.j2")
# Ansible config files
LAB_CONNECTION_GRAPH_PATH = os.path.normpath((os.path.join(os.path.dirname(__file__), "../../ansible/files")))

ACL_COUNTERS_UPDATE_INTERVAL = 10
ACL_TABLE_CREATE_INTERVAL = 30
PORT_STATE_UPDATE_INTERNAL = 30
LOG_EXPECT_ACL_TABLE_CREATE_RE = ".*Created ACL table.*"
LOG_EXPECT_ACL_RULE_CREATE_RE = ".*Successfully created ACL rule.*"
LOG_EXPECT_ACL_RULE_REMOVE_RE = ".*Successfully deleted ACL rule.*"
LOG_EXPECT_PORT_OPER_DOWN_RE = ".*Port {} oper state set from up to down.*"
LOG_EXPECT_PORT_OPER_UP_RE = ".*Port {} oper state set from down to up.*"


logger = logging.getLogger(__name__)


@pytest.fixture(scope='module')
def sai_acl_drop_adj_enabled(duthosts, enum_rand_one_per_hwsku_frontend_hostname, setup):
    """
    Determines if the `sai_adjust_acl_drop_in_rx_drop` property is enabled

    Note that this property is specific to BRCM platforms

    Since this leads to an undpredictable number of packets getting
    counted as RX_DRP (in certain test cases), if it is enabled we need to
    skip checking the drop counters for certain test cases
    """
    # Since Broadcom DNX platform does not have the soc property (sai_adjust_acl_drop_in_rx_drop)
    # implemented yet, skipping drop count validation for now
    if setup.get("platform_asic") == "broadcom-dnx":
        return True

    check_cmd = "which bcmcmd > /dev/null && bcmcmd 'config show' | grep 'sai_adjust_acl_drop_in_rx_drop=1'"
    try:
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        duthost.shell(check_cmd)
    except RunAnsibleModuleFail:
        # If the above command fails, we can assume that either
        # we are not on a BRCM platform or the specified property
        # is not enabled/available
        return False

    return True


@pytest.fixture
def fanouthost(duthosts, enum_rand_one_per_hwsku_frontend_hostname, fanouthosts, conn_graph_facts, localhost):
    """
    Fixture that allows to update Fanout configuration if there is a need to send incorrect packets.
    Added possibility to create vendor specific logic to handle fanout configuration.
    If vendor need to update Fanout configuration, 'fanouthost' fixture should load and return appropriate instance.
    This instance can be used inside test case to handle fanout configuration in vendor specific section.
    By default 'fanouthost' fixture will not instantiate any instance so it will return None, and in such case
    'fanouthost' instance should not be used in test case logic.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    fanout = None
    # Check that class to handle fanout config is implemented
    if "mellanox" == duthost.facts["asic_type"]:
        fanout = get_fanout_obj(conn_graph_facts, duthost, fanouthosts)
        # if the leaf fanout switch is Mellanox, but running SONiC OS
        # then we have to skip some test cases because some operation (like the openflow)
        # is only supported on the Mellanox onyx
        if not is_mellanox_fanout(duthost, localhost) or fanout.os == "sonic":
            fanout = None

    yield fanout
    if fanout:
        if hasattr(fanout, 'restore_drop_counter_config'):
            fanout.restore_drop_counter_config()


@pytest.fixture
def configure_copp_drop_for_ttl_error(duthosts, rand_one_dut_hostname):
    """
    Fixture that allows to update copp configuration for dropping packets with TTL=0

    Args:
        duthosts: fixture to get DUT hosts defined in testbed
        rand_one_dut_hostname: fixture to return the randomly selected duthost
    """
    duthost = duthosts[rand_one_dut_hostname]
    copp_trap_group_json = "/tmp/copp_trap_group.json"
    copp_trap_rule_json = "/tmp/copp_trap_rule.json"

    cmd_copp_trap_group = '''
cat << EOF >  %s
{
   "COPP_GROUP": {
        "ttl_error": {
            "queue": "4",
            "trap_action": "drop"
        }
  }
}
EOF
''' % (copp_trap_group_json)

    cmd_copp_trap_rule = '''
cat << EOF > %s
{
   "COPP_TRAP": {
        "ttl_error": {
            "trap_ids": "ttl_error",
            "trap_group": "ttl_error",
            "always_enabled": "true"
        }
    }
}
EOF
''' % (copp_trap_rule_json)

    duthost.shell(cmd_copp_trap_group)
    duthost.command("sudo config load {} -y".format(copp_trap_group_json))

    duthost.shell(cmd_copp_trap_rule)
    duthost.command("sudo config load {} -y".format(copp_trap_rule_json))

    yield

    duthost.command("rm {} {}".format(copp_trap_group_json, copp_trap_rule_json))
    config_reload(duthost)


def is_mellanox_devices(hwsku):
    """
    A helper function to check if a given sku is Mellanox device
    """
    hwsku = hwsku.lower()
    return 'mellanox' in hwsku \
        or 'msn' in hwsku \
        or 'mlnx' in hwsku


def is_mellanox_fanout(duthost, localhost):
    # Ansible localhost fixture which calls ansible playbook on the local host

    if duthost.facts.get("asic_type") == "vs":
        return False

    try:
        dut_facts = \
            localhost.conn_graph_facts(host=duthost.hostname, filepath=LAB_CONNECTION_GRAPH_PATH)["ansible_facts"]
    except RunAnsibleModuleFail as e:
        logger.info("Get dut_facts failed, reason:{}".format(e.results['msg']))
        return False

    intf = list(dut_facts["device_conn"][duthost.hostname].keys())[0]
    fanout_host = dut_facts["device_conn"][duthost.hostname][intf]["peerdevice"]

    try:
        fanout_facts = \
            localhost.conn_graph_facts(host=fanout_host, filepath=LAB_CONNECTION_GRAPH_PATH)["ansible_facts"]
    except RunAnsibleModuleFail:
        return False

    fanout_sku = fanout_facts['device_info'][fanout_host]['HwSku']
    if not is_mellanox_devices(fanout_sku):
        return False

    return True


def get_fanout_obj(conn_graph_facts, duthost, fanouthosts):
    for fanout_name, fanout_obj in list(fanouthosts.items()):
        for interface, interface_info in list(conn_graph_facts['device_conn'][duthost.hostname].items()):
            if fanout_name == interface_info.get('peerdevice'):
                return fanout_obj
    pytest_assert(False, "Failed to get the fanout for dut {}".format(duthost.hostname))


@pytest.fixture(scope="module")
def pkt_fields(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    # Gather ansible facts
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ipv4_addr = None
    ipv6_addr = None

    for item in mg_facts["minigraph_bgp"]:
        if item["name"] == mg_facts["minigraph_bgp"][0]["name"]:
            if netaddr.valid_ipv4(item["addr"]):
                ipv4_addr = item["addr"]
            else:
                ipv6_addr = item["addr"]

    class Collector(dict):
        def __getitem__(self, key):
            value = super(Collector, self).__getitem__(key)
            if key == "ipv4_dst" and value is None:
                pytest.skip("IPv4 address is not defined")
            elif key == "ipv6_dst" and value is None:
                pytest.skip("IPv6 address is not defined")
            return value

    test_pkt_data = Collector({
        "ipv4_dst": ipv4_addr,
        "ipv4_src": "1.1.1.1",
        "ipv6_dst": ipv6_addr,
        "ipv6_src": "ffff::101:101",
        "tcp_sport": 1234,
        "tcp_dport": 4321
        })
    return test_pkt_data


def expected_packet_mask(pkt, ip_ver):
    """ Return mask for sniffing packet """
    exp_pkt = pkt.copy()
    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
    if ip_ver == "ipv4" and pkt.haslayer(packet.IP):
        exp_pkt.set_do_not_care_scapy(packet.IP, 'ttl')
        exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')
    elif ip_ver == "ipv6" and pkt.haslayer(packet.IPv6):
        exp_pkt.set_do_not_care_scapy(packet.IPv6, 'hlim')
    return exp_pkt


@pytest.fixture(scope="module")
def setup(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    """
    Setup fixture for collecting PortChannel, VLAN and RIF port members.
    @return: Dictionary with keys:
        port_channel_members, vlan_members, rif_members, dut_to_ptf_port_map, neighbor_sniff_ports, vlans, mg_facts
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    intf_per_namespace = {}
    port_channel_members = {}
    vlan_members = {}
    configured_vlans = []
    rif_members = []

    if tbinfo["topo"]["type"] == "ptf":
        pytest.skip("Unsupported topology {}".format(tbinfo["topo"]))

    # Gather interface facts per asic
    for ns in duthost.get_asic_namespace_list():
        intf_per_namespace[ns if ns is not DEFAULT_NAMESPACE else ''] = \
            duthost.interface_facts(namespace=ns)['ansible_facts']['ansible_interface_facts']

    # Gather ansible facts
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    for port_channel, interfaces in list(mg_facts['minigraph_portchannels'].items()):
        for iface in interfaces["members"]:
            port_channel_members[iface] = port_channel

    l2_port_channel_members = []
    for vlan_id in mg_facts["minigraph_vlans"]:
        for iface in mg_facts["minigraph_vlans"][vlan_id]["members"]:
            # Add only physical interfaces to vlan_members dict(skip PortChannel interfaces)
            if 'PortChannel' in iface:
                physical_ifaces = mg_facts['minigraph_portchannels'][iface]["members"]
                l2_port_channel_members.extend(physical_ifaces)
            else:
                vlan_members[iface] = vlan_id

    # Remove physical interfaces related to L2 PortChannel from port_channel_members dict(case with t0-56-po2vlan topo)
    for po_member in set(l2_port_channel_members):
        port_channel_members.pop(po_member)

    rif_members = {item["attachto"]: item["attachto"] for item in mg_facts["minigraph_interfaces"]}
    # Compose list of sniff ports
    neighbor_sniff_ports = []
    for dut_port, neigh in list(mg_facts['minigraph_neighbors'].items()):
        neighbor_sniff_ports.append(mg_facts['minigraph_ptf_indices'][dut_port])

    for vlan_name, vlans_data in list(mg_facts["minigraph_vlans"].items()):
        configured_vlans.append(int(vlans_data["vlanid"]))

    setup_information = {
        "port_channel_members": port_channel_members,
        "vlan_members": vlan_members,
        "rif_members": rif_members,
        "dut_to_ptf_port_map": mg_facts["minigraph_ptf_indices"],
        "neighbor_sniff_ports": neighbor_sniff_ports,
        "vlans": configured_vlans,
        "mg_facts": mg_facts,
        "intf_per_namespace": intf_per_namespace,
        "platform_asic": duthost.facts.get("platform_asic")
    }

    return setup_information


@pytest.fixture
def rif_port_down(duthosts, enum_rand_one_per_hwsku_frontend_hostname, setup, fanouthosts):
    """Shut RIF interface and return neighbor IP address attached to this interface."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="drop_packet_rif_port_down")

    if not setup["rif_members"]:
        pytest.skip("RIF interface is absent")
    rif_member_iface = list(setup["rif_members"].keys())[0]

    vm_name = setup["mg_facts"]["minigraph_neighbors"][rif_member_iface].get("name", None)
    pytest_assert(vm_name, 'Neighbor not found for RIF member "{}"'.format(rif_member_iface))

    ip_dst = None
    for item in setup["mg_facts"]["minigraph_bgp"]:
        if item["name"] == vm_name and netaddr.valid_ipv4(item["addr"]):
            ip_dst = item["addr"]
            break
    pytest_assert(ip_dst, 'Unable to find IP address for neighbor "{}"'.format(vm_name))

    fanout_neighbor, fanout_intf = fanout_switch_port_lookup(fanouthosts, duthost.hostname, rif_member_iface)

    loganalyzer.expect_regex = [LOG_EXPECT_PORT_OPER_DOWN_RE.format(rif_member_iface)]
    with loganalyzer as _:
        fanout_neighbor.shutdown(fanout_intf)
        # Add a delay to ensure loganalyzer can find a match in the log. Without this delay, there's a
        # chance it might miss the matching log.
        time.sleep(PORT_STATE_UPDATE_INTERNAL)

    time.sleep(1)

    yield ip_dst

    loganalyzer.expect_regex = [LOG_EXPECT_PORT_OPER_UP_RE.format(rif_member_iface)]
    with loganalyzer as _:
        fanout_neighbor.no_shutdown(fanout_intf)
        # Add a delay to ensure loganalyzer can find a match in the log. Without this delay, there's a
        # chance it might miss the matching log.
        time.sleep(PORT_STATE_UPDATE_INTERNAL)


@pytest.fixture(params=["port_channel_members", "vlan_members", "rif_members"])
def tx_dut_ports(request, setup):
    """ Fixture for getting port members of specific port group """
    return setup[request.param] if setup[request.param] else pytest.skip("No {} available".format(request.param))


@pytest.fixture
def ports_info(ptfadapter, duthosts, enum_rand_one_per_hwsku_frontend_hostname, setup, tx_dut_ports):
    """
    Return:
        dut_iface - DUT interface name expected to receive packtes from PTF
        asic_index - asic which owns the dut_iface, significant on a multi-asic platform.
        ptf_tx_port_id - Port ID used by PTF for sending packets from expected PTF interface
        dst_mac - DUT interface destination MAC address
        src_mac - PTF interface source MAC address
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    data = {}
    data["dut_iface"] = random.choice(list(tx_dut_ports.keys()))
    # Check which asic owns this interface
    for ns in duthost.get_asic_namespace_list():
        if data["dut_iface"] in setup['intf_per_namespace'][ns if ns is not DEFAULT_NAMESPACE else '']:
            break

    # Get the asic index
    asic_index = duthost.get_asic_id_from_namespace(ns)
    data["asic_index"] = asic_index

    data["ptf_tx_port_id"] = setup["dut_to_ptf_port_map"][data["dut_iface"]]
    ns = ns if ns is not DEFAULT_NAMESPACE else ''
    vlan = None
    if data["dut_iface"] in setup["vlan_members"]:
        vlan = setup["vlan_members"][data["dut_iface"]]
    if vlan in setup['intf_per_namespace'][ns]:
        data["dst_mac"] = setup['intf_per_namespace'][ns][vlan]['macaddress']
    else:
        data["dst_mac"] = setup['intf_per_namespace'][ns][data["dut_iface"]]['macaddress']
    data["src_mac"] = ptfadapter.dataplane.ports[(0, data["ptf_tx_port_id"])].mac()
    return data


def acl_setup(duthosts, template_dir, acl_rules_template, del_acl_rules_template, dut_tmp_dir,
              dut_clear_conf_file_path):
    for duthost in duthosts.frontend_nodes:
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="drop_packet_acl_setup")
        acl_facts = duthost.acl_facts()["ansible_facts"]["ansible_acl_facts"]
        if 'DATAACL' not in list(acl_facts.keys()):
            pytest.skip("Skipping test since DATAACL table is not present on DUT")

        duthost.command("mkdir -p {}".format(dut_tmp_dir))
        dut_conf_file_path = os.path.join(dut_tmp_dir, acl_rules_template)

        logger.info("Generating config for ACL rule, ACL table - DATAACL")
        duthost.template(src=os.path.join(template_dir, acl_rules_template), dest=dut_conf_file_path)
        logger.info("Generating clear config for ACL rule, ACL table - DATAACL")
        duthost.template(src=os.path.join(template_dir, del_acl_rules_template), dest=dut_clear_conf_file_path)

        logger.info("Applying {}".format(dut_conf_file_path))

        loganalyzer.expect_regex = [LOG_EXPECT_ACL_RULE_CREATE_RE]
        with loganalyzer:
            duthost.command("config acl update full {}".format(dut_conf_file_path))


def acl_teardown(duthosts, dut_tmp_dir, dut_clear_conf_file_path):
    for duthost in duthosts.frontend_nodes:
        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="drop_packet_acl_teardown")
        loganalyzer.expect_regex = [LOG_EXPECT_ACL_RULE_REMOVE_RE]
        with loganalyzer:
            logger.info("Applying {}".format(dut_clear_conf_file_path))
            duthost.command("config acl update full {}".format(dut_clear_conf_file_path))
            logger.info("Removing {}".format(dut_tmp_dir))
            duthost.command("rm -rf {}".format(dut_tmp_dir))
            # Add a delay to ensure loganalyzer can find a match in the log. Without this delay, there's a
            # chance it might miss the matching log.
            time.sleep(ACL_COUNTERS_UPDATE_INTERVAL)


@pytest.fixture
def acl_ingress(duthosts):
    """ Create acl rule defined in config file. Delete rule after test case finished """
    base_dir = os.path.dirname(os.path.realpath(__file__))
    template_dir = os.path.join(base_dir, 'acl_templates')
    acl_rules_template = "acltb_test_rule.json"
    del_acl_rules_template = "acl_rule_del.json"
    dut_tmp_dir = os.path.join("tmp", os.path.basename(base_dir))
    dut_clear_conf_file_path = os.path.join(dut_tmp_dir, del_acl_rules_template)

    acl_setup(duthosts, template_dir, acl_rules_template, del_acl_rules_template, dut_tmp_dir,
              dut_clear_conf_file_path)
    yield
    acl_teardown(duthosts, dut_tmp_dir, dut_clear_conf_file_path)


def create_or_remove_acl_egress_table(duthost, op):
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="drop_packet_create_or_remove_acl_egress_table")
    for sonic_host_or_asic_inst in duthost.get_sonic_host_and_frontend_asic_instance():
        namespace = sonic_host_or_asic_inst.namespace if hasattr(sonic_host_or_asic_inst, 'namespace') \
                                                      else DEFAULT_NAMESPACE
        if duthost.sonichost.is_multi_asic and namespace == DEFAULT_NAMESPACE:
            # Create ACL table on host namespace without any ports.
            # This is done so that config acl update full can execute on all namspaces.
            # ACL update looks for table name in host namespace.
            sonic_host_or_asic_inst.command("config acl add table {} {} -s {}" .format("OUTDATAACL", "L3", "egress"))
        else:
            acl_table_config = {
                "table_name": "OUTDATAACL",
                "table_ports": ",".join(
                    duthost.acl_facts(namespace=namespace)["ansible_facts"]["ansible_acl_facts"]["DATAACL"]["ports"]),
                "table_stage": "egress",
                "table_type": "L3"
            }
            table_port_list = []
            if namespace:
                for port in acl_table_config["table_ports"].split(','):
                    intf_per_namespace = duthost.interface_facts(
                                                  namespace=namespace)['ansible_facts']['ansible_interface_facts']
                    if port in intf_per_namespace:
                        table_port_list.append(port)
            else:
                table_port_list = acl_table_config["table_ports"].split(',')
            if table_port_list == []:
                continue
            if op == "add":
                loganalyzer.expect_regex = [LOG_EXPECT_ACL_TABLE_CREATE_RE]
                logger.info("Creating ACL table: \"{}\" on device {}".format(acl_table_config["table_name"], duthost))
                with loganalyzer:
                    sonic_host_or_asic_inst.command(
                        "config acl add table {} {} -s {} -p {}".format(
                            acl_table_config["table_name"],
                            acl_table_config["table_type"],
                            acl_table_config["table_stage"],
                            ','.join(table_port_list)
                        )
                    )

                    # Add a delay to ensure loganalyzer can find a match in the log. Without this delay, there's a
                    # chance it might miss the matching log.
                    time.sleep(ACL_TABLE_CREATE_INTERVAL)
            elif op == "remove":
                logger.info("Removing ACL table \"{}\" on device {}".format(acl_table_config["table_name"], duthost))
                sonic_host_or_asic_inst.command("config acl remove table {}".format(acl_table_config["table_name"]))
            else:
                pytest.fail("Unvalid op {} should use add or remove".format(op))


@pytest.fixture
def acl_egress(duthosts):
    """
    Create acl table OUTDATAACL
    Create acl rule defined in config file.
    Delete rule and table after test case finished
    """
    base_dir = os.path.dirname(os.path.realpath(__file__))
    template_dir = os.path.join(base_dir, 'acl_templates')
    acl_rules_template = "acltb_test_rule_egress.json"
    del_acl_rules_template = "acl_rule_del.json"
    dut_tmp_dir = os.path.join("tmp", os.path.basename(base_dir))
    dut_clear_conf_file_path = os.path.join(dut_tmp_dir, del_acl_rules_template)

    for duthost in duthosts.frontend_nodes:
        try:
            create_or_remove_acl_egress_table(duthost, "add")
        except LogAnalyzerError as err:
            # Cleanup Config DB if table creation failed
            logger.error("ACL table creation failed, attempting to clean-up...")
            create_or_remove_acl_egress_table(duthost, "remove")
            raise err

    acl_setup(duthosts, template_dir, acl_rules_template, del_acl_rules_template, dut_tmp_dir,
              dut_clear_conf_file_path)
    yield
    acl_teardown(duthosts, dut_tmp_dir, dut_clear_conf_file_path)

    for duthost in duthosts.frontend_nodes:
        create_or_remove_acl_egress_table(duthost, "remove")


def log_pkt_params(dut_iface, mac_dst, mac_src, ip_dst, ip_src):
    """ Displays information about packet fields used in test case: mac_dst, mac_src, ip_dst, ip_src """
    logger.info("Selected TX interface on DUT - {}".format(dut_iface))
    logger.info("Packet DST MAC - {}".format(mac_dst))
    logger.info("Packet SRC MAC - {}".format(mac_src))
    logger.info("Packet IP DST - {}".format(ip_dst))
    logger.info("Packet IP SRC - {}".format(ip_src))


def send_packets(pkt, ptfadapter, ptf_tx_port_id, num_packets=1):
    # Clear packets buffer on PTF
    ptfadapter.dataplane.flush()
    time.sleep(1)

    # Send packets
    testutils.send(ptfadapter, ptf_tx_port_id, pkt, count=num_packets)
    time.sleep(1)


def test_equal_smac_dmac_drop(do_test, ptfadapter, setup, fanouthost,
                              pkt_fields, ports_info, enum_fanout_graph_facts):      # noqa F811
    """
    @summary: Create a packet with equal SMAC and DMAC.
    """
    if not fanouthost:
        pytest.skip("Test case requires explicit fanout support")

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"],
                   ports_info["dst_mac"], pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])
    src_mac = ports_info["dst_mac"]

    if fanouthost.os == 'onyx':
        pytest.SKIP_COUNTERS_FOR_MLNX = True
        src_mac = "00:00:00:00:00:11"
        # Prepare openflow rule
        fanouthost.prepare_drop_counter_config(
            fanout_graph_facts=enum_fanout_graph_facts, match_mac=src_mac,
            set_mac=ports_info["dst_mac"], eth_field="eth_src")

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=src_mac,  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],  # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
    )

    comparable_pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["dst_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],  # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
    )

    group = "L2"
    do_test(group, pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"], comparable_pkt=comparable_pkt)


def test_multicast_smac_drop(do_test, ptfadapter, setup, fanouthost,
                             pkt_fields, ports_info, enum_fanout_graph_facts):   # noqa F811
    """
    @summary: Create a packet with multicast SMAC.
    """
    if not fanouthost:
        pytest.skip("Test case requires explicit fanout support")

    multicast_smac = "01:00:5e:00:01:02"
    src_mac = multicast_smac

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], multicast_smac,
                   pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

    if fanouthost.os == 'onyx':
        pytest.SKIP_COUNTERS_FOR_MLNX = True
        src_mac = "00:00:00:00:00:11"
        # Prepare openflow rule
        fanouthost.prepare_drop_counter_config(
            fanout_graph_facts=enum_fanout_graph_facts, match_mac=src_mac, set_mac=multicast_smac, eth_field="eth_src")

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=src_mac,
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],  # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
    )

    comparable_pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=multicast_smac,
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],  # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
    )

    group = "L2"
    do_test(group, pkt, ptfadapter, ports_info,
            setup["neighbor_sniff_ports"], comparable_pkt=comparable_pkt)


def test_not_expected_vlan_tag_drop(do_test, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                    ptfadapter, setup, pkt_fields, ports_info):
    """
    @summary: Create a VLAN tagged packet which VLAN ID does not match ingress port VLAN ID.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if "mellanox" == duthost.facts["asic_type"]:
        pytest.SKIP_COUNTERS_FOR_MLNX = True
    start_vlan_id = 2
    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"],
                   pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])
    max_vlan_id = 1000
    upper_bound = max(setup["vlans"]) if setup["vlans"] else max_vlan_id
    for interim in range(start_vlan_id, upper_bound):
        if interim not in setup["vlans"]:
            vlan_id = interim
            break
    else:
        pytest.fail(
            "Unable to generate unique not yet existed VLAN ID. Already configured VLANs range {}-{}"
            .format(start_vlan_id, upper_bound))

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],  # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"],
        dl_vlan_enable=True,
        vlan_vid=vlan_id,
        )

    group = "L2"
    do_test(group, pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"])


def test_dst_ip_is_loopback_addr(do_test, ptfadapter, setup, pkt_fields, tx_dut_ports, ports_info):
    """
    @summary: Create a packet with loopback destination IP adress.
    """
    ip_dst = "127.0.0.1"

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"],
                   ports_info["src_mac"], ip_dst, pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=ip_dst,  # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    group = "L3"
    do_test(group, pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


def test_src_ip_is_loopback_addr(do_test, ptfadapter, setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Create a packet with loopback source IP adress.
    """
    ip_src = "127.0.0.1"

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"],
                   ports_info["src_mac"], pkt_fields["ipv4_dst"], ip_src)

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=ip_src,  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],  # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    group = "L3"
    do_test(group, pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


def test_dst_ip_absent(do_test, ptfadapter, setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Create a packet with absent destination IP address.
    """
    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"],
                   ports_info["src_mac"], "", pkt_fields["ipv4_src"])
    try:
        # ip_dst accept None as empty dst ip address in scapy version such as 2.4.5,
        # but in old scapy version such as 2.2.0.dev0, it will throw TypeError
        pkt = testutils.simple_tcp_packet(
            eth_dst=ports_info["dst_mac"],  # DUT port
            eth_src=ports_info["src_mac"],  # PTF port
            ip_src=pkt_fields["ipv4_src"],  # PTF source
            ip_dst=None,  # VM source
            tcp_sport=pkt_fields["tcp_sport"],
            tcp_dport=pkt_fields["tcp_dport"])
    except TypeError:
        # in old scapy version such as 2.2.0.dev0, ip_dst accept "" as dst ip address
        pkt = testutils.simple_tcp_packet(
            eth_dst=ports_info["dst_mac"],  # DUT port
            eth_src=ports_info["src_mac"],  # PTF port
            ip_src=pkt_fields["ipv4_src"],  # PTF source
            ip_dst="",  # VM source
            tcp_sport=pkt_fields["tcp_sport"],
            tcp_dport=pkt_fields["tcp_dport"])

    group = "L3"
    print(("msm group {}, setup {}".format(group, setup)))
    do_test(group, pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


@pytest.mark.parametrize("ip_addr", ["ipv4", "ipv6"])
def test_src_ip_is_multicast_addr(do_test, ptfadapter, setup, tx_dut_ports, pkt_fields, ip_addr, ports_info):
    """
    @summary: Create a packet with multicast source IP adress.
    """
    ip_src = None

    if ip_addr == "ipv4":
        ip_src = "224.0.0.5"
        pkt = testutils.simple_tcp_packet(
            eth_dst=ports_info["dst_mac"],  # DUT port
            eth_src=ports_info["src_mac"],  # PTF port
            ip_src=ip_src,
            ip_dst=pkt_fields["ipv4_dst"],  # VM source
            tcp_sport=pkt_fields["tcp_sport"],
            tcp_dport=pkt_fields["tcp_dport"])
    elif ip_addr == "ipv6":
        if not pkt_fields["ipv6_dst"]:
            pytest.skip("BGP neighbour with IPv6 addr was not found")
        ip_src = "FF02:AAAA:FEE5::1:3"
        pkt = testutils.simple_tcpv6_packet(
            eth_dst=ports_info["dst_mac"],  # DUT port
            eth_src=ports_info["src_mac"],  # PTF port
            ipv6_src=ip_src,
            ipv6_dst=pkt_fields["ipv6_dst"],  # VM source
            tcp_sport=pkt_fields["tcp_sport"],
            tcp_dport=pkt_fields["tcp_dport"])
    else:
        pytest.fail("Incorrect value specified for 'ip_addr' test parameter. Supported parameters: 'ipv4' and 'ipv6'")

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"],
                   ports_info["src_mac"], pkt_fields["ipv4_dst"], ip_src)

    group = "L3"
    do_test(group, pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports, ip_ver=ip_addr)


def test_src_ip_is_class_e(do_test, ptfadapter, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                           setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Create a packet with source IP address in class E.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_type = duthost.facts["asic_type"]
    pytest_require("broadcom" not in asic_type, "BRCM does not drop SIP class E packets")

    ip_list = ["240.0.0.1", "255.255.255.254"]

    for ip_class_e in ip_list:
        log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"],
                       ports_info["src_mac"], pkt_fields["ipv4_dst"], ip_class_e)

        pkt = testutils.simple_tcp_packet(
            eth_dst=ports_info["dst_mac"],  # DUT port
            eth_src=ports_info["src_mac"],  # PTF port
            ip_src=ip_class_e,
            ip_dst=pkt_fields["ipv4_dst"],  # VM source
            tcp_sport=pkt_fields["tcp_sport"],
            tcp_dport=pkt_fields["tcp_dport"])

        group = "L3"
        do_test(group, pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


@pytest.mark.parametrize("addr_type, addr_direction", [("ipv4", "src"), ("ipv6", "src"),
                                                       ("ipv4", "dst"), ("ipv6", "dst")])
def test_ip_is_zero_addr(do_test, ptfadapter, setup, tx_dut_ports, pkt_fields, addr_type, addr_direction, ports_info):
    """
    @summary: Create a packet with "0.0.0.0" source or destination IP address.
    """
    zero_ipv4 = "0.0.0.0"
    zero_ipv6 = "::0"

    pkt_params = {
        "eth_dst": ports_info["dst_mac"],  # DUT port
        "eth_src": ports_info["src_mac"],  # PTF port
        "tcp_sport": pkt_fields["tcp_sport"],
        "tcp_dport": pkt_fields["tcp_dport"]
        }

    if addr_type == "ipv4":
        if addr_direction == "src":
            pkt_params["ip_src"] = zero_ipv4
            pkt_params["ip_dst"] = pkt_fields["ipv4_dst"]  # VM source
        elif addr_direction == "dst":
            pkt_params["ip_src"] = pkt_fields["ipv4_src"]  # VM source
            pkt_params["ip_dst"] = zero_ipv4
        else:
            pytest.fail("Incorrect value specified for 'addr_direction'. Supported parameters: 'src' and 'dst'")
        pkt = testutils.simple_tcp_packet(**pkt_params)
    elif addr_type == "ipv6":
        if not pkt_fields["ipv6_dst"]:
            pytest.skip("BGP neighbour with IPv6 addr was not found")
        if addr_direction == "src":
            pkt_params["ipv6_src"] = zero_ipv6
            pkt_params["ipv6_dst"] = pkt_fields["ipv6_dst"]  # VM source
        elif addr_direction == "dst":
            pkt_params["ipv6_src"] = pkt_fields["ipv6_src"]  # VM source
            pkt_params["ipv6_dst"] = zero_ipv6
        else:
            pytest.fail("Incorrect value specified for 'addr_direction'. Supported parameters: 'src' and 'dst'")
        pkt = testutils.simple_tcpv6_packet(**pkt_params)
    else:
        pytest.fail("Incorrect value specified for 'addr_type' test parameter. Supported parameters: 'ipv4' or 'ipv6'")

    logger.info(pkt_params)

    group = "L3"
    # Src IP zero drops not supported on DNX platform
    if setup.get("platform_asic") == "broadcom-dnx" and addr_direction == "src":
        pytest.skip("Src IP zero packets are not dropped on Broadcom DNX platform currently")

    do_test(group, pkt, ptfadapter, ports_info, list(setup["dut_to_ptf_port_map"].values()), tx_dut_ports,
            ip_ver=addr_type)


def test_dst_ip_link_local(do_test, ptfadapter, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                           setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Create a packet with link-local address "169.254.0.0/16".
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic_type = duthost.facts["asic_type"]
    pytest_require("broadcom" not in asic_type, "BRCM does not drop DIP link local packets")

    link_local_ip = "169.254.10.125"

    pkt_params = {
        "eth_dst": ports_info["dst_mac"],  # DUT port
        "eth_src": ports_info["src_mac"],  # PTF port
        "tcp_sport": pkt_fields["tcp_sport"],
        "tcp_dport": pkt_fields["tcp_dport"]
    }
    pkt_params["ip_src"] = pkt_fields["ipv4_src"]  # VM source
    pkt_params["ip_dst"] = link_local_ip
    pkt = testutils.simple_tcp_packet(**pkt_params)

    group = "L3"

    logger.info(pkt_params)
    do_test(group, pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


def test_loopback_filter(do_test, ptfadapter, setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Create a packet drops by loopback-filter. Loop-back filter means that route to the host
              with DST IP of received packet exists on received interface
    """
    ip_dst = None
    vm_name = setup["mg_facts"]["minigraph_neighbors"][ports_info["dut_iface"]]["name"]

    for item in setup["mg_facts"]["minigraph_bgp"]:
        if item["name"] == vm_name:
            ip_dst = item["addr"]
            break
    if ip_dst is None:
        pytest.skip("Testcase is not supported on current interface")

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"],
                   ports_info["src_mac"], ip_dst, pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=ip_dst,
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    group = "L3"

    do_test(group, pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


def test_ip_pkt_with_expired_ttl(duthost, do_test, ptfadapter, setup, tx_dut_ports, pkt_fields,
                                 ports_info, sai_acl_drop_adj_enabled, configure_copp_drop_for_ttl_error):
    """
    @summary: Create an IP packet with TTL=0.
    """
    if "x86_64-mlnx_msn" in duthost.facts["platform"] or "x86_64-nvidia_sn" in duthost.facts["platform"]:
        pytest.skip("Not supported on Mellanox devices")

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"],
                   pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],  # VM IP address
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"],
        ip_ttl=0)

    group = "L3"
    do_test(group, pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"],
            tx_dut_ports, skip_counter_check=sai_acl_drop_adj_enabled)


@pytest.mark.parametrize("pkt_field, value", [("version", 1), ("chksum", 10), ("ihl", 1)])
def test_broken_ip_header(do_test, ptfadapter, setup, tx_dut_ports, pkt_fields, pkt_field,
                          value, ports_info, sai_acl_drop_adj_enabled):
    """
    @summary: Create a packet with broken IP header.
    """
    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"],
                   pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )
    setattr(pkt[packet.IP], pkt_field, value)

    group = "L3"
    do_test(group, pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"],
            tx_dut_ports, skip_counter_check=sai_acl_drop_adj_enabled)


def test_absent_ip_header(do_test, ptfadapter, setup, tx_dut_ports, pkt_fields, ports_info, sai_acl_drop_adj_enabled):
    """
    @summary: Create packets with absent IP header.
    """
    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"],
                   pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )
    tcp = pkt[packet.TCP]
    del pkt[packet.IP]
    pkt.type = 0x800
    pkt = pkt/tcp

    group = "L3"

    do_test(group, pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"],
            tx_dut_ports, skip_counter_check=sai_acl_drop_adj_enabled)


@pytest.mark.parametrize("eth_dst", ["01:00:5e:00:01:02", "ff:ff:ff:ff:ff:ff"])
def test_unicast_ip_incorrect_eth_dst(do_test, ptfadapter, setup, tx_dut_ports,
                                      pkt_fields, eth_dst, ports_info):
    """
    @summary: Create packets with multicast/broadcast ethernet dst.
    """
    if "vlan" in tx_dut_ports[ports_info["dut_iface"]].lower():
        pytest.skip("Test case is not supported on VLAN interface")

    log_pkt_params(ports_info["dut_iface"], eth_dst, ports_info["src_mac"],
                   pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=eth_dst,  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )

    group = "L3"
    do_test(group, pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


@pytest.mark.parametrize("igmp_version,msg_type", [("v1", "general_query"), ("v3", "general_query"),
                                                   ("v1", "membership_report"), ("v2", "membership_report"),
                                                   ("v3", "membership_report"), ("v2", "leave_group")])
def test_non_routable_igmp_pkts(do_test, ptfadapter, setup, fanouthost, tx_dut_ports,
                                pkt_fields, igmp_version, msg_type, ports_info):
    """
    @summary: Create an IGMP non-routable packets.
    """
    # IGMP Types:
    # 0x11 = Membership Query
    # 0x12 = Version 1 Membership Report
    # 0x16 = Version 2 Membership Report
    # 0x17 = Leave Group

    # IP destination address according to the RFC 2236:
    # Message Type                  Destination Group
    # ------------                  -----------------
    # General Query                 ALL-SYSTEMS (224.0.0.1)
    # Group-Specific Query          The group being queried
    # Membership Report             The group being reported
    # Leave Message                 ALL-ROUTERS (224.0.0.2)

    # TODO: fix this workaround as of now current PTF and Scapy versions do not support creation of IGMP packets
    # Temporaly created hex of IGMP packet layer by using scapy version 2.4.3.
    # Example how to get HEX of specific IGMP packets:
    # v3_membership_query = IGMPv3(type=0x11, mrcode=0, chksum=None)/scapy.contrib.igmpv3.IGMPv3mq(gaddr="224.0.0.1",
    # srcaddrs=["172.16.11.1", "10.0.0.59"], qrv=1, qqic=125, numsrc=2)
    # gr_obj = scapy.contrib.igmpv3.IGMPv3gr(rtype=1, auxdlen=0, maddr="224.2.2.4", numsrc=2, srcaddrs=["172.16.11.1",
    # "10.0.0.59"]).build()
    # v3_membership_report = \
    #     IGMPv3(type=0x22, mrcode=0, chksum=None)/scapy.contrib.igmpv3.IGMPv3mr(res2=0x00, numgrp=1,
    # records=[gr_obj]).build()
    # The rest packets are build like "simple_igmp_packet" function from PTF testutils.py

    # FIXME: Need some sort of configuration for EOS and SONiC fanout hosts to
    # not drop IGMP packets before they reach the DUT
    if not fanouthost:
        pytest.skip("Test case requires explicit fanout support")

    from scapy.contrib.igmp import IGMP
    Ether = packet.Ether
    IP = packet.IP

    if "vlan" in tx_dut_ports[ports_info["dut_iface"]].lower() and msg_type == "membership_report":
        pytest.skip("Test case is not supported on VLAN interface")

    igmp_proto = 0x02
    multicast_group_addr = "224.1.1.1"
    ethernet_dst = "01:00:5e:01:01:01"
    ip_dst = {"general_query": "224.0.0.1",
              "membership_report": multicast_group_addr}
    igmp_types = {
        "v1": {"general_query": IGMP(type=0x11, gaddr="224.0.0.1"),
               "membership_report": IGMP(type=0x12, gaddr=multicast_group_addr)},
        "v2": {"membership_report": IGMP(type=0x16, gaddr=multicast_group_addr),
               "leave_group": IGMP(type=0x17, gaddr=multicast_group_addr)},
        "v3": {"general_query": "\x11\x00L2\xe0\x00\x00\x01\x01}\x00\x02\xac\x10\x0b\x01\n\x00\x00;",
               "membership_report": "\"\x009\xa9\x00\x00\x00\x01\x01\x00\x00\x02\xe0\x02\x02\x04\xac\x10\x0b\x01\n\x00\x00;"}   # noqa E501
    }

    if igmp_version == "v3":
        pkt = testutils.simple_ip_packet(
            eth_dst=ethernet_dst,
            eth_src=ports_info["src_mac"],
            ip_src=pkt_fields["ipv4_src"],
            ip_dst=ip_dst[msg_type],
            ip_ttl=1,
            ip_proto=igmp_proto
        )
        del pkt["Raw"]
        pkt = pkt / igmp_types[igmp_version][msg_type]
    else:
        eth_layer = Ether(src=ports_info["src_mac"], dst=ethernet_dst)
        ip_layer = IP(src=pkt_fields["ipv4_src"], )
        igmp_layer = igmp_types[igmp_version][msg_type]
        pkt = eth_layer/ip_layer/igmp_layer
        try:
            # in old scapy version such as 2.2.0.dev0, igmpize method require the parameter ip and ether,
            # if these params not specified the return value will be False
            # in new scapy version such as 2.4.5, the igmpize dose not require any parameters,
            # if any parameter is given, it will throw TypeError
            assert igmp_layer.igmpize(ip=ip_layer, ether=eth_layer), "Can't create IGMP packet"
        except TypeError:
            assert igmp_layer.igmpize(), "Can't create IGMP packet"

    log_pkt_params(ports_info["dut_iface"], ethernet_dst, ports_info["src_mac"],
                   pkt.getlayer("IP").dst, pkt_fields["ipv4_src"])

    group = "L3"
    do_test(group, pkt, ptfadapter, ports_info, list(setup["dut_to_ptf_port_map"].values()), tx_dut_ports)


def test_acl_drop(do_test, ptfadapter, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                  setup, tx_dut_ports, pkt_fields, acl_ingress, ports_info):
    """
        @summary: Verify that DUT drops packet with SRC IP 20.0.0.0/24 matched by ingress ACL
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    namespace = duthost.get_namespace_from_asic_id(ports_info['asic_index'])
    if tx_dut_ports[ports_info["dut_iface"]] not in \
            duthost.acl_facts(namespace=namespace)["ansible_facts"]["ansible_acl_facts"]["DATAACL"]["ports"]:
        pytest.skip("RX DUT port absent in 'DATAACL' table")

    ip_src = "20.0.0.5"

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"],
                   ip_src)

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=ip_src,
        ip_dst=pkt_fields["ipv4_dst"],
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
    )

    do_test("ACL", pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


def test_acl_egress_drop(do_test, ptfadapter, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                         setup, tx_dut_ports, pkt_fields, acl_egress, ports_info):
    """
        @summary: Verify that DUT drops packet with DST IP 192.168.144.1/24
        matched by egress ACL and ACL drop counter incremented
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    namespace = duthost.get_namespace_from_asic_id(ports_info['asic_index'])
    if tx_dut_ports[ports_info["dut_iface"]] not in \
            duthost.acl_facts(namespace=namespace)["ansible_facts"]["ansible_acl_facts"]["DATAACL"]["ports"]:
        pytest.skip("RX DUT port absent in 'DATAACL' table")

    ip_dst = "192.168.144.1"

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], ip_dst,
                   pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_dst=ip_dst,
        ip_src=pkt_fields["ipv4_src"],
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"],
        ip_ttl=64
    )
    do_test(discard_group="ACL", pkt=pkt, ptfadapter=ptfadapter, ports_info=ports_info,
            sniff_ports=setup["neighbor_sniff_ports"], tx_dut_ports=tx_dut_ports, drop_information="OUTDATAACL")
