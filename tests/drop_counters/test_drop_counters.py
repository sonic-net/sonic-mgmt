import pytest
import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet
import logging
import pprint
import random
import time
import scapy
import yaml
import re
import os
import json
import netaddr


logger = logging.getLogger(__name__)

PKT_NUMBER = 1000

# Discard key from 'portstat -j' CLI command output
RX_DRP = "RX_DRP"
RX_ERR = "RX_ERR"
# CLI commands to obtain drop counters
GET_L2_COUNTERS = "portstat -j"
GET_L3_COUNTERS = "intfstat -j"
ACL_COUNTERS_UPDATE_INTERVAL = 10
LOG_EXPECT_ACL_RULE_CREATE_RE = ".*Successfully created ACL rule.*"
LOG_EXPECT_ACL_RULE_REMOVE_RE = ".*Successfully deleted ACL rule.*"
LOG_EXPECT_PORT_ADMIN_DOWN_RE = ".*Configure {} admin status to down.*"
LOG_EXPECT_PORT_ADMIN_UP_RE = ".*Port {} oper state set from down to up.*"

COMBINED_L2L3_DROP_COUNTER = False
COMBINED_ACL_DROP_COUNTER = False


def parse_combined_counters(duthost):
    # Get info whether L2 and L3 drop counters are linked
    # Or ACL and L2 drop counters are linked
    base_dir = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(base_dir, "combined_drop_counters.yml")) as stream:
        regexps = yaml.safe_load(stream)
        if regexps["l2_l3"]:
            for item in regexps["l2_l3"]:
                if re.match(item, duthost.facts["platform"]):
                    COMBINED_L2L3_DROP_COUNTER = True
                    break
        if regexps["acl"]:
            for item in regexps["acl"]:
                if re.match(item, duthost.facts["platform"]):
                    COMBINED_ACL_DROP_COUNTER = True
                    break


@pytest.fixture(scope="module")
def pkt_fields(duthost):
    # Gather ansible facts
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
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


@pytest.fixture(scope="module")
def setup(duthost, testbed):
    """
    Setup fixture for collecting PortChannel, VLAN and RIF port members.
    @return: Dictionary with keys:
        port_channel_members, vlan_members, rif_members, dut_to_ptf_port_map, neighbor_sniff_ports, vlans, mg_facts
    """
    port_channel_members = {}
    vlan_members = {}
    configured_vlans = []
    rif_members = []

    if testbed["topo"] == "ptf32":
        pytest.skip("Unsupported topology {}".format(testbed["topo"]))

    # Gather ansible facts
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']

    for port_channel, interfaces in mg_facts['minigraph_portchannels'].items():
        for iface in interfaces["members"]:
            port_channel_members[iface] = port_channel

    for vlan_id in mg_facts["minigraph_vlans"]:
        for iface in mg_facts["minigraph_vlans"][vlan_id]["members"]:
            vlan_members[iface] = vlan_id

    rif_members = {item["attachto"]: item["attachto"] for item in mg_facts["minigraph_interfaces"]}

    # Compose list of sniff ports
    neighbor_sniff_ports = []
    for dut_port, neigh in mg_facts['minigraph_neighbors'].items():
        neighbor_sniff_ports.append(mg_facts['minigraph_port_indices'][dut_port])

    for vlan_name, vlans_data in mg_facts["minigraph_vlans"].items():
        configured_vlans.append(int(vlans_data["vlanid"]))

    setup_information = {
        "port_channel_members": port_channel_members,
        "vlan_members": vlan_members,
        "rif_members": rif_members,
        "dut_to_ptf_port_map": mg_facts["minigraph_port_indices"],
        "neighbor_sniff_ports": neighbor_sniff_ports,
        "vlans": configured_vlans,
        "mg_facts": mg_facts
    }
    parse_combined_counters(duthost)
    return setup_information


@pytest.fixture(params=["port_channel_members", "vlan_members", "rif_members"])
def tx_dut_ports(request, setup):
    """ Fixture for getting port members of specific port group """
    return setup[request.param] if setup[request.param] else pytest.skip("No {} available".format(request.param))


@pytest.fixture(autouse=True, scope="module")
def enable_counters(duthost):
    """ Fixture which enables RIF and L2 counters """
    cmd_list = ["intfstat -D", "counterpoll port enable", "counterpoll rif enable", "sonic-clear counters",
                "sonic-clear rifcounters"]
    cmd_get_cnt_status = "redis-cli -n 4 HGET \"FLEX_COUNTER_TABLE|{}\" \"FLEX_COUNTER_STATUS\""

    previous_cnt_status = {item: duthost.command(cmd_get_cnt_status.format(item.upper()))["stdout"] for item in ["port", "rif"]}

    for cmd in cmd_list:
        duthost.command(cmd)
    try:
        yield
    finally:
        for port, status in previous_cnt_status.items():
            if status == "disable":
                logger.info("Restoring counter '{}' state to disable".format(port))
                duthost.command("counterpoll {} disable".format(port))


@pytest.fixture
def mtu_config(duthost):
    """ Fixture which prepare port MTU configuration for 'test_ip_pkt_with_exceeded_mtu' test case """
    class MTUConfig(object):
        iface = None
        mtu = None
        default_mtu = 9100
        @classmethod
        def set_mtu(cls, mtu, iface):
            cls.mtu = duthost.command("redis-cli -n 4 hget \"PORTCHANNEL|{}\" mtu".format(iface))["stdout"]
            if not cls.mtu:
                cls.mtu = cls.default_mtu
            if "PortChannel" in iface:
                duthost.command("redis-cli -n 4 hset \"PORTCHANNEL|{}\" mtu {}".format(iface, mtu))["stdout"]
            elif "Ethernet" in iface:
                duthost.command("redis-cli -n 4 hset \"PORT|{}\" mtu {}".format(iface, mtu))["stdout"]
            else:
                raise Exception("Unsupported interface parameter - {}".format(iface))
            cls.iface = iface
        @classmethod
        def restore_mtu(cls):
            if "PortChannel" in cls.iface:
                duthost.command("redis-cli -n 4 hset \"PORTCHANNEL|{}\" mtu {}".format(cls.iface, cls.mtu))["stdout"]
            elif "Ethernet" in cls.iface:
                duthost.command("redis-cli -n 4 hset \"PORT|{}\" mtu {}".format(cls.iface, cls.mtu))["stdout"]
            else:
                raise Exception("Trying to restore MTU on unsupported interface - {}".format(cls.iface))
    try:
        yield MTUConfig
    finally:
        MTUConfig.restore_mtu()


@pytest.fixture
def acl_setup(duthost, loganalyzer):
    """ Create acl rule defined in config file. Delete rule after test case finished """
    base_dir = os.path.dirname(os.path.realpath(__file__))
    template_dir = os.path.join(base_dir, 'acl_templates')
    acl_rules_template = "acltb_test_rule.json"
    del_acl_rules_template = "acl_rule_del.json"
    dut_tmp_dir = os.path.join("tmp", os.path.basename(base_dir))

    duthost.command("mkdir -p {}".format(dut_tmp_dir))
    dut_conf_file_path = os.path.join(dut_tmp_dir, acl_rules_template)
    dut_clear_conf_file_path = os.path.join(dut_tmp_dir, del_acl_rules_template)

    logger.info("Generating config for ACL rule, ACL table - DATAACL")
    duthost.template(src=os.path.join(template_dir, acl_rules_template), dest=dut_conf_file_path)
    logger.info("Generating clear config for ACL rule, ACL table - DATAACL")
    duthost.template(src=os.path.join(template_dir, del_acl_rules_template), dest=dut_clear_conf_file_path)

    logger.info("Applying {}".format(dut_conf_file_path))

    loganalyzer.expect_regex = [LOG_EXPECT_ACL_RULE_CREATE_RE]
    with loganalyzer as analyzer:
        duthost.command("config acl update full {}".format(dut_conf_file_path))

    try:
        yield
    finally:
        loganalyzer.expect_regex = [LOG_EXPECT_ACL_RULE_REMOVE_RE]
        with loganalyzer as analyzer:
            logger.info("Applying {}".format(dut_clear_conf_file_path))
            duthost.command("config acl update full {}".format(dut_clear_conf_file_path))
            logger.info("Removing {}".format(dut_tmp_dir))
            duthost.command("rm -rf {}".format(dut_tmp_dir))


@pytest.fixture
def rif_port_down(duthost, setup, loganalyzer):
    """ Disable RIF interface and return neighbor IP address attached to this interface """
    wait_after_ports_up = 30

    if not setup["rif_members"]:
        pytest.skip("RIF interface is absent")
    rif_member_iface = setup["rif_members"].keys()[0]

    try:
        vm_name = setup["mg_facts"]["minigraph_neighbors"][rif_member_iface]["name"]
    except KeyError as err:
        pytest.fail("Didn't found RIF interface in 'minigraph_neighbors'. {}".format(str(err)))

    ip_dst = None
    for item in setup["mg_facts"]["minigraph_bgp"]:
        if item["name"] == vm_name:
            if netaddr.valid_ipv4(item["addr"]):
                ip_dst = item["addr"]
                break
    else:
        pytest.fail("Unable to find neighbor in 'minigraph_bgp' list")

    loganalyzer.expect_regex = [LOG_EXPECT_PORT_ADMIN_DOWN_RE.format(rif_member_iface)]
    with loganalyzer as analyzer:
        duthost.command("config interface shutdown {}".format(rif_member_iface))

    time.sleep(1)
    try:
        yield ip_dst
    finally:
        loganalyzer.expect_regex = [LOG_EXPECT_PORT_ADMIN_UP_RE.format(rif_member_iface)]
        with loganalyzer as analyzer:
            duthost.command("config interface startup {}".format(rif_member_iface))
            time.sleep(wait_after_ports_up)


def get_pkt_drops(duthost, cli_cmd):
    """
    @summary: Parse output of "portstat" or "intfstat" commands and convert it to the dictionary.
    @param module: The AnsibleModule object
    @param cli_cmd: one of supported CLI commands - "portstat -j" or "intfstat -j"
    @return: Return dictionary of parsed counters
    """
    stdout = duthost.command(cli_cmd)
    if stdout["rc"] != 0:
        raise Exception(stdout["stdout"] + stdout["stderr"])
    stdout = stdout["stdout"]

    match = re.search("Last cached time was.*\n", stdout)
    if match:
        stdout = re.sub("Last cached time was.*\n", "", stdout)

    try:
        return json.loads(stdout)
    except Exception as err:
        raise Exception("Failed to parse output of '{}', err={}".format(cli_cmd, str(err)))


def get_dut_iface_mac(duthost, iface_name):
    """ Fixture for getting MAC address of specified interface """
    for iface, iface_info in duthost.setup()['ansible_facts'].items():
        if iface_name in iface:
            return iface_info["macaddress"]


def get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports):
    """
    Return:
        dut_iface - DUT interface name expected to receive packtes from PTF
        ptf_tx_port_id - Port ID used by PTF for sending packets from expected PTF interface
        dst_mac - DUT interface destination MAC address
        src_mac - PTF interface source MAC address
    """
    dut_iface = random.choice(tx_dut_ports.keys())
    ptf_tx_port_id = setup["dut_to_ptf_port_map"][dut_iface]
    dst_mac = get_dut_iface_mac(duthost, dut_iface)
    src_mac = ptfadapter.dataplane.ports[(0, ptf_tx_port_id)].mac()
    return dut_iface, ptf_tx_port_id, dst_mac, src_mac


def expected_packet_mask(pkt):
    """ Return mask for sniffing packet """

    exp_pkt = pkt.copy()
    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
    exp_pkt.set_do_not_care_scapy(packet.IP, 'ttl')
    exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')
    return exp_pkt


def log_pkt_params(dut_iface, mac_dst, mac_src, ip_dst, ip_src):
    """ Displays information about packet fields used in test case: mac_dst, mac_src, ip_dst, ip_src """
    logger.info("Selected TX interface on DUT - {}".format(dut_iface))
    logger.info("Packet DST MAC - {}".format(mac_dst))
    logger.info("Packet SRC MAC - {}".format(mac_src))
    logger.info("Packet IP DST - {}".format(ip_dst))
    logger.info("Packet IP SRC - {}".format(ip_src))


def ensure_no_l3_drops(duthost):
    """ Verify L3 drop counters were not incremented """
    intf_l3_counters = get_pkt_drops(duthost, GET_L3_COUNTERS)
    unexpected_drops = {}
    for iface, value in intf_l3_counters.items():
        if int(value[RX_ERR]) >= PKT_NUMBER:
            unexpected_drops[iface] = int(value[RX_ERR])
    if unexpected_drops:
        pytest.fail("L3 'RX_ERR' was incremented for the following interfaces:\n{}".format(unexpected_drops))


def ensure_no_l2_drops(duthost):
    """ Verify L2 drop counters were not incremented """
    intf_l2_counters = get_pkt_drops(duthost, GET_L2_COUNTERS)
    unexpected_drops = {}
    for iface, value in intf_l2_counters.items():
        if int(value[RX_DRP]) >= PKT_NUMBER:
            unexpected_drops[iface] = int(value[RX_DRP])
    if unexpected_drops:
        pytest.fail("L2 'RX_DRP' was incremented for the following interfaces:\n{}".format(unexpected_drops))


def send_packets(pkt, duthost, ptfadapter, ptf_tx_port_id):
    # Clear SONiC counters
    duthost.command("sonic-clear counters")
    duthost.command("sonic-clear rifcounters")

    # Clear packets buffer on PTF
    ptfadapter.dataplane.flush()
    time.sleep(1)

    # Send packets
    testutils.send(ptfadapter, ptf_tx_port_id, pkt, count=PKT_NUMBER)
    time.sleep(1)


def str_to_int(value):
    """ Convert string value which can contain ',' symbols to integer value """
    return int("".join(value.split(",")))


def base_verification(discard_group, pkt, ptfadapter, duthost, ptf_tx_port_id, dut_iface):
    """
    Base test function for verification of L2 or L3 packet drops. Verification type depends on 'discard_group' value.
    Supported 'discard_group' values: 'L2', 'L3', 'ACL'
    """
    send_packets(pkt, duthost, ptfadapter, ptf_tx_port_id)
    if discard_group == "L2":
        # Verify drop counter incremented on specific interface
        intf_l2_counters = get_pkt_drops(duthost, GET_L2_COUNTERS)
        if int(intf_l2_counters[dut_iface][RX_DRP]) != PKT_NUMBER:
            fail_msg = "'{}' drop counter was not incremented on iface {}. DUT {} == {}; Sent == {}".format(
                RX_DRP, dut_iface, RX_DRP,
                int(intf_l2_counters[dut_iface][RX_DRP]), PKT_NUMBER
            )
            pytest.fail(fail_msg)

        # Skip L3 discards verification for platform with linked L2 and L3 drop counters
        if not COMBINED_L2L3_DROP_COUNTER:
            ensure_no_l3_drops(duthost)
    elif discard_group == "L3":
        # Verify L3 drop counter incremented on specific interface
        l3_drops = get_pkt_drops(duthost, GET_L3_COUNTERS)[dut_iface][RX_ERR]
        l3_drops = str_to_int(l3_drops)

        if l3_drops != PKT_NUMBER:
            fail_msg = "RX_ERR drop counter was not incremented on iface {}. DUT RX_ERR == {}; Sent pkts == {}".format(
                dut_iface, l3_drops, PKT_NUMBER
            )
            pytest.fail(fail_msg)

        # Skip L2 discards verification for platform with linked L2 and L3 drop counters
        if not COMBINED_L2L3_DROP_COUNTER:
            ensure_no_l2_drops(duthost)
    elif discard_group == "ACL":
        time.sleep(ACL_COUNTERS_UPDATE_INTERVAL)
        acl_drops = duthost.acl_facts()["ansible_facts"]["ansible_acl_facts"]["DATAACL"]["rules"]["RULE_1"]["packets_count"]
        if acl_drops != PKT_NUMBER:
            fail_msg = "ACL drop counter was not incremented on iface {}. DUT ACL counter == {}; Sent pkts == {}".format(
                dut_iface, acl_drops, PKT_NUMBER
            )
            pytest.fail(fail_msg)
        if not COMBINED_ACL_DROP_COUNTER:
            ensure_no_l3_drops(duthost)
            ensure_no_l2_drops(duthost)
    else:
        pytest.fail("Incorrect 'discard_group' specified. Supported values: 'L2' or 'L3'")


def test_equal_smac_dmac_drop(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields):
    """
    @summary: Verify that packet with equal SMAC and DMAC is dropped and L2 drop counter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)

    log_pkt_params(dut_iface, dst_mac, dst_mac, pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=dst_mac, # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=pkt_fields["ipv4_dst"], # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    base_verification("L2", pkt, ptfadapter, duthost, ptf_tx_port_id, dut_iface)

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


def test_multicast_smac_drop(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields):
    """
    @summary: Verify that packet with multicast SMAC is dropped and L2 drop counter incremented
    """
    multicast_smac = "01:00:5e:00:01:02"
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)

    log_pkt_params(dut_iface, dst_mac, multicast_smac, pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=multicast_smac,
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=pkt_fields["ipv4_dst"], # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    base_verification("L2", pkt, ptfadapter, duthost, ptf_tx_port_id, dut_iface)

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


def test_reserved_dmac_drop(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields):
    """
    @summary: Verify that packet with reserved DMAC is dropped and L2 drop counter incremented
    @used_mac_address:
        01:80:C2:00:00:05 - reserved for future standardization
        01:80:C2:00:00:08 - provider Bridge group address
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)
    reserved_mac_addr = ["01:80:C2:00:00:05", "01:80:C2:00:00:08"]

    for reserved_dmac in reserved_mac_addr:
        log_pkt_params(dut_iface, dst_mac, reserved_dmac, pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])
        pkt = testutils.simple_tcp_packet(
            eth_dst=reserved_dmac, # DUT port
            eth_src=src_mac,
            ip_src=pkt_fields["ipv4_src"], # PTF source
            ip_dst=pkt_fields["ipv4_dst"], # VM source
            tcp_sport=pkt_fields["tcp_sport"],
            tcp_dport=pkt_fields["tcp_dport"])

        base_verification("L2", pkt, ptfadapter, duthost, ptf_tx_port_id, dut_iface)

        # Verify packets were not egresed the DUT
        exp_pkt = expected_packet_mask(pkt)
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


def test_not_expected_vlan_tag_drop(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields):
    """
    @summary: Verify that VLAN tagged packet which VLAN ID does not match ingress port VLAN ID is dropped
              and L2 drop counter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)

    log_pkt_params(dut_iface, dst_mac, src_mac, pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

    # Generate unexisted vlan value
    vlan_id = None
    while not vlan_id:
        interim = random.randint(2, 1000)
        if interim not in setup["vlans"]:
            vlan_id = interim

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=pkt_fields["ipv4_dst"], # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"],
        dl_vlan_enable=True,
        vlan_vid=vlan_id,
        )

    base_verification("L2", pkt, ptfadapter, duthost, ptf_tx_port_id, dut_iface)

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


def test_dst_ip_is_loopback_addr(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields):
    """
    @summary: Verify that packet with loopback destination IP adress is dropped and L3 drop counter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)
    ip_dst = "127.0.0.1"

    log_pkt_params(dut_iface, dst_mac, src_mac, ip_dst, pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=ip_dst, # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    base_verification("L3", pkt, ptfadapter, duthost, ptf_tx_port_id, tx_dut_ports[dut_iface])

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


def test_src_ip_is_loopback_addr(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields):
    """
    @summary: Verify that packet with loopback source IP adress is dropped and L3 drop counter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)
    ip_src = "127.0.0.1"

    log_pkt_params(dut_iface, dst_mac, src_mac, pkt_fields["ipv4_dst"], ip_src)

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=ip_src, # PTF source
        ip_dst=pkt_fields["ipv4_dst"], # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    base_verification("L3", pkt, ptfadapter, duthost, ptf_tx_port_id, tx_dut_ports[dut_iface])

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


def test_dst_ip_absent(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields):
    """
    @summary: Verify that packet with absent destination IP address is dropped and L3 drop counter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)

    log_pkt_params(dut_iface, dst_mac, src_mac, "", pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst="", # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    base_verification("L3", pkt, ptfadapter, duthost, ptf_tx_port_id, tx_dut_ports[dut_iface])

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


@pytest.mark.parametrize("ip_addr", ["ipv4", "ipv6"])
def test_src_ip_is_multicast_addr(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, ip_addr):
    """
    @summary: Verify that packet with multicast source IP adress is dropped and L3 drop counter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)
    ip_src = None

    if ip_addr == "ipv4":
        ip_src = "224.0.0.5"
        pkt = testutils.simple_tcp_packet(
            eth_dst=dst_mac, # DUT port
            eth_src=src_mac, # PTF port
            ip_src=ip_src,
            ip_dst=pkt_fields["ipv4_dst"], # VM source
            tcp_sport=pkt_fields["tcp_sport"],
            tcp_dport=pkt_fields["tcp_dport"])
    elif ip_addr == "ipv6":
        if not pkt_fields["ipv6_dst"]:
            pytest.skip("BGP neighbour with IPv6 addr was not found")
        ip_src = "FF02:AAAA:FEE5::1:3"
        pkt = testutils.simple_tcpv6_packet(
            eth_dst=dst_mac, # DUT port
            eth_src=src_mac, # PTF port
            ipv6_src=ip_src,
            ipv6_dst=pkt_fields["ipv6_dst"], # VM source
            tcp_sport=pkt_fields["tcp_sport"],
            tcp_dport=pkt_fields["tcp_dport"])
    else:
        pytest.fail("Incorrect value specified for 'ip_addr' test parameter. Supported parameters: 'ipv4' and 'ipv6'")

    log_pkt_params(dut_iface, dst_mac, src_mac, pkt_fields["ipv4_dst"], ip_src)
    base_verification("L3", pkt, ptfadapter, duthost, ptf_tx_port_id, tx_dut_ports[dut_iface])

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


def test_src_ip_is_class_e(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields):
    """
    @summary: Verify that packet with source IP address in class E is dropped and L3 drop counter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)
    ip_list = ["240.0.0.1", "255.255.255.254"]

    for ip_class_e in ip_list:
        log_pkt_params(dut_iface, dst_mac, src_mac, pkt_fields["ipv4_dst"], ip_class_e)

        pkt = testutils.simple_tcp_packet(
            eth_dst=dst_mac, # DUT port
            eth_src=src_mac, # PTF port
            ip_src=ip_class_e,
            ip_dst=pkt_fields["ipv4_dst"], # VM source
            tcp_sport=pkt_fields["tcp_sport"],
            tcp_dport=pkt_fields["tcp_dport"])

        base_verification("L3", pkt, ptfadapter, duthost, ptf_tx_port_id, tx_dut_ports[dut_iface])

        # Verify packets were not egresed the DUT
        exp_pkt = expected_packet_mask(pkt)
        testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


@pytest.mark.parametrize("addr_type, addr_direction", [("ipv4", "src"), ("ipv6", "src"), ("ipv4", "dst"),
                                                        ("ipv6", "dst")])
def test_ip_is_zero_addr(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, addr_type, addr_direction):
    """
    @summary: Verify that packet with "0.0.0.0" source or destination IP address is dropped and L3 drop counter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)
    zero_ipv4 = "0.0.0.0"
    zero_ipv6 = "::0"

    pkt_params = {
        "eth_dst": dst_mac, # DUT port
        "eth_src": src_mac, # PTF port
        "tcp_sport": pkt_fields["tcp_sport"],
        "tcp_dport": pkt_fields["tcp_dport"]
        }

    if addr_type == "ipv4":
        if addr_direction == "src":
            pkt_params["ip_src"] = zero_ipv4
            pkt_params["ip_dst"] = pkt_fields["ipv4_dst"] # VM source
        elif addr_direction == "dst":
            pkt_params["ip_src"] = pkt_fields["ipv4_src"] # VM source
            pkt_params["ip_dst"] = zero_ipv4
        else:
            pytest.fail("Incorrect value specified for 'addr_direction'. Supported parameters: 'src' and 'dst'")
        pkt = testutils.simple_tcp_packet(**pkt_params)
    elif addr_type == "ipv6":
        if not pkt_fields["ipv6_dst"]:
            pytest.skip("BGP neighbour with IPv6 addr was not found")
        if addr_direction == "src":
            pkt_params["ipv6_src"] = zero_ipv6
            pkt_params["ipv6_dst"] = pkt_fields["ipv6_dst"] # VM source
        elif addr_direction == "dst":
            pkt_params["ipv6_src"] = pkt_fields["ipv6_src"] # VM source
            pkt_params["ipv6_dst"] = zero_ipv6
        else:
            pytest.fail("Incorrect value specified for 'addr_direction'. Supported parameters: 'src' and 'dst'")
        pkt = testutils.simple_tcpv6_packet(**pkt_params)
    else:
        pytest.fail("Incorrect value specified for 'addr_type' test parameter. Supported parameters: 'ipv4' or 'ipv6'")

    logger.info(pkt_params)
    base_verification("L3", pkt, ptfadapter, duthost, ptf_tx_port_id, tx_dut_ports[dut_iface])

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["dut_to_ptf_port_map"].values())


@pytest.mark.parametrize("addr_direction", ["src", "dst"])
def test_ip_link_local(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, addr_direction):
    """
    @summary: Verify that packet with link-local address "169.254.0.0/16" is dropped and L3 drop counter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)
    link_local_ip = "169.254.10.125"

    pkt_params = {
        "eth_dst": dst_mac, # DUT port
        "eth_src": src_mac, # PTF port
        "tcp_sport": pkt_fields["tcp_sport"],
        "tcp_dport": pkt_fields["tcp_dport"]
        }

    if addr_direction == "src":
        pkt_params["ip_src"] = link_local_ip
        pkt_params["ip_dst"] = pkt_fields["ipv4_dst"] # VM source
    elif addr_direction == "dst":
        pkt_params["ip_src"] = pkt_fields["ipv4_src"] # VM source
        pkt_params["ip_dst"] = link_local_ip
    else:
        pytest.fail("Incorrect value specified for 'addr_direction'. Supported parameters: 'src' and 'dst'")
    pkt = testutils.simple_tcp_packet(**pkt_params)

    logger.info(pkt_params)
    base_verification("L3", pkt, ptfadapter, duthost, ptf_tx_port_id, tx_dut_ports[dut_iface])

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


def test_loopback_filter(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields):
    """
    @summary: Verify that packet drops by loopback-filter. Loop-back filter means that route to the host
              with DST IP of received packet exists on received interface
    """
    ip_dst = None
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)
    vm_name = setup["mg_facts"]["minigraph_neighbors"][dut_iface]["name"]

    for item in setup["mg_facts"]["minigraph_bgp"]:
        if item["name"] == vm_name:
            ip_dst = item["addr"]
            break
    if ip_dst is None:
        pytest.skip("Testcase is not supported on current interface")

    log_pkt_params(dut_iface, dst_mac, src_mac, ip_dst, pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=ip_dst,
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    base_verification("L3", pkt, ptfadapter, duthost, ptf_tx_port_id, tx_dut_ports[dut_iface])

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


def test_ip_pkt_with_exceeded_mtu(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, mtu_config):
    """
    @summary: Verify that IP packet with exceeded MTU is dropped and L3 drop counter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)
    tmp_port_mtu = 1500

    log_pkt_params(dut_iface, dst_mac, src_mac, pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])
    # Set temporal MTU. This will be restored by 'mtu' fixture
    mtu_config.set_mtu(tmp_port_mtu, tx_dut_ports[dut_iface])

    pkt = testutils.simple_tcp_packet(
        pktlen=9100,
        eth_dst=dst_mac, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=pkt_fields["ipv4_dst"], # VM IP address
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )

    send_packets(pkt, duthost, ptfadapter, ptf_tx_port_id)

    # Verify L2 drop counter incremented on specific interface
    l2_drops = get_pkt_drops(duthost, "portstat -j")[dut_iface][RX_ERR]
    l2_drops = str_to_int(l2_drops)

    if l2_drops != PKT_NUMBER:
        fail_msg = "RX_ERR drop counter was not incremented on iface {}. DUT RX_ERR == {}; Sent pkts == {}".format(
            dut_iface, l2_drops, PKT_NUMBER
        )
        pytest.fail(fail_msg)

    # Skip L3 discards verification for platform with linked L2 and L3 drop counters
    if not COMBINED_L2L3_DROP_COUNTER:
        ensure_no_l2_drops(duthost)

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


def test_ip_pkt_with_expired_ttl(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields):
    """
    @summary: Verify that IP packet with TTL=0 is dropped and L3 drop counter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)

    log_pkt_params(dut_iface, dst_mac, src_mac, pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=pkt_fields["ipv4_dst"], # VM IP address
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"],
        ip_ttl=0)

    base_verification("L3", pkt, ptfadapter, duthost, ptf_tx_port_id, tx_dut_ports[dut_iface])

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


@pytest.mark.parametrize("igmp_version,msg_type", [("v1", "membership_query"), ("v3", "membership_query"), ("v1", "membership_report"),
("v2", "membership_report"), ("v3", "membership_report"), ("v2", "leave_group")])
def test_non_routable_igmp_pkts(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, igmp_version, msg_type):
    """
    @summary: Verify IGMP non-routable packets dropped by DUT and L3 drop counter incremented
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
    # Temporaly created hex of IGMP packet layer
    # Example how to get HEX of specific IGMP packets:
    # v3_membership_query = IGMPv3(type=0x11, mrcode=0, chksum=None)/scapy.contrib.igmpv3.IGMPv3mq(gaddr="224.0.0.1",
    # srcaddrs=["172.16.11.1", "10.0.0.59"], qrv=1, qqic=125, numsrc=2)
    # gr_obj = scapy.contrib.igmpv3.IGMPv3gr(rtype=1, auxdlen=0, maddr="224.2.2.4", numsrc=2, srcaddrs=["172.16.11.1",
    # "10.0.0.59"]).build()
    # v3_membership_report = IGMPv3(type=0x22, mrcode=0, chksum=None)/scapy.contrib.igmpv3.IGMPv3mr(res2=0x00, numgrp=1,
    # records=[gr_obj]).build()
    # The rest packets are build like "simple_igmp_packet" function from PTF testutils.py
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)

    ethernet_dst = {"membership_query": "01:00:5e:00:00:01",
                    "membership_report": "01:00:5e:02:02:04",
                    "leave_group": "01:00:5e:00:00:02"}
    ip_dst = {"membership_query": "224.0.0.1",
              "membership_report": "224.2.2.4",
              "leave_group": "224.0.0.2"}
    igmp_types = {"v1": {"membership_query": "\x11\x00\x0e\xfe\xe0\x00\x00\x01",
                         "membership_report": "\x12\x00\x0b\xf9\xe0\x02\x02\x04"},
                  "v2": {"membership_report": "\x16\x00\x07\xf9\xe0\x02\x02\x04",
                         "leave_group": "\x17\x00\x08\xfd\xe0\x00\x00\x02"},
                  "v3": {"membership_query": "\x11\x00L2\xe0\x00\x00\x01\x01}\x00\x02\xac\x10\x0b\x01\n\x00\x00;",
                         "membership_report": "\"\x009\xa9\x00\x00\x00\x01\x01\x00\x00\x02\xe0\x02\x02\x04\xac\x10\x0b\x01\n\x00\x00;"}
    }

    log_pkt_params(dut_iface, ethernet_dst[msg_type], src_mac, ip_dst[msg_type], pkt_fields["ipv4_src"])

    pkt = testutils.simple_ip_packet(
        eth_dst=ethernet_dst[msg_type], # DUT port
        eth_src=src_mac, # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=ip_dst[msg_type],
        ip_ttl=1,
    )

    del pkt[testutils.scapy.scapy.all.Raw]
    pkt = pkt / igmp_types[igmp_version][msg_type]
    base_verification("L3", pkt, ptfadapter, duthost, ptf_tx_port_id, tx_dut_ports[dut_iface])

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["dut_to_ptf_port_map"].values())


def test_absent_ip_header(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields):
    """
    @summary: Verify that packets with absent IP header are dropped and L3 drop counter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)

    log_pkt_params(dut_iface, dst_mac, src_mac, pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=pkt_fields["ipv4_dst"],
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )
    tcp = pkt[testutils.scapy.scapy.all.TCP]
    del pkt[testutils.scapy.scapy.all.IP]
    pkt.type = 0x800
    pkt = pkt/tcp

    base_verification("L3", pkt, ptfadapter, duthost, ptf_tx_port_id, tx_dut_ports[dut_iface])

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


@pytest.mark.parametrize("pkt_field, value", [("version", 1), ("chksum", 10), ("ihl", 1)])
def test_broken_ip_header(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, pkt_field, value):
    """
    @summary: Verify that packets with broken IP header are dropped and L3 drop counter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)

    log_pkt_params(dut_iface, dst_mac, src_mac, pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=pkt_fields["ipv4_dst"],
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )
    setattr(pkt[testutils.scapy.scapy.all.IP], pkt_field, value)
    base_verification("L3", pkt, ptfadapter, duthost, ptf_tx_port_id, tx_dut_ports[dut_iface])

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


@pytest.mark.parametrize("eth_dst", ["01:00:5e:00:01:02", "ff:ff:ff:ff:ff:ff"])
def test_unicast_ip_incorrect_eth_dst(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, eth_dst):
    """
    @summary: Verify that packets with multicast/broadcast ethernet dst are dropped on L3 interfaces and L3 drop counter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)

    if  "vlan" in tx_dut_ports[dut_iface].lower():
        pytest.skip("Test case is not supported on VLAN interface")

    log_pkt_params(dut_iface, eth_dst, src_mac, pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=eth_dst, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=pkt_fields["ipv4_dst"],
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )
    base_verification("L3", pkt, ptfadapter, duthost, ptf_tx_port_id, tx_dut_ports[dut_iface])

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


def test_acl_drop(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, acl_setup):
    """
    @summary: Verify that DUT drops packet with SRC IP 20.0.0.0/24 matched by ingress ACL and ACL drop counter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)

    if tx_dut_ports[dut_iface] not in duthost.acl_facts()["ansible_facts"]["ansible_acl_facts"]["DATAACL"]["ports"]:
        pytest.skip("RX DUT port absent in 'DATAACL' table")

    ip_src = "20.0.0.5"

    log_pkt_params(dut_iface, dst_mac, src_mac, pkt_fields["ipv4_dst"], ip_src)

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=ip_src,
        ip_dst=pkt_fields["ipv4_dst"],
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )
    base_verification("ACL", pkt, ptfadapter, duthost, ptf_tx_port_id, tx_dut_ports[dut_iface])

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    exp_pkt.set_do_not_care_scapy(packet.IP, 'ip_src')
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


def test_egress_drop_on_down_link(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, rif_port_down):
    """
    @summary: Verify that packets on ingress port are dropped when egress RIF link is down and check that L3 drop counter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)
    ip_dst = rif_port_down
    log_pkt_params(dut_iface, dst_mac, src_mac, ip_dst, pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=ip_dst,
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )
    base_verification("L3", pkt, ptfadapter, duthost, ptf_tx_port_id, tx_dut_ports[dut_iface])

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])
