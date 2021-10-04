import logging
import os
import time
import pytest
import yaml
import re

import ptf.testutils as testutils

from collections import defaultdict

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from tests.common.helpers.drop_counters.drop_counters import verify_drop_counters, ensure_no_l3_drops, ensure_no_l2_drops
from .drop_packets import *  # FIXME

pytestmark = [
    pytest.mark.topology("any")
]

logger = logging.getLogger(__name__)

PKT_NUMBER = 1000

# CLI commands to obtain drop counters.
NAMESPACE_PREFIX = "sudo ip netns exec {} "
NAMESPACE_SUFFIX = "-n {} "
GET_L2_COUNTERS = "portstat -j "
GET_L3_COUNTERS = "intfstat -j "
LOG_EXPECT_PORT_ADMIN_DOWN_RE = ".*Configure {} admin status to down.*"
LOG_EXPECT_PORT_ADMIN_UP_RE = ".*Port {} oper state set from down to up.*"

COMBINED_L2L3_DROP_COUNTER = False
COMBINED_ACL_DROP_COUNTER = False


@pytest.fixture(autouse=True, scope="module")
def enable_counters(duthosts):
    """ Fixture which enables RIF and L2 counters """
    previous_cnt_status = defaultdict(dict)
    # Separating comands based on whether they need to be done per namespace or globally.
    cmd_list = ["intfstat -D", "sonic-clear counters"]
    cmd_list_per_ns = ["counterpoll port enable", "counterpoll rif enable", "sonic-clear rifcounters"]

    """ Fixture which enables RIF and L2 counters """
    for duthost in duthosts:
        duthost.shell_cmds(cmds=cmd_list)

        namespace_list = duthost.get_asic_namespace_list() if duthost.is_multi_asic else ['']
        for namespace in namespace_list:
            cmd_get_cnt_status = "sonic-db-cli -n '{}' CONFIG_DB HGET \"FLEX_COUNTER_TABLE|{}\" FLEX_COUNTER_STATUS"
            previous_cnt_status[duthost][namespace] = {item: duthost.command(cmd_get_cnt_status.format(namespace, item.upper()))["stdout"] for item in ["port", "rif"]}

            ns_cmd_list = []
            CMD_PREFIX = NAMESPACE_PREFIX.format(namespace) if duthost.is_multi_asic else ''
            for cmd in cmd_list_per_ns:
                ns_cmd_list.append(CMD_PREFIX + cmd)
            duthost.shell_cmds(cmds=ns_cmd_list)

    yield
    for duthost in duthosts:
        for namespace in namespace_list:
            for port, status in previous_cnt_status[duthost][namespace].items():
                if status == "disable":
                    logger.info("Restoring counter '{}' state to disable".format(port))
                    CMD_PREFIX = NAMESPACE_PREFIX.format(namespace) if duthost.is_multi_asic else ''
                    duthost.command(CMD_PREFIX + "counterpoll {} disable".format(port))


@pytest.fixture(scope='module', autouse=True)
def parse_combined_counters(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    # Get info whether L2 and L3 drop counters are linked
    # Or ACL and L2 drop counters are linked
    global COMBINED_L2L3_DROP_COUNTER, COMBINED_ACL_DROP_COUNTER
    base_dir = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(base_dir, "combined_drop_counters.yml")) as stream:
        regexps = yaml.safe_load(stream)
        if regexps["l2_l3"]:
            for item in regexps["l2_l3"]:
                if re.match(item, duthost.facts["platform"]):
                    COMBINED_L2L3_DROP_COUNTER = True
                    break
        if regexps["acl_l2"]:
            for item in regexps["acl_l2"]:
                if re.match(item, duthost.facts["platform"]):
                    COMBINED_ACL_DROP_COUNTER = True
                    break


def base_verification(discard_group, pkt, ptfadapter, duthosts, asic_index, ports_info, tx_dut_ports=None,
                      skip_counter_check=False, drop_information=None):
    """
    Base test function for verification of L2 or L3 packet drops. Verification type depends on 'discard_group' value.
    Supported 'discard_group' values: 'L2', 'L3', 'ACL', 'NO_DROPS'
    """
    # Clear SONiC counters
    for duthost in duthosts:
        duthost.command("sonic-clear counters")

        # Clear RIF counters per namespace.
        namespace = duthost.get_namespace_from_asic_id(asic_index)
        CMD_PREFIX = NAMESPACE_PREFIX.format(namespace) if duthost.is_multi_asic else ''
        duthost.command(CMD_PREFIX+"sonic-clear rifcounters")

    send_packets(pkt, ptfadapter, ports_info["ptf_tx_port_id"], PKT_NUMBER)

    # Some test cases will not increase the drop counter consistently on certain platforms
    if skip_counter_check:
        logger.info("Skipping counter check")
        return None

    if discard_group == "L2":
        verify_drop_counters(duthosts, asic_index, ports_info["dut_iface"], GET_L2_COUNTERS, L2_COL_KEY, packets_count=PKT_NUMBER)
        for duthost in duthosts:
            ensure_no_l3_drops(duthost, asic_index, packets_count=PKT_NUMBER)
    elif discard_group == "L3":
        if COMBINED_L2L3_DROP_COUNTER:
            verify_drop_counters(duthosts, asic_index, ports_info["dut_iface"], GET_L2_COUNTERS, L2_COL_KEY, packets_count=PKT_NUMBER)
            for duthost in duthosts:
                ensure_no_l3_drops(duthost, asic_index, packets_count=PKT_NUMBER)
        else:
            if not tx_dut_ports:
                pytest.fail("No L3 interface specified")

            verify_drop_counters(duthosts, asic_index, tx_dut_ports[ports_info["dut_iface"]], GET_L3_COUNTERS, L3_COL_KEY, packets_count=PKT_NUMBER)
            for duthost in duthosts:
                ensure_no_l2_drops(duthost, asic_index, packets_count=PKT_NUMBER)
    elif discard_group == "ACL":
        if not tx_dut_ports:
            pytest.fail("No L3 interface specified")

        time.sleep(ACL_COUNTERS_UPDATE_INTERVAL)
        acl_drops = 0
        for duthost in duthosts:
            acl_drops += duthost.acl_facts()["ansible_facts"]["ansible_acl_facts"][
                drop_information if drop_information else "DATAACL"]["rules"]["RULE_1"]["packets_count"]
        if acl_drops != PKT_NUMBER:
            fail_msg = "ACL drop counter was not incremented on iface {}. DUT ACL counter == {}; Sent pkts == {}".format(
                tx_dut_ports[ports_info["dut_iface"]], acl_drops, PKT_NUMBER
            )
            pytest.fail(fail_msg)
        if not COMBINED_ACL_DROP_COUNTER:
            for duthost in duthosts:
                ensure_no_l3_drops(duthost, asic_index, packets_count=PKT_NUMBER)
                ensure_no_l2_drops(duthost, asic_index, packets_count=PKT_NUMBER)
    elif discard_group == "NO_DROPS":
        for duthost in duthosts:
            ensure_no_l2_drops(duthost, asic_index, packets_count=PKT_NUMBER)
            ensure_no_l3_drops(duthost, asic_index, packets_count=PKT_NUMBER)
    else:
        pytest.fail("Incorrect 'discard_group' specified. Supported values: 'L2', 'L3', 'ACL' or 'NO_DROPS'")


def get_intf_mtu(duthost, intf, asic_index):
    # Get namespace from asic_index.
    namespace = duthost.get_namespace_from_asic_id(asic_index)

    CMD_PREFIX = NAMESPACE_PREFIX.format(namespace) if duthost.is_multi_asic else ''
    return int(duthost.shell(CMD_PREFIX + "/sbin/ifconfig {} | grep -i mtu | awk '{{print $NF}}'".format(intf))["stdout"])


@pytest.fixture
def mtu_config(duthosts):
    """ Fixture which prepare port MTU configuration for 'test_ip_pkt_with_exceeded_mtu' test case """
    class MTUConfig(object):
        iface = None
        mtu = None
        default_mtu = 9100

        @classmethod
        def set_mtu(cls, mtu, iface, asic_index):
            for duthost in duthosts:
                namespace = duthost.get_namespace_from_asic_id(asic_index) if duthost.is_multi_asic else ''
                cls.mtu = duthost.command("sonic-db-cli -n '{}' CONFIG_DB hget \"PORTCHANNEL|{}\" mtu".format(namespace, iface))["stdout"]
                if not cls.mtu:
                    cls.mtu = cls.default_mtu
                if "PortChannel" in iface:
                    duthost.command("sonic-db-cli -n '{}' CONFIG_DB hset \"PORTCHANNEL|{}\" mtu {}".format(namespace, iface, mtu))["stdout"]
                elif "Ethernet" in iface:
                    duthost.command("sonic-db-cli -n '{}' CONFIG_DB hset \"PORT|{}\" mtu {}".format(namespace, iface, mtu))["stdout"]
                else:
                    raise Exception("Unsupported interface parameter - {}".format(iface))
                cls.iface = iface
                check_mtu = lambda: get_intf_mtu(duthost, iface, asic_index) == mtu  # lgtm[py/loop-variable-capture]
                pytest_assert(wait_until(5, 1, check_mtu), "MTU on interface {} not updated".format(iface))
                cls.asic_index = asic_index

        @classmethod
        def restore_mtu(cls):
            for duthost in duthosts:
                if cls.iface:
                    namespace = duthost.get_namespace_from_asic_id(cls.asic_index) if duthost.is_multi_asic else ''
                    if "PortChannel" in cls.iface:
                        duthost.command("sonic-db-cli -n '{}' CONFIG_DB hset \"PORTCHANNEL|{}\" mtu {}".format(namespace, cls.iface, cls.mtu))["stdout"]
                    elif "Ethernet" in cls.iface:
                        duthost.command("sonic-db-cli -n '{}' CONFIG_DB hset \"PORT|{}\" mtu {}".format(namespace, cls.iface, cls.mtu))["stdout"]
                    else:
                        raise Exception("Trying to restore MTU on unsupported interface - {}".format(cls.iface))

    yield MTUConfig

    MTUConfig.restore_mtu()


def check_if_skip():
    if pytest.SKIP_COUNTERS_FOR_MLNX:
       pytest.SKIP_COUNTERS_FOR_MLNX = False
       pytest.skip("Currently not supported on Mellanox platform")


@pytest.fixture(scope='module')
def do_test(duthosts):
    def do_counters_test(discard_group, pkt, ptfadapter, ports_info, sniff_ports, tx_dut_ports=None,
                         comparable_pkt=None, skip_counter_check=False, drop_information=None):
        """
        Execute test - send packet, check that expected discard counters were incremented and packet was dropped
        @param discard_group: Supported 'discard_group' values: 'L2', 'L3', 'ACL', 'NO_DROPS'
        @param pkt: PTF composed packet, sent by test case
        @param ptfadapter: fixture
        @param duthost: fixture
        @param dut_iface: DUT interface name expected to receive packets from PTF
        @param sniff_ports: DUT ports to check that packets were not egressed from
        """
        check_if_skip()
        asic_index = ports_info["asic_index"]
        base_verification(discard_group, pkt, ptfadapter, duthosts, asic_index, ports_info, tx_dut_ports,
                          skip_counter_check=skip_counter_check, drop_information=drop_information)

        # Verify packets were not egresed the DUT
        if discard_group != "NO_DROPS":
            exp_pkt = expected_packet_mask(pkt)
            testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=sniff_ports)

    return do_counters_test


def test_reserved_dmac_drop(do_test, ptfadapter, duthosts, rand_one_dut_hostname, setup, fanouthost, pkt_fields, ports_info):
    """
    @summary: Verify that packet with reserved DMAC is dropped and L2 drop counter incremented
    @used_mac_address:
        01:80:C2:00:00:05 - reserved for future standardization
        01:80:C2:00:00:08 - provider Bridge group address
    """
    duthost = duthosts[rand_one_dut_hostname]
    if not fanouthost:
        pytest.skip("Test case requires explicit fanout support")

    reserved_mac_addr = ["01:80:C2:00:00:05", "01:80:C2:00:00:08"]
    for reserved_dmac in reserved_mac_addr:
        dst_mac = reserved_dmac

        if "mellanox" == duthost.facts["asic_type"]:
            pytest.skip("Currently not supported on Mellanox platform")
            dst_mac = "00:00:00:00:00:11"
            # Prepare openflow rule
            fanouthost.update_config(template_path=MELLANOX_MAC_UPDATE_SCRIPT, match_mac=dst_mac, set_mac=reserved_dmac, eth_field="eth_dst")

        log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], reserved_dmac, pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])
        pkt = testutils.simple_tcp_packet(
            eth_dst=dst_mac,  # DUT port
            eth_src=ports_info["src_mac"],
            ip_src=pkt_fields["ipv4_src"],  # PTF source
            ip_dst=pkt_fields["ipv4_dst"],  # VM source
            tcp_sport=pkt_fields["tcp_sport"],
            tcp_dport=pkt_fields["tcp_dport"]
        )

        do_test("L2", pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"])


def test_no_egress_drop_on_down_link(do_test, ptfadapter, setup, tx_dut_ports, pkt_fields, rif_port_down, ports_info):
    """
    @summary: Verify that packets on ingress port are not dropped when egress RIF link is down and check that drop counters not incremented
    """
    ip_dst = rif_port_down
    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], ip_dst, pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=ip_dst,
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )

    do_test("NO_DROPS", pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


def test_src_ip_link_local(do_test, ptfadapter, duthosts, rand_one_dut_hostname, setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Verify that packet with link-local address "169.254.0.0/16" is dropped and L3 drop counter incremented
    """
    duthost = duthosts[rand_one_dut_hostname]
    asic_type = duthost.facts["asic_type"]
    pytest_require("broadcom" not in asic_type, "BRCM does not drop SIP link local packets")

    link_local_ip = "169.254.10.125"

    pkt_params = {
        "eth_dst": ports_info["dst_mac"],  # DUT port
        "eth_src": ports_info["src_mac"],  # PTF port
        "tcp_sport": pkt_fields["tcp_sport"],
        "tcp_dport": pkt_fields["tcp_dport"]
    }

    pkt_params["ip_src"] = link_local_ip
    pkt_params["ip_dst"] = pkt_fields["ipv4_dst"]  # VM source

    pkt = testutils.simple_tcp_packet(**pkt_params)

    logger.info(pkt_params)
    do_test("L3", pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


def test_ip_pkt_with_exceeded_mtu(do_test, ptfadapter, setup, tx_dut_ports, pkt_fields, mtu_config, ports_info):
    """
    @summary: Verify that IP packet with exceeded MTU is dropped and L3 drop counter incremented
    """
    global L2_COL_KEY
    if  "vlan" in tx_dut_ports[ports_info["dut_iface"]].lower():
        pytest.skip("Test case is not supported on VLAN interface")

    tmp_port_mtu = 1500

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"],
                    pkt_fields["ipv4_src"])

    # Get the asic_index
    asic_index = ports_info["asic_index"]

    # Set temporal MTU. This will be restored by 'mtu' fixture
    mtu_config.set_mtu(tmp_port_mtu, tx_dut_ports[ports_info["dut_iface"]], asic_index)

    pkt = testutils.simple_tcp_packet(
        pktlen=9100,
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],  # VM IP address
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
    )
    L2_COL_KEY = RX_ERR
    try:
        do_test("L2", pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"])
    finally:
        L2_COL_KEY = RX_DRP
