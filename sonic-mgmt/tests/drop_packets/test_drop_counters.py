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
from tests.common.helpers.drop_counters.drop_counters import verify_drop_counters,\
    ensure_no_l3_drops, ensure_no_l2_drops
from .drop_packets import L2_COL_KEY, L3_COL_KEY, RX_ERR, RX_DRP, ACL_COUNTERS_UPDATE_INTERVAL,\
    MELLANOX_MAC_UPDATE_SCRIPT, expected_packet_mask, log_pkt_params, setup, fanouthost, pkt_fields,\
    send_packets, ports_info, tx_dut_ports, rif_port_down, sai_acl_drop_adj_enabled, acl_ingress, \
    acl_egress, configure_copp_drop_for_ttl_error, test_equal_smac_dmac_drop, test_multicast_smac_drop, \
    test_not_expected_vlan_tag_drop, test_dst_ip_is_loopback_addr, test_src_ip_is_loopback_addr, \
    test_dst_ip_absent, test_src_ip_is_multicast_addr, test_src_ip_is_class_e, test_ip_is_zero_addr, \
    test_dst_ip_link_local, test_loopback_filter, test_ip_pkt_with_expired_ttl, test_broken_ip_header, \
    test_absent_ip_header, test_unicast_ip_incorrect_eth_dst, test_non_routable_igmp_pkts, test_acl_drop, \
    test_acl_egress_drop  # noqa F401
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.fixtures.conn_graph_facts import enum_fanout_graph_facts  # noqa F401

pytestmark = [
    pytest.mark.topology("any")
]

logger = logging.getLogger(__name__)

PTF_PORT_MAPPING_MODE = 'use_orig_interface'

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
    for duthost in duthosts.frontend_nodes:
        duthost.shell_cmds(cmds=cmd_list)

        namespace_list = duthost.get_asic_namespace_list() if duthost.is_multi_asic else ['']
        for namespace in namespace_list:
            cmd_get_cnt_status = "sonic-db-cli -n '{}' CONFIG_DB HGET \"FLEX_COUNTER_TABLE|{}\" FLEX_COUNTER_STATUS"
            previous_cnt_status[duthost][namespace] = {
                item: duthost.command(
                    cmd_get_cnt_status.format(namespace, item.upper()))["stdout"] for item in ["port", "rif"]}

            ns_cmd_list = []
            CMD_PREFIX = NAMESPACE_PREFIX.format(namespace) if duthost.is_multi_asic else ''
            for cmd in cmd_list_per_ns:
                ns_cmd_list.append(CMD_PREFIX + cmd)
            duthost.shell_cmds(cmds=ns_cmd_list)

    yield
    for duthost in duthosts.frontend_nodes:
        namespace_list = duthost.get_asic_namespace_list() if duthost.is_multi_asic else ['']
        for namespace in namespace_list:
            for port, status in list(previous_cnt_status[duthost][namespace].items()):
                if status == "disable":
                    logger.info("Restoring counter '{}' state to disable".format(port))
                    CMD_PREFIX = NAMESPACE_PREFIX.format(namespace) if duthost.is_multi_asic else ''
                    duthost.command(CMD_PREFIX + "counterpoll {} disable".format(port))


@pytest.fixture(scope='module', autouse=True)
def parse_combined_counters(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
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


@pytest.fixture(scope='module', autouse=True)
def handle_backend_acl(duthost, tbinfo):
    """
    Cleanup/Recreate all the existing DATAACL rules
    """
    if "t0-backend" in tbinfo["topo"]["name"]:
        duthost.shell('acl-loader delete DATAACL')

    yield

    if "t0-backend" in tbinfo["topo"]["name"]:
        duthost.shell('systemctl restart backend-acl')


def base_verification(discard_group, pkt, ptfadapter, duthosts, asic_index, ports_info,   # noqa F811
                      tx_dut_ports=None, skip_counter_check=False, drop_information=None):  # noqa F811
    """
    Base test function for verification of L2 or L3 packet drops. Verification type depends on 'discard_group' value.
    Supported 'discard_group' values: 'L2', 'L3', 'ACL', 'NO_DROPS'
    """
    # Clear SONiC counters all the asic on all the duts
    for duthost in duthosts.frontend_nodes:
        duthost.command("sonic-clear counters")
        namespace_list = duthost.get_asic_namespace_list() if duthost.is_multi_asic else ['']
        for namespace in namespace_list:
            # Clear RIF counters on all namespaces
            CMD_PREFIX = NAMESPACE_PREFIX.format(namespace) if duthost.is_multi_asic else ''
            duthost.command(CMD_PREFIX+"sonic-clear rifcounters")

    send_packets(pkt, ptfadapter, ports_info["ptf_tx_port_id"], PKT_NUMBER)

    # Some test cases will not increase the drop counter consistently on certain platforms
    if skip_counter_check:
        logger.info("Skipping counter check")
        return None

    if discard_group == "L2":
        verify_drop_counters(duthosts, asic_index, ports_info["dut_iface"],
                             GET_L2_COUNTERS, L2_COL_KEY, packets_count=PKT_NUMBER)
        for duthost in duthosts.frontend_nodes:
            ensure_no_l3_drops(duthost, packets_count=PKT_NUMBER)
    elif discard_group == "L3":
        if COMBINED_L2L3_DROP_COUNTER:
            verify_drop_counters(duthosts, asic_index, ports_info["dut_iface"],
                                 GET_L2_COUNTERS, L2_COL_KEY, packets_count=PKT_NUMBER)
            for duthost in duthosts.frontend_nodes:
                ensure_no_l3_drops(duthost, packets_count=PKT_NUMBER)
        else:
            if not tx_dut_ports:
                pytest.fail("No L3 interface specified")

            verify_drop_counters(duthosts, asic_index, tx_dut_ports[ports_info["dut_iface"]],
                                 GET_L3_COUNTERS, L3_COL_KEY, packets_count=PKT_NUMBER)
            for duthost in duthosts.frontend_nodes:
                ensure_no_l2_drops(duthost, packets_count=PKT_NUMBER)
    elif discard_group == "ACL":
        if not tx_dut_ports:
            pytest.fail("No L3 interface specified")

        time.sleep(ACL_COUNTERS_UPDATE_INTERVAL)
        acl_drops = 0
        for duthost in duthosts.frontend_nodes:
            for sonic_host_or_asic_inst in duthost.get_sonic_host_and_frontend_asic_instance():
                namespace = sonic_host_or_asic_inst.namespace if hasattr(sonic_host_or_asic_inst,
                                                                         'namespace') else DEFAULT_NAMESPACE
                if duthost.sonichost.is_multi_asic and namespace == DEFAULT_NAMESPACE:
                    continue
                acl_drops += duthost.acl_facts(namespace=namespace)["ansible_facts"]["ansible_acl_facts"][
                    drop_information if drop_information else "DATAACL"]["rules"]["RULE_1"]["packets_count"]
        if acl_drops != PKT_NUMBER:
            fail_msg = "ACL drop counter was not incremented on iface {}. DUT ACL counter == {}; Sent pkts == {}"\
                .format(tx_dut_ports[ports_info["dut_iface"]], acl_drops, PKT_NUMBER)
            pytest.fail(fail_msg)
        if not COMBINED_ACL_DROP_COUNTER:
            for duthost in duthosts.frontend_nodes:
                ensure_no_l3_drops(duthost, packets_count=PKT_NUMBER)
                ensure_no_l2_drops(duthost, packets_count=PKT_NUMBER)
    elif discard_group == "NO_DROPS":
        for duthost in duthosts.frontend_nodes:
            ensure_no_l2_drops(duthost, packets_count=PKT_NUMBER)
            ensure_no_l3_drops(duthost, packets_count=PKT_NUMBER)
    else:
        pytest.fail("Incorrect 'discard_group' specified. Supported values: 'L2', 'L3', 'ACL' or 'NO_DROPS'")


def get_intf_mtu(duthost, intf, asic_index):
    # Get namespace from asic_index.
    namespace = duthost.get_namespace_from_asic_id(asic_index)

    CMD_PREFIX = NAMESPACE_PREFIX.format(namespace) if duthost.is_multi_asic else ''
    return int(duthost.shell(
        CMD_PREFIX + "/sbin/ifconfig {} | grep -i mtu | awk '{{print $NF}}'".format(intf))["stdout"])


@pytest.fixture
def mtu_config(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """ Fixture which prepare port MTU configuration for 'test_ip_pkt_with_exceeded_mtu' test case """
    class MTUConfig(object):
        iface = None
        mtu = None
        default_mtu = 9100
        key = None
        asic_index = None

        @classmethod
        def set_mtu(cls, mtu, iface, asic_index):
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
            namespace = duthost.get_namespace_from_asic_id(asic_index) if duthost.is_multi_asic else ''
            if "PortChannel" in iface:
                cls.key = "PORTCHANNEL"
            elif "Ethernet" in iface:
                cls.key = "PORT"
            else:
                raise Exception("Unsupported interface parameter - {}".format(iface))

            cls.mtu = duthost.command(
                "sonic-db-cli -n '{}' CONFIG_DB hget \"{}|{}\" mtu".format(
                    namespace, cls.key, iface
                )
            )["stdout"]

            if not cls.mtu:
                cls.mtu = cls.default_mtu

            duthost.command(
                "sonic-db-cli -n '{}' CONFIG_DB hset \"{}|{}\" mtu {}".format(
                    namespace, cls.key, iface, mtu
                )
            )["stdout"]

            cls.asic_index = asic_index
            cls.iface = iface

            def check_mtu():
                return get_intf_mtu(duthost, iface, asic_index) == mtu

            pytest_assert(
                wait_until(5, 1, 0, check_mtu),
                "MTU on interface {} not updated".format(iface)
            )

        @classmethod
        def restore_mtu(cls):
            duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
            namespace = duthost.get_namespace_from_asic_id(
                cls.asic_index
            ) if duthost.is_multi_asic else ''
            duthost.command(
                "sonic-db-cli -n '{}' CONFIG_DB hset \"{}|{}\" mtu {}".format(
                    namespace, cls.key, cls.iface, cls.mtu
                )
            )["stdout"]

    yield MTUConfig

    MTUConfig.restore_mtu()


def check_if_skip():
    if pytest.SKIP_COUNTERS_FOR_MLNX:
        pytest.SKIP_COUNTERS_FOR_MLNX = False
        pytest.skip("Currently not supported on Mellanox platform")


@pytest.fixture(scope='module')
def do_test(duthosts):
    def do_counters_test(discard_group, pkt, ptfadapter, ports_info, sniff_ports, tx_dut_ports=None,    # noqa F811
                         comparable_pkt=None, skip_counter_check=False, drop_information=None, ip_ver='ipv4'):
        """
        Execute test - send packet, check that expected discard counters were incremented and packet was dropped
        @param discard_group: Supported 'discard_group' values: 'L2', 'L3', 'ACL', 'NO_DROPS'
        @param pkt: PTF composed packet, sent by test case
        @param ptfadapter: fixture
        @param duthost: fixture
        @param dut_iface: DUT interface name expected to receive packets from PTF
        @param sniff_ports: DUT ports to check that packets were not egressed from
        @param ip_ver: A string, ipv4 or ipv6
        """
        check_if_skip()
        asic_index = ports_info["asic_index"]
        base_verification(discard_group, pkt, ptfadapter, duthosts, asic_index, ports_info, tx_dut_ports,
                          skip_counter_check=skip_counter_check, drop_information=drop_information)

        # Verify packets were not egresed the DUT
        if discard_group != "NO_DROPS":
            exp_pkt = expected_packet_mask(pkt, ip_ver=ip_ver)
            testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=sniff_ports)

    return do_counters_test


def test_reserved_dmac_drop(do_test, ptfadapter, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                            setup, fanouthost, pkt_fields, ports_info):  # noqa F811
    """
    @summary: Verify that packet with reserved DMAC is dropped and L2 drop counter incremented
    @used_mac_address:
        01:80:C2:00:00:05 - reserved for future standardization
        01:80:C2:00:00:08 - provider Bridge group address
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    if not fanouthost:
        pytest.skip("Test case requires explicit fanout support")

    reserved_mac_addr = ["01:80:C2:00:00:05", "01:80:C2:00:00:08"]
    for reserved_dmac in reserved_mac_addr:
        dst_mac = reserved_dmac

        if "mellanox" == duthost.facts["asic_type"]:
            pytest.skip("Currently not supported on Mellanox platform")
            dst_mac = "00:00:00:00:00:11"
            # Prepare openflow rule
            fanouthost.update_config(template_path=MELLANOX_MAC_UPDATE_SCRIPT, match_mac=dst_mac,
                                     set_mac=reserved_dmac, eth_field="eth_dst")

        log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], reserved_dmac,
                       pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])
        pkt = testutils.simple_tcp_packet(
            eth_dst=dst_mac,  # DUT port
            eth_src=ports_info["src_mac"],
            ip_src=pkt_fields["ipv4_src"],  # PTF source
            ip_dst=pkt_fields["ipv4_dst"],  # VM source
            tcp_sport=pkt_fields["tcp_sport"],
            tcp_dport=pkt_fields["tcp_dport"]
        )

        group = "L2"
        do_test(group, pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"])


def test_no_egress_drop_on_down_link(do_test, ptfadapter, setup, tx_dut_ports, pkt_fields, rif_port_down, ports_info):  # noqa F811
    """
    @summary: Verify that packets on ingress port are not dropped
              when egress RIF link is down and check that drop counters not incremented
    """
    ip_dst = rif_port_down
    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"],
                   ports_info["src_mac"], ip_dst, pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=ip_dst,
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )

    do_test("NO_DROPS", pkt, ptfadapter, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


def test_src_ip_link_local(do_test, ptfadapter, duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                           setup, tx_dut_ports, pkt_fields, ports_info):  # noqa F811
    """
    @summary: Verify that packet with link-local address "169.254.0.0/16" is dropped and L3 drop counter incremented
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
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


def test_ip_pkt_with_exceeded_mtu(do_test, ptfadapter, setup, tx_dut_ports, pkt_fields, mtu_config, ports_info):  # noqa F811
    """
    @summary: Verify that IP packet with exceeded MTU is dropped and L3 drop counter incremented
    """
    global L2_COL_KEY
    if "vlan" in tx_dut_ports[ports_info["dut_iface"]].lower():
        pytest.skip("Test case is not supported on VLAN interface")

    tmp_port_mtu = 1500

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"],
                   pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

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
