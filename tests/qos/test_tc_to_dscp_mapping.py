"""
Test cases for testing TC to DSCP mapping for packets in SONiC.
"""

import json
import logging
import random
import time
from enum import StrEnum
from typing import Any

import ptf.packet as scapy
import ptf.testutils as testutils
import pytest
from ptf import mask
from scapy.all import IP, Ether
from scapy.layers.l2 import Ether
from tabulate import tabulate

from tests.common.devices.multi_asic import MultiAsicSonicHost
from tests.common.dualtor.mux_simulator_control import (
    toggle_all_simulator_ports_to_rand_selected_tor,
)  # noqa F401
from tests.common.fixtures.duthost_utils import dut_qos_maps_module  # noqa F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import check_config_table_presence
from tests.common.helpers.ptf_tests_helper import (
    apply_dscp_cfg_setup,
    apply_dscp_cfg_teardown,
    downstream_links,
    get_dut_pair_port_from_ptf_port,
    get_stream_ptf_ports,
    select_random_link,
    upstream_links,
)  # noqa F401
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.plugins.ptfadapter.ptfadapter import PtfTestAdapter
from tests.common.utilities import (
    find_egress_queue,
    get_dscp_to_queue_value,
    get_egress_queue_pkt_count_all_prio,
    get_ipv4_loopback_ip,
    wait_until,
)

logger = logging.getLogger(__name__)

pytestmark = [pytest.mark.topology("t0", "t1")]

DEFAULT_ECN = 1
DEFAULT_PKT_COUNT = 5
DUMMY_SRC_IP = "8.8.8.8"
output_table = []
packet_egressed_success = False
CONFIG_DB_JSON_PATH: str = "/etc/sonic/config_db.json"
TC_TO_DSCP_MAP: dict[str, dict[str, str]] = {
    "AZURE": {
        "0": "1",
        "1": "2",
        "2": "2",
        "3": "3",
        "4": "4",
        "5": "6",
        "6": "7",
        "7": "8",
    }
}


class TestMode(StrEnum):
    """
    States which kind of test is being run.

    VALID_TABLE_VALID_MAP: a valid TC_TO_DSCP map is present with the egress
                           interface having a valid mapping.
    VALID_TABLE_MISSING_MAP: a valid TC_TO_DSCP map is present but the egress
                             interface is missing a valid mapping.
    MISSING_TABLE: the TC_TO_DSCP map is missing.
    """

    VALID_TABLE_VALID_MAP = "valid_table_valid_map"
    VALID_TABLE_MISSING_MAP = "valid_table_missing_map"
    MISSING_TABLE = "missing_table"


@pytest.fixture
def apply_tc_to_dscp_map_config(
    duthost,
    upstream_links: dict,  # noqa F811
):
    """
    Apply the TC_TO_DSCP map configuration to the DUT.

    Args:
        duthost: The DUT host object.
    """
    tc_to_dscp_map_present = check_config_table_presence(
        duthost, table_name="TC_TO_DSCP_MAP"
    )
    if tc_to_dscp_map_present:
        logger.info("TC_TO_DSCP_MAP already present in config db. Skipping setup.")
        yield
    else:
        config_db_json = duthost.shell(f"cat {CONFIG_DB_JSON_PATH}")["stdout"]
        config_db_dict: dict = json.loads(config_db_json)
        config_db_dict["TC_TO_DSCP_MAP"] = TC_TO_DSCP_MAP
        port_qos_map: dict = config_db_dict.get("PORT_QOS_MAP")
        pytest_assert(port_qos_map, "PORT_QOS_MAP missing from duthost config.")

        for upstream_intf in upstream_links.keys():
            # Set TC_TO_DSCP map attribute for egress intfs
            config_db_dict["PORT_QOS_MAP"][upstream_intf]["tc_to_dscp_map"] = "AZURE"

        backup_file = "/etc/sonic/config_db_backup.json"
        duthost.shell(f"cp /etc/sonic/config_db.json {backup_file}")
        duthost.copy(
            content=json.dumps(config_db_dict, indent=4), dest=CONFIG_DB_JSON_PATH
        )
        logger.info("Running QoS Reload on switch")
        duthost.shell("sudo config qos reload -y")
        wait_critical_processes(duthost)

        yield

    # Reset back to original config
    if tc_to_dscp_map_present:
        logger.info("TC_TO_DSCP_MAP already present in config db. Skipping teardown.")
        return None
    duthost.shell(f"cp {backup_file} /etc/sonic/config_db.json")
    logger.info("Running QoS Reload on switch")
    duthost.shell("sudo config qos reload -y")
    wait_critical_processes(duthost)


def create_ip_packet(
    src_mac: str,
    dst_mac: str,
    src_pkt_ip: str,
    dst_pkt_ip: str,
    dscp: int,
    exp_dscp: int,
):
    """
    Generate IPV4 IP packets.

    Args:
        src_mac: source MAC address
        dst_mac: destination MAC address
        src_pkt_ip: source IP address
        dst_pkt_ip: destination IP address
        dscp: DSCP value
        exp_dscp: expected DSCP value of egressed packet

    Returns:
        IP packet, expected packet
    """

    pkt = testutils.simple_ipv4ip_packet(
        eth_src=src_mac,
        eth_dst=dst_mac,
        ip_src=src_pkt_ip,
        ip_dst=dst_pkt_ip,
        ip_dscp=dscp,
        ip_ecn=DEFAULT_ECN,
    )

    exp_pkt = testutils.simple_tcp_packet(
        ip_src=src_pkt_ip,
        ip_dst=dst_pkt_ip,
        ip_dscp=exp_dscp,
        ip_ecn=DEFAULT_ECN,
    )

    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(Ether, "src")
    exp_pkt.set_do_not_care_scapy(Ether, "dst")
    exp_pkt.set_do_not_care_scapy(IP, "id")
    exp_pkt.set_do_not_care_scapy(IP, "ttl")
    exp_pkt.set_do_not_care_scapy(IP, "chksum")

    return pkt, exp_pkt


def send_and_verify_traffic(
    ptfadapter: PtfTestAdapter,
    pkt: Ether,
    exp_pkt: mask.Mask,
    ptf_src_port_id: str,
    ptf_dst_port_id: str,
):
    """
    Send traffic and verify that traffic was received

    Args:
        ptfadapter: PTF adapter
        pkt: Packet that should be sent
        exp_pkt: Expected packet
        ptf_src_port_id: Source port of ptf
        ptf_dst_port_id: Destination port of ptf
    """

    ptfadapter.dataplane.flush()
    logger.info(f"Send packet(s) from ptf port {ptf_src_port_id} upstream")
    testutils.send(ptfadapter, ptf_src_port_id, pkt, count=DEFAULT_PKT_COUNT)

    try:
        _ = testutils.verify_packets(ptfadapter, exp_pkt, ports=[ptf_dst_port_id])
        logger.info(f"Received packet(s) on port {ptf_dst_port_id}")
        global packet_egressed_success
        packet_egressed_success = True
        return ptf_dst_port_id

    except AssertionError as detail:
        if "Did not receive expected packet" in str(detail):
            logger.error(
                f"Expected packet(s) was not received on upstream ptf port {ptf_dst_port_id}"
            )


def validate_qos_map_on_port(intf: str, qos_map: str, config_db: dict) -> bool:
    """
    Checks if a specific qos map ex. dscp_to_tc_map is present for
    a specific interface on the switch. Returns True if present,
    False otherwise.

    Here config_db is the dict version of the config_db.json file
    found in /etc/sonic/config_db.json
    """
    global_port_qos_map = config_db.get("PORT_QOS_MAP", {})
    intf_port_qos_map = global_port_qos_map.get(intf, {})
    return qos_map in intf_port_qos_map


def ingress_to_egress_dscp_conversion(
    ingress_dscp: int, dscp_to_tc_map: dict, tc_to_dscp_map: dict
) -> int:
    if not tc_to_dscp_map:
        return ingress_dscp

    if "AZURE" in dscp_to_tc_map:
        dscp_to_tc_map = dscp_to_tc_map["AZURE"]
    if "AZURE" in tc_to_dscp_map:
        tc_to_dscp_map = tc_to_dscp_map["AZURE"]

    tc = dscp_to_tc_map.get(str(ingress_dscp))
    if not tc:
        raise ValueError(
            f"Ingress DSCP value {ingress_dscp} has no matching traffic class."
        )
    egress_dscp = tc_to_dscp_map.get(tc)
    if not egress_dscp:
        return ingress_dscp

    return int(egress_dscp)


class TestQoSSai_TC_TO_DSCP_Mapping_Base:
    """
    Test class for TC to DSCP Mapping for IP packets.
    """

    def _setup_test_params(
        self,
        duthost,
        downstream_links: dict,  # noqa F811
        upstream_links: dict,  # noqa F811
        test_mode: TestMode,
    ):
        """
        Set up test parameters for the TC to DSCP mapping packets.

        Args:
            duthost (fixture): DUT fixture
            downstream_links (fixture): Dictionary of downstream links info for DUT
            upstream_links (fixture): Dictionary of upstream links info for DUT
            test_mode (str): Type of test i.e. correct mapping, invalid mapping, missing mapping, etc
        """
        test_params: dict[str, Any] = {}
        downlink = select_random_link(downstream_links)
        router_mac = duthost.facts["router_mac"]
        egress_intf = None

        # Read the current config_db.json
        config_db_json = duthost.shell("cat /etc/sonic/config_db.json")["stdout"]
        config_db_dict = json.loads(config_db_json)

        tc_to_dscp_map_present = check_config_table_presence(
            duthost, table_name="TC_TO_DSCP_MAP"
        )
        if tc_to_dscp_map_present and test_mode == TestMode.VALID_TABLE_VALID_MAP:
            # Find the first intf with a tc_to_dscp mapping
            for intf in upstream_links.keys():
                intf_tc_to_dscp_map_present = validate_qos_map_on_port(
                    intf,
                    "tc_to_dscp_map",
                    config_db_dict,
                )
                if intf_tc_to_dscp_map_present:
                    egress_intf = intf
                    break
        else:
            # Pick a random uplink intf
            egress_intf = random.choice(list(upstream_links.keys()))

        egress_intf_neigh_info: dict = upstream_links.get(egress_intf, {})
        dst_ip = egress_intf_neigh_info.get("peer_ipv4_addr")
        if not dst_ip:
            raise ValueError(
                f"Egress port {egress_intf} does not have peer ipv4 address configured in {egress_intf_neigh_info=}"
            )

        pytest_assert(
            downlink.get("ptf_port_id") is not None, "No downlink ptf port found"
        )
        pytest_assert(
            egress_intf_neigh_info.get("ptf_port_id") is not None,
            "No uplink ptf port found",
        )
        pytest_assert(router_mac is not None, "No router MAC found")

        test_params["ptf_downlink_port"] = downlink.get("ptf_port_id")
        test_params["ptf_uplink_port"] = egress_intf_neigh_info.get("ptf_port_id")
        test_params["egress_intf"] = egress_intf
        test_params["src_ip"] = DUMMY_SRC_IP
        test_params["dst_ip"] = dst_ip
        test_params["router_mac"] = router_mac

        return test_params

    def _run_test(
        self,
        ptfadapter: PtfTestAdapter,
        duthost: MultiAsicSonicHost,
        tbinfo: dict,
        test_params: dict,
        dut_qos_maps_module: dict,  # noqa F811
        test_mode: TestMode,
    ):  # noqa F811
        """
        Test QoS SAI TC to DSCP mapping for IP packets
        Args:
            ptfadapter (PtfAdapter): PTF adapter
            duthost (AnsibleHost): The DUT host
            tbinfo (fixture): Testbed info
            test_params (dict): Dictionary of test parameters - initialized in _setup_test_params()
            dut_qos_maps_module (Fixture): A module level fixture, return qos maps on DUT host
        Returns:
            None
        Raises:
            RunAnsibleModuleFail if ptf test fails
        """
        asic_type = duthost.facts["asic_type"]
        router_mac = test_params["router_mac"]
        ptf_src_port_id = test_params["ptf_downlink_port"]
        ptf_dst_port_id = test_params["ptf_uplink_port"]
        dst_pkt_ip = test_params["outer_dst_ip"]
        src_pkt_ip = DUMMY_SRC_IP
        ptf_src_mac = ptfadapter.dataplane.get_mac(0, ptf_src_port_id)
        failed_once = False

        # Log packet information
        logger.info("Pkt Src IP: {}".format(src_pkt_ip))
        logger.info("Pkt Dst IP: {}".format(dst_pkt_ip))
        logger.info("Pkt Src MAC: {}".format(ptf_src_mac))
        logger.info("Pkt Dst MAC: {}".format(router_mac))

        pytest_assert(
            dut_qos_maps_module.get("dscp_to_tc_map"),
            "No DSCP_TO_TC map found on DUT",
        )

        for ingress_dscp in range(0, 64):
            if test_mode == TestMode.VALID_TABLE_VALID_MAP:
                exp_dscp = ingress_to_egress_dscp_conversion(
                    ingress_dscp=ingress_dscp,
                    dscp_to_tc_map=dut_qos_maps_module.get("dscp_to_tc_map"),
                    tc_to_dscp_map=TC_TO_DSCP_MAP,
                )
            else:
                exp_dscp = ingress_dscp

            pkt, exp_pkt = create_ip_packet(
                src_mac=ptf_src_mac,
                dst_mac=router_mac,
                src_pkt_ip=src_pkt_ip,
                dst_pkt_ip=dst_pkt_ip,
                dscp=ingress_dscp,
                exp_dscp=exp_dscp,
            )

            global output_table
            global packet_egressed_success

            # Clear queue counters
            duthost.command("sonic-clear queuecounters")
            time.sleep(2)

            try:
                send_and_verify_traffic(
                    ptfadapter=ptfadapter,
                    pkt=pkt,
                    exp_pkt=exp_pkt,
                    ptf_src_port_id=ptf_src_port_id,
                    ptf_dst_port_ids=ptf_dst_port_id,
                )
                if packet_egressed_success:
                    output_table.append(
                        [ingress_dscp, exp_dscp, "SUCCESS", "", test_mode]
                    )
                else:
                    failed_once = True
                    output_table.append(
                        [
                            ingress_dscp,
                            exp_dscp,
                            "FAILED",
                            "Invalid egress DSCP",
                            test_mode,
                        ]
                    )
            except ConnectionError as e:
                # Sending large number of packets can cause socket buffer to be full and leads connection timeout.
                logger.error(f"Try reducing DEFAULT_PKT_COUNT value: {e}")
                failed_once = True
                output_table.append(
                    [ingress_dscp, exp_dscp, "FAILED", "ConnectionError", test_mode]
                )

            # Reset packet egress status
            packet_egressed_success = False

        output_table.insert(
            0,
            ["Ingress DSCP", "Expected Egress DSCP", "Status", "Remarks", "Test Mode"],
        )
        # Log the table results
        logger.info(
            "QoS TC to DSCP Mapping Test Results:\n"
            + tabulate(output_table, headers="firstrow")
        )
        # Clear the output_table (for next test functions).
        output_table = []

        pytest_assert(not failed_once, "FAIL: Test failed. See table details.")

    def test_tc_to_dscp_map_valid_table_valid_map(
        self,
        ptfadapter,
        rand_selected_dut,
        toggle_all_simulator_ports_to_rand_selected_tor,  # noqa F811
        setup_standby_ports_on_rand_unselected_tor,  # noqa F811
        tbinfo,
        downstream_links,  # noqa F811
        upstream_links,  # noqa F811
        dut_qos_maps_module,  # noqa F811
        apply_tc_to_dscp_map_config,  # noqa F811
    ):
        """
        Test TC to DSCP mapping for TC TO DSCP mapping on egress is correct
        when table and mapping are both present so packet will egress with
        newly mapped DSCP.
        """
        duthost = rand_selected_dut
        test_mode = TestMode.VALID_TABLE_VALID_MAP
        test_params = self._setup_test_params(
            duthost, downstream_links, upstream_links, test_mode
        )
        self._run_test(
            ptfadapter,
            duthost,
            tbinfo,
            test_params,
            dut_qos_maps_module,
            test_mode,
        )

    def test_tc_to_dscp_map_missing_table(
        self,
        ptfadapter,
        rand_selected_dut,
        toggle_all_simulator_ports_to_rand_selected_tor,  # noqa F811
        setup_standby_ports_on_rand_unselected_tor,  # noqa F811
        tbinfo,
        downstream_links,  # noqa F811
        upstream_links,  # noqa F811
        dut_qos_maps_module,  # noqa F811
    ):
        """
        Test TC to DSCP mapping for missing TC TO DSCP mapping
        so packet will egress with ingress DSCP value.
        """
        duthost = rand_selected_dut
        test_mode = TestMode.VALID_TABLE_VALID_MAP
        test_params = self._setup_test_params(
            duthost, downstream_links, upstream_links, test_mode
        )
        self._run_test(
            ptfadapter,
            duthost,
            tbinfo,
            test_params,
            dut_qos_maps_module,
            test_mode,
        )
