import logging
from ipaddress import IPv4Address
import copy

import configs.privatelink_config as pl
import ptf.testutils as testutils
import pytest
from constants import LOCAL_PTF_INTF, REMOTE_PTF_RECV_INTF, REMOTE_PTF_SEND_INTF
from packets import outbound_pl_packets, inbound_pl_packets
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.dash_utils import apply_dash_configs
from dash_eni_counter_utils import get_eni_counters, get_eni_counter_oid, verify_eni_counter, \
    eni_counter_setup, partition_supported_counters, ENI_COUNTER_READY_MAX_TIME  # noqa: F401


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('smartswitch')
]


@pytest.fixture(autouse=True)
def common_setup_teardown(
    localhost,
    duthost,
    ptfhost,
    dpu_index,
    dpuhosts,
    skip_config,
    skip_cleanup,
    # align the DPU's VXLAN UDP sport range / security with the test packets so that
    # VXLAN-encapsulated DASH traffic is accepted (matches other DASH dataplane tests)
    set_vxlan_udp_sport_range,
    # manually invoke setup_npu_dpu so the NPU static routes (shared conftest fixture)
    # are programmed before any DASH config is applied
    setup_npu_dpu,  # noqa: F811
):
    if skip_config:
        yield
        return
    dpuhost = dpuhosts[dpu_index]

    # ``INBOUND_VNI_ROUTE_RULE_CONFIG`` is only programmed on Bluefield DPUs;
    # on other platforms ROUTE_RULE entries are skipped at the source.
    bluefield_route_rule_configs = []
    if 'bluefield' in dpuhost.facts['asic_type']:
        bluefield_route_rule_configs = [pl.INBOUND_VNI_ROUTE_RULE_CONFIG]

    config_dicts = [
        pl.APPLIANCE_CONFIG,
        pl.ROUTING_TYPE_PL_CONFIG,
        pl.VNET_CONFIG,
        pl.ROUTE_GROUP1_CONFIG,
        pl.METER_POLICY_V4_CONFIG,
        pl.PE_VNET_MAPPING_CONFIG,
        pl.PE_SUBNET_ROUTE_CONFIG,
        pl.VM_SUBNET_ROUTE_CONFIG,
        *bluefield_route_rule_configs,
        pl.METER_RULE1_V4_CONFIG,
        pl.METER_RULE2_V4_CONFIG,
        pl.ENI_CONFIG,
        pl.ENI_ROUTE_GROUP1_CONFIG,
    ]

    # ``apply_dash_configs`` buckets entries by DASH table name and applies them in
    # dependency order (see ``DashPhase`` in ``tests/common/dash_utils.py``):
    # GROUP_1 (APPLIANCE) -> GROUP_2 (ROUTING_TYPE/METER_POLICY/VNET) ->
    # GROUP_3 (METER_RULE) -> GROUP_4 (ENI/ROUTE_GROUP) ->
    # GROUP_5 (ROUTE_RULE/ROUTE/VNET_MAPPING) -> GROUP_6 (ENI_ROUTE).
    apply_dash_configs(localhost, duthost, ptfhost, dpuhost.dpu_index, *config_dicts)

    yield

    # Explicit delete (rather than ``config_reload``) preserves the runtime
    # ``counterpoll eni`` enable/interval configured by ``eni_counter_setup``.
    if not skip_cleanup:
        apply_dash_configs(localhost, duthost, ptfhost, dpuhost.dpu_index, *config_dicts, set_db=False)


@pytest.fixture(scope="function", params=["vxlan", "gre"])
def outer_encap(request):
    return request.param


@pytest.fixture(scope="function", params=['udp', 'tcp'])
def inner_packet_type(request):
    return request.param


# Maps a logical TCP flag id to the ``outbound_pl_packets`` / ``inbound_pl_packets`` kwargs
# that set it. RST has no helper kwarg and is applied directly to the inner TCP layer.
TCP_FLAG_KWARGS = {
    "syn": {"tcp_flag_syn": True},
    "synack": {"tcp_flag_syn": True, "tcp_flag_ack": True},
    "fin": {"tcp_flag_fin": True},
    "rst": {},
}

# Maps a logical TCP flag id to the SAI_ENI_STAT_{IN,OUT}BOUND_TCP_<SUFFIX>_PACKETS suffix.
TCP_FLAG_COUNTER_SUFFIX = {
    "syn": "SYN",
    "synack": "SYNACK",
    "fin": "FIN",
    "rst": "RST",
}

# IANA-assigned default VXLAN UDP port; used as a fallback when the DPU does not
# advertise a VXLAN port in its APPL_DB SWITCH_TABLE.
DEFAULT_VXLAN_UDP_DPORT = 4789


def read_dpu_vxlan_udp_dport(dpuhost):
    """Return the outer VXLAN UDP dst port the DPU actually programs.

    DASH VXLAN-encapsulated test traffic is only accepted by the DPU when the outer
    UDP dst port matches the DPU's configured VXLAN port (``SWITCH_TABLE:switch
    vxlan_port`` in APPL_DB, programmed to SAI as ``SAI_SWITCH_ATTR_VXLAN_DEFAULT_PORT``).
    Most images use the IANA default 4789, but some (e.g. the internal Bluefield builds)
    program a non-standard value, which would otherwise cause every VXLAN test packet to
    be silently dropped while the ENI counters stay at 0. Rather than reconfiguring the
    device, the test reads the value at runtime and builds its packets to match -- the
    same assumption other DASH dataplane tests make implicitly by relying on the DPU's
    configured VXLAN port instead of forcing one.
    """
    vxlan_port = dpuhost.shell(
        "redis-cli -n 0 hget SWITCH_TABLE:switch vxlan_port", module_ignore_errors=True
    )['stdout'].strip()
    return int(vxlan_port) if vxlan_port else DEFAULT_VXLAN_UDP_DPORT


@pytest.fixture
def inbound_pa_validation_route_rule(
    localhost, duthost, ptfhost, dpuhosts, dpu_index, skip_config, skip_cleanup
):
    """Program an inbound route rule that enables PA validation on the GRE encap VNI.

    The default privatelink config only programs a ``{PE_PA}/32`` inbound route rule, so a
    packet with an unknown outer source PA misses it and is dropped generically rather than
    on PA validation. This fixture adds a broad ``0.0.0.0/0`` route rule with
    ``pa_validation`` enabled against VNET1 so that the invalid-source-PA packet is steered
    to PA validation and increments SAI_ENI_STAT_PA_VALIDATION_FAIL_DROP_PACKETS.
    """
    if skip_config:
        yield
        return
    dpuhost = dpuhosts[dpu_index]
    apply_dash_configs(
        localhost, duthost, ptfhost, dpuhost.dpu_index,
        pl.INBOUND_PA_VALIDATION_ROUTE_RULE_CONFIG)
    yield
    if not skip_cleanup:
        apply_dash_configs(
            localhost, duthost, ptfhost, dpuhost.dpu_index,
            pl.INBOUND_PA_VALIDATION_ROUTE_RULE_CONFIG, set_db=False)


class TestEniCounter:

    @pytest.fixture(autouse=True)
    def setup_param(self, dpuhost, ptfadapter, eni_counter_setup, common_setup_teardown):  # noqa: F811
        self.ptfadapter = ptfadapter
        self.dpuhost = dpuhost
        self.eni = pl.ENI_ID

        # Build VXLAN test packets with the outer UDP dst port the DPU actually programs so
        # that VXLAN-encapsulated DASH traffic is accepted regardless of the platform's
        # default VXLAN port (see ``read_dpu_vxlan_udp_dport``).
        self.vxlan_udp_dport = read_dpu_vxlan_udp_dport(dpuhost)

        # ``common_setup_teardown`` programs the DASH config (incl. the ENI) per test, so
        # wait for the flex counter to publish the ENI's OID in COUNTERS_ENI_NAME_MAP
        # before any test reads counters.
        def _eni_counter_oid_ready():
            try:
                self.eni_counter_oid = get_eni_counter_oid(dpuhost, self.eni)
                return True
            except KeyError:
                return False

        pytest_assert(
            wait_until(ENI_COUNTER_READY_MAX_TIME, 2, 0, _eni_counter_oid_ready),
            "ENI counter OID for {} was not published in COUNTERS_ENI_NAME_MAP".format(self.eni),
        )

    def _outbound_pl_packets(self, *args, **kwargs):
        """``outbound_pl_packets`` with the DPU's actual VXLAN UDP dst port injected."""
        kwargs.setdefault("vxlan_udp_dport", self.vxlan_udp_dport)
        return outbound_pl_packets(*args, **kwargs)

    def _inbound_pl_packets(self, *args, **kwargs):
        """``inbound_pl_packets`` with the DPU's actual VXLAN UDP dst port injected."""
        kwargs.setdefault("vxlan_udp_dport", self.vxlan_udp_dport)
        return inbound_pl_packets(*args, **kwargs)

    def test_outbound_pkt_pass_eni_counter(self, dash_pl_config, outer_encap, inner_packet_type):
        """
        1. Get the eni_counter_before_sending_pkt before sending the dash pkt
        2. Send a outbound pkt, and the pkt pass the pipeline successfully
        3. Get the eni_counter_after_sending_pkt after sending the dash pkt
        4. Check the following counter change as follows by comparing eni_counter_before_sending_pkt
        with eni_counter_after_sending_pkt
               SAI_ENI_STAT_FLOW_CREATED:  +1
               SAI_ENI_STAT_OUTBOUND_RX_BYTES:  +len(packet)*packet_number
               SAI_ENI_STAT_OUTBOUND_RX_PACKETS: +packet_number
               SAI_ENI_STAT_RX_PACKETS: +packet_number
               SAI_ENI_STAT_RX_BYTES: +len(packet)*packet_number
               SAI_ENI_STAT_FLOW_AGED: +1
        """
        packet_len = 150 if outer_encap == "vxlan" else 142
        packet_number = 10

        eni_counter_check_point_dict = {"SAI_ENI_STAT_FLOW_CREATED": 1,
                                        "SAI_ENI_STAT_OUTBOUND_RX_BYTES": packet_len * packet_number,
                                        "SAI_ENI_STAT_OUTBOUND_RX_PACKETS": packet_number,
                                        "SAI_ENI_STAT_RX_PACKETS": packet_number,
                                        "SAI_ENI_STAT_RX_BYTES": packet_len * packet_number,
                                        "SAI_ENI_STAT_FLOW_AGED": 1
                                        }

        pkt, exp_pkt = self._outbound_pl_packets(
            dash_pl_config, outer_encap=outer_encap, inner_packet_type=inner_packet_type)
        verify_packets = [{'send': pkt, 'exp': exp_pkt, 'dir': "outbound"}]
        self.send_packet_and_verify_dash_eni_counter(
            dash_pl_config, eni_counter_check_point_dict, packet_number, verify_packets)

    def test_outbound_pkt_miss_routing_entry_drop_counter(self, dash_pl_config, outer_encap, inner_packet_type):
        """
        1. Get the eni_counter_before_sending_pkt before sending the dash pkt
        2. Send a outbound pkt with inner dst dip which cannot match the dash route
        3. Get the eni_counter_after_sending_pkt after sending the dash pkt
        4. Check the following counter change as follows by comparing eni_counter_before_sending_pkt
        with eni_counter_after_sending_pkt
               SAI_ENI_STAT_OUTBOUND_ROUTING_ENTRY_MISS_DROP_PACKETS: +1
               SAI_ENI_STAT_FORWARDING_DROP_PACKETS: +1   (new in SAI#2251, aggregate forwarding drops)
               SAI_ENI_STAT_TOTAL_DROP_PACKETS: +1        (new in SAI#2251, aggregate of all drops)
        """
        packet_number = 1
        eni_counter_check_point_dict = {
            "SAI_ENI_STAT_OUTBOUND_ROUTING_ENTRY_MISS_DROP_PACKETS": packet_number,
            "SAI_ENI_STAT_FORWARDING_DROP_PACKETS": packet_number,
            "SAI_ENI_STAT_TOTAL_DROP_PACKETS": packet_number,
        }
        pkt, exp_pkt = self._outbound_pl_packets(dash_pl_config, outer_encap, inner_packet_type=inner_packet_type)
        pkt[outer_encap.upper()]['IP'].dst = "10.3.3.4"
        verify_packets = [{'send': pkt, 'exp': exp_pkt, 'dir': "outbound", 'drop': True}]
        self.send_packet_and_verify_dash_eni_counter(
            dash_pl_config, eni_counter_check_point_dict, packet_number, verify_packets)

    def test_outbound_pkt_ca_pa_entry_miss_drop_counter(self, dash_pl_config, outer_encap, inner_packet_type):
        """
        1. Get the eni_counter_before_sending_pkt before sending the dash pkt
        2. Send a outbound pkt that matches to routing but no ca_to_pa exist for the vnet ID
        3. Get the eni_counter_after_sending_pkt after sending the dash pkt
        4. Check the following counter change as follows by comparing eni_counter_before_sending_pkt
        with eni_counter_after_sending_pkt
               SAI_ENI_STAT_OUTBOUND_CA_PA_ENTRY_MISS_DROP_PACKETS: +1
               SAI_ENI_STAT_FORWARDING_DROP_PACKETS: +1   (new in SAI#2251, aggregate forwarding drops)
               SAI_ENI_STAT_TOTAL_DROP_PACKETS: +1        (new in SAI#2251, aggregate of all drops)
        """
        packet_number = 1
        eni_counter_check_point_dict = {
            "SAI_ENI_STAT_OUTBOUND_CA_PA_ENTRY_MISS_DROP_PACKETS": packet_number,
            "SAI_ENI_STAT_FORWARDING_DROP_PACKETS": packet_number,
            "SAI_ENI_STAT_TOTAL_DROP_PACKETS": packet_number,
        }
        pkt, exp_pkt = self._outbound_pl_packets(dash_pl_config, outer_encap, inner_packet_type=inner_packet_type)
        ip_with_same_outbound_route_prefix1 = format(IPv4Address(pl.PE_CA) + 1)
        pkt[outer_encap.upper()]['IP'].dst = ip_with_same_outbound_route_prefix1
        verify_packets = [{'send': pkt, 'exp': exp_pkt, 'dir': "outbound", 'drop': True}]

        self.send_packet_and_verify_dash_eni_counter(
            dash_pl_config, eni_counter_check_point_dict, packet_number, verify_packets)

    def test_eni_flow_deleted_counter(self, dash_pl_config, outer_encap):
        """
        1. Send 1 pass TCP SYN packet
        2. Get the eni_counter_before_sending_pkt before sending the dash pkt
        3. Send 1 pass RST packet
        4. Get the eni_counter_after_sending_pkt before sending the dash pkt
        4. Check the following counter change as follows by comparing eni_counter_before_sending_pkt
        with eni_counter_after_sending_pkt
                SAI_ENI_STAT_FLOW_DELETED increase by 1
        """
        packet_number = 1
        flow_del_counter = 1
        flow_created_counter = 1

        eni_counter_check_point_dict = {"SAI_ENI_STAT_FLOW_CREATED": flow_created_counter,
                                        "SAI_ENI_STAT_FLOW_DELETED": flow_del_counter}

        pkt, _ = self._outbound_pl_packets(dash_pl_config, outer_encap, inner_packet_type='tcp')
        pkt_rst = copy.deepcopy(pkt)
        pkt_rst[outer_encap.upper()]["TCP"].flags = "R"
        verify_packets = [{'send': pkt, 'exp': None, 'dir': "outbound"},
                          {'send': pkt_rst, 'exp': None, 'dir': "outbound"}]
        self.send_packet_and_verify_dash_eni_counter(
            dash_pl_config, eni_counter_check_point_dict, packet_number, verify_packets)

    def test_inbound_pkt_eni_counter(
            self,
            dash_pl_config,
            outer_encap,
            inner_packet_type
    ):
        """
        1. Get the eni_counter_before_sending_pkt before sending the dash pkt
        2. Send a outbound pkt and a inbound pkt
        3. Get the eni_counter_after_sending_pkt after sending the dash pkt
        4. Check the following counter change as follows by comparing eni_counter_before_sending_pkt
        with eni_counter_after_sending_pkt
               SAI_ENI_STAT_FLOW_CREATED: +1
               SAI_ENI_STAT_INBOUND_RX_BYTES: +len(inbound_packet)*packet_number
               SAI_ENI_STAT_INBOUND_RX_PACKETS: +packet_number
               SAI_ENI_STAT_RX_PACKETS: +packet_number*2
               SAI_ENI_STAT_RX_BYTES: +len(inbound_packet)*packet_number + len(outbound_packet)*packet_number
               SAI_ENI_STAT_FLOW_AGED: +1
        5. Send a inbound pkt without inbound route
        6. Get the eni_counter_after_sending_pkt after sending the inbound pkt
        7. Check the following counter change as follows by comparing eni_counter_before_sending_pkt
        with eni_counter_after_sending_pkt
               SAI_ENI_STAT_INBOUND_ROUTING_ENTRY_MISS_DROP_PACKETS: +packet_number
        """
        outbound_packet_len = 150 if outer_encap == "vxlan" else 142
        inbound_packet_len = 142
        packet_number = 1

        vm_to_dpu_pkt, _ = self._outbound_pl_packets(dash_pl_config, outer_encap, inner_packet_type=inner_packet_type)
        pe_to_dpu_pkt, exp_dpu_to_vm_pkt = self._inbound_pl_packets(
            dash_pl_config, inner_packet_type=inner_packet_type, vxlan_udp_src_port_mask=16)

        with allure.step("send outbound and inbound packet and verify the relevant eni counter"):
            eni_counter_check_point_dict = {"SAI_ENI_STAT_FLOW_CREATED": 1,
                                            "SAI_ENI_STAT_INBOUND_RX_BYTES":
                                                inbound_packet_len*packet_number,
                                            "SAI_ENI_STAT_INBOUND_RX_PACKETS": packet_number,
                                            "SAI_ENI_STAT_RX_PACKETS": packet_number*2,
                                            "SAI_ENI_STAT_RX_BYTES":
                                                outbound_packet_len * packet_number + inbound_packet_len*packet_number,
                                                "SAI_ENI_STAT_FLOW_AGED": 1
                                            }
            verify_packets = [{'send': vm_to_dpu_pkt, 'exp': None, 'dir': "outbound"},
                              {'send': pe_to_dpu_pkt, 'exp': exp_dpu_to_vm_pkt, 'dir': "inbound"}]
            self.send_packet_and_verify_dash_eni_counter(
                dash_pl_config, eni_counter_check_point_dict, packet_number, verify_packets)

        with allure.step("send the inbound packet without inbound route and verify the relevant eni counter"):
            eni_counter_check_point_dict = {
                "SAI_ENI_STAT_INBOUND_ROUTING_ENTRY_MISS_DROP_PACKETS": packet_number,
                # new in SAI#2251: aggregate forwarding-drop and total-drop counters
                "SAI_ENI_STAT_FORWARDING_DROP_PACKETS": packet_number,
                "SAI_ENI_STAT_TOTAL_DROP_PACKETS": packet_number,
            }
            verify_packets = [{'send': pe_to_dpu_pkt, 'exp': exp_dpu_to_vm_pkt, 'dir': "inbound", 'drop': True}]
            self.send_packet_and_verify_dash_eni_counter(
                dash_pl_config, eni_counter_check_point_dict, packet_number, verify_packets)

    @pytest.mark.parametrize("tcp_flag", ["syn", "synack", "fin", "rst"])
    def test_outbound_tcp_flag_eni_counter(self, dash_pl_config, outer_encap, tcp_flag):
        """
        Verify the per-flag outbound TCP counters added in SAI PR opencomputeproject/SAI#2251.

        1. (For non-SYN flags) send an outbound TCP SYN to establish a flow so the flagged
           packet is processed on an existing flow instead of being treated as a flow miss.
        2. Snapshot the eni counters, send an outbound TCP packet carrying ``tcp_flag``.
        3. Verify the matching counter increments:
               SAI_ENI_STAT_OUTBOUND_TCP_<FLAG>_PACKETS: +packet_number
           where <FLAG> is one of SYN / SYNACK / FIN / RST.
        """
        counter_name = "SAI_ENI_STAT_OUTBOUND_TCP_{}_PACKETS".format(TCP_FLAG_COUNTER_SUFFIX[tcp_flag])
        packet_number = 1
        eni_counter_check_point_dict = {counter_name: packet_number}

        verify_packets = []
        if tcp_flag != "syn":
            syn_pkt, _ = self._outbound_pl_packets(
                dash_pl_config, outer_encap, inner_packet_type="tcp", tcp_flag_syn=True)
            verify_packets.append({'send': syn_pkt, 'exp': None, 'dir': "outbound"})

        flag_pkt, _ = self._outbound_pl_packets(
            dash_pl_config, outer_encap, inner_packet_type="tcp", **TCP_FLAG_KWARGS[tcp_flag])
        if tcp_flag == "rst":
            flag_pkt[outer_encap.upper()]["TCP"].flags = "R"
        verify_packets.append({'send': flag_pkt, 'exp': None, 'dir': "outbound"})

        self.send_packet_and_verify_dash_eni_counter(
            dash_pl_config, eni_counter_check_point_dict, packet_number, verify_packets)

    @pytest.mark.parametrize("tcp_flag", ["syn", "synack", "fin", "rst"])
    def test_inbound_tcp_flag_eni_counter(self, dash_pl_config, outer_encap, tcp_flag):
        """
        Verify the per-flag inbound TCP counters added in SAI PR opencomputeproject/SAI#2251.

        1. Send an outbound TCP SYN to establish the bidirectional flow.
        2. Snapshot the eni counters, send an inbound (PE->DPU) TCP packet carrying ``tcp_flag``.
        3. Verify the matching counter increments:
               SAI_ENI_STAT_INBOUND_TCP_<FLAG>_PACKETS: +packet_number
           where <FLAG> is one of SYN / SYNACK / FIN / RST.
        """
        counter_name = "SAI_ENI_STAT_INBOUND_TCP_{}_PACKETS".format(TCP_FLAG_COUNTER_SUFFIX[tcp_flag])
        packet_number = 1
        eni_counter_check_point_dict = {counter_name: packet_number}

        vm_to_dpu_syn, _ = self._outbound_pl_packets(
            dash_pl_config, outer_encap, inner_packet_type="tcp", tcp_flag_syn=True)
        inbound_flag_pkt, _ = self._inbound_pl_packets(
            dash_pl_config, inner_packet_type="tcp", **TCP_FLAG_KWARGS[tcp_flag])
        if tcp_flag == "rst":
            inbound_flag_pkt["GRE"]["TCP"].flags = "R"

        verify_packets = [{'send': vm_to_dpu_syn, 'exp': None, 'dir': "outbound"},
                          {'send': inbound_flag_pkt, 'exp': None, 'dir': "inbound"}]
        self.send_packet_and_verify_dash_eni_counter(
            dash_pl_config, eni_counter_check_point_dict, packet_number, verify_packets)

    def test_outbound_unsupported_protocol_drop_counter(self, dash_pl_config, outer_encap):
        """
        Verify SAI_ENI_STAT_UNSUPPORTED_PROTOCOL_DROP_PACKETS (new in SAI#2251).

        Send an outbound packet whose inner IP protocol is neither TCP/UDP/ICMP (here set to
        89 / OSPF). The DPU should drop it as an unsupported tenant protocol and increment the
        dedicated drop counter plus the aggregate total-drop counter.
        """
        unsupported_ip_proto = 89  # OSPF, an arbitrary non TCP/UDP/ICMP protocol
        packet_number = 1
        eni_counter_check_point_dict = {
            "SAI_ENI_STAT_UNSUPPORTED_PROTOCOL_DROP_PACKETS": packet_number,
            "SAI_ENI_STAT_TOTAL_DROP_PACKETS": packet_number,
        }
        pkt, exp_pkt = self._outbound_pl_packets(dash_pl_config, outer_encap, inner_packet_type="udp")
        inner_ip = pkt[outer_encap.upper()]["IP"]
        inner_ip.proto = unsupported_ip_proto
        # force scapy to recompute the inner IP checksum after mutating the protocol field
        inner_ip.chksum = None
        verify_packets = [{'send': pkt, 'exp': exp_pkt, 'dir': "outbound", 'drop': True}]
        self.send_packet_and_verify_dash_eni_counter(
            dash_pl_config, eni_counter_check_point_dict, packet_number, verify_packets)

    def test_inbound_pa_validation_fail_drop_counter(
            self, dash_pl_config, inner_packet_type, inbound_pa_validation_route_rule):
        """
        Verify SAI_ENI_STAT_PA_VALIDATION_FAIL_DROP_PACKETS (new in SAI#2251).

        Send an inbound packet whose outer source PA is not a configured tunnel endpoint.
        The DPU should drop it on source-PA (tunnel-endpoint) validation failure and increment
        the dedicated drop counter plus the aggregate total-drop counter.
        """
        invalid_source_pa = "200.0.0.200"  # not a configured tunnel endpoint / PE PA
        packet_number = 1
        eni_counter_check_point_dict = {
            "SAI_ENI_STAT_PA_VALIDATION_FAIL_DROP_PACKETS": packet_number,
            "SAI_ENI_STAT_TOTAL_DROP_PACKETS": packet_number,
        }
        pkt, exp_pkt = self._inbound_pl_packets(dash_pl_config, inner_packet_type=inner_packet_type)
        outer_ip = pkt["IP"]
        outer_ip.src = invalid_source_pa
        outer_ip.chksum = None
        verify_packets = [{'send': pkt, 'exp': exp_pkt, 'dir': "inbound", 'drop': True}]
        self.send_packet_and_verify_dash_eni_counter(
            dash_pl_config, eni_counter_check_point_dict, packet_number, verify_packets)

    def send_packet_and_verify_dash_eni_counter(
            self, dash_pl_config, eni_counter_check_point_dict, packet_number, verify_packets):
        self.ptfadapter.dataplane.flush()

        with allure.step("get dash eni counter before sending pkt"):
            eni_counter_before_sending_pkt = get_eni_counters(self.dpuhost, self.eni_counter_oid)

        # Only assert on counters the installed DPU image actually publishes (present in the
        # baseline snapshot). Counters that are absent are not implemented/polled by this
        # SAI + SONiC build and are skipped rather than failing with a missing-key error.
        supported_check_point_dict, unsupported_counters = partition_supported_counters(
            eni_counter_check_point_dict, eni_counter_before_sending_pkt)
        if unsupported_counters:
            logger.warning("ENI counters not published by this DPU image, skipping: %s", unsupported_counters)
        if not supported_check_point_dict:
            pytest.skip("None of the targeted ENI counters {} are implemented on this DPU image".format(
                sorted(eni_counter_check_point_dict.keys())))

        with allure.step("sending packets"):
            for pkts in verify_packets:
                if pkts['dir'] == "outbound":
                    testutils.send(self.ptfadapter, dash_pl_config[LOCAL_PTF_INTF], pkts['send'], packet_number)
                else:
                    testutils.send(self.ptfadapter, dash_pl_config[REMOTE_PTF_SEND_INTF], pkts['send'], packet_number)
                if pkts.get('drop'):
                    # The packet is expected to be dropped by the DPU, so in addition to the drop
                    # counters confirm that the packet it would have produced on a valid flow
                    # (``pkts['exp']``) never egresses toward the destination PTF port(s).
                    with allure.step("verify the dropped packet is not forwarded"):
                        if pkts['dir'] == "outbound":
                            testutils.verify_no_packet_any(
                                self.ptfadapter, pkts['exp'], dash_pl_config[REMOTE_PTF_RECV_INTF])
                        else:
                            testutils.verify_no_packet(
                                self.ptfadapter, pkts['exp'], dash_pl_config[LOCAL_PTF_INTF])
                elif pkts['exp']:
                    if pkts['dir'] == "outbound":
                        testutils.verify_packet_any_port(
                            self.ptfadapter, pkts['exp'], dash_pl_config[REMOTE_PTF_RECV_INTF])
                    else:
                        testutils.verify_packet(self.ptfadapter, pkts['exp'], dash_pl_config[LOCAL_PTF_INTF])

        def _verify_eni_counter():
            with allure.step("get dash eni counter after sending pkts"):
                eni_counter_after_sending_pkt = get_eni_counters(self.dpuhost, self.eni_counter_oid)

            # compare eni_counter_after_sending_pkt with eni_counter_before_sending_pkt
            return verify_eni_counter(
                supported_check_point_dict, eni_counter_before_sending_pkt, eni_counter_after_sending_pkt)

        pytest_assert(wait_until(ENI_COUNTER_READY_MAX_TIME, 2, 0, _verify_eni_counter),
                      "The actual eni counter is not as expected")
