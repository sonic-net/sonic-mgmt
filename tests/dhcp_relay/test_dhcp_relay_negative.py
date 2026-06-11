"""
DHCPv4 relay negative tests (dhcp4relay). Pytest module: test_dhcp_relay_negative.py.

- Hop count exceeded: DISCOVER with hops=255; no relay to servers + syslog.
- Server OFFER with Option 82 but no circuit ID: no relay to client + syslog.
- Discard / relay-from-relay: DISCOVER with giaddr + Option 82; no relay + syslog
  (requires agent_relay_mode discard — default when not append/replace).
- Bad IP/UDP checksums: corrupted DISCOVER; no relay + syslog (untagged L2, eth len 14).
- Unknown giaddr from server: OFFER with giaddr 99.99.99.99, no Option 82; no relay + syslog.
- Malformed Option 82 TLV: OFFER with truncated sub-option length; no relay + syslog
  (decode_tlv logs with tag DHCPV4_INFO; source string has typo realy).
- Malformed client frame — l2_only: L2-only DISCOVER; kernel BPF drop — no syslog; PTF no relay.
- Malformed client frame — partial_udp: shortened IPv4 tot_len + partial UDP; Invalid UDP syslog.
- Malformed client frame — l2_runt: pytest.skip (PTF cannot inject true <14 B L2; see PTF doc §7).

Naming (sync with PTF module dhcp_relay_negative_test.py): all pytest entry points use prefix
test_dhcp_relay_negative_*; PTF ptf_runner uses dhcp_relay_negative_test.<Class>.

Malformed client frame: class DHCPRelayMalformedClientFrameTest; param malformed_client_frame =
l2_only | partial_udp; tests test_dhcp_relay_negative_malformed_client_frame_l2_runt |
_l2_only | _partial_udp.

PTF: ansible/roles/test/files/ptftests/py3/dhcp_relay_negative_test.py
"""

import logging

import pytest

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory  # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m  # noqa F401
from tests.ptf_runner import ptf_runner
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError
from tests.common.utilities import skip_release

from tests.dhcp_relay.test_dhcp_relay import (
    BROADCAST_MAC,
    DEFAULT_DHCP_CLIENT_PORT,
    DUAL_TOR_MODE,
    check_interface_status,
)

pytestmark = [
    pytest.mark.topology("t0", "m0"),
    pytest.mark.device_type("vs"),
]

logger = logging.getLogger(__name__)

_EXPECT_HOP_DROP_SYSLOG = (
    r".*\[DHCPV4_RELAY\].*Dropping packet: hop count .* exceeds max allowed.*"
)

_EXPECT_MISSING_CIRCUIT_SYSLOG = (
    r".*\[DHCPV4_RELAY\].*Circuit id sub-option is missing in relay agent option from server.*"
)

# dhcp4relay.cpp from_client() syslogs at LOG_INFO when agent_relay_mode == discard:
#   "[DHCPV4_RELAY] agent relay mode is discard, dropping the packet %s", ...
_EXPECT_DISCARD_RELAY_FROM_RELAY_SYSLOG = (
    r".*\[DHCPV4_RELAY\].*agent relay mode is discard, dropping the packet.*"
)

_EXPECT_BAD_IP_CHKSUM_SYSLOG = (
    r".*\[DHCPV4_RELAY\].*Checksum failed for IP packet from interface.*"
)

# dhcp4relay.cpp typo: DHCPV4_REALY (not RELAY) in UDP checksum syslog string
_EXPECT_BAD_UDP_CHKSUM_SYSLOG = (
    r".*\[DHCPV4_REALY\].*UDP checksum validation is failing.*"
)

_EXPECT_UNKNOWN_GIADDR_SYSLOG = (
    r".*\[DHCPV4_RELAY\].*Failed to find interface attached to address.*"
)

# dhcp4relay.cpp decode_tlv(): LOG_ERR "[DHCPV4_INFO] Failed to decode realy agent sub-option" (typo: realy)
_EXPECT_MALFORMED_OPT82_TLV_SYSLOG = (
    r".*Failed to decode realy agent sub-option.*exceeded total option len.*"
)

_EXPECT_MALFORMED_CLIENT_PARTIAL_UDP_SYSLOG = (
    r".*\[DHCPV4_RELAY\].*Invalid UDP packet from interface.*"
)


def _dhcp_relay_negative_ptf_params(duthost, dhcp_relay, testing_mode):
    """Shared PTF test params for dhcp_relay_negative_test module."""
    return {
        "hostname": duthost.hostname,
        "client_port_index": dhcp_relay["client_iface"]["port_idx"],
        "other_client_port": repr(dhcp_relay["other_client_ports"]),
        "client_iface_alias": str(dhcp_relay["client_iface"]["alias"]),
        "leaf_port_indices": repr(dhcp_relay["uplink_port_indices"]),
        "num_dhcp_servers": len(
            dhcp_relay["downlink_vlan_iface"]["dhcp_server_addrs"]
        ),
        "server_ip": dhcp_relay["downlink_vlan_iface"]["dhcp_server_addrs"],
        "relay_iface_ip": str(dhcp_relay["downlink_vlan_iface"]["addr"]),
        "relay_iface_mac": str(dhcp_relay["downlink_vlan_iface"]["mac"]),
        "relay_iface_netmask": str(dhcp_relay["downlink_vlan_iface"]["mask"]),
        "dest_mac_address": BROADCAST_MAC,
        "client_udp_src_port": DEFAULT_DHCP_CLIENT_PORT,
        "switch_loopback_ip": dhcp_relay["switch_loopback_ip"],
        "uplink_mac": str(dhcp_relay["uplink_mac"]),
        "testing_mode": testing_mode,
        "downlink_vlan_iface_name": str(
            dhcp_relay["downlink_vlan_iface"]["name"]
        ),
    }


def test_dhcp_relay_negative_hop_limit_exceeded(
    ptfhost,
    dut_dhcp_relay_data,
    validate_dut_routes_exist,
    testing_config,
    setup_standby_ports_on_rand_unselected_tor,  # noqa F811
    rand_unselected_dut,  # noqa F811
    toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa F811
):
    """
    Inject DISCOVER with hops=255 from the VLAN client PTF port; assert no relayed
    traffic on server-facing PTF ports and that DUT syslog records the drop.
    """
    testing_mode, duthost = testing_config

    if testing_mode == DUAL_TOR_MODE:
        skip_release(duthost, ["201811", "201911"])

    pytest_assert(
        check_interface_status(duthost),
        "dhcp4relay does not appear to be listening; hop-limit check applies to dhcp4relay",
    )

    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="dhcp_relay_negative_hop_limit")
    marker = loganalyzer.init()
    loganalyzer.expect_regex = [_EXPECT_HOP_DROP_SYSLOG]

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            params = _dhcp_relay_negative_ptf_params(duthost, dhcp_relay, testing_mode)
            params.update({"bootp_hops": 255, "relay_wait_sec": 3})
            ptf_runner(
                ptfhost,
                "ptftests",
                "dhcp_relay_negative_test.DHCPRelayHopLimitTest",
                platform_dir="ptftests",
                params=params,
                log_file="/tmp/dhcp_relay_negative_hop_limit.log",
                is_python3=True,
            )
        loganalyzer.analyze(marker)
    except LogAnalyzerError as err:
        logger.error("Syslog did not contain expected dhcp4relay hop-limit drop message")
        raise err


def test_dhcp_relay_negative_server_offer_missing_circuit_id(
    ptfhost,
    dut_dhcp_relay_data,
    validate_dut_routes_exist,
    testing_config,
    setup_standby_ports_on_rand_unselected_tor,  # noqa F811
    rand_unselected_dut,  # noqa F811
    toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa F811
):
    """
    Inject OFFER with Option 82 containing only remote-ID; assert no relay to client
    and syslog records the error.
    """
    testing_mode, duthost = testing_config

    if testing_mode == DUAL_TOR_MODE:
        skip_release(duthost, ["201811", "201911"])

    pytest_assert(
        check_interface_status(duthost),
        "dhcp4relay does not appear to be listening; Option 82 check applies to dhcp4relay",
    )

    loganalyzer = LogAnalyzer(
        ansible_host=duthost, marker_prefix="dhcp_relay_negative_missing_circuit_id"
    )
    marker = loganalyzer.init()
    loganalyzer.expect_regex = [_EXPECT_MISSING_CIRCUIT_SYSLOG]

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            params = _dhcp_relay_negative_ptf_params(duthost, dhcp_relay, testing_mode)
            params.update({"offer_wait_sec": 3})
            ptf_runner(
                ptfhost,
                "ptftests",
                "dhcp_relay_negative_test.DHCPRelayMissingCircuitIdTest",
                platform_dir="ptftests",
                params=params,
                log_file="/tmp/dhcp_relay_negative_missing_circuit_id.log",
                is_python3=True,
            )
        loganalyzer.analyze(marker)
    except LogAnalyzerError as err:
        logger.error(
            "Syslog did not contain expected dhcp4relay missing-circuit-id message"
        )
        raise err


def test_dhcp_relay_negative_unknown_giaddr_from_server(
    ptfhost,
    dut_dhcp_relay_data,
    validate_dut_routes_exist,
    testing_config,
    setup_standby_ports_on_rand_unselected_tor,  # noqa F811
    rand_unselected_dut,  # noqa F811
    toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa F811
):
    """
    Server OFFER with giaddr not on DUT (99.99.99.99) and no Option 82; assert no relay
    to client and syslog from to_client() giaddr resolution.
    """
    testing_mode, duthost = testing_config

    if testing_mode == DUAL_TOR_MODE:
        skip_release(duthost, ["201811", "201911"])

    pytest_assert(
        check_interface_status(duthost),
        "dhcp4relay does not appear to be listening",
    )

    loganalyzer = LogAnalyzer(
        ansible_host=duthost, marker_prefix="dhcp_relay_negative_unknown_giaddr"
    )
    marker = loganalyzer.init()
    loganalyzer.expect_regex = [_EXPECT_UNKNOWN_GIADDR_SYSLOG]

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            params = _dhcp_relay_negative_ptf_params(duthost, dhcp_relay, testing_mode)
            params.update(
                {
                    "offer_wait_sec": 3,
                    "bogus_server_giaddr": "99.99.99.99",
                }
            )
            ptf_runner(
                ptfhost,
                "ptftests",
                "dhcp_relay_negative_test.DHCPRelayUnknownGiaddrFromServerTest",
                platform_dir="ptftests",
                params=params,
                log_file="/tmp/dhcp_relay_negative_unknown_giaddr.log",
                is_python3=True,
            )
        loganalyzer.analyze(marker)
    except LogAnalyzerError as err:
        logger.error(
            "Syslog did not contain expected dhcp4relay unknown-giaddr message"
        )
        raise err


def test_dhcp_relay_negative_malformed_option82_tlv(
    ptfhost,
    dut_dhcp_relay_data,
    validate_dut_routes_exist,
    testing_config,
    setup_standby_ports_on_rand_unselected_tor,  # noqa F811
    rand_unselected_dut,  # noqa F811
    toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa F811
):
    """
    Server OFFER: Option 82 sub-option length larger than option payload (decode_tlv path).
    """
    testing_mode, duthost = testing_config

    if testing_mode == DUAL_TOR_MODE:
        skip_release(duthost, ["201811", "201911"])

    pytest_assert(
        check_interface_status(duthost),
        "dhcp4relay does not appear to be listening",
    )

    loganalyzer = LogAnalyzer(
        ansible_host=duthost, marker_prefix="dhcp_relay_negative_malformed_opt82_tlv"
    )
    marker = loganalyzer.init()
    loganalyzer.expect_regex = [_EXPECT_MALFORMED_OPT82_TLV_SYSLOG]

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            params = _dhcp_relay_negative_ptf_params(duthost, dhcp_relay, testing_mode)
            params.update(
                {
                    "offer_wait_sec": 3,
                    "malformed_opt82_declared_len": 10,
                }
            )
            ptf_runner(
                ptfhost,
                "ptftests",
                "dhcp_relay_negative_test.DHCPRelayMalformedOption82TlvTest",
                platform_dir="ptftests",
                params=params,
                log_file="/tmp/dhcp_relay_negative_malformed_opt82_tlv.log",
                is_python3=True,
            )
        loganalyzer.analyze(marker)
    except LogAnalyzerError as err:
        logger.error(
            "Syslog did not contain expected dhcp4relay malformed Option 82 TLV message"
        )
        raise err


def test_dhcp_relay_negative_discard_relay_from_relay(
    ptfhost,
    dut_dhcp_relay_data,
    validate_dut_routes_exist,
    testing_config,
    setup_standby_ports_on_rand_unselected_tor,  # noqa F811
    rand_unselected_dut,  # noqa F811
    toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa F811
):
    """
    Inject DISCOVER with non-zero giaddr and Option 82 (prior relay). With
    agent_relay_mode discard (default), assert no relay to servers and syslog.
    Fails if relay mode is append or replace.
    """
    testing_mode, duthost = testing_config

    if testing_mode == DUAL_TOR_MODE:
        skip_release(duthost, ["201811", "201911"])

    pytest_assert(
        check_interface_status(duthost),
        "dhcp4relay does not appear to be listening",
    )

    loganalyzer = LogAnalyzer(
        ansible_host=duthost, marker_prefix="dhcp_relay_negative_discard_relay_from_relay"
    )
    marker = loganalyzer.init()
    loganalyzer.expect_regex = [_EXPECT_DISCARD_RELAY_FROM_RELAY_SYSLOG]

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            params = _dhcp_relay_negative_ptf_params(duthost, dhcp_relay, testing_mode)
            params.update({"relay_wait_sec": 3, "relay_from_relay_hops": 1})
            ptf_runner(
                ptfhost,
                "ptftests",
                "dhcp_relay_negative_test.DHCPRelayDiscardRelayFromRelayTest",
                platform_dir="ptftests",
                params=params,
                log_file="/tmp/dhcp_relay_negative_discard_relay_from_relay.log",
                is_python3=True,
            )
        loganalyzer.analyze(marker)
    except LogAnalyzerError as err:
        logger.error(
            "Syslog did not contain expected dhcp4relay discard relay-from-relay message"
        )
        raise err


def test_dhcp_relay_negative_bad_ip_checksum(
    ptfhost,
    dut_dhcp_relay_data,
    validate_dut_routes_exist,
    testing_config,
    setup_standby_ports_on_rand_unselected_tor,  # noqa F811
    rand_unselected_dut,  # noqa F811
    toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa F811
):
    """DISCOVER with invalid IPv4 header checksum; no relay + syslog."""
    testing_mode, duthost = testing_config

    if testing_mode == DUAL_TOR_MODE:
        skip_release(duthost, ["201811", "201911"])

    pytest_assert(
        check_interface_status(duthost),
        "dhcp4relay does not appear to be listening",
    )

    loganalyzer = LogAnalyzer(
        ansible_host=duthost, marker_prefix="dhcp_relay_negative_bad_ip_checksum"
    )
    marker = loganalyzer.init()
    loganalyzer.expect_regex = [_EXPECT_BAD_IP_CHKSUM_SYSLOG]

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            params = _dhcp_relay_negative_ptf_params(duthost, dhcp_relay, testing_mode)
            params.update(
                {
                    "relay_wait_sec": 3,
                    "bad_checksum_layer": "ip",
                    "eth_header_len": 14,
                }
            )
            ptf_runner(
                ptfhost,
                "ptftests",
                "dhcp_relay_negative_test.DHCPRelayBadChecksumTest",
                platform_dir="ptftests",
                params=params,
                log_file="/tmp/dhcp_relay_negative_bad_checksum_ip.log",
                is_python3=True,
            )
        loganalyzer.analyze(marker)
    except LogAnalyzerError as err:
        logger.error(
            "Syslog did not contain expected dhcp4relay bad IP checksum message"
        )
        raise err


def test_dhcp_relay_negative_bad_udp_checksum(
    ptfhost,
    dut_dhcp_relay_data,
    validate_dut_routes_exist,
    testing_config,
    setup_standby_ports_on_rand_unselected_tor,  # noqa F811
    rand_unselected_dut,  # noqa F811
    toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa F811
):
    """DISCOVER with invalid UDP checksum (IPv4 header valid); no relay + syslog."""
    testing_mode, duthost = testing_config

    if testing_mode == DUAL_TOR_MODE:
        skip_release(duthost, ["201811", "201911"])

    pytest_assert(
        check_interface_status(duthost),
        "dhcp4relay does not appear to be listening",
    )

    loganalyzer = LogAnalyzer(
        ansible_host=duthost, marker_prefix="dhcp_relay_negative_bad_udp_checksum"
    )
    marker = loganalyzer.init()
    loganalyzer.expect_regex = [_EXPECT_BAD_UDP_CHKSUM_SYSLOG]

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            params = _dhcp_relay_negative_ptf_params(duthost, dhcp_relay, testing_mode)
            params.update(
                {
                    "relay_wait_sec": 3,
                    "bad_checksum_layer": "udp",
                    "eth_header_len": 14,
                }
            )
            ptf_runner(
                ptfhost,
                "ptftests",
                "dhcp_relay_negative_test.DHCPRelayBadChecksumTest",
                platform_dir="ptftests",
                params=params,
                log_file="/tmp/dhcp_relay_negative_bad_checksum_udp.log",
                is_python3=True,
            )
        loganalyzer.analyze(marker)
    except LogAnalyzerError as err:
        logger.error(
            "Syslog did not contain expected dhcp4relay bad UDP checksum message"
        )
        raise err


def test_dhcp_relay_negative_malformed_client_frame_l2_runt(
    ptfhost,
    dut_dhcp_relay_data,
    validate_dut_routes_exist,
    testing_config,
    setup_standby_ports_on_rand_unselected_tor,  # noqa F811
    rand_unselected_dut,  # noqa F811
    toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa F811
):
    """True L2 runt (<14 B) would trigger Invalid Ethernet in dhcp4relay; not injectable on Linux PTF."""
    pytest.skip(
        "Linux PTF TAP rejects Ethernet frames shorter than ~60 B (OSError EINVAL). "
        "Padding to 60 B yields a parsable EthLayer, so dhcp4relay logs Invalid IP, not "
        "Invalid Ethernet. Cover malformed paths via test_dhcp_relay_negative_malformed_client_frame_l2_only "
        "and test_dhcp_relay_negative_malformed_client_frame_partial_udp."
    )


def test_dhcp_relay_negative_malformed_client_frame_l2_only(
    ptfhost,
    dut_dhcp_relay_data,
    validate_dut_routes_exist,
    testing_config,
    setup_standby_ports_on_rand_unselected_tor,  # noqa F811
    rand_unselected_dut,  # noqa F811
    toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa F811
):
    """
    L2-only frame (no IPv4 at BPF offsets). dhcp4relay uses SO_ATTACH_FILTER (UDP/67) in
    dhcp4relay.cpp; the kernel drops the packet — no Invalid IP syslog. PTF still verifies
    no spurious relay to servers.
    """
    testing_mode, duthost = testing_config

    if testing_mode == DUAL_TOR_MODE:
        skip_release(duthost, ["201811", "201911"])

    pytest_assert(
        check_interface_status(duthost),
        "dhcp4relay does not appear to be listening",
    )

    for dhcp_relay in dut_dhcp_relay_data:
        params = _dhcp_relay_negative_ptf_params(duthost, dhcp_relay, testing_mode)
        params.update(
            {
                "relay_wait_sec": 3,
                "malformed_client_frame": "l2_only",
                "eth_header_len": 14,
            }
        )
        ptf_runner(
            ptfhost,
            "ptftests",
            "dhcp_relay_negative_test.DHCPRelayMalformedClientFrameTest",
            platform_dir="ptftests",
            params=params,
            log_file="/tmp/dhcp_relay_negative_malformed_client_l2_only.log",
            is_python3=True,
        )


def test_dhcp_relay_negative_malformed_client_frame_partial_udp(
    ptfhost,
    dut_dhcp_relay_data,
    validate_dut_routes_exist,
    testing_config,
    setup_standby_ports_on_rand_unselected_tor,  # noqa F811
    rand_unselected_dut,  # noqa F811
    toggle_all_simulator_ports_to_rand_selected_tor_m,  # noqa F811
):
    """Partial UDP (IPv4 tot_len ends after sport/dport); no relay + Invalid UDP syslog."""
    testing_mode, duthost = testing_config

    if testing_mode == DUAL_TOR_MODE:
        skip_release(duthost, ["201811", "201911"])

    pytest_assert(
        check_interface_status(duthost),
        "dhcp4relay does not appear to be listening",
    )

    loganalyzer = LogAnalyzer(
        ansible_host=duthost, marker_prefix="dhcp_relay_negative_malformed_partial_udp"
    )
    marker = loganalyzer.init()
    loganalyzer.expect_regex = [_EXPECT_MALFORMED_CLIENT_PARTIAL_UDP_SYSLOG]

    try:
        for dhcp_relay in dut_dhcp_relay_data:
            params = _dhcp_relay_negative_ptf_params(duthost, dhcp_relay, testing_mode)
            params.update(
                {
                    "relay_wait_sec": 3,
                    "malformed_client_frame": "partial_udp",
                    "eth_header_len": 14,
                }
            )
            ptf_runner(
                ptfhost,
                "ptftests",
                "dhcp_relay_negative_test.DHCPRelayMalformedClientFrameTest",
                platform_dir="ptftests",
                params=params,
                log_file="/tmp/dhcp_relay_negative_malformed_client_partial_udp.log",
                is_python3=True,
            )
        loganalyzer.analyze(marker)
    except LogAnalyzerError as err:
        logger.error(
            "Syslog did not contain expected dhcp4relay Invalid UDP (malformed partial_udp) message"
        )
        raise err
