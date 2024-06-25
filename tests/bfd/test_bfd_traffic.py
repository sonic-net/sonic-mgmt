import logging

import pytest

from tests.bfd.bfd_base import BfdBase
from tests.bfd.bfd_helpers import get_ptf_src_port, get_backend_interface_in_use_by_counter, verify_bfd_state, \
    prepare_traffic_test_variables, toggle_port_channel, get_random_bgp_neighbor_ip_of_asic, \
    toggle_port_channel_member, assert_bp_iface_after_shutdown
from tests.common.utilities import wait_until

pytestmark = [pytest.mark.topology("t2")]

logger = logging.getLogger(__name__)


class TestBfdTraffic(BfdBase):
    PACKET_COUNT = 10000

    @pytest.mark.parametrize("version", ["ipv4", "ipv6"])
    def test_bfd_traffic_remote_port_channel_shutdown(
        self,
        request,
        tbinfo,
        ptfadapter,
        get_src_dst_asic,
        bfd_cleanup_db,
        version,
    ):
        (
            dut,
            src_asic,
            src_asic_index,
            dst_asic,
            dst_asic_index,
            src_asic_next_hops,
            dst_asic_next_hops,
            src_asic_router_mac,
            backend_port_channels,
        ) = prepare_traffic_test_variables(get_src_dst_asic, request, version)

        dst_neighbor_ip = get_random_bgp_neighbor_ip_of_asic(dut, dst_asic_index, version)
        if not dst_neighbor_ip:
            pytest.skip("No BGP neighbor found on asic{} of dut {}".format(dst_asic_index, dut.hostname))

        ptf_src_port = get_ptf_src_port(src_asic, tbinfo)
        bp_iface_in_use_before_shutdown = get_backend_interface_in_use_by_counter(
            dut,
            self.PACKET_COUNT,
            version,
            src_asic_router_mac,
            ptfadapter,
            ptf_src_port,
            dst_neighbor_ip,
            dst_asic_index,
            "rx_ok",
        )

        if not bp_iface_in_use_before_shutdown:
            pytest.fail("No backend interface in use on asic{} of dut {}".format(dst_asic_index, dut.hostname))

        toggle_port_channel(
            dut,
            dst_asic,
            backend_port_channels,
            bp_iface_in_use_before_shutdown,
            request,
            "shutdown",
        )

        bp_iface_in_use_after_shutdown = get_backend_interface_in_use_by_counter(
            dut,
            self.PACKET_COUNT,
            version,
            src_asic_router_mac,
            ptfadapter,
            ptf_src_port,
            dst_neighbor_ip,
            dst_asic_index,
            "rx_ok",
        )

        assert_bp_iface_after_shutdown(
            bp_iface_in_use_after_shutdown,
            dst_asic_index,
            dut.hostname,
            bp_iface_in_use_before_shutdown,
        )

        toggle_port_channel(
            dut,
            dst_asic,
            backend_port_channels,
            bp_iface_in_use_before_shutdown,
            request,
            "startup",
        )

        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(dut, src_asic_next_hops.values(), src_asic, "Up"),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(dut, dst_asic_next_hops.values(), dst_asic, "Up"),
        )

    @pytest.mark.parametrize("version", ["ipv4", "ipv6"])
    def test_bfd_traffic_local_port_channel_shutdown(
        self,
        request,
        tbinfo,
        ptfadapter,
        get_src_dst_asic,
        bfd_cleanup_db,
        version,
    ):
        (
            dut,
            src_asic,
            src_asic_index,
            dst_asic,
            dst_asic_index,
            src_asic_next_hops,
            dst_asic_next_hops,
            src_asic_router_mac,
            backend_port_channels,
        ) = prepare_traffic_test_variables(get_src_dst_asic, request, version)

        dst_neighbor_ip = get_random_bgp_neighbor_ip_of_asic(dut, dst_asic_index, version)
        if not dst_neighbor_ip:
            pytest.skip("No BGP neighbor found on asic{} of dut {}".format(dst_asic_index, dut.hostname))

        ptf_src_port = get_ptf_src_port(src_asic, tbinfo)
        bp_iface_in_use_before_shutdown = get_backend_interface_in_use_by_counter(
            dut,
            self.PACKET_COUNT,
            version,
            src_asic_router_mac,
            ptfadapter,
            ptf_src_port,
            dst_neighbor_ip,
            src_asic_index,
            "tx_ok",
        )

        if not bp_iface_in_use_before_shutdown:
            pytest.fail("No backend interface in use on asic{} of dut {}".format(src_asic_index, dut.hostname))

        toggle_port_channel(
            dut,
            src_asic,
            backend_port_channels,
            bp_iface_in_use_before_shutdown,
            request,
            "shutdown",
        )

        bp_iface_in_use_after_shutdown = get_backend_interface_in_use_by_counter(
            dut,
            self.PACKET_COUNT,
            version,
            src_asic_router_mac,
            ptfadapter,
            ptf_src_port,
            dst_neighbor_ip,
            src_asic_index,
            "tx_ok",
        )

        assert_bp_iface_after_shutdown(
            bp_iface_in_use_after_shutdown,
            src_asic_index,
            dut.hostname,
            bp_iface_in_use_before_shutdown,
        )

        toggle_port_channel(
            dut,
            src_asic,
            backend_port_channels,
            bp_iface_in_use_before_shutdown,
            request,
            "startup",
        )

        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(dut, src_asic_next_hops.values(), src_asic, "Up"),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(dut, dst_asic_next_hops.values(), dst_asic, "Up"),
        )

    @pytest.mark.parametrize("version", ["ipv4", "ipv6"])
    def test_bfd_traffic_remote_port_channel_member_shutdown(
        self,
        request,
        tbinfo,
        ptfadapter,
        get_src_dst_asic,
        bfd_cleanup_db,
        version,
    ):
        (
            dut,
            src_asic,
            src_asic_index,
            dst_asic,
            dst_asic_index,
            src_asic_next_hops,
            dst_asic_next_hops,
            src_asic_router_mac,
            backend_port_channels,
        ) = prepare_traffic_test_variables(get_src_dst_asic, request, version)

        dst_neighbor_ip = get_random_bgp_neighbor_ip_of_asic(dut, dst_asic_index, version)
        if not dst_neighbor_ip:
            pytest.skip("No BGP neighbor found on asic{} of dut {}".format(dst_asic_index, dut.hostname))

        ptf_src_port = get_ptf_src_port(src_asic, tbinfo)
        bp_iface_in_use_before_shutdown = get_backend_interface_in_use_by_counter(
            dut,
            self.PACKET_COUNT,
            version,
            src_asic_router_mac,
            ptfadapter,
            ptf_src_port,
            dst_neighbor_ip,
            dst_asic_index,
            "rx_ok",
        )

        if not bp_iface_in_use_before_shutdown:
            pytest.fail("No backend interface in use on asic{} of dut {}".format(dst_asic_index, dut.hostname))

        toggle_port_channel_member(
            dut,
            dst_asic,
            bp_iface_in_use_before_shutdown,
            request,
            "shutdown",
        )

        bp_iface_in_use_after_shutdown = get_backend_interface_in_use_by_counter(
            dut,
            self.PACKET_COUNT,
            version,
            src_asic_router_mac,
            ptfadapter,
            ptf_src_port,
            dst_neighbor_ip,
            dst_asic_index,
            "rx_ok",
        )

        assert_bp_iface_after_shutdown(
            bp_iface_in_use_after_shutdown,
            dst_asic_index,
            dut.hostname,
            bp_iface_in_use_before_shutdown,
        )

        toggle_port_channel_member(
            dut,
            dst_asic,
            bp_iface_in_use_before_shutdown,
            request,
            "startup",
        )

        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(dut, src_asic_next_hops.values(), src_asic, "Up"),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(dut, dst_asic_next_hops.values(), dst_asic, "Up"),
        )

    @pytest.mark.parametrize("version", ["ipv4", "ipv6"])
    def test_bfd_traffic_local_port_channel_member_shutdown(
        self,
        request,
        tbinfo,
        ptfadapter,
        get_src_dst_asic,
        bfd_cleanup_db,
        version,
    ):
        (
            dut,
            src_asic,
            src_asic_index,
            dst_asic,
            dst_asic_index,
            src_asic_next_hops,
            dst_asic_next_hops,
            src_asic_router_mac,
            backend_port_channels,
        ) = prepare_traffic_test_variables(get_src_dst_asic, request, version)

        dst_neighbor_ip = get_random_bgp_neighbor_ip_of_asic(dut, dst_asic_index, version)
        if not dst_neighbor_ip:
            pytest.skip("No BGP neighbor found on asic{} of dut {}".format(dst_asic_index, dut.hostname))

        ptf_src_port = get_ptf_src_port(src_asic, tbinfo)
        bp_iface_in_use_before_shutdown = get_backend_interface_in_use_by_counter(
            dut,
            self.PACKET_COUNT,
            version,
            src_asic_router_mac,
            ptfadapter,
            ptf_src_port,
            dst_neighbor_ip,
            src_asic_index,
            "tx_ok",
        )

        if not bp_iface_in_use_before_shutdown:
            pytest.fail("No backend interface in use on asic{} of dut {}".format(src_asic_index, dut.hostname))

        toggle_port_channel_member(
            dut,
            src_asic,
            bp_iface_in_use_before_shutdown,
            request,
            "shutdown",
        )

        bp_iface_in_use_after_shutdown = get_backend_interface_in_use_by_counter(
            dut,
            self.PACKET_COUNT,
            version,
            src_asic_router_mac,
            ptfadapter,
            ptf_src_port,
            dst_neighbor_ip,
            src_asic_index,
            "tx_ok",
        )

        assert_bp_iface_after_shutdown(
            bp_iface_in_use_after_shutdown,
            src_asic_index,
            dut.hostname,
            bp_iface_in_use_before_shutdown,
        )

        toggle_port_channel_member(
            dut,
            src_asic,
            bp_iface_in_use_before_shutdown,
            request,
            "startup",
        )

        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(dut, src_asic_next_hops.values(), src_asic, "Up"),
        )
        assert wait_until(
            180,
            10,
            0,
            lambda: verify_bfd_state(dut, dst_asic_next_hops.values(), dst_asic, "Up"),
        )
