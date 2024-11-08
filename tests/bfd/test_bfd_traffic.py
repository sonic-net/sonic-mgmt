import logging

import pytest

from tests.bfd.bfd_base import BfdBase
from tests.bfd.bfd_helpers import get_ptf_src_port, get_backend_interface_in_use_by_counter, \
    get_random_bgp_neighbor_ip_of_asic, toggle_port_channel_or_member, get_port_channel_by_member, \
    wait_until_given_bfd_down, assert_traffic_switching, create_and_verify_bfd_state, verify_bfd_only
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor

pytestmark = [
    pytest.mark.topology("t2"),
    pytest.mark.device_type('physical')
]

logger = logging.getLogger(__name__)


class TestBfdTraffic(BfdBase):
    PACKET_COUNT = 10000

    def test_bfd_traffic_remote_port_channel_shutdown(
        self,
        request,
        tbinfo,
        ptfadapter,
        prepare_traffic_test_variables,
        bfd_cleanup_db,
    ):
        dut = prepare_traffic_test_variables["dut"]
        src_asic = prepare_traffic_test_variables["src_asic"]
        src_asic_index = prepare_traffic_test_variables["src_asic_index"]
        dst_asic = prepare_traffic_test_variables["dst_asic"]
        dst_asic_index = prepare_traffic_test_variables["dst_asic_index"]
        src_asic_next_hops = prepare_traffic_test_variables["src_asic_next_hops"]
        dst_asic_next_hops = prepare_traffic_test_variables["dst_asic_next_hops"]
        src_prefix = prepare_traffic_test_variables["src_prefix"]
        dst_prefix = prepare_traffic_test_variables["dst_prefix"]
        src_asic_router_mac = prepare_traffic_test_variables["src_asic_router_mac"]
        backend_port_channels = prepare_traffic_test_variables["backend_port_channels"]
        version = prepare_traffic_test_variables["version"]
        src_dst_context = [
            ("src", src_asic, src_prefix, src_asic_next_hops),
            ("dst", dst_asic, dst_prefix, dst_asic_next_hops),
        ]

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, next_hops in src_dst_context:
                executor.submit(create_and_verify_bfd_state, asic, prefix, dut, next_hops)

        dst_neighbor_ip = get_random_bgp_neighbor_ip_of_asic(dut, dst_asic_index, version)
        if not dst_neighbor_ip:
            pytest.skip("No BGP neighbor found on asic{} of dut {}".format(dst_asic_index, dut.hostname))

        ptf_src_port = get_ptf_src_port(src_asic, tbinfo)
        src_bp_iface_before_shutdown, dst_bp_iface_before_shutdown = get_backend_interface_in_use_by_counter(
            dut,
            self.PACKET_COUNT,
            version,
            src_asic_router_mac,
            ptfadapter,
            ptf_src_port,
            dst_neighbor_ip,
            src_asic_index,
            dst_asic_index,
        )

        dst_port_channel_before_shutdown = get_port_channel_by_member(
            backend_port_channels,
            dst_bp_iface_before_shutdown,
        )

        if not dst_port_channel_before_shutdown:
            pytest.fail("No port channel found with interface in use")

        toggle_port_channel_or_member(
            dst_port_channel_before_shutdown,
            dut,
            dst_asic,
            request,
            "shutdown",
        )

        src_port_channel_before_shutdown = get_port_channel_by_member(
            backend_port_channels,
            src_bp_iface_before_shutdown,
        )

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for next_hops, port_channel, asic_index in [
                (src_asic_next_hops, dst_port_channel_before_shutdown, src_asic_index),
                (dst_asic_next_hops, src_port_channel_before_shutdown, dst_asic_index),
            ]:
                executor.submit(wait_until_given_bfd_down, next_hops, port_channel, asic_index, dut)

        src_bp_iface_after_shutdown, dst_bp_iface_after_shutdown = get_backend_interface_in_use_by_counter(
            dut,
            self.PACKET_COUNT,
            version,
            src_asic_router_mac,
            ptfadapter,
            ptf_src_port,
            dst_neighbor_ip,
            src_asic_index,
            dst_asic_index,
        )

        assert_traffic_switching(
            dut,
            backend_port_channels,
            src_asic_index,
            src_bp_iface_before_shutdown,
            src_bp_iface_after_shutdown,
            src_port_channel_before_shutdown,
            dst_asic_index,
            dst_bp_iface_after_shutdown,
            dst_bp_iface_before_shutdown,
            dst_port_channel_before_shutdown,
        )

        toggle_port_channel_or_member(
            dst_port_channel_before_shutdown,
            dut,
            dst_asic,
            request,
            "startup",
        )

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, _, next_hops in src_dst_context:
                executor.submit(verify_bfd_only, dut, next_hops, asic, "Up")

    def test_bfd_traffic_local_port_channel_shutdown(
        self,
        request,
        tbinfo,
        ptfadapter,
        prepare_traffic_test_variables,
        bfd_cleanup_db,
    ):
        dut = prepare_traffic_test_variables["dut"]
        src_asic = prepare_traffic_test_variables["src_asic"]
        src_asic_index = prepare_traffic_test_variables["src_asic_index"]
        dst_asic = prepare_traffic_test_variables["dst_asic"]
        dst_asic_index = prepare_traffic_test_variables["dst_asic_index"]
        src_asic_next_hops = prepare_traffic_test_variables["src_asic_next_hops"]
        dst_asic_next_hops = prepare_traffic_test_variables["dst_asic_next_hops"]
        src_prefix = prepare_traffic_test_variables["src_prefix"]
        dst_prefix = prepare_traffic_test_variables["dst_prefix"]
        src_asic_router_mac = prepare_traffic_test_variables["src_asic_router_mac"]
        backend_port_channels = prepare_traffic_test_variables["backend_port_channels"]
        version = prepare_traffic_test_variables["version"]
        src_dst_context = [
            ("src", src_asic, src_prefix, src_asic_next_hops),
            ("dst", dst_asic, dst_prefix, dst_asic_next_hops),
        ]

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, next_hops in src_dst_context:
                executor.submit(create_and_verify_bfd_state, asic, prefix, dut, next_hops)

        dst_neighbor_ip = get_random_bgp_neighbor_ip_of_asic(dut, dst_asic_index, version)
        if not dst_neighbor_ip:
            pytest.skip("No BGP neighbor found on asic{} of dut {}".format(dst_asic_index, dut.hostname))

        ptf_src_port = get_ptf_src_port(src_asic, tbinfo)
        src_bp_iface_before_shutdown, dst_bp_iface_before_shutdown = get_backend_interface_in_use_by_counter(
            dut,
            self.PACKET_COUNT,
            version,
            src_asic_router_mac,
            ptfadapter,
            ptf_src_port,
            dst_neighbor_ip,
            src_asic_index,
            dst_asic_index,
        )

        src_port_channel_before_shutdown = get_port_channel_by_member(
            backend_port_channels,
            src_bp_iface_before_shutdown,
        )

        if not src_port_channel_before_shutdown:
            pytest.fail("No port channel found with interface in use")

        toggle_port_channel_or_member(
            src_port_channel_before_shutdown,
            dut,
            src_asic,
            request,
            "shutdown",
        )

        dst_port_channel_before_shutdown = get_port_channel_by_member(
            backend_port_channels,
            dst_bp_iface_before_shutdown,
        )

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for next_hops, port_channel, asic_index in [
                (src_asic_next_hops, dst_port_channel_before_shutdown, src_asic_index),
                (dst_asic_next_hops, src_port_channel_before_shutdown, dst_asic_index),
            ]:
                executor.submit(wait_until_given_bfd_down, next_hops, port_channel, asic_index, dut)

        src_bp_iface_after_shutdown, dst_bp_iface_after_shutdown = get_backend_interface_in_use_by_counter(
            dut,
            self.PACKET_COUNT,
            version,
            src_asic_router_mac,
            ptfadapter,
            ptf_src_port,
            dst_neighbor_ip,
            src_asic_index,
            dst_asic_index,
        )

        assert_traffic_switching(
            dut,
            backend_port_channels,
            src_asic_index,
            src_bp_iface_before_shutdown,
            src_bp_iface_after_shutdown,
            src_port_channel_before_shutdown,
            dst_asic_index,
            dst_bp_iface_after_shutdown,
            dst_bp_iface_before_shutdown,
            dst_port_channel_before_shutdown,
        )

        toggle_port_channel_or_member(
            src_port_channel_before_shutdown,
            dut,
            src_asic,
            request,
            "startup",
        )

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, _, next_hops in src_dst_context:
                executor.submit(verify_bfd_only, dut, next_hops, asic, "Up")

    def test_bfd_traffic_remote_port_channel_member_shutdown(
        self,
        request,
        tbinfo,
        ptfadapter,
        prepare_traffic_test_variables,
        bfd_cleanup_db,
    ):
        dut = prepare_traffic_test_variables["dut"]
        src_asic = prepare_traffic_test_variables["src_asic"]
        src_asic_index = prepare_traffic_test_variables["src_asic_index"]
        dst_asic = prepare_traffic_test_variables["dst_asic"]
        dst_asic_index = prepare_traffic_test_variables["dst_asic_index"]
        src_asic_next_hops = prepare_traffic_test_variables["src_asic_next_hops"]
        dst_asic_next_hops = prepare_traffic_test_variables["dst_asic_next_hops"]
        src_prefix = prepare_traffic_test_variables["src_prefix"]
        dst_prefix = prepare_traffic_test_variables["dst_prefix"]
        src_asic_router_mac = prepare_traffic_test_variables["src_asic_router_mac"]
        backend_port_channels = prepare_traffic_test_variables["backend_port_channels"]
        version = prepare_traffic_test_variables["version"]
        src_dst_context = [
            ("src", src_asic, src_prefix, src_asic_next_hops),
            ("dst", dst_asic, dst_prefix, dst_asic_next_hops),
        ]

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, next_hops in src_dst_context:
                executor.submit(create_and_verify_bfd_state, asic, prefix, dut, next_hops)

        dst_neighbor_ip = get_random_bgp_neighbor_ip_of_asic(dut, dst_asic_index, version)
        if not dst_neighbor_ip:
            pytest.skip("No BGP neighbor found on asic{} of dut {}".format(dst_asic_index, dut.hostname))

        ptf_src_port = get_ptf_src_port(src_asic, tbinfo)
        src_bp_iface_before_shutdown, dst_bp_iface_before_shutdown = get_backend_interface_in_use_by_counter(
            dut,
            self.PACKET_COUNT,
            version,
            src_asic_router_mac,
            ptfadapter,
            ptf_src_port,
            dst_neighbor_ip,
            src_asic_index,
            dst_asic_index,
        )

        toggle_port_channel_or_member(
            dst_bp_iface_before_shutdown,
            dut,
            dst_asic,
            request,
            "shutdown",
        )

        src_port_channel_before_shutdown = get_port_channel_by_member(
            backend_port_channels,
            src_bp_iface_before_shutdown,
        )

        dst_port_channel_before_shutdown = get_port_channel_by_member(
            backend_port_channels,
            dst_bp_iface_before_shutdown,
        )

        if not src_port_channel_before_shutdown or not dst_port_channel_before_shutdown:
            pytest.fail("No port channel found with interface in use")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for next_hops, port_channel, asic_index in [
                (src_asic_next_hops, dst_port_channel_before_shutdown, src_asic_index),
                (dst_asic_next_hops, src_port_channel_before_shutdown, dst_asic_index),
            ]:
                executor.submit(wait_until_given_bfd_down, next_hops, port_channel, asic_index, dut)

        src_bp_iface_after_shutdown, dst_bp_iface_after_shutdown = get_backend_interface_in_use_by_counter(
            dut,
            self.PACKET_COUNT,
            version,
            src_asic_router_mac,
            ptfadapter,
            ptf_src_port,
            dst_neighbor_ip,
            src_asic_index,
            dst_asic_index,
        )

        assert_traffic_switching(
            dut,
            backend_port_channels,
            src_asic_index,
            src_bp_iface_before_shutdown,
            src_bp_iface_after_shutdown,
            src_port_channel_before_shutdown,
            dst_asic_index,
            dst_bp_iface_after_shutdown,
            dst_bp_iface_before_shutdown,
            dst_port_channel_before_shutdown,
        )

        toggle_port_channel_or_member(
            dst_bp_iface_before_shutdown,
            dut,
            dst_asic,
            request,
            "startup",
        )

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, _, next_hops in src_dst_context:
                executor.submit(verify_bfd_only, dut, next_hops, asic, "Up")

    def test_bfd_traffic_local_port_channel_member_shutdown(
        self,
        request,
        tbinfo,
        ptfadapter,
        prepare_traffic_test_variables,
        bfd_cleanup_db,
    ):
        dut = prepare_traffic_test_variables["dut"]
        src_asic = prepare_traffic_test_variables["src_asic"]
        src_asic_index = prepare_traffic_test_variables["src_asic_index"]
        dst_asic = prepare_traffic_test_variables["dst_asic"]
        dst_asic_index = prepare_traffic_test_variables["dst_asic_index"]
        src_asic_next_hops = prepare_traffic_test_variables["src_asic_next_hops"]
        dst_asic_next_hops = prepare_traffic_test_variables["dst_asic_next_hops"]
        src_prefix = prepare_traffic_test_variables["src_prefix"]
        dst_prefix = prepare_traffic_test_variables["dst_prefix"]
        src_asic_router_mac = prepare_traffic_test_variables["src_asic_router_mac"]
        backend_port_channels = prepare_traffic_test_variables["backend_port_channels"]
        version = prepare_traffic_test_variables["version"]
        src_dst_context = [
            ("src", src_asic, src_prefix, src_asic_next_hops),
            ("dst", dst_asic, dst_prefix, dst_asic_next_hops),
        ]

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, prefix, next_hops in src_dst_context:
                executor.submit(create_and_verify_bfd_state, asic, prefix, dut, next_hops)

        dst_neighbor_ip = get_random_bgp_neighbor_ip_of_asic(dut, dst_asic_index, version)
        if not dst_neighbor_ip:
            pytest.skip("No BGP neighbor found on asic{} of dut {}".format(dst_asic_index, dut.hostname))

        ptf_src_port = get_ptf_src_port(src_asic, tbinfo)
        src_bp_iface_before_shutdown, dst_bp_iface_before_shutdown = get_backend_interface_in_use_by_counter(
            dut,
            self.PACKET_COUNT,
            version,
            src_asic_router_mac,
            ptfadapter,
            ptf_src_port,
            dst_neighbor_ip,
            src_asic_index,
            dst_asic_index,
        )

        toggle_port_channel_or_member(
            src_bp_iface_before_shutdown,
            dut,
            src_asic,
            request,
            "shutdown",
        )

        src_port_channel_before_shutdown = get_port_channel_by_member(
            backend_port_channels,
            src_bp_iface_before_shutdown,
        )

        dst_port_channel_before_shutdown = get_port_channel_by_member(
            backend_port_channels,
            dst_bp_iface_before_shutdown,
        )

        if not src_port_channel_before_shutdown or not dst_port_channel_before_shutdown:
            pytest.fail("No port channel found with interface in use")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for next_hops, port_channel, asic_index in [
                (src_asic_next_hops, dst_port_channel_before_shutdown, src_asic_index),
                (dst_asic_next_hops, src_port_channel_before_shutdown, dst_asic_index),
            ]:
                executor.submit(wait_until_given_bfd_down, next_hops, port_channel, asic_index, dut)

        src_bp_iface_after_shutdown, dst_bp_iface_after_shutdown = get_backend_interface_in_use_by_counter(
            dut,
            self.PACKET_COUNT,
            version,
            src_asic_router_mac,
            ptfadapter,
            ptf_src_port,
            dst_neighbor_ip,
            src_asic_index,
            dst_asic_index,
        )

        assert_traffic_switching(
            dut,
            backend_port_channels,
            src_asic_index,
            src_bp_iface_before_shutdown,
            src_bp_iface_after_shutdown,
            src_port_channel_before_shutdown,
            dst_asic_index,
            dst_bp_iface_after_shutdown,
            dst_bp_iface_before_shutdown,
            dst_port_channel_before_shutdown,
        )

        toggle_port_channel_or_member(
            src_bp_iface_before_shutdown,
            dut,
            src_asic,
            request,
            "startup",
        )

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for _, asic, _, next_hops in src_dst_context:
                executor.submit(verify_bfd_only, dut, next_hops, asic, "Up")
