import logging
import random

import pytest

from tests.bfd.bfd_helpers import get_ptf_src_port, get_backend_interface_in_use_by_counter, \
    get_random_bgp_neighbor_ip_of_asic, toggle_port_channel_or_member, get_port_channel_by_member, \
    wait_until_given_bfd_down, assert_traffic_switching, verify_bfd_only, extract_backend_portchannels, \
    get_src_dst_asic_next_hops, get_upstream_and_downstream_dut_pool
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor

pytestmark = [
    pytest.mark.topology("t2"),
    pytest.mark.device_type('physical')
]

logger = logging.getLogger(__name__)


class TestBfdTraffic:
    PACKET_COUNT = 10000

    @pytest.fixture(scope="class")
    def get_src_dst_asic(self, request, duthosts):
        if not duthosts.frontend_nodes:
            pytest.skip("DUT does not have any frontend nodes")

        src_dut_pool, dst_dut_pool = get_upstream_and_downstream_dut_pool(duthosts.frontend_nodes)
        if not src_dut_pool or not dst_dut_pool:
            pytest.skip("No upstream or downstream DUTs found")

        src_dut_index = random.choice(list(range(len(src_dut_pool))))
        dst_dut_index = random.choice(list(range(len(dst_dut_pool))))
        src_dut = src_dut_pool[src_dut_index]
        dst_dut = dst_dut_pool[dst_dut_index]
        src_asic_namespace_list = src_dut.get_asic_namespace_list()
        dst_asic_namespace_list = dst_dut.get_asic_namespace_list()
        if not src_asic_namespace_list or not dst_asic_namespace_list:
            pytest.skip("No asic namespaces found on source or destination DUT")

        src_asic_namespace = random.choice(src_asic_namespace_list)
        dst_asic_namespace = random.choice(dst_asic_namespace_list)
        src_asic_index = int(src_asic_namespace.split("asic")[1])
        dst_asic_index = int(dst_asic_namespace.split("asic")[1])
        src_asic = src_dut.asics[src_asic_index]
        dst_asic = dst_dut.asics[dst_asic_index]

        yield {
            "src_dut": src_dut,
            "src_asic": src_asic,
            "src_asic_index": src_asic_index,
            "dst_dut": dst_dut,
            "dst_asic": dst_asic,
            "dst_asic_index": dst_asic_index,
        }

    @pytest.fixture(scope="class", params=["ipv4", "ipv6"])
    def prepare_traffic_test_variables(self, get_src_dst_asic, request):
        version = request.param
        logger.info("Version: %s", version)

        src_dut = get_src_dst_asic["src_dut"]
        src_asic = get_src_dst_asic["src_asic"]
        src_asic_index = get_src_dst_asic["src_asic_index"]
        dst_dut = get_src_dst_asic["dst_dut"]
        dst_asic = get_src_dst_asic["dst_asic"]
        dst_asic_index = get_src_dst_asic["dst_asic_index"]
        logger.info(
            "src_dut: {}, src_asic_index: {}, dst_dut: {}, dst_asic_index: {}".format(
                src_dut.hostname,
                src_asic_index,
                dst_dut.hostname,
                dst_asic_index,
            )
        )

        src_backend_port_channels = extract_backend_portchannels(src_dut)
        dst_backend_port_channels = extract_backend_portchannels(dst_dut)
        src_asic_next_hops, dst_asic_next_hops = get_src_dst_asic_next_hops(
            version,
            src_dut,
            src_asic,
            src_backend_port_channels,
            dst_dut,
            dst_asic,
            dst_backend_port_channels,
        )

        src_asic_router_mac = src_asic.get_router_mac()

        yield {
            "src_dut": src_dut,
            "src_asic": src_asic,
            "src_asic_index": src_asic_index,
            "dst_dut": dst_dut,
            "dst_asic": dst_asic,
            "dst_asic_index": dst_asic_index,
            "src_asic_next_hops": src_asic_next_hops,
            "dst_asic_next_hops": dst_asic_next_hops,
            "src_asic_router_mac": src_asic_router_mac,
            "src_backend_port_channels": src_backend_port_channels,
            "dst_backend_port_channels": dst_backend_port_channels,
            "version": version,
        }

    def test_bfd_traffic_remote_port_channel_shutdown(self, request, tbinfo, ptfadapter,
                                                      prepare_traffic_test_variables, bfd_cleanup_db):
        src_dut = prepare_traffic_test_variables["src_dut"]
        src_asic = prepare_traffic_test_variables["src_asic"]
        src_asic_index = prepare_traffic_test_variables["src_asic_index"]
        dst_dut = prepare_traffic_test_variables["dst_dut"]
        dst_asic = prepare_traffic_test_variables["dst_asic"]
        dst_asic_index = prepare_traffic_test_variables["dst_asic_index"]
        src_asic_next_hops = prepare_traffic_test_variables["src_asic_next_hops"]
        dst_asic_next_hops = prepare_traffic_test_variables["dst_asic_next_hops"]
        src_asic_router_mac = prepare_traffic_test_variables["src_asic_router_mac"]
        src_backend_port_channels = prepare_traffic_test_variables["src_backend_port_channels"]
        dst_backend_port_channels = prepare_traffic_test_variables["dst_backend_port_channels"]
        version = prepare_traffic_test_variables["version"]

        dst_neighbor_ip = get_random_bgp_neighbor_ip_of_asic(dst_dut, dst_asic_index, version)
        if not dst_neighbor_ip:
            pytest.skip("No BGP neighbor found on asic{} of dut {}".format(dst_asic_index, dst_dut.hostname))

        ptf_src_port = get_ptf_src_port(src_asic, tbinfo)
        src_bp_iface_before_shutdown, dst_bp_iface_before_shutdown = get_backend_interface_in_use_by_counter(
            src_dut,
            dst_dut,
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
            dst_backend_port_channels,
            dst_bp_iface_before_shutdown,
        )

        if not dst_port_channel_before_shutdown:
            pytest.fail("No port channel found with interface in use")

        toggle_port_channel_or_member(
            dst_port_channel_before_shutdown,
            dst_dut,
            dst_asic,
            request,
            "shutdown",
        )

        src_port_channel_before_shutdown = get_port_channel_by_member(
            src_backend_port_channels,
            src_bp_iface_before_shutdown,
        )

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for next_hops, port_channel, asic_index, dut in [
                (src_asic_next_hops, dst_port_channel_before_shutdown, src_asic_index, src_dut),
                (dst_asic_next_hops, src_port_channel_before_shutdown, dst_asic_index, dst_dut),
            ]:
                executor.submit(wait_until_given_bfd_down, next_hops, port_channel, asic_index, dut)

        src_bp_iface_after_shutdown, dst_bp_iface_after_shutdown = get_backend_interface_in_use_by_counter(
            src_dut,
            dst_dut,
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
            src_dut,
            dst_dut,
            src_backend_port_channels,
            dst_backend_port_channels,
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
            dst_dut,
            dst_asic,
            request,
            "startup",
        )

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for dut, next_hops, asic in [
                (src_dut, src_asic_next_hops, src_asic),
                (dst_dut, dst_asic_next_hops, dst_asic),
            ]:
                executor.submit(verify_bfd_only, dut, next_hops, asic, "Up")

    def test_bfd_traffic_local_port_channel_shutdown(self, request, tbinfo, ptfadapter,
                                                     prepare_traffic_test_variables, bfd_cleanup_db):
        src_dut = prepare_traffic_test_variables["src_dut"]
        src_asic = prepare_traffic_test_variables["src_asic"]
        src_asic_index = prepare_traffic_test_variables["src_asic_index"]
        dst_dut = prepare_traffic_test_variables["dst_dut"]
        dst_asic = prepare_traffic_test_variables["dst_asic"]
        dst_asic_index = prepare_traffic_test_variables["dst_asic_index"]
        src_asic_next_hops = prepare_traffic_test_variables["src_asic_next_hops"]
        dst_asic_next_hops = prepare_traffic_test_variables["dst_asic_next_hops"]
        src_asic_router_mac = prepare_traffic_test_variables["src_asic_router_mac"]
        src_backend_port_channels = prepare_traffic_test_variables["src_backend_port_channels"]
        dst_backend_port_channels = prepare_traffic_test_variables["dst_backend_port_channels"]
        version = prepare_traffic_test_variables["version"]

        dst_neighbor_ip = get_random_bgp_neighbor_ip_of_asic(dst_dut, dst_asic_index, version)
        if not dst_neighbor_ip:
            pytest.skip("No BGP neighbor found on asic{} of dut {}".format(dst_asic_index, dst_dut.hostname))

        ptf_src_port = get_ptf_src_port(src_asic, tbinfo)
        src_bp_iface_before_shutdown, dst_bp_iface_before_shutdown = get_backend_interface_in_use_by_counter(
            src_dut,
            dst_dut,
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
            src_backend_port_channels,
            src_bp_iface_before_shutdown,
        )

        if not src_port_channel_before_shutdown:
            pytest.fail("No port channel found with interface in use")

        toggle_port_channel_or_member(
            src_port_channel_before_shutdown,
            src_dut,
            src_asic,
            request,
            "shutdown",
        )

        dst_port_channel_before_shutdown = get_port_channel_by_member(
            dst_backend_port_channels,
            dst_bp_iface_before_shutdown,
        )

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for next_hops, port_channel, asic_index, dut in [
                (src_asic_next_hops, dst_port_channel_before_shutdown, src_asic_index, src_dut),
                (dst_asic_next_hops, src_port_channel_before_shutdown, dst_asic_index, dst_dut),
            ]:
                executor.submit(wait_until_given_bfd_down, next_hops, port_channel, asic_index, dut)

        src_bp_iface_after_shutdown, dst_bp_iface_after_shutdown = get_backend_interface_in_use_by_counter(
            src_dut,
            dst_dut,
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
            src_dut,
            dst_dut,
            src_backend_port_channels,
            dst_backend_port_channels,
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
            src_dut,
            src_asic,
            request,
            "startup",
        )

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for dut, next_hops, asic in [
                (src_dut, src_asic_next_hops, src_asic),
                (dst_dut, dst_asic_next_hops, dst_asic),
            ]:
                executor.submit(verify_bfd_only, dut, next_hops, asic, "Up")

    def test_bfd_traffic_remote_port_channel_member_shutdown(self, request, tbinfo, ptfadapter,
                                                             prepare_traffic_test_variables, bfd_cleanup_db):
        src_dut = prepare_traffic_test_variables["src_dut"]
        src_asic = prepare_traffic_test_variables["src_asic"]
        src_asic_index = prepare_traffic_test_variables["src_asic_index"]
        dst_dut = prepare_traffic_test_variables["dst_dut"]
        dst_asic = prepare_traffic_test_variables["dst_asic"]
        dst_asic_index = prepare_traffic_test_variables["dst_asic_index"]
        src_asic_next_hops = prepare_traffic_test_variables["src_asic_next_hops"]
        dst_asic_next_hops = prepare_traffic_test_variables["dst_asic_next_hops"]
        src_asic_router_mac = prepare_traffic_test_variables["src_asic_router_mac"]
        src_backend_port_channels = prepare_traffic_test_variables["src_backend_port_channels"]
        dst_backend_port_channels = prepare_traffic_test_variables["dst_backend_port_channels"]
        version = prepare_traffic_test_variables["version"]

        dst_neighbor_ip = get_random_bgp_neighbor_ip_of_asic(dst_dut, dst_asic_index, version)
        if not dst_neighbor_ip:
            pytest.skip("No BGP neighbor found on asic{} of dut {}".format(dst_asic_index, dst_dut.hostname))

        ptf_src_port = get_ptf_src_port(src_asic, tbinfo)
        src_bp_iface_before_shutdown, dst_bp_iface_before_shutdown = get_backend_interface_in_use_by_counter(
            src_dut,
            dst_dut,
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
            src_backend_port_channels,
            src_bp_iface_before_shutdown,
        )

        dst_port_channel_before_shutdown = get_port_channel_by_member(
            dst_backend_port_channels,
            dst_bp_iface_before_shutdown,
        )

        if not src_port_channel_before_shutdown or not dst_port_channel_before_shutdown:
            pytest.fail("No port channel found with interface in use")

        toggle_port_channel_or_member(
            dst_bp_iface_before_shutdown,
            dst_dut,
            dst_asic,
            request,
            "shutdown",
        )

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for next_hops, port_channel, asic_index, dut in [
                (src_asic_next_hops, dst_port_channel_before_shutdown, src_asic_index, src_dut),
                (dst_asic_next_hops, src_port_channel_before_shutdown, dst_asic_index, dst_dut),
            ]:
                executor.submit(wait_until_given_bfd_down, next_hops, port_channel, asic_index, dut)

        src_bp_iface_after_shutdown, dst_bp_iface_after_shutdown = get_backend_interface_in_use_by_counter(
            src_dut,
            dst_dut,
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
            src_dut,
            dst_dut,
            src_backend_port_channels,
            dst_backend_port_channels,
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
            dst_dut,
            dst_asic,
            request,
            "startup",
        )

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for dut, next_hops, asic in [
                (src_dut, src_asic_next_hops, src_asic),
                (dst_dut, dst_asic_next_hops, dst_asic),
            ]:
                executor.submit(verify_bfd_only, dut, next_hops, asic, "Up")

    def test_bfd_traffic_local_port_channel_member_shutdown(self, request, tbinfo, ptfadapter,
                                                            prepare_traffic_test_variables, bfd_cleanup_db):
        src_dut = prepare_traffic_test_variables["src_dut"]
        src_asic = prepare_traffic_test_variables["src_asic"]
        src_asic_index = prepare_traffic_test_variables["src_asic_index"]
        dst_dut = prepare_traffic_test_variables["dst_dut"]
        dst_asic = prepare_traffic_test_variables["dst_asic"]
        dst_asic_index = prepare_traffic_test_variables["dst_asic_index"]
        src_asic_next_hops = prepare_traffic_test_variables["src_asic_next_hops"]
        dst_asic_next_hops = prepare_traffic_test_variables["dst_asic_next_hops"]
        src_asic_router_mac = prepare_traffic_test_variables["src_asic_router_mac"]
        src_backend_port_channels = prepare_traffic_test_variables["src_backend_port_channels"]
        dst_backend_port_channels = prepare_traffic_test_variables["dst_backend_port_channels"]
        version = prepare_traffic_test_variables["version"]

        dst_neighbor_ip = get_random_bgp_neighbor_ip_of_asic(dst_dut, dst_asic_index, version)
        if not dst_neighbor_ip:
            pytest.skip("No BGP neighbor found on asic{} of dut {}".format(dst_asic_index, dst_dut.hostname))

        ptf_src_port = get_ptf_src_port(src_asic, tbinfo)
        src_bp_iface_before_shutdown, dst_bp_iface_before_shutdown = get_backend_interface_in_use_by_counter(
            src_dut,
            dst_dut,
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
            src_backend_port_channels,
            src_bp_iface_before_shutdown,
        )

        dst_port_channel_before_shutdown = get_port_channel_by_member(
            dst_backend_port_channels,
            dst_bp_iface_before_shutdown,
        )

        if not src_port_channel_before_shutdown or not dst_port_channel_before_shutdown:
            pytest.fail("No port channel found with interface in use")

        toggle_port_channel_or_member(
            src_bp_iface_before_shutdown,
            src_dut,
            src_asic,
            request,
            "shutdown",
        )

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for next_hops, port_channel, asic_index, dut in [
                (src_asic_next_hops, dst_port_channel_before_shutdown, src_asic_index, src_dut),
                (dst_asic_next_hops, src_port_channel_before_shutdown, dst_asic_index, dst_dut),
            ]:
                executor.submit(wait_until_given_bfd_down, next_hops, port_channel, asic_index, dut)

        src_bp_iface_after_shutdown, dst_bp_iface_after_shutdown = get_backend_interface_in_use_by_counter(
            src_dut,
            dst_dut,
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
            src_dut,
            dst_dut,
            src_backend_port_channels,
            dst_backend_port_channels,
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
            src_dut,
            src_asic,
            request,
            "startup",
        )

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for dut, next_hops, asic in [
                (src_dut, src_asic_next_hops, src_asic),
                (dst_dut, dst_asic_next_hops, dst_asic),
            ]:
                executor.submit(verify_bfd_only, dut, next_hops, asic, "Up")
