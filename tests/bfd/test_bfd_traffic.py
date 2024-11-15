import logging
import random

import pytest

from tests.bfd.bfd_helpers import get_ptf_src_port, get_backend_interface_in_use_by_counter, \
    get_random_bgp_neighbor_ip_of_asic, toggle_port_channel_or_member, get_port_channel_by_member, \
    wait_until_given_bfd_down, assert_traffic_switching, verify_bfd_only, extract_backend_portchannels, \
    get_src_dst_asic_next_hops
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor

pytestmark = [pytest.mark.topology("t2")]

logger = logging.getLogger(__name__)


class TestBfdTraffic:
    PACKET_COUNT = 10000

    @pytest.fixture(scope="class")
    def select_dut_and_src_dst_asic_index(self, duthosts):
        if not duthosts.frontend_nodes:
            pytest.skip("DUT does not have any frontend nodes")

        dut_index = random.choice(list(range(len(duthosts.frontend_nodes))))
        asic_namespace_list = duthosts.frontend_nodes[dut_index].get_asic_namespace_list()
        if len(asic_namespace_list) < 2:
            pytest.skip("DUT does not have more than one ASICs")

        # Random selection of src asic & dst asic on DUT
        src_asic_namespace, dst_asic_namespace = random.sample(asic_namespace_list, 2)
        src_asic_index = src_asic_namespace.split("asic")[1]
        dst_asic_index = dst_asic_namespace.split("asic")[1]

        yield {
            "dut_index": dut_index,
            "src_asic_index": int(src_asic_index),
            "dst_asic_index": int(dst_asic_index),
        }

    @pytest.fixture(scope="class")
    def get_src_dst_asic(self, request, duthosts, select_dut_and_src_dst_asic_index):
        logger.info("Printing select_dut_and_src_dst_asic_index")
        logger.info(select_dut_and_src_dst_asic_index)

        logger.info("Printing duthosts.frontend_nodes")
        logger.info(duthosts.frontend_nodes)
        dut = duthosts.frontend_nodes[select_dut_and_src_dst_asic_index["dut_index"]]

        logger.info("Printing dut asics")
        logger.info(dut.asics)

        src_asic = dut.asics[select_dut_and_src_dst_asic_index["src_asic_index"]]
        dst_asic = dut.asics[select_dut_and_src_dst_asic_index["dst_asic_index"]]

        request.config.src_asic = src_asic
        request.config.dst_asic = dst_asic
        request.config.dut = dut

        rtn_dict = {
            "src_asic": src_asic,
            "dst_asic": dst_asic,
            "dut": dut,
        }

        rtn_dict.update(select_dut_and_src_dst_asic_index)
        yield rtn_dict

    @pytest.fixture(scope="class", params=["ipv4", "ipv6"])
    def prepare_traffic_test_variables(self, get_src_dst_asic, request):
        version = request.param
        logger.info("Version: %s", version)

        dut = get_src_dst_asic["dut"]
        src_asic = get_src_dst_asic["src_asic"]
        src_asic_index = get_src_dst_asic["src_asic_index"]
        dst_asic = get_src_dst_asic["dst_asic"]
        dst_asic_index = get_src_dst_asic["dst_asic_index"]
        logger.info(
            "DUT: {}, src_asic_index: {}, dst_asic_index: {}".format(dut.hostname, src_asic_index, dst_asic_index)
        )

        backend_port_channels = extract_backend_portchannels(dut)
        src_asic_next_hops, dst_asic_next_hops, src_prefix, dst_prefix = get_src_dst_asic_next_hops(
            version,
            dut,
            src_asic,
            dst_asic,
            request,
            backend_port_channels,
        )

        src_asic_router_mac = src_asic.get_router_mac()

        yield {
            "dut": dut,
            "src_asic": src_asic,
            "src_asic_index": src_asic_index,
            "dst_asic": dst_asic,
            "dst_asic_index": dst_asic_index,
            "src_asic_next_hops": src_asic_next_hops,
            "dst_asic_next_hops": dst_asic_next_hops,
            "src_prefix": src_prefix,
            "dst_prefix": dst_prefix,
            "src_asic_router_mac": src_asic_router_mac,
            "backend_port_channels": backend_port_channels,
            "version": version,
        }

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
