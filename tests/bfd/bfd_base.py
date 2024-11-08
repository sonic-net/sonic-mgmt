import logging
import random

import pytest

from tests.bfd.bfd_helpers import prepare_bfd_state, selecting_route_to_delete, \
    extract_ip_addresses_for_backend_portchannels, get_dut_asic_static_routes, extract_backend_portchannels, \
    get_src_dst_asic_next_hops
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor

logger = logging.getLogger(__name__)


class BfdBase:
    @pytest.fixture(autouse=True, scope="class")
    def modify_bfd_sessions(self, duthosts):
        """
        1. Gather all front end nodes
        2. Modify BFD state to required state & issue config reload.
        3. Wait for Critical processes
        4. Gather all ASICs for each dut
        5. Calls find_bfd_peers_with_given_state using wait_until
            a. Runs ip netns exec asic{} show bfd sum
            b. If expected state is "Total number of BFD sessions: 0" and it is in result, output is True
            c. If expected state is "Up" and no. of down peers is 0, output is True
            d. If expected state is "Down" and no. of up peers is 0, output is True
        """
        duts = duthosts.frontend_nodes
        try:
            with SafeThreadPoolExecutor(max_workers=8) as executor:
                for dut in duts:
                    executor.submit(prepare_bfd_state, dut, "false", "No BFD sessions found")

            yield

        finally:
            with SafeThreadPoolExecutor(max_workers=8) as executor:
                for dut in duts:
                    executor.submit(prepare_bfd_state, dut, "true", "Up")

    @pytest.fixture(scope="class", name="select_src_dst_dut_and_asic")
    def select_src_dst_dut_and_asic(self, duthosts, tbinfo):
        if (len(duthosts.frontend_nodes)) < 2:
            pytest.skip("Don't have 2 frontend nodes - so can't run multi_dut tests")
        # Random selection of dut indices based on number of front end nodes
        dut_indices = random.sample(list(range(len(duthosts.frontend_nodes))), 2)
        src_dut_index = dut_indices[0]
        dst_dut_index = dut_indices[1]

        # Random selection of source asic based on number of asics available on source dut
        src_asic_index_selection = random.choice(
            duthosts.frontend_nodes[src_dut_index].get_asic_namespace_list()
        )
        src_asic_index = src_asic_index_selection.split("asic")[1]

        # Random selection of destination asic based on number of asics available on destination dut
        dst_asic_index_selection = random.choice(
            duthosts.frontend_nodes[dst_dut_index].get_asic_namespace_list()
        )
        dst_asic_index = dst_asic_index_selection.split("asic")[1]

        yield {
            "src_dut_index": src_dut_index,
            "dst_dut_index": dst_dut_index,
            "src_asic_index": int(src_asic_index),
            "dst_asic_index": int(dst_asic_index),
        }

    @pytest.fixture(scope="class")
    def get_src_dst_asic_and_duts(self, duthosts, select_src_dst_dut_and_asic):
        logger.info("Printing select_src_dst_dut_and_asic")
        logger.info(select_src_dst_dut_and_asic)

        logger.info("Printing duthosts.frontend_nodes")
        logger.info(duthosts.frontend_nodes)
        src_dut = duthosts.frontend_nodes[select_src_dst_dut_and_asic["src_dut_index"]]
        dst_dut = duthosts.frontend_nodes[select_src_dst_dut_and_asic["dst_dut_index"]]

        logger.info("Printing source dut asics")
        logger.info(src_dut.asics)
        logger.info("Printing destination dut asics")
        logger.info(dst_dut.asics)
        src_asic = src_dut.asics[select_src_dst_dut_and_asic["src_asic_index"]]
        dst_asic = dst_dut.asics[select_src_dst_dut_and_asic["dst_asic_index"]]

        all_asics = [src_asic, dst_asic]
        all_duts = [src_dut, dst_dut]

        rtn_dict = {
            "src_asic": src_asic,
            "dst_asic": dst_asic,
            "src_dut": src_dut,
            "dst_dut": dst_dut,
            "all_asics": all_asics,
            "all_duts": all_duts,
        }
        rtn_dict.update(select_src_dst_dut_and_asic)
        yield rtn_dict

    @pytest.fixture(scope="class", params=["ipv4", "ipv6"])
    def select_src_dst_dut_with_asic(self, request, get_src_dst_asic_and_duts):
        logger.info(
            "Selecting Source dut, destination dut, source asic, destination asic, source prefix, destination prefix"
        )

        version = request.param
        logger.info("Version: %s", version)

        # Random selection of dut & asic.
        src_asic = get_src_dst_asic_and_duts["src_asic"]
        dst_asic = get_src_dst_asic_and_duts["dst_asic"]
        src_dut = get_src_dst_asic_and_duts["src_dut"]
        dst_dut = get_src_dst_asic_and_duts["dst_dut"]

        logger.info("Source Asic: %s", src_asic)
        logger.info("Destination Asic: %s", dst_asic)
        logger.info("Source dut: %s", src_dut)
        logger.info("Destination dut: %s", dst_dut)

        request.config.src_asic = src_asic
        request.config.dst_asic = dst_asic
        request.config.src_dut = src_dut
        request.config.dst_dut = dst_dut

        src_asic_routes = get_dut_asic_static_routes(version, src_dut)
        dst_asic_routes = get_dut_asic_static_routes(version, dst_dut)

        # Extracting nexthops
        dst_dut_nexthops = (
            extract_ip_addresses_for_backend_portchannels(
                src_dut, src_asic, version
            )
        )
        logger.info("Destination nexthops, {}".format(dst_dut_nexthops))
        assert len(dst_dut_nexthops) != 0, "Destination Nexthops are empty"

        src_dut_nexthops = (
            extract_ip_addresses_for_backend_portchannels(
                dst_dut, dst_asic, version
            )
        )
        logger.info("Source nexthops, {}".format(src_dut_nexthops))
        assert len(src_dut_nexthops) != 0, "Source Nexthops are empty"

        # Picking a static route to delete corresponding BFD session
        src_prefix = selecting_route_to_delete(
            src_asic_routes, src_dut_nexthops.values()
        )
        logger.info("Source prefix: %s", src_prefix)
        request.config.src_prefix = src_prefix
        assert src_prefix is not None and src_prefix != "", "Source prefix not found"

        dst_prefix = selecting_route_to_delete(
            dst_asic_routes, dst_dut_nexthops.values()
        )
        logger.info("Destination prefix: %s", dst_prefix)
        request.config.dst_prefix = dst_prefix
        assert (
            dst_prefix is not None and dst_prefix != ""
        ), "Destination prefix not found"

        yield {
            "src_asic": src_asic,
            "dst_asic": dst_asic,
            "src_dut": src_dut,
            "dst_dut": dst_dut,
            "src_dut_nexthops": src_dut_nexthops,
            "dst_dut_nexthops": dst_dut_nexthops,
            "src_prefix": src_prefix,
            "dst_prefix": dst_prefix,
            "version": version,
        }

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
