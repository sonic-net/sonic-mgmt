import logging
import random

import pytest

from tests.bfd.bfd_helpers import modify_all_bfd_sessions, find_bfd_peers_with_given_state
from tests.common import config_reload
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until

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
        try:
            duts = duthosts.frontend_nodes
            for dut in duts:
                modify_all_bfd_sessions(dut, "false")
            for dut in duts:
                # config reload
                config_reload(dut)
                wait_critical_processes(dut)
            # Verification that all BFD sessions are deleted
            for dut in duts:
                asics = [
                    asic.split("asic")[1] for asic in dut.get_asic_namespace_list()
                ]
                for asic in asics:
                    assert wait_until(
                        600,
                        10,
                        0,
                        lambda: find_bfd_peers_with_given_state(
                            dut, asic, "No BFD sessions found"
                        ),
                    )

            yield

        finally:
            duts = duthosts.frontend_nodes
            for dut in duts:
                modify_all_bfd_sessions(dut, "true")
            for dut in duts:
                config_reload(dut)
                wait_critical_processes(dut)
            # Verification that all BFD sessions are added
            for dut in duts:
                asics = [
                    asic.split("asic")[1] for asic in dut.get_asic_namespace_list()
                ]
                for asic in asics:
                    assert wait_until(
                        600,
                        10,
                        0,
                        lambda: find_bfd_peers_with_given_state(
                            dut, asic, "Up"
                        ),
                    )

    @pytest.fixture(scope="class", name="select_src_dst_dut_and_asic", params=(["multi_dut"]))
    def select_src_dst_dut_and_asic(self, duthosts, request, tbinfo):
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
