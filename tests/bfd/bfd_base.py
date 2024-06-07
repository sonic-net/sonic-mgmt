import logging
import random

import pytest

logger = logging.getLogger(__name__)


class BfdBase:
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
            duthosts[src_dut_index].get_asic_namespace_list()
        )
        src_asic_index = src_asic_index_selection.split("asic")[1]

        # Random selection of destination asic based on number of asics available on destination dut
        dst_asic_index_selection = random.choice(
            duthosts[dst_dut_index].get_asic_namespace_list()
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
