"""
GCU coverage for the downstream neighbors of a disaggregated T2.

On a UT2 the downstream neighbor is the LowerSpineRouter; on an LT2 it is the T1
LeafRouter, which is the non-chassis counterpart of the chassis add-cluster test.
Per scenario the test removes the existing downstream neighbor via GCU and adds it
back, verifying CONFIG_DB, BGP routes and forwarding through the cycle. Downstream
counterpart of test_add_t3.py; both run dt2_helpers.run_remove_and_readd_cycle.
"""
import logging
import pytest
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.generic_config_updater.dt2.dt2_helpers import (
    DOWNSTREAM_SCENARIOS,
    pick_target_neighbor,
    run_remove_and_readd_cycle,
)

pytestmark = [
    pytest.mark.topology("ut2", "t2", "lt2"),
]

logger = logging.getLogger(__name__)
allure.logger = logger


@pytest.fixture(scope="function", params=DOWNSTREAM_SCENARIOS, ids=[s["id"] for s in DOWNSTREAM_SCENARIOS])
def downstream_scenario(request):
    return request.param


@pytest.fixture(scope="function")
def selected_downstream_neighbor(mg_facts, config_facts, config_facts_localhost, downstream_scenario):
    return pick_target_neighbor(config_facts, config_facts_localhost, mg_facts, downstream_scenario)


def test_add_downstream(
    tbinfo,
    duthosts,
    ptfadapter,
    loganalyzer,
    enum_downstream_dut_hostname,
    enum_upstream_dut_hostname,
    enum_rand_one_frontend_asic_index,
    enum_rand_one_asic_namespace,
    mg_facts,
    config_facts,
    config_facts_localhost,
    downstream_scenario,
    selected_downstream_neighbor,
):
    """
    Add a downstream (LowerSpineRouter on UT2, T1 LeafRouter on LT2) neighbor via GCU. A test
    cannot create a new physical downlink, so it first removes the existing neighbor of that
    type via GCU and then performs the add against the reduced configuration; both halves
    are verified.
    """
    run_remove_and_readd_cycle(
        tbinfo,
        duthosts,
        ptfadapter,
        loganalyzer,
        enum_downstream_dut_hostname,
        enum_upstream_dut_hostname,
        enum_rand_one_frontend_asic_index,
        enum_rand_one_asic_namespace,
        mg_facts,
        config_facts,
        config_facts_localhost,
        downstream_scenario,
        selected_downstream_neighbor,
    )
