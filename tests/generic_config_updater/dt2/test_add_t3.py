"""
GCU coverage for the uplink (T3) neighbors of a disaggregated-T2 upper tier (UT2).

Per scenario (AZNGHub, RegionalHub) the test removes the existing T3 neighbor via GCU
and adds it back, verifying CONFIG_DB, BGP routes and forwarding through the cycle.
Uplink counterpart of test_add_downstream.py; both run
dt2_helpers.run_remove_and_readd_cycle.
"""
import logging
import pytest
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.generic_config_updater.dt2.dt2_helpers import (
    T3_SCENARIOS,
    pick_target_neighbor,
    run_remove_and_readd_cycle,
)

pytestmark = [
    pytest.mark.topology("ut2", "t2"),
]

logger = logging.getLogger(__name__)
allure.logger = logger


@pytest.fixture(scope="function", params=T3_SCENARIOS, ids=[s["id"] for s in T3_SCENARIOS])
def t3_scenario(request):
    return request.param


@pytest.fixture(scope="function")
def selected_t3_neighbor(mg_facts, config_facts, config_facts_localhost, t3_scenario):
    return pick_target_neighbor(config_facts, config_facts_localhost, mg_facts, t3_scenario)


def test_add_t3(
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
    t3_scenario,
    selected_t3_neighbor,
):
    """
    Add a T3 (AZNGHub / RegionalHub) neighbor on a UT2 via GCU. A test cannot create a new
    physical uplink, so it first removes the existing neighbor of that type via GCU and then
    performs the add against the reduced configuration; both halves are verified.

    Uplinks may carry MACsec: when a session is established on the neighbor's member ports
    the flow validates MACsec teardown and recovery instead of PTF traffic.
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
        t3_scenario,
        selected_t3_neighbor,
        validate_macsec=True,
    )
