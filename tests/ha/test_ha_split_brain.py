import logging

import pytest
import time
from constants import (
    NPU_DATAPLANE_PORT
)
from tests.common.helpers.assertions import pytest_assert
from tests.ha.conftest import apply_dash_pl_pipeline_config
from ha_utils import (
    set_dash_ha_scope,
    activate_secondary_dash_ha,
    verify_ha_state,
    wait_for_pending_operation_id,
    _apply_ha_scope_gnmi
)
from ha_link_utils import add_acl_link_drop, remove_acl_link_drop_table

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1-smartswitch-ha'),
    pytest.mark.skip_check_dut_health
]


def restore_ha_state(localhost, ptfhost, duthost, standby_vdpu_key="vdpu1_0:haset0_0"):
    set_dash_ha_scope(localhost, duthost, ptfhost, standby_vdpu_key, "dead", "dpu", disabled=True)
    pending_id = wait_for_pending_operation_id(duthost, standby_vdpu_key, "brainsplit_recover", timeout=60)
    if pending_id is not None:
        _apply_ha_scope_gnmi(localhost, duthost, ptfhost, standby_vdpu_key,
                             {"version": "1", "disabled": True, "desired_ha_state": "dead", "owner": "dpu"},
                             approved_pending_operation_ids=[pending_id])
    activate_secondary_dash_ha(localhost, duthost, ptfhost, standby_vdpu_key, "activate_role")
    pytest_assert(pending_id, f"pending_operation_id brainsplit_recover not found for scope {standby_vdpu_key}")


@pytest.fixture(autouse=True, scope="module")
def common_setup_teardown(
    localhost,
    duthosts,
    ptfhost,
    dpu_index,
    skip_config,
    dpuhosts,
    setup_ha_config,
    setup_dash_ha_from_json,
    setup_gnmi_server,
    set_vxlan_udp_sport_range,
    setup_npu_dpu  # noqa: F811
):
    if skip_config:
        return

    apply_dash_pl_pipeline_config(localhost, duthosts, dpuhosts, ptfhost)

    yield


"""
We are testing 2 scenarios:
    1. Primary Link failure
    2. Standby Link failure
"""


@pytest.mark.parametrize(
    "standby_link_fail", [True, False],
    ids=["Standby Link Fail", "Primary Link Fail"]
)
def test_ha_split_brain(
    ptfadapter,
    localhost,
    duthosts,
    dpuhosts,
    ptfhost,
    activate_dash_ha_from_json,
    dash_pl_config,
    standby_link_fail
):
    primary_vdpu_key = f"vdpu0_{dpuhosts[0].dpu_index}:haset0_0"
    standby_vdpu_key = f"vdpu1_{dpuhosts[1].dpu_index}:haset0_0"

    if standby_link_fail:
        logger.info("HA: Simulate standby link failure")
        remove_acl_link_drop_table(duthosts[1])
        add_acl_link_drop(duthosts[1], dash_pl_config[1][NPU_DATAPLANE_PORT])
    else:
        logger.info("HA: Simulate primary link failure")
        remove_acl_link_drop_table(duthosts[0])
        add_acl_link_drop(duthosts[0], dash_pl_config[0][NPU_DATAPLANE_PORT])
    logger.info("HA: After link failure")
    pytest_assert(verify_ha_state(duthosts[0], primary_vdpu_key, "standalone"),
                  "Primary HA state is not standalone")
    pytest_assert(verify_ha_state(duthosts[1], standby_vdpu_key, "standalone"),
                  "Standby HA state is not standalone")

    if standby_link_fail:
        remove_acl_link_drop_table(duthosts[1])
    else:
        remove_acl_link_drop_table(duthosts[0])
    time.sleep(20)
    # take system out of split-brain
    restore_ha_state(localhost, ptfhost, duthosts[1], standby_vdpu_key=standby_vdpu_key)
    pytest_assert(verify_ha_state(duthosts[0], primary_vdpu_key, "active"),
                  "Primary HA state is not active")
    pytest_assert(verify_ha_state(duthosts[1], standby_vdpu_key, "active"),
                  "Standby HA state is not active")
