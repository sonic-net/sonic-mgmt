import logging
import concurrent.futures

import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload
from tests.ha.conftest import (
    apply_dash_pl_pipeline_config,
    setup_dash_ha_from_json_util,
    remove_setup_dash_ha_from_json_util,
    activate_dash_ha_from_json_util,
    deactivate_dash_ha_from_json_util
)
from ha_utils import verify_ha_state

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1-smartswitch-ha')
]


def reload_config_for_host(dpuhost):
    logger.info(f"config reload on {dpuhost.hostname}")
    config_reload(dpuhost, safe_reload=True, yang_validate=False)


def test_ha_eni_out_of_order(
    ptfadapter,
    localhost,
    duthosts,
    dpuhosts,
    ptfhost,
    setup_gnmi_server,
    setup_dash_pl_pipeline_module_scope,
    ha_owner,
    primary_vdpu_key,
    standby_vdpu_key
):
    """
    This test executes these steps:
    - configure ENI  - setup_dash_pl_pipeline_module_scope fixture
    - configure HA_SET - setup_dash_ha_from_json_util
    - configure HA_SCOPE [activate] - activate_dash_ha_from_json_util
    - delete HA_SCOPE - deactivate_dash_ha_from_json_util
    - delete HA_SET - remove_setup_dash_ha_from_json_util
    - delete ENI - config_reload on DPU
    - normal order of creation.
    """
    try:
        setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
        logger.info("HA: setup successful")
        try:
            activate_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
        except AssertionError as e:
            logger.warning(f"HA: activation failed: {e}")
        deactivate_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
        remove_setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
        # cleanup the ENI
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(dpuhosts)) as executor:
            executor.map(reload_config_for_host, dpuhosts)

        logger.info("HA: reprogram HA and ENI")
        setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
        apply_dash_pl_pipeline_config(localhost, duthosts, dpuhosts, ptfhost)
        activate_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)

        pytest_assert(verify_ha_state(duthosts[0], primary_vdpu_key, "active"),
                      "Primary HA state is not active")
        pytest_assert(verify_ha_state(duthosts[1], standby_vdpu_key, "active"),
                      "Standby HA state is not active")
    finally:
        deactivate_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(dpuhosts)) as executor:
            executor.map(reload_config_for_host, dpuhosts)
        remove_setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
