import logging
import concurrent.futures

import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.config_reload import config_reload
from tests.ha.conftest import (
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
    try:
        try:
            setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
            ha_setup_ok = True
        except Exception as e:
            ha_setup_ok = False
            logger.info(f"HA: setup failed with exception: {e}")

        if ha_setup_ok:
            try:
                activate_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
                ha_activate_ok = True
            except Exception as e:
                ha_activate_ok = False
                logger.info(f"HA: activation failed with exception: {e}")

        if ha_setup_ok and ha_activate_ok:
            pytest.fail("HA: setup and activation succeeded - failure expected")
        else:
            logger.info("HA: activation failed due to out of order ENI, test passed")

        if ha_setup_ok:
            remove_setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
            logger.info("HA: removed HA config to allow successful setup and activation on next attempt")
        # Remove the ENI config to allow the HA setup and activation to complete successfully
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(dpuhosts)) as executor:
            # Map the reload_config_for_host function to the dpuhosts list
            executor.map(reload_config_for_host, dpuhosts)

        setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
        activate_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)

        pytest_assert(verify_ha_state(duthosts[0], primary_vdpu_key, "active"),
                      "Primary HA state is not active")
        pytest_assert(verify_ha_state(duthosts[1], standby_vdpu_key, "active"),
                      "Standby HA state is not active")
    finally:
        deactivate_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
        remove_setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
