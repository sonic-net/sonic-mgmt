import logging
import concurrent.futures

import pytest
from tests.common.config_reload import config_reload
from tests.ha.conftest import (
    setup_dash_ha_from_json_util,
    remove_setup_dash_ha_from_json_util,
    activate_dash_ha_from_json_util
)

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t1-smartswitch-ha')
]


def reload_config_for_host(dpuhost):
    logger.info(f"config reload on {dpuhost.hostname}")
    config_reload(dpuhost, safe_reload=True, yang_validate=False)


@pytest.fixture(autouse=True, scope="function")
def common_setup_teardown(
    localhost,
    duthosts,
    ptfhost,
    dpu_index,
    skip_config,
    dpuhosts,
    setup_ha_config,
    set_vxlan_udp_sport_range,
    setup_npu_dpu,  # noqa: F811
    setup_dash_pl_pipeline
):
    if skip_config:
        return

    yield
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(dpuhosts)) as executor:
        # Map the reload_config_for_host function to the dpuhosts list
        executor.map(reload_config_for_host, dpuhosts)


def test_ha_eni_out_of_order(
    ptfadapter,
    localhost,
    duthosts,
    dpuhosts,
    ptfhost,
    setup_gnmi_server,
    ha_owner
):
    try:
        setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
        ha_setup_ok = True
    except Exception as e:
        logger.info(f"HA: setup failed with exception: {e}")

    if ha_setup_ok:
        try:
            activate_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
            ha_activate_ok = True
        except Exception as e:
            logger.info(f"HA: activation failed with exception: {e}")

    if ha_setup_ok and ha_activate_ok:
        pytest.fail("HA: setup and activation succeeded - failure expected")
    else:
        logger.info("HA: setup or activation failed with exception as expected due to out of order ENI, test passed")

    if ha_setup_ok:
        remove_setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
        logger.info("HA: removed HA config to allow successful setup and activation on next attempt")
    # Remove the ENI config to allow the HA setup and activation to complete successfully
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(dpuhosts)) as executor:
        # Map the reload_config_for_host function to the dpuhosts list
        executor.map(reload_config_for_host, dpuhosts)

    setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
    activate_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
