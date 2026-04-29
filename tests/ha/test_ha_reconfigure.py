import pytest
import logging
from tests.ha.conftest import setup_dash_ha_from_json_util, remove_setup_dash_ha_from_json_util, \
    activate_dash_ha_from_json_util, deactivate_dash_ha_from_json_util, setup_gnmi_server


pytestmark = [
    pytest.mark.topology("t1-smartswitch-ha")
]

logger = logging.getLogger(__name__)
NUM_RECONFIGS = 3

"""
The assumption for the test is that duthosts has primary and secondary in this order
The fixture parameters will configure HA and test will start by doing a deconfigure followed by configure
"""


def test_ha_reconfigure(request, duthosts, localhost, dpuhosts, ptfhost, setup_ha_config,
                        setup_dash_ha_from_json, activate_dash_ha_from_json, ha_owner):

    for i in range(NUM_RECONFIGS):
        iter = i + 1
        logger.info(f"HA: deconfigure iteration {iter}")
        deactivate_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server)
        remove_setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)

        # Reconfigure HA to verify that configuration was removed properly
        logger.info(f"HA: reconfigure iteration {iter}")
        setup_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
        activate_dash_ha_from_json_util(duthosts, dpuhosts, localhost, ptfhost, setup_gnmi_server, ha_owner)
