import pytest
import logging
from tests.ha.conftest import setup_dash_ha_from_json_util, remove_setup_dash_ha_from_json_util, \
    activate_dash_ha_from_json_util, deactivate_dash_ha_from_json_util, setup_gnmi_server


pytestmark = [
    pytest.mark.topology("t1-smartswitch-ha")
]

logger = logging.getLogger(__name__)
NUM_RECONFIGS = 1

"""
The assumption for the test is that duthosts has primary and secondary in this order
The fixture parameters will configure HA and test will start by doing a deconfigure followed by configure
"""


def test_ha_reconfigure(request, duthosts, localhost, ptfhost, setup_ha_config,
                        setup_dash_ha_from_json, activate_dash_ha_from_json):

    for i in range(NUM_RECONFIGS):
        logger.info("Deconfigure HA")
        deactivate_dash_ha_from_json_util(duthosts, localhost, ptfhost, setup_gnmi_server)
        remove_setup_dash_ha_from_json_util(duthosts, localhost, ptfhost, setup_gnmi_server)

        # Reconfigure HA to verify that configuration was removed properly
        logger.info("Reconfigure HA")
        setup_dash_ha_from_json_util(duthosts, localhost, ptfhost, setup_gnmi_server)
        activate_dash_ha_from_json_util(duthosts, localhost, ptfhost, setup_gnmi_server)
