from tests.common.helpers.assertions import pytest_assert, pytest_require  # noqa F401
from tests.snappi_tests.dash.ha.ha_helper import *  # noqa F401,F403
from tests.common.snappi_tests.ixload.snappi_fixtures import config_snappi_l47  # noqa F401
from tests.common.snappi_tests.snappi_fixtures import config_uhd_connect  # noqa F401

import pytest
import snappi  # noqa F401
import requests  # noqa F401
import json  # noqa F401
import ipaddress
import macaddress

SNAPPI_POLL_DELAY_SEC = 2

ipp = ipaddress.ip_address
maca = macaddress.MAC


pytestmark = [pytest.mark.topology('tgen')]


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('ha_test_case', ['cps'])
def test_cps_baby_hero(
                       duthost,
                       localhost,
                       tbinfo,
                       ha_test_case,
                       config_snappi_l47,  # noqa F811
                       config_uhd_connect,  # noqa F811
): # noqa F811

    run_ha_test(  # noqa F405
                duthost,
                localhost,
                tbinfo,
                ha_test_case,
                config_snappi_l47)

    return
