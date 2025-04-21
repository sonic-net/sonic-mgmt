from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.snappi_tests.dash.ha.ha_helper import *
from tests.common.snappi_tests.ixload.snappi_fixtures import config_snappi_ixl
from tests.common.snappi_tests.snappi_fixtures import config_uhd_connect

import time
import pytest
import snappi
import requests
import json
import ipaddress
import os
import macaddress
import time


SNAPPI_POLL_DELAY_SEC = 2

ipp = ipaddress.ip_address
maca = macaddress.MAC


pytestmark = [pytest.mark.topology('snappi')]
@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('ha_test_case', ['cps'])
def test_cps_baby_hero(
                       duthost,
                       localhost,
                       ha_test_case,
                       config_snappi_ixl,
                       config_uhd_connect,
): # noqa F811


    run_ha_test(
                duthost,
                localhost,
                ha_test_case,
                config_snappi_ixl)

    return
