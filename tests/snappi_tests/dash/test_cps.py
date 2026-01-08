from tests.common.helpers.assertions import pytest_assert, pytest_require  # noqa F401
from tests.snappi_tests.dash.ha.ha_helper import is_smartswitch, run_ha_test
from tests.common.snappi_tests.snappi_fixtures import config_uhd_connect  # noqa F401
from tests.common.snappi_tests.ixload.snappi_fixtures import config_snappi_l47  # noqa F401
from tests.common.snappi_tests.ixload.snappi_fixtures import config_npu_dpu  # noqa F401
from concurrent.futures import ThreadPoolExecutor, as_completed

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
                       request,
): # noqa F811

    fixture_names = ["config_snappi_l47", "config_npu_dpu", "config_uhd_connect"]

    results = {}
    errors = {}

    sw1 = is_smartswitch(duthost)
    if sw1 is False:
        pytest.skip("Skipping test since is not a smartswitch")

    def _resolve_fixture(name):
        # Resolve the fixture value on-demand
        return request.getfixturevalue(name)

    with ThreadPoolExecutor(max_workers=3) as ex:
        fm = {ex.submit(_resolve_fixture, name): name for name in fixture_names}
        for fut in as_completed(fm):
            name = fm[fut]
            try:
                results[name] = fut.result()
            except Exception as e:
                errors[name] = e

    pytest_require(not errors, f"Concurrent setup failed for: {errors}")
    pytest_require("config_snappi_l47" in results, "Missing config_snappi_l47 result")
    pytest_require("config_npu_dpu" in results, "Missing config_npu_dpu result")

    config_npu_dpu = results["config_npu_dpu"]  # noqa F811
    config_snappi_l47 = results["config_snappi_l47"]  # noqa F811

    run_ha_test(  # noqa F405
                duthost,
                localhost,
                tbinfo,
                ha_test_case,
                config_npu_dpu,
                config_snappi_l47,)

    return
