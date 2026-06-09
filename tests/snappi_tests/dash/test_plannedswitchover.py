from tests.common.helpers.assertions import pytest_assert, pytest_require  # noqa F401
from tests.snappi_tests.dash.ha.ha_helper import is_smartswitch, run_ha_test
from tests.common.snappi_tests.snappi_fixtures import config_uhd_connect  # noqa F401
from tests.common.snappi_tests.ixload.snappi_fixtures import config_snappi_l47  # noqa F401
from tests.common.snappi_tests.ixload.snappi_fixtures import config_npu_dpu  # noqa F401
from tests.common.snappi_tests.ixload.snappi_fixtures import setup_config_snappi_l47, setup_config_npu_dpu  # noqa F401
from tests.common.snappi_tests.snappi_fixtures import setup_config_uhd_connect  # noqa F401
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
@pytest.mark.parametrize('ha_test_case', ['planned_switchover'])
def test_ha_planned_switchover(
                       duthosts,
                       localhost,
                       tbinfo,
                       ha_test_case,
                       request,
): # noqa F811

    results = {}
    errors = {}

    sw1 = is_smartswitch(duthosts[0])
    if sw1 is False:
        pytest.skip("Skipping test since is not a smartswitch")
    sw2 = is_smartswitch(duthosts[1])
    if sw2 is False:
        pytest.skip("Skipping test since DUT is not a smartswitch")

    def _run_config_snappi_l47():
        try:
            return setup_config_snappi_l47(request, duthosts, tbinfo, ha_test_case)
        except Exception as e:
            raise e

    def _run_config_npu_dpu():
        try:
            return setup_config_npu_dpu(request, duthosts, localhost, tbinfo, ha_test_case)
        except Exception as e:
            raise e

    def _run_config_uhd_connect():
        try:
            return setup_config_uhd_connect(request, tbinfo, ha_test_case)
        except Exception as e:
            raise e

    # Run the setup functions in parallel
    with ThreadPoolExecutor(max_workers=3) as ex:
        future_snappi = ex.submit(_run_config_snappi_l47)
        future_npu = ex.submit(_run_config_npu_dpu)
        future_uhd = ex.submit(_run_config_uhd_connect)

        futures = {
            future_snappi: "config_snappi_l47",
            future_npu: "config_npu_dpu",
            future_uhd: "config_uhd_connect"
        }

        for fut in as_completed(futures):
            name = futures[fut]
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
                duthosts,
                localhost,
                tbinfo,
                ha_test_case,
                config_npu_dpu,
                config_snappi_l47,)

    return
