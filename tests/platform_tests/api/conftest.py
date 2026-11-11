import pytest

from tests.common.helpers.platform_api import psu
from tests.common.platform.device_utils import stop_platform_api_server
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer


def skip_absent_psu(psu_num, platform_api_conn, psu_skip_list, logger):    # noqa: F811
    name = psu.get_name(platform_api_conn, psu_num)
    if name in psu_skip_list:
        logger.info("Skipping PSU {} since it is part of psu_skip_list".format(name))
        return True
    return False


@pytest.fixture(scope='module', autouse=True)
def stop_platform_api_service(duthosts):
    try:
        yield
    finally:
        for duthost in duthosts:
            stop_platform_api_server(duthost)


@pytest.fixture(autouse=True)
def check_not_implemented_warnings(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # The BMC runs a minimal sonic_platform plugin, so the "API not implemented"
    # pmon warning scan is not meaningful. Skipping the LogAnalyzer init/analyze
    # also avoids a per-test ansible copy to the DUT, which stalls the whole api
    # suite if the BMC mgmt channel becomes unreachable mid-run.
    if duthost.is_bmc():
        yield
        return

    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="platformapi_test")
    marker = loganalyzer.init()
    yield
    loganalyzer.match_regex.extend(['WARNING pmon#platform_api_server.py: API.+not implemented'])
    loganalyzer.analyze(marker)
