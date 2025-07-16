import logging
import json
import os
import pytest
from tests.common.helpers.assertions import pytest_assert
import cli_helpers as helper
from telemetry_utils import generate_client_cli

pytestmark = [
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

METHOD_GET = "get"
METHOD_SUBSCRIBE = "subscribe"
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
SHOW_PATHS_FILE = os.path.join(BASE_DIR, "cli_paths.json")

@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_telemetry_show_non_get(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost,
                                setup_streaming_telemetry, gnxi_path):
    """
    Test non-get mode from APPL_DB and query a non existing table and key, ensure no errors
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    logger.info('Start telemetry SHOW testing')
    cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_SUBSCRIBE,
                              xpath="reboot-cause", target="SHOW")
    ptf_result = ptfhost.shell(cmd)
    pytest_assert(ptf_result['rc'] != 0, "SHOW command for non GET operation should fail".format(cmd))


@pytest.mark.parametrize('setup_streaming_telemetry', [False], indirect=True)
def test_telemetry_show_get(duthosts, localhost, enum_rand_one_per_hwsku_hostname, ptfhost,
                            setup_streaming_telemetry, gnxi_path, request):
    """
    Test poll mode from APPL_DB and query a non existing table and key, ensure no errors
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    logger.info('Start telemetry SHOW testing')

    with open(SHOW_PATHS_FILE, 'r') as show_paths_file:
        show_paths_data = json.load(show_paths_file)

    for path, test_config in show_paths_data.items():
        # Do any setup that is required before executing query
        if test_config["setup"]:
            setup_fixtures = [request.getfixturevalue(fixture) for fixture in test_config["setup_fixtures"]]
            setup_args = test_config["setup_args"]
            getattr(helper, test_config["setup"])(*setup_fixtures, *setup_args)

        cmd = generate_client_cli(duthost=duthost, gnxi_path=gnxi_path, method=METHOD_GET,
                                  xpath=path, target="SHOW")
        ptf_result = ptfhost.shell(cmd)
        pytest_assert(ptf_result['rc'] == 0, "ptf cmd command {} failed".format(cmd))
        show_gnmi_out = ptf_result['stdout']
        logger.info("GNMI Server output: {}".format(show_gnmi_out))

        if test_config["verify"]:
            output = helper.get_json_from_gnmi_output(show_gnmi_out)
            verify_fixtures = [request.getfixturevalue(fixture) for fixture in test_config["verify_fixtures"]]
            verify_args = test_config["verify_args"]
            getattr(helper, test_config["verify"])(*verify_fixtures, *verify_args, output)
