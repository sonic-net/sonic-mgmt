import pytest
import logging

from tests.common.helpers.assertions import pytest_require
from tests.common.utilities import skip_release
from tests.platform_tests.verify_dut_health import verify_dut_health      # lgtm[py/unused-import]

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('t0')
]

@pytest.fixture(autouse=True, scope="module")
def check_image_version(duthost):
    """Skips this test if the SONiC image installed on DUT is older than 202205

    Args:
        duthost: Hostname of DUT.

    Returns:
        None.
    """
    skip_release(duthost, ["201811", "201911", "202012", "202106"])


def test_service_warm_restart(request, duthosts, rand_one_dut_hostname, verify_dut_health, get_advanced_reboot,
    advanceboot_loganalyzer, capture_interface_counters):
    duthost = duthosts[rand_one_dut_hostname]

    # Get built-in service
    spm_data = duthost.show_and_parse('spm list')
    built_in_repo_set = {item['repository'] for item in spm_data if item['status'] == 'Built-In'}
    built_in_service_set = set()
    for built_in_repo in built_in_repo_set:
        service_name = duthost.shell('docker ps --filter "ancestor={}" --format \{{\{{.Names\}}\}}'.format(built_in_repo))['stdout']
        service_name = service_name.strip()
        if service_name:
            built_in_service_set.add(service_name)
        else:
            logging.info('service with docker repo {} is not enabled or running, skip warm restart for it'.format(built_in_repo))

    feature_list = duthost.show_and_parse('show feature status')
    ignored_services = request.config.getoption("--ignore_service")
    candidate_service_list = []
    for feature_data in feature_list:
        if feature_data['feature'] in ['database', 'syncd']:
            # Features that do not support warm restart
            continue

        if feature_data['feature'] not in built_in_service_set:
            # There is no guarantee that non built-in feature support warm restart, so ignore them
            logging.info('Feature {} is not a built-in feature, skip warm restart for it.'.format(feature_data['feature']))
            continue

        if ignored_services:
            ignored_services = ignored_services.split(',')
            if feature_data['feature'] in ignored_services:
                logging.info("Feature {} is ignored by user, skip warm restart for it.".format(feature_data['feature']))
                continue

        if feature_data['state'] == 'disabled' or feature_data['state'] == 'always_disabled':
            logging.info("Feature {} is not enabled, skip warm restart for it.".format(feature_data['feature']))
            continue

        candidate_service_list.append(feature_data['feature'])

    pytest_require(candidate_service_list, 'Skip service warm restart test because candidate_service_list is empty')

    advancedReboot = get_advanced_reboot(rebootType='service-warm-restart',
                                         service_list=candidate_service_list,
                                         advanceboot_loganalyzer=advanceboot_loganalyzer)
    advancedReboot.runRebootTestcase()
