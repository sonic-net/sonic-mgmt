import pytest
import logging

from tests.common.fixtures.advanced_reboot import get_advanced_reboot
from tests.common.helpers.assertions import pytest_require
from tests.common.utilities import skip_release
from tests.platform_tests.verify_dut_health import verify_dut_health  # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory  # lgtm[py/unused-import]

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


def get_builtin_services(duthost):
    spm_data = duthost.show_and_parse('spm list')
    return {item['name'] for item in spm_data if item['status'] == 'Built-In'}


def get_running_services(duthost):
    services = duthost.shell('docker ps --format \{\{.Names\}\}')['stdout_lines']
    return services


def get_ignored_services(request):
    ignored_services = request.config.getoption("--ignore_service")
    return ignored_services.split(',') if ignored_services else []


class ServiceMatchRules:
    services_warmboot_unsupported = ['database', 'syncd']

    def __init__(self, duthost, request):
        feature_info = duthost.show_and_parse('show feature status')
        self.feature_data = {info['feature']: info for info in feature_info}

        self.ignored_services = get_ignored_services(request)
        self.builtin_services = get_builtin_services(duthost)
        self.running_services = get_running_services(duthost)

    def is_running(self, s):
        return s in self.running_services

    def is_not_ignored(self, s):
        return s not in self.ignored_services

    def is_built_in(self, s):
        return s in self.builtin_services

    def is_feature_enabled(self, s):
        return self.feature_data[s]['state'] not in ['disabled', 'always_disabled']

    def is_warmboot_supported(self, s):
        return s not in ServiceMatchRules.services_warmboot_unsupported


def select_services_to_warmrestart(duthost, request):
    all_services = [feature_data['feature'] for feature_data in duthost.show_and_parse('show feature status')]

    rules = ServiceMatchRules(duthost, request)

    not_running_services = [service for service in all_services if not rules.is_running(service)]
    if not_running_services:
        logging.info('skipping test for not running services: {}'.format(not_running_services))

    all_checks = [
        rules.is_built_in,
        rules.is_warmboot_supported,
        rules.is_not_ignored,
        rules.is_running,
        rules.is_feature_enabled
    ]

    def passes_all_checks(service):
        return all(rule(service) for rule in all_checks)

    return [service for service in all_services if passes_all_checks(service)]


def test_service_warm_restart(request, duthosts, rand_one_dut_hostname, verify_dut_health, get_advanced_reboot,
                              advanceboot_loganalyzer, capture_interface_counters):
    duthost = duthosts[rand_one_dut_hostname]

    candidate_service_list = select_services_to_warmrestart(duthost, request)
    pytest_require(candidate_service_list, 'Skip service warm restart test because candidate_service_list is empty')

    advancedReboot = get_advanced_reboot(rebootType='service-warm-restart',
                                         service_list=candidate_service_list,
                                         advanceboot_loganalyzer=advanceboot_loganalyzer)
    advancedReboot.runRebootTestcase()
