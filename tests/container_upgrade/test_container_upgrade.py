import pytest
import logging

from tests.common.helpers.custom_msg_utils import add_custom_msg
from container_upgrade_helper import parse_containers, parse_os_versions
from container_upgrade_helper import createImageList, createTestcaseList, createParametersMapping
from container_upgrade_helper import os_upgrade, pull_run_dockers

from tests.common.helpers.constants import (
    DUT_CHECK_NAMESPACE
)

CUSTOM_MSG_PREFIX = "sonic_custom_msg"

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]


logger = logging.getLogger(__name__)


class ContainerUpgradeTestEnvironment(object):
    def __init__(self, required_container_upgrade_params):
        containers = required_container_upgrade_params["containers"]
        self.containerString = containers
        self.containers, self.containerVersions, self.containerNames = parse_containers(containers)

        os_versions = required_container_upgrade_params["os_versions"]
        self.osVersions = parse_os_versions(os_versions)

        image_url_template = required_container_upgrade_params["image_url_template"]
        self.imageURLs = createImageList(self.osVersions, image_url_template)

        testcase_file = required_container_upgrade_params["testcase_file"]
        self.testcases = createTestcaseList(testcase_file)
        parameters_file = required_container_upgrade_params["parameters_file"]
        self.parameters = createParametersMapping(containers, parameters_file)

        self.versionPointer = 0


def test_container_upgrade(localhost, duthosts, rand_one_dut_hostname, tbinfo,
                           required_container_upgrade_params, creds, request):
    env = ContainerUpgradeTestEnvironment(required_container_upgrade_params)
    duthost = duthosts[rand_one_dut_hostname]
    tb_name = tbinfo["conf-name"]
    tb_file = request.config.option.testbed_file
    inventory = ",".join(request.config.option.ansible_inventory)
    hostname = duthost.hostname

    while env.versionPointer < len(env.osVersions):
        expectedOSVersion = env.osVersions[env.versionPointer]
        if expectedOSVersion not in duthost.os_version:
            os_upgrade(duthost, localhost, tbinfo, env.imageURLs[env.versionPointer])
        pull_run_dockers(duthost, creds, env)

        for testcase in env.testcases:
            testcase_success = True
            logger.info(f"Testing {testcase} for {expectedOSVersion}")
            log_file = f"logs/container_upgrade/{testcase}.{expectedOSVersion}.log"
            log_xml = f"logs/container_upgrade/{testcase}.{expectedOSVersion}.xml"
            command = f"python3 -m pytest {testcase} --inventory={inventory} --testbed={tb_name} \
                      --testbed_file={tb_file} --host-pattern={hostname} --log-cli-level=warning \
                      --log-file-level=debug --kube_master=unset --showlocals \
                      --assert=plain --show-capture=no -rav --allow_recover \
                      --skip_sanity --disable_loganalyzer \
                      --log-file={log_file} --junit-xml={log_xml}"
            try:
                localhost.shell(command)
            except Exception:
                testcase_success = False
            add_custom_msg(request, f"{DUT_CHECK_NAMESPACE}.container_upgrade", testcase_success)
        env.versionPointer += 1
