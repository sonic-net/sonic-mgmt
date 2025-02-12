import pytest
import json
import logging

from container_upgrade_helper import parse_containers, parse_os_versions, createImageList, createTestcaseList, createParametersMapping
from container_upgrade_helper import os_upgrade, pull_run_dockers

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
        self.containers, self.containerVersions, self.containerNames = parse_containers(containers)
        os_versions = required_container_upgrade_params["os_versions"]
        self.osVersions = parse_os_versions(os_versions)
        image_url_template = required_container_upgrade_params["image_url_template"]
        self.imageURLs = createImageList(self.osVersions, image_url_template)

        # TODO
        testcase_file = required_container_upgrade_params["testcase_file"]
        self.testcases = createTestcaseList(testcase_file)
        parameters_file = required_container_upgrade_params["parameters_file"]
        self.parameters = createParametersMapping(containers, parameters_file)

        self.versionPointer = 0
        logger.info(f"Values for test run are {self.containers}, {self.containerVersions}, {self.containerNames}, {self.osVersions}, {self.imageURLs} \
                    {self.testcases}, {self.parameters}, {self.versionPointer}")


def test_container_upgrade(localhost, duthosts, rand_one_dut_hostname, tbinfo,
                           required_container_upgrade_params, creds):
    env = ContainerUpgradeTestEnvironment(required_container_upgrade_params)
    duthost = duthosts[rand_one_dut_hostname]
    while(env.versionPointer < len(env.osVersions)):
        expectedOSVersion = env.osVersions[env.versionPointer]
        if expectedOSVersion not in duthost.os_version:
            os_upgrade(duthost, localhost, tbinfo, env.imageURLs[env.versionPointer])
        pull_run_dockers(duthost, creds, env)
        # TODO: RUN TESTCASES
        # TODO: PUBLISH TO KUSTO
        env.versionPointer += 1
