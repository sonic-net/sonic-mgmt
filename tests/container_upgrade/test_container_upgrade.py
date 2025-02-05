import json
import logging


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
        os_versions = required_container_upgrade["os_versions"]
        self.osVersions = parse_os_versions(os_versions)
        image_url_template = required_container_upgrade_params["image_url_template"]
        self.imageURLs = createImageList(os_versions, image_url_template)

        # TODO
        testcase_file = required_container_upgrade_params["testcase_file"]
        self.testcases = createTestcaseList(testcase_file)
        parameters_file = required_container_upgrade_params["parameters_file"]
        self.parameters = createParametersMapping(containers, parameters_file)

        self.versionPointer = 0


def test_container_upgrade(localhost, duthosts, rand_one_dut_hostname, tbinfo,
                           required_container_upgrade_params, creds):
    """
    Steps:
        1. Create test env (self.versionPointer, self.osVersions, self.containers, self.containerVersions, self.imageURLs, self.testcaseFile, self.parameters)
        2. Loop
           2.1 Check if versionPointer is greater than or equal to the length of osVersion (all os versions accounted for); break case
           2.2 In loop check if currentOSVersion == versions[ptr], if so, proceed with test, else proceed with trying to upgrade
           2.3 Pull docker images
           2.4 Run testcases
           2.5 Publish Kusto
    """
    env = ContainerUpgradeTestEnvironment(duthost, required_container_upgrade_params)
    while(env.versionPointer < len(env.osVersions)):
        expectedOSVersion = env.osVersions[env.versionPointer]
        if expectedOSVersion not in duthost.os_version:
            os_upgrade(duthost, localhost, tbinfo, env.imageURLs[env.versionPointer])
        pull_run_dockers(duthost, creds, env)
        # TODO: RUN TESTCASES
        # TODO: PUBLISH TO KUSTO
        env.versionPointer += 1
