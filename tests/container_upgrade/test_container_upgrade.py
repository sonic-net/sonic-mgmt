import pytest
import logging

from container_upgrade_helper import parse_containers, parse_os_versions
from container_upgrade_helper import create_image_list, create_testcase_mapping, create_parameters_mapping
from container_upgrade_helper import os_upgrade, pull_run_dockers, store_results

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
        self.container_string = containers
        self.containers, self.container_versions, self.container_names = parse_containers(containers)

        os_versions = required_container_upgrade_params["os_versions"]
        self.osversions = parse_os_versions(os_versions)

        image_url_template = required_container_upgrade_params["image_url_template"]
        self.image_urls = create_image_list(self.osversions, image_url_template)

        testcase_file = required_container_upgrade_params["testcase_file"]
        self.testcases = create_testcase_mapping(testcase_file)
        parameters_file = required_container_upgrade_params["parameters_file"]
        self.parameters = create_parameters_mapping(containers, parameters_file)

        self.optional_parameters = required_container_upgrade_params.get("optional_parameters", "") or ""

        self.version_pointer = 0


def test_container_upgrade(localhost, duthosts, rand_one_dut_hostname, tbinfo,
                           required_container_upgrade_params, creds, request):
    env = ContainerUpgradeTestEnvironment(required_container_upgrade_params)
    duthost = duthosts[rand_one_dut_hostname]
    tb_name = tbinfo["conf-name"]
    tb_file = request.config.option.testbed_file
    inventory = ",".join(request.config.option.ansible_inventory)
    hostname = duthost.hostname
    test_results = {}

    while env.version_pointer < len(env.osversions):
        expected_os_version = env.osversions[env.version_pointer]
        if expected_os_version not in duthost.os_version:
            os_upgrade(duthost, localhost, tbinfo, env.image_urls[env.version_pointer])
        pull_run_dockers(duthost, creds, env)

        for testcase in env.testcases.keys():
            logger.info(f"Testing {testcase} for {expected_os_version}")
            os_version_key = expected_os_version.replace('.', '_')
            testcase_key = testcase.replace(".py", "").replace('/', '_').replace('.', '_')
            log_file = f"logs/container_upgrade/{testcase_key}_{os_version_key}.log"
            log_xml = f"logs/container_upgrade/{testcase_key}_{os_version_key}.xml"
            command = f"python3 -m pytest {testcase} --inventory={inventory} --testbed={tb_name} \
                      --testbed_file={tb_file} --host-pattern={hostname} --log-cli-level=warning \
                      --log-file-level=debug --kube_master=unset --showlocals \
                      --assert=plain --show-capture=no -rav --allow_recover \
                      --skip_sanity --disable_loganalyzer --container_test=true \
                      --log-file={log_file} --junit-xml={log_xml}"

            output = None
            passed = False
            retry = 0
            max_retry = env.testcases[testcase]
            while retry <= max_retry and not passed:
                retry += 1
                output = localhost.shell(command, module_ignore_errors=True)
                passed = not output['failed']
                if not passed:
                    logger.warning(f"Test {testcase} passed {passed} retry: {retry}/{max_retry}")

            if not passed:
                logger.warning(f"Test {testcase} output start =====================")
                logger.warning(f"{output}".replace('\\n', '\n'))
                logger.warning(f"Test {testcase} output end   =====================")

            test_results.setdefault(expected_os_version, {})[testcase] = passed
        env.version_pointer += 1

    store_results(request, test_results, env)
