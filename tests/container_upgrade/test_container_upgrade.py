import pytest
import logging

from container_upgrade_helper import parse_containers, parse_os_versions
from container_upgrade_helper import create_image_list, create_testcase_list, create_parameters_mapping
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
        self.testcases = create_testcase_list(testcase_file)
        parameters_file = required_container_upgrade_params["parameters_file"]
        self.parameters = create_parameters_mapping(containers, parameters_file)

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

        for testcase in env.testcases:
            testcase_success = True
            logger.info(f"Testing {testcase} for {expected_os_version}")
            log_file = f"logs/container_upgrade/{testcase}.{expected_os_version}.log"
            log_xml = f"logs/container_upgrade/{testcase}.{expected_os_version}.xml"
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

            test_results.setdefault(expected_os_version, {})[testcase] = testcase_success

        env.version_pointer += 1

    store_results(request, test_results, env)


def build_required_container_upgrade_params(containers, os_versions, image_url_template,
                                            parameters_file, testcase_file):
    if any(var == "" or var is None for var in [containers, os_versions, image_url_template,
                                                parameters_file, testcase_file]):
        pytest.skip("Test does not have required parameters")
    params = {}
    params["containers"] = containers
    params["os_versions"] = os_versions
    params["image_url_template"] = image_url_template
    params["parameters_file"] = parameters_file
    params["testcase_file"] = testcase_file
    return params


def pytest_generate_tests(metafunc):
    containers = metafunc.config.getoption("containers")
    os_versions = metafunc.config.getoption("os_versions")
    image_url_template = metafunc.config.getoption("image_url_template")
    parameters_file = metafunc.config.getoption("parameters_file")
    testcase_file = metafunc.config.getoption("testcase_file")
    if "required_container_upgrade_params" in metafunc.fixturenames:
        params = build_required_container_upgrade_params(containers, os_versions,
                                                         image_url_template,
                                                         parameters_file,
                                                         testcase_file)
        metafunc.parametrize("required_container_upgrade_params", [params],
                             ids=lambda p: "containers=%s, os_versions=%s, \
                             image_url_template=%s, parameters_file=%s \
                             testcase_file=%s" % (p['containers'], p['os_versions'], p['image_url_template'],
                             p['parameters_file'], p['testcase_file']), scope="module")
    else:
        pytest.fail("Required container upgrade params fixture should exist")
