import pytest


def build_required_container_upgrade_params(containers, os_versions, image_url_template, parameters_file, testcase_file):
    if containers == "" or os_versions == "" or image_url_template == "" or parameters_file == "" or testcase_file == "":
        pytest.fail("One of the required test parameters is empty")
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
