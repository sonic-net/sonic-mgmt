import pytest


def build_required_container_upgrade_params(containers, os_versions, image_url_template,
                                            parameters_file, testcase_file, optional_parameters):
    if any(var == "" or var is None for var in [containers, os_versions, image_url_template,
                                                parameters_file, testcase_file]):
        return None
    params = {}
    params["containers"] = containers
    params["os_versions"] = os_versions
    params["image_url_template"] = image_url_template
    params["parameters_file"] = parameters_file
    params["testcase_file"] = testcase_file
    params["optional_parameters"] = optional_parameters or ""
    return params


def pytest_generate_tests(metafunc):
    containers = metafunc.config.getoption("containers")
    os_versions = metafunc.config.getoption("os_versions")
    image_url_template = metafunc.config.getoption("image_url_template")
    parameters_file = metafunc.config.getoption("parameters_file")
    testcase_file = metafunc.config.getoption("testcase_file")
    optional_parameters = metafunc.config.getoption("optional_parameters")
    if "required_container_upgrade_params" in metafunc.fixturenames:
        params = build_required_container_upgrade_params(containers, os_versions,
                                                         image_url_template,
                                                         parameters_file,
                                                         testcase_file,
                                                         optional_parameters)

        skip_condition = False
        if params is None:
            params = {}
            skip_condition = True

        metafunc.parametrize(
            "required_container_upgrade_params",
            [
                pytest.param(
                    params,
                    marks=pytest.mark.skipif(
                        skip_condition,
                        reason="Test does not have required parameters"
                    )
                )
            ],
            ids=lambda p: "containers=%s, os_versions=%s, \
            image_url_template=%s, parameters_file=%s \
            testcase_file=%s" % (p.get('containers', 'None'),
                                 p.get('os_versions', 'None'),
                                 p.get('image_url_template', 'None'),
                                 p.get('parameters_file', 'None'),
                                 p.get('testcase_file', 'None')),
            scope="module"
        )
    else:
        pytest.fail("required_container_upgrade_params fixture should exist")
