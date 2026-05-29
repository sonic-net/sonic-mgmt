import pytest
import logging
import os
import json

from tests.common.errors import RunAnsibleModuleFail
from tests.common.utilities import wait_until

ans_host = None


def pytest_addoption(parser):
    parser.addoption("--limited_ports", action="store_true", help="Test with limited number of ports")


@pytest.fixture(scope="module")
def limited_ports(request):
    return request.config.getoption('--limited_ports')


def teardown_module():
    logging.info("remove script to retrieve port mapping")
    file_path = os.path.join('/usr/share/sonic/device', ans_host.facts['platform'], 'plugins/getportmap.py')
    ans_host.file(path=file_path, state='absent')


def check_pmon_service(duthost):
    pmon_service_state = duthost.get_service_props("pmon")
    return pmon_service_state["ActiveState"] == "active"


def restart_pmon(duthost):
    duthost.shell("service pmon restart")
    if not wait_until(1, 60, 0, check_pmon_service, duthost):
        pytest.fail('pmon service is not up after 60 seconds. Test failed')


def modify_daemon_file(daemon_dict):
    daemon_dict["skip_xcvrd"] = True
    daemon_dict.pop("delay_xcvrd", None)
    daemon_dict.pop("skip_xcvrd_cmis_mgr", None)
    return daemon_dict


def create_json_file(temp_path, pmon_daemon_dict):
    with open(temp_path, 'w') as pmon_daemon_json:
        json.dump(pmon_daemon_dict, pmon_daemon_json, indent=4)
        pmon_daemon_json.write("\n")


def backup_original_daemon_file(duthost, pmon_daemon_file_path):
    duthost.shell("cp {} /tmp/pmon_daemon_control.json".format(pmon_daemon_file_path))
    original_file_path = os.path.join("/tmp", "pmon_daemon_control.json")
    return original_file_path


def check_pmon_file_and_create(duthost, pmon_daemon_path, pmon_daemon_file_path):
    try:
        duthost.shell('ls {} | grep pmon_daemon_control.json'.format(pmon_daemon_path))['stdout']
        return False
    except RunAnsibleModuleFail:
        temp_dict = {}
        temp_path = os.path.join("/tmp", "pmon_daemon_control.json")
        create_json_file(temp_path, temp_dict)
        duthost.copy(src=temp_path, dest=pmon_daemon_file_path)
        return True
