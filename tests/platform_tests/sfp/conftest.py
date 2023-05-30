import pytest
import logging
import os
import json
from tests.common.utilities import wait_until

ans_host = None


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


@pytest.fixture(autouse=False)
def stop_xcvrd(duthost):
    dut_platfrom = duthost.facts['platform']
    pmon_daemon_path = os.path.join("/usr/share/sonic/device", dut_platfrom)
    pmon_daemon_file_path = os.path.join(pmon_daemon_path, "pmon_daemon_control.json")
    original_file_path = backup_original_daemon_file(duthost, pmon_daemon_file_path)
    cmd = duthost.shell('cat {}'.format(pmon_daemon_file_path))
    daemon_control_dict = json.loads(cmd['stdout'])
    modified_dict = modify_daemon_file(daemon_control_dict)
    temp_path = os.path.join("/tmp", "pmon_daemon_control.json")
    create_json_file(temp_path, modified_dict)
    duthost.copy(src=temp_path, dest=pmon_daemon_file_path)
    restart_pmon(duthost)

    yield
    # return the original daemon control file to the path
    duthost.shell("mv {} {}".format(original_file_path, pmon_daemon_file_path))
    restart_pmon(duthost)

