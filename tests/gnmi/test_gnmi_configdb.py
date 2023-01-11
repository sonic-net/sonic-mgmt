import json
import logging
import pytest
import re

from helper import gnmi_set, gnmi_get, gnoi_reboot
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.platform.interface_utils import check_interface_status_of_up_ports

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


def get_first_interface(duthost):
    cmds = "show interface status"
    output = duthost.shell(cmds)
    assert (not output['rc']), "No output"
    status_data = output["stdout_lines"]
    if 'Admin' not in status_data[0]:
        return None
    admin_index = status_data[0].split().index('Admin')
    for line in status_data:
        if "trunk" in line:
            interface_status = line.strip()
            assert len(interface_status) > 0, "Failed to read interface properties"
            sl = interface_status.split()
            if sl[admin_index] == 'up':
                return sl[0]
    return None


def get_interface_status(duthost, field, interface='Ethernet0'):
    cmds = "show interface status {}".format(interface)
    output = duthost.shell(cmds)
    assert (not output['rc']), "No output"
    status_data = output["stdout_lines"]
    if field not in status_data[0]:
        return None
    field_index = status_data[0].split().index(field)
    for line in status_data:
        if interface in line:
            interface_status = line.strip()
            assert len(interface_status) > 0, "Failed to read {} interface properties".format(interface)
            status = re.split(r" {2,}", interface_status)[field_index]
            return status
    return None


def test_gnmi_configdb_incremental_01(duthosts, rand_one_dut_hostname, localhost):
    '''
    Verify GNMI native write, incremental config for configDB
    Toggle interface admin status
    '''
    duthost = duthosts[rand_one_dut_hostname]
    file_name = "port.txt"
    interface = get_first_interface(duthost)
    assert interface is not None, "Invalid interface"
    update_list = ["/sonic-db:CONFIG_DB/PORT/%s/admin_status:@./%s" % (interface, file_name)]
    path_list = ["/sonic-db:CONFIG_DB/PORT/%s/admin_status" % (interface)]

    # Shutdown interface
    text = "\"down\""
    with open(file_name, 'w') as file:
        file.write(text)
    ret, msg = gnmi_set(duthost, localhost, [], update_list, [])
    assert ret == 0, msg
    # Check interface status and gnmi_get result
    status = get_interface_status(duthost, "Admin", interface)
    assert status == "down", "Incremental config failed to toggle interface %s status" % interface
    ret, msg_list = gnmi_get(duthost, localhost, path_list)
    assert ret == 0, msg_list[0]
    assert msg_list[0] == "\"down\"", msg_list[0]

    # Startup interface
    text = "\"up\""
    with open(file_name, 'w') as file:
        file.write(text)
    ret, msg = gnmi_set(duthost, localhost, [], update_list, [])
    assert ret == 0, msg
    # Check interface status and gnmi_get result
    status = get_interface_status(duthost, "Admin", interface)
    assert status == "up", "Incremental config failed to toggle interface %s status" % interface
    ret, msg_list = gnmi_get(duthost, localhost, path_list)
    assert ret == 0, msg_list[0]
    assert msg_list[0] == "\"up\"", msg_list[0]


def test_gnmi_configdb_incremental_02(duthosts, rand_one_dut_hostname, localhost):
    '''
    Verify GNMI native write, incremental config for configDB
    GNMI set request with invalid path
    '''
    duthost = duthosts[rand_one_dut_hostname]
    file_name = "port.txt"
    update_list = ["/sonic-db:CONFIG_DB/PORTABC/Ethernet100/admin_status:@./%s" % (file_name)]

    # GNMI set request with invalid path
    text = "\"down\""
    with open(file_name, 'w') as file:
        file.write(text)
    ret, msg = gnmi_set(duthost, localhost, [], update_list, [])
    assert ret != 0, msg


def test_gnmi_configdb_full_01(duthosts, rand_one_dut_hostname, localhost):
    '''
    Verify GNMI native write, full config for configDB
    Toggle interface admin status
    '''
    duthost = duthosts[rand_one_dut_hostname]
    output = duthost.shell("sonic-cfggen -d --print-data")
    assert (not output['rc']), "No output"
    dic = json.loads(output["stdout"])
    assert "PORT" in dic, "Failed to read running config"
    interface = get_first_interface(duthost)
    assert interface is not None, "Invalid interface"
    assert interface in dic["PORT"], "Failed to get interface %s" % interface
    assert "admin_status" in dic["PORT"][interface], "Failed to get interface %s" % interface

    # Update full config with GNMI
    dic["PORT"][interface]["admin_status"] = "down"
    filename = "full.txt"
    with open(filename, 'w') as file:
        json.dump(dic, file)
    delete_list = ["/sonic-db:CONFIG_DB/"]
    update_list = ["/sonic-db:CONFIG_DB/:@%s" % filename]
    ret, msg = gnmi_set(duthost, localhost, delete_list, update_list, [])
    assert ret == 0, msg
    # Check interface status and gnmi_get result
    status = get_interface_status(duthost, "Admin", interface)
    assert status == "up", "Port status is changed"
    # GNOI reboot
    ret, msg = gnoi_reboot(duthost, localhost, 0, 0, "abc")
    pytest_assert(
        wait_until(600, 10, 0, duthost.critical_services_fully_started),
        "All critical services should be fully started!")
    wait_critical_processes(duthost)
    pytest_assert(
        wait_until(300, 10, 0, check_interface_status_of_up_ports, duthost),
        "Not all ports that are admin up on are operationally up")
    # Check interface status
    status = get_interface_status(duthost, "Admin", interface)
    assert status == "down", "Full config failed to toggle interface %s status" % interface
    # Startup interface
    duthost.shell("config interface startup %s" % interface)
