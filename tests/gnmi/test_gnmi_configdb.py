import json
import logging
import multiprocessing
import pytest
import re
import time

from .helper import gnmi_set, gnmi_get, gnoi_reboot
from .helper import gnmi_subscribe_polling
from .helper import gnmi_subscribe_streaming_sample, gnmi_subscribe_streaming_onchange
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
    if 'Lanes' not in status_data[0]:
        return None
    admin_index = status_data[0].split().index('Admin')
    lanes_index = status_data[0].split().index('Lanes')
    for line in status_data:
        interface_status = line.strip()
        assert len(interface_status) > 0, "Failed to read interface properties"
        sl = interface_status.split()
        # Skip portchannel
        if sl[lanes_index] == 'N/A':
            continue
        if sl[admin_index] == 'up':
            return sl[0]
    return None


def get_interface_status(duthost, field, interface='Ethernet0'):
    cmds = 'sonic-db-cli CONFIG_DB hget "PORT|{}" {}'.format(interface, field)
    output = duthost.shell(cmds)
    assert (not output['rc']), "No output"
    return output["stdout"]


def test_gnmi_configdb_incremental_01(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI native write, incremental config for configDB
    Toggle interface admin status
    '''
    duthost = duthosts[rand_one_dut_hostname]
    file_name = "port.txt"
    interface = get_first_interface(duthost)
    assert interface is not None, "Invalid interface"
    update_list = ["/sonic-db:CONFIG_DB/localhost/PORT/%s/admin_status:@/root/%s" % (interface, file_name)]
    path_list = ["/sonic-db:CONFIG_DB/localhost/PORT/%s/admin_status" % (interface)]

    # Shutdown interface
    text = "\"down\""
    with open(file_name, 'w') as file:
        file.write(text)
    ptfhost.copy(src=file_name, dest='/root')
    gnmi_set(duthost, ptfhost, [], update_list, [])
    # Check interface status and gnmi_get result
    status = get_interface_status(duthost, "admin_status", interface)
    assert status == "down", "Incremental config failed to toggle interface %s status" % interface
    msg_list = gnmi_get(duthost, ptfhost, path_list)
    assert msg_list[0] == "\"down\"", msg_list[0]

    # Startup interface
    text = "\"up\""
    with open(file_name, 'w') as file:
        file.write(text)
    ptfhost.copy(src=file_name, dest='/root')
    gnmi_set(duthost, ptfhost, [], update_list, [])
    # Check interface status and gnmi_get result
    status = get_interface_status(duthost, "admin_status", interface)
    assert status == "up", "Incremental config failed to toggle interface %s status" % interface
    msg_list = gnmi_get(duthost, ptfhost, path_list)
    assert msg_list[0] == "\"up\"", msg_list[0]


def test_gnmi_configdb_incremental_02(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI native write, incremental config for configDB
    GNMI set request with invalid path
    '''
    duthost = duthosts[rand_one_dut_hostname]
    file_name = "port.txt"
    update_list = ["/sonic-db:CONFIG_DB/localhost/PORTABC/Ethernet100/admin_status:@/root/%s" % (file_name)]

    # GNMI set request with invalid path
    text = "\"down\""
    with open(file_name, 'w') as file:
        file.write(text)
    ptfhost.copy(src=file_name, dest='/root')
    try:
        gnmi_set(duthost, ptfhost, [], update_list, [])
    except Exception as e:
        logger.info("Incremental config failed: " + str(e))
    else:
        pytest.fail("Set request with invalid path")


test_data_metadata = [
    {
        "name": "Subscribe table for DEVICE_METADATA",
        "path": "/sonic-db:CONFIG_DB/localhost/DEVICE_METADATA"
    },
    {
        "name": "Subscribe table key for DEVICE_METADATA",
        "path": "/sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost"
    },
    {
        "name": "Subscribe table field for DEVICE_METADATA",
        "path": "/sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost/bgp_asn"
    }
]


@pytest.mark.parametrize('test_data', test_data_metadata)
def test_gnmi_configdb_polling_01(duthosts, rand_one_dut_hostname, ptfhost, test_data):
    '''
    Verify GNMI subscribe API, streaming onchange mode
    Subscribe polling mode
    '''
    duthost = duthosts[rand_one_dut_hostname]
    exp_cnt = 3
    path_list = [test_data["path"]]
    msg, _ = gnmi_subscribe_polling(duthost, ptfhost, path_list, 1000, exp_cnt)
    assert msg.count("bgp_asn") >= exp_cnt, test_data["name"] + ": " + msg


@pytest.mark.parametrize('test_data', test_data_metadata)
def test_gnmi_configdb_streaming_sample_01(duthosts, rand_one_dut_hostname, ptfhost, test_data):
    '''
    Verify GNMI subscribe API, streaming onchange mode
    Subscribe streaming sample mode
    '''
    duthost = duthosts[rand_one_dut_hostname]
    exp_cnt = 5
    path_list = [test_data["path"]]
    msg, _ = gnmi_subscribe_streaming_sample(duthost, ptfhost, path_list, 0, exp_cnt)
    assert msg.count("bgp_asn") >= exp_cnt, test_data["name"] + ": " + msg


@pytest.mark.parametrize('test_data', test_data_metadata)
def test_gnmi_configdb_streaming_onchange_01(duthosts, rand_one_dut_hostname, ptfhost, test_data):
    '''
    Verify GNMI subscribe API, streaming onchange mode
    Subscribe streaming onchange mode
    '''
    duthost = duthosts[rand_one_dut_hostname]
    run_flag = multiprocessing.Value('I', True)

    # Update DEVICE_METADATA table to trigger onchange event
    def worker(duthost, run_flag):
        for i in range(100):
            if not run_flag.value:
                break
            time.sleep(0.5)
            cmd = "sonic-db-cli CONFIG_DB hdel \"DEVICE_METADATA|localhost\" bgp_asn "
            duthost.shell(cmd, module_ignore_errors=True)
            time.sleep(0.5)
            cmd = "sonic-db-cli CONFIG_DB hset \"DEVICE_METADATA|localhost\" bgp_asn " + str(i+1000)
            duthost.shell(cmd, module_ignore_errors=True)

    client_task = multiprocessing.Process(target=worker, args=(duthost, run_flag,))
    client_task.start()
    exp_cnt = 5
    path_list = [test_data["path"]]
    msg, _ = gnmi_subscribe_streaming_onchange(duthost, ptfhost, path_list, exp_cnt*2)
    run_flag.value = False
    client_task.join()
    assert msg.count("bgp_asn") >= exp_cnt, test_data["name"] + ": " + msg


def test_gnmi_configdb_streaming_onchange_02(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI subscribe API, streaming onchange mode
    Subscribe table, and verify gnmi output has table key
    '''
    duthost = duthosts[rand_one_dut_hostname]
    run_flag = multiprocessing.Value('I', True)

    # Update DEVICE_METADATA table to trigger onchange event
    def worker(duthost, run_flag):
        for i in range(100):
            if not run_flag.value:
                break
            time.sleep(0.5)
            cmd = "sonic-db-cli CONFIG_DB hset \"DEVICE_METADATA|localhost\" bgp_asn " + str(i+1000)
            duthost.shell(cmd, module_ignore_errors=True)

    client_task = multiprocessing.Process(target=worker, args=(duthost, run_flag,))
    client_task.start()
    exp_cnt = 3
    path_list = ["/sonic-db:CONFIG_DB/localhost/DEVICE_METADATA"]
    msg, _ = gnmi_subscribe_streaming_onchange(duthost, ptfhost, path_list, exp_cnt)
    run_flag.value = False
    client_task.join()

    match_list = re.findall("json_ietf_val: \"({.*?})\"", msg)
    assert len(match_list) >= exp_cnt, "Missing json_ietf_val in gnmi response: " + msg
    for match in match_list:
        result = json.loads(match)
        # Verify table key
        assert "localhost" in result, "Invalid result: " + match
        # Verify table field
        assert "bgp_asn" in result["localhost"], "Invalid result: " + match


def test_gnmi_configdb_full_01(duthosts, rand_one_dut_hostname, ptfhost):
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
    ptfhost.copy(src=filename, dest='/root')
    delete_list = ["/sonic-db:CONFIG_DB/localhost/"]
    update_list = ["/sonic-db:CONFIG_DB/localhost/:@/root/%s" % filename]
    gnmi_set(duthost, ptfhost, delete_list, update_list, [])
    # Check interface status and gnmi_get result
    status = get_interface_status(duthost, "admin_status", interface)
    assert status == "up", "Port status is changed"
    # GNOI reboot
    gnoi_reboot(duthost, 0, 0, "abc")
    pytest_assert(
        wait_until(600, 10, 0, duthost.critical_services_fully_started),
        "All critical services should be fully started!")
    wait_critical_processes(duthost)
    pytest_assert(
        wait_until(300, 10, 0, check_interface_status_of_up_ports, duthost),
        "Not all ports that are admin up on are operationally up")
    # Check interface status
    status = get_interface_status(duthost, "admin_status", interface)
    assert status == "down", "Full config failed to toggle interface %s status" % interface
    # Startup interface
    duthost.shell("config interface startup %s" % interface)
