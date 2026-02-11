import json
import logging
import multiprocessing
import pytest
import re
import time

from .helper import gnmi_set, gnmi_get
from .helper import gnmi_subscribe_polling
from .helper import gnmi_subscribe_streaming_sample, gnmi_subscribe_streaming_onchange
from tests.common.helpers.gnmi_utils import add_gnmi_client_common_name
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure

logger = logging.getLogger(__name__)
allure.logger = logger

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


def get_sonic_cfggen_output(duthost, namespace=None):
    '''
    Fetch and return the sonic-cfggen output
    '''
    cmd = "sonic-cfggen -d --print-data"
    if namespace:
        cmd = f"sonic-cfggen -n {namespace} -d --print-data"
    output = duthost.shell(cmd)
    assert (not output['rc']), "No output"
    return (json.loads(output["stdout"]))


def wait_bgp_neighbor(duthost):
    '''
    Wait for BGP neighbor to be up
    '''
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
    pytest_assert(wait_until(60, 10, 0, duthost.check_bgp_session_state, list(bgp_neighbors.keys())),
                  "Not all BGP sessions are established on DUT")


def test_gnmi_configdb_incremental_01(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI native write, incremental config for configDB
    Toggle interface admin status
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("gnmi test relies on port data not present on supervisor card '%s'" % rand_one_dut_hostname)
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
    # Wait for BGP neighbor to be up
    wait_bgp_neighbor(duthost)


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


def test_gnmi_configdb_full_replace_01(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI native write, full config replace for configDB
    Toggle interface admin status
    '''
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.is_supervisor_node():
        pytest.skip("gnmi test relies on port data not present on supervisor card '%s'" % rand_one_dut_hostname)
    interface = get_first_interface(duthost)
    assert interface is not None, "Invalid interface"

    # Get ASIC namespace and check interface
    if duthost.sonichost.is_multi_asic:
        for asic in duthost.frontend_asics:
            dic = get_sonic_cfggen_output(duthost, asic.namespace)
            if interface in dic["PORT"]:
                break
    else:
        dic = get_sonic_cfggen_output(duthost)

    assert "PORT" in dic, "Failed to read running config"
    assert interface in dic["PORT"], "Failed to get interface %s" % interface
    assert "admin_status" in dic["PORT"][interface], "Failed to get interface %s" % interface

    def check_admin_status(duthost, interface, expected_status):
        status = get_interface_status(duthost, "admin_status", interface)
        return status == expected_status

    # Make sure interface is up to begin with
    assert check_admin_status(duthost, interface, "up"), "Unexpected port status"

    # Update full config with GNMI
    dic["PORT"][interface]["admin_status"] = "down"
    filename = "full.txt"
    with open(filename, 'w') as file:
        json.dump(dic, file)
    ptfhost.copy(src=filename, dest='/root')

    replace_list = ["/sonic-db:CONFIG_DB/localhost/:@/root/%s" % filename]
    gnmi_set(duthost, ptfhost, [], [], replace_list)

    # Check that interface is down after full config push
    pytest_assert(
        wait_until(30, 2, 0, check_admin_status, duthost, interface, "down"),
        "Full config failed to toggle interface %s status" % interface)

    # Startup interface
    duthost.shell("config interface startup %s" % interface)
    duthost.shell("config save -y")
    # Wait for BGP neighbor to be up
    wait_bgp_neighbor(duthost)


def test_gnmi_configdb_set_authenticate(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI native write with authentication
    '''
    duthost = duthosts[rand_one_dut_hostname]
    file_name = "cloud.txt"
    text = "\"Public\""
    with open(file_name, 'w') as file:
        file.write(text)
    ptfhost.copy(src=file_name, dest='/root')
    update_list = ["/sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost/cloudtype:@/root/%s" % (file_name)]

    with allure.step("Verify GNMI set with noaccess role"):
        role = "gnmi_config_db_noaccess"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        try:
            gnmi_set(duthost, ptfhost, [], update_list, [])
        except Exception as e:
            logger.info("Failed to set: " + str(e))
            assert role in str(e), str(e)

    with allure.step("Verify GNMI set with readwrite role"):
        role = "gnmi_config_db_readwrite"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        try:
            gnmi_set(duthost, ptfhost, [], update_list, [])
        except Exception as e:
            logger.info("Failed to set: " + str(e))
            pytest.fail("Set request failed: " + str(e))

    with allure.step("Verify GNMI set with readonly role"):
        role = "gnmi_config_db_readonly"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        try:
            gnmi_set(duthost, ptfhost, [], update_list, [])
        except Exception as e:
            logger.info("Failed to set: " + str(e))
            assert role in str(e), str(e)

    with allure.step("Verify GNMI set with empty role"):
        role = ""
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        try:
            gnmi_set(duthost, ptfhost, [], update_list, [])
        except Exception as e:
            logger.info("Failed to set: " + str(e))
            assert "write access" in str(e), str(e)

    # Restore default role
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")


def test_gnmi_configdb_get_authenticate(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI native read with authentication
    '''
    duthost = duthosts[rand_one_dut_hostname]
    path_list = ["/sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost"]

    with allure.step("Verify GNMI get with noaccess role"):
        role = "gnmi_config_db_noaccess"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        try:
            gnmi_get(duthost, ptfhost, path_list)
        except Exception as e:
            logger.info("Failed to get: " + str(e))
            assert role in str(e), str(e)

    with allure.step("Verify GNMI get with readwrite role"):
        role = "gnmi_config_db_readwrite"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        try:
            gnmi_get(duthost, ptfhost, path_list)
        except Exception as e:
            logger.info("Failed to get: " + str(e))
            pytest.fail("Get request failed: " + str(e))

    with allure.step("Verify GNMI get with readonly role"):
        role = "gnmi_config_db_readonly"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        try:
            gnmi_get(duthost, ptfhost, path_list)
        except Exception as e:
            logger.info("Failed to get: " + str(e))
            pytest.fail("Get request failed: " + str(e))

    with allure.step("Verify GNMI get with empty role"):
        role = ""
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        try:
            gnmi_get(duthost, ptfhost, path_list)
        except Exception as e:
            logger.info("Failed to get: " + str(e))
            pytest.fail("Get request failed: " + str(e))

    # Restore default role
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")


def test_gnmi_configdb_subscribe_authenticate(duthosts, rand_one_dut_hostname, ptfhost):
    '''
    Verify GNMI native read with authentication
    '''
    duthost = duthosts[rand_one_dut_hostname]
    path_list = ["/sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost"]

    with allure.step("Verify GNMI subscribe with noaccess role"):
        role = "gnmi_config_db_noaccess"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        output, _ = gnmi_subscribe_streaming_sample(duthost, ptfhost, path_list, 0, 1)
        logger.info("GNMI subscribe output: " + output)
        assert "GRPC error" in output, output
        assert role in output, output

    with allure.step("Verify GNMI subscribe with readwrite role"):
        role = "gnmi_config_db_readwrite"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        output, _ = gnmi_subscribe_streaming_sample(duthost, ptfhost, path_list, 0, 1)
        assert "GRPC error" not in output, output
        assert "cloudtype" in output, output

    with allure.step("Verify GNMI subscribe with readonly role"):
        role = "gnmi_config_db_readonly"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        output, _ = gnmi_subscribe_streaming_sample(duthost, ptfhost, path_list, 0, 1)
        assert "GRPC error" not in output, output
        assert "cloudtype" in output, output

    with allure.step("Verify GNMI subscribe with empty role"):
        role = ""
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        output, _ = gnmi_subscribe_streaming_sample(duthost, ptfhost, path_list, 0, 1)
        assert "GRPC error" not in output, output
        assert "cloudtype" in output, output

    # Restore default role
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")
