import json
import logging
import multiprocessing
import pytest
import shlex
import time

from .helper import is_mgmt_vrf_enabled
from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.gnmi_utils import add_gnmi_client_common_name
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import DEFAULT_VRF_NAME, MGMT_VRF_NAME, wait_until
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.pygnmi_client import PygnmiClientError, SubscribeMode, StreamMode

logger = logging.getLogger(__name__)
allure.logger = logger

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server", "check_dut_timestamp")
]


VRF_SCENARIOS = [
    {"name": "default_1", "vrf": None, "description": "Default (no VRF)"},
    {"name": "default_2", "vrf": DEFAULT_VRF_NAME, "description": f"Default (explicit '{DEFAULT_VRF_NAME}')"},
    {"name": "mgmt", "vrf": MGMT_VRF_NAME, "description": "Management VRF"},
]


@pytest.fixture(scope="module", params=VRF_SCENARIOS, ids=lambda scenario: f"vrf_{scenario['name']}")
def vrf_config(request, duthosts, rand_one_dut_hostname, ptfhost):
    duthost = duthosts[rand_one_dut_hostname]
    vrf_cfg = request.param.copy()
    vrf_cfg.update({
        "dut_ip": duthost.mgmt_ip,
        "ptf_ip": ptfhost.mgmt_ip,
        "dut_intf": "eth0",
        "ptf_intf": "mgmt",
    })
    return vrf_cfg


@pytest.fixture(scope="module", autouse=True)
def setup_vrf_configuration(duthosts, rand_one_dut_hostname, vrf_config):
    """
    This fixture runs before gnmi_tls to ensure VRF config is in place.
    Only default and mgmt VRFs are supported.

    While these GNMI tests do not depend on SNMP, some tests fail while waiting
    for all critical processes to be up and running. These are caused by SNMP
    agent address misconfiguration during VRF transition. Hence SNMP services
    are stopped before toggling mgmt VRF and restarted after.
    """
    duthost = duthosts[rand_one_dut_hostname]
    vrf_name = vrf_config["vrf"]
    mgmt_vrf_enabled = is_mgmt_vrf_enabled(duthost)
    original_vrf = duthost.shell('sonic-db-cli CONFIG_DB hget "GNMI|gnmi" vrf')["stdout"]
    original_vrf_exists = duthost.shell('sonic-db-cli CONFIG_DB hexists "GNMI|gnmi" vrf')["stdout"] == "1"

    try:
        if vrf_name == MGMT_VRF_NAME and not mgmt_vrf_enabled:
            duthost.shell('sudo systemctl stop snmpd snmp-subagent', module_ignore_errors=True)
            duthost.shell('sonic-db-cli CONFIG_DB hset "MGMT_VRF_CONFIG|vrf_global" "mgmtVrfEnabled" "true"')
            duthost.shell('sudo systemctl start snmpd snmp-subagent', module_ignore_errors=True)
        if vrf_name is None:
            duthost.shell('sonic-db-cli CONFIG_DB hdel "GNMI|gnmi" vrf')
        else:
            duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" vrf "{}"'.format(vrf_name))
        yield vrf_config

    finally:
        if original_vrf_exists:
            duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" vrf {}'.format(shlex.quote(original_vrf)))
        else:
            duthost.shell('sonic-db-cli CONFIG_DB hdel "GNMI|gnmi" vrf')
        if vrf_name == MGMT_VRF_NAME and not mgmt_vrf_enabled:
            duthost.shell('sudo systemctl stop snmpd snmp-subagent', module_ignore_errors=True)
            duthost.shell('sonic-db-cli CONFIG_DB hset "MGMT_VRF_CONFIG|vrf_global" "mgmtVrfEnabled" "false"')
            duthost.shell('sonic-db-cli CONFIG_DB hdel "MGMT_VRF_CONFIG|vrf_global" "mgmtVrfEnabled"')
            # Tests may save while the management VRF is enabled.
            duthost.shell("sudo config save -y")
            duthost.shell('sudo systemctl start snmpd snmp-subagent', module_ignore_errors=True)
        duthost.shell("config save -y")
        duthost.shell("sudo systemctl restart gnmi")


def get_first_interface(duthost, excluded_interfaces=[]):
    if duthost.is_supervisor_node():
        return None
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
        intf_name = sl[0]
        # Skip portchannel
        if sl[lanes_index] == 'N/A' or intf_name in excluded_interfaces:
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


def test_gnmi_configdb_incremental_01(gnmi_tls, vrf_config):  # noqa: F811
    '''
    Verify GNMI native write, incremental config for configDB
    Toggle interface admin status
    '''
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    if duthost.is_supervisor_node():
        pytest.skip("gnmi test relies on port data not present on supervisor card '%s'" % duthost.hostname)
    interface = get_first_interface(duthost, [vrf_config['dut_intf']])
    assert interface is not None, "Invalid interface"
    path_list = ["/sonic-db:CONFIG_DB/localhost/PORT/%s/admin_status" % (interface)]

    # Shutdown interface
    text = "\"down\""
    update_list = [(path_list[0], text)]
    client.set(update=update_list)
    # Check interface status and gnmi_get result
    status = get_interface_status(duthost, "admin_status", interface)
    assert status == "down", "Incremental config failed to toggle interface %s status" % interface
    msg_list = client.get(path_list)["notification"][0]["update"]
    assert msg_list[0]["val"] == "down", msg_list[0]

    # Startup interface
    text = "\"up\""
    update_list = [(path_list[0], text)]
    client.set(update=update_list)
    # Check interface status and gnmi_get result
    status = get_interface_status(duthost, "admin_status", interface)
    assert status == "up", "Incremental config failed to toggle interface %s status" % interface
    msg_list = client.get(path_list)["notification"][0]["update"]
    assert msg_list[0]["val"] == "up", msg_list[0]
    # Wait for BGP neighbor to be up
    wait_bgp_neighbor(duthost)


def test_gnmi_configdb_incremental_02(gnmi_tls, vrf_config):  # noqa: F811
    '''
    Verify GNMI native write, incremental config for configDB
    GNMI set request with invalid path
    '''
    client = gnmi_tls.pygnmi_client

    # GNMI set request with invalid path
    text = "\"down\""
    update_list = [("/sonic-db:CONFIG_DB/localhost/PORTABC/Ethernet100/admin_status", text)]
    try:
        client.set(update=update_list)
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
def test_gnmi_configdb_polling_01(gnmi_tls, test_data, vrf_config):  # noqa: F811
    '''
    Verify GNMI subscribe API, streaming onchange mode
    Subscribe polling mode
    '''
    client = gnmi_tls.pygnmi_client
    exp_cnt = 3
    path_list = [test_data["path"]]
    msg = json.dumps(list(client.subscribe(
        path_list, mode=SubscribeMode.POLL, poll_count=exp_cnt, poll_interval=1, prefix="sonic-db:",
    )))
    assert msg.count("bgp_asn") >= exp_cnt, test_data["name"] + ": " + msg


@pytest.mark.parametrize('test_data', test_data_metadata)
def test_gnmi_configdb_streaming_sample_01(gnmi_tls, test_data, vrf_config):  # noqa: F811
    '''
    Verify GNMI subscribe API, streaming onchange mode
    Subscribe streaming sample mode
    '''
    client = gnmi_tls.pygnmi_client
    exp_cnt = 5
    path_list = [test_data["path"]]
    msg = json.dumps(list(client.subscribe(
        path_list, mode=SubscribeMode.STREAM, stream_mode=StreamMode.SAMPLE,
        sample_interval=0, count=exp_cnt, collect_seconds=30, prefix="sonic-db:",
    )))
    assert msg.count("bgp_asn") >= exp_cnt, test_data["name"] + ": " + msg


@pytest.mark.parametrize('test_data', test_data_metadata)
def test_gnmi_configdb_streaming_onchange_01(gnmi_tls, test_data, vrf_config):  # noqa: F811
    '''
    Verify GNMI subscribe API, streaming onchange mode
    Subscribe streaming onchange mode
    '''
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
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
    try:
        msg = json.dumps(list(client.subscribe(
            path_list, stream_mode=StreamMode.ON_CHANGE, count=exp_cnt*2,
            collect_seconds=120, prefix="sonic-db:",
        )))
    finally:
        run_flag.value = False
        client_task.join()
    assert msg.count("bgp_asn") >= exp_cnt, test_data["name"] + ": " + msg


def test_gnmi_configdb_streaming_onchange_02(gnmi_tls, vrf_config):  # noqa: F811
    '''
    Verify GNMI subscribe API, streaming onchange mode
    Subscribe table, and verify gnmi output has table key
    '''
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
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
    try:
        msg = list(client.subscribe(
            path_list, stream_mode=StreamMode.ON_CHANGE, count=exp_cnt,
            collect_seconds=120, prefix="sonic-db:",
        ))
    finally:
        run_flag.value = False
        client_task.join()

    match_list = [json.dumps(update["val"]) for response in msg
                  for update in response.get("update", {}).get("update", [])]
    msg = json.dumps(msg)
    assert len(match_list) >= exp_cnt, "Missing json_ietf_val in gnmi response: " + msg
    for match in match_list:
        result = json.loads(match)
        # Verify table key
        assert "localhost" in result, "Invalid result: " + match
        # Verify table field
        assert "bgp_asn" in result["localhost"], "Invalid result: " + match


def test_gnmi_configdb_full_replace_01(gnmi_tls, vrf_config):  # noqa: F811
    '''
    Verify GNMI native write, full config replace for configDB
    Toggle interface admin status
    '''
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    if duthost.is_supervisor_node():
        pytest.skip("gnmi test relies on port data not present on supervisor card '%s'" % duthost.hostname)
    interface = get_first_interface(duthost, [vrf_config['dut_intf']])
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
    replace_list = [("/sonic-db:CONFIG_DB/localhost/", json.dumps(dic))]
    client.set(replace=replace_list)

    # Check that interface is down after full config push
    pytest_assert(
        wait_until(30, 2, 0, check_admin_status, duthost, interface, "down"),
        "Full config failed to toggle interface %s status" % interface)

    # Startup interface
    duthost.shell("config interface startup %s" % interface)
    duthost.shell("config save -y")
    # Wait for BGP neighbor to be up
    wait_bgp_neighbor(duthost)


def test_gnmi_configdb_set_authenticate(gnmi_tls, vrf_config):  # noqa: F811
    '''
    Verify GNMI native write with authentication
    '''
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    text = "\"Public\""
    update_list = [("/sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost/cloudtype", text)]

    with allure.step("Verify GNMI set with noaccess role"):
        role = "gnmi_config_db_noaccess"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        try:
            client.set(update=update_list)
        except Exception as e:
            logger.info("Failed to set: " + str(e))
            assert role in str(e), str(e)

    with allure.step("Verify GNMI set with readwrite role"):
        role = "gnmi_config_db_readwrite"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        try:
            client.set(update=update_list)
        except Exception as e:
            logger.info("Failed to set: " + str(e))
            pytest.fail("Set request failed: " + str(e))

    with allure.step("Verify GNMI set with readonly role"):
        role = "gnmi_config_db_readonly"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        try:
            client.set(update=update_list)
        except Exception as e:
            logger.info("Failed to set: " + str(e))
            assert role in str(e), str(e)

    with allure.step("Verify GNMI set with empty role"):
        role = ""
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        try:
            client.set(update=update_list)
        except Exception as e:
            logger.info("Failed to set: " + str(e))
            assert "write access" in str(e), str(e)

    # Restore default role
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")


def test_gnmi_configdb_get_authenticate(gnmi_tls, vrf_config):  # noqa: F811
    '''
    Verify GNMI native read with authentication
    '''
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    path_list = ["/sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost"]

    with allure.step("Verify GNMI get with noaccess role"):
        role = "gnmi_config_db_noaccess"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        try:
            client.get(path_list)
        except Exception as e:
            logger.info("Failed to get: " + str(e))
            assert role in str(e), str(e)

    with allure.step("Verify GNMI get with readwrite role"):
        role = "gnmi_config_db_readwrite"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        try:
            client.get(path_list)
        except Exception as e:
            logger.info("Failed to get: " + str(e))
            pytest.fail("Get request failed: " + str(e))

    with allure.step("Verify GNMI get with readonly role"):
        role = "gnmi_config_db_readonly"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        try:
            client.get(path_list)
        except Exception as e:
            logger.info("Failed to get: " + str(e))
            pytest.fail("Get request failed: " + str(e))

    with allure.step("Verify GNMI get with empty role"):
        role = ""
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        try:
            client.get(path_list)
        except Exception as e:
            logger.info("Failed to get: " + str(e))
            pytest.fail("Get request failed: " + str(e))

    # Restore default role
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")


def test_gnmi_configdb_subscribe_authenticate(gnmi_tls, vrf_config):  # noqa: F811
    '''
    Verify GNMI native read with authentication
    '''
    duthost = gnmi_tls.duthost
    client = gnmi_tls.pygnmi_client
    path_list = ["/sonic-db:CONFIG_DB/localhost/DEVICE_METADATA/localhost"]

    with allure.step("Verify GNMI subscribe with noaccess role"):
        role = "gnmi_config_db_noaccess"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        with pytest.raises(PygnmiClientError, match=role):
            list(client.subscribe(path_list, sample_interval=0, count=1,
                                  collect_seconds=30, prefix="sonic-db:"))

    with allure.step("Verify GNMI subscribe with readwrite role"):
        role = "gnmi_config_db_readwrite"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        output = json.dumps(list(client.subscribe(path_list, sample_interval=0, count=1,
                                                  collect_seconds=30, prefix="sonic-db:")))
        assert "GRPC error" not in output, output
        assert "cloudtype" in output, output

    with allure.step("Verify GNMI subscribe with readonly role"):
        role = "gnmi_config_db_readonly"
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        output = json.dumps(list(client.subscribe(path_list, sample_interval=0, count=1,
                                                  collect_seconds=30, prefix="sonic-db:")))
        assert "GRPC error" not in output, output
        assert "cloudtype" in output, output

    with allure.step("Verify GNMI subscribe with empty role"):
        role = ""
        add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic", role)
        output = json.dumps(list(client.subscribe(path_list, sample_interval=0, count=1,
                                                  collect_seconds=30, prefix="sonic-db:")))
        assert "GRPC error" not in output, output
        assert "cloudtype" in output, output

    # Restore default role
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")
