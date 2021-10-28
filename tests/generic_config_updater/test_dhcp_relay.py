import logging
import time
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.duthost_utils import utils_vlan_intfs_dict_orig, utils_vlan_intfs_dict_add, utils_create_test_vlans
from tests.generic_config_updater.dhcp_utils import apply_patch, expect_op_success, expect_res_success, expect_op_failure

pytestmark = [
    pytest.mark.topology('t0'),
]

logger = logging.getLogger(__name__)

@pytest.fixture(scope="module")
def cfg_facts(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']

@pytest.fixture(scope="module")
def vlan_intfs_dict(utils_vlan_intfs_dict_orig):
    ''' Add two new vlan for test

    If added vlan_id is 108 and 109, it will add a dict as below
    {108: {'ip': u'192.168.8.1/24', 'orig': False}, 109: {'ip': u'192.168.9.1/24', 'orig': False}}
    '''
    logger.info("vlan_intrfs_dict ORIG {}".format(utils_vlan_intfs_dict_orig))
    vlan_intfs_dict = utils_vlan_intfs_dict_add(utils_vlan_intfs_dict_orig, 2)
    logger.info("vlan_intrfs_dict FINAL {}".format(vlan_intfs_dict))
    return vlan_intfs_dict

@pytest.fixture(scope="module")
def rand_vlan_port(rand_selected_dut, tbinfo):
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    logger.info("Find a vlan port for new created vlan member")

    for v in mg_facts['minigraph_vlans'].values():
        if len(v['members']):
            return v['members'][0] 

    logger.error("No vlan member ready for test")
    pytest_assert(False, "No vlan member ready for test")

def ensure_dhcp_relay_running(duthost):
    if not duthost.is_service_fully_started('dhcp_relay'):
        duthost.shell('sudo systemctl start dhcp_relay')
        pytest_assert(duthost.is_service_fully_started('dhcp_relay'), "dhcp_relay service is not running before test dhcp servers")


def create_test_vlans(duthost, cfg_facts, vlan_intfs_dict, rand_vlan_port):
    '''Generate two vlan config for testing

    This function should generate two VLAN detail shown below
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |   VLAN ID | IP Address       | Ports     | Port Tagging   | Proxy ARP   | DHCP Helper Address   |
    +===========+==================+===========+================+=============+=======================+
    |       108 | 192.168.8.1/24   | Ethernet4 | tagged         | disabled    |                       |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |       109 | 192.168.9.1/24   | Ethernet4 | tagged         | disabled    |                       |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    '''

    logger.info("CREATE TEST VLANS START")
    vlan_ports_list = [{
        'dev': rand_vlan_port,
        'port_index' : 'unused',
        'permit_vlanid' : [ key for key, value in vlan_intfs_dict.items() ],
        'pvid': 0
    }]

    utils_create_test_vlans(duthost, cfg_facts, vlan_ports_list, vlan_intfs_dict, delete_untagged_vlan=False)
    logger.info("CREATE TEST VLANS DONE")

def clean_setup():
    pass

def default_setup(duthost, vlan_intfs_list):
    '''Generate 4 dhcp server for each vlan

    This VLAN detail shows below
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |   VLAN ID | IP Address       | Ports     | Port Tagging   | Proxy ARP   | DHCP Helper Address   |
    +===========+==================+===========+================+=============+=======================+
    |       108 | 192.168.108.1/24 | Ethernet4 | tagged         | disabled    | 192.0.108.1           |
    |           |                  |           |                |             | 192.0.108.2           |
    |           |                  |           |                |             | 192.0.108.3           |
    |           |                  |           |                |             | 192.0.108.4           |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |       109 | 192.168.109.1/24 | Ethernet4 | tagged         | disabled    | 192.0.109.1           |
    |           |                  |           |                |             | 192.0.109.2           |
    |           |                  |           |                |             | 192.0.109.3           |
    |           |                  |           |                |             | 192.0.109.4           |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    '''
    cmds = []
    expected_server_list = []

    # Generate 4 dhcp servers for each new created vlan
    for vlan in vlan_intfs_list:
        for i in range(1, 5):
            cmds.append('config vlan dhcp_relay add {} 192.0.{}.{}'.format(vlan, vlan, i))
            expected_server_list.append('192.0.{}.{}'.format(vlan, i))
    
    duthost.shell_cmds(cmds=cmds)
    time.sleep(5) # This may take more time if orignal config setup has more dhcp servers under vlan
    pytest_assert(duthost.is_service_fully_started('dhcp_relay'), "dhcp_relay service is not running during setup")
    expect_res_success(duthost, expected_server_list, unexpected_server_list=[])

def runout_setup():
    pass

#TODO: runout_setup
@pytest.fixture(scope="module", params=['clean_setup', 'default_setup'])
def init_dhcp_server_config(request):
    return request.param


@pytest.fixture(scope="module")
def setup_vlan(duthosts, rand_one_dut_hostname, vlan_intfs_dict, rand_vlan_port, cfg_facts, init_dhcp_server_config, vlan_intfs_list):
    duthost = duthosts[rand_one_dut_hostname]

    # --------------------- Setup -----------------------
    try:
        create_test_vlans(duthost, cfg_facts, vlan_intfs_dict, rand_vlan_port)
        ensure_dhcp_relay_running(duthost)

        if init_dhcp_server_config == "clean_setup":
            clean_setup
        elif init_dhcp_server_config == "default_setup":
            default_setup(duthost, vlan_intfs_list)
        elif init_dhcp_server_config == "runout_setup":
            runout_setup
        
    # --------------------- Testing -----------------------
        yield

    # --------------------- Teardown -----------------------
    finally:
        tearDown(duthost, vlan_intfs_dict, rand_vlan_port)

def tearDown(duthost, vlan_intfs_dict, rand_vlan_port):
    '''Clean up VLAN CONFIG for this test
    '''
    logger.info("VLAN test ending ...")
    logger.info("Delete VLAN intf")

    cmds = []

    for key, value in vlan_intfs_dict.items():
        if not value['orig']:
            cmds.append('config vlan member del {} {}'.format(key, rand_vlan_port))
            cmds.append("config interface ip remove Vlan{} {}".format(key, value['ip'].upper()))
            cmds.append('config vlan del {}'.format(key))

    logger.info("Commands: {}".format(cmds))
    duthost.shell_cmds(cmds=cmds,  module_ignore_errors=True)

    # Clean up files
    for temp_file in DHCP_TEST_FILE_LIST:
        duthost.shell('rm -rf {}'.format(temp_file))

    logger.info("TEARDOWN COMPLETED")

DHCP_TEST_FILE_LIST=[]
#TODO: DHCPV6 SETUP AND TEST
@pytest.fixture(scope="module")
def vlan_intfs_list(vlan_intfs_dict):
    return [ key for key, value in vlan_intfs_dict.items() if not value['orig'] ]

DUT_EMPTY_JSON='/tmp/dhcp_apply_empty.json'
DHCP_TEST_FILE_LIST.append(DUT_EMPTY_JSON)
def test_dhcp_relay_tc1_apply_empty(duthost, setup_vlan, init_dhcp_server_config):
    """Test apply empty JSON file to see if apply-patch command work as expected
    """
    dhcp_apply_empty_json = []

    output = apply_patch(duthost, json_data=dhcp_apply_empty_json, dest_file=DUT_EMPTY_JSON)
    expect_op_success(duthost, output)

DUT_RM_ON_EMPTY='/tmp/dhcp_rm_on_empty.json'
DHCP_TEST_FILE_LIST.append(DUT_RM_ON_EMPTY)
def test_dhcp_relay_tc2_rm_on_empty(duthost, setup_vlan, init_dhcp_server_config, vlan_intfs_list):
    """Test remove dhcp server on no dhcp server setup
    """
    if init_dhcp_server_config != "clean_setup":
        pytest.skip("Unsupported init config")

    dhcp_rm_on_empty_json = [
        {
            "op": "remove",
            "path": "/VLAN/Vlan" + str(vlan_intfs_list[0]) + "/dhcp_servers/1"
        }]

    output = apply_patch(duthost, json_data=dhcp_rm_on_empty_json, dest_file=DUT_RM_ON_EMPTY)
    expect_op_failure(output)

DUT_RM_NONEXIST='/tmp/dhcp_rm_nonexist.json'
DHCP_TEST_FILE_LIST.append(DUT_RM_NONEXIST)
def test_dhcp_relay_tc3_rm_nonexist(duthost, setup_vlan, init_dhcp_server_config, vlan_intfs_list):
    """Test remove nonexisted dhcp server on default setup
    """
    if init_dhcp_server_config != "default_setup":
        pytest.skip("Unsupported init config")

    dhcp_rm_nonexist_json = [
        {
            "op": "remove",
            "path": "/VLAN/Vlan"+ str(vlan_intfs_list[0]) + "/dhcp_servers/5"
        }]

    output = apply_patch(duthost, json_data=dhcp_rm_nonexist_json, dest_file=DUT_RM_NONEXIST)
    expect_op_failure(output)

DUT_ADD_EXIST='/tmp/dhcp_add_exist.json'
DHCP_TEST_FILE_LIST.append(DUT_ADD_EXIST)
def test_dhcp_relay_tc4_add_exist(duthost, setup_vlan, init_dhcp_server_config, vlan_intfs_list):
    """Test add existed dhcp server on default setup
    """
    if init_dhcp_server_config != "default_setup":
        pytest.skip("Unsupported init config")

    dhcp_add_exist_json = [
        {
            "op": "add",
            "path": "/VLAN/Vlan" + str(vlan_intfs_list[0]) + "/dhcp_servers/2",
            "value": "192.0." + str(vlan_intfs_list[0]) + ".3"
        }]

    output = apply_patch(duthost, json_data=dhcp_add_exist_json, dest_file=DUT_ADD_EXIST)
    expect_op_failure(output)

DUT_RM='/tmp/dhcp_rm.json'
DHCP_TEST_FILE_LIST.append(DUT_RM)
def test_dhcp_relay_tc5_rm(duthost, setup_vlan, init_dhcp_server_config, vlan_intfs_list):
    """Test normal remove dhcp server on default setup

    This VLAN detail should show below after test
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |   VLAN ID | IP Address       | Ports     | Port Tagging   | Proxy ARP   | DHCP Helper Address   |
    +===========+==================+===========+================+=============+=======================+
    |       108 | 192.168.108.1/24 | Ethernet4 | tagged         | disabled    | 192.0.108.1           |
    |           |                  |           |                |             | 192.0.108.2           |
    |           |                  |           |                |             | 192.0.108.3           |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |       109 | 192.168.109.1/24 | Ethernet4 | tagged         | disabled    | 192.0.109.1           |
    |           |                  |           |                |             | 192.0.109.2           |
    |           |                  |           |                |             | 192.0.109.3           |
    |           |                  |           |                |             | 192.0.109.4           |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    """
    if init_dhcp_server_config != "default_setup":
        pytest.skip("Unsupported init config")

    dhcp_rm_json = [
        {
        "op": "remove",
        "path": "/VLAN/Vlan" + str(vlan_intfs_list[0]) + "/dhcp_servers/3"
        }]
    output = apply_patch(duthost, json_data=dhcp_rm_json, dest_file=DUT_RM)
    expect_op_success(duthost, output)
    unexpected_server_list = ["192.0." + str(vlan_intfs_list[0]) + ".4"]
    expect_res_success(duthost, [], unexpected_server_list)

DUT_ADD='/tmp/dhcp_add.json'
DHCP_TEST_FILE_LIST.append(DUT_ADD)
def test_dhcp_relay_tc6_add(duthost, setup_vlan, init_dhcp_server_config, vlan_intfs_list):
    """Test normal add dhcp server on default setup

    This VLAN detail should show below after test
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |   VLAN ID | IP Address       | Ports     | Port Tagging   | Proxy ARP   | DHCP Helper Address   |
    +===========+==================+===========+================+=============+=======================+
    |       108 | 192.168.108.1/24 | Ethernet4 | tagged         | disabled    | 192.0.108.1           |
    |           |                  |           |                |             | 192.0.108.2           |
    |           |                  |           |                |             | 192.0.108.3           |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |       109 | 192.168.109.1/24 | Ethernet4 | tagged         | disabled    | 192.0.109.1           |
    |           |                  |           |                |             | 192.0.109.2           |
    |           |                  |           |                |             | 192.0.109.3           |
    |           |                  |           |                |             | 192.0.109.4           |
    |           |                  |           |                |             | 192.0.109.5           |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    """
    if init_dhcp_server_config != "default_setup":
        pytest.skip("Unsupported init config")

    dhcp_add_json = [
        {
            "op": "add",
            "path": "/VLAN/Vlan" + str(vlan_intfs_list[1]) + "/dhcp_servers/4",
            "value": "192.0." + str(vlan_intfs_list[1]) + ".5"
        }]

    output = apply_patch(duthost, json_data=dhcp_add_json, dest_file=DUT_ADD)
    expect_op_success(duthost, output)
    expected_server_list = ["192.0." + str(vlan_intfs_list[1]) + ".5"]
    expect_res_success(duthost, expected_server_list, [])

DUT_ADD_RM='/tmp/dhcp_add_rm.json'
DHCP_TEST_FILE_LIST.append(DUT_ADD_RM)
def test_dhcp_relay_tc7_add_rm(duthost, setup_vlan, init_dhcp_server_config, vlan_intfs_list):
    """Test mixed add and rm ops for dhcp server on default setup

    This VLAN detail should show below after test
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |   VLAN ID | IP Address       | Ports     | Port Tagging   | Proxy ARP   | DHCP Helper Address   |
    +===========+==================+===========+================+=============+=======================+
    |       108 | 192.168.108.1/24 | Ethernet4 | tagged         | disabled    | 192.0.108.1           |
    |           |                  |           |                |             | 192.0.108.2           |
    |           |                  |           |                |             | 192.0.108.3           |
    |           |                  |           |                |             | 192.0.108.4           |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |       109 | 192.168.109.1/24 | Ethernet4 | tagged         | disabled    | 192.0.109.1           |
    |           |                  |           |                |             | 192.0.109.2           |
    |           |                  |           |                |             | 192.0.109.3           |
    |           |                  |           |                |             | 192.0.109.4           |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    """
    if init_dhcp_server_config != "default_setup":
        pytest.skip("Unsupported init config")

    dhcp_add_rm_json = [
        {
            "op": "remove",
            "path": "/VLAN/Vlan" + str(vlan_intfs_list[1]) + "/dhcp_servers/4"
        },
        {
            "op": "add",
            "path": "/VLAN/Vlan" + str(vlan_intfs_list[0]) + "/dhcp_servers/3",
            "value": "192.0." + str(vlan_intfs_list[0]) + ".4"
        }]

    output = apply_patch(duthost, json_data=dhcp_add_rm_json, dest_file=DUT_ADD_RM)
    expect_op_success(duthost, output)
    expected_server_list = ["192.0." + str(vlan_intfs_list[0]) + ".4"]
    unexpected_server_list = ["192.0." + str(vlan_intfs_list[1]) + ".5"]
    expect_res_success(duthost, expected_server_list, unexpected_server_list)

DUT_REPLACE='/tmp/dhcp_replace.json'
DHCP_TEST_FILE_LIST.append(DUT_REPLACE)
def test_dhcp_relay_tc7_replace(duthost, setup_vlan, init_dhcp_server_config, vlan_intfs_list):
    """Test replace dhcp server on default setup

    This VLAN detail should show below after test
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |   VLAN ID | IP Address       | Ports     | Port Tagging   | Proxy ARP   | DHCP Helper Address   |
    +===========+==================+===========+================+=============+=======================+
    |       108 | 192.168.108.1/24 | Ethernet4 | tagged         | disabled    | 192.0.108.2           |
    |           |                  |           |                |             | 192.0.108.3           |
    |           |                  |           |                |             | 192.0.108.4           |
    |           |                  |           |                |             | 192.0.108.8           |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    |       109 | 192.168.109.1/24 | Ethernet4 | tagged         | disabled    | 192.0.109.1           |
    |           |                  |           |                |             | 192.0.109.2           |
    |           |                  |           |                |             | 192.0.109.3           |
    |           |                  |           |                |             | 192.0.109.4           |
    +-----------+------------------+-----------+----------------+-------------+-----------------------+
    """
    if init_dhcp_server_config != "default_setup":
        pytest.skip("Unsupported init config")

    dhcp_replace_json = [
        {
            "op": "replace",
            "path": "/VLAN/Vlan" + str(vlan_intfs_list[0]) + "/dhcp_servers/0",
            "value": "192.0." + str(vlan_intfs_list[0]) + ".8"
        }]

    output = apply_patch(duthost, json_data=dhcp_replace_json, dest_file=DUT_REPLACE)
    expect_op_success(duthost, output)
    expected_server_list = ["192.0." + str(vlan_intfs_list[0]) + ".8"]
    unexpected_server_list = ["192.0." + str(vlan_intfs_list[0]) + ".1"]
    expect_res_success(duthost, expected_server_list, unexpected_server_list)
