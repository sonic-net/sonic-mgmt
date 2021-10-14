import logging
import json
import time
import pytest

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('t0'),
]

vlan_id_list = [ 100, 200 ]

logger = logging.getLogger(__name__)

@pytest.fixture(scope="module")
def vlan_intfs_list():
    return [ { 'vlan_id': vlan, 'ip': '192.168.{}.1/24'.format(vlan) } for vlan in vlan_id_list  ]

@pytest.fixture(scope="module")
def rand_vlan_port(rand_selected_dut, tbinfo):
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    logger.info("Find a vlan port for new created vlan member")

    for v in mg_facts['minigraph_vlans'].values():
        if len(v['members']):
            return v['members'][0] 

    logger.error("No vlan member ready for test")
    pytest_assert(False, "No vlan member ready for test")


def create_test_vlans(duthost, vlan_intfs_list, rand_vlan_port):
    cmds = []
    logger.info("Add vlans, assign IPs, add member")

    for vlan in vlan_intfs_list:
        cmds.append('config vlan add {}'.format(vlan['vlan_id']))
        cmds.append("config interface ip add Vlan{} {}".format(vlan['vlan_id'], vlan['ip'].upper()))
        cmds.append('config vlan member add {} {}'.format(vlan['vlan_id'], rand_vlan_port))
    
    logger.info("Commands: {}".format(cmds))
    duthost.shell_cmds(cmds=cmds)

def create_test_dhcp_servers(duthost, vlan_intfs_list):
    cmds = []

    # Generate 4 dhcp servers for each new created vlan
    for vlan in vlan_intfs_list:
        for i in range(1, 5):
            cmds.append('config vlan dhcp_relay add {} 192.0.{}.{}'.format(vlan['vlan_id'], vlan['vlan_id'], i))
    
    duthost.shell_cmds(cmds=cmds)

@pytest.fixture(scope="module")
def setup_vlan(duthosts, rand_one_dut_hostname, vlan_intfs_list, rand_vlan_port):
    duthost = duthosts[rand_one_dut_hostname]

    # --------------------- Setup -----------------------
    try:
        create_test_vlans(duthost, vlan_intfs_list, rand_vlan_port)
        create_test_dhcp_servers(duthost, vlan_intfs_list)
        
    # --------------------- Testing -----------------------
        yield

    # --------------------- Teardown -----------------------
    finally:
        tearDown(duthost, vlan_intfs_list, rand_vlan_port)

def tearDown(duthost, vlan_intfs_list, rand_vlan_port):
    logger.info("VLAN test ending ...")
    logger.info("Delete VLAN intf")

    cmds = []

    for vlan in vlan_intfs_list:
        cmds.append('config vlan member del {} {}'.format(vlan['vlan_id'], rand_vlan_port))
        cmds.append("config interface ip remove Vlan{} {}".format(vlan['vlan_id'], vlan['ip'].upper()))
        cmds.append('config vlan del {}'.format(vlan['vlan_id']))

    logger.info("Commands: {}".format(cmds))
    duthost.shell_cmds(cmds=cmds,  module_ignore_errors=True)

    # Clean up files
    duthost.shell('rm -rf {}'.format(DUT_EMPTY_JSON_FILE))
    duthost.shell('rm -rf {}'.format(DUT_ADD_SERVERS_JSON_FILE))
    duthost.shell('rm -rf {}'.format(DUT_DEL_SERVERS_JSON_FILE))

DUT_EMPTY_JSON_FILE='/tmp/dhcp_empty.json'
def test_dhcp_relay_tc1_empty(duthost, setup_vlan):
    """Test Empty JSON file to see if apply-patch command work
    """
    empty_json = []
    duthost.copy(content=json.dumps(empty_json, indent=4), dest=DUT_EMPTY_JSON_FILE)

    cmds = 'config apply-patch {}'.format(DUT_EMPTY_JSON_FILE)

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds)

    pytest_assert("Patch applied successfully" in output['stdout'], "apply-patch is not working correctly")

DUT_ADD_SERVERS_JSON_FILE='/tmp/dhcp_add_servers.json'
DUT_DEL_SERVERS_JSON_FILE='/tmp/dhcp_del_servers.json'
def test_dhcp_relay_tc2_servers(duthost, setup_vlan):
    """Test add and del dhcp servers cases
    """

    dhcp_add_servers_json = [{
    "op": "add",
    "path": "/VLAN/Vlan200/dhcp_servers/4",
    "value": "192.0.200.5"
    },
    {
    "op": "add",
    "path": "/VLAN/Vlan100/dhcp_servers/4",
    "value": "192.0.100.5"
    }]

    dhcp_del_servers_json = [{
    "op": "remove",
    "path": "/VLAN/Vlan200/dhcp_servers/4"
    },
    {
    "op": "remove",
    "path": "/VLAN/Vlan100/dhcp_servers/4"
    }]

    # Test add dhcp_server
    duthost.copy(content=json.dumps(dhcp_add_servers_json, indent=4), dest=DUT_ADD_SERVERS_JSON_FILE)

    cmds = 'config apply-patch {}'.format(DUT_ADD_SERVERS_JSON_FILE)

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds)

    pytest_assert("Patch applied successfully" in output['stdout'], "Please check if json file is validate")
    time.sleep(5)
    pytest_assert(duthost.is_service_fully_started('dhcp_relay'), "dhcp_relay service is not running")
    
    output = duthost.shell('docker exec dhcp_relay ps aux')
    pytest_assert("192.0.100.5" in output['stdout'], "dhcp server for Vlan100 is not added successfully")
    pytest_assert("192.0.200.5" in output['stdout'], "dhcp server for Vlan200 is not added successfully")
    
    # Test del dhcp_server
    duthost.copy(content=json.dumps(dhcp_del_servers_json, indent=4), dest=DUT_DEL_SERVERS_JSON_FILE)

    cmds = 'config apply-patch {}'.format(DUT_DEL_SERVERS_JSON_FILE)

    logger.info("Commands: {}".format(cmds))
    output = duthost.shell(cmds)

    pytest_assert("Patch applied successfully" in output['stdout'], "Please check if json file is validate")
    time.sleep(5)
    pytest_assert(duthost.is_service_fully_started('dhcp_relay'), "dhcp_relay service not running")
    
    output = duthost.shell('docker exec dhcp_relay ps aux')
    pytest_assert("192.0.100.5" not in output['stdout'], "dhcp server for Vlan100 is not deleted successfully")
    pytest_assert("192.0.200.5" not in output['stdout'], "dhcp server for Vlan200 is not deleted successfully")
