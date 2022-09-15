import logging
import pytest
import time
import re

from tests.common.devices.cisco import CiscoHost
from tests.common.devices.arista import AristaHost
from tests.common.devices.juniper import JuniperHost
from tests.common.devices.duthosts import DutHosts
from tests.common.utilities import get_inventory_files
from tests.common.utilities import get_host_vars

# CONFIG_PATH = '/var/tmp/'
# BASE_DIR = os.path.dirname(os.path.realpath(__file__))
# TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
# ISIS_TEMPLATE = 'isis_config.j2'

# logger = logging.getLogger(__name__)

# def recover_isis_config(duthosts):
#     """ recover isis configuration """
#     isis_vars = {
#          "primary_authentication_key":"rightpass",
#          "primary_authentication_type":"hmac-md5" 
#     }

#     for duthost in duthosts.nodes:
#        duthost.command("mkdir -p {}".format(CONFIG_PATH))
    
#        isis_config = 'isis_config.json'
#        isis_config_path = os.path.join(CONFIG_PATH, isis_config)
#        duthost.host.options['variable_manager'].extra_vars.update(isis_vars)

#        duthost.template(src=os.path.join(TEMPLATE_DIR, ISIS_TEMPLATE), dest=isis_config_path)
#        duthost.command('sonic-cfggen -j {} --write-to-db'.format(isis_config_path))  


# @pytest.fixture(scope="module")
# def common_setup_teardown(ptfhost, duthosts):
#     """clean up configure"""
#     yield None
    
#     #Recover PTF interface and route table
#     ptfhost.shell("""
#                     ip netns exec net1 ip link set dev eth1 netns 1
#                     ip netns del net1
#                     ip link set eth1 up
#                     ip addr del 10.0.0.57 dev eth0
#                     ip route del 10.0.4.0/24 via 10.0.0.56 dev eth0 
#                     """, module_ignore_errors=True)
    
#     recover_isis_config(duthosts)
def pytest_addoption(parser):
    ############################
    #   dut_vendor options     #
    ############################
    parser.addoption("--dut_vendor", action="store", default="sonic", type=str,
                     choices=["arista", "cisco", "juniper", "sonic"], help="dut device vendor name")

def pytest_ignore_collect(path, config):
    """
    Exclude vendor test cases under wan_test/vendor_test/
    """
    dut_vendor = config.getoption("--dut_vendor")
    dir_path = path.strpath
    if path.isfile():
        dir_path = path.dirpath().strpath
    if dut_vendor != 'sonic' and re.search(r'\s*wan_test/vendor_test$', dir_path) is None:
    # for non-sonic test, only cases in wan_test/vendor_test should be collected, others cases should be ignored.
        return True
    elif dut_vendor == 'sonic' and re.search(r'\s*wan_test/vendor_test$', dir_path) is not None:
    # for sonic test, all cases should be collected except wan_test/vendor_test
        return True
    return False

def pytest_collection_modifyitems(session, config, items):
    """
    Adding --dut_vendor to avoid pull a bunch of data from non-sonic dut device, but it also will
    result in many of APIs not available, it should be ok as these APIs are for sonic device only.
    """
    dut_vendor = config.getoption("--dut_vendor")
    not_support_fixtures = ['tag_test_report', 'duthosts', 'duthost', 'nbrhosts', 'creds', 'ptfhost',
                            'clear_neigh_entries', 'get_reboot_cause','reset_critical_services_list',
                            'verify_new_core_dumps', 'sanity_check', 'fanouthosts', 'conn_graph_facts',
                            'collect_db_dump','loganalyzer', 'run_icmp_responder_session', 'check_dut_health_status']
    if dut_vendor != 'sonic':
        for item in session.items:
            item.fixturenames = [fixtrue for fixtrue in item.fixturenames if fixtrue not in not_support_fixtures]

def get_host_data(request, dut):
    '''
    This function parses multple inventory files and returns the dut information present in the inventory
    '''
    inv_files = get_inventory_files(request)
    return get_host_vars(inv_files, dut)

@pytest.fixture(scope='session')
def ciscohosts(request, ansible_adhoc, tbinfo, creds):
    duts = []
    for host in tbinfo['duts']:
        data = get_host_data(request, host)
        if 'cisco' == data.get('image'):
            duts.append(CiscoHost(ansible_adhoc, host,
                                creds['cisco_login'] if 'cisco_login' in creds else None,
                                creds['cisco_password'] if 'cisco_password' in creds else None))
    return duts

@pytest.fixture(scope='session')
def aristahosts(request, ansible_adhoc, tbinfo):
    duts = []
    for host in tbinfo['duts']:
        data = get_host_data(request, host)
        if 'arista' == data.get('image'):
            duts.append(AristaHost(ansible_adhoc, host, data.get('ansible_user'), data.get('ansible_password')))
    return duts

@pytest.fixture(scope='session')
def juniperhosts(request, ansible_adhoc, tbinfo):
    duts = []
    for host in tbinfo['duts']:
        data = get_host_data(request, host)
        if 'juniper' == data.get('image'):
            duts.append(JuniperHost(ansible_adhoc, host, data.get('ansible_user'), data.get('ansible_password')))
    return duts

@pytest.fixture(scope='session')
def sonichosts(request, ansible_adhoc, tbinfo):
    dutnames = []
    for host in tbinfo['duts']:
        data = get_host_data(request, host)
        if 'sonic' == data.get('image') and host.startswith('vlab-'):
            dutnames.append(host)
    return DutHosts(ansible_adhoc, tbinfo, dutnames)

@pytest.fixture(scope="module")
def dut_collection(duthosts, enum_frontend_asic_index, ciscohosts, aristahosts, juniperhosts, sonichosts):
    duts = {}
    dutlist = []
    for duthost in sonichosts:
        config_facts = duthost.asic_instance(enum_frontend_asic_index).config_facts(host=duthost.hostname, source="running")['ansible_facts']
        for _, v in config_facts['DEVICE_NEIGHBOR'].items():
            if v['name'] not in dutlist:
                dutlist.append(v['name'])

    duts['sonic'] = [duthost for duthost in sonichosts if duthost.hostname in dutlist]
    duts['cisco'] = [duthost for duthost in ciscohosts if duthost.hostname in dutlist]
    duts['arista'] = [duthost for duthost in aristahosts if duthost.hostname in dutlist]
    duts['juniper'] = [duthost for duthost in juniperhosts if duthost.hostname in dutlist]

    return duts
