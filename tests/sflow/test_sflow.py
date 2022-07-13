"""
    Tests the sFlow feature in SONiC.

    Parameters:
        --enable_sflow_feature: Enable sFlow feature on DUT. Default is disabled
"""

import pytest
import logging
import time
import json
import re

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py     # lgtm[py/unused-import]
from tests.ptf_runner import ptf_runner
from tests.common import reboot
from tests.common  import config_reload
from tests.common.utilities import wait_until
from netaddr import *

pytestmark = [
    pytest.mark.topology('t0')
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope='module',autouse=True)
def setup(duthosts, rand_one_dut_hostname, ptfhost, tbinfo, config_sflow_feature):
    duthost = duthosts[rand_one_dut_hostname]
    global var
    var = {}

    feature_status, _ = duthost.get_feature_status()
    if 'sflow' not in feature_status or feature_status['sflow'] == 'disabled':
        pytest.skip("sflow feature is not eanbled")

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    var['router_mac']  = duthost.facts['router_mac']
    vlan_dict = mg_facts['minigraph_vlans']
    var['test_ports'] = []
    var['ptf_test_indices'] = []
    var['sflow_ports'] = {}

    for i in range(0,3,1):
        var['test_ports'].append(vlan_dict['Vlan1000']['members'][i])
        var['ptf_test_indices'].append(mg_facts['minigraph_ptf_indices'][vlan_dict['Vlan1000']['members'][i]])

    collector_ips = ['20.1.1.2' ,'30.1.1.2']
    var['dut_intf_ips'] = ['20.1.1.1','30.1.1.1']
    var['mgmt_ip'] = mg_facts['minigraph_mgmt_interface']['addr']
    var['lo_ip'] =  mg_facts['minigraph_lo_interfaces'][0]['addr']

    config_dut_ports(duthost,var['test_ports'][0:2],vlan=1000)

    for port_channel, interfaces in mg_facts['minigraph_portchannels'].items():
        port = interfaces['members'][0]
        var['sflow_ports'][port] = {}
        var['sflow_ports'][port]['ifindex'] = get_ifindex(duthost,port)
        var['sflow_ports'][port]['port_index'] = get_port_index(duthost,port)
        var['sflow_ports'][port]['ptf_indices'] = mg_facts['minigraph_ptf_indices'][interfaces['members'][0]]
        var['sflow_ports'][port]['sample_rate'] = 512
    var['portmap'] = json.dumps(var['sflow_ports'])

    udp_port = 6343
    for i in range(0,2,1):
        var['collector%s'%i] = {}
        var['collector%s'%i]['name'] = 'collector%s'%i
        var['collector%s'%i]['ip_addr'] = collector_ips[i]
        var['collector%s'%i]['port'] = udp_port
        udp_port += 1
    collector_ports = var['ptf_test_indices'][0:2]
    setup_ptf(ptfhost,collector_ports)

    # -------- Testing ----------
    yield
    # -------- Teardown ----------
    config_reload(duthost, config_source='minigraph', wait=120)

 # ----------------------------------------------------------------------------------
def setup_ptf(ptfhost, collector_ports):
    root_dir   = "/root"
    extra_vars = {'arp_responder_args' : '--conf /tmp/sflow_arpresponder.conf'}
    ptfhost.host.options['variable_manager'].extra_vars.update(extra_vars)
    ptfhost.template(src="../ansible/roles/test/templates/arp_responder.conf.j2", dest="/etc/supervisor/conf.d/arp_responder.conf")
    ptfhost.shell('supervisorctl reread')
    ptfhost.shell('supervisorctl update')
    for i in range(len(collector_ports)):
        ptfhost.shell('ifconfig eth%s %s/24' %(collector_ports[i],var['collector%s'%i]['ip_addr']))
    ptfhost.copy(content=var['portmap'],dest="/tmp/sflow_ports.json")

# ----------------------------------------------------------------------------------

def config_dut_ports(duthost, ports, vlan):
   # https://github.com/Azure/sonic-buildimage/issues/2665
   # Introducing config vlan member add and remove for the test port due to above mentioned PR.
   # Even though port is deleted from vlan , the port shows its master as Bridge upon assigning ip address.
   # Hence config reload is done as workaround. ##FIXME
    for i in range(len(ports)):
        duthost.command('config vlan member del %s %s' %(vlan,ports[i]))
        duthost.command('config interface ip add %s %s/24' %(ports[i],var['dut_intf_ips'][i]))
    duthost.command('config save -y')
    config_reload(duthost, config_source='config_db', wait=120)
    time.sleep(5)

# ----------------------------------------------------------------------------------

def get_ifindex(duthost, port):
     ifindex = duthost.shell('cat /sys/class/net/%s/ifindex' %port)['stdout']
     return ifindex

# ----------------------------------------------------------------------------------

def get_port_index(duthost, port):
    py_version = 'python' if '201911' in duthost.os_version else 'python3'

    # if sonic_py_common.port_util exist, use port_util from sonic_py_common.
    util_lib = "swsssdk"
    cmd = "{} -c \"import pkgutil; print(pkgutil.find_loader(\'sonic_py_common.port_util\'))\"".format(py_version)
    class_exist = duthost.shell(cmd)['stdout']
    if class_exist != "None":
        util_lib = "sonic_py_common"

    cmd = "{} -c \"from {} import port_util; print(port_util.get_index_from_str(\'{}\'))\""
    index = duthost.shell(cmd.format(py_version, util_lib, port))['stdout']
    return index

# ----------------------------------------------------------------------------------

@pytest.fixture
def config_sflow_agent(duthosts, rand_one_dut_hostname):
    # NOTE: When no agent-id is set, hsflowd chooses the agent-id based on simple heuristics
    # Hence, this fixture to keep the test stable
    duthost = duthosts[rand_one_dut_hostname]
    duthost.shell("config sflow agent-id del") # Remove any existing agent-id
    duthost.shell("config sflow agent-id add Loopback0")
    yield
    duthost.shell("config sflow agent-id del")

# ----------------------------------------------------------------------------------

def config_sflow(duthost, sflow_status='enable'):
    duthost.shell('config sflow %s'%sflow_status)
    time.sleep(2)
# ----------------------------------------------------------------------------------

@pytest.fixture(scope='module')
def config_sflow_feature(request, duthost):
    # Enable sFlow feature on DUT if enable_sflow_feature argument was passed
    if request.config.getoption("--enable_sflow_feature"):
        feature_status, _ = duthost.get_feature_status()
        if feature_status['sflow'] == 'disabled':
            duthost.shell("sudo config feature state sflow enabled")
            time.sleep(2)
# ----------------------------------------------------------------------------------

def config_sflow_interfaces(duthost, intf, **kwargs):

    if 'status' in kwargs:
        duthost.shell('config sflow interface %s %s'%(kwargs['status'],intf))
    if 'sample_rate' in kwargs:
        duthost.shell('config sflow interface sample-rate %s %s' %(intf,kwargs['sample_rate']))

# ----------------------------------------------------------------------------------

def config_sflow_collector(duthost, collector, config):
     collector = var[collector]
     if config == 'add':
          duthost.shell('config sflow collector add %s %s --port %s ' %(collector['name'],collector['ip_addr'],collector['port']))
     elif config == 'del':
          duthost.shell('config sflow collector  del %s' %collector['name'])
# ----------------------------------------------------------------------------------



def verify_show_sflow(duthost, status, **kwargs):
    show_sflow = duthost.shell('show sflow')['stdout']
    assert re.search("sFlow Admin State:\s+%s"%status,show_sflow), "Sflow Admin State is not %s"%status
    if 'polling_int' in kwargs:
        assert re.search("sFlow Polling Interval:\s+%s"%kwargs['polling_int'],show_sflow) , "Sflow Polling Interval is not %s"%kwargs['polling_int']
    if 'agent_id' in kwargs:
        assert re.search("sFlow AgentID:\s+%s"%kwargs['agent_id'],show_sflow), "Sflow Agent Id is not %s" %kwargs['agent_id']
    if 'collector' in kwargs:
        collector = kwargs['collector']
        if len(collector) is None:
            assert re.search("0 Collectors configured",show_sflow)," Expected 0 collectors , but collectors are present"
        else:
            assert re.search("%s Collectors configured:"%len(collector),show_sflow) ,"Number of Sflow collectors should be %s"%len(collector)
            for col  in collector:
                assert re.search("Name:\s+%s\s+IP addr:\s%s\s+UDP port:\s%s"%(var[col]['name'],var[col]['ip_addr'],var[col]['port']),show_sflow) , "col %s is not properly Configured" %col

# ----------------------------------------------------------------------------------

def verify_sflow_interfaces(duthost, intf, status, sampling_rate):
    show_sflow_intf = duthost.shell('show sflow interface')['stdout']
    assert re.search("%s\s+\|\s+%s\s+\|\s+%s"%(intf,status,sampling_rate),show_sflow_intf),"Interface %s is not properly configured"%intf

# ----------------------------------------------------------------------------------

@pytest.fixture
def partial_ptf_runner(request, ptfhost, tbinfo):
    def _partial_ptf_runner(**kwargs):
        params = {'testbed_type': tbinfo['topo']['name'],
                  'router_mac': var['router_mac'],
                  'dst_port' : var['ptf_test_indices'][2],
                  'agent_id' : var['lo_ip'],
                  'sflow_ports_file' : "/tmp/sflow_ports.json"}
        params.update(kwargs)
        ptf_runner(host=ptfhost,
                   testdir="ptftests",
                   platform_dir="ptftests",
                   testname="sflow_test",
                   params=params,
                   socket_recv_size=16384,
                   log_file="/tmp/{}.{}.log".format(request.cls.__name__, request.function.__name__),
                   is_python3=True)

    return _partial_ptf_runner

# ----------------------------------------------------------------------------------
@pytest.fixture(scope='class')
def sflowbase_config(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    config_sflow(duthost,'enable')
    config_sflow_collector(duthost,'collector0','add')
    config_sflow_collector(duthost,'collector1','add')
    duthost.shell("config sflow polling-interval 20")
    for port in var['sflow_ports']:
        config_sflow_interfaces(duthost,port,status='enable',sample_rate='512')
    time.sleep(2)
    verify_show_sflow(duthost,status='up',collector=['collector0','collector1'])
    for intf in var['sflow_ports']:
        verify_sflow_interfaces(duthost,intf,'up',512)



# ----------------------------------------------------------------------------------

class TestSflowCollector():
    """
    Test Sflow with 2 collectors , adding or removibg collector and verify collector samples
    """

    def test_sflow_config(self, duthosts, rand_one_dut_hostname, partial_ptf_runner):
        duthost = duthosts[rand_one_dut_hostname]
        # Enable sflow globally and enable sflow on 4 test interfaces
        # add single collector , send traffic and check samples are received in collector
        config_sflow(duthost,'enable')
        config_sflow_collector(duthost,'collector0','add')
        duthost.command("config sflow interface disable all")
        for port in var['sflow_ports']:
            config_sflow_interfaces(duthost,port,status='enable',sample_rate='512')
        verify_show_sflow(duthost,status='up',collector=['collector0'])
        for intf in var['sflow_ports']:
            verify_sflow_interfaces(duthost,intf,'up',512)
        time.sleep(5)
        partial_ptf_runner(
              enabled_sflow_interfaces=var['sflow_ports'].keys(),
              active_collectors="['collector0']" )


    def test_collector_del_add(self, duthosts, rand_one_dut_hostname, partial_ptf_runner):
        duthost = duthosts[rand_one_dut_hostname]
        # Delete a collector and check samples are not received in collectors
        config_sflow_collector(duthost,'collector0','del')
        time.sleep(2)
        verify_show_sflow(duthost,status='up',collector=[])
        time.sleep(5)
        partial_ptf_runner(
              enabled_sflow_interfaces=var['sflow_ports'].keys(),
              active_collectors="[]" )
        #re-add collector
        config_sflow_collector(duthost,'collector0','add')
        verify_show_sflow(duthost,status='up',collector=['collector0'])
        time.sleep(2)
        partial_ptf_runner(
              enabled_sflow_interfaces=var['sflow_ports'].keys(),
              active_collectors="['collector0']" )


    def test_two_collectors(self, sflowbase_config, duthosts, rand_one_dut_hostname, partial_ptf_runner):
        duthost = duthosts[rand_one_dut_hostname]
        #add 2 collectors with 2 different udp ports and check samples are received in both collectors
        verify_show_sflow(duthost,status='up',collector=['collector0','collector1'])
        time.sleep(2)
        partial_ptf_runner(
              enabled_sflow_interfaces=var['sflow_ports'].keys(),
              active_collectors="['collector0','collector1']" )

        # Remove second collector anc check samples are received in only 1st collector
        config_sflow_collector(duthost,'collector1','del')
        verify_show_sflow(duthost,status='up',collector=['collector0'])
        time.sleep(5)
        partial_ptf_runner(
              enabled_sflow_interfaces=var['sflow_ports'].keys(),
              active_collectors="['collector0']" )

        #Re-add second collector and check if samples are received in both collectors again
        config_sflow_collector(duthost,'collector1','add')
        verify_show_sflow(duthost,status='up',collector=['collector0','collector1'])
        time.sleep(5)
        partial_ptf_runner(
              enabled_sflow_interfaces=var['sflow_ports'].keys(),
              active_collectors="['collector0','collector1']" )

        # Add third collector and check only 2 collectors can be configured
        out = duthost.command("config sflow collector add collector2 192.168.0.5 ",module_ignore_errors=True)
        assert "Only 2 collectors can be configured, please delete one" in out['stdout']

        #remove first collector and check DUT sends samples to collector 2 woth non default port number (6344)
        config_sflow_collector(duthost,'collector0','del')
        verify_show_sflow(duthost,status='up',collector=['collector1'])
        time.sleep(10)
        partial_ptf_runner(
              enabled_sflow_interfaces=var['sflow_ports'].keys(),
              active_collectors="['collector1']" )



# ------------------------------------------------------------------------------
@pytest.mark.usefixtures("sflowbase_config")
@pytest.mark.usefixtures("config_sflow_agent")
class TestSflowPolling():
    """
    Test Sflow polling with different polling interval and check whether the test interface sends one counter sample for every polling interval
    Disable polling and check the dut doesn't send counter samples .
    """

    def testPolling(self, duthost, partial_ptf_runner):
        duthost.shell("config sflow polling-interval 20")
        verify_show_sflow(duthost,status='up',polling_int=20)
        partial_ptf_runner(
              polling_int=20,
              active_collectors="['collector0','collector1']" )

    def testDisablePolling(self, duthost, partial_ptf_runner):
        duthost.shell("config sflow polling-interval 0")

        verify_show_sflow(duthost,status='up',polling_int=0)
        partial_ptf_runner(
              polling_int=0,
              active_collectors="['collector0','collector1']" )

    def testDifferntPollingInt(self, duthost, partial_ptf_runner):
        duthost.shell("config sflow polling-interval 60")

        verify_show_sflow(duthost,status='up',polling_int=60)
        partial_ptf_runner(
              polling_int=60,
              active_collectors="['collector0','collector1']" )

# ------------------------------------------------------------------------------

class TestSflowInterface():
    """
    Enable / Disable Sflow interfaces and check the samples are received only from  the intended interface
    Test interfaceswith different sampling rates
    """

    def testIntfRemoval(self, sflowbase_config, duthost, partial_ptf_runner):
        sflow_int = sorted(var['sflow_ports'].keys())
        config_sflow_interfaces(duthost,sflow_int[0],status='disable')
        config_sflow_interfaces(duthost,sflow_int[1],status='disable')

        verify_sflow_interfaces(duthost,sflow_int[0],'down',512)
        verify_sflow_interfaces(duthost,sflow_int[1],'down',512)
        enabled_intf = sflow_int[2:]
        for intf in enabled_intf:
            verify_sflow_interfaces(duthost, intf, 'up', 512)
        partial_ptf_runner(
              enabled_sflow_interfaces=enabled_intf,
              active_collectors="['collector0','collector1']" )

    def testIntfSamplingRate(self, sflowbase_config, duthost, ptfhost, partial_ptf_runner):

        #re-add ports with different sampling rate
        sflow_int = sorted(var['sflow_ports'].keys())
        test_intf = sflow_int[0]
        test_intf1 =  sflow_int[1]
        config_sflow_interfaces(duthost,test_intf,status='enable',sample_rate=256)
        config_sflow_interfaces(duthost,test_intf1,status='enable',sample_rate=1024)

        var['sflow_ports'][test_intf]['sample_rate'] = 256
        var['sflow_ports'][test_intf1]['sample_rate'] = 1024
        var['portmap'] = json.dumps(var['sflow_ports'])
        for intf in sflow_int :
            verify_sflow_interfaces(duthost,intf,'up',var['sflow_ports'][intf]['sample_rate'])
        ptfhost.copy(content=var['portmap'],dest="/tmp/sflow_ports.json")
        time.sleep(2)
        partial_ptf_runner(
              enabled_sflow_interfaces=sflow_int,
              active_collectors="['collector0','collector1']" )

    def testIntfChangeSamplingRate(self, sflowbase_config, duthost, partial_ptf_runner, ptfhost):

        sflow_int = sorted(var['sflow_ports'].keys())
        test_intf = sflow_int[0]
        test_intf1 =  sflow_int[1]
        # revert the sampling rate to 512 on both ports
        config_sflow_interfaces(duthost,test_intf,sample_rate=512)
        config_sflow_interfaces(duthost,test_intf1,sample_rate=512)
        var['sflow_ports'][test_intf]['sample_rate'] = 512
        var['sflow_ports'][test_intf1]['sample_rate'] = 512
        var['portmap'] = json.dumps(var['sflow_ports'])
        for intf in sflow_int :
            verify_sflow_interfaces(duthost,intf,'up',var['sflow_ports'][intf]['sample_rate'])
        ptfhost.copy(content=var['portmap'],dest="/tmp/sflow_ports.json")
        partial_ptf_runner(
              enabled_sflow_interfaces=sflow_int,
              active_collectors="['collector0','collector1']" )

# ------------------------------------------------------------------------------
@pytest.mark.usefixtures("sflowbase_config")
class TestAgentId():
    """
    Add loopback0 ip as the agent id and check the samples are received with intended agent-id.
    Remove agent-ip and check whether samples are received with previously cofigured agent ip.
    Add eth0 ip as the agent ip and check the samples are received with intended agent-id.
    """

    def testNonDefaultAgent(self, duthost, partial_ptf_runner):
        agent_ip = var['lo_ip']
        duthost.shell(" config sflow agent-id del")
        duthost.shell(" config sflow agent-id  add Loopback0")
        verify_show_sflow(duthost,status='up',agent_id='Loopback0')
        partial_ptf_runner(
              polling_int=20,
              agent_id=agent_ip,
              active_collectors="['collector0','collector1']" )


    def testDelAgent(self, duthost, partial_ptf_runner):
        duthost.shell(" config sflow agent-id del")
        verify_show_sflow(duthost,status='up',agent_id='default')
        time.sleep(5)
        #Verify  whether the samples are received with previously configured agent ip
        partial_ptf_runner(
              polling_int=20,
              agent_id=var['lo_ip'],
              active_collectors="['collector0','collector1']" )

    def testAddAgent(self, duthost, partial_ptf_runner):
        agent_ip = var['mgmt_ip']
        duthost.shell(" config sflow agent-id  add  eth0")
        verify_show_sflow(duthost,status='up',agent_id='eth0')
        partial_ptf_runner(
              polling_int=20,
              agent_id=agent_ip,
              active_collectors="['collector0','collector1']" )

# ------------------------------------------------------------------------------

@pytest.mark.disable_loganalyzer
class TestReboot():

    def testRebootSflowEnable(self, sflowbase_config, config_sflow_agent, duthost, localhost, partial_ptf_runner, ptfhost):
        duthost.command("config sflow polling-interval 80")
        verify_show_sflow(duthost,status='up',polling_int=80)
        duthost.command('sudo config save -y')
        reboot(duthost, localhost)
        assert wait_until(300, 20, 0, duthost.critical_services_fully_started), "Not all critical services are fully started"
        verify_show_sflow(duthost,status='up',collector=['collector0','collector1'],polling_int=80)
        for intf in var['sflow_ports']:
            var['sflow_ports'][intf]['ifindex'] = get_ifindex(duthost,intf)
            var['sflow_ports'][intf]['port_index'] = get_port_index(duthost,intf)
            verify_sflow_interfaces(duthost,intf,'up',512)
        var['portmap'] = json.dumps(var['sflow_ports'])
        ptfhost.copy(content=var['portmap'],dest="/tmp/sflow_ports.json")
        partial_ptf_runner(
              enabled_sflow_interfaces=var['sflow_ports'].keys(),
              active_collectors="['collector0','collector1']" )
        # Test Polling
        partial_ptf_runner(
              polling_int=80,
              active_collectors="['collector0','collector1']" )


    def testRebootSflowDisable(self, sflowbase_config, duthost, localhost, partial_ptf_runner, ptfhost):
        config_sflow(duthost,sflow_status='disable')
        verify_show_sflow(duthost,status='down')
        partial_ptf_runner(
              enabled_sflow_interfaces=var['sflow_ports'].keys(),
              active_collectors="[]" )
        duthost.command('sudo config save -y')
        reboot(duthost, localhost)
        assert wait_until(300, 20, 0, duthost.critical_services_fully_started), "Not all critical services are fully started"
        verify_show_sflow(duthost,status='down')
        for intf in var['sflow_ports']:
            var['sflow_ports'][intf]['ifindex'] = get_ifindex(duthost,intf)
            var['sflow_ports'][intf]['port_index'] = get_port_index(duthost,intf)
        var['portmap'] = json.dumps(var['sflow_ports'])
        ptfhost.copy(content=var['portmap'],dest="/tmp/sflow_ports.json")
        partial_ptf_runner(
              enabled_sflow_interfaces=var['sflow_ports'].keys(),
              active_collectors="[]" )


    def testFastreboot(self, sflowbase_config, config_sflow_agent, duthost, localhost, partial_ptf_runner, ptfhost):

        config_sflow(duthost,sflow_status='enable')
        verify_show_sflow(duthost,status='up',collector=['collector0','collector1'])
        duthost.command('sudo config save -y')
        reboot(duthost, localhost,reboot_type='fast')
        assert wait_until(300, 20, 0, duthost.critical_services_fully_started), "Not all critical services are fully started"
        verify_show_sflow(duthost,status='up',collector=['collector0','collector1'])
        for intf in var['sflow_ports']:
            var['sflow_ports'][intf]['ifindex'] = get_ifindex(duthost,intf)
            var['sflow_ports'][intf]['port_index'] = get_port_index(duthost,intf)
            verify_sflow_interfaces(duthost,intf,'up',512)
        var['portmap'] = json.dumps(var['sflow_ports'])
        ptfhost.copy(content=var['portmap'],dest="/tmp/sflow_ports.json")
        partial_ptf_runner(
              enabled_sflow_interfaces=var['sflow_ports'].keys(),
              active_collectors="['collector0','collector1']" )

    def testWarmreboot(self, sflowbase_config, duthost, localhost, partial_ptf_runner, ptfhost):

        config_sflow(duthost,sflow_status='enable')
        verify_show_sflow(duthost,status='up',collector=['collector0','collector1'])
        duthost.command('sudo config save -y')
        reboot(duthost, localhost,reboot_type='warm')
        assert wait_until(300, 20, 0, duthost.critical_services_fully_started), "Not all critical services are fully started"
        verify_show_sflow(duthost,status='up',collector=['collector0','collector1'])
        for intf in var['sflow_ports']:
            var['sflow_ports'][intf]['ifindex'] = get_ifindex(duthost,intf)
            var['sflow_ports'][intf]['port_index'] = get_port_index(duthost,intf)
            verify_sflow_interfaces(duthost,intf,'up',512)
        var['portmap'] = json.dumps(var['sflow_ports'])
        ptfhost.copy(content=var['portmap'],dest="/tmp/sflow_ports.json")
        partial_ptf_runner(
              enabled_sflow_interfaces=var['sflow_ports'].keys(),
              active_collectors="['collector0','collector1']" )


