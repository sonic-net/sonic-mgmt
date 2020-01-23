import csv
import json
import logging
import re
import random
import sys
import time
import threading
import Queue

import ipaddr as ipaddress
import pytest

from ansible_host import AnsibleHost
from common.devices import SonicHost
from common.utilities import wait_until
from natsort import natsorted
from ptf_runner import ptf_runner

sys.path.append("../ansible/library")
import topo_facts

# global vars
g_vars = {}
test_scenario    = "l3"
mclag_local_ip   = ipaddress.IPNetwork("10.100.1.1/30")
mclag_peer_ip    = ipaddress.IPNetwork("{}/{}".format(mclag_local_ip.ip+1, mclag_local_ip.prefixlen))

# SSH defines
SONIC_SSH_PORT  = 22
SONIC_SSH_REGEX = 'OpenSSH_[\\w\\.]+ Debian'

class TBInfo(object):
    """
    Parse the CSV file used to describe whole testbed info
    Please refer to the example of the CSV file format
    CSV file first line is title
    The topology name in title is using uniq-name | conf-name
    """

    def __init__(self, testbed_file):
        self.testbed_filename = testbed_file
        self.testbed_topo = {}

        with open(self.testbed_filename) as f:
            topo = csv.DictReader(f)
            for line in topo:
                tb_prop = {}
                name = ''
                for key in line:
                    if ('uniq-name' in key or 'conf-name' in key) and '#' in line[key]:
                        ### skip comment line
                        continue
                    elif 'uniq-name' in key or 'conf-name' in key:
                        name = line[key]
                    elif 'ptf_ip' in key and line[key]:
                        ptfaddress = ipaddress.IPNetwork(line[key])
                        tb_prop['ptf_ip'] = str(ptfaddress.ip)
                        tb_prop['ptf_netmask'] = str(ptfaddress.netmask)
                    else:
                        tb_prop[key] = line[key]
                if name:
                    self.testbed_topo[name] = tb_prop

# functions
def continuous_traffic_check(casename, event, ptf_runner, exc_queue, **kwargs):
    '''
    With this simple warpper function, we could use a Queue to store the
    exception infos and check it later in main thread.

    Example:
        refer to test warm_reboot
    '''
    while True:
        try:
            log_file = "/tmp/mclag/log/mclag_{}_[{}]_[{}]_{}.log".format(test_scenario, casename, sys._getframe().f_code.co_name, time.strftime("%H%M%S"))
            ptf_runner(log_file=log_file, **kwargs)
        except Exception:
            exc_queue.put(sys.exc_info())
        if not event.is_set():
            break

def check_teamd_status(host, addr=None, status='up', ptf=False, base=0, select=True):
    if ptf:
        for lag in g_vars['mclag_interfaces']:
            lag_id = int(lag.strip("PortChannel"))
            state = host.shell("teamdctl PortChannel{} state dump".format(lag_id))['stdout']
            port = base + (lag_id - 1)
            server_port_status = json.loads(state)['ports']['eth{}'.format(port)]['runner']['selected']
            logging.info("Device: {}, status: {}, expect: {}".format(lag, server_port_status, select))
            if server_port_status == select:
                continue
            else:
                return False
    else:
        for lag in g_vars['mclag_interfaces']:
            sys_id = host.shell("teamdctl {} state item get team_device.ifinfo.dev_addr".format(lag))['stdout']
            logging.info("Device: {}, dev_addr: {}".format(lag, sys_id))
            if sys_id != addr:
                return False
            else:
                continue
        time.sleep(30)
        for lag in g_vars['mclag_interfaces']:
            lag_status = host.shell("redis-cli -n 0 hget LAG_TABLE:{} oper_status".format(lag))['stdout']
            logging.info("Device: {}, oper_status: {}".format(lag, lag_status))
            if lag_status != status:
                return False
            else:
                continue
    return True

def check_warm_status(host):
    finalizer_state = host.shell("systemctl is-active warmboot-finalizer.service", module_ignore_errors=True)['stdout']
    if finalizer_state == 'inactive':
        return True
    else:
        return False

# FIXME later may move to "common.reboot"
#
# The reason to introduce a new 'reboot' here is due to
# the difference of fixture 'localhost' between the two 'reboot' functions.
#
# 'common.reboot' request *ansible_fixtures.localhost*,
# but here it request *common.devices.Localhost*.
def reboot(duthost, localhost, delay=10, timeout=180, wait=120, basic_check=True):
    """
    cold reboots DUT
    :param duthost: DUT host object
    :param localhost:  local host object
    :param delay: delay between ssh availability checks
    :param timeout: timeout for waiting ssh port state change
    :param wait: time to wait for DUT to initialize
    :param basic_check: check duthost.critical_services_fully_started after DUT initialize
    :return:
    """

    dut_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).address
    duthost.shell("nohup reboot &")

    logging.info('waiting for ssh to drop')
    res = localhost.wait_for(host=dut_ip,
                             port=SONIC_SSH_PORT,
                             state='absent',
                             search_regex=SONIC_SSH_REGEX,
                             delay=delay,
                             timeout=timeout)

    if res.is_failed:
        raise Exception('DUT did not shutdown')

    # TODO: add serial output during reboot for better debuggability
    #       This feature requires serial information to be present in
    #       testbed information

    logging.info('waiting for ssh to startup')
    res = localhost.wait_for(host=dut_ip,
                             port=SONIC_SSH_PORT,
                             state='started',
                             search_regex=SONIC_SSH_REGEX,
                             delay=delay,
                             timeout=timeout)

    if res.is_failed:
        raise Exception('DUT did not startup')

    logging.info('ssh has started up')

    logging.info('waiting for switch to initialize')
    time.sleep(wait)

    if basic_check:
        assert wait_until(timeout, 10, duthost.critical_services_fully_started), \
               "All critical services should fully started!{}".format(duthost.CRITICAL_SERVICES)

# fixtures
@pytest.fixture(scope="module")
def localhost(testbed_devices):
    return testbed_devices['localhost']

@pytest.fixture(scope="module")
def duthost2(ansible_adhoc, request):
    """
    Shortcut fixture for getting DUT2 host
    """
    tbname = request.config.getoption("--testbed")
    tbfile = request.config.getoption("--testbed_file")
    tbinfo = TBInfo(tbfile)
    hostname2 = tbinfo.testbed_topo[tbname+'-dut2']['dut']
    return SonicHost(ansible_adhoc, hostname2, gather_facts=True)

@pytest.fixture(scope="module", autouse=True)
def setup_init(testbed, duthost, duthost2, ptfhost, localhost):
    global g_vars
    # get dut origin router-mac
    g_vars.update({'dut1_router_mac': duthost.shell("redis-cli -n 4 hget 'DEVICE_METADATA|localhost' mac")['stdout']})
    g_vars.update({'dut2_router_mac': duthost2.shell("redis-cli -n 4 hget 'DEVICE_METADATA|localhost' mac")['stdout']})

    tp_facts = topo_facts.ParseTestbedTopoinfo().get_topo_config(testbed['topo'])
    tp_facts_dut1 = topo_facts.ParseTestbedTopoinfo().get_topo_config(testbed['topo'] + "_dut1")
    tp_facts_dut2 = topo_facts.ParseTestbedTopoinfo().get_topo_config(testbed['topo'] + "_dut2")

    # get mclag topo info
    g_vars.update({'mclag_interconnection_interfaces': tp_facts['devices_interconnect_interfaces'].values()})
    g_vars.update({'mclag_link_server_interfaces': tp_facts['host_interfaces']})
    g_vars.update({'mclag_link_vm_interfaces': tp_facts['link_vm_interfaces']})

    # get dut topo info
    g_vars.update({'dut1_interconnection_interfaces': [p for port in tp_facts_dut1['devices_interconnect_interfaces'].values() for p in port]})
    g_vars.update({'dut1_link_server_interfaces': tp_facts_dut1['host_interfaces']})
    g_vars.update({'dut1_link_vm_interfaces': tp_facts_dut1['link_vm_interfaces']})
    g_vars.update({'dut1_all_interfaces': g_vars['dut1_link_server_interfaces'] + g_vars['dut1_interconnection_interfaces'] + g_vars['dut1_link_vm_interfaces']})

    g_vars.update({'dut2_interconnection_interfaces': [p for port in tp_facts_dut2['devices_interconnect_interfaces'].values() for p in port]})
    g_vars.update({'dut2_link_server_interfaces': [p for p in g_vars['mclag_link_server_interfaces'] if p not in g_vars['dut1_link_server_interfaces']]})
    g_vars.update({'dut2_link_vm_interfaces': [p for p in g_vars['mclag_link_vm_interfaces'] if p not in g_vars['dut1_link_vm_interfaces']]})
    g_vars.update({'dut2_all_interfaces': g_vars['dut2_link_server_interfaces'] + g_vars['dut2_interconnection_interfaces'] + g_vars['dut2_link_vm_interfaces']})

    # get dut1/dut2 port_alisa
    dut1_hwsku = duthost.shell("show platform summary |grep HwSKU|awk '{print $2}'")['stdout']
    dut2_hwsku = duthost2.shell("show platform summary |grep HwSKU|awk '{print $2}'")['stdout']
    g_vars.update({'dut1_port_alias': duthost.port_alias(hwsku=dut1_hwsku)['ansible_facts']})
    g_vars.update({'dut2_port_alias': duthost2.port_alias(hwsku=dut2_hwsku)['ansible_facts']})

    # get dut1/dut2 port_ptf_indices
    g_vars.update({'dut1_orphan_ports': g_vars['dut1_link_server_interfaces'][len(g_vars['dut1_link_server_interfaces'])/2-2:len(g_vars['dut1_link_server_interfaces'])/2] + \
                    g_vars['dut1_link_server_interfaces'][-2:]})
    g_vars.update({'dut2_orphan_ports': g_vars['dut2_link_server_interfaces'][len(g_vars['dut2_link_server_interfaces'])/2-2:len(g_vars['dut2_link_server_interfaces'])/2] + \
                    g_vars['dut2_link_server_interfaces'][-2:]})


    # init to ptf
    ptfhost.shell("mkdir -p /tmp/mclag/log")
    ptfhost.copy(src="ptftests", dest="/root")
    ptfhost.script("scripts/remove_ip.sh")
    ptfhost.script("scripts/change_mac.sh")

    g_vars.update({'mclag_port_channel_id_list': range(1, len(g_vars['dut1_link_server_interfaces'])+1)})

    ptf_mac_prefix = ptfhost.shell("ip -br link show eth0|awk '{print $3}'")['stdout'][:-2]
    g_vars.update({'ptf_mac_prefix': ptf_mac_prefix})
    g_vars.update({'dut1_server_mac': [(g_vars['ptf_mac_prefix']+"{:02x}".format(i-1)).upper() for i in g_vars['mclag_port_channel_id_list']]})
    dut2_server_mac =   [(g_vars['ptf_mac_prefix']+"{:02x}".format(i-1)).upper() for i in g_vars['mclag_port_channel_id_list'][:len(g_vars['mclag_port_channel_id_list'])/2-2]] + \
                        [(g_vars['ptf_mac_prefix']+"{:02x}".format(i+len(g_vars['dut1_all_interfaces'])-1)).upper() for i in g_vars['mclag_port_channel_id_list'][len(g_vars['mclag_port_channel_id_list'])/2-2:len(g_vars['mclag_port_channel_id_list'])/2]] + \
                        [(g_vars['ptf_mac_prefix']+"{:02x}".format(i-1)).upper() for i in g_vars['mclag_port_channel_id_list'][len(g_vars['mclag_port_channel_id_list'])/2:-2]] + \
                        [(g_vars['ptf_mac_prefix']+"{:02x}".format(i+len(g_vars['dut1_all_interfaces'])-1)).upper() for i in g_vars['mclag_port_channel_id_list'][-2:]]
    g_vars.update({'dut2_server_mac': dut2_server_mac})

    for lag_id in g_vars['mclag_port_channel_id_list']:
        ptf_extra_vars = {
            'test_scenario'         : test_scenario,
            'item'                  : lag_id,
            'ptf_mac_prefix'        : g_vars['ptf_mac_prefix'],
            'dut1_all_interfaces'   : g_vars['dut1_all_interfaces'],
            'dut1_link_server_interfaces': g_vars['dut1_link_server_interfaces'],
            'mclag_port_channel_id_list' : g_vars['mclag_port_channel_id_list'],
            'mclag_link_vm_interfaces'   : g_vars['mclag_link_vm_interfaces']
        }
        ptfhost.host.options['variable_manager'].extra_vars = ptf_extra_vars
        ptfhost.template(src="mclag/mclag_ptf_port_channel_config_files.j2", dest="/tmp/mclag/PortChannel{}.conf".format(lag_id))

    ptfhost.template(src="mclag/mclag_ptf_port_channel_startup.j2", dest="/tmp/mclag/mclag_ptf.sh", mode="u+rwx")
    ptfhost.template(src="mclag/mclag_switch_info.j2", dest="/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario))

    ptfhost.shell("/tmp/mclag/mclag_ptf.sh startup_portchannel_{}".format(test_scenario))

    # init to dut
    dut1_cfg = json.loads(duthost.shell("sonic-cfggen -d --print-data")['stdout'])
    dut2_cfg = json.loads(duthost2.shell("sonic-cfggen -d --print-data")['stdout'])

    dut1_extra_vars = {
        'test_scenario': test_scenario,
        'mclag_local_ip': mclag_local_ip.ip,
        'mclag_peer_ip': mclag_peer_ip.ip,
        'dut_interconnection_interfaces': g_vars['dut1_interconnection_interfaces'],
        'port_alias_map': g_vars['dut1_port_alias']['port_alias_map'],
        'port_alias': g_vars['dut1_port_alias']['port_alias'],
        'port_name_map': g_vars['dut1_port_alias']['port_name_map'],
        'mclag_port_channel_id_list': g_vars['mclag_port_channel_id_list'],
        'topology': tp_facts_dut1,
        'cfg_origin': dut1_cfg
    }
    duthost.host.options['variable_manager'].extra_vars = dut1_extra_vars
    duthost.template(src="mclag/mclag_configuration.j2", dest="/tmp/mclag_{}.json".format(test_scenario))
    duthost.shell("mv /etc/sonic/config_db.json /etc/sonic/config_db.json.bak")
    duthost.shell("cp /tmp/mclag_{}.json /etc/sonic/config_db.json".format(test_scenario))
    duthost.shell("docker exec -i bgp sed -i '/router bgp/a\\  redistribute connected' /usr/share/sonic/templates/bgpd.conf.default.j2")
    duthost.shell("systemctl enable iccpd")
    reboot(duthost, localhost)

    dut2_extra_vars = {
        'test_scenario': test_scenario,
        'mclag_local_ip': mclag_peer_ip.ip,
        'mclag_peer_ip': mclag_local_ip.ip,
        'dut_interconnection_interfaces': g_vars['dut2_interconnection_interfaces'],
        'port_alias_map': g_vars['dut2_port_alias']['port_alias_map'],
        'port_alias': g_vars['dut2_port_alias']['port_alias'],
        'port_name_map': g_vars['dut2_port_alias']['port_name_map'],
        'mclag_port_channel_id_list': g_vars['mclag_port_channel_id_list'],
        'topology': tp_facts_dut2,
        'cfg_origin': dut2_cfg,
        'base': len(g_vars['dut1_all_interfaces'])
    }
    duthost2.host.options['variable_manager'].extra_vars = dut2_extra_vars
    duthost2.template(src="mclag/mclag_configuration.j2", dest="/tmp/mclag_{}.json".format(test_scenario))
    duthost2.shell("mv /etc/sonic/config_db.json /etc/sonic/config_db.json.bak")
    duthost2.shell("cp /tmp/mclag_{}.json /etc/sonic/config_db.json".format(test_scenario))
    duthost2.shell("docker exec -i bgp sed -i '/router bgp/a\\  redistribute connected' /usr/share/sonic/templates/bgpd.conf.default.j2")
    duthost2.shell("systemctl enable iccpd")
    reboot(duthost2, localhost)

    g_vars.update({'mclag_domain_id': duthost.shell("mclagdctl dump state|grep 'Domain id'")['stdout'].split(":")[-1].strip()})
    g_vars.update({'mclag_interfaces': natsorted(duthost.shell("mclagdctl dump state|grep 'MCLAG Interface'")['stdout'].split(": ")[-1].split(","))})

    yield
    # teardown on ptf
    ptfhost.shell("/tmp/mclag/mclag_ptf.sh delete_portchannel{}".format("_"+test_scenario if test_scenario == "l2" else ""))

    # teardown on dut
    duthost.shell("mv /etc/sonic/config_db.json.bak /etc/sonic/config_db.json")
    duthost.shell("docker exec -i bgp sed -ni 'p;/router bgp/n' /usr/share/sonic/templates/bgpd.conf.default.j2")
    duthost.shell("systemctl disable iccpd")
    reboot(duthost, localhost)

    duthost2.shell("mv /etc/sonic/config_db.json.bak /etc/sonic/config_db.json")
    duthost2.shell("docker exec -i bgp sed -ni 'p;/router bgp/n' /usr/share/sonic/templates/bgpd.conf.default.j2")
    duthost2.shell("systemctl disable iccpd")
    reboot(duthost2, localhost)

@pytest.fixture(scope="class", autouse=True)
def ip_neigh_flush(duthost, duthost2):
    duthost.shell("ip neigh flush all")
    duthost2.shell("ip neigh flush all")
    time.sleep(10)

@pytest.fixture(scope="function")
def basic_traffic_check(request, ptfhost, testbed):
    ptf_runner(
                ptfhost,
                "ptftests",
                "mclag_test.MclagTest",
                platform_dir="ptftests",
                params={
                    "router_mac": g_vars['dut1_router_mac'],
                    "router_mac_dut2": g_vars['dut2_router_mac'],
                    "testbed_type": testbed['topo'],
                    "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                    "test_scenario": test_scenario,
                    "ignore_ports": []
                },
                log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, request.instance.__class__.__name__, sys._getframe().f_code.co_name)
    )

@pytest.fixture(scope="function")
def syncheck(request, duthost, duthost2):
    dut1_arp_res = duthost.shell("show arp")['stdout_lines']
    dut2_arp_res = duthost2.shell("show arp")['stdout_lines']
    dut1_arp = {}
    dut2_arp = {}
    # gather arp info on dut
    for lag in g_vars['mclag_interfaces']:
        for line in dut1_arp_res:
            if lag in line:
                dut1_arp[lag].append(line.split()[0]) if dut1_arp.has_key(lag) else dut1_arp.update({lag: [line.split()[0]]})
        for line in dut2_arp_res:
            if lag in line:
                dut2_arp[lag].append(line.split()[0]) if dut2_arp.has_key(lag) else dut2_arp.update({lag: [line.split()[0]]})
    # check
    for lag in g_vars['mclag_interfaces']:
        assert set(dut1_arp[lag]) == set(dut2_arp[lag]), "Arp on {} should be same on both peers"

class TestCase1_VerifyMclagStatus():
    def test_check_keepalive_link(self, duthost, duthost2):
        status = duthost.shell("mclagdctl -i {} dump state|grep keepalive".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        assert status == "OK", "MCLAG keepalive status should be OK on dut1"

        status = duthost2.shell("mclagdctl -i {} dump state|grep keepalive".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        assert status == "OK", "MCLAG keepalive status should be OK on dut2"

    def test_check_teamd_system_id(self, duthost, duthost2):
        for lag in g_vars['mclag_interfaces']:
            dut1_sys_id = duthost.shell("teamdctl {} state item get team_device.ifinfo.dev_addr".format(lag))['stdout']
            dut2_sys_id = duthost2.shell("teamdctl {} state item get team_device.ifinfo.dev_addr".format(lag))['stdout']
            assert dut1_sys_id == dut2_sys_id, "Mclag standby device {} system ID shoule be same as active device".format(lag)

    def test_traffic_between_servers(self, basic_traffic_check):
        pass

    def test_syncheck(self, syncheck):
        pass

class TestCase2_MclagMemberPortStatusChange():
    @pytest.fixture(scope="function")
    def setup_mclag_interface_member(self, duthost, duthost2):
        # shutdown active's port joined to first mclag interface and standby's port joined to last
        dut1_team_cfg = duthost.shell("teamdctl {} config dump".format(g_vars['mclag_interfaces'][0]))['stdout']
        dut2_team_cfg = duthost.shell("teamdctl {} config dump".format(g_vars['mclag_interfaces'][-1]))['stdout']
        dut1_team_port = json.loads(dut1_team_cfg)['ports'].keys()
        dut2_team_port = json.loads(dut2_team_cfg)['ports'].keys()
        for port1, port2 in zip(dut1_team_port, dut2_team_port):
            duthost.shell("config interface shutdown {}".format(port1))
            duthost2.shell("config interface shutdown {}".format(port2))
        time.sleep(5)

        yield
        for port1,port2 in zip(dut1_team_port, dut2_team_port):
            duthost.shell("config interface startup {}".format(port1))
            duthost2.shell("config interface startup {}".format(port2))
        time.sleep(5)

    def test_traffic_between_servers(self, basic_traffic_check):
        pass

    @pytest.mark.usefixtures("setup_mclag_interface_member")
    def test_mclag_member_port_down(self, ptfhost, testbed):
        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "router_mac_dut2": g_vars['dut2_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "learning_flag": False,
                        "ignore_ports": [int(g_vars['mclag_interfaces'][0].strip("PortChannel"))-1, len(g_vars['dut1_all_interfaces'])+int(g_vars['mclag_interfaces'][-1].strip("PortChannel"))-1]
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

    def test_mclag_member_port_up(self, ptfhost, testbed):
        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "router_mac_dut2": g_vars['dut2_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "learning_flag": False,
                        "ignore_ports": []
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

class TestCase3_KeepaliveLinkStatusChange():
    keepalive_intf = []
    @pytest.fixture(scope="function")
    def setup_keepalive_link(self, duthost):
        res = duthost.shell("show ip route {}|grep '*'".format(mclag_peer_ip.ip))['stdout']
        self.keepalive_intf = [entry.split("via ")[-1] for entry in res.split("\n")] if "via" in res else [res.split(", ")[-1]]

        for intf in self.keepalive_intf:
            duthost.shell("config interface shutdown {}".format(intf))
        time.sleep(20) # default keepalive timeout is 15s

        yield
        for intf in self.keepalive_intf:
            duthost.shell("config interface startup {}".format(intf))
        time.sleep(20)

    def test_traffic_between_servers(self, basic_traffic_check):
        pass

    @pytest.mark.usefixtures("setup_keepalive_link")
    def test_keepalive_link_down(self, duthost, duthost2, ptfhost, testbed):
        dut1_status = duthost.shell("mclagdctl -i {} dump state|grep 'keepalive'".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        dut2_status = duthost2.shell("mclagdctl -i {} dump state|grep 'keepalive'".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        assert dut1_status == dut2_status == "ERROR", "Mclag keepalive status should be ERROR on both peers after keepalive link down"

        for lag in g_vars['mclag_interfaces']:
            dut2_sys_id = duthost2.shell("teamdctl {} state item get team_device.ifinfo.dev_addr".format(lag))['stdout']
            assert dut2_sys_id == g_vars['dut2_router_mac'], "Mclag standby device {} system ID shoule be recovered to default".format(lag)

        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "router_mac_dut2": g_vars['dut2_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "learning_flag": False,
                        "ignore_ports": g_vars['dut2_link_server_interfaces']
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

    def test_keepalive_link_up(self, duthost, duthost2, ptfhost, testbed):
        dut1_status = duthost.shell("mclagdctl -i {} dump state|grep 'keepalive'".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        dut2_status = duthost2.shell("mclagdctl -i {} dump state|grep 'keepalive'".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        assert dut1_status == dut2_status == "OK", "Mclag keepalive status should be OK on both peers after keepalive link up"

        for lag in g_vars['mclag_interfaces']:
            dut1_sys_id = duthost2.shell("teamdctl {} state item get team_device.ifinfo.dev_addr".format(lag))['stdout']
            dut2_sys_id = duthost2.shell("teamdctl {} state item get team_device.ifinfo.dev_addr".format(lag))['stdout']
            assert dut1_sys_id == dut2_sys_id, "Mclag {} system ID shoule be same after keepalive link up".format(lag)

        time.sleep(30)
        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "router_mac_dut2": g_vars['dut2_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "ignore_ports": []
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

class TestCase4_ActiveDevStatusChange():
    @pytest.fixture(scope="function")
    def setup_reboot_active(self, duthost, localhost, delay=10, timeout=180):
        dut1_ports = natsorted(g_vars['dut1_port_alias']['port_name_map'].keys())[:len(g_vars['dut1_all_interfaces'])]
        for port in dut1_ports:
            duthost.shell("config interface shutdown {}".format(port))
        duthost.shell("config save -y")
        duthost.shell("nohup reboot &", module_ignore_errors=True)
        time.sleep(20)

        yield
        # waiting for ssh to startup
        dut_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).address
        localhost.wait_for( host=dut_ip,
                            port=SONIC_SSH_PORT,
                            state='started',
                            search_regex=SONIC_SSH_REGEX,
                            delay=delay,
                            timeout=timeout)

        wait_until(120, 10, duthost.critical_services_fully_started)
        for port in dut1_ports:
            duthost.shell("config interface startup {}".format(port))
        duthost.shell("config save -y")
        time.sleep(5)

    def test_traffic_between_servers(self, basic_traffic_check):
        pass

    @pytest.mark.usefixtures("setup_reboot_active")
    def test_active_down(self, duthost, duthost2, ptfhost, testbed):
        dut2_status = duthost2.shell("mclagdctl -i {} dump state|grep 'keepalive'".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        assert dut2_status == "ERROR", "Mclag keepalive status should be ERROR on standby after active reboot"

        # before send pkts, wait until standby mclag re-aggregate successfully due to router_mac change
        assert wait_until(150, 10, check_teamd_status, duthost2, g_vars['dut2_router_mac']), \
                "Standby teamd status should be up and sysid should changes to standby's default mac"

        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut2_router_mac'],
                        "router_mac_dut2": g_vars['dut2_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "ignore_ports": g_vars['dut1_all_interfaces']
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

    def test_active_up(self, duthost, duthost2, ptfhost, testbed):
        dut1_status = duthost.shell("mclagdctl -i {} dump state|grep 'keepalive'".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        dut2_status = duthost2.shell("mclagdctl -i {} dump state|grep 'keepalive'".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        assert dut1_status == dut2_status == "OK", "Mclag keepalive status should be OK on both peers after active reboot up"

        # before send pkts, wait until standby mclag re-aggregate successfully due to router_mac change
        assert wait_until(150, 10, check_teamd_status, duthost2, g_vars['dut1_router_mac']), \
                "Standby teamd status should be up and sysid should be same as active's mac"

        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "router_mac_dut2": g_vars['dut2_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "ignore_ports": []
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

class TestCase5_StandbyDevStatusChange():
    @pytest.fixture(scope="function")
    def setup_reboot_standby(self, duthost2, localhost, delay=10, timeout=180):
        dut2_ports = natsorted(g_vars['dut2_port_alias']['port_name_map'].keys())[:len(g_vars['dut2_all_interfaces'])]
        for port in dut2_ports:
            duthost2.shell("config interface shutdown {}".format(port))
        duthost2.shell("config save -y")
        duthost2.shell("nohup reboot &", module_ignore_errors=True)
        time.sleep(20)

        yield
        # waiting for ssh to startup
        dut_ip = duthost2.host.options['inventory_manager'].get_host(duthost2.hostname).address
        localhost.wait_for( host=dut_ip,
                            port=SONIC_SSH_PORT,
                            state='started',
                            search_regex=SONIC_SSH_REGEX,
                            delay=delay,
                            timeout=timeout)

        wait_until(120, 10, duthost2.critical_services_fully_started)
        for port in dut2_ports:
            duthost2.shell("config interface startup {}".format(port))
        duthost2.shell("config save -y")
        time.sleep(5)

    def test_traffic_between_servers(self, basic_traffic_check):
        pass

    @pytest.mark.usefixtures("setup_reboot_standby")
    def test_standby_down(self, duthost, ptfhost, testbed):
        dut1_status = duthost.shell("mclagdctl -i {} dump state|grep 'keepalive'".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        assert dut1_status == "ERROR", "Mclag keepalive status should be ERROR on active after standby reboot"

        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "router_mac_dut2": g_vars['dut2_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "learning_flag": False,
                        "ignore_ports": g_vars['dut2_all_interfaces']
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

    def test_standby_up(self, duthost, duthost2, ptfhost, testbed):
        dut1_status = duthost.shell("mclagdctl -i {} dump state|grep 'keepalive'".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        dut2_status = duthost2.shell("mclagdctl -i {} dump state|grep 'keepalive'".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        assert dut1_status == dut2_status == "OK", "Mclag keepalive status should be OK on both peers after active reboot up"

        # before send pkts, wait until standby mclag re-aggregate successfully due to router_mac change
        assert wait_until(150, 10, check_teamd_status, duthost2, g_vars['dut1_router_mac']), \
                "Standby teamd status should be up and sysid should be same as active's mac"

        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "router_mac_dut2": g_vars['dut2_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "ignore_ports": []
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

class TestCase6_ActiveDevWarmreboot():
    ev = threading.Event()
    ev.set()

    @pytest.fixture(scope="class", autouse=True)
    def stop_bg_traffic(self):
        yield
        self.ev.clear()

    def test_traffic_between_servers(self, basic_traffic_check):
        pass

    def test_traffic_during_warmreboot(self, localhost, duthost, ptfhost, testbed, delay=10, timeout=180):
        exc_que = Queue.Queue()

        params = {
                    "casename": self.__class__.__name__,
                    "event": self.ev,
                    "ptf_runner": ptf_runner,
                    "exc_queue": exc_que,  # use for store exception infos
                    "host": ptfhost,
                    "testdir": "ptftests",
                    "testname": "mclag_test.MclagTest",
                    "platform_dir": "ptftests",
                    "params": {
                                "router_mac": g_vars['dut1_router_mac'],
                                "router_mac_dut2": g_vars['dut2_router_mac'],
                                "testbed_type": testbed['topo'],
                                "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                                "test_scenario": test_scenario,
                                "learning_flag": False,
                                "ignore_ports": []
                              }
        }

        bg_traffic = threading.Thread(target=continuous_traffic_check, kwargs=params)
        bg_traffic.start()

        # warm-reboot
        duthost.shell("nohup warm-reboot >/dev/null 2>&1 &")

        # waiting for ssh to absent then startup
        dut_ip = duthost.host.options['inventory_manager'].get_host(duthost.hostname).address
        res = localhost.wait_for( host=dut_ip,
                            port=SONIC_SSH_PORT,
                            state='absent',
                            search_regex=SONIC_SSH_REGEX,
                            delay=delay,
                            timeout=timeout,
                            module_ignore_errors=True)
        if res.is_failed:
            raise Exception('DUT did not warm-reboot, maybe orchagent_restart_check faild')

        localhost.wait_for( host=dut_ip,
                            port=SONIC_SSH_PORT,
                            state='started',
                            search_regex=SONIC_SSH_REGEX,
                            delay=delay,
                            timeout=timeout)

        finalizer_state = wait_until(300, 10, check_warm_status, duthost)
        # stop send traffic
        self.ev.clear()
        assert finalizer_state, "Warmreboot expect finished in 300s"

        traffic_res = True
        if exc_que.qsize() != 0:
            traffic_res = False
            _, exc_obj, _ = exc_que.get()
        assert traffic_res, "Traffic Test Failed \n {}".format(str(exc_obj))

        # basic check after warmreboot
        assert duthost.critical_services_fully_started
        time.sleep(30)

    def test_syncheck(self, syncheck):
        pass

class TestCase7_StandbyDevWarmreboot():
    ev = threading.Event()
    ev.set()

    @pytest.fixture(scope="class", autouse=True)
    def stop_bg_traffic(self):
        yield
        self.ev.clear()

    def test_traffic_between_servers(self, basic_traffic_check):
        pass

    def test_traffic_during_warmreboot(self, localhost, duthost2, ptfhost, testbed, delay=10, timeout=180):
        exc_que = Queue.Queue()
        params = {
                    "casename": self.__class__.__name__,
                    "event": self.ev,
                    "ptf_runner": ptf_runner,
                    "exc_queue": exc_que,  # use for store exception infos
                    "host": ptfhost,
                    "testdir": "ptftests",
                    "testname": "mclag_test.MclagTest",
                    "platform_dir": "ptftests",
                    "params": {
                                "router_mac": g_vars['dut1_router_mac'],
                                "router_mac_dut2": g_vars['dut2_router_mac'],
                                "testbed_type": testbed['topo'],
                                "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                                "test_scenario": test_scenario,
                                "learning_flag": False,
                                "ignore_ports": []
                              }
        }

        bg_traffic = threading.Thread(target=continuous_traffic_check, kwargs=params)
        bg_traffic.start()

        # warm-reboot
        duthost2.shell("nohup warm-reboot >/dev/null 2>&1 &")

        # waiting for ssh to absent then startup
        dut_ip = duthost2.host.options['inventory_manager'].get_host(duthost2.hostname).address
        res = localhost.wait_for( host=dut_ip,
                                  port=SONIC_SSH_PORT,
                                  state='absent',
                                  search_regex=SONIC_SSH_REGEX,
                                  delay=delay,
                                  timeout=timeout,
                                  module_ignore_errors=True)
        if res.is_failed:
            raise Exception('DUT did not warm-reboot, maybe orchagent_restart_check faild')

        localhost.wait_for( host=dut_ip,
                            port=SONIC_SSH_PORT,
                            state='started',
                            search_regex=SONIC_SSH_REGEX,
                            delay=delay,
                            timeout=timeout)

        finalizer_state = wait_until(300, 10, check_warm_status, duthost2)
        # stop send traffic
        self.ev.clear()
        assert finalizer_state, "Warmreboot expect finished in 300s"

        traffic_res = True
        if exc_que.qsize() != 0:
            traffic_res = False
            _, exc_obj, _ = exc_que.get()
        assert traffic_res, "Traffic Test Failed \n {}".format(str(exc_obj))

        # basic check after warmreboot
        assert duthost2.critical_services_fully_started
        time.sleep(30)

    def test_syncheck(self, syncheck):
        pass

class TestCase8_Scaling():
    # max num <= 252
    port_server_count = 100

    @pytest.fixture(scope="class", autouse=True)
    def setup_servers(self, duthost, duthost2, ptfhost):
        duthost.shell("sysctl -w net.ipv4.neigh.default.gc_thresh1=10000")
        duthost.shell("sysctl -w net.ipv4.neigh.default.gc_thresh2=10000")
        duthost.shell("sysctl -w net.ipv4.neigh.default.gc_thresh3=10000")
        duthost2.shell("sysctl -w net.ipv4.neigh.default.gc_thresh1=10000")
        duthost2.shell("sysctl -w net.ipv4.neigh.default.gc_thresh2=10000")
        duthost2.shell("sysctl -w net.ipv4.neigh.default.gc_thresh3=10000")

        ptf_extra_vars = {
            'test_scenario'         : test_scenario,
            'dut1_all_interfaces'   : g_vars['dut1_all_interfaces'],
            'dut1_link_server_interfaces': g_vars['dut1_link_server_interfaces'],
            'mclag_port_channel_id_list' : g_vars['mclag_port_channel_id_list'],
            'mclag_link_vm_interfaces'   : g_vars['mclag_link_vm_interfaces'],
            'port_server_count'          : self.port_server_count,
            'arp_responder_args'         : '--conf /tmp/mclag/mclag_arpresponder.conf -e',
            'scaling_test'               : True
        }
        ptfhost.host.options['variable_manager'].extra_vars = ptf_extra_vars
        ptfhost.template(src="mclag/mclag_switch_info.j2", dest="/tmp/mclag/mclag_switch_info_{}_scaling.txt".format(test_scenario))
        ptfhost.copy(src="scripts/arp_responder.py", dest="/opt")
        ptfhost.template(src="scripts/arp_responder.conf.j2", dest="/etc/supervisor/conf.d/arp_responder.conf")
        ptfhost.template(src="mclag/mclag_arpresponder.j2", dest="/tmp/mclag/mclag_arpresponder.conf")
        ptfhost.shell("supervisorctl reread")
        ptfhost.shell("supervisorctl update")
        ptfhost.shell("supervisorctl start arp_responder")

        yield
        ptfhost.shell("supervisorctl stop arp_responder")
        # clear neighbors used for test
        for lag in g_vars['mclag_interfaces']:
            duthost.shell("ip link set arp off dev {0}; ip link set arp on dev {0}".format(lag))
            duthost2.shell("ip link set arp off dev {0}; ip link set arp on dev {0}".format(lag))

        dut1_orphan_ports = natsorted(g_vars['dut1_port_alias']['port_name_map'].keys())[:len(g_vars['dut1_link_server_interfaces'])][-2:]
        dut2_orphan_ports = natsorted(g_vars['dut2_port_alias']['port_name_map'].keys())[:len(g_vars['dut2_link_server_interfaces'])][-2:]
        for port1, port2 in zip(dut1_orphan_ports, dut2_orphan_ports):
            duthost.shell("ip link set arp off dev {0}; ip link set arp on dev {0}".format(port1))
            duthost2.shell("ip link set arp off dev {0}; ip link set arp on dev {0}".format(port2))

    def test_traffic_between_servers(self, ptfhost, testbed):
        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "router_mac_dut2": g_vars['dut2_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}_scaling.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "scale": True,
                        "ignore_ports": []
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

    def test_syncheck(self, syncheck):
        pass
