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
test_scenario    = "l2"
testbed_mtu      = 8100  # set mclag keepalive intf mtu, the value should be less than your testbed's Trunk port(which connect to root fanout swich) mtu.
mclag_local_ip   = ipaddress.IPNetwork("10.100.0.1/30")
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
        'mtu': testbed_mtu,
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
    duthost.shell("systemctl enable iccpd")
    reboot(duthost, localhost)

    dut2_extra_vars = {
        'test_scenario': test_scenario,
        'mtu': testbed_mtu,
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
    duthost2.shell("systemctl enable iccpd")
    reboot(duthost2, localhost)

    g_vars.update({'mclag_domain_id': duthost.shell("mclagdctl dump state|grep 'Domain id'")['stdout'].split(":")[-1].strip()})
    g_vars.update({'mclag_interfaces': natsorted(duthost.shell("mclagdctl dump state|grep 'MCLAG Interface'")['stdout'].split(": ")[-1].split(","))})
    g_vars.update({'peer_link_interface': duthost.shell("mclagdctl dump state|grep 'Peer Link Interface'")['stdout'].split(":")[-1].strip()})

    yield
    # teardown on ptf
    ptfhost.shell("/tmp/mclag/mclag_ptf.sh delete_portchannel{}".format("_"+test_scenario if test_scenario == "l2" else ""))

    # teardown on dut
    duthost.shell("mv /etc/sonic/config_db.json.bak /etc/sonic/config_db.json")
    duthost.shell("systemctl disable iccpd")
    reboot(duthost, localhost)

    duthost2.shell("mv /etc/sonic/config_db.json.bak /etc/sonic/config_db.json")
    duthost2.shell("systemctl disable iccpd")
    reboot(duthost2, localhost)

@pytest.fixture(scope="class", autouse=False)
def fdb_neigh_flush(duthost, duthost2):
    duthost.shell("fdbclear; ip neigh flush all")
    duthost2.shell("fdbclear; ip neigh flush all")
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
                    "testbed_type": testbed['topo'],
                    "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                    "test_scenario": test_scenario,
                    "ignore_ports": []
                },
                log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, request.instance.__class__.__name__, sys._getframe().f_code.co_name)
    )

@pytest.fixture(scope="function")
def syncheck(request, duthost, duthost2):
    orphan_ports = request.param['orphan_ports']
    vlans = eval(duthost.shell("sonic-cfggen -d --var-json VLAN")['stdout']).keys()

    res = False
    for vlan in [v.split('Vlan')[-1] for v in vlans]:
        for module in ['mac', 'arp']:
            if module == 'mac':
                cmd = "show mac -v %s|grep %s|awk '{print $3,$4}'" % (vlan, vlan)
            elif module == 'arp':
                cmd = "show arp|grep %s|awk '{print $1,$3}'" % vlan

            dut1_port_item_map = {}
            dut2_port_item_map = {}
            dut1_entry = duthost.shell(cmd)['stdout_lines']
            dut2_entry = duthost2.shell(cmd)['stdout_lines']

            assert dut1_entry, "Can not get DUT1 {} entry".format(module)
            assert dut2_entry, "Can not get DUT2 {} entry".format(module)

            server_mac = g_vars['dut1_server_mac'] + g_vars['dut2_server_mac']
            for entry in dut1_entry:
                port = entry.split()[-1]
                if (module == "mac" and entry.split()[0] in server_mac) or module == "arp":
                    item = entry.split()[0]
                else :
                    continue
                dut1_port_item_map[port].append(item) if port in dut1_port_item_map else dut1_port_item_map.update({port: [item]})

            for entry in dut2_entry:
                port = entry.split()[-1]
                if (module == "mac" and entry.split()[0] in server_mac) or module == "arp":
                    item = entry.split()[0]
                else :
                    continue
                dut2_port_item_map[port].append(item) if port in dut2_port_item_map else dut2_port_item_map.update({port: [item]})


            dut1_orphan_port_item = []
            for port in dut1_port_item_map:
                # check mclag interfaces
                if "PortChannel" in port and port != g_vars['peer_link_interface']:
                    res = natsorted(dut1_port_item_map[port]) == natsorted(dut2_port_item_map[port])
                    assert res, "{} learned on mclag should be synced between mclag active and standby devices".format(module)

            if orphan_ports:
                dut1_orphan_port_item = []
                for port in dut1_port_item_map:
                    if "Ethernet" in port:
                        for item in dut1_port_item_map[port]:
                            dut1_orphan_port_item.append(item)

                res = natsorted(dut1_orphan_port_item) == natsorted(dut2_port_item_map[g_vars['peer_link_interface']])
                # check DUT1 orphan ports
                assert res, "{} learned on DUT1 orphan port should be pointed to peer link on DUT2".format(module)

                dut2_orphan_port_item = []
                for port in dut2_port_item_map:
                    if "Ethernet" in port:
                        for item in dut2_port_item_map[port]:
                            dut2_orphan_port_item.append(item)

                res = natsorted(dut2_orphan_port_item) == natsorted(dut1_port_item_map[g_vars['peer_link_interface']])
                # check DUT2 orphan ports
                assert res, "{} learned on DUT2 orphan port should be pointed to peer link on DUT1".format(module)

class TestCase1_VerifyMclagStatus():
    def test_check_keepalive_link(self, duthost, duthost2):
        duthost.shell("ping {} -c 3 -f -W 2".format(mclag_peer_ip.ip))

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

    @pytest.mark.parametrize("syncheck", [{'orphan_ports': True}], indirect=True)
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
    def test_mclag_member_port_down(self, duthost, duthost2, ptfhost, testbed):
        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "learning_flag": False,
                        "ignore_ports": [int(g_vars['mclag_interfaces'][0].strip("PortChannel"))-1, len(g_vars['dut1_all_interfaces'])+int(g_vars['mclag_interfaces'][-1].strip("PortChannel"))-1]
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

        # verify mac pointed to peer link after mclag member port down
        # DUT1 mclag member port down
        dut1_mac = (g_vars['ptf_mac_prefix']+"{:02x}".format(int(g_vars['mclag_interfaces'][0].strip("PortChannel"))-1))
        dut1_port = duthost.shell("show mac|grep -i %s|awk '{print $4}'" % dut1_mac)['stdout']
        assert dut1_port == g_vars['peer_link_interface'], \
                "Mac {} on {} should be pointed to peer link after DUT1 mclag member port down".format(dut1_mac, g_vars['mclag_interfaces'][0])

        # DUT2 mclag member port down
        dut2_mac = (g_vars['ptf_mac_prefix']+"{:02x}".format(int(g_vars['mclag_interfaces'][-1].strip("PortChannel"))-1))
        dut2_port = duthost2.shell("show mac|grep -i %s|awk '{print $4}'" % dut2_mac)['stdout']
        assert dut2_port == g_vars['peer_link_interface'], \
                "Mac {} on {} should be pointed to peer link after DUT2 mclag member port down".format(dut2_mac, g_vars['mclag_interfaces'][-1])

        # verify mac age flag changes after mclag member port down
        # DUT1 mclag member port down
        dut1_age_flag = duthost.shell("mclagdctl -i %s dump mac|grep -i %s|awk '{print $7}'" % (g_vars['mclag_domain_id'], dut1_mac))['stdout']
        assert dut1_age_flag == "L", "Mac learned on DUT1 down port before should add 'L' flag"

        dut2_age_flag = duthost2.shell("mclagdctl -i %s dump mac|grep -i %s|awk '{print $7}'" % (g_vars['mclag_domain_id'], dut1_mac))['stdout']
        assert dut2_age_flag == "P", "Mac learned from peer link on DUT2 should add 'P' flag"

        # DUT2 mclag member port down
        dut2_age_flag2 = duthost2.shell("mclagdctl -i %s dump mac|grep -i %s|awk '{print $7}'" % (g_vars['mclag_domain_id'], dut2_mac))['stdout']
        assert dut2_age_flag2 == "L", "Mac learned on DUT2 down port before should add 'L' flag"

        dut1_age_flag2 = duthost.shell("mclagdctl -i %s dump mac|grep -i %s|awk '{print $7}'" % (g_vars['mclag_domain_id'], dut2_mac))['stdout']
        assert dut1_age_flag2 == "P", "Mac learned from peer link on DUT1 should add 'P' flag"

        # verify arp pointed to peer link after mclag member port down
        # DUT1 mclag member port down
        dut1_vmember = duthost.shell("sonic-cfggen -d --var-json VLAN_MEMBER")['stdout']
        for k in json.loads(dut1_vmember):
            if g_vars['mclag_interfaces'][0] in k:
                vlan = k.split("|")[0]
        dut1_vlan_intf = duthost.shell("sonic-cfggen -d --var-json VLAN_INTERFACE")['stdout']
        for k in json.loads(dut1_vlan_intf):
            if vlan+"|" in k:
                vlan_ip = ipaddress.IPNetwork(k.split("|")[-1])

        dut1_arp = vlan_ip.network + 256*int(g_vars['mclag_interfaces'][0].strip("PortChannel")) + 2
        dut1_arp_port = duthost.shell("show arp|grep %s|awk '{print $3}'" % dut1_arp)['stdout']
        assert dut1_arp_port == g_vars['peer_link_interface'], \
                "Arp {} on {} should be pointed to peer link after DUT1 mclag member port down".format(dut1_arp, g_vars['mclag_interfaces'][0])

        # DUT2 mclag member port down
        dut2_vmember = duthost2.shell("sonic-cfggen -d --var-json VLAN_MEMBER")['stdout']
        for k in json.loads(dut2_vmember):
            if g_vars['mclag_interfaces'][-1] in k:
                vlan = k.split("|")[0]
        dut2_vlan_intf = duthost2.shell("sonic-cfggen -d --var-json VLAN_INTERFACE")['stdout']
        for k in json.loads(dut2_vlan_intf):
            if vlan+"|" in k:
                vlan_ip = ipaddress.IPNetwork(k.split("|")[-1])

        dut2_arp = vlan_ip.network + 256*int(g_vars['mclag_interfaces'][-1].strip("PortChannel")) + 2
        dut2_arp_port = duthost2.shell("show arp|grep %s|awk '{print $3}'" % dut2_arp)['stdout']
        assert dut2_arp_port == g_vars['peer_link_interface'], \
                "Arp {} on {} should be pointed to peer link after DUT2 mclag member port down".format(dut2_arp, g_vars['mclag_interfaces'][-1])

    def test_mclag_member_port_up(self, ptfhost, testbed):
        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "learning_flag": False,
                        "ignore_ports": []
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

    @pytest.mark.parametrize("syncheck", [{'orphan_ports': True}], indirect=True)
    def test_syncheck(self, syncheck):
        # verify mac and arp sync
        pass

class TestCase3_PeerLinkStatusChange():
    def test_traffic_between_servers(self, basic_traffic_check):
        pass

    def test_peer_link_interface_down(self, duthost, duthost2, ptfhost, testbed):
        duthost.shell("config interface shutdown {}".format(g_vars['peer_link_interface']))
        duthost2.shell("config interface shutdown {}".format(g_vars['peer_link_interface']))
        time.sleep(5)
        dut1_status = duthost.shell("mclagdctl -i {} dump state|grep 'keepalive'".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        dut2_status = duthost2.shell("mclagdctl -i {} dump state|grep 'keepalive'".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        assert dut1_status == dut2_status == "OK", "Mclag keepalive status should be OK on both peers after peer link down"

        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "learning_flag": False,
                        "ignore_ports": g_vars['dut1_orphan_ports'] + g_vars['dut2_orphan_ports']
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

    @pytest.mark.parametrize("syncheck", [{'orphan_ports': False}], indirect=True)
    def test_syncheck_on_mclag_interface(self, syncheck):
        # verify mac and arp sync on mclag interfaces
        pass

    def test_peer_link_interface_up(self, duthost, duthost2, ptfhost, testbed):
        duthost.shell("config interface startup {}".format(g_vars['peer_link_interface']))
        duthost2.shell("config interface startup {}".format(g_vars['peer_link_interface']))
        time.sleep(5)
        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "ignore_ports": []
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

    @pytest.mark.parametrize("syncheck", [{'orphan_ports': True}], indirect=True)
    def test_syncheck(self, syncheck):
        # verify mac and arp sync
        pass

class TestCase4_KeepaliveLinkStatusChange():
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
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "learning_flag": False,
                        "ignore_ports": g_vars['dut2_link_server_interfaces']
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

        for module in ['mac', 'arp']:
            cmd = "show {}|grep {}".format(module, g_vars['peer_link_interface'])
            res1 = duthost.shell(cmd, module_ignore_errors=True)['stdout']
            res2 = duthost2.shell(cmd, module_ignore_errors=True)['stdout']
            assert g_vars['peer_link_interface'] not in res1 + res2, "Mac and arp should be removed after keepalive link down"

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
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "ignore_ports": []
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

    @pytest.mark.parametrize("syncheck", [{'orphan_ports': True}], indirect=True)
    def test_syncheck(self, syncheck):
        # verify mac and arp sync
        pass

class TestCase5_PeerKeepaliveBothStatusChange():
    keepalive_intf = []
    @pytest.fixture(scope="function")
    def setup_peer_keepalive_link(self, duthost):
        duthost.shell("config interface shutdown {}".format(g_vars['peer_link_interface']))

        res = duthost.shell("show ip route {}|grep '*'".format(mclag_peer_ip.ip))['stdout']
        self.keepalive_intf = [entry.split("via ")[-1] for entry in res.split("\n")] if "via" in res else [res.split(", ")[-1]]

        for intf in self.keepalive_intf:
            duthost.shell("config interface shutdown {}".format(intf))
        time.sleep(20)

        yield
        duthost.shell("config interface startup {}".format(g_vars['peer_link_interface']))

        for intf in self.keepalive_intf:
            duthost.shell("config interface startup {}".format(intf))
        time.sleep(20)

    def test_traffic_between_servers(self, basic_traffic_check):
        pass

    @pytest.mark.usefixtures("setup_peer_keepalive_link")
    def test_peer_keepalive_link_down(self, duthost, duthost2, ptfhost, testbed):
        dut1_status = duthost.shell("mclagdctl -i {} dump state|grep 'keepalive'".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        dut2_status = duthost2.shell("mclagdctl -i {} dump state|grep 'keepalive'".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        assert dut1_status == dut2_status == "ERROR", "Mclag keepalive status should be ERROR on both peers after peer and keepalive link down"

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
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "learning_flag": False,
                        "ignore_ports": g_vars['dut1_orphan_ports'] + g_vars['dut2_link_server_interfaces']
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

        for module in ['mac', 'arp']:
            cmd = "show {}|grep {}".format(module, g_vars['peer_link_interface'])
            res1 = duthost.shell(cmd, module_ignore_errors=True)['stdout']
            res2 = duthost2.shell(cmd, module_ignore_errors=True)['stdout']
            assert g_vars['peer_link_interface'] not in res1 + res2, "Mac and arp should be removed after peer and keepalive link down"

    def test_peer_keepalive_link_up(self, duthost, duthost2, ptfhost, testbed):
        dut1_status = duthost.shell("mclagdctl -i {} dump state|grep 'keepalive'".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        dut2_status = duthost2.shell("mclagdctl -i {} dump state|grep 'keepalive'".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        assert dut1_status == dut2_status == "OK", "Mclag keepalive status should be OK on both peers after peer and keepalive link up"

        for lag in g_vars['mclag_interfaces']:
            dut1_sys_id = duthost2.shell("teamdctl {} state item get team_device.ifinfo.dev_addr".format(lag))['stdout']
            dut2_sys_id = duthost2.shell("teamdctl {} state item get team_device.ifinfo.dev_addr".format(lag))['stdout']
            assert dut1_sys_id == dut2_sys_id, "Mclag {} system ID shoule be same after peer and keepalive link up".format(lag)

        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "ignore_ports": []
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

    @pytest.mark.parametrize("syncheck", [{'orphan_ports': True}], indirect=True)
    def test_syncheck(self, syncheck):
        # verify mac and arp sync
        pass

class TestCase6_ActiveDevStatusChange():
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
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "ignore_ports": g_vars['dut1_all_interfaces']
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

        for module in ['mac', 'arp']:
            cmd = "show {}|grep {}".format(module, g_vars['peer_link_interface'])
            res = duthost2.shell(cmd, module_ignore_errors=True)['stdout']
            assert g_vars['peer_link_interface'] not in res, "{} pointed to peer link should be removed after active reboot".format(module)

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
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "ignore_ports": []
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

    @pytest.mark.parametrize("syncheck", [{'orphan_ports': True}], indirect=True)
    def test_syncheck(self, syncheck):
        # verify mac and arp sync
        pass

class TestCase7_StandbyDevStatusChange():
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
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "learning_flag": False,
                        "ignore_ports": g_vars['dut2_all_interfaces']
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

        for module in ['mac', 'arp']:
            cmd = "show {}|grep {}".format(module, g_vars['peer_link_interface'])
            res = duthost.shell(cmd, module_ignore_errors=True)['stdout']
            assert g_vars['peer_link_interface'] not in res, "{} pointed to peer link should be removed after standby reboot".format(module)

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
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "ignore_ports": []
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

    @pytest.mark.parametrize("syncheck", [{'orphan_ports': True}], indirect=True)
    def test_syncheck(self, syncheck):
        # verify mac and arp sync
        pass

class TestCase8_ActiveDevWarmreboot():
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
                                "testbed_type": testbed['topo'],
                                "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                                "test_scenario": test_scenario,
                                "learning_flag": False,
                                "ignore_ports": []
                              }
        }

        bg_traffic = threading.Thread(target=continuous_traffic_check, kwargs=params)
        # start send traffic circularly
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

    @pytest.mark.parametrize("syncheck", [{'orphan_ports': True}], indirect=True)
    def test_syncheck_after_warmreboot(self, syncheck):
        # verify mac and arp sync
        pass

class TestCase9_StandbyDevWarmreboot():
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
        # If standby warm-reboot, after neighsyncd warm start state changed to reconciled, iccpd will change intf mac after reconnection,
        # intf mac change will lead to kernel remove all arp entries, this will cause packet drop. So we modify the neighsyncd_timer to
        # avoid it
        duthost2.shell("config warm_restart neighsyncd_timer 110")
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

    @pytest.mark.parametrize("syncheck", [{'orphan_ports': True}], indirect=True)
    def test_syncheck_after_warmreboot(self, syncheck):
        # verify mac and arp sync
        pass

class TestCase10_MacFlapping():
    flapping = {}
    @pytest.fixture(scope="function")
    def setup_mac_flapping(self, ptfhost):
        # move first orphan port's host to standby
        self.flapping['server1_index'] = len(g_vars['dut1_link_server_interfaces'])/2 - 2
        self.flapping['server1_index_flapped'] = len(g_vars['dut1_all_interfaces']) + self.flapping['server1_index']

        self.flapping['server1_mac'] = ptfhost.shell("ip netns exec ns%s ip -br link show ivp%s | awk '{print $3}'" % (self.flapping['server1_index']+1, self.flapping['server1_index']+1))['stdout']
        self.flapping['server1_ip'] = ptfhost.shell("ip netns exec ns%s ip -br addr show ivp%s | awk '{print $3}'" % (self.flapping['server1_index']+1, self.flapping['server1_index']+1))['stdout']

        self.flapping['server1_flapped_mac'] = ptfhost.shell("ip netns exec ns%s ip -br link show ivp%s | awk '{print $3}'" % (self.flapping['server1_index_flapped']+1, self.flapping['server1_index_flapped']+1))['stdout']
        self.flapping['server1_flapped_ip'] = ptfhost.shell("ip netns exec ns%s ip -br addr show ivp%s | awk '{print $3}'" % (self.flapping['server1_index_flapped']+1, self.flapping['server1_index_flapped']+1))['stdout']

        ptfhost.shell("ip netns exec ns{0} ip link set ivp{0} down".format(self.flapping['server1_index']+1))

        ptfhost.shell("ip netns delete ns{}".format(self.flapping['server1_index_flapped']+1))
        ptfhost.shell("ip link set dev eth{} address {}".format(self.flapping['server1_index_flapped'], self.flapping['server1_mac']))
        ptfhost.shell("ip link add link eth{} name ivp{} type ipvlan mode l2".format(self.flapping['server1_index_flapped'], self.flapping['server1_index_flapped']+1))
        ptfhost.shell("ip netns add ns{}".format(self.flapping['server1_index_flapped']+1))
        ptfhost.shell("ip link set dev ivp{0} netns ns{0}".format(self.flapping['server1_index_flapped']+1))
        ptfhost.shell("ip netns exec ns{0} ip link set ivp{0} up".format(self.flapping['server1_index_flapped']+1))
        ptfhost.shell("ip netns exec ns{0} ip address add {1} dev ivp{0}".format(self.flapping['server1_index_flapped']+1, self.flapping['server1_ip']))

        yield
        ptfhost.shell("ip netns exec ns{0} ip link set ivp{0} up".format(self.flapping['server1_index']+1))

        ptfhost.shell("ip netns delete ns{}".format(self.flapping['server1_index_flapped']+1))
        ptfhost.shell("ip link set dev eth{} address {}".format(self.flapping['server1_index_flapped'], self.flapping['server1_flapped_mac']))
        ptfhost.shell("ip link add link eth{} name ivp{} type ipvlan mode l2".format(self.flapping['server1_index_flapped'], self.flapping['server1_index_flapped']+1))
        ptfhost.shell("ip netns add ns{}".format(self.flapping['server1_index_flapped']+1))
        ptfhost.shell("ip link set dev ivp{0} netns ns{0}".format(self.flapping['server1_index_flapped']+1))
        ptfhost.shell("ip netns exec ns{0} ip link set ivp{0} up".format(self.flapping['server1_index_flapped']+1))
        ptfhost.shell("ip netns exec ns{0} ip address add {1} dev ivp{0}".format(self.flapping['server1_index_flapped']+1, self.flapping['server1_flapped_ip']))

    def test_traffic_before_mac_flapping(self, duthost, duthost2, ptfhost, testbed):
        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "ignore_ports": []
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

        # verify mclag mac age flag
        dut1_mac_res = duthost.shell("show mac|awk '{print $3,$4}'")['stdout_lines']
        dut2_mac_res = duthost2.shell("show mac|awk '{print $3,$4}'")['stdout_lines']
        dut1_macs_on_orphan_ports = []
        dut2_macs_on_orphan_ports = []
        for line in dut1_mac_res:
            if "Ethernet" in line.split()[-1]:
                dut1_macs_on_orphan_ports.append(line.split()[0])
        for line in dut2_mac_res:
            if "Ethernet" in line.split()[-1]:
                dut2_macs_on_orphan_ports.append(line.split()[0])

        dut1_mclag_mac_res = duthost.shell("mclagdctl -i %s dump mac|grep -v TYPE|awk '{print $3,$7}'" % g_vars['mclag_domain_id'])['stdout_lines']
        dut2_mclag_mac_res = duthost2.shell("mclagdctl -i %s dump mac|grep -v TYPE|awk '{print $3,$7}'" % g_vars['mclag_domain_id'])['stdout_lines']
        dut1_mclag_mac = {}
        dut2_mclag_mac = {}

        for line in dut1_mclag_mac_res:
            dut1_mclag_mac.update({line.split()[0]: line.split()[-1]})
        for line2 in dut2_mclag_mac_res:
            dut2_mclag_mac.update({line2.split()[0]: line2.split()[-1]})

        for mac in dut1_macs_on_orphan_ports:
            assert dut1_mclag_mac[mac] == "P", "Mac learned on DUT1 orphan port should add P age flag on local device"
            assert dut2_mclag_mac[mac] == "L", "Mac learned on DUT1 orphan port should add L age flag on peer device"
        for mac2 in dut2_macs_on_orphan_ports:
            assert dut2_mclag_mac[mac2] == "P", "Mac learned on DUT2 orphan port should add P age flag on local device"
            assert dut1_mclag_mac[mac2] == "L", "Mac learned on DUT2 orphan port should add L age flag on peer device"

    @pytest.mark.parametrize("syncheck", [{'orphan_ports': True}], indirect=True)
    def test_syncheck_before_mac_flapping(self, syncheck):
        # verify mac and arp sync
        pass

    @pytest.mark.usefixtures("setup_mac_flapping")
    def test_mac_flapping(self, duthost, duthost2, ptfhost, testbed):
        vlan_ip = ipaddress.IPNetwork(duthost2.shell("ip -br addr show dev Vlan1000|awk '{print $3}'")['stdout'])

        ptfhost.shell("ip netns exec ns{} ping {} -c 3 -f -W 2".format(self.flapping['server1_index_flapped']+1, vlan_ip.ip))

        time.sleep(60)
        # check port after flapping
        dut1_mac_port = duthost.shell("show mac|grep -i %s|awk '{print $4}'" % self.flapping['server1_mac'])['stdout']
        assert dut1_mac_port == g_vars['peer_link_interface'], \
            "Flapping mac {} should pointed to peer link interface on active device, from {} flapped to {}".format(self.flapping['server1_mac'], self.flapping['server1_index'], self.flapping['server1_index_flapped'])

        dut2_mac_port = duthost2.shell("show mac|grep -i %s|awk '{print $4}'" % self.flapping['server1_mac'])['stdout']
        assert "PortChannel" not in dut2_mac_port, "Flapping mac {} should pointed to orphan port on standby device".format(self.flapping['server1_mac'])

        # check mclag age flag after flapping
        dut1_mac_flag = duthost.shell("mclagdctl -i %s dump mac|grep -i %s|awk '{print $7}'" % (g_vars['mclag_domain_id'], self.flapping['server1_mac']))['stdout']
        dut2_mac_flag = duthost2.shell("mclagdctl -i %s dump mac|grep -i %s|awk '{print $7}'" % (g_vars['mclag_domain_id'], self.flapping['server1_mac']))['stdout']

        assert dut1_mac_flag == "L", "Mac age flag on active should be L after flapped to standby device"
        assert dut2_mac_flag == "P", "Mac age flag on standby should be P after flapped to standby device"

        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "learning_flag": False,
                        "ignore_ports": [self.flapping['server1_index']]
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

class TestCase11_MacSyncAndAge():
    dut1_orphan_ports_mac = []
    dut2_orphan_ports_mac = []
    mclag_interface_mac   = []
    dut1_down_port_server_mac = []
    dut2_down_port_server_mac = []
    aging_time = 90

    @pytest.fixture(scope="class", autouse=True)
    def setup_servers(self, ptfhost):
        ptf_extra_vars = {
            'test_scenario'         : test_scenario,
            'dut1_all_interfaces'   : g_vars['dut1_all_interfaces'],
            'dut1_link_server_interfaces': g_vars['dut1_link_server_interfaces'],
            'mclag_port_channel_id_list' : g_vars['mclag_port_channel_id_list'],
            'mclag_link_vm_interfaces'   : g_vars['mclag_link_vm_interfaces'],
            'port_server_count'          : 1,
            'arp_responder_args'         : '--conf /tmp/mclag/mclag_arpresponder.conf -e',
            'scaling_test'               : True
        }
        ptfhost.host.options['variable_manager'].extra_vars = ptf_extra_vars
        ptfhost.template(src="mclag/mclag_switch_info.j2", dest="/tmp/mclag/mclag_switch_info_{}_aging.txt".format(test_scenario))
        ptfhost.copy(src="scripts/arp_responder.py", dest="/opt")
        ptfhost.template(src="scripts/arp_responder.conf.j2", dest="/etc/supervisor/conf.d/arp_responder.conf")
        ptfhost.template(src="mclag/mclag_arpresponder.j2", dest="/tmp/mclag/mclag_arpresponder.conf")
        ptfhost.shell("supervisorctl reread")
        ptfhost.shell("supervisorctl update")
        ptfhost.shell("supervisorctl start arp_responder")

        yield
        ptfhost.shell("supervisorctl stop arp_responder", module_ignore_errors=True)

    @pytest.fixture(scope="function")
    def setup_aging_time(self, duthost, duthost2):
        res = duthost.shell("redis-cli -n 0 hget SWITCH_TABLE:switch fdb_aging_time")['stdout']
        default_aging_time = res if res else 600

        dut_extra_vars = {'aging_time': self.aging_time}
        duthost.host.options['variable_manager'].extra_vars = dut_extra_vars
        duthost2.host.options['variable_manager'].extra_vars = dut_extra_vars

        # duthost.template(src="mclag/mclag_fdb_aging.j2", dest="/tmp/mclag_fdb_aging.json")
        # duthost.shell("docker cp /tmp/mclag_fdb_aging.json swss:/etc/swss/config.d/mclag_fdb_aging.json")
        # duthost.shell("docker exec -i swss swssconfig /etc/swss/config.d/mclag_fdb_aging.json")

        duthost2.template(src="mclag/mclag_fdb_aging.j2", dest="/tmp/mclag_fdb_aging.json")
        duthost2.shell("docker cp /tmp/mclag_fdb_aging.json swss:/etc/swss/config.d/mclag_fdb_aging.json")
        duthost2.shell("docker exec -i swss swssconfig /etc/swss/config.d/mclag_fdb_aging.json")

        yield
        dut_extra_vars = {'aging_time': default_aging_time}
        duthost.host.options['variable_manager'].extra_vars = dut_extra_vars
        duthost2.host.options['variable_manager'].extra_vars = dut_extra_vars

        # duthost.template(src="mclag/mclag_fdb_aging.j2", dest="/tmp/mclag_fdb_aging.json")
        # duthost.shell("docker cp /tmp/mclag_fdb_aging.json swss:/etc/swss/config.d/mclag_fdb_aging.json")
        # duthost.shell("docker exec -i swss swssconfig /etc/swss/config.d/mclag_fdb_aging.json")

        duthost2.template(src="mclag/mclag_fdb_aging.j2", dest="/tmp/mclag_fdb_aging.json")
        duthost2.shell("docker cp /tmp/mclag_fdb_aging.json swss:/etc/swss/config.d/mclag_fdb_aging.json")
        duthost2.shell("docker exec -i swss swssconfig /etc/swss/config.d/mclag_fdb_aging.json")

    @pytest.fixture(scope="function")
    def get_mclag_mac_table(self, duthost, duthost2):
        dut1_mclag_mac_dump = duthost.shell("mclagdctl -i %s dump mac|grep -v TYPE|awk '{print $3,$7}'" % g_vars['mclag_domain_id'])['stdout_lines']
        dut2_mclag_mac_dump = duthost2.shell("mclagdctl -i %s dump mac|grep -v TYPE|awk '{print $3,$7}'" % g_vars['mclag_domain_id'])['stdout_lines']
        dut1_mclag_mac = {}
        dut2_mclag_mac = {}

        for line in dut1_mclag_mac_dump:
            mac = line.split()[0]
            flag = line.split()[-1] if line.split()[-1] != line.split()[0] else "null"
            dut1_mclag_mac[mac] = flag

        for line in dut2_mclag_mac_dump:
            mac = line.split()[0]
            flag = line.split()[-1] if line.split()[-1] != line.split()[0] else "null"
            dut2_mclag_mac[mac] = flag

        return dut1_mclag_mac, dut2_mclag_mac

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

    def test_traffic_between_servers(self, ptfhost, testbed):
        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}_aging.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "scale": True,
                        "ignore_ports": []
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

        # gather mac info on orphan ports and mclag interfaces from mclag_arpresponder.conf
        res = json.loads(ptfhost.shell("cat /tmp/mclag/mclag_arpresponder.conf")['stdout'])
        for index in g_vars['dut1_orphan_ports']:
            mac_str = res["eth{}".format(index)].values()[0]
            mac     = ":".join([mac_str[i:i+2].upper() for i in range(0, 12, 2)])
            self.dut1_orphan_ports_mac.append(mac)
        for index in g_vars['dut2_orphan_ports']:
            mac_str = res["eth{}".format(index)].values()[0]
            mac     = ":".join([mac_str[i:i+2].upper() for i in range(0, 12, 2)])
            self.dut2_orphan_ports_mac.append(mac)
        for intf in g_vars['mclag_interfaces']:
            mac_str = res['eth{}'.format(int(intf.strip("PortChannel"))-1)].values()[0]
            mac     = ":".join([mac_str[i:i+2].upper() for i in range(0, 12, 2)])
            self.mclag_interface_mac.append(mac)

    @pytest.mark.usefixtures("setup_mclag_interface_member")
    def test_mclag_age_flag_after_mclag_member_port_down(self, ptfhost, get_mclag_mac_table):
        res = json.loads(ptfhost.shell("cat /tmp/mclag/mclag_arpresponder.conf")['stdout'])
        mac1_str = res["eth{}".format(int(g_vars['mclag_interfaces'][0].strip("PortChannel"))-1)].values()[0]
        mac1     = ":".join([mac1_str[i:i+2].upper() for i in range(0, 12, 2)])
        self.dut1_down_port_server_mac.append(mac1)

        mac2_str = res["eth{}".format(int(g_vars['mclag_interfaces'][-1].strip("PortChannel"))-1)].values()[0]
        mac2     = ":".join([mac2_str[i:i+2].upper() for i in range(0, 12, 2)])
        self.dut2_down_port_server_mac.append(mac2)

        dut1_mclag_mac, dut2_mclag_mac = get_mclag_mac_table
        assert dut1_mclag_mac[self.dut1_down_port_server_mac[0]] == "L", "Mac {} add L flag on dut1 after dut1 mclag {} member port down".format(self.dut1_down_port_server_mac[0], g_vars['mclag_interfaces'][0])
        assert dut2_mclag_mac[self.dut1_down_port_server_mac[0]] == "P", "Mac {} add P flag on dut2 after dut1 mclag {} member port down".format(self.dut1_down_port_server_mac[0], g_vars['mclag_interfaces'][0])
        assert dut2_mclag_mac[self.dut2_down_port_server_mac[0]] == "L", "Mac {} add L flag on dut2 after dut2 mclag {} member port down".format(self.dut2_down_port_server_mac[0], g_vars['mclag_interfaces'][-1])
        assert dut1_mclag_mac[self.dut2_down_port_server_mac[0]] == "P", "Mac {} add P flag on dut1 after dut2 mclag {} member port down".format(self.dut2_down_port_server_mac[0], g_vars['mclag_interfaces'][-1])

    def test_mclag_age_flag_after_mclag_member_port_up(self, get_mclag_mac_table):
        dut1_mclag_mac, dut2_mclag_mac = get_mclag_mac_table
        assert dut1_mclag_mac[self.dut1_down_port_server_mac[0]] == "null", "Mac {} on dut1 mclag interfaces should not add any age flag after dut1 mclag {} member port up".format(self.dut1_down_port_server_mac[0], g_vars['mclag_interfaces'][0])
        assert dut2_mclag_mac[self.dut1_down_port_server_mac[0]] == "null", "Mac {} on dut2 mclag interfaces should not add any age flag after dut1 mclag {} member port up".format(self.dut1_down_port_server_mac[0], g_vars['mclag_interfaces'][0])
        assert dut2_mclag_mac[self.dut2_down_port_server_mac[0]] == "null", "Mac {} on dut2 mclag interfaces should not add any age flag after dut2 mclag {} member port up".format(self.dut2_down_port_server_mac[0], g_vars['mclag_interfaces'][-1])
        assert dut1_mclag_mac[self.dut2_down_port_server_mac[0]] == "null", "Mac {} on dut1 mclag interfaces should not add any age flag after dut2 mclag {} member port up".format(self.dut2_down_port_server_mac[0], g_vars['mclag_interfaces'][-1])

    def test_traffic_between_servers_after_mclag_member_port_up(self, ptfhost, testbed):
        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}_aging.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "learning_flag": False,
                        "scale": True,
                        "ignore_ports": []
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

    def test_mclag_age_flag_after_traffic_between_servers(self, get_mclag_mac_table):
        dut1_mclag_mac, dut2_mclag_mac = get_mclag_mac_table
        # check server macs attach to dut1 orphan ports
        for mac in self.dut1_orphan_ports_mac:
            assert dut1_mclag_mac[mac] == "P", "Mac {} on dut1 orphan port should add P age flag on dut1".format(mac)
            assert dut2_mclag_mac[mac] == "L", "Mac {} on dut1 orphan port should add L age flag on dut2".format(mac)
        # check server macs attach to dut2 orphan ports
        for mac in self.dut2_orphan_ports_mac:
            assert dut2_mclag_mac[mac] == "P", "Mac {} on dut2 orphan port should add P age flag on dut2".format(mac)
            assert dut1_mclag_mac[mac] == "L", "Mac {} on dut2 orphan port should add L age flag on dut1".format(mac)
        # check server macs attach to mclag interfaces
        for mac in self.mclag_interface_mac:
            assert dut1_mclag_mac[mac] == "null", "Mac {} on dut1 mclag interfaces should not add any age flag".format(mac)
            assert dut2_mclag_mac[mac] == "null", "Mac {} on dut2 mclag interfaces should not add any age flag".format(mac)

    def test_mclag_age_flag_before_age(self, duthost, duthost2, ptfhost, get_mclag_mac_table):
        dut1_mclag_mac, dut2_mclag_mac = get_mclag_mac_table

        # check server macs attach to dut1 orphan ports
        for mac in self.dut1_orphan_ports_mac:
            assert dut1_mclag_mac[mac] == "P", "Mac {} on dut1 orphan port should add P age flag on dut1".format(mac)
            assert dut2_mclag_mac[mac] == "L", "Mac {} on dut1 orphan port should add L age flag on dut2".format(mac)
        # check server macs attach to dut2 orphan ports
        for mac in self.dut2_orphan_ports_mac:
            assert dut2_mclag_mac[mac] == "P", "Mac {} on dut2 orphan port should add P age flag on dut2".format(mac)
            assert dut1_mclag_mac[mac] == "L", "Mac {} on dut2 orphan port should add L age flag on dut1".format(mac)
        # check server macs attach to mclag interfaces
        for mac in self.mclag_interface_mac:
            assert dut1_mclag_mac[mac] == "null", "Mac {} on dut1 mclag interfaces should not add any age flag".format(mac)
            assert dut2_mclag_mac[mac] == "null", "Mac {} on dut2 mclag interfaces should not add any age flag".format(mac)

    def test_mac_aging_on_peer(self, duthost2, ptfhost, testbed, setup_aging_time):
        ptfhost.shell("supervisorctl stop arp_responder")
        i = 1
        interval = 60
        while(i <= self.aging_time*2/interval):
            # only send traffic to dut1 ports
            ptf_runner(
                        ptfhost,
                        "ptftests",
                        "mclag_test.MclagTest",
                        platform_dir="ptftests",
                        params={
                            "router_mac": g_vars['dut1_router_mac'],
                            "testbed_type": testbed['topo'],
                            "switch_info": "/tmp/mclag/mclag_switch_info_{}_aging.txt".format(test_scenario),
                            "test_scenario": test_scenario,
                            "learning_flag": False,
                            "scale": True,
                            "ignore_ports": g_vars['dut2_link_server_interfaces']
                        },
                        log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
            )
            time.sleep(interval)
            i += 1

        dut2_mac = duthost2.shell("show mac|grep Dynamic|awk '{print $3}'")['stdout_lines']
        res = set(self.dut2_orphan_ports_mac) & set(dut2_mac)
        assert not res, "Mac on dut2 should aged after setting aging time to {}s and already waited for {}s".format(self.aging_time, self.aging_time*2)
        time.sleep(60) # wait for mclag mac sync

    def test_mclag_age_flag_after_aging(self, get_mclag_mac_table):
        dut1_mclag_mac, dut2_mclag_mac = get_mclag_mac_table
        # check server macs attach to dut1 orphan ports
        for mac in self.dut1_orphan_ports_mac:
            assert dut1_mclag_mac[mac] == "P", "Mac {} on dut1 orphan port should add P age flag on dut1 after dut2 mac age".format(mac)
            assert dut2_mclag_mac[mac] == "L", "Mac {} on dut1 orphan port should add L age flag on dut2 after dut2 mac age".format(mac)
        # check server macs attach to dut2 orphan ports
        for mac in self.dut2_orphan_ports_mac:
            assert dut2_mclag_mac.has_key(mac) == False, "Mac {} on dut2 orphan port should be deleted on dut2 after dut2 mac age".format(mac)
            assert dut1_mclag_mac.has_key(mac) == False, "Mac {} on dut2 orphan port should be deleted on dut1 after dut2 mac age".format(mac)
        # check server macs attach to mclag interfaces
        for mac in self.mclag_interface_mac:
            assert dut1_mclag_mac[mac] == "P", "Mac {} on dut1 mclag interfaces should add P age flag after dut2 mac age".format(mac)
            assert dut2_mclag_mac[mac] == "L", "Mac {} on dut2 mclag interfaces should add L age flag after dut2 mac age".format(mac)

    def test_relearn_after_mac_age(self, ptfhost, testbed):
        ptfhost.shell("supervisorctl start arp_responder")
        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}_aging.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "scale": True,
                        "ignore_ports": []
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

    def test_mclag_age_flag_after_relearn(self, get_mclag_mac_table):
        dut1_mclag_mac, dut2_mclag_mac = get_mclag_mac_table

        # check server macs attach to dut1 orphan ports
        for mac in self.dut1_orphan_ports_mac:
            assert dut1_mclag_mac[mac] == "P", "Mac {} on dut1 orphan port should add P age flag on dut1".format(mac)
            assert dut2_mclag_mac[mac] == "L", "Mac {} on dut1 orphan port should add L age flag on dut2".format(mac)
        # check server macs attach to dut2 orphan ports
        for mac in self.dut2_orphan_ports_mac:
            assert dut2_mclag_mac[mac] == "P", "Mac {} on dut2 orphan port should add P age flag on dut2".format(mac)
            assert dut1_mclag_mac[mac] == "L", "Mac {} on dut2 orphan port should add L age flag on dut1".format(mac)
        # check server macs attach to mclag interfaces
        for mac in self.mclag_interface_mac:
            assert dut1_mclag_mac[mac] == "P", "Mac {} on dut1 mclag interfaces age flag should not changed after dut2 relearn".format(mac)
            assert dut2_mclag_mac[mac] == "L", "Mac {} on dut2 mclag interfaces age flag should not changed after dut2 relearn".format(mac)

class TestCase12_ICCP_CSM():
    @pytest.fixture(scope="function", autouse=True)
    def setup_logrotate_cron_task(self, duthost, duthost2):
        # Disable logrotate cron task
        duthost.shell("sed -i 's/^/#/g' /etc/cron.d/logrotate")
        duthost2.shell("sed -i 's/^/#/g' /etc/cron.d/logrotate")
        # Wait for logrotate from previous cron task run to finish
        i = 1
        while(i<=6):
            res1 = duthost.shell("! pgrep -f logrotate", module_ignore_errors=True)['rc']
            res2 = duthost2.shell("! pgrep -f logrotate", module_ignore_errors=True)['rc']
            if res1 == 0 and res2 == 0:
                break
            else:
                i += 1
                time.sleep(5)

        duthost.shell("logrotate -f /etc/logrotate.conf")
        duthost2.shell("logrotate -f /etc/logrotate.conf")

        yield
        duthost.shell("sed -i 's/^#//g' /etc/cron.d/logrotate")
        duthost2.shell("sed -i 's/^#//g' /etc/cron.d/logrotate")

    def test_active_restart(self, duthost, localhost):
        # reboot dut and wait for recovered
        reboot(duthost, localhost, wait=180)

        status = duthost.shell("mclagdctl -i {} dump state|grep keepalive".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        assert status == "OK", "MCLAG keepalive status should be OK on dut1"

        iccp_csm_log = duthost.shell("cat /var/log/syslog|grep iccp_csm_transit")['stdout']
        match_msg_regex = re.compile("^.*?from NONEXISTENT to INITIALIZED.\n(.*?\n)??.*?from .*? to CAPREC.\n(.*?\n)??.*?from .*? to OPERATIONAL")
        assert match_msg_regex.search(iccp_csm_log) != None

    def test_standby_restart(self, duthost2, localhost):
        # reboot dut and wait for recovered
        reboot(duthost2, localhost, wait=180)

        status = duthost2.shell("mclagdctl -i {} dump state|grep keepalive".format(g_vars['mclag_domain_id']))['stdout'].split(":")[-1].strip()
        assert status == "OK", "MCLAG keepalive status should be OK on dut2"

        iccp_csm_log = duthost2.shell("cat /var/log/syslog|grep iccp_csm_transit")['stdout']
        match_msg_regex = re.compile("^.*?from NONEXISTENT to INITIALIZED.\n(.*?\n)??.*?from .*? to CAPREC.\n(.*?\n)??.*?from .*? to OPERATIONAL")
        assert match_msg_regex.search(iccp_csm_log) != None

class TestCase13_Scaling():
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
        vlans = json.loads(duthost.shell("sonic-cfggen -d --var-json VLAN")['stdout']).keys()
        for vlan in vlans:
            duthost.shell("ip link set arp off dev {0}; ip link set arp on dev {0}".format(vlan))
            duthost2.shell("ip link set arp off dev {0}; ip link set arp on dev {0}".format(vlan))

    def test_traffic_between_servers(self, ptfhost, testbed):
        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}_scaling.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "scale": True,
                        "ignore_ports": []
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

    def test_mac_arp_sync(self, duthost, duthost2, ptfhost):
        random_check_num = self.port_server_count
        res = json.loads(ptfhost.shell("cat /tmp/mclag/mclag_arpresponder.conf")['stdout'])
        dut1_ports = natsorted(g_vars['dut1_port_alias']['port_name_map'].keys())
        dut2_ports = natsorted(g_vars['dut2_port_alias']['port_name_map'].keys())
        dut1_orphan_ports = dut1_ports[len(g_vars['dut1_link_server_interfaces'])/2-2:len(g_vars['dut1_link_server_interfaces'])/2] + \
                            dut1_ports[len(g_vars['dut1_link_server_interfaces'])-2:len(g_vars['dut1_link_server_interfaces'])]
        dut2_orphan_ports = dut2_ports[len(g_vars['dut2_link_server_interfaces'])/2-2:len(g_vars['dut2_link_server_interfaces'])/2] + \
                            dut2_ports[len(g_vars['dut2_link_server_interfaces'])-2:len(g_vars['dut2_link_server_interfaces'])]
        for t in ["mac", "arp"]:
            if t == "mac":
                dut1_entry_res = duthost.shell("show mac")['stdout_lines']
                dut2_entry_res = duthost2.shell("show mac")['stdout_lines']
            else:
                dut1_entry_res = duthost.shell("show arp")['stdout_lines']
                dut2_entry_res = duthost2.shell("show arp")['stdout_lines']

            assert dut1_entry_res, "Can not get DUT1 {} entry".format(t)
            assert dut2_entry_res, "Can not get DUT2 {} entry".format(t)
            # syncheck on dut1 orphan ports
            for dut_port, ptf_port in zip(dut1_orphan_ports, g_vars['dut1_orphan_ports']):
                if t == "mac":
                    dut_res   = [line.split()[2] for line in dut1_entry_res if dut_port in line]
                    peer_res  = [line.split()[2] for line in dut2_entry_res if g_vars['peer_link_interface'] in line]
                    ptf_entry = res['eth{}'.format(ptf_port)].values()
                else:
                    dut_res   = [line.split()[0] for line in dut1_entry_res if dut_port in line]
                    peer_res  = [line.split()[0] for line in dut2_entry_res if g_vars['peer_link_interface'] in line]
                    ptf_entry = res['eth{}'.format(ptf_port)].keys()

                dut_entry    = ["".join(entry.split(":")).lower() for entry in dut_res]
                peer_entry   = ["".join(entry.split(":")).lower() for entry in peer_res]
                random_entry = set(random.sample(ptf_entry, random_check_num))

                assert random_entry <= set(dut_entry), "{} on dut1 {} should match servers on ptf eth{}".format(t, dut_port, ptf_port)
                assert random_entry <= set(peer_entry), "{} learned from active orphan port {} should point to peer link on standby".format(t, dut_port)
            # syncheck on dut2 orphan ports
            for dut_port, ptf_port in zip(dut2_orphan_ports, g_vars['dut2_orphan_ports']):
                if t == "mac":
                    dut_res   = [line.split()[2] for line in dut2_entry_res if dut_port in line]
                    peer_res  = [line.split()[2] for line in dut1_entry_res if g_vars['peer_link_interface'] in line]
                    ptf_entry = res['eth{}'.format(ptf_port)].values()
                else:
                    dut_res   = [line.split()[0] for line in dut2_entry_res if dut_port in line]
                    peer_res  = [line.split()[0] for line in dut1_entry_res if g_vars['peer_link_interface'] in line]
                    ptf_entry = res['eth{}'.format(ptf_port)].keys()

                dut_entry    = ["".join(entry.split(":")).lower() for entry in dut_res]
                peer_entry   = ["".join(entry.split(":")).lower() for entry in peer_res]
                random_entry = set(random.sample(ptf_entry, random_check_num))

                assert random_entry <= set(dut_entry), "{} on dut1 {} should match servers on ptf eth{}".format(t, dut_port, ptf_port)
                assert random_entry <= set(peer_entry), "{} learned from standby orphan port {} should point to peer link on active".format(t, dut_port)
            # syncheck on mclag interfaces
            mclag_res = duthost.shell("mclagdctl dump state|grep 'MCLAG Interface'")['stdout']
            mclag_intf = natsorted(mclag_res.split(":")[1].strip().split(","))
            for intf in mclag_intf:
                if t == "mac":
                    dut1_res = [line.split()[2] for line in dut1_entry_res if intf in line]
                    dut2_res  = [line.split()[2] for line in dut2_entry_res if intf in line]
                    ptf_entry = res['eth{}'.format(int(intf.strip("PortChannel"))-1)].values()
                else:
                    dut1_res = [line.split()[0] for line in dut1_entry_res if intf in line]
                    dut2_res  = [line.split()[0] for line in dut2_entry_res if intf in line]
                    ptf_entry = res['eth{}'.format(int(intf.strip("PortChannel"))-1)].keys()

                dut1_entry    = ["".join(entry.split(":")).lower() for entry in dut1_res]
                dut2_entry   = ["".join(entry.split(":")).lower() for entry in dut2_res]
                random_entry = set(random.sample(ptf_entry, random_check_num))

                assert random_entry <= set(dut1_entry), "{} on dut1 {} should match servers on ptf eth{}".format(t, intf, int(intf.strip("PortChannel"))-1)
                assert random_entry <= set(dut2_entry), "{} on dut2 {} should match servers on ptf eth{}".format(t, intf, int(intf.strip("PortChannel"))-1)

class TestCase14_CornerTest():
    @pytest.fixture(scope="function")
    def setup_stop_teamd_on_active(self, duthost):
        duthost.shell("systemctl stop teamd")

        yield
        duthost.shell("systemctl start teamd")
        duthost.shell("systemctl start iccpd")
        # after restart teamd, PortChannel will be removed from Bridge in kernel, so we restart swss to recover
        duthost.shell("systemctl restart swss")
        wait_until(60, 10, duthost.critical_services_fully_started)

    @pytest.fixture(scope="function")
    def setup_stop_teamd_on_standby(self, duthost2):
        duthost2.shell("systemctl stop teamd")

        yield
        duthost2.shell("systemctl start teamd")
        duthost2.shell("systemctl start iccpd")
        duthost2.shell("systemctl restart swss")
        wait_until(60, 10, duthost2.critical_services_fully_started)

    @pytest.mark.usefixtures("setup_stop_teamd_on_active")
    def test_stop_teamd_on_active(self, duthost, ptfhost, testbed):
        assert wait_until(100, 10, check_teamd_status, ptfhost, ptf=True, base=0, select=False), \
                "Server port attached to active device should be deselected after active device stopped teamd"

        time.sleep(30)
        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut2_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "ignore_ports": g_vars['dut1_link_server_interfaces']
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

    def test_start_teamd_on_active(self, duthost, ptfhost, testbed):
        assert wait_until(100, 10, check_teamd_status, ptfhost, ptf=True, base=0, select=True), \
                "Server port attached to active device should be selected after active device startup teamd"

        time.sleep(30)
        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "ignore_ports": []
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

    @pytest.mark.usefixtures("setup_stop_teamd_on_standby")
    def test_stop_teamd_on_standby(self, duthost2, ptfhost, testbed):
        assert wait_until(100, 10, check_teamd_status, ptfhost, ptf=True, base=len(g_vars['dut1_all_interfaces']), select=False), \
                "Server port attached to standby device should be deselected after standby device stopped teamd"

        time.sleep(30)
        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "ignore_ports": g_vars['dut2_link_server_interfaces']
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )

    def test_start_teamd_on_standby(self, duthost2, ptfhost, testbed):
        assert wait_until(100, 10, check_teamd_status, ptfhost, ptf=True, base=len(g_vars['dut1_all_interfaces']), select=True), \
                "Server port attached to standby device should be selected after standby device startup teamd"

        time.sleep(30)
        ptf_runner(
                    ptfhost,
                    "ptftests",
                    "mclag_test.MclagTest",
                    platform_dir="ptftests",
                    params={
                        "router_mac": g_vars['dut1_router_mac'],
                        "testbed_type": testbed['topo'],
                        "switch_info": "/tmp/mclag/mclag_switch_info_{}.txt".format(test_scenario),
                        "test_scenario": test_scenario,
                        "ignore_ports": []
                    },
                    log_file="/tmp/mclag/log/mclag_{}_[{}]_[{}].log".format(test_scenario, self.__class__.__name__, sys._getframe().f_code.co_name)
        )
