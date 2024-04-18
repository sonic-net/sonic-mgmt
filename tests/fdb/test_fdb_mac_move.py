import logging
import time
import math
import pytest

from collections import defaultdict
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from utils import MacToInt, IntToMac, fdb_cleanup, get_crm_resources, send_arp_request, get_fdb_dynamic_mac_count

TOTAL_FDB_ENTRIES = 12000
FDB_POPULATE_SLEEP_TIMEOUT = 2
BASE_MAC_ADDRESS = "02:11:22:{:02x}:00:00"

LOOP_TIMES_LEVEL_MAP = {
    'debug': 1,
    'basic': 10,
    'confident': 50,
    'thorough': 100,
    'diagnose': 200
}

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
]


def modify_rsyslog_severity_level(dut):
    logger.info('Modify rsyslog severity level to error on dut: {}'.format(dut.hostname))
    dut.shell("sudo mv /etc/rsyslog.d /etc/rsyslog.d.bak")
    dut.shell("sudo mkdir /etc/rsyslog.d")
    dut.shell("sudo echo '*.err    /var/log/syslog' > /etc/rsyslog.d/50_debug.conf")
    dut.shell("sudo systemctl restart rsyslog")
    time.sleep(5)


def revert_rsyslog_severity_level(dut):
    logger.info('Revert rsyslog severity level to error on dut: {}'.format(dut.hostname))
    dut.shell("sudo rm -rf /etc/rsyslog.d")
    dut.shell("sudo mv /etc/rsyslog.d.bak /etc/rsyslog.d")
    dut.shell("sudo systemctl restart rsyslog")
    time.sleep(5)


@pytest.fixture(scope="function")
def fixture_rsyslog_conf_setup_teardown(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    # workaround for small disk devices which also has limitation on /var/log size
    cmd = "df -m"
    cmd_response_lines = duthost.shell(cmd, module_ignore_errors=True).get('stdout_lines', [])
    logger.debug("cmd {} rsp {}".format(cmd, cmd_response_lines))

    available_size = 0
    for line in cmd_response_lines:
        if "/var/log" in line:
            available_size = int(line.split()[3])
            break

    if available_size < 400:
        modify_rsyslog_severity_level(duthost)
        rsyslog_severity_level_modified = True
    else:
        rsyslog_severity_level_modified = False

    yield

    if rsyslog_severity_level_modified:
        revert_rsyslog_severity_level(duthost)


def get_fdb_dict(ptfadapter, vlan_table, dummay_mac_count):
    """
    :param ptfadapter: PTF adapter object
    :param vlan_table: VLAN table map: VLAN subnet -> list of VLAN members
    :return: FDB table map : VLAN member -> MAC addresses set
    """

    fdb = {}
    vlan = vlan_table.keys()[0]

    for member in vlan_table[vlan]:
        if 'port_index' not in member or 'tagging_mode' not in member:
            continue
        if not member['port_index']:
            continue

        port_index = member['port_index'][0]

        fdb[port_index] = {}

        dummy_macs = []
        base_mac = BASE_MAC_ADDRESS.format(port_index)
        for i in range(dummay_mac_count):
            mac_address = IntToMac(MacToInt(base_mac) + i)
            dummy_macs.append(mac_address)
        fdb[port_index] = dummy_macs
    return fdb


def test_fdb_mac_move(ptfadapter, duthosts, rand_one_dut_hostname, ptfhost, get_function_conpleteness_level,
                      fixture_rsyslog_conf_setup_teardown):
    # Perform FDB clean up before each test
    fdb_cleanup(duthosts, rand_one_dut_hostname)

    normalized_level = get_function_conpleteness_level
    if normalized_level is None:
        normalized_level = "basic"
    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]

    duthost = duthosts[rand_one_dut_hostname]
    conf_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']

    # reinitialize data plane due to above changes on PTF interfaces
    ptfadapter.reinit()

    router_mac = duthost.facts['router_mac']

    port_index_to_name = {v: k for k, v in conf_facts['port_index_map'].items()}

    # Only take interfaces that are in ptf topology
    ptf_ports_available_in_topo = ptfhost.host.options['variable_manager'].extra_vars.get("ifaces_map")
    available_ports_idx = []
    for idx, name in ptf_ports_available_in_topo.items():
        if idx in port_index_to_name and conf_facts['PORT'][port_index_to_name[idx]].get('admin_status',
                                                                                         'down') == 'up':
            available_ports_idx.append(idx)

    vlan_table = {}
    interface_table = defaultdict(set)
    config_portchannels = conf_facts.get('PORTCHANNEL', {})

    # if DUT has more than one VLANs, use the first vlan
    name = conf_facts['VLAN'].keys()[0]
    vlan = conf_facts['VLAN'][name]
    vlan_id = int(vlan['vlanid'])
    vlan_table[vlan_id] = []

    for ifname in conf_facts['VLAN_MEMBER'][name].keys():
        if 'tagging_mode' not in conf_facts['VLAN_MEMBER'][name][ifname]:
            continue
        tagging_mode = conf_facts['VLAN_MEMBER'][name][ifname]['tagging_mode']
        port_index = []
        if ifname in config_portchannels:
            for member in config_portchannels[ifname]['members']:
                if conf_facts['port_index_map'][member] in available_ports_idx:
                    port_index.append(conf_facts['port_index_map'][member])
            if port_index:
                interface_table[ifname].add(vlan_id)
        elif conf_facts['port_index_map'][ifname] in available_ports_idx:
            port_index.append(conf_facts['port_index_map'][ifname])
            interface_table[ifname].add(vlan_id)
        if port_index:
            vlan_table[vlan_id].append({'port_index': port_index, 'tagging_mode': tagging_mode})

    vlan = vlan_table.keys()[0]
    vlan_member_count = len(vlan_table[vlan])
    total_fdb_entries = min(TOTAL_FDB_ENTRIES, (
            get_crm_resources(duthost, "fdb_entry", "available") - get_crm_resources(duthost, "fdb_entry", "used")))
    dummay_mac_count = int(math.floor(total_fdb_entries / vlan_member_count))

    fdb = get_fdb_dict(ptfadapter, vlan_table, dummay_mac_count)
    port_list = fdb.keys()
    dummy_mac_list = fdb.values()

    for loop_time in range(0, loop_times):
        port_index_start = (0 + loop_time) % len(port_list)

        for (port, dummy_mac_set) in zip(range(len(port_list)), dummy_mac_list):
            port_index = (port_index_start + port) % len(port_list)
            for dummy_mac in dummy_mac_set:
                send_arp_request(ptfadapter, port_index, dummy_mac, router_mac, vlan_id)

        time.sleep(FDB_POPULATE_SLEEP_TIMEOUT)
        pytest_assert(wait_until(20, 1, 0, lambda: get_fdb_dynamic_mac_count(duthost) > vlan_member_count),
                      "FDB Table Add failed")
        # Flush dataplane
        ptfadapter.dataplane.flush()
        fdb_cleanup(duthosts, rand_one_dut_hostname)
        # Wait for 10 seconds before starting next loop
        time.sleep(10)