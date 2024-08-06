from typing import Dict, List

import paramiko
import pytest
import logging
import itertools
import collections
import ipaddress
import time
import json

from pytest_ansible.errors import AnsibleConnectionFailure
from paramiko.ssh_exception import AuthenticationException

from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from jinja2 import Template
from netaddr import valid_ipv4, valid_ipv6
from tests.common.mellanox_data import is_mellanox_device
from tests.common.platform.processes_utils import wait_critical_processes


logger = logging.getLogger(__name__)


def _backup_and_restore_config_db(duts, scope='function'):
    """Back up the existing config_db.json file and restore it once the test ends.

    Some cases will update the running config during the test and save the config
    to be recovered aftet reboot. In such a case we need to backup config_db.json before
    the test starts and then restore it after the test ends.
    """
    CONFIG_DB = "/etc/sonic/config_db.json"
    CONFIG_DB_BAK = "/host/config_db.json.before_test_{}".format(scope)

    if type(duts) is not list:
        duthosts = [duts]
    else:
        duthosts = duts

    for duthost in duthosts:
        logger.info("Backup {} to {} on {}".format(CONFIG_DB, CONFIG_DB_BAK, duthost.hostname))
        duthost.shell("cp {} {}".format(CONFIG_DB, CONFIG_DB_BAK))

    yield

    for duthost in duthosts:
        logger.info("Restore {} with {} on {}".format(CONFIG_DB, CONFIG_DB_BAK, duthost.hostname))
        duthost.shell("mv {} {}".format(CONFIG_DB_BAK, CONFIG_DB))


@pytest.fixture(scope="module")
def backup_and_restore_config_db_on_duts(duthosts):
    """
    A module level fixture to backup and restore config_db.json on all duts
    """
    for func in _backup_and_restore_config_db(duthosts, "module"):
        yield func


@pytest.fixture
def backup_and_restore_config_db(duthosts, rand_one_dut_hostname):
    """Back up and restore config DB at the function level."""
    duthost = duthosts[rand_one_dut_hostname]
    # TODO: Use the neater "yield from _function" syntax when we move to python3
    for func in _backup_and_restore_config_db(duthost, "function"):
        yield func


@pytest.fixture(scope="module")
def backup_and_restore_config_db_module(duthosts, rand_one_dut_hostname):
    """Back up and restore config DB at the module level."""
    duthost = duthosts[rand_one_dut_hostname]
    # TODO: Use the neater "yield from _function" syntax when we move to python3
    for func in _backup_and_restore_config_db(duthost, "module"):
        yield func


@pytest.fixture(scope="module")
def backup_and_restore_config_db_package(duthosts):

    for func in _backup_and_restore_config_db(duthosts, "package"):
        yield func


@pytest.fixture(scope="session")
def backup_and_restore_config_db_session(duthosts):

    for func in _backup_and_restore_config_db(duthosts, "session"):
        yield func


def _disable_route_checker(duthost):
    """
        Some test cases will add static routes for test, which may trigger route_checker
        to report error. This function is to disable route_checker before test, and recover it
        after test.

        Args:
            duthost: DUT fixture
    """
    duthost.command('monit stop routeCheck', module_ignore_errors=True)
    yield
    duthost.command('monit start routeCheck', module_ignore_errors=True)


@pytest.fixture
def disable_route_checker(duthosts, rand_one_dut_hostname):
    """
    Wrapper for _disable_route_checker, function level
    """
    duthost = duthosts[rand_one_dut_hostname]
    for func in _disable_route_checker(duthost):
        yield func


@pytest.fixture(scope='module')
def disable_route_checker_module(duthosts, rand_one_dut_hostname):
    """
    Wrapper for _disable_route_checker, module level
    """
    duthost = duthosts[rand_one_dut_hostname]
    for func in _disable_route_checker(duthost):
        yield func


@pytest.fixture(scope='module')
def disable_fdb_aging(duthost):
    """
    Disable fdb aging by swssconfig.
    The original config will be recovered after running test.
    """
    switch_config = """[
    {
        "SWITCH_TABLE:switch": {
            "ecmp_hash_seed": "0",
            "lag_hash_seed": "0",
            "fdb_aging_time": "{{ aging_time }}"
        },
        "OP": "SET"
    }
    ]"""
    TMP_SWITCH_CONFIG_FILE = "/tmp/switch_config.json"
    DST_SWITCH_CONFIG_FILE = "/switch_config.json"
    switch_config_template = Template(switch_config)
    duthost.copy(content=switch_config_template.render(aging_time=0),
                 dest=TMP_SWITCH_CONFIG_FILE)
    if duthost.is_multi_asic:
        ns = duthost.get_asic_namespace_list()[0]
        asic_id = duthost.get_asic_id_from_namespace(ns)
    else:
        asic_id = ''

    # Generate and load config with swssconfig
    cmds = [
        "docker cp {} swss{}:{}".format(TMP_SWITCH_CONFIG_FILE, asic_id, DST_SWITCH_CONFIG_FILE),
        "docker exec -i swss{} swssconfig {}".format(asic_id, DST_SWITCH_CONFIG_FILE)
    ]
    duthost.shell_cmds(cmds=cmds)

    yield
    # Recover default aging time
    DEFAULT_SWITCH_CONFIG_FILE = "/etc/swss/config.d/switch.json"
    cmds = [
        "docker exec -i swss{} rm {}".format(asic_id, DST_SWITCH_CONFIG_FILE),
        "docker exec -i swss{} swssconfig {}".format(asic_id, DEFAULT_SWITCH_CONFIG_FILE)
    ]
    duthost.shell_cmds(cmds=cmds)
    duthost.file(path=TMP_SWITCH_CONFIG_FILE, state="absent")


@pytest.fixture(scope="module")
def ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    config_ports = {k: v for k, v in list(cfg_facts['PORT'].items()) if v.get('admin_status', 'down') == 'up'}
    config_port_indices = {k: v for k, v in list(mg_facts['minigraph_ptf_indices'].items()) if k in config_ports}
    ptf_ports_available_in_topo = {
        port_index: 'eth{}'.format(port_index) for port_index in list(config_port_indices.values())
    }
    config_portchannels = cfg_facts.get('PORTCHANNEL_MEMBER', {})
    config_port_channel_members = [list(port_channel.keys()) for port_channel in list(config_portchannels.values())]
    config_port_channel_member_ports = list(itertools.chain.from_iterable(config_port_channel_members))
    ports = [port for port in config_ports if config_port_indices[port] in ptf_ports_available_in_topo and
             config_ports[port].get('admin_status', 'down') == 'up' and port not in config_port_channel_member_ports]
    return ports


def check_orch_cpu_utilization(dut, orch_cpu_threshold):
    """
    Compare orchagent CPU utilization 5 times, with 1 second interval in between and make sure all 5 readings are
    less than threshold

    Args:
        dut: DUT host object
        orch_cpu_threshold: orch cpu threshold
    """
    for i in range(5):
        orch_cpu = dut.shell("COLUMNS=512 show processes cpu | grep orchagent | awk '{print $9}'")["stdout_lines"]
        for line in orch_cpu:
            if int(float(line)) > orch_cpu_threshold:
                return False
        time.sleep(1)
    return True


def check_ebgp_routes(num_v4_routes, num_v6_routes, duthost):
    MAX_DIFF = 5
    sumv4, sumv6 = duthost.get_ip_route_summary()
    rtn_val = True
    if 'ebgp' in sumv4 and 'routes' in sumv4['ebgp'] and \
            abs(int(float(sumv4['ebgp']['routes'])) - int(float(num_v4_routes))) >= MAX_DIFF:
        logger.info("IPv4 ebgp routes: {}".format(float(sumv4['ebgp']['routes'])))
        rtn_val = False
    if 'ebgp' in sumv6 and 'routes' in sumv6['ebgp'] and \
            abs(int(float(sumv6['ebgp']['routes'])) - int(float(num_v6_routes))) >= MAX_DIFF:
        logger.info("IPv6 ebgp routes: {}".format(float(sumv6['ebgp']['routes'])))
        rtn_val = False
    return rtn_val


@pytest.fixture(scope="module")
def shutdown_ebgp(duthosts, rand_one_dut_hostname):
    # To store the original number of eBGP v4 and v6 routes.
    v4ebgps = {}
    v6ebgps = {}
    orch_cpu_threshold = 10
    # increase timeout for check_orch_cpu_utilization to 120sec for chassis
    # especially uplink cards need >60sec for orchagent cpu usage to come down to 10%
    duthost = duthosts[rand_one_dut_hostname]
    is_chassis = duthost.get_facts().get("modular_chassis")
    orch_cpu_timeout = 120 if is_chassis else 60
    for duthost in duthosts.frontend_nodes:
        # Get the original number of eBGP v4 and v6 routes on the DUT.
        sumv4, sumv6 = duthost.get_ip_route_summary()
        v4ebgps[duthost.hostname] = sumv4.get('ebgp', {'routes': 0})['routes']
        v6ebgps[duthost.hostname] = sumv6.get('ebgp', {'routes': 0})['routes']
        # Shutdown all eBGP neighbors
        duthost.command("sudo config bgp shutdown all")
        # Verify that the total eBGP routes are 0.
        pytest_assert(wait_until(60, 2, 5, check_ebgp_routes, 0, 0, duthost),
                      "eBGP routes are not 0 after shutting down all neighbors on {}".format(duthost))
        pytest_assert(wait_until(orch_cpu_timeout, 2, 0, check_orch_cpu_utilization, duthost, orch_cpu_threshold),
                      "Orch CPU utilization {} > orch cpu threshold {} after shutdown all eBGP"
                      .format(duthost.shell("show processes cpu | grep orchagent | awk '{print $9}'")["stdout"],
                              orch_cpu_threshold))

    yield

    for duthost in duthosts.frontend_nodes:
        # Startup all the eBGP neighbors
        duthost.command("sudo config bgp startup all")

    for duthost in duthosts.frontend_nodes:
        # Verify that total eBGP routes are what they were before shutdown of all eBGP neighbors
        orig_v4_ebgp = v4ebgps[duthost.hostname]
        orig_v6_ebgp = v6ebgps[duthost.hostname]
        pytest_assert(wait_until(120, 10, 10, check_ebgp_routes, orig_v4_ebgp, orig_v6_ebgp, duthost),
                      "eBGP v4 routes are {}, and v6 route are {}, and not what they were originally after enabling "
                      "all neighbors on {}".format(orig_v4_ebgp, orig_v6_ebgp, duthost))
        pytest_assert(wait_until(orch_cpu_timeout, 2, 0, check_orch_cpu_utilization, duthost, orch_cpu_threshold),
                      "Orch CPU utilization {} > orch cpu threshold {} after startup all eBGP"
                      .format(duthost.shell("show processes cpu | grep orchagent | awk '{print $9}'")["stdout"],
                              orch_cpu_threshold))


@pytest.fixture(scope="module")
def utils_vlan_ports_list(duthosts, rand_one_dut_hostname, rand_selected_dut, tbinfo, ports_list):
    """
    Get configured VLAN ports
    """
    duthost = duthosts[rand_one_dut_hostname]
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    vlan_ports_list = []
    config_ports = {k: v for k, v in list(cfg_facts['PORT'].items()) if v.get('admin_status', 'down') == 'up'}
    config_portchannels = cfg_facts.get('PORTCHANNEL_MEMBER', {})
    config_port_indices = {k: v for k, v in list(mg_facts['minigraph_ptf_indices'].items()) if k in config_ports}
    config_ports_vlan = collections.defaultdict(list)
    vlan_members = cfg_facts.get('VLAN_MEMBER', {})
    # key is dev name, value is list for configured VLAN member.
    for k, v in list(cfg_facts['VLAN'].items()):
        vlanid = v['vlanid']
        for addr in cfg_facts['VLAN_INTERFACE']['Vlan'+vlanid]:
            # address could be IPV6 and IPV4, only need IPV4 here
            if addr and valid_ipv4(addr.split('/')[0]):
                ip = addr
                break
        else:
            continue
        if k not in vlan_members:
            continue
        for port in vlan_members[k]:
            if 'tagging_mode' not in vlan_members[k][port]:
                continue
            mode = vlan_members[k][port]['tagging_mode']
            config_ports_vlan[port].append({'vlanid': int(vlanid), 'ip': ip, 'tagging_mode': mode})

    if config_portchannels:
        for po in config_portchannels:
            vlan_port = {
                'dev': po,
                'port_index': [config_port_indices[member] for member in list(config_portchannels[po].keys())],
                'permit_vlanid': []
            }
            if po in config_ports_vlan:
                vlan_port['pvid'] = 0
                for vlan in config_ports_vlan[po]:
                    if 'vlanid' not in vlan or 'ip' not in vlan or 'tagging_mode' not in vlan:
                        continue
                    if vlan['tagging_mode'] == 'untagged':
                        vlan_port['pvid'] = vlan['vlanid']
                    vlan_port['permit_vlanid'].append(vlan['vlanid'])
            if 'pvid' in vlan_port:
                vlan_ports_list.append(vlan_port)

    for i, port in enumerate(ports_list):
        vlan_port = {
            'dev': port,
            'port_index': [config_port_indices[port]],
            'permit_vlanid': []
        }
        if port in config_ports_vlan:
            vlan_port['pvid'] = 0
            for vlan in config_ports_vlan[port]:
                if 'vlanid' not in vlan or 'ip' not in vlan or 'tagging_mode' not in vlan:
                    continue
                if vlan['tagging_mode'] == 'untagged':
                    vlan_port['pvid'] = vlan['vlanid']
                vlan_port['permit_vlanid'].append(vlan['vlanid'])
        if 'pvid' in vlan_port:
            vlan_ports_list.append(vlan_port)

    return vlan_ports_list


def compare_network(src_ipprefix, dst_ipprefix):
    src_network = ipaddress.IPv4Interface(src_ipprefix).network
    dst_network = ipaddress.IPv4Interface(dst_ipprefix).network
    return src_network.overlaps(dst_network)


@pytest.fixture(scope="module")
def utils_vlan_intfs_dict_orig(duthosts, rand_one_dut_hostname, tbinfo):
    '''A module level fixture to record duthost's original vlan info

    Args:
        duthosts: All DUTs belong to the testbed.
        rand_one_dut_hostname: hostname of a random chosen dut to run test.
        tbinfo: A fixture to gather information about the testbed.

    Returns:
        VLAN info dict with original VLAN info
        Example:
            "Vlan1000": {
                "fc02:1000::1/64": {},
                "grat_arp": "enabled",
                "proxy_arp": "enabled",
                "192.168.0.1/21": {}
            }
    '''
    duthost = duthosts[rand_one_dut_hostname]
    cfg_facts = duthost.config_facts(host=duthost.hostname, source="persistent")['ansible_facts']
    vlan_intfs_dict = {}
    if 'VLAN_INTERFACE' not in cfg_facts:
        return vlan_intfs_dict
    for k, v in list(cfg_facts['VLAN'].items()):
        vlanid = v['vlanid']
        for addr in cfg_facts['VLAN_INTERFACE']['Vlan'+vlanid]:
            # NOTE: here only returning IPv4.
            if addr and valid_ipv4(addr.split('/')[0]):
                ip = addr
                break
        else:
            continue
        logger.info("Original VLAN {}, ip {}".format(vlanid, ip))
        vlan_intfs_dict[int(vlanid)] = {'ip': ip, 'orig': True}
    return vlan_intfs_dict


def utils_vlan_intfs_dict_add(vlan_intfs_dict, add_cnt):
    '''Utilities function to add add_cnt of new VLAN

    Args:
        vlan_intfs_dict: Original VLAN info dict
        add_cnt: number of new vlan to add

    Returns:
        VLAN info dict combined with original and new added VLAN info
        Example:
        {
            1000: {'ip':'192.168.0.1/21', 'orig': True},
            108: {'ip':'192.168.8.1/24', 'orig': False},
            109: {'ip':'192.168.9.1/24', 'orig': False}
        }
    '''
    vlan_cnt = 0
    for i in range(0, 255):
        vid = 100 + i
        if vid in vlan_intfs_dict:
            continue
        ip = '192.168.{}.1/24'.format(i)
        for v in list(vlan_intfs_dict.values()):
            if compare_network(ip, v['ip']):
                break
        else:
            logger.info("Add VLAN {}, ip {}".format(vid, ip))
            vlan_intfs_dict[vid] = {'ip': ip, 'orig': False}
            vlan_cnt += 1
        if vlan_cnt >= add_cnt:
            break
    assert vlan_cnt == add_cnt
    return vlan_intfs_dict


def utils_create_test_vlans(duthost, cfg_facts, vlan_ports_list, vlan_intfs_dict, delete_untagged_vlan):
    '''Utilities function to create vlans for test

    Args:
        duthost: Device Under Test (DUT)
        cfg_facts: config facts fot the duthost
        vlan_ports_list: vlan ports info
        vlan_intfs_dict: VLAN info dict with VLAN info
        delete_untagged_vlan: check to delete unttaged vlan
    '''
    cmds = []
    logger.info("Add vlans, assign IPs")
    for k, v in list(vlan_intfs_dict.items()):
        if v['orig']:
            continue
        cmds.append('config vlan add {}'.format(k))
        cmds.append("config interface ip add Vlan{} {}".format(k, v['ip'].upper()))

    # Delete untagged vlans from interfaces to avoid error message
    # when adding untagged vlan to interface that already have one
    if delete_untagged_vlan and '201911' not in duthost.os_version:
        logger.info("Delete untagged vlans from interfaces")
        for vlan_port in vlan_ports_list:
            vlan_members = cfg_facts.get('VLAN_MEMBER', {})
            vlan_name, vid = list(vlan_members.keys())[0], list(vlan_members.keys())[0].replace("Vlan", '')
            try:
                if vlan_members[vlan_name][vlan_port['dev']]['tagging_mode'] == 'untagged':
                    cmds.append("config vlan member del {} {}".format(vid, vlan_port['dev']))
            except KeyError:
                continue

    logger.info("Add members to Vlans")
    for vlan_port in vlan_ports_list:
        for permit_vlanid in vlan_port['permit_vlanid']:
            if vlan_intfs_dict[int(permit_vlanid)]['orig']:
                continue
            cmds.append('config vlan member add {tagged} {id} {port}'.format(
                tagged=('--untagged' if vlan_port['pvid'] == permit_vlanid else ''),
                id=permit_vlanid,
                port=vlan_port['dev']
            ))
    logger.info("Commands: {}".format(cmds))
    duthost.shell_cmds(cmds=cmds)


def _dut_qos_map(dut):
    """
    A helper function to get QoS map from DUT host.
    Return a dict
    {
        "dscp_to_tc_map": {
            "0":"1",
            ...
        },
        "tc_to_queue_map": {
            "0":"0"
        },
        ...
    }
    or an empty dict if failed to parse the output
    """
    maps = {}
    try:
        if dut.is_multi_asic:
            sonic_cfggen_cmd = "sonic-cfggen -n asic0 -d --var-json"
        else:
            sonic_cfggen_cmd = "sonic-cfggen -d --var-json"

        # port_qos_map
        port_qos_map = dut.shell("{} 'PORT_QOS_MAP'".format(sonic_cfggen_cmd))['stdout']
        maps['port_qos_map'] = json.loads(port_qos_map) if port_qos_map else None

        # dscp_to_tc_map
        dscp_to_tc_map = dut.shell("{} 'DSCP_TO_TC_MAP'".format(sonic_cfggen_cmd))['stdout']
        maps['dscp_to_tc_map'] = json.loads(dscp_to_tc_map) if dscp_to_tc_map else None

        # tc_to_queue_map
        tc_to_queue_map = dut.shell("{} 'TC_TO_QUEUE_MAP'".format(sonic_cfggen_cmd))['stdout']
        maps['tc_to_queue_map'] = json.loads(tc_to_queue_map) if tc_to_queue_map else None

        # tc_to_priority_group_map
        tc_to_priority_group_map = dut.shell("{} 'TC_TO_PRIORITY_GROUP_MAP'".format(sonic_cfggen_cmd))['stdout']
        maps['tc_to_priority_group_map'] = json.loads(tc_to_priority_group_map) if tc_to_priority_group_map else None

        # tc_to_dscp_map
        tc_to_dscp_map = dut.shell("{} 'TC_TO_DSCP_MAP'".format(sonic_cfggen_cmd))['stdout']
        maps['tc_to_dscp_map'] = json.loads(tc_to_dscp_map) if tc_to_dscp_map else None
    except Exception as e:
        logger.error("Got exception: " + repr(e))
    return maps


@pytest.fixture(scope='class')
def dut_qos_maps(get_src_dst_asic_and_duts):
    """
    A class level fixture to get QoS map from DUT host.
    Return a dict
    """
    dut = get_src_dst_asic_and_duts['src_dut']
    return _dut_qos_map(dut)


@pytest.fixture(scope='module')
def dut_qos_maps_module(rand_selected_front_end_dut):
    """
    A module level fixture to get QoS map from DUT host.
    return a dict
    """
    dut = rand_selected_front_end_dut
    return _dut_qos_map(dut)


@pytest.fixture(scope='module')
def is_support_mock_asic(duthosts, rand_one_dut_hostname):
    """
    Check if dut supports mock asic. For mellanox device, it doesn't support mock asic
    """
    duthost = duthosts[rand_one_dut_hostname]
    return not is_mellanox_device(duthost)


def separated_dscp_to_tc_map_on_uplink(dut_qos_maps_module):
    """
    A helper function to check if separated DSCP_TO_TC_MAP is applied to
    downlink/unlink ports.
    """
    dscp_to_tc_map_names = set()
    for port_name, qos_map in dut_qos_maps_module['port_qos_map'].items():
        if port_name == "global":
            continue
        dscp_to_tc_map_names.add(qos_map.get("dscp_to_tc_map", ""))
        if len(dscp_to_tc_map_names) > 1:
            return True
    return False


def load_dscp_to_pg_map(duthost, port, dut_qos_maps_module):
    """
    Helper function to calculate DSCP to PG map for a port.
    The map is derived from DSCP_TO_TC_MAP + TC_TO_PG_MAP
    return a dict like {0:0, 1:1...}
    """
    try:
        port_qos_map = dut_qos_maps_module['port_qos_map']
        dscp_to_tc_map_name = port_qos_map[port]['dscp_to_tc_map'].split('|')[-1].strip(']')
        tc_to_pg_map_name = port_qos_map[port]['tc_to_pg_map'].split('|')[-1].strip(']')
        # Load dscp_to_tc_map
        dscp_to_tc_map = dut_qos_maps_module['dscp_to_tc_map'][dscp_to_tc_map_name]
        # Load tc_to_pg_map
        tc_to_pg_map = dut_qos_maps_module['tc_to_priority_group_map'][tc_to_pg_map_name]
        # Calculate dscp to pg map
        dscp_to_pg_map = {}
        for dscp, tc in list(dscp_to_tc_map.items()):
            dscp_to_pg_map[dscp] = tc_to_pg_map[tc]
        return dscp_to_pg_map
    except:     # noqa E722
        logger.error("Failed to retrieve dscp to pg map for port {} on {}".format(port, duthost.hostname))
        return {}


def load_dscp_to_queue_map(duthost, port, dut_qos_maps_module):
    """
    Helper function to calculate DSCP to Queue map for a port.
    The map is derived from DSCP_TO_TC_MAP + TC_TO_QUEUE_MAP
    return a dict like {0:0, 1:1...}
    """
    try:
        port_qos_map = dut_qos_maps_module['port_qos_map']
        dscp_to_tc_map_name = port_qos_map[port]['dscp_to_tc_map'].split('|')[-1].strip(']')
        tc_to_queue_map_name = port_qos_map[port]['tc_to_queue_map'].split('|')[-1].strip(']')
        # Load dscp_to_tc_map
        dscp_to_tc_map = dut_qos_maps_module['dscp_to_tc_map'][dscp_to_tc_map_name][dscp_to_tc_map_name]
        # Load tc_to_queue_map
        tc_to_queue_map = dut_qos_maps_module['tc_to_queue_map'][tc_to_queue_map_name]
        # Calculate dscp to queue map
        dscp_to_queue_map = {}
        for dscp, tc in list(dscp_to_tc_map.items()):
            dscp_to_queue_map[dscp] = tc_to_queue_map[tc]
        return dscp_to_queue_map
    except:     # noqa E722
        logger.error("Failed to retrieve dscp to queue map for port {} on {}".format(port, duthost.hostname))
        return {}


def check_bgp_router_id(duthost, mgFacts):
    """
    Check bgp router ID is same as Loopback0
    """
    check_bgp_router_id_cmd = r'vtysh -c "show ip bgp summary json"'
    bgp_summary = duthost.shell(check_bgp_router_id_cmd, module_ignore_errors=True)
    try:
        bgp_summary_json = json.loads(bgp_summary['stdout'])
        router_id = str(bgp_summary_json['ipv4Unicast']['routerId'])
        loopback0 = str(mgFacts['minigraph_lo_interfaces'][0]['addr'])
        if router_id == loopback0:
            logger.info("BGP router identifier: %s == Loopback0 address %s" % (router_id, loopback0))
            return True
        else:
            logger.info("BGP router identifier %s != Loopback0 address %s" % (router_id, loopback0))
            return False
    except Exception as e:
        logger.error("Error loading BGP routerID - {}".format(e))


@pytest.fixture(scope="module")
def convert_and_restore_config_db_to_ipv6_only(duthosts):
    """Convert the DUT's mgmt-ip to IPv6 only

    Convert the DUT's mgmt-ip to IPv6 only by removing the IPv4 mgmt-ip,
    will revert the change after finished.

    Since the change commands is distributed by IPv4 mgmt-ip,
    the fixture will detect the IPv6 availability first,
    only remove the IPv4 mgmt-ip when the IPv6 mgmt-ip is available,
    and will re-establish the connection to the DUTs with IPv6 mgmt-ip.
    """
    config_db_file = "/etc/sonic/config_db.json"
    config_db_bak_file = "/etc/sonic/config_db.json.before_ipv6_only"

    # Sample MGMT_INTERFACE:
    #     "MGMT_INTERFACE": {
    #         "eth0|192.168.0.2/24": {
    #             "forced_mgmt_routes": [
    #                 "192.168.1.1/24"
    #             ],
    #             "gwaddr": "192.168.0.1"
    #         },
    #         "eth0|fc00:1234:5678:abcd::2/64": {
    #             "gwaddr": "fc00:1234:5678:abcd::1",
    #             "forced_mgmt_routes": [
    #                 "fc00:1234:5678:abc1::1/64"
    #             ]
    #         }
    #     }
    #
    # Sample SNMP_AGENT_ADDRESS_CONFIG:
    #   "SNMP_AGENT_ADDRESS_CONFIG": {
    #    "10.1.0.32|161|": {},
    #    "10.250.0.101|161|": {},
    #    "FC00:1::32|161|": {},
    #    "fec0::ffff:afa:1|161|": {}
    #    },                                         },

    # duthost_name: config_db_modified
    config_db_modified: Dict[str, bool] = {duthost.hostname: False
                                           for duthost in duthosts.nodes}
    # duthost_name: [ip_addr]
    ipv4_address: Dict[str, List] = {duthost.hostname: []
                                     for duthost in duthosts.nodes}
    ipv6_address: Dict[str, List] = {duthost.hostname: []
                                     for duthost in duthosts.nodes}
    # Check IPv6 mgmt-ip is set and available, otherwise the DUT will lose control after v4 mgmt-ip is removed
    for duthost in duthosts.nodes:
        mgmt_interface = json.loads(duthost.shell(f"jq '.MGMT_INTERFACE' {config_db_file}",
                                                  module_ignore_errors=True)["stdout"])
        # Use list() to make a copy of mgmt_interface.keys() to avoid
        # "RuntimeError: dictionary changed size during iteration" error
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        has_available_ipv6_addr = False
        for key in list(mgmt_interface):
            ip_addr = key.split("|")[1]
            ip_addr_without_mask = ip_addr.split('/')[0]
            if ip_addr:
                is_ipv6 = valid_ipv6(ip_addr_without_mask)
                if is_ipv6:
                    logger.info(f"Host[{duthost.hostname}] IPv6[{ip_addr}]")
                    ipv6_address[duthost.hostname].append(ip_addr_without_mask)
                    try:
                        # Add a temporary debug log to see if the DUT is reachable via IPv6 mgmt-ip. Will remove later
                        duthost_interface = duthost.shell("sudo ifconfig eth0")['stdout']
                        logging.debug(f"Checking host[{duthost.hostname}] ifconfig eth0:[{duthost_interface}]")
                        ssh_client.connect(ip_addr_without_mask,
                                           username="WRONG_USER", password="WRONG_PWD", timeout=15)
                    except AuthenticationException:
                        logger.info(f"Host[{duthost.hostname}] IPv6[{ip_addr_without_mask}] mgmt-ip is available")
                        has_available_ipv6_addr = has_available_ipv6_addr or True
                    except BaseException as e:
                        logger.info(f"Host[{duthost.hostname}] IPv6[{ip_addr_without_mask}] mgmt-ip is unavailable, "
                                    f"exception[{type(e)}], msg[{str(e)}]")
                    finally:
                        ssh_client.close()

        pytest_assert(len(ipv6_address[duthost.hostname]) > 0,
                      f"{duthost.hostname} doesn't have IPv6 Management IP address")
        pytest_assert(has_available_ipv6_addr,
                      f"{duthost.hostname} doesn't have available IPv6 Management IP address")

    # Remove IPv4 mgmt-ip
    for duthost in duthosts.nodes:
        logger.info(f"Backup {config_db_file} to {config_db_bak_file} on {duthost.hostname}")
        duthost.shell(f"cp {config_db_file} {config_db_bak_file}")
        mgmt_interface = json.loads(duthost.shell(f"jq '.MGMT_INTERFACE' {config_db_file}",
                                                  module_ignore_errors=True)["stdout"])

        # Use list() to make a copy of mgmt_interface.keys() to avoid
        # "RuntimeError: dictionary changed size during iteration" error
        for key in list(mgmt_interface):
            ip_addr = key.split("|")[1]
            ip_addr_without_mask = ip_addr.split('/')[0]
            if ip_addr:
                is_ipv4 = valid_ipv4(ip_addr_without_mask)
                if is_ipv4:
                    ipv4_address[duthost.hostname].append(ip_addr_without_mask)
                    logger.info(f"Removing host[{duthost.hostname}] IPv4[{ip_addr}]")
                    duthost.shell(f"""jq 'del(."MGMT_INTERFACE"."{key}")' {config_db_file} > temp.json"""
                                  f"""&& mv temp.json {config_db_file}""", module_ignore_errors=True)
                    config_db_modified[duthost.hostname] = True

    # Save both IPv4 and IPv6 SNMP address for verification purpose.
    snmp_ipv4_address: Dict[str, List] = {duthost.hostname: []
                                          for duthost in duthosts.nodes}
    snmp_ipv6_address: Dict[str, List] = {duthost.hostname: []
                                          for duthost in duthosts.nodes}
    for duthost in duthosts.nodes:
        snmp_address = json.loads(duthost.shell(f"jq '.SNMP_AGENT_ADDRESS_CONFIG' {config_db_file}",
                                                module_ignore_errors=True)["stdout"])
        # In case device doesn't have SNMP_AGENT_CONFIG: this could happen if
        # DUT is running old image.
        if not snmp_address:
            logger.info(f"No SNMP_AGENT_ADDRESS_CONFIG found in host[{duthost.hostname}] {config_db_file}, continue.")
            continue
        for key in list(snmp_address):
            ip_addr = key.split("|")[0]
            if ip_addr:
                if valid_ipv4(ip_addr):
                    snmp_ipv4_address[duthost.hostname].append(ip_addr)
                    logger.info(f"Removing host[{duthost.hostname}] SNMP IPv4 address {ip_addr}")
                    duthost.shell(f"""jq 'del(."SNMP_AGENT_ADDRESS_CONFIG"."{key}")' {config_db_file} > temp.json"""
                                  f"""&& mv temp.json {config_db_file}""", module_ignore_errors=True)
                    config_db_modified[duthost.hostname] = True
                elif valid_ipv6(ip_addr):
                    snmp_ipv6_address[duthost.hostname].append(ip_addr.lower())

    # Do config_reload after processing BOTH SNMP and MGMT config
    for duthost in duthosts.nodes:
        if config_db_modified[duthost.hostname]:
            logger.info(f"config changed. Doing config reload for {duthost.hostname}")
            try:
                config_reload(duthost, wait=120)
            except AnsibleConnectionFailure as e:
                # IPV4 mgmt interface been deleted by config reload
                # In latest SONiC, config reload command will exit after mgmt interface restart
                # Then 'duthost' will lost IPV4 connection and throw exception
                logger.warning(f'Exception after config reload: {e}')
    duthosts.reset()

    for duthost in duthosts.nodes:
        if config_db_modified[duthost.hostname]:
            # Wait until all critical processes are up,
            # especially snmpd as it needs to be up for SNMP status verification
            wait_critical_processes(duthost)

    # Verify mgmt-interface status
    mgmt_intf_name = "eth0"
    for duthost in duthosts.nodes:
        logger.info(f"Checking host[{duthost.hostname}] mgmt interface[{mgmt_intf_name}]")
        mgmt_intf_ifconfig = duthost.shell(f"ifconfig {mgmt_intf_name}", module_ignore_errors=True)["stdout"]
        assert_addr_in_output(addr_set=ipv4_address, hostname=duthost.hostname,
                              expect_exists=False, cmd_output=mgmt_intf_ifconfig,
                              cmd_desc="ifconfig")
        assert_addr_in_output(addr_set=ipv6_address, hostname=duthost.hostname,
                              expect_exists=True, cmd_output=mgmt_intf_ifconfig,
                              cmd_desc="ifconfig")

    # Verify SNMP address status
    for duthost in duthosts.nodes:
        logger.info(f"Checking host[{duthost.hostname}] SNMP status in netstat output")
        snmp_netstat_output = duthost.shell("sudo netstat -tulnpW | grep snmpd",
                                            module_ignore_errors=True)["stdout"]
        assert_addr_in_output(addr_set=snmp_ipv4_address, hostname=duthost.hostname,
                              expect_exists=False, cmd_output=snmp_netstat_output,
                              cmd_desc="netstat")
        assert_addr_in_output(addr_set=snmp_ipv6_address, hostname=duthost.hostname,
                              expect_exists=True, cmd_output=snmp_netstat_output,
                              cmd_desc="netstat")

    yield

    # Recover IPv4 mgmt-ip and other config (SNMP_ADDRESS, etc.)
    for duthost in duthosts.nodes:
        if config_db_modified[duthost.hostname]:
            logger.info(f"Restore {config_db_file} with {config_db_bak_file} on {duthost.hostname}")
            duthost.shell(f"mv {config_db_bak_file} {config_db_file}")
            config_reload(duthost, safe_reload=True)
    duthosts.reset()

    # Verify mgmt-interface status
    for duthost in duthosts.nodes:
        logger.info(f"Checking host[{duthost.hostname}] mgmt interface[{mgmt_intf_name}]")
        mgmt_intf_ifconfig = duthost.shell(f"ifconfig {mgmt_intf_name}", module_ignore_errors=True)["stdout"]
        assert_addr_in_output(addr_set=ipv4_address, hostname=duthost.hostname,
                              expect_exists=True, cmd_output=mgmt_intf_ifconfig,
                              cmd_desc="ifconfig")
        assert_addr_in_output(addr_set=ipv6_address, hostname=duthost.hostname,
                              expect_exists=True, cmd_output=mgmt_intf_ifconfig,
                              cmd_desc="ifconfig")

    # Verify SNMP address status
    for duthost in duthosts.nodes:
        logger.info(f"Checking host[{duthost.hostname}] SNMP status in netstat output")
        snmp_netstat_output = duthost.shell("sudo netstat -tulnpW | grep snmpd",
                                            module_ignore_errors=True)["stdout"]
        assert_addr_in_output(addr_set=snmp_ipv4_address, hostname=duthost.hostname,
                              expect_exists=True, cmd_output=snmp_netstat_output,
                              cmd_desc="netstat")
        assert_addr_in_output(addr_set=snmp_ipv6_address, hostname=duthost.hostname,
                              expect_exists=True, cmd_output=snmp_netstat_output,
                              cmd_desc="netstat")


def assert_addr_in_output(addr_set: Dict[str, List], hostname: str,
                          expect_exists: bool, cmd_output: str, cmd_desc: str):
    """
    Assert the address status in the command output,
    if status not as expected, assert as failure

    @param addr_set: addr_set, key is dut hostname, value is the list of ip addresses
    @param hostname: hostname
    @param expect_exists: Expectation of the ip,
            True means expect all ip addresses in addr_set appears in the output of cmd_output
            False means expect no ip addresses in addr_set appears in the output of cmd_output
    @param cmd_output: command output
    @param cmd_desc: command description, used for logging purpose.
    """
    for addr in addr_set[hostname]:
        if expect_exists:
            pytest_assert(addr in cmd_output,
                          f"{addr} not appeared in {hostname} {cmd_desc}")
            logger.info(f"{addr} exists in the output of {cmd_desc}")
        else:
            pytest_assert(addr not in cmd_output,
                          f"{hostname} {cmd_desc} still with addr {addr}")
            logger.info(f"{addr} not exists in the output of {cmd_desc} which is expected")


# Currently, conditional mark would only match longest prefix,
# so our mark in tests_mark_conditions_skip_traffic_test.yaml couldn't be matched.
# Use a temporary work around to add skip_traffic_test fixture here,
# once conditional mark support add all matches, will remove this code.
@pytest.fixture(scope="module")
def skip_traffic_test(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.facts["asic_type"] == "vs":
        return True
    return False
