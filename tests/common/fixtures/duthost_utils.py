import pytest
import logging
import itertools
import collections
import ipaddress
import time
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from jinja2 import Template
from netaddr import valid_ipv4


logger = logging.getLogger(__name__)


def _backup_and_restore_config_db(duts, scope='function'):
    """Back up the existing config_db.json file and restore it once the test ends.

    Some cases will update the running config during the test and save the config
    to be recovered aftet reboot. In such a case we need to backup config_db.json before
    the test starts and then restore it after the test ends.
    """
    CONFIG_DB = "/etc/sonic/config_db.json"
    CONFIG_DB_BAK = "/etc/sonic/config_db.json.before_test_{}".format(scope)

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
    config_ports = {k: v for k,v in cfg_facts['PORT'].items() if v.get('admin_status', 'down') == 'up'}
    config_port_indices = {k: v for k, v in mg_facts['minigraph_ptf_indices'].items() if k in config_ports}
    ptf_ports_available_in_topo = {port_index: 'eth{}'.format(port_index) for port_index in config_port_indices.values()}
    config_portchannels = cfg_facts.get('PORTCHANNEL', {})
    config_port_channel_members = [port_channel['members'] for port_channel in config_portchannels.values()]
    config_port_channel_member_ports = list(itertools.chain.from_iterable(config_port_channel_members))
    ports = [port for port in config_ports
        if config_port_indices[port] in ptf_ports_available_in_topo
        and config_ports[port].get('admin_status', 'down') == 'up'
        and port not in config_port_channel_member_ports]
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
    if 'ebgp' in sumv4 and 'routes' in sumv4['ebgp'] and abs(int(float(sumv4['ebgp']['routes'])) - int(float(num_v4_routes))) >= MAX_DIFF:
        rtn_val = False
    if 'ebgp' in sumv6 and 'routes' in sumv6['ebgp'] and abs(int(float(sumv6['ebgp']['routes'])) - int(float(num_v6_routes))) >= MAX_DIFF:
        rtn_val = False
    return rtn_val

@pytest.fixture(scope="module")
def shutdown_ebgp(duthosts):
    # To store the original number of eBGP v4 and v6 routes.
    v4ebgps = {}
    v6ebgps = {}
    orch_cpu_threshold = 10
    for duthost in duthosts.frontend_nodes:
        # Get the original number of eBGP v4 and v6 routes on the DUT.
        sumv4, sumv6 = duthost.get_ip_route_summary()
        v4ebgps[duthost.hostname] = sumv4.get('ebgp', {'routes': 0})['routes']
        v6ebgps[duthost.hostname] = sumv6.get('ebgp', {'routes': 0})['routes']
        # Shutdown all eBGP neighbors
        duthost.command("sudo config bgp shutdown all")
        # Verify that the total eBGP routes are 0.
        pytest_assert(wait_until(30, 2, 0, check_ebgp_routes, 0, 0, duthost),
                      "eBGP routes are not 0 after shutting down all neighbors on {}".format(duthost))
        pytest_assert(wait_until(60, 2, 0, check_orch_cpu_utilization, duthost, orch_cpu_threshold),
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
                      "eBGP v4 routes are {}, and v6 route are {}, and not what they were originally after enabling all neighbors on {}".format(orig_v4_ebgp, orig_v6_ebgp, duthost))
        pytest_assert(wait_until(60, 2, 0, check_orch_cpu_utilization, duthost, orch_cpu_threshold),
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
    config_ports = {k: v for k,v in cfg_facts['PORT'].items() if v.get('admin_status', 'down') == 'up'}
    config_portchannels = cfg_facts.get('PORTCHANNEL', {})
    config_port_indices = {k: v for k, v in mg_facts['minigraph_ptf_indices'].items() if k in config_ports}
    config_ports_vlan = collections.defaultdict(list)
    vlan_members = cfg_facts.get('VLAN_MEMBER', {})
    # key is dev name, value is list for configured VLAN member.
    for k, v in cfg_facts['VLAN'].items():
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
            config_ports_vlan[port].append({'vlanid':int(vlanid), 'ip':ip, 'tagging_mode':mode})

    if config_portchannels:
        for po in config_portchannels:
            vlan_port = {
                'dev' : po,
                'port_index' : [config_port_indices[member] for member in config_portchannels[po]['members']],
                'permit_vlanid' : []
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
            'dev' : port,
            'port_index' : [config_port_indices[port]],
            'permit_vlanid' : []
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
    for k, v in cfg_facts['VLAN'].items():
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
    for i in xrange(0, 255):
        vid = 100 + i
        if vid in vlan_intfs_dict:
            continue
        ip = u'192.168.{}.1/24'.format(i)
        for v in vlan_intfs_dict.values():
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
    for k, v in vlan_intfs_dict.items():
        if v['orig'] == True:
            continue
        cmds.append('config vlan add {}'.format(k))
        cmds.append("config interface ip add Vlan{} {}".format(k, v['ip'].upper()))

    # Delete untagged vlans from interfaces to avoid error message
    # when adding untagged vlan to interface that already have one
    if delete_untagged_vlan and '201911' not in duthost.os_version:
        logger.info("Delete untagged vlans from interfaces")
        for vlan_port in vlan_ports_list:
            vlan_members = cfg_facts.get('VLAN_MEMBER', {})
            vlan_name, vid = vlan_members.keys()[0], vlan_members.keys()[0].replace("Vlan", '')
            try:
                if vlan_members[vlan_name][vlan_port['dev']]['tagging_mode'] == 'untagged':
                    cmds.append("config vlan member del {} {}".format(vid, vlan_port['dev']))
            except KeyError:
                continue

    logger.info("Add members to Vlans")
    for vlan_port in vlan_ports_list:
        for permit_vlanid in vlan_port['permit_vlanid']:
            if vlan_intfs_dict[int(permit_vlanid)]['orig'] == True:
                continue
            cmds.append('config vlan member add {tagged} {id} {port}'.format(
                tagged=('--untagged' if vlan_port['pvid'] == permit_vlanid else ''),
                id=permit_vlanid,
                port=vlan_port['dev']
            ))
    logger.info("Commands: {}".format(cmds))
    duthost.shell_cmds(cmds=cmds)
