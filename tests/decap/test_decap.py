'''
IPinIP Decap configs for different ASICs:
Table Name in APP_DB: TUNNEL_DECAP_TABLE:IPINIP_TUNNEL

Config          Mellanox <= [201911]        Mellanox >= [202012]        Broadcom <= [201911]        Broadcom >= [202012]     Innovium               # noqa E501
dscp_mode       uniform                     uniform                     pipe                        uniform                  pipe                   # noqa E501
ecn_mode        standard                    standard                    copy_from_outer             copy_from_outer          copy_from_outer        # noqa E501
ttl_mode        pipe                        pipe                        pipe                        pipe                     pipe                   # noqa E501
'''
import json
import logging
from datetime import datetime
import time

import pytest
from jinja2 import Template
from netaddr import IPNetwork
from ansible.plugins.filter.core import to_bool

from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # noqa F401
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses         # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # noqa F401
from tests.common.fixtures.ptfhost_utils import set_ptf_port_mapping_mode   # noqa F401
# from tests.common.fixtures.ptfhost_utils import skip_traffic_test           # noqa F401
from tests.common.fixtures.ptfhost_utils import ptf_test_port_map_active_active
# Temporary work around to add skip_traffic_test fixture from duthost_utils
from tests.common.fixtures.duthost_utils import skip_traffic_test           # noqa F401
from tests.common.fixtures.fib_utils import fib_info_files                  # noqa F401
from tests.common.fixtures.fib_utils import single_fib_for_duts             # noqa F401
from tests.ptf_runner import ptf_runner
from tests.common.dualtor.mux_simulator_control import mux_server_url       # noqa F401
from tests.common.utilities import wait, setup_ferret
from tests.common.dualtor.dual_tor_common import active_active_ports                                # noqa F401
from tests.common.dualtor.dual_tor_common import active_standby_ports                               # noqa F401
from tests.common.dualtor.dual_tor_common import mux_config                                         # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_random_side    # noqa F401
from tests.common.dualtor.nic_simulator_control import mux_status_from_nic_simulator                # noqa F401
from tests.common.dualtor.dual_tor_utils import is_tunnel_qos_remap_enabled

logger = logging.getLogger(__name__)

PTFRUNNER_QLEN = 1000

pytestmark = [
    pytest.mark.topology('any')
]


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthosts, rand_one_dut_hostname, loganalyzer):
    # Ignore in KVM test
    KVMIgnoreRegex = [
        ".*unknown decap tunnel table attribute 'dst_ip'.*",
        ".*Tunnel TEST_IPINIP_V4_TUNNEL cannot be removed since it doesn't exist.*",
        ".*Tunnel TEST_IPINIP_V6_TUNNEL cannot be removed since it doesn't exist.*",
    ]
    duthost = duthosts[rand_one_dut_hostname]
    if loganalyzer:  # Skip if loganalyzer is disabled
        if duthost.facts["asic_type"] == "vs":
            loganalyzer[duthost.hostname].ignore_regex.extend(KVMIgnoreRegex)


def remove_default_decap_cfg(duthosts):
    for duthost in duthosts:
        logger.info('Remove default decap cfg on {}'.format(duthost.hostname))
        for asic_id in duthost.get_frontend_asic_ids():
            swss = 'swss{}'.format(asic_id if asic_id is not None else '')
            cmds = [
                'docker exec {} cp /etc/swss/config.d/ipinip.json /default_ipinip.json'.format(swss),
                'docker exec {} sed -i -e \'s/"OP": *"SET"/"OP": "DEL"/g\' /default_ipinip.json'.format(swss),
                'docker exec {} swssconfig /default_ipinip.json'.format(swss),
                'docker exec {} rm /default_ipinip.json'.format(swss)
            ]
            duthost.shell_cmds(cmds=cmds)


def restore_default_decap_cfg(duthosts):
    for duthost in duthosts:
        logger.info('Restore default decap cfg on {}'.format(duthost.hostname))
        for asic_id in duthost.get_frontend_asic_ids():
            swss = 'swss{}'.format(asic_id if asic_id is not None else '')
            cmd = 'docker exec {} swssconfig /etc/swss/config.d/ipinip.json'.format(swss)
            duthost.shell(cmd)


@pytest.fixture(scope='module')
def ip_ver(request):
    return {
        "outer_ipv4": to_bool(request.config.getoption("outer_ipv4")),
        "outer_ipv6": to_bool(request.config.getoption("outer_ipv6")),
        "inner_ipv4": to_bool(request.config.getoption("inner_ipv4")),
        "inner_ipv6": to_bool(request.config.getoption("inner_ipv6")),
    }


@pytest.fixture(scope='module')
def loopback_ips(active_active_ports, duthosts, duts_running_config_facts, tbinfo):             # noqa F811
    if "dualtor" in tbinfo["topo"]["name"] and active_active_ports:
        # for dualtor testbeds with active-active mux ports, use Loopback2
        lo_dev = "Loopback2"
    else:
        lo_dev = "Loopback0"

    lo_ips = []
    lo_ipv6s = []
    for duthost in duthosts:
        if duthost.is_supervisor_node():
            continue
        cfg_facts = duts_running_config_facts[duthost.hostname]
        lo_ip = None
        lo_ipv6 = None
        # Loopback0 ip is same on all ASICs
        for addr in cfg_facts[0][1]["LOOPBACK_INTERFACE"][lo_dev]:
            ip = IPNetwork(addr).ip
            if ip.version == 4 and not lo_ip:
                lo_ip = str(ip)
            elif ip.version == 6 and not lo_ipv6:
                lo_ipv6 = str(ip)
        lo_ips.append(lo_ip)
        lo_ipv6s.append(lo_ipv6)
    return {'lo_ips': lo_ips, 'lo_ipv6s': lo_ipv6s}


@pytest.fixture(scope='module')
def setup_teardown(request, duthosts, duts_running_config_facts, ip_ver, loopback_ips,
                   fib_info_files, single_fib_for_duts, supported_ttl_dscp_params):     # noqa F811

    vxlan = supported_ttl_dscp_params['vxlan']
    is_multi_asic = duthosts[0].sonichost.is_multi_asic

    setup_info = {
        "fib_info_files": fib_info_files[:3],  # Test at most 3 DUTs in case of multi-DUT
        "single_fib_for_duts": single_fib_for_duts,
        "ignore_ttl": True if is_multi_asic else False,
        "max_internal_hops": 3 if is_multi_asic else 0
    }

    setup_info.update(ip_ver)
    setup_info.update(loopback_ips)
    logger.info(json.dumps(setup_info, indent=2))

    if vxlan != "set_unset":
        # Remove default tunnel
        remove_default_decap_cfg(duthosts)

    yield setup_info

    if vxlan != "set_unset":
        # Restore default tunnel
        restore_default_decap_cfg(duthosts)


def apply_decap_cfg(duthosts, ip_ver, loopback_ips, ttl_mode, dscp_mode, ecn_mode, op):

    decap_conf_template = Template(open("../ansible/roles/test/templates/decap_conf.j2").read())

    # apply test decap configuration (SET or DEL)
    for idx, duthost in enumerate(duthosts):
        if duthost.is_supervisor_node():
            continue
        decap_conf_vars = {
            'lo_ip': loopback_ips['lo_ips'][idx],
            'lo_ipv6': loopback_ips['lo_ipv6s'][idx],
            'ttl_mode': ttl_mode,
            'dscp_mode': dscp_mode,
            'ecn_mode': ecn_mode,
            'op': op,
        }
        decap_conf_vars.update(ip_ver)
        duthost.copy(
            content=decap_conf_template.render(**decap_conf_vars),
            dest='/tmp/decap_conf_{}.json'.format(op))

        for asic_id in duthost.get_frontend_asic_ids():
            swss = 'swss{}'.format(asic_id if asic_id is not None else '')
            cmds = [
                'docker cp /tmp/decap_conf_{}.json {}:/decap_conf_{}.json'.format(op, swss, op),
                'docker exec {} swssconfig /decap_conf_{}.json'.format(swss, op),
                'docker exec {} rm /decap_conf_{}.json'.format(swss, op)
            ]
            duthost.shell_cmds(cmds=cmds)
        duthost.shell('rm /tmp/decap_conf_{}.json'.format(op))


def simulate_vxlan_teardown(duthosts, ptfhost, tbinfo):
    for duthost in duthosts:
        setup_ferret(duthost, ptfhost, tbinfo)
        reboot_script_path = duthost.shell('which {}'.format("neighbor_advertiser"))['stdout']
        ptf_ip = ptfhost.host.options['inventory_manager'].get_host(ptfhost.hostname).vars['ansible_host']
        duthost.shell("{} -s {} -m set".format(reboot_script_path, ptf_ip), module_ignore_errors=True)
        time.sleep(10)
        duthost.shell("{} -s {} -m reset".format(reboot_script_path, ptf_ip), module_ignore_errors=True)
        ptfhost.shell('supervisorctl stop ferret')


def test_decap(tbinfo, duthosts, ptfhost, setup_teardown, mux_server_url,                                   # noqa F811
               toggle_all_simulator_ports_to_random_side, supported_ttl_dscp_params, ip_ver, loopback_ips,  # noqa F811
               duts_running_config_facts, duts_minigraph_facts, mux_status_from_nic_simulator,              # noqa F811
               skip_traffic_test):                                                                          # noqa F811
    setup_info = setup_teardown
    asic_type = duthosts[0].facts["asic_type"]
    ecn_mode = "copy_from_outer"
    ttl_mode = supported_ttl_dscp_params['ttl']
    dscp_mode = supported_ttl_dscp_params['dscp']
    vxlan = supported_ttl_dscp_params['vxlan']
    if duthosts[0].facts['asic_type'] in ['mellanox']:
        ecn_mode = 'standard'

    try:
        if vxlan == "set_unset":
            # checking decap after vxlan set/unset is to make sure that deletion of vxlan
            # tunnel and CPA ACLs won't negatively impact ipinip tunnel & decap mechanism
            # Hence a new decap config is not applied to the device in this case. This is
            # to avoid creating new tables and test ipinip decap with default loaded config
            simulate_vxlan_teardown(duthosts, ptfhost, tbinfo)
        else:
            apply_decap_cfg(duthosts, ip_ver, loopback_ips, ttl_mode, dscp_mode, ecn_mode, 'SET')

        if skip_traffic_test:
            return

        if 'dualtor' in tbinfo['topo']['name']:
            wait(30, 'Wait some time for mux active/standby state to be stable after toggled mux state')

        log_file = "/tmp/decap.{}.log".format(datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
        ptf_runner(ptfhost,
                   "ptftests",
                   "IP_decap_test.DecapPacketTest",
                   platform_dir="ptftests",
                   params={"outer_ipv4": setup_info["outer_ipv4"],
                           "outer_ipv6": setup_info["outer_ipv6"],
                           "inner_ipv4": setup_info["inner_ipv4"],
                           "inner_ipv6": setup_info["inner_ipv6"],
                           "lo_ips": setup_info["lo_ips"],
                           "lo_ipv6s": setup_info["lo_ipv6s"],
                           "ttl_mode": ttl_mode,
                           "dscp_mode": dscp_mode,
                           "asic_type": asic_type,
                           "ignore_ttl": setup_info["ignore_ttl"],
                           "max_internal_hops": setup_info["max_internal_hops"],
                           "fib_info_files": setup_info["fib_info_files"],
                           "single_fib_for_duts": setup_info["single_fib_for_duts"],
                           "ptf_test_port_map": ptf_test_port_map_active_active(
                               ptfhost, tbinfo, duthosts, mux_server_url,
                               duts_running_config_facts, duts_minigraph_facts,
                               mux_status_from_nic_simulator()),
                           "topo": tbinfo['topo']['type'],
                           "qos_remap_enabled": is_tunnel_qos_remap_enabled(duthosts[0])
                           },
                   qlen=PTFRUNNER_QLEN,
                   log_file=log_file,
                   is_python3=True)
    finally:
        # Remove test decap configuration
        if vxlan != "set_unset":
            # in vxlan setunset case the config was not applied, hence DEL is also not required
            apply_decap_cfg(duthosts, ip_ver, loopback_ips, ttl_mode, dscp_mode, ecn_mode, 'DEL')
