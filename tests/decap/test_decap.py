'''
IPinIP Decap configs for different ASICs:
Table Name in APP_DB: TUNNEL_DECAP_TABLE:IPINIP_TUNNEL

Config          Mellanox <= [202411]        Mellanox >= [202505]        Broadcom <= [201911]        Broadcom >= [202012]     Innovium               # noqa: E501
dscp_mode       uniform                     pipe                        pipe                        uniform                  pipe                   # noqa: E501
ecn_mode        standard                    copy_from_outer             copy_from_outer             copy_from_outer          copy_from_outer        # noqa: E501
ttl_mode        pipe                        pipe                        pipe                        pipe                     pipe                   # noqa: E501
'''
import json
import logging
from datetime import datetime
import time

import pytest
from jinja2 import Template
from netaddr import IPNetwork
from ansible.plugins.filter.core import to_bool

from tests.common.reboot import reboot                                      # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # noqa: F401
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses         # noqa: F401
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # noqa: F401
from tests.common.fixtures.ptfhost_utils import set_ptf_port_mapping_mode   # noqa: F401
from tests.common.fixtures.ptfhost_utils import ptf_test_port_map_active_active
from tests.common.fixtures.fib_utils import fib_info_files                  # noqa: F401
from tests.common.fixtures.fib_utils import single_fib_for_duts             # noqa: F401
from tests.ptf_runner import ptf_runner
from tests.common.dualtor.mux_simulator_control import mux_server_url       # noqa: F401
from tests.common.utilities import wait, setup_ferret
from tests.common.utilities import is_ipv6_only_topology
from tests.common.dualtor.dual_tor_common import active_active_ports                                # noqa: F401
from tests.common.dualtor.dual_tor_common import active_standby_ports                               # noqa: F401
from tests.common.dualtor.dual_tor_common import mux_config                                         # noqa: F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_random_side    # noqa: F401
from tests.common.dualtor.nic_simulator_control import mux_status_from_nic_simulator                # noqa: F401
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
def ip_ver(request, tbinfo):
    if is_ipv6_only_topology(tbinfo):
        return {
            "outer_ipv4": False,
            "outer_ipv6": to_bool(request.config.getoption("outer_ipv6")),
            "inner_ipv4": False,
            "inner_ipv6": to_bool(request.config.getoption("inner_ipv6")),
        }
    else:
        return {
            "outer_ipv4": to_bool(request.config.getoption("outer_ipv4")),
            "outer_ipv6": to_bool(request.config.getoption("outer_ipv6")),
            "inner_ipv4": to_bool(request.config.getoption("inner_ipv4")),
            "inner_ipv6": to_bool(request.config.getoption("inner_ipv6")),
        }


@pytest.fixture(scope='module')
def loopback_ips(active_active_ports, duthosts, duts_running_config_facts, tbinfo):             # noqa: F811
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
                   fib_info_files, single_fib_for_duts, supported_ttl_dscp_params):     # noqa: F811

    vxlan = supported_ttl_dscp_params['vxlan']
    is_multi_asic = duthosts[0].sonichost.is_multi_asic
    asic_type = duthosts[0].facts["asic_type"]

    setup_info = {
        "fib_info_files": fib_info_files[:3],  # Test at most 3 DUTs in case of multi-DUT
        "single_fib_for_duts": single_fib_for_duts,
        "ignore_ttl": True if is_multi_asic else False,
        "max_internal_hops": 3 if is_multi_asic else 0
    }

    setup_info.update(ip_ver)
    setup_info.update(loopback_ips)
    logger.info(json.dumps(setup_info, indent=2))

    if vxlan != "set_unset" or asic_type in ["cisco-8000"]:
        # Remove default tunnel
        remove_default_decap_cfg(duthosts)

    yield setup_info

    if vxlan != "set_unset" or asic_type in ["cisco-8000"]:
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


def launch_ptf_runner(
    ptfhost,
    tbinfo,
    duthosts,
    mux_server_url,  # noqa: F811
    duts_running_config_facts,
    duts_minigraph_facts,
    mux_status_from_nic_simulator,  # noqa: F811
    setup_info,
    outer_ipv4,
    outer_ipv6,
    inner_ipv4,
    inner_ipv6,
    ttl_mode,
    dscp_mode,
    asic_type,
):
    log_file = "/tmp/decap.{}.log".format(
        datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
    )
    ptf_runner(
        ptfhost,
        "ptftests",
        "IP_decap_test.DecapPacketTest",
        platform_dir="ptftests",
        params={
            "outer_ipv4": outer_ipv4,
            "outer_ipv6": outer_ipv6,
            "inner_ipv4": inner_ipv4,
            "inner_ipv6": inner_ipv6,
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
                ptfhost,
                tbinfo,
                duthosts,
                mux_server_url,
                duts_running_config_facts,
                duts_minigraph_facts,
                mux_status_from_nic_simulator(),
            ),
            "topo": tbinfo["topo"]["type"],
            "qos_remap_enabled": is_tunnel_qos_remap_enabled(duthosts[0]),
        },
        qlen=PTFRUNNER_QLEN,
        log_file=log_file,
        is_python3=True,
    )


def test_decap(tbinfo, duthosts, ptfhost, setup_teardown, mux_server_url,                                   # noqa: F811
               toggle_all_simulator_ports_to_random_side, supported_ttl_dscp_params, ip_ver, loopback_ips,  # noqa: F811
               duts_running_config_facts, duts_minigraph_facts, mux_status_from_nic_simulator):             # noqa: F811
    setup_info = setup_teardown
    asic_type = duthosts[0].facts["asic_type"]
    ecn_mode = "copy_from_outer"
    ttl_mode = supported_ttl_dscp_params['ttl']
    dscp_mode = supported_ttl_dscp_params['dscp']
    vxlan = supported_ttl_dscp_params['vxlan']

    cross_decap = True
    # Skip the IPv4inIPv6 and IPv6inIPv4. Run only the IPv4inIPv4 and IPv6inIPv6
    if asic_type in ["cisco-8000"] and duthosts[0].facts["platform"] in [
        "x86_64-8122_64ehf_o-r0",
        "x86_64-8122_64eh_o-r0",
    ]:
        cross_decap = False

    try:
        if vxlan == "set_unset":
            # checking decap after vxlan set/unset is to make sure that deletion of vxlan
            # tunnel and CPA ACLs won't negatively impact ipinip tunnel & decap mechanism
            # Hence a new decap config is not applied to the device in this case. This is
            # to avoid creating new tables and test ipinip decap with default loaded config
            simulate_vxlan_teardown(duthosts, ptfhost, tbinfo)
        if vxlan != "set_unset" or asic_type in ["cisco-8000"]:
            apply_decap_cfg(duthosts, ip_ver, loopback_ips, ttl_mode, dscp_mode, ecn_mode, 'SET')

        if 'dualtor' in tbinfo['topo']['name']:
            wait(30, 'Wait some time for mux active/standby state to be stable after toggled mux state')

        if cross_decap:
            # Run the IPv4inIPv6, IPv6inIPv4, IPv6inIPv6, IPv4inIPv4
            launch_ptf_runner(
                ptfhost=ptfhost,
                tbinfo=tbinfo,
                duthosts=duthosts,
                mux_server_url=mux_server_url,
                duts_running_config_facts=duts_running_config_facts,
                duts_minigraph_facts=duts_minigraph_facts,
                mux_status_from_nic_simulator=mux_status_from_nic_simulator,
                setup_info=setup_info,
                outer_ipv4=setup_info["outer_ipv4"],
                outer_ipv6=setup_info["outer_ipv6"],
                inner_ipv4=setup_info["inner_ipv4"],
                inner_ipv6=setup_info["inner_ipv6"],
                ttl_mode=ttl_mode,
                dscp_mode=dscp_mode,
                asic_type=asic_type,
            )
        else:
            # Run only the IPv6inIPv6
            launch_ptf_runner(
                ptfhost=ptfhost,
                tbinfo=tbinfo,
                duthosts=duthosts,
                mux_server_url=mux_server_url,
                duts_running_config_facts=duts_running_config_facts,
                duts_minigraph_facts=duts_minigraph_facts,
                mux_status_from_nic_simulator=mux_status_from_nic_simulator,
                setup_info=setup_info,
                outer_ipv4=setup_info["outer_ipv4"],
                outer_ipv6=False,
                inner_ipv4=setup_info["inner_ipv4"],
                inner_ipv6=False,
                ttl_mode=ttl_mode,
                dscp_mode=dscp_mode,
                asic_type=asic_type,
            )
            # Run only the IPv4inIPv4
            launch_ptf_runner(
                ptfhost=ptfhost,
                tbinfo=tbinfo,
                duthosts=duthosts,
                mux_server_url=mux_server_url,
                duts_running_config_facts=duts_running_config_facts,
                duts_minigraph_facts=duts_minigraph_facts,
                mux_status_from_nic_simulator=mux_status_from_nic_simulator,
                setup_info=setup_info,
                outer_ipv4=False,
                outer_ipv6=setup_info["outer_ipv6"],
                inner_ipv4=False,
                inner_ipv6=setup_info["inner_ipv6"],
                ttl_mode=ttl_mode,
                dscp_mode=dscp_mode,
                asic_type=asic_type,
            )

    finally:
        # Remove test decap configuration
        if vxlan != "set_unset" or asic_type in ["cisco-8000"]:
            # in vxlan setunset case the config was not applied, hence DEL is also not required
            apply_decap_cfg(duthosts, ip_ver, loopback_ips, ttl_mode, dscp_mode, ecn_mode, 'DEL')


# ---------------------------------------------------------------------------
# Warm-reboot decap test (Test Gap #16480)
# ---------------------------------------------------------------------------

TUNNEL_TABLE_KEY = "TUNNEL_DECAP_TABLE:TEST_IPINIP_V4_TUNNEL"
DECAP_RULE_FIELDS = ["dscp_mode", "ecn_mode", "ttl_mode", "tunnel_type"]


def _read_decap_rules(duthost):
    """Return default IPINIP_TUNNEL configuration from APP_DB as a dict."""
    rules = {}
    for field in DECAP_RULE_FIELDS:
        cmd = "redis-cli -n 0 hget '{}' '{}'".format(TUNNEL_TABLE_KEY, field)
        res = duthost.shell(cmd, module_ignore_errors=True)
        value = (res.get("stdout") or "").strip()
        if value:
            rules[field] = value
    return rules


def _verify_decap_rules(duthost, context=""):
    """Assert that TEST_IPINIP_V4_TUNNEL decap rules are present in APP_DB."""
    rules = _read_decap_rules(duthost)
    pytest_assert(
        rules.get("tunnel_type") == "IPINIP",
        "TEST_IPINIP_V4_TUNNEL not found in APP_DB on {} {}".format(duthost.hostname, context)
    )
    pytest_assert(
        "dscp_mode" in rules and "ecn_mode" in rules and "ttl_mode" in rules,
        "Incomplete decap rules on {}: {} {}".format(duthost.hostname, rules, context)
    )
    logger.info("Decap rules verified on %s: %s %s", duthost.hostname, rules, context)
    return rules


@pytest.mark.disable_loganalyzer
def test_decap_warmboot(tbinfo, duthosts, rand_one_dut_hostname, localhost, ptfhost,
                        mux_server_url,                                                 # noqa: F811
                        toggle_all_simulator_ports_to_random_side,                      # noqa: F811
                        supported_ttl_dscp_params, ip_ver, loopback_ips,
                        duts_running_config_facts, duts_minigraph_facts,
                        mux_status_from_nic_simulator):                                 # noqa: F811
    """Verify IPinIP decap rules and traffic survive warm-reboot.

    Test Gap: https://github.com/sonic-net/sonic-mgmt/issues/16480

    Unlike test_decap, this test manages its own decap config independently
    (does not use the setup_teardown fixture) to avoid interference with the
    module-scoped fixture that removes the default tunnel.

    Test steps:
        1. Apply test decap config and verify rules in APP_DB before warm-reboot
        2. Run IPv4-in-IPv4 traffic test to confirm decap works before warm-reboot
        3. Save config and perform warm-reboot
        4. Verify decap rules are unchanged in APP_DB after warm-reboot
        5. Run IPv4-in-IPv4 traffic test again to confirm decap still works
    """
    duthost = duthosts[rand_one_dut_hostname]
    asic_type = duthost.facts["asic_type"]
    ecn_mode = "copy_from_outer"
    ttl_mode = supported_ttl_dscp_params['ttl']
    dscp_mode = supported_ttl_dscp_params['dscp']
    vxlan = supported_ttl_dscp_params['vxlan']

    # Skip vxlan set_unset variant — not relevant for warmboot persistence test
    if vxlan == "set_unset":
        pytest.skip("Skipping warmboot test for vxlan set_unset variant")

    is_multi_asic = duthost.sonichost.is_multi_asic
    setup_info = {
        "fib_info_files": duts_running_config_facts,
        "single_fib_for_duts": False,
        "ignore_ttl": True if is_multi_asic else False,
        "max_internal_hops": 3 if is_multi_asic else 0,
        "outer_ipv4": True,
        "outer_ipv6": False,
        "inner_ipv4": True,
        "inner_ipv6": False,
    }

    # Build loopback IPs for this DUT
    lo_ips = []
    lo_ipv6s = []
    cfg_facts = duts_running_config_facts[duthost.hostname]
    lo_ip = None
    lo_ipv6 = None
    for addr in cfg_facts[0][1]["LOOPBACK_INTERFACE"]["Loopback0"]:
        ip = IPNetwork(addr).ip
        if ip.version == 4 and not lo_ip:
            lo_ip = str(ip)
        elif ip.version == 6 and not lo_ipv6:
            lo_ipv6 = str(ip)
    lo_ips.append(lo_ip)
    lo_ipv6s.append(lo_ipv6)
    local_loopback_ips = {'lo_ips': lo_ips, 'lo_ipv6s': lo_ipv6s}
    setup_info.update(local_loopback_ips)

    local_ip_ver = {"outer_ipv4": True, "outer_ipv6": False,
                    "inner_ipv4": True, "inner_ipv6": False}

    try:
        # Step 1: Apply test decap config and verify rules before warm-reboot
        logger.info("Step 1: Applying decap config and verifying rules before warm-reboot on %s",
                    duthost.hostname)
        apply_decap_cfg([duthost], local_ip_ver, local_loopback_ips, ttl_mode, dscp_mode, ecn_mode, 'SET')
        pre_reboot_rules = _verify_decap_rules(duthost, context="(before warm-reboot)")

        # Step 2: Verify decap traffic before warm-reboot
        logger.info("Step 2: Running decap traffic test before warm-reboot")
        if 'dualtor' in tbinfo['topo']['name']:
            wait(30, 'Wait for mux active/standby state to stabilize')

        launch_ptf_runner(
            ptfhost=ptfhost, tbinfo=tbinfo, duthosts=[duthost],
            mux_server_url=mux_server_url,
            duts_running_config_facts=duts_running_config_facts,
            duts_minigraph_facts=duts_minigraph_facts,
            mux_status_from_nic_simulator=mux_status_from_nic_simulator,
            setup_info=setup_info,
            outer_ipv4=True, outer_ipv6=False,
            inner_ipv4=True, inner_ipv6=False,
            ttl_mode=ttl_mode, dscp_mode=dscp_mode, asic_type=asic_type,
        )

        # Step 3: Save config and perform warm-reboot
        logger.info("Step 3: Performing warm-reboot on %s", duthost.hostname)
        duthost.shell('config save -y')
        reboot(duthost, localhost, reboot_type='warm', wait_warmboot_finalizer=True,
               safe_reboot=True, check_intf_up_ports=True, wait_for_bgp=True)
        logger.info("Warm-reboot completed on %s", duthost.hostname)

        # Step 4: Verify decap rules are unchanged after warm-reboot
        logger.info("Step 4: Verifying decap rules after warm-reboot on %s", duthost.hostname)
        post_reboot_rules = _verify_decap_rules(duthost, context="(after warm-reboot)")
        pytest_assert(
            pre_reboot_rules == post_reboot_rules,
            "Decap rules changed after warm-reboot on {}: before={}, after={}".format(
                duthost.hostname, pre_reboot_rules, post_reboot_rules)
        )
        logger.info("Decap rules match before and after warm-reboot on %s", duthost.hostname)

        # Step 5: Verify decap traffic after warm-reboot
        logger.info("Step 5: Running decap traffic test after warm-reboot")
        if 'dualtor' in tbinfo['topo']['name']:
            wait(30, 'Wait for mux active/standby state to stabilize after warm-reboot')

        launch_ptf_runner(
            ptfhost=ptfhost, tbinfo=tbinfo, duthosts=[duthost],
            mux_server_url=mux_server_url,
            duts_running_config_facts=duts_running_config_facts,
            duts_minigraph_facts=duts_minigraph_facts,
            mux_status_from_nic_simulator=mux_status_from_nic_simulator,
            setup_info=setup_info,
            outer_ipv4=True, outer_ipv6=False,
            inner_ipv4=True, inner_ipv6=False,
            ttl_mode=ttl_mode, dscp_mode=dscp_mode, asic_type=asic_type,
        )

        logger.info("test_decap_warmboot PASSED on %s", duthost.hostname)

    finally:
        apply_decap_cfg([duthost], local_ip_ver, local_loopback_ips, ttl_mode, dscp_mode, ecn_mode, 'DEL')
