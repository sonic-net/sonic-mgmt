import json
import logging
import re
import pytest

from datetime import datetime
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.ptf_runner import ptf_runner
from .vnet_constants import CLEANUP_KEY, VXLAN_UDP_SPORT_KEY,\
    VXLAN_UDP_SPORT_MASK_KEY, VXLAN_RANGE_ENABLE_KEY, DUT_VNET_NBR_JSON

from .vnet_utils import generate_dut_config_files, safe_open_template, \
    apply_dut_config_files, cleanup_dut_vnets, cleanup_vxlan_tunnels, cleanup_vnet_routes

from tests.common.fixtures.ptfhost_utils import remove_ip_addresses, change_mac_addresses, \
    copy_arp_responder_py, copy_ptftests_directory      # noqa F401
# Temporary work around to add skip_traffic_test fixture from duthost_utils
from tests.common.fixtures.duthost_utils import skip_traffic_test               # noqa F401
from tests.flow_counter.flow_counter_utils import RouteFlowCounterTestContext,\
    is_route_flow_counter_supported     # noqa F401
import tests.arp.test_wr_arp as test_wr_arp

from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.disable_loganalyzer
]

vlan_tagging_mode = ""


@pytest.fixture(scope='module', autouse=True)
def load_minigraph_after_test(rand_selected_dut):
    """
    Restore config_db as vnet with wram-reboot will write testing config into
    config_db.json
    """
    yield
    config_reload(rand_selected_dut, config_source='minigraph')


def prepare_ptf(ptfhost, mg_facts, dut_facts, vnet_config):
    """
    Prepares the PTF container for testing

    Generates and copies PTF required config files to the PTF host

    Args:
        ptfhost: PTF host object
        mg_facts: Minigraph facts
        dut_facts: DUT host facts
        vnet_config: Configuration file generated from templates/vnet_config.j2
    """

    logger.info("Preparing PTF host")

    arp_responder_conf = safe_open_template("templates/arp_responder.conf.j2") \
        .render(arp_responder_args="--conf /tmp/vnet_arpresponder.conf")

    ptfhost.copy(content=arp_responder_conf,
                 dest="/etc/supervisor/conf.d/arp_responder.conf")

    ptfhost.shell("supervisorctl reread")
    ptfhost.shell("supervisorctl update")

    logger.debug("VNet config is: " + str(vnet_config))
    vnet_json = {
        "minigraph_port_indices": mg_facts["minigraph_port_indices"],
        "minigraph_portchannel_interfaces": mg_facts["minigraph_portchannel_interfaces"],
        "minigraph_portchannels": mg_facts["minigraph_portchannels"],
        "minigraph_lo_interfaces": mg_facts["minigraph_lo_interfaces"],
        "minigraph_vlans": mg_facts["minigraph_vlans"],
        "minigraph_vlan_interfaces": mg_facts["minigraph_vlan_interfaces"],
        "dut_mac": dut_facts["router_mac"],
        "vnet_interfaces": vnet_config["vnet_intf_list"],
        "vnet_routes": vnet_config["vnet_route_list"] + vnet_config["vnet_subnet_routes"],
        "vnet_local_routes": vnet_config["vnet_local_routes"],
        "vnet_neighbors": vnet_config["vnet_nbr_list"],
        "vnet_peers": vnet_config["vnet_peer_list"]
    }
    ptfhost.copy(content=json.dumps(
        vnet_json, indent=2), dest="/tmp/vnet.json")

    return vnet_json


@pytest.fixture(scope="module")
def setup(duthosts, rand_one_dut_hostname, ptfhost, minigraph_facts, vnet_config, vnet_test_params):
    """
    Prepares DUT and PTF hosts for testing

    Args:
        duthost: DUT host object
        ptfhost: PTF host object
        minigraph_facts: Minigraph facts
        vnet_config: Configuration file generated from templates/vnet_config.j2
        vnet_test_params: Dictionary holding vnet test parameters
    """
    duthost = duthosts[rand_one_dut_hostname]

    dut_facts = duthost.facts

    vnet_json_data = prepare_ptf(
        ptfhost, minigraph_facts, dut_facts, vnet_config)

    generate_dut_config_files(duthost, minigraph_facts,
                              vnet_test_params, vnet_config)

    return minigraph_facts, vnet_json_data


@pytest.fixture(params=["Disabled", "Enabled", "WR_ARP", "Cleanup"])
def vxlan_status(setup, request, duthosts, rand_one_dut_hostname,
                 ptfhost, vnet_test_params, vnet_config, creds, tbinfo):
    """
    Paramterized fixture that tests the Disabled, Enabled, and Cleanup configs for VxLAN

    Args:
        setup: Pytest fixture that provides access to minigraph facts
        request: Contains the parameter (Disabled, Enabled, WR_ARP, or Cleanup) for the current test iteration
        duthost: DUT host object

    Returns:
        A tuple containing the VxLAN status (True or False), and the test scenario (one of the pytest parameters)
    """
    duthost = duthosts[rand_one_dut_hostname]
    mg_facts, _ = setup
    attached_vlan = mg_facts["minigraph_vlan_interfaces"][0]['attachto']
    vlan_member = mg_facts["minigraph_vlans"][attached_vlan]['members'][0]
    global vlan_tagging_mode

    num_routes = request.config.option.num_routes
    vxlan_enabled = False
    if request.param == "Disabled":
        vxlan_enabled = False
    elif request.param == "Enabled":
        duthost.shell("sonic-clear fdb all")
        result = duthost.shell(
            "redis-cli -n 4 HGET \"VLAN_MEMBER|{}|{}\" tagging_mode ".format(attached_vlan, vlan_member))
        if result["stdout_lines"] is not None:
            vlan_tagging_mode = result["stdout_lines"][0]
            duthost.shell(
                "redis-cli -n 4 del \"VLAN_MEMBER|{}|{}\"".format(attached_vlan, vlan_member))

        apply_dut_config_files(duthost, vnet_test_params, num_routes)
        # Check arp table status in a loop with delay.
        pytest_assert(wait_until(120, 20, 10, is_neigh_reachable,
                      duthost, vnet_config), "Neighbor is unreachable")
        vxlan_enabled = True
    elif request.param == "Cleanup" and vnet_test_params[CLEANUP_KEY]:
        if vlan_tagging_mode != "":
            duthost.shell("redis-cli -n 4 hset \"VLAN_MEMBER|{}|{}\" tagging_mode {} ".format(
                attached_vlan, vlan_member, vlan_tagging_mode))

        vxlan_enabled = True
        cleanup_vnet_routes(duthost, vnet_config, num_routes)
        cleanup_dut_vnets(duthost, vnet_config)
        cleanup_vxlan_tunnels(duthost, vnet_test_params)
    elif request.param == "WR_ARP":
        testWrArp = test_wr_arp.TestWrArp()
        testWrArp.Setup(duthost, ptfhost, tbinfo)
        try:
            test_wr_arp.TestWrArp.testWrArp(
                testWrArp, request, duthost, ptfhost, creds)
        finally:
            testWrArp.Teardown(duthost)

    return vxlan_enabled, request.param


def is_neigh_reachable(duthost, vnet_config):
    expected_neigh_list = vnet_config["vnet_nbr_list"]
    ip_neigh_cmd_output = duthost.shell("sudo ip -4 neigh")['stdout']
    for exp_neigh in expected_neigh_list:
        if exp_neigh["ifname"].startswith("Vlan"):
            regexp = '{}.*{}.*?REACHABLE'.format(
                exp_neigh["ip"], exp_neigh["ifname"])
            if re.search(regexp, ip_neigh_cmd_output):
                logger.info('Neigh {} {} is reachable'.format(
                    exp_neigh["ip"], exp_neigh["ifname"]))
            else:
                logger.error('Neigh {} {} is not reachable'.format(
                    exp_neigh["ip"], exp_neigh["ifname"]))
                logger.info("Reapplying config {}".format(DUT_VNET_NBR_JSON))
                duthost.shell(
                    "sudo config load {} -y".format(DUT_VNET_NBR_JSON))
                return False
        else:
            logger.warning('Neighbor expected but not found: {} {}'.format(
                exp_neigh["ip"], exp_neigh["ifname"]))
    return True


def test_vnet_vxlan(setup, vxlan_status, duthosts, rand_one_dut_hostname, ptfhost,
                    vnet_test_params, creds, is_route_flow_counter_supported, skip_traffic_test):  # noqa F811
    """
    Test case for VNET VxLAN

    Args:
        setup: Pytest fixture that sets up PTF and DUT hosts
        vxlan_status: Parameterized pytest fixture used to test different VxLAN configurations
        duthost: DUT host object
        ptfhost: PTF host object
        vnet_test_params: Dictionary containing vnet test parameters
    """
    duthost = duthosts[rand_one_dut_hostname]

    vxlan_enabled, scenario = vxlan_status
    _, vnet_json_data = setup

    logger.info("vxlan_enabled={}, scenario={}".format(
        vxlan_enabled, scenario))

    log_file = "/tmp/vnet-vxlan.Vxlan.{}.{}.log".format(
        scenario, datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
    ptf_params = {
        "vxlan_enabled": vxlan_enabled,
        "config_file": '/tmp/vnet.json',
        "sonic_admin_user": creds.get('sonicadmin_user'),
        "sonic_admin_password": creds.get('sonicadmin_password'),
        "dut_host": duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host'],
        "vxlan_udp_sport": vnet_test_params[VXLAN_UDP_SPORT_KEY],
        "vxlan_udp_sport_mask": vnet_test_params[VXLAN_UDP_SPORT_MASK_KEY],
        "vxlan_range_enable": vnet_test_params[VXLAN_RANGE_ENABLE_KEY]
        }

    if scenario == "Cleanup":
        ptf_params["routes_removed"] = True

    if scenario == "Cleanup" and not vnet_test_params[CLEANUP_KEY]:
        logger.info("Skipping cleanup")
        pytest.skip("Skip cleanup specified")

    if skip_traffic_test is True:
        logger.info("Skipping traffic test")
        return
    logger.debug("Starting PTF runner")
    if scenario == 'Enabled' and vxlan_enabled:
        route_pattern = 'Vnet1|100.1.1.1/32'
        expected_route_flow_packets = get_expected_flow_counter_packets_number(
            vnet_json_data)
        with RouteFlowCounterTestContext(is_route_flow_counter_supported, duthost, [route_pattern],
                                         {route_pattern: {'packets': expected_route_flow_packets}}):
            ptf_runner(ptfhost,
                       "ptftests",
                       "vnet_vxlan.VNET",
                       platform_dir="ptftests",
                       params=ptf_params,
                       qlen=1000,
                       log_file=log_file,
                       is_python3=True)
    else:
        ptf_runner(ptfhost,
                   "ptftests",
                   "vnet_vxlan.VNET",
                   platform_dir="ptftests",
                   params=ptf_params,
                   qlen=1000,
                   log_file=log_file,
                   is_python3=True)


def get_expected_flow_counter_packets_number(vnet_json_data):
    total_routes = 0
    for routes in vnet_json_data['vnet_routes']:
        for name, rt_list in list(routes.items()):
            total_routes += len(rt_list)
            for peers in vnet_json_data['vnet_peers']:
                for key, peer in list(peers.items()):
                    if name.split('_')[0] == key:
                        total_routes += len(rt_list)
            for l_routes in vnet_json_data['vnet_local_routes']:
                for l_name, l_rt_list in list(l_routes.items()):
                    if name == l_name:
                        total_routes += len(l_rt_list)

    max_routes_wo_scaling = 1000
    packets_without_scale = 3
    packets_with_scale = 2
    expected_route_flow_packets = \
        packets_without_scale if total_routes <= max_routes_wo_scaling else packets_with_scale

    return expected_route_flow_packets
