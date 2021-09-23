import json
import logging
import pytest

from datetime import datetime
from tests.ptf_runner import ptf_runner
from vnet_constants import CLEANUP_KEY, LOWER_BOUND_UDP_PORT_KEY, UPPER_BOUND_UDP_PORT_KEY
from vnet_utils import generate_dut_config_files, safe_open_template, \
                       apply_dut_config_files, cleanup_dut_vnets, cleanup_vxlan_tunnels, cleanup_vnet_routes

from tests.common.fixtures.ptfhost_utils import remove_ip_addresses, change_mac_addresses, \
                                                copy_arp_responder_py, copy_ptftests_directory
from tests.common.mellanox_data import is_mellanox_device as isMellanoxDevice

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.sanity_check(post_check=True),
    pytest.mark.asic("mellanox")
]

vlan_tagging_mode = ""

def get_vxlan_srcport_range_enabled(duthost):
    if not isMellanoxDevice(duthost):
	return False
    dut_platform = duthost.facts["platform"]
    dut_hwsku = duthost.facts["hwsku"]
    sai_profile = "/usr/share/sonic/device/%s/%s/sai.profile" % (dut_platform, dut_hwsku)
    cmd = "grep SAI_VXLAN_SRCPORT_RANGE_ENABLE {} | cut -d'=' -f2".format(sai_profile)
    vxlan_srcport_range_enabled = duthost.shell(cmd)["stdout"].strip() == "1"

    return vxlan_srcport_range_enabled

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

    ptfhost.copy(content=arp_responder_conf, dest="/etc/supervisor/conf.d/arp_responder.conf")

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
    ptfhost.copy(content=json.dumps(vnet_json, indent=2), dest="/tmp/vnet.json")

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

    prepare_ptf(ptfhost, minigraph_facts, dut_facts, vnet_config)

    generate_dut_config_files(duthost, minigraph_facts, vnet_test_params, vnet_config)

    return minigraph_facts

@pytest.fixture(params=["Disabled", "Enabled", "Cleanup"])
def vxlan_status(setup, request, duthosts, rand_one_dut_hostname, vnet_test_params, vnet_config):
    """
    Paramterized fixture that tests the Disabled, Enabled, and Cleanup configs for VxLAN

    Args:
        setup: Pytest fixture that provides access to minigraph facts
        request: Contains the parameter (Disabled, Enabled, or Cleanup) for the current test iteration
        duthost: DUT host object

    Returns:
        A tuple containing the VxLAN status (True or False), and the test scenario (one of the pytest parameters)
    """
    duthost = duthosts[rand_one_dut_hostname]
    mg_facts = setup
    attached_vlan = mg_facts["minigraph_vlan_interfaces"][0]['attachto']
    vlan_member = mg_facts["minigraph_vlans"][attached_vlan]['members'][0]
    global vlan_tagging_mode

    vxlan_enabled = False
    if request.param == "Disabled":
        vxlan_enabled = False
    elif request.param == "Enabled":
        duthost.shell("sonic-clear fdb all")
        result = duthost.shell("redis-cli -n 4 HGET \"VLAN_MEMBER|{}|{}\" tagging_mode ".format(attached_vlan, vlan_member))
        if result["stdout_lines"] is not None:
            vlan_tagging_mode = result["stdout_lines"][0]
            duthost.shell("redis-cli -n 4 del \"VLAN_MEMBER|{}|{}\"".format(attached_vlan, vlan_member))

        apply_dut_config_files(duthost, vnet_test_params)

        vxlan_enabled = True
    elif request.param == "Cleanup" and vnet_test_params[CLEANUP_KEY]:
        if vlan_tagging_mode != "":
            duthost.shell("redis-cli -n 4 hset \"VLAN_MEMBER|{}|{}\" tagging_mode {} ".format(attached_vlan, vlan_member, vlan_tagging_mode))

        vxlan_enabled = True
        cleanup_vnet_routes(duthost, vnet_config)
        cleanup_dut_vnets(duthost, setup, vnet_config)
        cleanup_vxlan_tunnels(duthost, vnet_test_params)
    return vxlan_enabled, request.param


def test_vnet_vxlan(setup, vxlan_status, duthosts, rand_one_dut_hostname, ptfhost, vnet_test_params, creds):
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
    vxlan_srcport_range_enabled =  get_vxlan_srcport_range_enabled(duthost)

    vxlan_enabled, scenario = vxlan_status

    logger.info("vxlan_enabled={}, scenario={}, vxlan_srcport_range_enabled={}".format(vxlan_enabled, scenario, vxlan_srcport_range_enabled))

    log_file = "/tmp/vnet-vxlan.Vxlan.{}.{}.log".format(scenario, datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
    ptf_params = {"vxlan_enabled": vxlan_enabled,
                  "config_file": '/tmp/vnet.json',
                  "sonic_admin_user": creds.get('sonicadmin_user'),
                  "sonic_admin_password": creds.get('sonicadmin_password'),
                  "dut_host": duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host'],
                  "vxlan_srcport_range_enabled": vxlan_srcport_range_enabled,
                  "lower_bound_port" : vnet_test_params[LOWER_BOUND_UDP_PORT_KEY],
                  "upper_bound_port" : vnet_test_params[UPPER_BOUND_UDP_PORT_KEY]
                  }
    if scenario == "Cleanup":
        ptf_params["routes_removed"] = True

    if scenario == "Cleanup" and not vnet_test_params[CLEANUP_KEY]:
        logger.info("Skipping cleanup")
        pytest.skip("Skip cleanup specified")

    logger.debug("Starting PTF runner")
    ptf_runner(ptfhost,
               "ptftests",
               "vnet_vxlan.VNET",
               platform_dir="ptftests",
               params=ptf_params,
               qlen=1000,
               log_file=log_file)
