import json
import logging
import pytest

from datetime import datetime
from tests.ptf_runner import ptf_runner
from vnet_constants import CLEANUP_KEY
from vnet_utils import generate_dut_config_files, safe_open_template, \
                       apply_dut_config_files, cleanup_dut_vnets, cleanup_vxlan_tunnels, cleanup_vnet_routes

from tests.common.fixtures.ptfhost_utils import remove_ip_addresses, change_mac_addresses, \
                                                copy_arp_responder_py, copy_ptftests_directory

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0"),
    pytest.mark.sanity_check(post_check=True),
    pytest.mark.asic("mellanox")
]

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
        "dut_mac": dut_facts["ansible_Ethernet0"]["macaddress"],
        "vnet_interfaces": vnet_config["vnet_intf_list"],
        "vnet_routes": vnet_config["vnet_route_list"] + vnet_config["vnet_subnet_routes"],
        "vnet_local_routes": vnet_config["vnet_local_routes"],
        "vnet_neighbors": vnet_config["vnet_nbr_list"],
        "vnet_peers": vnet_config["vnet_peer_list"]
    }
    ptfhost.copy(content=json.dumps(vnet_json, indent=2), dest="/tmp/vnet.json")

@pytest.fixture(scope="module")
def setup(duthost, ptfhost, minigraph_facts, vnet_config, vnet_test_params):
    """
    Prepares DUT and PTF hosts for testing

    Args:
        duthost: DUT host object
        ptfhost: PTF host object
        minigraph_facts: Minigraph facts
        vnet_config: Configuration file generated from templates/vnet_config.j2
        vnet_test_params: Dictionary holding vnet test parameters
    """

    dut_facts = duthost.setup(gather_subset="!all,!any,network", filter="ansible_Ethernet*")["ansible_facts"]

    prepare_ptf(ptfhost, minigraph_facts, dut_facts, vnet_config)

    generate_dut_config_files(duthost, minigraph_facts, vnet_test_params, vnet_config)

    return minigraph_facts

@pytest.fixture(params=["Disabled", "Enabled", "Cleanup"])
def vxlan_status(setup, request, duthost, vnet_test_params, vnet_config):
    """
    Paramterized fixture that tests the Disabled, Enabled, and Cleanup configs for VxLAN

    Args:
        setup: Pytest fixture that provides access to minigraph facts
        request: Contains the parameter (Disabled, Enabled, or Cleanup) for the current test iteration
        duthost: DUT host object

    Returns:
        A tuple containing the VxLAN status (True or False), and the test scenario (one of the pytest parameters)
    """

    vxlan_enabled = False
    if request.param == "Disabled":
        vxlan_enabled = False
    elif request.param == "Enabled":
        mg_facts = setup

        duthost.shell("sonic-clear fdb all")

        attached_vlan = mg_facts["minigraph_vlan_interfaces"][0]['attachto']
        member_to_remove = mg_facts["minigraph_vlans"][attached_vlan]['members'][0]
        duthost.shell("redis-cli -n 4 del \"VLAN_MEMBER|{}|{}\"".format(attached_vlan, member_to_remove))

        apply_dut_config_files(duthost, vnet_test_params)

        vxlan_enabled = True
    elif request.param == "Cleanup" and vnet_test_params[CLEANUP_KEY]:
        vxlan_enabled = True
        cleanup_vnet_routes(duthost, vnet_config)
        cleanup_dut_vnets(duthost, setup, vnet_config)
        cleanup_vxlan_tunnels(duthost, vnet_test_params)
    return vxlan_enabled, request.param


def test_vnet_vxlan(setup, vxlan_status, duthost, ptfhost, vnet_test_params, creds):
    """
    Test case for VNET VxLAN

    Args:
        setup: Pytest fixture that sets up PTF and DUT hosts
        vxlan_status: Parameterized pytest fixture used to test different VxLAN configurations
        duthost: DUT host object
        ptfhost: PTF host object
        vnet_test_params: Dictionary containing vnet test parameters
    """

    vxlan_enabled, scenario = vxlan_status

    logger.info("vxlan_enabled={}, scenario={}".format(vxlan_enabled, scenario))

    log_file = "/tmp/vnet-vxlan.Vxlan.{}.{}.log".format(scenario, datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
    ptf_params = {"vxlan_enabled": vxlan_enabled,
                  "config_file": '/tmp/vnet.json',
                  "sonic_admin_user": creds.get('sonicadmin_user'),
                  "sonic_admin_password": creds.get('sonicadmin_password'),
                  "dut_host": duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']}
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
