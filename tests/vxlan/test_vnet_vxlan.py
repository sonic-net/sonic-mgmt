import json
import logging
import pytest
import yaml

from datetime import datetime
from jinja2 import Template
from netaddr import IPAddress
from os import path
from time import sleep
from tests.ptf_runner import ptf_runner
from vnet_config import CLEANUP_KEY
from vnet_utils import *

from tests.common.fixtures.ptfhost_utils import remove_ip_addresses, change_mac_addresses, \
                                                copy_arp_responder_py, copy_ptftests_directory

logger = logging.getLogger(__name__)

def prepare_ptf(ptfhost, mg_facts, dut_facts):
    """
    @summary: Prepare the PTF docker container for testing
    @param ptfhost: Reference to the PTF container
    @param mg_facts: Minigraph facts
    @param dut_facts: DUT host facts
    """
    logger.info("Preparing PTF host")

    arp_responder_conf = Template(open("templates/arp_responder.conf.j2").read()) \
                            .render(arp_responder_args="--conf /tmp/vnet_arpresponder.conf")
    ptfhost.copy(content=arp_responder_conf, dest="/etc/supervisor/conf.d/arp_responder.conf")

    ptfhost.shell("supervisorctl reread")
    ptfhost.shell("supervisorctl update")

    logger.debug("VNet config is: " + str(vc.VNET_CONFIG))
    vnet_json = {
        "minigraph_port_indices": mg_facts["minigraph_port_indices"],
        "minigraph_portchannel_interfaces": mg_facts["minigraph_portchannel_interfaces"],
        "minigraph_portchannels": mg_facts["minigraph_portchannels"],
        "minigraph_lo_interfaces": mg_facts["minigraph_lo_interfaces"],
        "minigraph_vlans": mg_facts["minigraph_vlans"],
        "minigraph_vlan_interfaces": mg_facts["minigraph_vlan_interfaces"],
        "dut_mac": dut_facts["ansible_Ethernet0"]["macaddress"],
        "vnet_interfaces": vc.VNET_CONFIG["vnet_intf_list"],
        "vnet_routes": vc.VNET_CONFIG["vnet_route_list"],
        "vnet_local_routes": vc.VNET_CONFIG["vnet_local_routes"],
        "vnet_neighbors": vc.VNET_CONFIG["vnet_nbr_list"],
        "vnet_peers": vc.VNET_CONFIG["vnet_peer_list"]
    }
    ptfhost.copy(content=json.dumps(vnet_json, indent=2), dest="/tmp/vnet.json")

@pytest.fixture(scope="module")
def setup(duthost, ptfhost, vnet_test_params, scaled_vnet_params):
    """
    @summary: Fixture to prepare the DUT and PTF hosts for testing
    @param duthost: DUT host object
    @param ptfhost: PTF host object
    @param num_vnet: Number of VNETs
    @param num_routes: Number of routes
    @param num_endpoints: Number of endpoints
    @param skip_cleanup: Determines if cleanup is skipped or not
    """
    minigraph_facts = duthost.minigraph_facts(host=duthost.hostname)["ansible_facts"]
    dut_facts = duthost.setup(gather_subset="!all,!any,network", filter="ansible_Ethernet*")["ansible_facts"]

    gen_vnet_config(minigraph_facts, vnet_test_params, scaled_vnet_params)

    prepare_ptf(ptfhost, minigraph_facts, dut_facts)

    generate_dut_config_files(duthost, minigraph_facts, vnet_test_params)

    yield minigraph_facts 

@pytest.fixture(params=["Disabled", "Enabled", "Cleanup"])
def vxlan_status(setup, request, duthost, vnet_test_params):
    """
    @summary: Paramterized fixture that tests the Disabled, Enabled, and Cleanup configs for VxLAN
    @param setup: Pytest fixture that provides access to minigraph facts
    @param request: Contains the parameter (Disabled, Enabled, or Cleanup) for the current test iteration
    @param duthost: DUT host object
    @param returns: VxLAN status, and the test scenario
    """
    vxlan_enabled = False
    if request.param == "Disabled":
        vxlan_enabled = False
    elif request.param == "Enabled":
        mg_facts = setup

        duthost.shell("sonic-clear fdb all")
        
        attach_to = mg_facts["minigraph_vlan_interfaces"][0]['attachto']
        member_to_remove = mg_facts["minigraph_vlans"][attach_to]['members'][0]
        duthost.shell("docker exec -i database redis-cli -n 4 del \"VLAN_MEMBER|{}|{}\"".format(attach_to, member_to_remove))

        apply_dut_config_files(duthost) 

        vxlan_enabled = True
    elif request.param == "Cleanup" and vnet_test_params[CLEANUP_KEY]:
        vxlan_enabled = True
        render_template_to_host("vnet_routes.j2", duthost, vc.DUT_VNET_ROUTE_CONFIG, vc.VNET_CONFIG, op="DEL")
        duthost.shell("docker cp {} swss:/vnet.route.json".format(vc.DUT_VNET_ROUTE_CONFIG))
        duthost.shell("docker exec swss sh -c \"swssconfig /vnet.route.json\"")
        sleep(3)
        cleanup_dut_vnets(duthost, setup)
        cleanup_vxlan_tunnels(duthost, vnet_test_params)
    return vxlan_enabled, request.param


def test_vnet_vxlan(setup, vxlan_status, duthost, ptfhost, vnet_test_params):
    """
    @summary: Test case for VNET VxLAN
    @param setup: Pytest fixture that sets up PTF and DUT hosts and yields minigraph facts
    @param vxlan_status: Parameterized pytest fixture used to test different VxLAN configurations
    @param duthost: DUT host object
    @param ptfhost: PTF host object
    """
    vxlan_enabled, scenario = vxlan_status

    host_vars = duthost.host.options['variable_manager']._hostvars[duthost.hostname]
    inventory = host_vars['inventory_file'].split('/')[-1]
    secrets = duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']

    logger.info("vxlan_enabled={}, scenario={}".format(vxlan_enabled, scenario))

    log_file = "/tmp/vnet-vxlan.Vxlan.{}.{}.log".format(scenario, datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
    ptf_params = {"vxlan_enabled": vxlan_enabled,
                  "config_file": '/tmp/vnet.json',
                  "sonic_admin_user": secrets[inventory]['sonicadmin_user'],
                  "sonic_admin_password": secrets[inventory]['sonicadmin_password'],
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
