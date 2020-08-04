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

from tests.common.fixtures.ptfhost_utils import remove_ip_addresses, change_mac_addresses, \
                                                copy_arp_responder_py, copy_ptftests_directory

logger = logging.getLogger(__name__)

IPV6_VXLAN_TEST = False
VXLAN_PORT = 13330
VXLAN_MAC = "00:aa:bb:cc:78:9a"
APPLY_NEW_CONFIG = True
CLEANUP = True
DUT_VNET_SWITCH_CONFIG = "/tmp/vnet.switch.json"
DUT_VNET_CONF = "/tmp/vnet.conf.json"
DUT_VNET_ROUTE_CONFIG = "/tmp/vnet.route.json"
DUT_VNET_INTF_CONFIG = "/tmp/vnet.intf.json"
DUT_VNET_NBR_JSON = "/tmp/vnet.nbr.json"

def get_vnet_config(mg_facts):
    """
    @summary: Returns the VNET configuration
    @param mg_facts: Minigraph facts
    @returns: A Python dictionary containing the VNET configuration
    """
    logger.info("Generate VNet configuration")
    return yaml.safe_load(Template(open("templates/vnet_config.j2").read())
                                    .render(mg_facts, ipv6_vxlan_test=IPV6_VXLAN_TEST))

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

    vnet_config = get_vnet_config(mg_facts)
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
        "vnet_routes": vnet_config["vnet_route_list"],
        "vnet_local_routes": vnet_config["vnet_local_routes"],
        "vnet_neighbors": vnet_config["vnet_nbr_list"],
        "vnet_peers": vnet_config["vnet_peer_list"]
    }
    ptfhost.copy(content=json.dumps(vnet_json, indent=2), dest="/tmp/vnet.json")

def render_template_to_host(template_name, host, dest_file, *template_args, **template_kwargs):
    """
    @summary: Renders a template with the given arguments and copies it to the host
    @param template_name: A template inside the "templates" folder (without the preceding "templates/")
    @param host: The host device to copy the rendered template to
    @param dest_file: The location on the host to copy the rendered template to
    @param *template_args: Any arguments to be passed to j2 during rendering
    @param **template_kwargs: Any keyword arguments to be passed to j2 during rendering
    """
    # Combine all dictionaries given in template_args
    template_args_iter = iter(template_args)
    try:
        combined_template_args = next(template_args_iter).copy()
        for arg in template_args_iter:
            combined_template_args.update(arg)
    except StopIteration:
        combined_template_args = {}

    rendered = Template(open(path.join("templates",template_name)).read()) \
                        .render(combined_template_args, **template_kwargs)
    host.copy(content=json.dumps(rendered, indent=2), dest=dest_file)

def generate_dut_config_files(duthost, mg_facts):
    """
    @summary: Generate VNET and VXLAN config files and copy them to DUT.
    @param duthost: DUT host object
    @param mg_facts: Minigraph facts
    """
    logger.info("Generating config files and copying to DUT")

    vnet_switch_config = {
        "SWITCH_TABLE:switch": {
            "vxlan_port": VXLAN_PORT,
            "vxlan_router_mac": VXLAN_MAC
        },
        "OP": "SET"
    }

    duthost.copy(content=json.dumps(vnet_switch_config, indent=2), dest=DUT_VNET_SWITCH_CONFIG)

    vnet_config = get_vnet_config(mg_facts)

    render_template_to_host("vnet_vxlan.j2", duthost, DUT_VNET_CONF, vnet_config, mg_facts, ipv6_vxlan_test=IPV6_VXLAN_TEST)
    render_template_to_host("vnet_interface.j2", duthost, DUT_VNET_INTF_CONFIG, vnet_config)
    render_template_to_host("vnet_nbr.j2", duthost, DUT_VNET_NBR_JSON, vnet_config)
    render_template_to_host("vnet_routes.j2", duthost, DUT_VNET_ROUTE_CONFIG, vnet_config, op="SET")

def apply_dut_config_files(duthost):
    """
    @summary: Applies config files on disk
    """
    logger.info("Applying config files on DUT")

    config_files = ["/tmp/vnet.intf.json", "/tmp/vnet.nbr.json"]
    if APPLY_NEW_CONFIG:
        config_files.append("/tmp/vnet.conf.json")

    for config in config_files:
        duthost.shell("sonic-cfggen -j {} --write-to-db".format(config))
        sleep(3)

    duthost.shell("docker cp {} swss:/vnet.route.json".format(DUT_VNET_ROUTE_CONFIG))
    duthost.shell("docker cp {} swss:/vnet.switch.json".format(DUT_VNET_SWITCH_CONFIG))
    if APPLY_NEW_CONFIG:
        duthost.shell("docker exec swss sh -c \"swssconfig /vnet.switch.json\"")
        duthost.shell("docker exec swss sh -c \"swssconfig /vnet.route.json\"")
        sleep(3)

def cleanup_dut_vnets(duthost, mg_facts):
    """
    @summary: Removes all VNET information from DUT
    @param duthost: DUT host object
    @param mg_factS: Minigraph facts
    """
    logger.info("Removing VNET information from DUT")

    vnet_config = get_vnet_config(mg_facts)
    for intf in vnet_config['vlan_intf_list']:
        duthost.shell("docker exec -i database redis-cli -n 4 del \"VLAN_INTERFACE|{}|{}\"".format(intf['ifname'], intf['ip']))

    for intf in vnet_config['vlan_intf_list']:
        duthost.shell("docker exec -i database redis-cli -n 4 del \"VLAN_INTERFACE|{}\"".format(intf['ifname']))
    
    for vnet in vnet_config['vnet_id_list']:
        duthost.shell("docker exec -i database redis-cli -n 4 del \"VNET|{}\"".format(vnet))

@pytest.fixture(scope="module")
def setup(duthost, ptfhost):
    """
    @summary: Fixture to prepare the DUT and PTF hosts for testing
    @param duthost: DUT host object
    @param ptfhost: PTF host object
    """
    minigraph_facts = duthost.minigraph_facts(host=duthost.hostname)["ansible_facts"]
    dut_facts = duthost.setup(gather_subset="!all,!any,network", filter="ansible_Ethernet*")["ansible_facts"]


    prepare_ptf(ptfhost, minigraph_facts, dut_facts)

    generate_dut_config_files(duthost, minigraph_facts)

    yield minigraph_facts 

@pytest.fixture(params=["Disabled", "Enabled", "Cleanup"])
def vxlan_status(setup, request, duthost):
    """
    @summary: Paramterized fixture that tests the Disabled, Enabled, and Cleanup configs for VxLAN
    @param setup: Pytest fixture that provides access to minigraph facts
    @param request: Contains the parameter (Disabled, Enabled, or Cleanup) for the current test iteration
    @param duthost: DUT host object
    """
    vxlan_enabled = False
    if request.param == "Disabled":
        vxlan_enabled = False
    elif request.param == "Enabled":
        mg_facts = setup

        duthost.shell("sonic-clear fdb all")
        
        attach_to = mg_facts["minigraph_vlan_interfaces"][0]['attachto']
        member_to_remove = mg_facts["minigraph_vlans"][attach_to]['members'][0]
        duthost.shell("docker exec -i database redis-cli -n 4 del \"VLAN_MEMBER|{}|{}".format(attach_to, member_to_remove))

        apply_dut_config_files(duthost) 

        vxlan_enabled = True
    elif request.param == "Cleanup" and CLEANUP:
        vxlan_enabled = True
        render_template_to_host("vnet_routes.j2", duthost, DUT_VNET_ROUTE_CONFIG, get_vnet_config(setup), op="DEL")
        duthost.shell("docker cp {} swss:/vnet.route.json".format(DUT_VNET_ROUTE_CONFIG))
        duthost.shell("docker exec swss sh -c \"swssconfig /vnet.route.json\"")
        sleep(3)
        cleanup_dut_vnets(duthost, setup)
    return vxlan_enabled, request.param


def test_vnet_vxlan(setup, vxlan_status, duthost, ptfhost):
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
                  "config_file": '/tmp/vxlan_decap.json',
                  "sonic_admin_user": secrets[inventory]['sonicadmin_user'],
                  "sonic_admin_password": secrets[inventory]['sonicadmin_password'],
                  "dut_host": duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']}
    if scenario == "Cleanup":
        ptf_params["routes_removed"] = True
    
    if scenario == "Cleanup" and not CLEANUP:
        return None

    ptf_runner(ptfhost,
               "ptftests",
               "vnet_vxlan.VNET",
               platform_dir="ptftests",
               params=ptf_params,
               qlen=1000,
               log_file=log_file)
