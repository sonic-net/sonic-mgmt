import json
import logging
import yaml

from jinja2 import Template
from os import path
from time import sleep
from vnet_constants import *

logger = logging.getLogger(__name__)

def combine_dicts(*args):
    combined_args = {}
    args_iter = iter(args)
    try:
        combined_args = next(args_iter).copy()
        for arg in args_iter:
            combined_args.update(arg)
    except StopIteration:
        combined_args= {}
    
    return combined_args

def render_template_to_host(template_name, host, dest_file, *template_args, **template_kwargs):
    """
    @summary: Renders a template with the given arguments and copies it to the host
    @param template_name: A template inside the "templates" folder (without the preceding "templates/")
    @param host: The host device to copy the rendered template to
    @param dest_file: The location on the host to copy the rendered template to
    @param *template_args: Any arguments to be passed to j2 during rendering
    @param **template_kwargs: Any keyword arguments to be passed to j2 during rendering
    """

    combined_template_args = combine_dicts(*template_args)

    rendered = Template(open(path.join("templates",template_name)).read()) \
                        .render(combined_template_args, **template_kwargs)

    host.copy(content=rendered, dest=dest_file)

def generate_dut_config_files(duthost, mg_facts, vnet_test_params, vnet_config):
    """
    @summary: Generate VNET and VXLAN config files and copy them to DUT
    @param duthost: DUT host object
    @param mg_facts: Minigraph facts
    """

    logger.info("Generating config files and copying to DUT")

    vnet_switch_config = [{
        "SWITCH_TABLE:switch": {
            "vxlan_port": VXLAN_PORT,
            "vxlan_router_mac": VXLAN_MAC
        },
        "OP": "SET"
    }]

    duthost.copy(content=json.dumps(vnet_switch_config, indent=4), dest=DUT_VNET_SWITCH_CONFIG)


    render_template_to_host("vnet_vxlan.j2", duthost, DUT_VNET_CONF, vnet_config, mg_facts, vnet_test_params)
    render_template_to_host("vnet_interface.j2", duthost, DUT_VNET_INTF_CONFIG, vnet_config)
    render_template_to_host("vnet_nbr.j2", duthost, DUT_VNET_NBR_JSON, vnet_config)
    render_template_to_host("vnet_routes.j2", duthost, DUT_VNET_ROUTE_CONFIG, vnet_config, op="SET")

def apply_dut_config_files(duthost):
    """
    @summary: Applies config files on disk
    @param duthost: DUT host object
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

def cleanup_dut_vnets(duthost, mg_facts, vnet_config):
    """
    @summary: Removes all VNET information from DUT
    @param duthost: DUT host object
    @param mg_factS: Minigraph facts
    """
    logger.info("Removing VNET information from DUT")

    for intf in vnet_config['vlan_intf_list']:
        duthost.shell("docker exec -i database redis-cli -n 4 del \"VLAN_INTERFACE|{}|{}\"".format(intf['ifname'], intf['ip']))

    for intf in vnet_config['vlan_intf_list']:
        duthost.shell("docker exec -i database redis-cli -n 4 del \"VLAN_INTERFACE|{}\"".format(intf['ifname']))
    
    for vnet in vnet_config['vnet_id_list']:
        duthost.shell("docker exec -i database redis-cli -n 4 del \"VNET|{}\"".format(vnet))

def cleanup_vxlan_tunnels(duthost, vnet_test_params):
    """
    @summary: Removes all VxLAN tunnels from DUT
    @param duthost: DUT host object
    """
    logger.info("Removing VxLAN tunnel from DUT")
    tunnels = ["tunnel_v4"]
    if vnet_test_params[IPV6_VXLAN_TEST_KEY]:
        tunnels.append("tunnel_v6")

    for tunnel in tunnels:
        duthost.shell("docker exec -i database redis-cli -n 4 del \"VXLAN_TUNNEL|{}\"".format(tunnel))
