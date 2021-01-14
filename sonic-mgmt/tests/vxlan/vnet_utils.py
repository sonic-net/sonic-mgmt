import json
import logging

from jinja2 import Template
from os import path
from time import sleep
from vnet_constants import *
from vnet_constants import VXLAN_PORT, VXLAN_MAC

logger = logging.getLogger(__name__)

def safe_open_template(template_path):
    """
    Safely loads Jinja2 template from given path

    Note:
        All Jinja2 templates should be accessed with this method to ensure proper garbage disposal

    Args:
        template_path: String containing the location of the template file to be opened

    Returns:
        A Jinja2 Template object read from the provided file
    """

    with open(template_path) as template_file:
        return Template(template_file.read())

def combine_dicts(*args):
    """
    Combines multiple Python dictionaries into a single dictionary

    Used primarily to pass arguments contained in multiple dictionaries to the `render()` method for Jinja2 templates

    Args:
        *args: The dictionaries to be combined

    Returns:
        A single Python dictionary containing the key/value pairs of all the input dictionaries
    """

    combined_args = {}

    for arg in args:
        combined_args.update(arg)

    return combined_args

def render_template_to_host(template_name, host, dest_file, *template_args, **template_kwargs):
    """
    Renders a template with the given arguments and copies it to the host

    Args:
        template_name: A template inside the "templates" folder (without the preceding "templates/")
        host: The host device to copy the rendered template to (either a PTF or DUT host object)
        dest_file: The location on the host to copy the rendered template to
        *template_args: Any arguments to be passed to j2 during rendering
        **template_kwargs: Any keyword arguments to be passed to j2 during rendering
    """

    combined_args = combine_dicts(*template_args)

    rendered = safe_open_template(path.join(TEMPLATE_DIR, template_name)).render(combined_args, **template_kwargs)

    host.copy(content=rendered, dest=dest_file)

def generate_dut_config_files(duthost, mg_facts, vnet_test_params, vnet_config):
    """
    Generate VNET and VXLAN config files and copy them to DUT

    Note:
        Does not actually apply any of these new configs

    Args
        duthost: DUT host object
        mg_facts: Minigraph facts
        vnet_test_params: Dictionary holding vnet test parameters
        vnet_config: Configuration generated from templates/vnet_config.j2
    """

    logger.info("Generating config files and copying to DUT")

    vnet_switch_config = [{
        "SWITCH_TABLE:switch": {
            "vxlan_port": VXLAN_PORT,
            "vxlan_router_mac": VXLAN_MAC
        },
        "OP": "SET"
    }]

    duthost.copy(content=json.dumps(vnet_switch_config, indent=4), dest=DUT_VNET_SWITCH_JSON)

    render_template_to_host("vnet_vxlan.j2", duthost, DUT_VNET_CONF_JSON, vnet_config, mg_facts, vnet_test_params)
    render_template_to_host("vnet_interface.j2", duthost, DUT_VNET_INTF_JSON, vnet_config)
    render_template_to_host("vnet_nbr.j2", duthost, DUT_VNET_NBR_JSON, vnet_config)
    render_template_to_host("vnet_routes.j2", duthost, DUT_VNET_ROUTE_JSON, vnet_config, op="SET")

def apply_dut_config_files(duthost, vnet_test_params):
    """
    Applies config files that are stored on the given DUT

    Args:
        duthost: DUT host object
    """
    if vnet_test_params[APPLY_NEW_CONFIG_KEY]:
        logger.info("Applying config files on DUT")

        config_files = [DUT_VNET_INTF_JSON, DUT_VNET_NBR_JSON, DUT_VNET_CONF_JSON]
        for config in config_files:
            duthost.shell("sonic-cfggen -j {} --write-to-db".format(config))
            sleep(3)

        duthost.shell("docker cp {} swss:/vnet.route.json".format(DUT_VNET_ROUTE_JSON))
        duthost.shell("docker cp {} swss:/vnet.switch.json".format(DUT_VNET_SWITCH_JSON))
        duthost.shell("docker exec swss sh -c \"swssconfig /vnet.switch.json\"")
        duthost.shell("docker exec swss sh -c \"swssconfig /vnet.route.json\"")
        sleep(3)
    else:
        logger.info("Skip applying config files on DUT")

def cleanup_dut_vnets(duthost, mg_facts, vnet_config):
    """
    Removes all VNET information from DUT

    Args:
        duthost: DUT host object
        mg_facts: Minigraph facts
        vnet_config: Configuration generated from templates/vnet_config.j2
    """
    logger.info("Removing VNET information from DUT")

    duthost.shell("sonic-clear fdb all")

    for intf in vnet_config['vlan_intf_list']:
        duthost.shell("redis-cli -n 4 del \"VLAN_INTERFACE|{}|{}\"".format(intf['ifname'], intf['ip']))

    for intf in vnet_config['vlan_intf_list']:
        duthost.shell("redis-cli -n 4 del \"VLAN_INTERFACE|{}\"".format(intf['ifname']))

    for intf in vnet_config['vlan_intf_list']:
        duthost.shell("redis-cli -n 4 del \"VLAN_MEMBER|{}|{}\"".format(intf['ifname'], intf['port']))

    for intf in vnet_config['vlan_intf_list']:
        duthost.shell("redis-cli -n 4 del \"VLAN|{}\"".format(intf['ifname']))

    for vnet in vnet_config['vnet_id_list']:
        duthost.shell("redis-cli -n 4 del \"VNET|{}\"".format(vnet))

    for intf in vnet_config['intf_list']:
        duthost.shell("redis-cli -n 4 del \"INTERFACE|{}|{}\"".format(intf['ifname'], intf['ip']))
        duthost.shell("redis-cli -n 4 del \"INTERFACE|{}\"".format(intf['ifname']))

def cleanup_vxlan_tunnels(duthost, vnet_test_params):
    """
    Removes all VxLAN tunnels from DUT

    Args:
        duthost: DUT host object
        vnet_test_params: Dictionary holding vnet test parameters
    """
    logger.info("Removing VxLAN tunnel from DUT")
    tunnels = ["tunnel_v4"]
    if vnet_test_params[IPV6_VXLAN_TEST_KEY]:
        tunnels.append("tunnel_v6")

    for tunnel in tunnels:
        duthost.shell("redis-cli -n 4 del \"VXLAN_TUNNEL|{}\"".format(tunnel))

def cleanup_vnet_routes(duthost, vnet_config):
    """
    Generates, pushes, and applies VNET route config to clear routes set during test

    Args:
        duthost: DUT host object
        vnet_config: VNET configuration generated from templates/vnet_config.j2
    """

    render_template_to_host("vnet_routes.j2", duthost, DUT_VNET_ROUTE_JSON, vnet_config, op="DEL")
    duthost.shell("docker cp {} swss:/vnet.route.json".format(DUT_VNET_ROUTE_JSON))
    duthost.shell("docker exec swss sh -c \"swssconfig /vnet.route.json\"")
    sleep(3)
