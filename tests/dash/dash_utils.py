import logging
from os import path
from time import sleep

import ptf.packet as scapy
import ptf.testutils as testutils
import pytest
import json
from jinja2 import Template

from constants import TEMPLATE_DIR, VXLAN_UDP_BASE_SRC_PORT, VXLAN_UDP_SRC_PORT_MASK
from tests.common import config_reload


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


def render_template(template_name, *template_args, **template_kwargs):
    """
    Renders a template with the given arguments and copies it to the host

    Args:
        template_name: A template inside the "templates" folder (without the preceding "templates/")
        *template_args: Any arguments to be passed to j2 during rendering
        **template_kwargs: Any keyword arguments to be passed to j2 during rendering
    """

    combined_args = combine_dicts(*template_args)

    return safe_open_template(path.join(TEMPLATE_DIR, template_name)).render(combined_args, **template_kwargs)


def apply_swssconfig_file(duthost, file_path):
    """
    Copies config file from the DUT host to the SWSS docker and applies them with swssconfig

    Args:
        duthost: DUT host object
        file: Path to config file on the host
    """
    logger.info("Applying config files on DUT")
    file_name = path.basename(file_path)

    duthost.shell("docker cp {}  swss:/{}".format(file_path, file_name))
    duthost.shell("docker exec swss sh -c \"swssconfig /{}\"".format(file_name))
    sleep(5)


def verify_tunnel_packets(ptfadapter, ports, exp_dpu_to_vm_pkt, tunnel_endpoint_counts):
    timeout = 1
    if isinstance(ports, list):
        target_ports = ports
    else:
        target_ports = [ports]

    result = testutils.dp_poll(ptfadapter, timeout=timeout, exp_pkt=exp_dpu_to_vm_pkt)
    if isinstance(result, ptfadapter.dataplane.PollSuccess):
        pkt_repr = scapy.Ether(result.packet)
        if result.port in target_ports:
            if pkt_repr["IP"].dst in tunnel_endpoint_counts:
                tunnel_endpoint_counts[pkt_repr["IP"].dst] += 1
                logging.debug(
                    f"Packet sent to tunnel endpoint {pkt_repr['IP'].dst} matches:\
                        \n{result.format()} \nExpected:\n{exp_dpu_to_vm_pkt}"
                )
                return
            else:
                pytest.fail(
                    f"Received packet has unexpected dst IP {pkt_repr['IP'].dst}, \
                        expected one of {tunnel_endpoint_counts.keys()} \
                        \n{result.format()} \nExpected:\n{exp_dpu_to_vm_pkt}"
                )
        else:
            pytest.fail(f"Got expected packet on unexpected port {result.port}: {pkt_repr}")
    pytest.fail(f"DP poll failed:\n{result.format()}")


def set_vxlan_udp_sport_range_util(dpuhosts, dpu_index):
    """
    Configure VXLAN UDP source port range in dpu configuration.

    """
    dpuhost = dpuhosts[dpu_index]
    vxlan_sport_config = [
        {
            "SWITCH_TABLE:switch": {
                "vxlan_sport": VXLAN_UDP_BASE_SRC_PORT,
                "vxlan_mask": VXLAN_UDP_SRC_PORT_MASK
            },
            "OP": "SET"
        }
    ]

    logger.info(f"Setting VXLAN source port config: {vxlan_sport_config}")
    config_path = "/tmp/vxlan_sport_config.json"
    dpuhost.copy(content=json.dumps(vxlan_sport_config, indent=4), dest=config_path, verbose=False)
    apply_swssconfig_file(dpuhost, config_path)
    if 'pensando' in dpuhost.facts['asic_type']:
        logger.warning("Applying Pensando DPU VXLAN sport workaround")
        dpuhost.shell("pdsctl debug update device --vxlan-port 4789 --vxlan-src-ports 5120-5247")
    yield
    if str(VXLAN_UDP_BASE_SRC_PORT) in dpuhost.shell("redis-cli -n 0 hget SWITCH_TABLE:switch vxlan_sport")['stdout']:
        config_reload(dpuhost, safe_reload=True, yang_validate=False)
