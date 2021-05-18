import json
import logging
from datetime import datetime
from time import sleep

import pytest
from jinja2 import Template
from netaddr import IPAddress
from vnet_constants import DUT_VXLAN_PORT_JSON
from vnet_utils import render_template_to_host

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py     # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses       # lgtm[py/unused-import]
from tests.ptf_runner import ptf_runner

pytestmark = [
    pytest.mark.topology('t0')
]

logger = logging.getLogger(__name__)

VTEP2_IP = "8.8.8.8"
VNI_BASE = 336
COUNT = 10


def prepare_ptf(ptfhost, mg_facts, duthost):
    """Prepare arp responder configuration and store temporary vxlan decap related information to PTF docker

    Args:
        ptfhost (PTFHost): The ptfhost fixture, instance of PTFHost
        mg_facts (dict): Collected minigraph facts
        duthost (SonicHost): The duthost fixture, instance of SonicHost
    """

    logger.info("Prepare arp_responder")

    arp_responder_conf = Template(open("../ansible/roles/test/templates/arp_responder.conf.j2").read())
    ptfhost.copy(content=arp_responder_conf.render(arp_responder_args="--conf /tmp/vxlan_arpresponder.conf"),
                dest="/etc/supervisor/conf.d/arp_responder.conf")

    ptfhost.shell("supervisorctl reread")
    ptfhost.shell("supervisorctl update")

    logger.info("Put information needed by the PTF script to the PTF container.")
    vxlan_decap = {
        "minigraph_port_indices": mg_facts["minigraph_ptf_indices"],
        "minigraph_portchannel_interfaces": mg_facts["minigraph_portchannel_interfaces"],
        "minigraph_portchannels": mg_facts["minigraph_portchannels"],
        "minigraph_lo_interfaces": mg_facts["minigraph_lo_interfaces"],
        "minigraph_vlans": mg_facts["minigraph_vlans"],
        "minigraph_vlan_interfaces": mg_facts["minigraph_vlan_interfaces"],
        "dut_mac": duthost.facts["router_mac"]
    }
    ptfhost.copy(content=json.dumps(vxlan_decap, indent=2), dest="/tmp/vxlan_decap.json")


def generate_vxlan_config_files(duthost, mg_facts):
    """
    @summary: Generate VXLAN tunnel and VXLAN map configuration files to DUT.
    @param duthost: DUT host object
    @mg_facts: Minigraph facts
    """
    loopback_ip = None
    for intf in mg_facts["minigraph_lo_interfaces"]:
        if IPAddress(intf["addr"]).version == 4:
            loopback_ip = intf["addr"]
            break
    if not loopback_ip:
        pytest.fail("ipv4 lo interface not found")

    # Generate vxlan tunnel config json file on DUT
    vxlan_tunnel_cfg = {
        "VXLAN_TUNNEL": {
            "tunnelVxlan": {
                "src_ip": loopback_ip,
                "dst_ip": VTEP2_IP
            }
        }
    }
    duthost.copy(content=json.dumps(vxlan_tunnel_cfg, indent=2), dest="/tmp/vxlan_db.tunnel.json")

    # Generate vxlan maps config json file on DUT
    vxlan_maps_cfg = {
        "VXLAN_TUNNEL_MAP": {}
    }
    for vlan in mg_facts["minigraph_vlans"]:
        vxlan_maps_cfg["VXLAN_TUNNEL_MAP"]["tunnelVxlan|map%s" % vlan] = {
            "vni": int(vlan.replace("Vlan", "")) + VNI_BASE,
            "vlan": vlan
        }
    duthost.copy(content=json.dumps(vxlan_maps_cfg, indent=2), dest="/tmp/vxlan_db.maps.json")


@pytest.fixture(scope="module")
def setup(duthosts, rand_one_dut_hostname, ptfhost, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]

    logger.info("Gather some facts")
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    logger.info("Copying vxlan_switch.json")
    render_template_to_host("vxlan_switch.j2", duthost, DUT_VXLAN_PORT_JSON)
    duthost.shell("docker cp {} swss:/vxlan.switch.json".format(DUT_VXLAN_PORT_JSON))
    duthost.shell("docker exec swss sh -c \"swssconfig /vxlan.switch.json\"")
    sleep(3)

    logger.info("Prepare PTF")
    prepare_ptf(ptfhost, mg_facts, duthost)

    logger.info("Generate VxLAN config files")
    generate_vxlan_config_files(duthost, mg_facts)

    setup_info = {
        "mg_facts": mg_facts
    }

    yield setup_info

    logger.info("Stop arp_responder on PTF")
    ptfhost.shell("supervisorctl stop arp_responder")

    logger.info("Always try to remove any possible VxLAN tunnel and map configuration")
    for vlan in mg_facts["minigraph_vlans"]:
            duthost.shell('docker exec -i database redis-cli -n 4 -c DEL "VXLAN_TUNNEL_MAP|tunnelVxlan|map%s"' % vlan)
    duthost.shell('docker exec -i database redis-cli -n 4 -c DEL "VXLAN_TUNNEL|tunnelVxlan"')


@pytest.fixture(params=["NoVxLAN", "Enabled", "Removed"])
def vxlan_status(setup, request, duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    #clear FDB and arp cache on DUT
    duthost.shell('sonic-clear arp; fdbclear')
    if request.param == "Enabled":
        duthost.shell("sonic-cfggen -j /tmp/vxlan_db.tunnel.json --write-to-db")
        duthost.shell("sonic-cfggen -j /tmp/vxlan_db.maps.json --write-to-db")
        return True, request.param
    elif request.param == "Removed":
        for vlan in setup["mg_facts"]["minigraph_vlans"]:
            duthost.shell('docker exec -i database redis-cli -n 4 -c DEL "VXLAN_TUNNEL_MAP|tunnelVxlan|map%s"' % vlan)
        duthost.shell('docker exec -i database redis-cli -n 4 -c DEL "VXLAN_TUNNEL|tunnelVxlan"')
        return False, request.param
    else:
        return False, request.param


def test_vxlan_decap(setup, vxlan_status, duthosts, rand_one_dut_hostname, ptfhost, creds):
    duthost = duthosts[rand_one_dut_hostname]

    sonic_admin_alt_password = duthost.host.options['variable_manager']._hostvars[duthost.hostname].get("ansible_altpassword")

    vxlan_enabled, scenario = vxlan_status
    logger.info("vxlan_enabled=%s, scenario=%s" % (vxlan_enabled, scenario))
    log_file = "/tmp/vxlan-decap.Vxlan.{}.{}.log".format(scenario, datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
    ptf_runner(ptfhost,
               "ptftests",
               "vxlan-decap.Vxlan",
                platform_dir="ptftests",
                params={"vxlan_enabled": vxlan_enabled,
                        "config_file": '/tmp/vxlan_decap.json',
                        "count": COUNT,
                        "sonic_admin_user": creds.get('sonicadmin_user'),
                        "sonic_admin_password": creds.get('sonicadmin_password'),
                        "sonic_admin_alt_password": sonic_admin_alt_password,
                        "dut_hostname": duthost.host.options['inventory_manager'].get_host(duthost.hostname).vars['ansible_host']},
                qlen=10000,
                log_file=log_file)
