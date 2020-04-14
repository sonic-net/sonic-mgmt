import json
import logging
from datetime import datetime

import pytest
from jinja2 import Template
from netaddr import IPAddress

from ptf_runner import ptf_runner

logger = logging.getLogger(__name__)

VTEP2_IP = "8.8.8.8"
VNI_BASE = 336
COUNT = 10


def prepare_ptf(ptfhost, mg_facts, dut_facts):
    """
    @summary: Prepare the PTF docker container for testing
    @param mg_facts: Minigraph facts
    @param dut_facts: Host facts of DUT
    """
    logger.info("Remove IP and change MAC")
    ptfhost.script("./scripts/remove_ip.sh")
    ptfhost.script("./scripts/change_mac.sh")

    logger.info("Prepare arp_responder")
    ptfhost.copy(src="../ansible/roles/test/files/helpers/arp_responder.py", dest="/opt")

    arp_responder_conf = Template(open("../ansible/roles/test/templates/arp_responder.conf.j2").read())
    ptfhost.copy(content=arp_responder_conf.render(arp_responder_args="--conf /tmp/vxlan_arpresponder.conf"),
                dest="/etc/supervisor/conf.d/arp_responder.conf")

    ptfhost.shell("supervisorctl reread")
    ptfhost.shell("supervisorctl update")

    logger.info("Put information needed by the PTF script to the PTF container.")
    vxlan_decap = {
        "minigraph_port_indices": mg_facts["minigraph_port_indices"],
        "minigraph_portchannel_interfaces": mg_facts["minigraph_portchannel_interfaces"],
        "minigraph_portchannels": mg_facts["minigraph_portchannels"],
        "minigraph_lo_interfaces": mg_facts["minigraph_lo_interfaces"],
        "minigraph_vlans": mg_facts["minigraph_vlans"],
        "minigraph_vlan_interfaces": mg_facts["minigraph_vlan_interfaces"],
        "dut_mac": dut_facts["ansible_Ethernet0"]["macaddress"]
    }
    ptfhost.copy(content=json.dumps(vxlan_decap, indent=2), dest="/tmp/vxlan_decap.json")

    logger.info("Copy PTF scripts to PTF container")
    ptfhost.copy(src="ptftests", dest="/root")


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
def setup(duthost, ptfhost):

    logger.info("Gather some facts")
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)["ansible_facts"]
    dut_facts = duthost.setup(gather_subset="!all,!any,network", filter="ansible_Ethernet*")["ansible_facts"]
    ptf_facts = ptfhost.setup(gather_subset="!all,!any,network")["ansible_facts"]

    logger.info("Prepare PTF")
    prepare_ptf(ptfhost, mg_facts, dut_facts)

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
def vxlan_status(setup, request, duthost):
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


def test_vxlan_decap(setup, vxlan_status, duthost, ptfhost):

    vxlan_enabled, scenario = vxlan_status

    logger.info("vxlan_enabled=%s, scenario=%s" % (vxlan_enabled, scenario))
    log_file = "/tmp/vxlan-decap.Vxlan.{}.{}.log".format(scenario, datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))
    ptf_runner(ptfhost,
               "ptftests",
               "vxlan-decap.Vxlan",
                platform_dir="ptftests",
                params={"vxlan_enabled": vxlan_enabled,
                        "config_file": '/tmp/vxlan_decap.json',
                        "count": COUNT},
                qlen=1000,
                log_file=log_file)
