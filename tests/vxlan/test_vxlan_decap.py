import json
import logging
from datetime import datetime
from time import sleep

import pytest
from jinja2 import Template
from netaddr import IPAddress
from .vnet_constants import DUT_VXLAN_PORT_JSON
from .vnet_utils import render_template_to_host


from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory     # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses    # noqa F401
from tests.common.fixtures.ptfhost_utils import copy_arp_responder_py   # noqa F401
from tests.common.fixtures.ptfhost_utils import remove_ip_addresses     # noqa F401
# Temporary work around to add skip_traffic_test fixture from duthost_utils
from tests.common.fixtures.duthost_utils import skip_traffic_test       # noqa F401
from tests.ptf_runner import ptf_runner
from tests.common.dualtor.mux_simulator_control import mux_server_url,\
    toggle_all_simulator_ports_to_rand_selected_tor_m   # noqa F401
pytestmark = [
    pytest.mark.topology('t0')
]

logger = logging.getLogger(__name__)

VTEP2_IP = "8.8.8.8"
VNI_BASE = 336
COUNT = 1


def prepare_ptf(ptfhost, mg_facts, duthost, unslctd_mg_facts=None):
    """Prepare arp responder configuration and store temporary vxlan decap related information to PTF docker

    Args:
        ptfhost (PTFHost): The ptfhost fixture, instance of PTFHost
        mg_facts (dict): Collected minigraph facts
        duthost (SonicHost): The duthost fixture, instance of SonicHost
    """

    logger.info("Prepare arp_responder")

    arp_responder_conf = Template(
        open("../ansible/roles/test/templates/arp_responder.conf.j2").read())
    ptfhost.copy(content=arp_responder_conf.render(arp_responder_args="--conf /tmp/vxlan_arpresponder.conf"),
                 dest="/etc/supervisor/conf.d/arp_responder.conf")

    ptfhost.shell("supervisorctl reread")
    ptfhost.shell("supervisorctl update")

    logger.info("Put information needed by the PTF script to the PTF container.")

    vlan_table = duthost.get_running_config_facts()['VLAN']
    vlan_name = list(vlan_table.keys())[0]
    vlan_mac = duthost.get_dut_iface_mac(vlan_name)

    vxlan_decap = {
        "minigraph_port_indices": mg_facts["minigraph_ptf_indices"],
        "mg_unslctd_port_idx": [] if unslctd_mg_facts is None else unslctd_mg_facts["mg_ptf_idx"],
        "minigraph_portchannel_interfaces": mg_facts["minigraph_portchannel_interfaces"],
        "minigraph_portchannels": mg_facts["minigraph_portchannels"],
        "minigraph_lo_interfaces": mg_facts["minigraph_lo_interfaces"],
        "minigraph_vlans": mg_facts["minigraph_vlans"],
        "minigraph_vlan_interfaces": mg_facts["minigraph_vlan_interfaces"],
        "dut_mac": duthost.facts["router_mac"],
        "vlan_mac": vlan_mac
    }
    ptfhost.copy(content=json.dumps(vxlan_decap, indent=2),
                 dest="/tmp/vxlan_decap.json")


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
    duthost.copy(content=json.dumps(vxlan_tunnel_cfg, indent=2),
                 dest="/tmp/vxlan_db.tunnel.json")

    # Generate vxlan maps config json file on DUT
    vxlan_maps_cfg = {
        "VXLAN_TUNNEL_MAP": {}
    }
    for vlan in mg_facts["minigraph_vlans"]:
        vxlan_maps_cfg["VXLAN_TUNNEL_MAP"]["tunnelVxlan|map%s" % vlan] = {
            "vni": int(vlan.replace("Vlan", "")) + VNI_BASE,
            "vlan": vlan
        }
    duthost.copy(content=json.dumps(vxlan_maps_cfg, indent=2),
                 dest="/tmp/vxlan_db.maps.json")


@pytest.fixture(scope="module")
def setup(duthosts, rand_one_dut_hostname, ptfhost, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]

    logger.info("Gather some facts")
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        idx = duthosts.index(duthost)
        unselected_duthost = duthosts[1 - idx]
        unslctd_mg_facts = unselected_duthost.minigraph_facts(host=unselected_duthost.hostname)['ansible_facts']
        unslctd_mg_facts['mg_ptf_idx'] = unslctd_mg_facts['minigraph_port_indices'].copy()
        try:
            map = tbinfo['topo']['ptf_map'][str(1 - idx)]
            if map:
                for port, index in list(unslctd_mg_facts['minigraph_port_indices'].items()):
                    if str(index) in map:
                        unslctd_mg_facts['mg_ptf_idx'][port] = map[str(index)]
        except (ValueError, KeyError):
            pass

    logger.info("Copying vxlan_switch.json")
    render_template_to_host("vxlan_switch.j2", duthost, DUT_VXLAN_PORT_JSON)
    duthost.shell(
        "docker cp {} swss:/vxlan.switch.json".format(DUT_VXLAN_PORT_JSON))
    duthost.shell("docker exec swss sh -c \"swssconfig /vxlan.switch.json\"")
    sleep(3)

    logger.info("Prepare PTF")
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        prepare_ptf(ptfhost, mg_facts, duthost, unslctd_mg_facts)
    else:
        prepare_ptf(ptfhost, mg_facts, duthost)

    logger.info("Generate VxLAN config files")
    generate_vxlan_config_files(duthost, mg_facts)

    setup_info = {
        "mg_facts": mg_facts
    }

    yield setup_info

    logger.info("Stop arp_responder on PTF")
    ptfhost.shell("supervisorctl stop arp_responder",
                  module_ignore_errors=True)

    logger.info(
        "Always try to remove any possible VxLAN tunnel and map configuration")
    for vlan in mg_facts["minigraph_vlans"]:
        duthost.shell(
            'docker exec -i database redis-cli -n 4 -c DEL "VXLAN_TUNNEL_MAP|tunnelVxlan|map%s"' % vlan)
    duthost.shell(
        'docker exec -i database redis-cli -n 4 -c DEL "VXLAN_TUNNEL|tunnelVxlan"')


@pytest.fixture(params=["NoVxLAN", "Enabled", "Removed"])
def vxlan_status(setup, request, duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    if request.param == "Enabled":
        duthost.shell(
            "sonic-cfggen -j /tmp/vxlan_db.tunnel.json --write-to-db")
        duthost.shell("sonic-cfggen -j /tmp/vxlan_db.maps.json --write-to-db")
        return True, request.param
    elif request.param == "Removed":
        for vlan in setup["mg_facts"]["minigraph_vlans"]:
            duthost.shell(
                'docker exec -i database redis-cli -n 4 -c DEL "VXLAN_TUNNEL_MAP|tunnelVxlan|map%s"' % vlan)
        duthost.shell(
            'docker exec -i database redis-cli -n 4 -c DEL "VXLAN_TUNNEL|tunnelVxlan"')
        return False, request.param
    else:
        # clear FDB and arp cache on DUT
        duthost.shell('sonic-clear arp; fdbclear')
        return False, request.param


def test_vxlan_decap(setup, vxlan_status, duthosts, rand_one_dut_hostname, tbinfo,
                     ptfhost, creds, toggle_all_simulator_ports_to_rand_selected_tor_m, skip_traffic_test):    # noqa F811
    duthost = duthosts[rand_one_dut_hostname]

    sonic_admin_alt_password = duthost.host.options['variable_manager'].\
        _hostvars[duthost.hostname]['sonic_default_passwords']

    vxlan_enabled, scenario = vxlan_status
    is_active_active_dualtor = False
    if "dualtor-aa" in tbinfo["topo"]["name"]:
        is_active_active_dualtor = True
    logger.info("vxlan_enabled=%s, scenario=%s" % (vxlan_enabled, scenario))
    log_file = "/tmp/vxlan-decap.Vxlan.{}.{}.log".format(
        scenario, datetime.now().strftime('%Y-%m-%d-%H:%M:%S'))

    if skip_traffic_test is True:
        logger.info("Skip traffic test")
        return
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
                       "is_active_active_dualtor": is_active_active_dualtor,
                       "dut_hostname": duthost.host.options[
                           'inventory_manager'].get_host(duthost.hostname).vars['ansible_host']},
               qlen=10000,
               log_file=log_file,
               is_python3=True)
