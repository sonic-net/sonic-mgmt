
import ipaddress
import pytest
import logging
import json
import time
import ptf.packet as scapy
from ptf.mask import Mask
from ptf.testutils import simple_tcp_packet, simple_ipv4ip_packet
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common.helpers.assertions import pytest_assert
from tests.common.system_utils import docker
from tests.common.dualtor.mux_simulator_control import mux_server_url, toggle_all_simulator_ports
from tests.common.fixtures.ptfhost_utils import ptf_portmap_file_module    # lgtm[py/unused-import]

logger = logging.getLogger(__name__)

def build_testing_packet(src_ip, dst_ip, active_tor_mac, standby_tor_mac, active_tor_ip, standby_tor_ip, inner_dscp, outer_dscp, ecn=1):
    pkt = simple_tcp_packet(
                eth_dst=standby_tor_mac,
                ip_src=src_ip,
                ip_dst=dst_ip,
                ip_dscp=inner_dscp,
                ip_ecn=ecn,
                ip_ttl=64
            )
    # The ttl of inner_frame is decreased by 1
    pkt.ttl -= 1
    ipinip_packet = simple_ipv4ip_packet(
                eth_dst=active_tor_mac,
                eth_src=standby_tor_mac,
                ip_src=standby_tor_ip,
                ip_dst=active_tor_ip,
                ip_dscp=outer_dscp,
                ip_ecn=ecn,
                inner_frame=pkt[IP]
            )
    pkt.ttl += 1
    exp_tunnel_pkt = Mask(ipinip_packet)
    exp_tunnel_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
    exp_tunnel_pkt.set_do_not_care_scapy(scapy.Ether, "src")
    exp_tunnel_pkt.set_do_not_care_scapy(scapy.IP, "id") # since src and dst changed, ID would change too
    exp_tunnel_pkt.set_do_not_care_scapy(scapy.IP, "ttl") # ttl in outer packet is set to 255
    exp_tunnel_pkt.set_do_not_care_scapy(scapy.IP, "chksum") # checksum would differ as the IP header is not the same

    return pkt, exp_tunnel_pkt

def check_queue_counter(duthost, intfs, queue, counter):
    output = duthost.shell('show queue counters')['stdout_lines']

    for intf in intfs:
        for line in output:
            fields = line.split()
            if len(fields) == 6 and fields[0] == intf and fields[1] == 'UC{}'.format(queue):
                if int(fields[2]) >= counter:
                    return True
    
    return False


def load_tunnel_qos_map():
    """
    Read DSCP_TO_TC_MAP and TC_TO_PRIORITY_GROUP_MAP from file
    return a dict
    """
    TUNNEL_QOS_MAP_FILENAME = r"qos/files/tunnel_qos_map.json"
    MAP_NAME = "AZURE_TUNNEL"
    ret = {}
    with open(TUNNEL_QOS_MAP_FILENAME, "r") as f:
        maps = json.load(f)
        
    ret['dscp_to_tc_map'] = {}
    for k, v in maps['DSCP_TO_TC_MAP'][MAP_NAME].items():
        ret['dscp_to_tc_map'][int(k)] = int(v)
        
    ret['tc_to_priority_group_map'] = {}
    for k, v in maps['TC_TO_PRIORITY_GROUP_MAP'][MAP_NAME].items():
        ret["tc_to_priority_group_map"][int(k)] = int(v)
        
    return ret


def get_iface_ip(mg_facts, ifacename):
    for loopback in mg_facts['minigraph_lo_interfaces']:
        if loopback['name'] == ifacename and ipaddress.ip_address(loopback['addr']).version == 4:
            return loopback['addr']
    return None


@pytest.fixture(scope='module')
def dut_config(rand_selected_dut, rand_unselected_dut, tbinfo, ptf_portmap_file_module):
    '''
    Generate a dict including test required params
    '''
    duthost = rand_selected_dut
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    asic_type = duthost.facts["asic_type"]
    # Always use the first portchannel member
    lag_port_name = list(mg_facts['minigraph_portchannels'].values())[0]['members'][0]
    lag_port_ptf_id = mg_facts['minigraph_ptf_indices'][lag_port_name]

    muxcable_info = mux_cable_server_ip(duthost)
    server_port_name = list(muxcable_info.keys())[0]
    server_ip = muxcable_info[server_port_name]['server_ipv4'].split('/')[0]
    server_port_ptf_id = mg_facts['minigraph_ptf_indices'][server_port_name]
    server_port_slice = mg_facts['minigraph_port_indices'][server_port_name]
    
    selected_tor_mgmt = mg_facts['minigraph_mgmt_interface']['addr']
    selected_tor_mac = rand_selected_dut.facts['router_mac']
    selected_tor_loopback = get_iface_ip(mg_facts, 'Loopback0')

    unselected_dut_mg_facts = rand_unselected_dut.get_extended_minigraph_facts(tbinfo)
    unselected_tor_mgmt = unselected_dut_mg_facts['minigraph_mgmt_interface']['addr']
    unselected_tor_mac = rand_unselected_dut.facts['router_mac']
    unselected_tor_loopback = get_iface_ip(unselected_dut_mg_facts, 'Loopback0')

    return {
        "asic_type": asic_type,
        "lag_port_name": lag_port_name,
        "lag_port_ptf_id": lag_port_ptf_id,
        "server_port_name": server_port_name,
        "server_ip": server_ip,
        "server_port_ptf_id": server_port_ptf_id,
        "server_port_slice": server_port_slice,
        "selected_tor_mgmt": selected_tor_mgmt,
        "selected_tor_mac": selected_tor_mac,
        "selected_tor_loopback": selected_tor_loopback,
        "unselected_tor_mgmt": unselected_tor_mgmt,
        "unselected_tor_mac": unselected_tor_mac,
        "unselected_tor_loopback": unselected_tor_loopback,
        "tunnel_qos_map": load_tunnel_qos_map(),
        "port_map_file": ptf_portmap_file_module
    }

def _create_ssh_tunnel_to_syncd_rpc(duthost):
    dut_asic = duthost.asic_instance()
    dut_asic.create_ssh_tunnel_sai_rpc()


def _remove_ssh_tunnel_to_syncd_rpc(duthost):
    dut_asic = duthost.asic_instance()
    dut_asic.remove_ssh_tunnel_sai_rpc()


@pytest.fixture(scope='module')
def swap_syncd(rand_selected_dut, creds):
    # Swap syncd container
    docker.swap_syncd(rand_selected_dut, creds)
    _create_ssh_tunnel_to_syncd_rpc(rand_selected_dut)
    yield
    # Restore syncd container
    docker.restore_default_syncd(rand_selected_dut, creds)
    _remove_ssh_tunnel_to_syncd_rpc(rand_selected_dut)


def _update_docker_service(duthost, docker="", action="", service=""):
    """
    A helper function to start/stop service      
    """
    cmd = "docker exec {docker} supervisorctl {action} {service}".format(docker=docker, action=action, service=service)
    duthost.shell(cmd)
    logger.info("{}ed {}".format(action, service))


@pytest.fixture(scope='module')
def update_docker_services(rand_selected_dut, swap_syncd, disable_container_autorestart, enable_container_autorestart):
    """
    Disable/enable lldp and bgp
    """
    feature_list = ['lldp', 'bgp', 'syncd', 'swss']
    disable_container_autorestart(rand_selected_dut, testcase="test_tunnel_qos_remap", feature_list=feature_list)

    SERVICES = [
            {"docker": "lldp", "service": "lldp-syncd"},
            {"docker": "lldp", "service": "lldpd"},
            {"docker": "bgp",  "service": "bgpd"},
            {"docker": "bgp",  "service": "bgpmon"}
            ] 
    for service in SERVICES:
        _update_docker_service(rand_selected_dut, action="stop", **service)
    
    yield

    enable_container_autorestart(rand_selected_dut, testcase="test_tunnel_qos_remap", feature_list=feature_list)
    for service in SERVICES:
        _update_docker_service(rand_selected_dut, action="start", **service)


def _update_mux_feature(duthost, state):
    cmd = "sudo config feature state mux {}".format(state)
    duthost.shell(cmd)


def _update_muxcable_mode(duthost, mode):
    cmd = "sudo config muxcable mode {} all".format(mode)
    duthost.shell(cmd)


def _update_counterpoll_state(duthost, counter_name, state):
    cmd = "sudo counterpoll {} {}".format(counter_name, state)
    duthost.shell(cmd)


@pytest.fixture(scope='module')
def setup_module(rand_selected_dut, rand_unselected_dut, update_docker_services):
    '''
    Module level setup/teardown
    '''
    # Set the muxcable mode to manual so that the mux cable won't be toggled by heartbeat
    _update_muxcable_mode(rand_selected_dut, "manual")
    _update_muxcable_mode(rand_unselected_dut, "manual")
    # Disable the counter for watermark so that the cached counter in SAI is not cleared periodically
    _update_counterpoll_state(rand_selected_dut, 'watermark', 'disable')
    _update_counterpoll_state(rand_unselected_dut, 'watermark', 'disable')
    
    yield

    # Set the muxcable mode to auto
    _update_muxcable_mode(rand_selected_dut, "auto")
    _update_muxcable_mode(rand_unselected_dut, "auto")
    # Enable the counter for watermark
    _update_counterpoll_state(rand_selected_dut, 'watermark', 'enable')
    _update_counterpoll_state(rand_unselected_dut, 'watermark', 'enable')


def toggle_mux_to_host(duthost):
    '''
    Toggle the muxcable status with write_standby.py script
    '''
    WRITE_STANDBY = "/usr/local/bin/write_standby.py"
    cmd = "{} -s active".format(WRITE_STANDBY)
    duthost.shell(cmd)
    TIMEOUT = 90
    while TIMEOUT > 0:
        muxcables = json.loads(duthost.shell("show muxcable status --json")['stdout'])
        inactive_muxcables = [intf for intf, muxcable in muxcables['MUX_CABLE'].items() if muxcable['STATUS'] != 'active']
        if len(inactive_muxcables) > 0:
            logger.info('Found muxcables not active on {}: {}'.format(duthost.hostname, json.dumps(inactive_muxcables)))
            time.sleep(10)
            TIMEOUT -= 10
        else:
            logger.info("Mux cable toggled to {}".format(duthost.hostname))
            break
    
    pytest_assert(TIMEOUT > 0, "Failed to toggle muxcable to {}".format(duthost.hostname))


def run_ptf_test(ptfhost, test_case='', test_params={}):
    """
    A helper function to run test script on ptf host
    """
    logger.info("Start running {} on ptf host".format(test_case))
    pytest_assert(ptfhost.shell(
                      argv = [
                          "ptf",
                          "--test-dir",
                          "saitests",
                          test_case,
                          "--platform-dir",
                          "ptftests",
                          "--platform",
                          "remote",
                          "-t",
                          ";".join(["{}={}".format(k, repr(v)) for k, v in test_params.items()]),
                          "--disable-ipv6",
                          "--disable-vxlan",
                          "--disable-geneve",
                          "--disable-erspan",
                          "--disable-mpls",
                          "--disable-nvgre",
                          "--log-file",
                          "/tmp/{0}.log".format(test_case),
                          "--test-case-timeout",
                          "600"
                      ],
                      chdir = "/root",
                      )["rc"] == 0, "Failed when running test '{0}'".format(test_case))
