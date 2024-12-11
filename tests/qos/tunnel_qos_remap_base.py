
import copy
import pytest
import logging
import json
import yaml
import time
import ptf.packet as scapy
from ptf.mask import Mask
from ptf.testutils import simple_tcp_packet, simple_ipv4ip_packet
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip
from tests.common.helpers.assertions import pytest_assert
from tests.common.system_utils import docker
from tests.common.dualtor.mux_simulator_control import mux_server_url, toggle_all_simulator_ports   # noqa F401
from tests.common.fixtures.duthost_utils import dut_qos_maps_module                                 # noqa F401
from tests.common.fixtures.ptfhost_utils import ptf_portmap_file_module                             # noqa F401
from tests.common.utilities import get_iface_ip

logger = logging.getLogger(__name__)


def build_testing_packet(src_ip, dst_ip, active_tor_mac, standby_tor_mac,
                         active_tor_ip, standby_tor_ip, inner_dscp, outer_dscp, ecn=1):
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
        inner_frame=pkt[scapy.IP]
    )
    pkt.ttl += 1
    exp_tunnel_pkt = Mask(ipinip_packet)
    exp_tunnel_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
    exp_tunnel_pkt.set_do_not_care_scapy(scapy.Ether, "src")
    # since src and dst changed, ID would change too
    exp_tunnel_pkt.set_do_not_care_scapy(scapy.IP, "id")
    # ttl in outer packet is kept default (64)
    exp_tunnel_pkt.set_do_not_care_scapy(scapy.IP, "ttl")
    # checksum would differ as the IP header is not the same
    exp_tunnel_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
    # "Don't fragment" flag may be set in the outer header
    exp_tunnel_pkt.set_do_not_care_scapy(scapy.IP, "flags")

    return pkt, exp_tunnel_pkt


def get_queue_watermark(duthost, port, queue, clear_after_read=False):
    """
    Return the queue watermark for the given port and queue
    """
    # Wait a default interval (60 seconds)
    time.sleep(60)
    cmd = "show queue watermark unicast"
    output = duthost.shell(cmd)['stdout_lines']
    """
        Egress shared pool occupancy per unicast queue:
               Port    UC0    UC1    UC2    UC3    UC4    UC5    UC6    UC7
        -----------  -----  -----  -----  -----  -----  -----  -----  -----
          Ethernet0      0      0      0      0      0      0      0      0
    """
    port_line = None
    for line in output:
        if line.split()[0] == port:
            port_line = line
            break
    assert port_line is not None, "Failed to find queue watermark line in output for port '{}'".format(port)
    items = port_line.split()
    index = queue + 1
    assert index < len(items), "Index {} out of range for line:\n{}".format(index, port_line)
    wmk_str = items[index]
    assert wmk_str.isdigit(), "Invalid watermark string '{}' in line:\n{}".format(wmk_str, port_line)
    wmk = int(items[index])
    if clear_after_read:
        duthost.shell("sonic-clear queue watermark unicast")
    return wmk


def get_queue_counter(duthost, port, queue, clear_before_read=False):
    """
    Return the counter for given queue in given port
    """
    if clear_before_read:
        duthost.shell("sonic-clear queuecounters")
    # Wait a default interval (10 seconds)
    time.sleep(10)
    cmd = "show queue counters {}".format(port)
    output = duthost.shell(cmd)['stdout_lines']
    """
             Port    TxQ    Counter/pkts    Counter/bytes    Drop/pkts    Drop/bytes
        ---------  -----  --------------  ---------------  -----------  ------------
        Ethernet4    UC0               0                0            0             0
    """
    txq = "UC{}".format(queue)
    for line in output:
        fields = line.split()
        if fields[1] == txq:
            return int(fields[2].replace(',', ''))

    return 0


def check_queue_counter(duthost, intfs, queue, counter):
    output = duthost.shell('show queue counters')['stdout_lines']
    for line in output:
        fields = line.split()
        if len(fields) == 6 and fields[0] in intfs and fields[1] == 'UC{}'.format(queue):
            if int(fields[2].replace(',', '')) >= counter:
                return True

    return False


def counter_poll_config(duthost, type, interval_ms):
    """
    A helper function to config the interval of counterpoll
    """
    cmd = 'counterpoll {} interval {}'.format(type, interval_ms)
    duthost.shell(cmd)
    # Sleep for 10 seconds (default interval) for the new interval to be applied
    if interval_ms < 10000:
        time.sleep(10)


@pytest.fixture(scope='class')
def tunnel_qos_maps(rand_selected_dut, dut_qos_maps_module): # noqa F811
    """
    Read DSCP_TO_TC_MAP/TC_TO_PRIORITY_GROUP_MAP/TC_TO_DSCP_MAP/TC_TO_QUEUE_MAP from file
    or config DB depending on the ASIC type.
    return a dict
    """
    asic_name = rand_selected_dut.get_asic_name()
    is_nvidia_platform = asic_name is not None and 'spc' in asic_name
    if not is_nvidia_platform:
        TUNNEL_QOS_MAP_FILENAME = r"qos/files/tunnel_qos_map.json"
    else:
        TUNNEL_QOS_MAP_FILENAME = r"qos/files/tunnel_qos_map_nvidia.json"
    TUNNEL_MAP_NAME = "AZURE_TUNNEL"
    UPLINK_MAP_NAME = "AZURE_UPLINK"
    MAP_NAME = "AZURE"
    asic_type = rand_selected_dut.facts["asic_type"]
    if 'cisco-8000' in asic_type:
        # Cisco-8000 does not use the tunneled tc to pg map
        tc_to_pg_map_name = MAP_NAME
        # Use config DB for maps
        maps = {}
        for map_name in dut_qos_maps_module:
            maps[map_name.upper()] = dut_qos_maps_module[map_name]
    else:
        tc_to_pg_map_name = TUNNEL_MAP_NAME
        # Load maps from file
        with open(TUNNEL_QOS_MAP_FILENAME, "r") as f:
            maps = json.load(f)
    ret = {}
    # inner_dscp_to_pg map, a map for mapping dscp to priority group at decap side
    ret['inner_dscp_to_pg_map'] = {}
    if is_nvidia_platform:
        for k, v in maps['DSCP_TO_TC_MAP'][UPLINK_MAP_NAME].items():
            ret['inner_dscp_to_pg_map'][int(k)] = int(
                maps['TC_TO_PRIORITY_GROUP_MAP'][MAP_NAME][v])
    else:
        for k, v in maps['DSCP_TO_TC_MAP'][TUNNEL_MAP_NAME].items():
            ret['inner_dscp_to_pg_map'][int(k)] = int(
                maps['TC_TO_PRIORITY_GROUP_MAP'][tc_to_pg_map_name][v])
    # inner_dscp_to_outer_dscp_map, a map for rewriting DSCP in the encapsulated packets
    ret['inner_dscp_to_outer_dscp_map'] = {}
    if 'cisco-8000' in asic_type:
        for k, v in list(maps['TC_TO_DSCP_MAP'][TUNNEL_MAP_NAME].items()):
            ret['inner_dscp_to_outer_dscp_map'][int(k)] = int(v)
    else:
        for k, v in list(maps['DSCP_TO_TC_MAP'][MAP_NAME].items()):
            ret['inner_dscp_to_outer_dscp_map'][int(k)] = int(
                maps['TC_TO_DSCP_MAP'][TUNNEL_MAP_NAME][v])
    # inner_dscp_to_queue_map, a map for mapping the tunnel traffic to egress queue at decap side
    ret['inner_dscp_to_queue_map'] = {}
    if is_nvidia_platform:
        for k, v in maps['DSCP_TO_TC_MAP'][UPLINK_MAP_NAME].items():
            ret['inner_dscp_to_queue_map'][int(k)] = int(
                maps['TC_TO_QUEUE_MAP'][MAP_NAME][v])
    else:
        for k, v in maps['DSCP_TO_TC_MAP'][TUNNEL_MAP_NAME].items():
            ret['inner_dscp_to_queue_map'][int(k)] = int(
                maps['TC_TO_QUEUE_MAP'][MAP_NAME][v])

    return ret


@pytest.fixture(scope='module')
def dut_config(rand_selected_dut, rand_unselected_dut, tbinfo, ptf_portmap_file_module):    # noqa F811
    '''
    Generate a dict including test required params
    '''
    duthost = rand_selected_dut
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    asic_type = duthost.facts["asic_type"]
    if 'platform_asic' in duthost.facts:
        platform_asic = duthost.facts['platform_asic']
    else:
        platform_asic = None
    # Always use the first portchannel member
    lag_port_name = list(mg_facts['minigraph_portchannels'].values())[
        0]['members'][0]
    lag_port_ptf_id = mg_facts['minigraph_ptf_indices'][lag_port_name]

    muxcable_info = mux_cable_server_ip(duthost)
    server_port_name = list(muxcable_info.keys())[0]
    server_ip = muxcable_info[server_port_name]['server_ipv4'].split('/')[0]
    server_port_ptf_id = mg_facts['minigraph_ptf_indices'][server_port_name]
    server_port_slice = mg_facts['minigraph_port_indices'][server_port_name]

    selected_tor_mgmt = mg_facts['minigraph_mgmt_interface']['addr']
    selected_tor_mac = rand_selected_dut.facts['router_mac']
    selected_tor_loopback = get_iface_ip(mg_facts, 'Loopback0')

    unselected_dut_mg_facts = rand_unselected_dut.get_extended_minigraph_facts(
        tbinfo)
    unselected_tor_mgmt = unselected_dut_mg_facts['minigraph_mgmt_interface']['addr']
    unselected_tor_mac = rand_unselected_dut.facts['router_mac']
    unselected_tor_loopback = get_iface_ip(
        unselected_dut_mg_facts, 'Loopback0')

    return {
        "asic_type": asic_type,
        "platform_asic": platform_asic,
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
        "port_map_file_ini": ptf_portmap_file_module
    }


def _lossless_profile_name(dut, port_name, pgs='2-4'):
    """
    Read lossless PG name for given port
    """
    cmd = "sonic-db-cli APPL_DB hget \'BUFFER_PG_TABLE:{}:{}\' \'profile\'".format(
        port_name, pgs)
    profile_name = dut.shell(cmd)['stdout']
    pytest_assert(profile_name != "")
    # The output can be pg_lossless_100000_300m_profile or [BUFFER_PROFILE_TABLE:pg_lossless_100000_300m_profile]
    profile_name = profile_name.split(':')[-1].rstrip(']')
    return profile_name


@pytest.fixture(scope='module')
def qos_config(rand_selected_dut, tbinfo, dut_config):
    duthost = rand_selected_dut
    SUPPORTED_ASIC_LIST = ["gb", "td2", "th", "th2",
                           "spc1", "spc2", "spc3", "td3", "th3", "j2c+", "jr2"]

    qos_configs = {}
    with open(r"qos/files/qos.yml") as file:
        qos_configs = yaml.load(file, Loader=yaml.FullLoader)

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    vendor = duthost.facts["asic_type"]
    hostvars = duthost.host.options['variable_manager']._hostvars[duthost.hostname]
    dut_asic = None
    for asic in SUPPORTED_ASIC_LIST:
        vendor_asic = "{0}_{1}_hwskus".format(vendor, asic)
        if vendor_asic in list(hostvars.keys()) and mg_facts["minigraph_hwsku"] in hostvars[vendor_asic]:
            dut_asic = asic
            break

    pytest_assert(dut_asic, "Cannot identify DUT ASIC type")

    dut_topo = "topo-"
    topo = tbinfo["topo"]["name"]
    if dut_topo + topo in qos_configs['qos_params'].get(dut_asic, {}):
        dut_topo = dut_topo + topo
    else:
        # Default topo is any
        dut_topo = dut_topo + "any"

    # Get profile name for src port
    lag_port_name = dut_config["lag_port_name"]
    profile_name = _lossless_profile_name(duthost, lag_port_name, '2-4')
    profile_name = profile_name.lstrip('pg_lossless_').rstrip('_profile')

    return qos_configs['qos_params'][dut_asic][dut_topo][profile_name]


@pytest.fixture(scope='module', autouse=True)
def disable_packet_aging(rand_selected_dut, duthosts):
    """
        For Nvidia(Mellanox) platforms, packets in buffer will be aged after a timeout. Need to disable this
        before any buffer tests.
    """
    for duthost in duthosts:
        asic = duthost.get_asic_name()
        if 'spc' in asic:
            logger.info("Disable Mellanox packet aging")
            duthost.copy(src="qos/files/mellanox/packets_aging.py", dest="/tmp")
            duthost.command("docker cp /tmp/packets_aging.py syncd:/")
            duthost.command("docker exec syncd python /packets_aging.py disable")

    yield

    for duthost in duthosts:
        asic = duthost.get_asic_name()
        if 'spc' in asic:
            logger.info("Enable Mellanox packet aging")
            duthost.command("docker exec syncd python /packets_aging.py enable")
            duthost.command("docker exec syncd rm -rf /packets_aging.py")


def _create_ssh_tunnel_to_syncd_rpc(duthost):
    dut_asic = duthost.asic_instance()
    dut_asic.create_ssh_tunnel_sai_rpc()


def _remove_ssh_tunnel_to_syncd_rpc(duthost):
    dut_asic = duthost.asic_instance()
    dut_asic.remove_ssh_tunnel_sai_rpc()


@pytest.fixture(scope='module')
def swap_syncd(request, rand_selected_dut, creds):
    if request.config.getoption("--qos_swap_syncd"):
        public_docker_reg = request.config.getoption("--public_docker_registry")
        new_creds = None
        if public_docker_reg:
            new_creds = copy.deepcopy(creds)
            new_creds['docker_registry_host'] = new_creds['public_docker_registry_host']
            new_creds['docker_registry_username'] = ''
            new_creds['docker_registry_password'] = ''
        else:
            new_creds = creds
        # Swap syncd container
        docker.swap_syncd(rand_selected_dut, new_creds)
        _create_ssh_tunnel_to_syncd_rpc(rand_selected_dut)
    yield
    if request.config.getoption("--qos_swap_syncd"):
        # Restore syncd container
        docker.restore_default_syncd(rand_selected_dut, new_creds)
        _remove_ssh_tunnel_to_syncd_rpc(rand_selected_dut)


def _update_docker_service(duthost, docker="", action="", service=""):
    """
    A helper function to start/stop service
    """
    cmd = "docker exec {docker} supervisorctl {action} {service}".format(
        docker=docker, action=action, service=service)
    duthost.shell(cmd)
    logger.info("{}ed {}".format(action, service))


@pytest.fixture(scope='module')
def update_docker_services(rand_selected_dut, swap_syncd, disable_container_autorestart, enable_container_autorestart):
    """
    Disable/enable lldp and bgp
    """
    feature_list = ['lldp', 'bgp', 'syncd', 'swss']
    disable_container_autorestart(
        rand_selected_dut, testcase="test_tunnel_qos_remap", feature_list=feature_list)

    SERVICES = [
        {"docker": "lldp", "service": "lldp-syncd"},
        {"docker": "lldp", "service": "lldpd"},
        {"docker": "bgp",  "service": "bgpd"},
        {"docker": "bgp",  "service": "bgpmon"}
    ]
    for service in SERVICES:
        _update_docker_service(rand_selected_dut, action="stop", **service)

    yield

    enable_container_autorestart(
        rand_selected_dut, testcase="test_tunnel_qos_remap", feature_list=feature_list)
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
        muxcables = json.loads(duthost.shell(
            "show muxcable status --json")['stdout'])
        inactive_muxcables = [intf for intf, muxcable in list(
            muxcables['MUX_CABLE'].items()) if muxcable['STATUS'] != 'active']
        if len(inactive_muxcables) > 0:
            logger.info('Found muxcables not active on {}: {}'.format(
                duthost.hostname, json.dumps(inactive_muxcables)))
            time.sleep(10)
            TIMEOUT -= 10
        else:
            logger.info("Mux cable toggled to {}".format(duthost.hostname))
            break

    pytest_assert(
        TIMEOUT > 0, "Failed to toggle muxcable to {}".format(duthost.hostname))


def leaf_fanout_peer_info(duthost, conn_graph_facts, mg_facts, port_idx):
    dut_intf_paused = ""
    for port, indice in list(mg_facts['minigraph_ptf_indices'].items()):
        if indice == port_idx:
            dut_intf_paused = port
            break
    pytest_assert(dut_intf_paused,
                  "Failed to find port for idx {}".format(port_idx))

    peer_device = conn_graph_facts['device_conn'][duthost.hostname][dut_intf_paused]['peerdevice']
    peer_port = conn_graph_facts['device_conn'][duthost.hostname][dut_intf_paused]['peerport']
    peer_info = {
        'peerdevice': peer_device,
        'pfc_fanout_interface': peer_port
    }
    return peer_info


def start_pfc_storm(storm_handler, peer_info, prio):
    """
    Start sending PFC pause frames from fanout switch
    """
    storm_handler.deploy_pfc_gen()
    storm_handler.start_storm()
    # Wait for PFC pause frame generation
    time.sleep(2)


def stop_pfc_storm(storm_handler):
    """
    Stop sending PFC pause frames from fanout switch
    """
    storm_handler.stop_storm()


def run_ptf_test(ptfhost, test_case='', test_params={}):
    """
    A helper function to run test script on ptf host
    """
    logger.info("Start running {} on ptf host".format(test_case))
    pytest_assert(ptfhost.shell(
        argv=[
            "/root/env-python3/bin/ptf",
            "--test-dir",
            "saitests/py3",
            test_case,
            "--platform-dir",
            "ptftests",
            "--platform",
            "remote",
            "-t",
            ";".join(["{}={}".format(k, repr(v))
                      for k, v in list(test_params.items())]),
            "--disable-ipv6",
            "--disable-vxlan",
            "--disable-geneve",
            "--disable-erspan",
            "--disable-mpls",
            "--disable-nvgre",
            "--log-file",
            "/tmp/{0}.log".format(test_case),
            "--test-case-timeout",
            "1200"
        ],
        chdir="/root",
    )["rc"] == 0, "Failed when running test '{0}'".format(test_case))
