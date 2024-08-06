"""
1. Send IPinIP packets from t1 to ToR.
2. Check that for inner packet that has destination IP as active server IP, the packet
is decapsulated and forwarded to server port.
3. Check that for inner packet that has destination IP as standby server IP, the packet
is not forwarded to server port or re-encapsulated to T1s.
"""
import logging
import pytest
import random
import time
import contextlib
import scapy
import six

from ptf import mask
from ptf import testutils
from scapy.all import Ether, IP
from tests.common.dualtor.dual_tor_mock import *        # noqa F403
from tests.common.dualtor.dual_tor_utils import get_t1_ptf_ports
from tests.common.dualtor.dual_tor_utils import rand_selected_interface     # noqa F401
from tests.common.dualtor.dual_tor_utils import get_ptf_server_intf_index
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor      # noqa F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_unselected_tor    # noqa F401
from tests.common.dualtor.tunnel_traffic_utils import tunnel_traffic_monitor        # noqa F401
from tests.common.helpers.assertions import pytest_require
from tests.common.utilities import is_ipv4_address, wait_until
from tests.common.fixtures.ptfhost_utils import run_icmp_responder          # noqa F401
from tests.common.fixtures.ptfhost_utils import run_garp_service            # noqa F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses        # noqa F401
# Temporary work around to add skip_traffic_test fixture from duthost_utils
from tests.common.fixtures.duthost_utils import skip_traffic_test           # noqa F401
from tests.common.utilities import dump_scapy_packet_show_output
from tests.common.dualtor.dual_tor_utils import config_active_active_dualtor_active_standby                 # noqa F401
from tests.common.dualtor.dual_tor_utils import validate_active_active_dualtor_setup                        # noqa F401

pytestmark = [
    pytest.mark.topology("dualtor")
]

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module", autouse=True)
def mock_common_setup_teardown(
    apply_mock_dual_tor_tables,
    apply_mock_dual_tor_kernel_configs,
    cleanup_mocked_configs,
    request
):
    request.getfixturevalue("run_garp_service")


@pytest.fixture(scope="function")
def build_encapsulated_packet(rand_selected_interface, ptfadapter,          # noqa F401
                              rand_selected_dut, tunnel_traffic_monitor):   # noqa F811
    """Build the encapsulated packet sent from T1 to ToR."""
    tor = rand_selected_dut
    _, server_ips = rand_selected_interface
    server_ipv4 = server_ips["server_ipv4"].split("/")[0]
    config_facts = tor.get_running_config_facts()
    try:
        peer_ipv4_address = [_["address_ipv4"] for _ in list(config_facts["PEER_SWITCH"].values())][0]
    except IndexError:
        raise ValueError("Failed to get peer ToR address from CONFIG_DB")

    tor_ipv4_address = [_ for _ in config_facts["LOOPBACK_INTERFACE"]["Loopback0"]
                        if is_ipv4_address(_.split("/")[0])][0]
    tor_ipv4_address = tor_ipv4_address.split("/")[0]

    inner_dscp = random.choice(list(range(0, 33)))
    inner_ttl = random.choice(list(range(3, 65)))
    inner_packet = testutils.simple_ip_packet(
        ip_src="1.1.1.1",
        ip_dst=server_ipv4,
        ip_dscp=inner_dscp,
        ip_ttl=inner_ttl
    )[IP]
    packet = testutils.simple_ipv4ip_packet(
        eth_dst=tor.facts["router_mac"],
        eth_src=ptfadapter.dataplane.get_mac(0, 0),
        ip_src=peer_ipv4_address,
        ip_dst=tor_ipv4_address,
        ip_dscp=inner_dscp,
        ip_ttl=255,
        inner_frame=inner_packet
    )
    logging.info("the encapsulated packet to send:\n%s", dump_scapy_packet_show_output(packet))
    return packet


def build_expected_packet_to_server(encapsulated_packet, decrease_ttl=False):
    """Build packet expected to be received by server from the tunnel packet."""
    inner_packet = encapsulated_packet[IP].payload[IP].copy()
    # use dummy mac address that will be ignored in mask
    inner_packet = Ether(src="aa:bb:cc:dd:ee:ff", dst="aa:bb:cc:dd:ee:ff") / inner_packet
    if decrease_ttl:
        inner_packet.ttl = inner_packet.ttl - 1
    exp_pkt = mask.Mask(inner_packet)
    exp_pkt.set_do_not_care_scapy(Ether, "dst")
    exp_pkt.set_do_not_care_scapy(Ether, "src")
    exp_pkt.set_do_not_care_scapy(IP, "chksum")
    return exp_pkt


def test_decap_active_tor(
    build_encapsulated_packet, request, ptfhost,
    rand_selected_interface, ptfadapter,                    # noqa F401
    tbinfo, rand_selected_dut, tunnel_traffic_monitor, skip_traffic_test):  # noqa F811

    @contextlib.contextmanager
    def stop_garp(ptfhost):
        """Temporarily stop garp service."""
        ptfhost.shell("supervisorctl stop garp_service")
        yield
        ptfhost.shell("supervisorctl start garp_service")

    if is_t0_mocked_dualtor(tbinfo):        # noqa F405
        request.getfixturevalue('apply_active_state_to_orchagent')
        time.sleep(30)
    else:
        request.getfixturevalue('toggle_all_simulator_ports_to_rand_selected_tor')

    tor = rand_selected_dut
    encapsulated_packet = build_encapsulated_packet
    iface, _ = rand_selected_interface

    exp_ptf_port_index = get_ptf_server_intf_index(tor, tbinfo, iface)
    exp_pkt = build_expected_packet_to_server(encapsulated_packet, decrease_ttl=True)

    ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
    logging.info("send encapsulated packet from ptf t1 interface %s", ptf_t1_intf)
    if skip_traffic_test is True:
        logging.info("Skip following traffic test")
        return
    with stop_garp(ptfhost):
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), encapsulated_packet)
        testutils.verify_packet(ptfadapter, exp_pkt, exp_ptf_port_index, timeout=10)


def test_decap_standby_tor(
    build_encapsulated_packet, request,
    rand_selected_interface, ptfadapter,                    # noqa F401
    tbinfo, rand_selected_dut, tunnel_traffic_monitor, skip_traffic_test       # noqa F401
):

    def verify_downstream_packet_to_server(ptfadapter, port, exp_pkt):
        """Verify packet is passed downstream to server."""
        packets = ptfadapter.dataplane.packet_queues[(0, port)]
        for packet in packets:
            if six.PY2:
                if exp_pkt.pkt_match(packet):
                    return True
            else:
                if exp_pkt.pkt_match(packet[0]):
                    return True
        return False

    if is_t0_mocked_dualtor(tbinfo):        # noqa F405
        request.getfixturevalue('apply_standby_state_to_orchagent')
    else:
        request.getfixturevalue('toggle_all_simulator_ports_to_rand_unselected_tor')

    tor = rand_selected_dut
    encapsulated_packet = build_encapsulated_packet
    iface, _ = rand_selected_interface

    exp_ptf_port_index = get_ptf_server_intf_index(tor, tbinfo, iface)
    exp_pkt = build_expected_packet_to_server(encapsulated_packet)

    ptf_t1_intf = random.choice(get_t1_ptf_ports(tor, tbinfo))
    logging.info("send encapsulated packet from ptf t1 interface %s", ptf_t1_intf)
    if skip_traffic_test is True:
        logging.info("Skip following traffic test")
        return
    with tunnel_traffic_monitor(tor, existing=False):
        testutils.send(ptfadapter, int(ptf_t1_intf.strip("eth")), encapsulated_packet, count=10)
        time.sleep(2)
        verify_downstream_packet_to_server(ptfadapter, exp_ptf_port_index, exp_pkt)


def _wait_portchannel_up(duthost, portchannel):
    def _check_lag_status():
        cmd = "show interface portchannel | grep {}".format(portchannel)
        return '(Up)' in duthost.shell(cmd)['stdout']

    if not wait_until(300, 10, 30, _check_lag_status):
        pytest.fail("PortChannel didn't startup")
    # Wait another 60 seconds for routes announcement
    time.sleep(60)


@pytest.fixture
def enable_feature_autorestart(rand_selected_dut):
    # Enable autorestart for all features before the test begins
    duthost = rand_selected_dut
    feature_list, _ = duthost.get_feature_status()
    autorestart_states = duthost.get_container_autorestart_states()
    changed_features = []
    for feature, status in list(feature_list.items()):
        if status == 'enabled' and autorestart_states.get(feature) == 'disabled':
            duthost.shell("sudo config feature autorestart {} enabled".format(feature))
            changed_features.append(feature)
    yield
    # Restore the autorestart status after the test ends
    for feature in changed_features:
        duthost.shell("sudo config feature autorestart {} disabled".format(feature))


@pytest.fixture
def setup_uplink(rand_selected_dut, tbinfo, enable_feature_autorestart):
    """
    Function level fixture.
    1. Only keep 1 uplink up. Shutdown others to force the bounced back traffic is egressed
        from monitor port of mirror session
    2. If there are more than 1 member in the LAG, update the LAG to have only one member
    """
    pytest_require("dualtor" in tbinfo['topo']['name'], "Only run on dualtor testbed")
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    portchannels = list(mg_facts['minigraph_portchannels'].keys())
    up_portchannel = random.choice(portchannels)
    logger.info("Select uplink {} for testing".format(up_portchannel))
    # Shutdown other uplinks except for the selected one
    for pc in portchannels:
        if pc != up_portchannel:
            cmd = "config interface shutdown {}".format(pc)
            rand_selected_dut.shell(cmd)
    # Update the LAG if it has more than one member
    pc_members = mg_facts['minigraph_portchannels'][up_portchannel]['members']
    if len(pc_members) > 1:
        # Update min_links
        min_link_cmd = "sonic-db-cli CONFIG_DB hset 'PORTCHANNEL|{}' 'min_links' 1".format(up_portchannel)
        rand_selected_dut.shell(min_link_cmd)
        # Delete to min_links
        cmds = "config portchannel member del {} {}".format(up_portchannel, pc_members[len(pc_members) - 1])
        rand_selected_dut.shell_cmds(cmds=cmds)
        # Ensure delete to complete before restarting service
        time.sleep(5)
        # Unmask the service
        rand_selected_dut.shell_cmds(cmds="systemctl unmask teamd")
        # Restart teamd
        rand_selected_dut.shell_cmds(cmds="systemctl restart teamd")
        _wait_portchannel_up(rand_selected_dut, up_portchannel)
    up_member = pc_members[0]

    yield mg_facts['minigraph_ptf_indices'][up_member]

    # Startup the uplinks that were shutdown
    for pc in portchannels:
        if pc != up_portchannel:
            cmd = "config interface startup {}".format(pc)
            rand_selected_dut.shell(cmd)
    # Restore the LAG
    if len(pc_members) > 1:
        cmds = [
            # Update min_links
            "sonic-db-cli CONFIG_DB hset 'PORTCHANNEL|{}' 'min_links' 2".format(up_portchannel),
            # Add back portchannel member
            "config portchannel member add {} {}".format(up_portchannel, pc_members[1]),
            # Unmask the service
            "systemctl unmask teamd",
            # Resart teamd
            "systemctl restart teamd"
        ]
        rand_selected_dut.shell_cmds(cmds=cmds)
        _wait_portchannel_up(rand_selected_dut, up_portchannel)


@pytest.fixture
def setup_mirror_session(rand_selected_dut, setup_uplink):
    """
    A function level fixture to add/remove a dummy mirror session.
    The mirror session is to trigger the issue. No packet is mirrored actually.
    """
    session_name = "dummy_session"
    # Nvidia platforms support only the gre_type 0x8949, which is 35145 in decimal.
    gre_type = 35145 if "mellanox" == rand_selected_dut.facts['asic_type'] else 1234
    cmd = "config mirror_session add {} 25.192.243.243 20.2.214.125 8 100 {} 0".format(session_name, gre_type)
    rand_selected_dut.shell(cmd=cmd)
    uplink_port_id = setup_uplink
    yield uplink_port_id

    cmd = "config mirror_session remove {}".format(session_name)
    rand_selected_dut.shell(cmd=cmd)


@pytest.fixture
def setup_active_active_ports(active_active_ports, rand_selected_dut, rand_unselected_dut,
                            config_active_active_dualtor_active_standby, tbinfo,              # noqa F811
                            validate_active_active_dualtor_setup):                         # noqa F811
    # As the test case test_encap_with_mirror_session is to verify the bounced back traffic, we need
    # to make dualtor active-active work in active-standby mode.
    if active_active_ports:
        logger.info("Configuring {} as active".format(rand_unselected_dut.hostname))
        logger.info("Configuring {} as standby".format(rand_selected_dut.hostname))
        config_active_active_dualtor_active_standby(rand_unselected_dut, rand_selected_dut, active_active_ports)

    return


@pytest.mark.disable_loganalyzer
def test_encap_with_mirror_session(rand_selected_dut, rand_selected_interface,              # noqa F811
                                   ptfadapter, tbinfo, setup_mirror_session,
                                   toggle_all_simulator_ports_to_rand_unselected_tor,       # noqa F811
                                   tunnel_traffic_monitor, skip_traffic_test,               # noqa F811
                                   setup_standby_ports_on_rand_selected_tor):               # noqa F811
    """
    A test case to verify the bounced back packet from Standby ToR to T1 doesn't have an unexpected vlan id (4095)
    The issue can happen if the bounced back packets egressed from the monitor port of mirror session
    Find more details in CSP CS00012263713.
    """
    # Since we have only 1 uplink, the source port is also the dest port
    src_port_id = setup_mirror_session
    _, server_ip = rand_selected_interface
    # Construct the packet to server
    pkt_to_server = testutils.simple_tcp_packet(
        eth_dst=rand_selected_dut.facts["router_mac"],
        ip_src="1.1.1.1",
        ip_dst=server_ip['server_ipv4'].split('/')[0]
    )
    logging.info("Sending packet from ptf t1 interface {}".format(src_port_id))
    inner_packet = pkt_to_server[scapy.all.IP].copy()
    inner_packet[IP].ttl -= 1
    if skip_traffic_test is True:
        logging.info("Skip following traffic test")
        return
    with tunnel_traffic_monitor(rand_selected_dut, inner_packet=inner_packet, check_items=()):
        testutils.send(ptfadapter, src_port_id, pkt_to_server)
