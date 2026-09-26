"""
This module tests ARP scenarios specific to dual ToR testbeds
"""
from contextlib import contextmanager
from ipaddress import ip_address, ip_interface
import logging
import random
import socket
import time
import pytest

import ptf.mask as mask
import ptf.testutils as testutils
from scapy.all import (
    Ether, IPv6, ICMPv6ND_NA, ICMPv6ND_NS,
    ICMPv6NDOptDstLLAddr, ICMPv6NDOptSrcLLAddr,
    in6_getnsmac, in6_getnsma, inet_ntop, inet_pton
)
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_upper_tor  # noqa: F401
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor  # noqa: F401
from tests.common.dualtor.dual_tor_utils import upper_tor_host, lower_tor_host, \
    show_muxcable_status, config_dualtor_arp_responder      # noqa: F401
from tests.common.dualtor.dual_tor_common import (  # noqa: F401
    active_active_ports, active_standby_ports, cable_type,
    CableType, mux_config
)
from tests.common.fixtures.ptfhost_utils import run_garp_service, \
    change_mac_addresses, run_icmp_responder, pause_garp_service  # noqa: F401

from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('dualtor')
]

logger = logging.getLogger(__name__)

FAILED = "FAILED"
INCOMPLETE = "INCOMPLETE"
STALE = "STALE"
REACHABLE = "REACHABLE"
NEIGH_FAILED_TABLE = "NEIGH_FAILED_TABLE"
NEIGH_FAILURE_WAIT_TIME = 5
NEIGH_RESOLUTION_TIMEOUT = 30
INCOMPLETE_STABILITY_TIME = 10
GARP_SERVICE_SETTLE_TIME = 3
CONFIGURED_SERVER = "configured-server"
UNCONFIGURED_VLAN = "unconfigured-vlan"


@pytest.fixture
def restore_mux_auto_config(duthosts):
    """
    Fixture to ensure ToRs have all mux interfaces set to auto after testing
    """

    yield

    for duthost in duthosts:
        duthost.shell("sudo config mux mode auto all")


@pytest.fixture
def pause_arp_update(duthosts):
    """
    Temporarily stop arp_update process during test cases

    Some test cases manually call arp_update so we use this fixture to pause it on
    the testbed to prevent interference with the test case
    """
    arp_update_stop_cmd = "docker exec -t swss supervisorctl stop arp_update"
    for duthost in duthosts:
        duthost.shell(arp_update_stop_cmd)

    yield

    arp_update_start_cmd = "docker exec -t swss supervisorctl start arp_update"
    for duthost in duthosts:
        duthost.shell(arp_update_start_cmd)


@pytest.fixture(params=['IPv4', 'IPv6'])
def selected_mux_port(request, mux_config):       # noqa: F811
    """Randomly select a mux port for testing."""
    ip_version = request.param
    selected_intf = random.choice(list(mux_config.values()))
    neigh_ip = ip_interface(selected_intf["SERVER"][ip_version]).ip
    selected_cable_type = selected_intf["SERVER"].get(
        "cable_type", "active-standby"
    )
    logger.info("Using {} as neighbor IP".format(neigh_ip))
    return selected_intf, neigh_ip, selected_cable_type


@pytest.fixture
def clear_neighbor_table(duthosts, pause_arp_update, pause_garp_service):       # noqa: F811
    logger.info("Clearing neighbor table on {}".format(duthosts))
    for duthost in duthosts:
        duthost.shell("sudo ip neigh flush all")

    return


@pytest.fixture
def pause_arp_responder(ptfhost):
    needs_resume = False
    result = ptfhost.shell(
        "supervisorctl status arp_responder",
        module_ignore_errors=True
    )
    if result['rc'] != 0:
        logger.warning("ARP responder is not configured on the PTF host")
    elif 'RUNNING' in result['stdout']:
        ptfhost.shell("supervisorctl stop arp_responder")
        needs_resume = True

    yield

    if needs_resume:
        ptfhost.shell("supervisorctl start arp_responder")


@pytest.fixture
def failed_neighbor_test_setup(
    selected_neighbor_port, duthosts, pause_arp_update,  # noqa: F811
    pause_garp_service, pause_arp_responder              # noqa: F811
):
    clear_test_neighbors(duthosts, selected_neighbor_port)
    pytest_assert(
        wait_until(
            5, 1, 0, verify_failed_neighbor_requests_absent,
            duthosts,
            selected_neighbor_port['vlan_name'],
            selected_neighbor_port['neighbor_ipv6']
        ),
        "Failed-neighbor request remained before test for {}".format(
            selected_neighbor_port['neighbor_ipv6']
        )
    )

    yield

    clear_test_neighbors(duthosts, selected_neighbor_port)
    pytest_assert(
        wait_until(
            5, 1, 0, verify_failed_neighbor_requests_absent,
            duthosts,
            selected_neighbor_port['vlan_name'],
            selected_neighbor_port['neighbor_ipv6']
        ),
        "Failed-neighbor request remained after test for {}".format(
            selected_neighbor_port['neighbor_ipv6']
        )
    )


def get_neighbor_entry(duthost, neigh_ip):
    ip_version = 'v4' if ip_address(neigh_ip).version == 4 else 'v6'
    neighbor_table = duthost.switch_arptable()['ansible_facts']['arptable']
    neighbor_entry = neighbor_table.get(ip_version, {}).get(str(ip_address(neigh_ip)))
    logger.info("Neighbor entry for {}: {}".format(neigh_ip, neighbor_entry))
    return neighbor_entry


def verify_neighbor_status(duthost, neigh_ip, expected_status):
    neighbor_entry = get_neighbor_entry(duthost, neigh_ip)
    return neighbor_entry is not None and \
        expected_status.lower() in neighbor_entry.get('state', '').lower()


def verify_neighbor_resolution(
    duthost, neigh_ip, expected_mac, expected_states
):
    neighbor_entry = get_neighbor_entry(duthost, neigh_ip)
    if neighbor_entry is None:
        return False

    state = neighbor_entry.get('state', '').upper()
    mac = neighbor_entry.get('macaddress', '').lower()
    return mac == expected_mac.lower() and any(
        expected_state in state for expected_state in expected_states
    )


def verify_all_neighbor_status(duthosts, neigh_ip, expected_status):
    return all(
        verify_neighbor_status(duthost, neigh_ip, expected_status)
        for duthost in duthosts
    )


def verify_all_neighbor_resolution(
    duthosts, neigh_ip, expected_mac, expected_states
):
    return all(
        verify_neighbor_resolution(
            duthost, neigh_ip, expected_mac, expected_states
        )
        for duthost in duthosts
    )


def verify_neighbor_stays_incomplete(duthosts, neigh_ip):
    deadline = time.time() + INCOMPLETE_STABILITY_TIME
    while time.time() < deadline:
        if not verify_all_neighbor_status(duthosts, neigh_ip, INCOMPLETE):
            return False
        remaining_time = deadline - time.time()
        if remaining_time > 0:
            time.sleep(min(1, remaining_time))

    return verify_all_neighbor_status(duthosts, neigh_ip, INCOMPLETE)


def verify_failed_neighbor_request(duthost, vlan_name, neigh_ip):
    key = "{}:{}:{}".format(
        NEIGH_FAILED_TABLE, vlan_name, ip_address(neigh_ip)
    )
    result = duthost.shell(
        "sonic-db-cli APPL_DB exists '{}'".format(key)
    )
    return result['rc'] == 0 and result['stdout'].strip() == '1'


def verify_failed_neighbor_ready(
    duthosts, vlan_name, neigh_ip, expected_status
):
    return all(
        verify_neighbor_status(duthost, neigh_ip, expected_status) and
        verify_failed_neighbor_request(duthost, vlan_name, neigh_ip)
        for duthost in duthosts
    )


def verify_failed_neighbor_requests_absent(
    duthosts, vlan_name, neigh_ip
):
    return all(
        not verify_failed_neighbor_request(duthost, vlan_name, neigh_ip)
        for duthost in duthosts
    )


def clear_test_neighbors(duthosts, neighbor_info):
    vlan_name = neighbor_info['vlan_name']
    for duthost in duthosts:
        for address_key in ('neighbor_ipv4', 'neighbor_ipv6'):
            neighbor_ip = neighbor_info[address_key]
            family = '-4' if ip_address(neighbor_ip).version == 4 else '-6'
            duthost.shell(
                "sudo ip {} neigh del {} dev {}".format(
                    family, neighbor_ip, vlan_name
                ),
                module_ignore_errors=True
            )


def clear_neighbor_entry(duthost, neigh_ip):
    family = '-4' if ip_address(neigh_ip).version == 4 else '-6'
    duthost.shell(
        "sudo ip {} neigh flush to {}".format(family, neigh_ip),
        module_ignore_errors=True
    )


def trigger_neighbor_failure(duthosts, neigh_ip):
    ping_cmd = "timeout 0.2 ping -c1 -W1 -i0.2 -n -q {}".format(neigh_ip)
    for duthost in duthosts:
        duthost.shell(ping_cmd, module_ignore_errors=True)


@contextmanager
def pause_nbrmgrd(duthosts):
    paused_duthosts = []

    def resume_nbrmgrd(duthost):
        if duthost not in paused_duthosts:
            return
        duthost.control_process("nbrmgrd", pause=False)
        paused_duthosts.remove(duthost)

    try:
        for duthost in duthosts:
            duthost.control_process("nbrmgrd", pause=True)
            paused_duthosts.append(duthost)
        yield resume_nbrmgrd
    finally:
        resume_errors = []
        for duthost in list(paused_duthosts):
            try:
                resume_nbrmgrd(duthost)
            except Exception as error:
                logger.exception(
                    "Failed to resume nbrmgrd on %s",
                    duthost.hostname
                )
                resume_errors.append((duthost.hostname, error))

        if resume_errors:
            failed_hosts = [hostname for hostname, _ in resume_errors]
            raise RuntimeError(
                "Failed to resume nbrmgrd on {}".format(failed_hosts)
            )


def build_unsolicited_na(neighbor_info):
    neighbor_ip = neighbor_info['neighbor_ipv6']
    server_mac = neighbor_info['server_mac']
    return (
        Ether(src=server_mac, dst='33:33:00:00:00:01') /
        IPv6(src=neighbor_ip, dst='ff02::1', hlim=255) /
        ICMPv6ND_NA(tgt=neighbor_ip, R=0, S=0, O=1) /
        ICMPv6NDOptDstLLAddr(lladdr=server_mac)
    )


def build_gratuitous_arp(neighbor_info):
    neighbor_ip = neighbor_info['neighbor_ipv4']
    server_mac = neighbor_info['server_mac']
    return testutils.simple_arp_packet(
        pktlen=60,
        eth_dst='ff:ff:ff:ff:ff:ff',
        eth_src=server_mac,
        arp_op=2,
        ip_snd=neighbor_ip,
        ip_tgt=neighbor_ip,
        hw_snd=server_mac,
        hw_tgt='ff:ff:ff:ff:ff:ff'
    )


def verify_neighbor_solicitations(
    ptfadapter, ptf_port_index, neigh_ip, expected_count, timeout=10
):
    neighbor_ip = str(ip_address(neigh_ip))
    multicast_ip_packed = in6_getnsma(
        inet_pton(socket.AF_INET6, neighbor_ip)
    )
    multicast_ip = inet_ntop(socket.AF_INET6, multicast_ip_packed)
    multicast_mac = in6_getnsmac(multicast_ip_packed)

    expected_packet = (
        Ether(src='00:00:00:00:00:00', dst=multicast_mac) /
        IPv6(src='::', dst=multicast_ip, hlim=255) /
        ICMPv6ND_NS(tgt=neighbor_ip) /
        ICMPv6NDOptSrcLLAddr(lladdr='00:00:00:00:00:00')
    )
    expected_packet = mask.Mask(expected_packet)
    expected_packet.set_do_not_care_packet(Ether, 'src')
    expected_packet.set_do_not_care_packet(IPv6, 'src')
    expected_packet.set_do_not_care_packet(IPv6, 'fl')
    expected_packet.set_do_not_care_packet(ICMPv6ND_NS, 'cksum')
    expected_packet.set_do_not_care_packet(
        ICMPv6NDOptSrcLLAddr, 'lladdr'
    )

    for _ in range(expected_count):
        testutils.verify_packet(
            ptfadapter,
            expected_packet,
            ptf_port_index,
            timeout=timeout
        )

    logger.info(
        "Received %s expected NS packet(s) for %s on PTF port %s",
        expected_count,
        neighbor_ip,
        ptf_port_index
    )


def get_neighbor_vlan_subnet(config_facts, neigh_ip):
    neighbor_ip = ip_address(neigh_ip)

    for vlan_name, vlan_addresses in config_facts['VLAN_INTERFACE'].items():
        for vlan_address in vlan_addresses:
            try:
                vlan_ip = ip_interface(vlan_address)
            except ValueError:
                continue

            if vlan_ip.version == neighbor_ip.version and \
                    neighbor_ip in vlan_ip.network:
                return vlan_name, vlan_ip.network

    pytest.fail(
        "Could not find a VLAN containing neighbor {}".format(neighbor_ip)
    )


def get_unconfigured_vlan_ip(
    config_facts, mux_ports_config, vlan_name, vlan_network
):
    excluded_ips = set()
    address_key = 'IPv4' if vlan_network.version == 4 else 'IPv6'

    for port_config in mux_ports_config.values():
        server_address = port_config['SERVER'].get(address_key)
        if server_address:
            excluded_ips.add(ip_interface(server_address).ip)

    for vlan_address in config_facts['VLAN_INTERFACE'][vlan_name]:
        try:
            excluded_ips.add(ip_interface(vlan_address).ip)
        except ValueError:
            continue

    for candidate in vlan_network.hosts():
        if candidate not in excluded_ips:
            return candidate

    pytest.fail(
        "Could not find an unconfigured IPv{} address in {}".format(
            vlan_network.version, vlan_network
        )
    )


@pytest.fixture(
    params=[CONFIGURED_SERVER, UNCONFIGURED_VLAN]
)
def selected_neighbor_port(
    request, cable_type, active_active_ports,               # noqa: F811
    active_standby_ports, mux_config, rand_selected_dut,    # noqa: F811
    tbinfo, ptfadapter
):
    mux_ports = (
        active_active_ports
        if cable_type == CableType.active_active
        else active_standby_ports
    )
    mux_port = random.choice(mux_ports)
    server_config = mux_config[mux_port]['SERVER']
    server_ipv4 = ip_interface(server_config['IPv4']).ip
    server_ipv6 = ip_interface(server_config['IPv6']).ip
    config_facts = rand_selected_dut.get_running_config_facts()
    vlan_name_v4, vlan_network_v4 = get_neighbor_vlan_subnet(
        config_facts, server_ipv4
    )
    vlan_name_v6, vlan_network_v6 = get_neighbor_vlan_subnet(
        config_facts, server_ipv6
    )
    pytest_assert(
        vlan_name_v4 == vlan_name_v6,
        "Configured server IPv4 and IPv6 addresses use different VLANs"
    )

    if request.param == UNCONFIGURED_VLAN:
        neighbor_ipv4 = get_unconfigured_vlan_ip(
            config_facts, mux_config, vlan_name_v4, vlan_network_v4
        )
        neighbor_ipv6 = get_unconfigured_vlan_ip(
            config_facts, mux_config, vlan_name_v6, vlan_network_v6
        )
    else:
        neighbor_ipv4 = server_ipv4
        neighbor_ipv6 = server_ipv6

    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    ptf_port_index = mg_facts['minigraph_ptf_indices'][mux_port]
    server_mac = ptfadapter.dataplane.get_mac(0, ptf_port_index)
    if isinstance(server_mac, bytes):
        server_mac = server_mac.decode()

    logger.info(
        "Using %s neighbor IPv4 %s and IPv6 %s on %s via PTF port %s",
        request.param,
        neighbor_ipv4,
        neighbor_ipv6,
        vlan_name_v4,
        ptf_port_index
    )

    return {
        'neighbor_type': request.param,
        'mux_port': mux_port,
        'ptf_port_index': ptf_port_index,
        'server_mac': server_mac,
        'neighbor_ipv4': str(neighbor_ipv4),
        'neighbor_ipv6': str(neighbor_ipv6),
        'vlan_name': vlan_name_v4
    }


def get_neighbor_test_duthosts(
    cable_type, duthosts, rand_selected_dut  # noqa: F811
):
    if cable_type == CableType.active_active:
        return list(duthosts)
    return [rand_selected_dut]


def test_proxy_arp_for_standby_neighbor(proxy_arp_enabled, ip_and_intf_info, restore_mux_auto_config,
                                        ptfadapter, packets_for_test, upper_tor_host,   # noqa: F811
                                        toggle_all_simulator_ports_to_upper_tor):   # noqa: F811
    """
    Send an ARP request or neighbor solicitation (NS) to the DUT for an IP address
    within the subnet of the DUT's VLAN that is routed via the IPinIP tunnel
    (i.e. that IP points to a standby neighbor)

    DUT should reply with an ARP reply or neighbor advertisement (NA) containing the DUT's own MAC

    Test steps:
    1. During setup, learn neighbor IPs on ToR interfaces using `run_garp_service` fixture
    2. Pick a learned IP address as the target IP and generate an ARP request/neighbor solicitation for it
    3. Set the interface this IP is learned on to standby. This will ensure the route for the IP points to the
       IPinIP tunnel
    4. Send the ARP request/NS packet to the ToR on some other active interface
    5. Expect the ToR to still proxy ARP for the IP and send an ARP reply/neighbor advertisement back, even though
       the route for the requested IP is pointing to the tunnel
    """
    # This should never fail since we are only running on dual ToR platforms
    pytest_require(proxy_arp_enabled, 'Proxy ARP not enabled for all VLANs, check dual ToR configuration')

    ptf_intf_ipv4_addr, _, ptf_intf_ipv6_addr, _, ptf_intf_index = ip_and_intf_info
    ip_version, outgoing_packet, expected_packet = packets_for_test

    if ip_version == 'v4':
        pytest_require(ptf_intf_ipv4_addr is not None, 'No IPv4 VLAN address configured on device')
        intf_name_cmd = "show arp | grep -m 1 '{}' | awk '{{ print $3 }}'".format(ptf_intf_ipv4_addr)
    elif ip_version == 'v6':
        pytest_require(ptf_intf_ipv6_addr is not None, 'No IPv6 VLAN address configured on device')
        intf_name_cmd = "show ndp | grep -m 1 '{}' | awk '{{ print $3 }}'".format(ptf_intf_ipv6_addr)

    # Find the interface on which the target IP is learned and set it to standby to force it to point to a tunnel route
    intf_name = upper_tor_host.shell(intf_name_cmd)['stdout']
    mux_mode_cmd = "sudo config mux mode standby {}".format(intf_name)
    upper_tor_host.shell(mux_mode_cmd)
    pytest_assert(wait_until(5, 1, 0, lambda: show_muxcable_status(upper_tor_host)[intf_name]['status'] == "standby"),
                  "Interface {} not standby on {}".format(intf_name, upper_tor_host))
    ptfadapter.dataplane.flush()
    testutils.send_packet(ptfadapter, ptf_intf_index, outgoing_packet)
    testutils.verify_packet(ptfadapter, expected_packet, ptf_intf_index, timeout=10)


def test_arp_update_for_failed_standby_neighbor(
    config_dualtor_arp_responder, selected_mux_port, pause_arp_update, pause_garp_service,       # noqa: F811
    toggle_all_simulator_ports_to_rand_selected_tor, rand_selected_dut, rand_unselected_dut     # noqa: F811
):
    """
    Test the standby ToR's ability to recover from having a failed neighbor entry

    Test steps:
    1. Create a reachable neighbor entry on the active TOR.
    2. Clear that same neighbor on the standby TOR.
    3. Create a failed neighbor entry on the standby TOR.
    4. Run arp_update on the active TOR.
    5. Confirm that the neighbor entries are resolved/reachable on both TORs.
    """
    _, neighbor_ip, selected_cable_type = selected_mux_port

    if selected_cable_type == "active-active":
        pytest.skip("Skip as the testcase is designed for active-standby mux port.")

    if ip_address(neighbor_ip).version == 6 and rand_unselected_dut.facts["asic_type"] == "vs":
        pytest.skip("Temporarily skipped to let the sonic-swss submodule be updated.")
    # We only use ping to trigger an ARP request from the kernel, so exit early to save time
    ping_cmd = "timeout 0.2 ping -c1 -W1 -i0.2 -n -q {}".format(neighbor_ip)

    clear_neighbor_entry(rand_selected_dut, neighbor_ip)

    rand_selected_dut.shell(ping_cmd, module_ignore_errors=True)
    pytest_assert(wait_until(
        NEIGH_RESOLUTION_TIMEOUT, 1, 0,
        lambda: verify_neighbor_status(
            rand_selected_dut, neighbor_ip, REACHABLE
        )
    ))

    # The active ToR's ARP reply/NA also resolves the neighbor on the standby ToR.
    # Explicitly clear it and create a FAILED neighbor entry on the standby to simulate the test scenario
    clear_neighbor_entry(rand_unselected_dut, neighbor_ip)
    pytest_assert(
        wait_until(
            5, 1, 0, lambda: get_neighbor_entry(rand_unselected_dut, neighbor_ip) is None
        ),
        "Neighbor {} was not cleared before testing".format(neighbor_ip)
    )

    expected_initial_state = FAILED if ip_address(neighbor_ip).version == 4 else INCOMPLETE
    rand_unselected_dut.shell(ping_cmd, module_ignore_errors=True)
    pytest_assert(wait_until(
        5, 1, 0,
        lambda: verify_neighbor_status(rand_unselected_dut, neighbor_ip, expected_initial_state)
    ))

    rand_selected_dut.shell("docker exec -t swss supervisorctl start arp_update")

    pytest_assert(wait_until(
        NEIGH_RESOLUTION_TIMEOUT, 1, 0,
        lambda: verify_neighbor_status(rand_unselected_dut, neighbor_ip, REACHABLE)
    ))


@pytest.mark.enable_active_active
def test_ipv6_na_before_failed_neighbor_moves_to_incomplete(
    cable_type, selected_neighbor_port,                    # noqa: F811
    failed_neighbor_test_setup,                            # noqa: F811
    duthosts, rand_selected_dut, ptfadapter
):
    """
    Verify a failed IPv6 neighbor is reprobed when an NA arrives before
    nbrmgrd processes the failure.

    Test steps:
    1. Pause nbrmgrd and create a FAILED neighbor entry.
    2. Send an unsolicited NA while the entry is still FAILED.
    3. Resume nbrmgrd.
    4. Verify nbrmgrd moves the entry to INCOMPLETE and sends an NS for the
       neighbor.
    5. Verify the entry remains INCOMPLETE for at least 10 seconds.
    """
    neighbor_ip = selected_neighbor_port['neighbor_ipv6']
    vlan_name = selected_neighbor_port['vlan_name']
    target_duthosts = get_neighbor_test_duthosts(
        cable_type, duthosts, rand_selected_dut
    )

    for test_duthost in target_duthosts:
        clear_test_neighbors(target_duthosts, selected_neighbor_port)

        pytest_assert(
            wait_until(
                5, 1, 0, verify_failed_neighbor_requests_absent,
                target_duthosts, vlan_name, neighbor_ip
            ),
            "Previous failed-neighbor request for {} was not removed".format(
                neighbor_ip
            )
        )

        with pause_nbrmgrd([test_duthost]) as resume_nbrmgrd:
            trigger_neighbor_failure([test_duthost], neighbor_ip)
            time.sleep(NEIGH_FAILURE_WAIT_TIME)

            ptfadapter.dataplane.flush()
            testutils.send_packet(
                ptfadapter,
                selected_neighbor_port['ptf_port_index'],
                build_unsolicited_na(selected_neighbor_port)
            )
            ptfadapter.dataplane.flush()

            resume_nbrmgrd(test_duthost)
            verify_neighbor_solicitations(
                ptfadapter,
                selected_neighbor_port['ptf_port_index'],
                neighbor_ip,
                1
            )
            pytest_assert(
                wait_until(
                    15, 1, 0, verify_failed_neighbor_ready,
                    [test_duthost], vlan_name, neighbor_ip, INCOMPLETE
                ),
                "Neighbor {} was not moved to INCOMPLETE through the "
                "failed-neighbor path on {}".format(
                    neighbor_ip, test_duthost.hostname
                )
            )
            pytest_assert(
                verify_neighbor_stays_incomplete(
                    [test_duthost], neighbor_ip
                ),
                "Neighbor {} did not remain INCOMPLETE for {} seconds "
                "on {}".format(
                    neighbor_ip,
                    INCOMPLETE_STABILITY_TIME,
                    test_duthost.hostname
                )
            )


@pytest.mark.enable_active_active
def test_ipv6_na_after_failed_neighbor_moves_to_incomplete(
    cable_type, selected_neighbor_port,                    # noqa: F811
    failed_neighbor_test_setup,                            # noqa: F811
    duthosts, rand_selected_dut, ptfadapter
):
    """
    Verify an unsolicited NA resolves a failed IPv6 neighbor after nbrmgrd
    moves it to INCOMPLETE.

    Test steps:
    1. Create a failed neighbor and wait for the retained failed-neighbor
       request.
    2. Verify nbrmgrd moves the kernel entry to INCOMPLETE.
    3. Verify the entry remains INCOMPLETE for at least 10 seconds.
    4. Send an unsolicited NA.
    5. Verify the neighbor becomes STALE with the advertised MAC.
    """
    neighbor_ip = selected_neighbor_port['neighbor_ipv6']
    vlan_name = selected_neighbor_port['vlan_name']
    target_duthosts = get_neighbor_test_duthosts(
        cable_type, duthosts, rand_selected_dut
    )

    trigger_neighbor_failure(target_duthosts, neighbor_ip)
    pytest_assert(
        wait_until(
            15, 1, 0, verify_failed_neighbor_ready,
            target_duthosts, vlan_name, neighbor_ip, INCOMPLETE
        ),
        "Neighbor {} was not moved to INCOMPLETE through the failed-neighbor "
        "path on all target ToRs".format(neighbor_ip)
    )
    pytest_assert(
        verify_neighbor_stays_incomplete(target_duthosts, neighbor_ip),
        "Neighbor {} did not remain INCOMPLETE for {} seconds on all target "
        "ToRs".format(neighbor_ip, INCOMPLETE_STABILITY_TIME)
    )

    testutils.send_packet(
        ptfadapter,
        selected_neighbor_port['ptf_port_index'],
        build_unsolicited_na(selected_neighbor_port)
    )
    pytest_assert(
        wait_until(
            5, 1, 0, verify_all_neighbor_resolution,
            target_duthosts, neighbor_ip,
            selected_neighbor_port['server_mac'], (STALE,)
        ),
        "Neighbor {} did not become STALE with MAC {} on all target "
        "ToRs".format(neighbor_ip, selected_neighbor_port['server_mac'])
    )
    pytest_assert(
        wait_until(
            5, 1, 0, verify_failed_neighbor_requests_absent,
            target_duthosts, vlan_name, neighbor_ip
        ),
        "Failed-neighbor request for {} remained after resolution".format(
            neighbor_ip
        )
    )


@pytest.mark.enable_active_active
def test_ipv4_garp_resolves_failed_neighbor(
    cable_type, selected_neighbor_port,                    # noqa: F811
    failed_neighbor_test_setup,                            # noqa: F811
    duthosts, rand_selected_dut, ptfadapter
):
    """
    Verify a gratuitous ARP reply resolves an IPv4 neighbor that is in FAILED
    state.

    Test steps:
    1. Create and verify a FAILED IPv4 neighbor entry.
    2. Send a broadcast gratuitous ARP reply for the neighbor.
    3. Verify the advertised MAC is installed in a usable neighbor state.
    """
    neighbor_ip = selected_neighbor_port['neighbor_ipv4']
    target_duthosts = get_neighbor_test_duthosts(
        cable_type, duthosts, rand_selected_dut
    )

    trigger_neighbor_failure(target_duthosts, neighbor_ip)
    pytest_assert(
        wait_until(
            15, 1, 0, verify_all_neighbor_status,
            target_duthosts, neighbor_ip, FAILED
        ),
        "Neighbor {} did not reach FAILED on all target ToRs".format(
            neighbor_ip
        )
    )

    testutils.send_packet(
        ptfadapter,
        selected_neighbor_port['ptf_port_index'],
        build_gratuitous_arp(selected_neighbor_port)
    )
    pytest_assert(
        wait_until(
            5, 1, 0, verify_all_neighbor_resolution,
            target_duthosts, neighbor_ip,
            selected_neighbor_port['server_mac'], (REACHABLE, STALE)
        ),
        "Neighbor {} did not resolve to MAC {} on all target ToRs".format(
            neighbor_ip,
            selected_neighbor_port['server_mac']
        )
    )


def test_standby_unsolicited_neigh_learning(
    config_dualtor_arp_responder, selected_mux_port, clear_neighbor_table,                      # noqa: F811
    toggle_all_simulator_ports_to_rand_selected_tor, rand_selected_dut, rand_unselected_dut,    # noqa: F811
    setup_standby_ports_on_rand_unselected_tor                                                  # noqa: F811
):
    """
    Test the standby ToR's ability to perform unsolicited neighbor learning (GARP and unsolicited NA)

    Test steps:
    1. Create a reachable neighbor entry on the active ToR only
    2. Flush any existing neighbor entry on the standby TOR.
    3. Run arp_update on the active ToR
    4. Confirm that the standby ToR learned the entry and it is REACHABLE
    """
    neighbor_ip = selected_mux_port[1]
    if ip_address(neighbor_ip).version == 6 and rand_unselected_dut.facts["asic_type"] == "vs":
        pytest.skip("Temporarily skipped to let the sonic-swss submodule be updated.")
    ping_cmd = "timeout 0.2 ping -c1 -W1 -i0.2 -n -q {}".format(neighbor_ip)

    clear_neighbor_entry(rand_selected_dut, neighbor_ip)
    rand_selected_dut.shell(ping_cmd, module_ignore_errors=True)
    pytest_assert(wait_until(5, 1, 0, lambda: verify_neighbor_status(rand_selected_dut, neighbor_ip, REACHABLE)))
    clear_neighbor_entry(rand_unselected_dut, neighbor_ip)

    arp_update_cmd = "docker exec -t swss supervisorctl start arp_update"
    rand_selected_dut.shell(arp_update_cmd)

    pytest_assert(wait_until(5, 1, 0, lambda: verify_neighbor_status(rand_unselected_dut, neighbor_ip, REACHABLE)))
