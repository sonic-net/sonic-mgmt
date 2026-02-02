# Test cases to validate functionality of the arp_update script

import logging
import ptf.testutils as testutils
import pytest
import random

from tests.arp.arp_utils import clear_dut_arp_cache, fdb_cleanup, get_dut_mac, fdb_has_mac, get_first_vlan_ipv4
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor  # noqa: F401
from tests.common.fixtures.ptfhost_utils import setup_vlan_arp_responder, run_icmp_responder  # noqa: F401
from tests.common.helpers.assertions import pytest_assert as pt_assert
from tests.common.helpers.constants import PTF_TIMEOUT
from tests.common.utilities import wait_until
from tests.common.dualtor.dual_tor_utils import mux_cable_server_ip

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0")
]


@pytest.fixture
def setup(rand_selected_dut):
    cmds = [
        "docker exec swss supervisorctl stop arp_update",
        "ip neigh flush all"
    ]
    rand_selected_dut.shell_cmds(cmds)
    yield
    cmds[0] = "docker exec swss supervisorctl start arp_update"
    # rand_selected_dut.shell_cmds(cmds)


def neighbor_learned(dut, target_ip):
    neigh_output = dut.shell(f"ip neigh show {target_ip}")['stdout'].strip()
    logger.info(f"DUT neighbor entry: {neigh_output}")
    return neigh_output and ("REACHABLE" in neigh_output or "STALE" in neigh_output)


def appl_db_neighbor_syncd(dut, vlan_name, target_ip, exp_mac):
    asic_db_mac = dut.shell(f"sonic-db-cli APPL_DB hget 'NEIGH_TABLE:{vlan_name}:{target_ip}' 'neigh'")['stdout']
    logger.info(f"DUT neighbor mac: {asic_db_mac} of entry {vlan_name}:{target_ip}")
    return exp_mac.lower() == asic_db_mac.lower()


def ip_version_string(version):
    return f"ipv{version}"


@pytest.mark.parametrize("ip_version", [4, 6], ids=ip_version_string)
def test_kernel_asic_mac_mismatch(
    setup_standby_ports_on_non_enum_rand_one_per_hwsku_frontend_host_m_unconditionally,
    toggle_all_simulator_ports_to_rand_selected_tor,  # noqa: F811
    rand_selected_dut, ip_version, setup_vlan_arp_responder,  # noqa: F811
    tbinfo
):
    vlan_name, ipv4_base, ipv6_base, ip_offset = setup_vlan_arp_responder
    if 'dualtor' in tbinfo['topo']['name']:
        servers = mux_cable_server_ip(rand_selected_dut)
        intf = random.choice(list(servers))
        if ip_version == 4:
            target_ip = servers[intf]['server_ipv4'].split('/')[0]
        else:
            target_ip = servers[intf]['server_ipv6'].split('/')[0]
    else:
        if ip_version == 4:
            target_ip = ipv4_base.ip + ip_offset
        else:
            target_ip = ipv6_base.ip + ip_offset

    rand_selected_dut.shell(f"ping -c1 -W1 {target_ip}; true")

    wait_until(10, 1, 0, neighbor_learned, rand_selected_dut, target_ip)

    neighbor_info = rand_selected_dut.shell(f"ip neigh show {target_ip}")["stdout"].split()
    pt_assert(neighbor_info[2] == vlan_name)

    wait_until(5, 1, 0, appl_db_neighbor_syncd, rand_selected_dut, vlan_name, target_ip, neighbor_info[4])

    logger.info(f"Neighbor {target_ip} has been learned, APPL_DB and kernel are in sync")

    logger.info("Manually setting APPL_DB MAC address")
    rand_selected_dut.shell(
        f"sonic-db-cli APPL_DB hset 'NEIGH_TABLE:{vlan_name}:{target_ip}' 'neigh' '00:00:00:00:00:00'"
    )
    asic_db_mac = rand_selected_dut.shell(
        f"sonic-db-cli APPL_DB hget 'NEIGH_TABLE:{vlan_name}:{target_ip}' 'neigh'"
    )['stdout']
    pt_assert(neighbor_info[4].lower() != asic_db_mac.lower())
    logger.info("APPL_DB and kernel are out of sync (expected)")

    rand_selected_dut.shell("docker exec swss supervisorctl start arp_update")

    wait_until(10, 1, 0, lambda dut, ip: not neighbor_learned(dut, ip), rand_selected_dut, target_ip)


def test_ptf_arp_learns_mac(
    rand_selected_dut,
    ptfadapter,
    config_facts,
    ip_and_intf_info,
    tbinfo
):
    """
    After fdb_cleanup and clearing DUT ARP cache,
    simulate ARP request from PTF to DUT,
    verify DUT replies and learns PTF MAC in FDB
    """
    # Setup PTF interface info
    ptf_intf_ipv4_addr, _, _, _, ptf_intf_index = ip_and_intf_info
    ptf_intf_mac = ptfadapter.dataplane.get_mac(0, ptf_intf_index)
    if isinstance(ptf_intf_mac, (bytes, bytearray)):
        ptf_intf_mac = ptf_intf_mac.decode()

    # Setup DUT info
    duthost = rand_selected_dut
    dut_mac = get_dut_mac(duthost, config_facts, tbinfo)
    vlan_name, dut_ipv4 = get_first_vlan_ipv4(config_facts)
    logger.info("DUT VLAN IPv4: {}".format(dut_ipv4))

    # Cleanup FDB and DUT ARP cache
    fdb_cleanup(duthost)
    clear_dut_arp_cache(duthost)
    ptfadapter.dataplane.flush()

    # Simulate ARP request from PTF to DUT
    arp_req = testutils.simple_arp_packet(
        pktlen=60,
        eth_dst='ff:ff:ff:ff:ff:ff',
        eth_src=ptf_intf_mac,
        vlan_pcp=0,
        arp_op=1,
        ip_snd=str(ptf_intf_ipv4_addr),
        ip_tgt=str(dut_ipv4),
        hw_snd=ptf_intf_mac,
        hw_tgt='ff:ff:ff:ff:ff:ff'
    )

    # Expected ARP reply packet from DUT
    arp_reply = testutils.simple_arp_packet(
        eth_dst=ptf_intf_mac,
        eth_src=dut_mac,
        arp_op=2,
        ip_snd=str(dut_ipv4),
        ip_tgt=str(ptf_intf_ipv4_addr),
        hw_snd=dut_mac,
        hw_tgt=ptf_intf_mac
    )

    logger.info("Sending ARP request for target {} from PTF interface {}".format(dut_ipv4, ptf_intf_index))
    # Send ARP request and verify ARP reply
    testutils.send_packet(ptfadapter, ptf_intf_index, arp_req)
    testutils.verify_packet(ptfadapter, arp_reply, ptf_intf_index, timeout=PTF_TIMEOUT)

    # Confirm MAC is learned on DUT FDB
    pt_assert(
        wait_until(10, 1, 0, fdb_has_mac, duthost, ptf_intf_mac),
        "FDB did not learn PTF MAC after ARP request"
    )


def test_dut_arping_learns_mac(
    rand_selected_dut,
    ptfadapter,
    config_facts,
    ip_and_intf_info,
    tbinfo,
    setup_vlan_arp_responder  # noqa: F811
):
    """
    After fdb_cleanup and clearing DUT ARP cache,
    enable PTF to respond to arping,
    simulate arping from DUT to PTF,
    verify DUT learns PTF MAC in FDB
    """
    # Setup PTF responder info
    vlan_name, ipv4_base, _, ip_offset = setup_vlan_arp_responder
    ptf_ip = str(ipv4_base.ip + ip_offset)
    logger.info("PTF responder IP (setup_vlan_arp_responder): {}".format(ptf_ip))

    # Setup PTF interface info
    ptf_intf_ipv4_addr, _, _, _, ptf_intf_index = ip_and_intf_info
    ptf_intf_mac = ptfadapter.dataplane.get_mac(0, ptf_intf_index)
    if isinstance(ptf_intf_mac, (bytes, bytearray)):
        ptf_intf_mac = ptf_intf_mac.decode()

    # Setup DUT info
    duthost = rand_selected_dut
    vlan_name, dut_ipv4 = get_first_vlan_ipv4(config_facts)
    logger.info("DUT VLAN IPv4: {}".format(dut_ipv4))

    # Cleanup FDB and DUT ARP cache
    fdb_cleanup(duthost)
    clear_dut_arp_cache(duthost)
    ptfadapter.dataplane.flush()

    # Simulate arping from DUT to PTF interface
    duthost.shell(f"arping -c 1 -I {vlan_name} {ptf_ip}")

    # Confirm MAC is learned on DUT FDB
    pt_assert(
        wait_until(10, 1, 0, fdb_has_mac, duthost, ptf_intf_mac),
        "FDB did not learn PTF MAC after DUT arping"
    )


def test_dut_ping_learns_mac(
    rand_selected_dut,
    ptfadapter,
    config_facts,
    ip_and_intf_info,
    tbinfo
):
    """
    After fdbclear on DUT,
    PTF sends an ARP request to DUT,
    DUT replies to ARP request,
    PTF then sends ICMP echo request to DUT,
    Verify DUT learns PTF MAC in FDB.
    """
    # Get PTF interface info
    ptf_intf_ipv4_addr, _, _, _, ptf_intf_index = ip_and_intf_info
    ptf_intf_mac = ptfadapter.dataplane.get_mac(0, ptf_intf_index)
    if isinstance(ptf_intf_mac, (bytes, bytearray)):
        ptf_intf_mac = ptf_intf_mac.decode()

    # Get DUT info
    duthost = rand_selected_dut
    dut_mac = get_dut_mac(duthost, config_facts, tbinfo)
    vlan_name, dut_ipv4 = get_first_vlan_ipv4(config_facts)
    logger.info("DUT VLAN IPv4: {}".format(dut_ipv4))

    # Clear FDB and ARP cache on DUT
    fdb_cleanup(duthost)
    clear_dut_arp_cache(duthost)
    ptfadapter.dataplane.flush()

    # Step 1: Send ARP request from PTF to DUT (broadcast)
    arp_req = testutils.simple_arp_packet(
        pktlen=60,
        eth_dst='ff:ff:ff:ff:ff:ff',
        eth_src=ptf_intf_mac,
        vlan_pcp=0,
        arp_op=1,
        ip_snd=str(ptf_intf_ipv4_addr),
        ip_tgt=str(dut_ipv4),
        hw_snd=ptf_intf_mac,
        hw_tgt='ff:ff:ff:ff:ff:ff'
    )

    # Step 2: Expect ARP reply from DUT
    arp_reply = testutils.simple_arp_packet(
        eth_dst=ptf_intf_mac,
        eth_src=dut_mac,
        arp_op=2,
        ip_snd=str(dut_ipv4),
        ip_tgt=str(ptf_intf_ipv4_addr),
        hw_snd=dut_mac,
        hw_tgt=ptf_intf_mac
    )

    testutils.send_packet(ptfadapter, ptf_intf_index, arp_req)
    testutils.verify_packet(ptfadapter, arp_reply, ptf_intf_index, timeout=PTF_TIMEOUT)

    # Confirm neighbor entry is created on DUT
    pt_assert(
        wait_until(10, 1, 0, neighbor_learned, duthost, str(ptf_intf_ipv4_addr)),
        "DUT ARP table not updated for PTF IP after ICMP"
    )

    # Step 3: Send ICMP echo from PTF to DUT (unicast to DUT MAC)
    icmp_req = testutils.simple_icmp_packet(
        eth_dst=dut_mac,
        eth_src=ptf_intf_mac,
        ip_src=str(ptf_intf_ipv4_addr),
        ip_dst=str(dut_ipv4),
        icmp_type=8,
        icmp_code=0
    )
    testutils.send_packet(ptfadapter, ptf_intf_index, icmp_req)

    # Confirm MAC is learned on DUT FDB
    pt_assert(
        wait_until(10, 1, 0, fdb_has_mac, duthost, ptf_intf_mac),
        "FDB did not learn PTF MAC after PTF ARP + ICMP"
    )
