import pytest
import time
import logging
import ipaddress
import random
import re

from tests.common import constants
from datetime import datetime, timedelta
from tests.common.utilities import skip_release
from tests.common.utilities import wait_tcp_connection
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from bgp_helpers import update_routes
from tests.generic_config_updater.test_bgp_speaker import get_bgp_speaker_runningconfig
from tests.generic_config_updater.gu_utils import apply_patch, expect_op_success
from tests.generic_config_updater.gu_utils import generate_tmpfile, delete_tmpfile
from tests.generic_config_updater.gu_utils import (
    create_checkpoint,
    delete_checkpoint,
    rollback_or_reload,
)
from tests.common.dualtor.mux_simulator_control import toggle_all_simulator_ports_to_rand_selected_tor_m    # noqa F401


pytestmark = [pytest.mark.topology("t0")]


@pytest.fixture(autouse=True, scope="module")
def check_image_version(duthost):
    """Skips this test if the SONiC image installed on DUT is older than 202205

    Args:
        duthost: Hostname of DUT.

    Returns:
        None.
    """
    skip_release(duthost, ["201811", "201911", "202012", "202106", "202111"])


logger = logging.getLogger(__name__)

BGPSLB = "BGPSLBPassive"
BGPSLB_2 = "BGPSLBPassive2"
BGPSLB_V6 = "BGPSLBPassiveV6"
BGPSLB_V6_2 = "BGPSLBPassiveV62"
BGP_SRC_ADDR_RE = "neighbor {} update-source {}"
BGP_IP_RANGE_RE = "bgp listen range {} peer-group {}"
NEIGHBOR_ASN_LIST = [64523, 65511]
NEIGHBOR_PORT_LIST = [9000, 9001]
PREFIX = "3.3.3.0/24"
PREFIX_2 = "5.5.5.0/24"
PREFIX_V6 = "2001:3:3:3::0/64"
PREFIX_V6_2 = "2001:5:5:5::0/64"


def lo_intfs(duthost, tbinfo):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    lo_int = lo_int_v6 = []
    for lo_interface in mg_facts["minigraph_lo_interfaces"]:
        if ipaddress.ip_address(lo_interface["addr"]).version == 4:
            lo_int = lo_interface
        elif ipaddress.ip_address(lo_interface["addr"]).version == 6:
            lo_int_v6 = lo_interface
        if lo_int and lo_int_v6:
            return lo_int, lo_int_v6
    pytest_assert(True, "Required ipv4 and ipv6 to start the test")


@pytest.fixture(autouse=True)
def setup_env(
    duthosts, rand_one_dut_hostname, toggle_all_simulator_ports_to_rand_selected_tor_m, # noqa F811
):
    """
    Setup/teardown fixture for bgp speaker config
    Args:
        duthosts: list of DUTs.
        rand_selected_dut: The fixture returns a randomly selected DuT.
    """
    logger.info("Save bgp speaker configuration on %s" % (rand_one_dut_hostname))
    duthost = duthosts[rand_one_dut_hostname]
    original_bgp_speaker_config = get_bgp_speaker_runningconfig(duthost)
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolled back to original checkpoint")
        rollback_or_reload(duthost)
        # sleep for a short time, waiting for config apply
        time.sleep(30)
        current_bgp_speaker_config = get_bgp_speaker_runningconfig(duthost)
        pytest_assert(
            set(original_bgp_speaker_config) == set(current_bgp_speaker_config),
            "bgp speaker config are not suppose to change after test org: {}, cur: {}".format(
                original_bgp_speaker_config, current_bgp_speaker_config
            ),
        )
    finally:
        delete_checkpoint(duthost)


class BgpDualAsn:
    def __init__(self):
        self.local_asn = ""
        self.peer_subnets = []
        self.peer_subnets_v6 = []
        self.peer_addrs = []
        self.peer_addrs_v6 = []

    def __gen_vlan_subnets(self, mg_facts):
        # Generate peer ipv4 addresses
        vlan_network = ipaddress.IPv4Interface(
            "%s/%s"
            % (
                mg_facts["minigraph_vlan_interfaces"][0]["addr"],
                mg_facts["minigraph_vlan_interfaces"][0]["prefixlen"],
            )
        ).network
        peer_subnets = [
            list(vlan_network.subnets())[0],
            list(vlan_network.subnets())[1],
        ]
        logger.info(
            "Generated two bgp speeker ip subnets: %s, %s"
            % (peer_subnets[0], peer_subnets[1])
        )

        # Generate peer ipv6 addresses
        vlan_network_v6 = ipaddress.IPv6Interface(
            "%s/%s"
            % (
                mg_facts["minigraph_vlan_interfaces"][1]["addr"],
                mg_facts["minigraph_vlan_interfaces"][1]["prefixlen"],
            )
        ).network
        peer_subnets_v6 = [
            list(vlan_network_v6.subnets())[0],
            list(vlan_network_v6.subnets())[1],
        ]

        logger.info(
            "Generated two bgp speeker ipv6 subnets: %s, %s"
            % (peer_subnets_v6[0], peer_subnets_v6[1])
        )
        return peer_subnets, peer_subnets_v6

    def dual_asn_setup(
        self, duthosts, rand_one_dut_hostname, ptfhost, localhost, tbinfo
    ):
        logger.info("########### Setup for bgp dual asn testing ###########")
        duthost = duthosts[rand_one_dut_hostname]
        # TBD, for dual-tor add toggle all to this duthost

        mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

        self.local_asn = mg_facts["minigraph_bgp_asn"]

        self.peer_subnets, self.peer_subnets_v6 = self.__gen_vlan_subnets(mg_facts)
        self.peer_addrs = [
            str(
                ipaddress.IPv4Address(
                    random.randint(
                        int(self.peer_subnets[0].network_address),
                        int(self.peer_subnets[0].broadcast_address),
                    )
                )
            ),
            str(
                ipaddress.IPv4Address(
                    random.randint(
                        int(self.peer_subnets[1].network_address),
                        int(self.peer_subnets[1].broadcast_address),
                    )
                )
            ),
        ]
        self.peer_addrs_v6 = [
            str(
                ipaddress.IPv6Address(
                    random.randint(
                        int(self.peer_subnets_v6[0].network_address),
                        int(self.peer_subnets_v6[0].broadcast_address),
                    )
                )
            ),
            str(
                ipaddress.IPv6Address(
                    random.randint(
                        int(self.peer_subnets_v6[1].network_address),
                        int(self.peer_subnets_v6[1].broadcast_address),
                    )
                )
            ),
        ]

        logger.info(
            "Generated two bgp speeker ip: %s, %s, ipv6: %s, %s"
            % (
                self.peer_addrs[0],
                self.peer_addrs[1],
                self.peer_addrs_v6[0],
                self.peer_addrs_v6[1],
            )
        )

        self.lo, self.lo6 = lo_intfs(duthost, tbinfo)

        vlan_addr = mg_facts["minigraph_vlan_interfaces"][0]["addr"]
        vlan_addr6 = mg_facts["minigraph_vlan_interfaces"][1]["addr"]

        # find two vlan member interfaces
        vlan_ports = []
        for i in range(0, 1):
            vlan_ports.append(
                mg_facts["minigraph_ptf_indices"][
                    mg_facts["minigraph_vlans"][
                        mg_facts["minigraph_vlan_interfaces"][0]["attachto"]
                    ]["members"][i]
                ]
            )
        if "backend" in tbinfo["topo"]["name"]:
            vlan_id = mg_facts["minigraph_vlans"][
                mg_facts["minigraph_vlan_interfaces"][0]["attachto"]
            ]["vlanid"]
            self.ptf_ports = [
                ("eth%s" % _) + constants.VLAN_SUB_INTERFACE_SEPARATOR + vlan_id
                for _ in vlan_ports
            ]
        else:
            self.ptf_ports = ["eth%s" % _ for _ in vlan_ports]
        logger.info("vlan_ports: %s, ptf_ports: %s" % (str(vlan_ports), self.ptf_ports))

        # setup ip addr and routes on ptf
        # config ip addresses on one ptf port to avoid FDB, ND Cache mismatch issue
        for i in range(0, 2):
            ptfhost.shell(
                "ip addr add %s/%d dev %s:%s"
                % (
                    self.peer_addrs[i],
                    self.peer_subnets[i].prefixlen,
                    self.ptf_ports[0],
                    i,
                )
            )
            ptfhost.shell(
                "ip -6 addr add %s/%d dev %s:%s"
                % (
                    self.peer_addrs_v6[i],
                    self.peer_subnets_v6[i].prefixlen,
                    self.ptf_ports[0],
                    i,
                )
            )

        ptfhost.shell("ip route flush %s/%d" % (self.lo["addr"], self.lo["prefixlen"]))
        try:
            ptfhost.shell(
                "ip route add %s/%d via %s"
                % (self.lo["addr"], self.lo["prefixlen"], vlan_addr)
            )
            ptfhost.shell(
                "ip -6 route add %s/%d via %s"
                % (self.lo6["addr"], self.lo6["prefixlen"], vlan_addr6)
            )
        except Exception:
            logger.info("route may already exists, ignore error !")

        # Issue a ping command to populate entry for next_hop
        for port in self.ptf_ports:
            ptfhost.shell("arping %s -I %s -c 6" % (vlan_addr, port))

    def dual_asn_teardown(self, duthosts, rand_one_dut_hostname, ptfhost):
        logger.info("########### Teardown for bgp dual-asn testing ###########")

        duthost = duthosts[rand_one_dut_hostname]

        for i in range(0, 2):
            ptfhost.exabgp(name="bgps%d" % i, state="absent")
        logger.info("exabgp stopped")

        for port in self.ptf_ports:
            ptfhost.shell("ip addr flush dev {} scope global".format(port))
        duthost.command("sonic-clear arp")
        duthost.command("sonic-clear ndp")
        duthost.command("sonic-clear fdb all")
        duthost.command("ip -6 neigh flush all")
        # config_reload(duthost, wait=60)
        logger.info(
            "########### teardown finished for bgp dual-asn testing ###########"
        )


def bgp_peer_range_config_cleanup(duthost):
    """Clean up bgp speaker config to avoid ip range conflict"""
    cmds = 'sonic-db-cli CONFIG_DB keys "BGP_PEER_RANGE|*" | xargs -r sonic-db-cli CONFIG_DB del'
    output = duthost.shell(cmds)
    pytest_assert(not output["rc"], "bgp speaker config cleanup failed.")


def bgp_peer_range_add_config(
    duthost,
    lo,
    lo6,
    ip_range_name,
    ip_range,
    ipv6_range_name,
    ipv6_range,
    peer_asn,
    ip_range_name_2=None,
    ip_range_2=None,
    ipv6_range_name_2=None,
    ipv6_range_2=None,
    peer_asn_2=None,
):
    """Test to add desired v4&v6 bgp peer config"""
    json_patch = []
    if ip_range_name_2 is None:
        json_patch = [
            {
                "op": "add",
                "path": "/BGP_PEER_RANGE",
                "value": {
                    "{}".format(ip_range_name): {
                        "ip_range": ["{}".format(ip_range)],
                        "name": "{}".format(ip_range_name),
                        "src_address": "{}".format(lo["addr"]),
                        "peer_asn": "{}".format(peer_asn),
                    },
                    "{}".format(ipv6_range_name): {
                        "ip_range": ["{}".format(ipv6_range)],
                        "name": "{}".format(ipv6_range_name),
                        "src_address": "{}".format(lo6["addr"]),
                        "peer_asn": "{}".format(peer_asn),
                    },
                },
            }
        ]
    else:
        # following is add-on config change
        if ipv6_range_2 is None:
            json_patch = [
                {
                    "op": "add",
                    "path": "/BGP_PEER_RANGE/{}".format(ip_range_name_2),
                    "value": {
                        "ip_range": ["{}".format(ip_range_2)],
                        "name": "{}".format(ip_range_name_2),
                        "src_address": "{}".format(lo["addr"]),
                        "peer_asn": "{}".format(peer_asn_2),
                    },
                }
            ]
        else:
            json_patch = [
                {
                    "op": "add",
                    "path": "/BGP_PEER_RANGE/{}".format(ipv6_range_name_2),
                    "value": {
                        "ip_range": ["{}".format(ipv6_range_2)],
                        "name": "{}".format(ipv6_range_name_2),
                        "src_address": "{}".format(lo6["addr"]),
                        "peer_asn": "{}".format(peer_asn_2),
                    },
                }
            ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        bgp_config = duthost.shell("show runningconfiguration bgp")["stdout"]
        pytest_assert(
            re.search(BGP_SRC_ADDR_RE.format(ip_range_name, lo["addr"]), bgp_config)
            and re.search(
                BGP_SRC_ADDR_RE.format(ipv6_range_name, lo6["addr"]), bgp_config
            ),
            "Failed to update bgp speaker src address.",
        )
        pytest_assert(
            re.search(BGP_IP_RANGE_RE.format(ip_range, ip_range_name), bgp_config)
            and re.search(
                BGP_IP_RANGE_RE.format(ipv6_range, ipv6_range_name), bgp_config
            ),
            "Failed to add bgp speaker ip range.",
        )

    finally:
        delete_tmpfile(duthost, tmpfile)


def bgp_peer_range_delete_config(
    duthost, ip_range_name, ip_range, ipv6_range_name, ipv6_range
):

    json_patch = [
        {"op": "remove", "path": "/BGP_PEER_RANGE/{}".format(ip_range_name)},
        {"op": "remove", "path": "/BGP_PEER_RANGE/{}".format(ipv6_range_name)},
    ]

    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile {}".format(tmpfile))

    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        expect_op_success(duthost, output)

        bgp_config = duthost.shell("show runningconfiguration bgp")["stdout"]
        pytest_assert(
            not re.search(BGP_IP_RANGE_RE.format(ip_range_name, ip_range), bgp_config)
            and not re.search(
                BGP_IP_RANGE_RE.format(ipv6_range_name, ipv6_range), bgp_config
            ),
            "Failed to remove bgp speaker dummy ip range.",
        )

    finally:
        delete_tmpfile(duthost, tmpfile)


def start_peer_ipv4_bgp_session(
    ptfhost, localhost, lo_addr, local_asn, peer_addr, peer_asn, bgp_index, port
):
    logger.info("Start exabgp %d on ptf" % bgp_index)
    ptfhost.exabgp(
        name="bgps%d" % bgp_index,
        state="started",
        local_ip=peer_addr,
        router_id=peer_addr,
        peer_ip=lo_addr,
        local_asn=peer_asn,
        peer_asn=local_asn,
        port=port,
    )

    # check exabgp http_api port is ready
    if not wait_tcp_connection(localhost, ptfhost.mgmt_ip, port, timeout_s=60):
        pytest.fail(f"exabgp http_api {ptfhost.mgmt_ip} port {port} is not ready")


def verify_bgp_session(duthost, bgp_neighbor):
    """Verify the bgp session to the DUT is established."""
    bgp_facts = duthost.bgp_facts()["ansible_facts"]
    return (
        bgp_neighbor in bgp_facts["bgp_neighbors"]
        and bgp_facts["bgp_neighbors"][bgp_neighbor]["state"] == "established"
    )


def get_bgp_uptime(duthost, bgp_neighbor):
    # it's a work around for show ip bgp neighbors <ipaddress>, it can not show
    # neighbors which are not configured
    output = duthost.shell(
        "show ip bgp neighbors | grep -A 10 {} | grep 'Established'".format(
            bgp_neighbor
        )
    )
    if not output["stdout"]:
        pytest_assert(True, "Bgp neighbor {} is not up".format(bgp_neighbor))
    time_string = re.search(r"up for (\d{2}:\d{2}:\d{2})", output["stdout"]).group(1)
    t = datetime.strptime(time_string, "%H:%M:%S").time()
    return int(
        timedelta(hours=t.hour, minutes=t.minute, seconds=t.second).total_seconds()
    )


def check_bgp_routes_exist(duthost, prefix):
    result = duthost.get_route(prefix)
    pytest_assert(result, "Route {} is not found on DUT".format(prefix))


def announce_route(ptfhost, exabgp_port, prefix, nexthop):
    route = {}
    route["prefix"] = prefix
    route["nexthop"] = nexthop
    update_routes("announce", ptfhost.mgmt_ip, exabgp_port, route)


def test_bgp_dual_asn_v4(
    duthosts, rand_one_dut_hostname, ptfhost, localhost, tbinfo, setup_env
):
    duthost = duthosts[rand_one_dut_hostname]

    dualAsn = BgpDualAsn()
    dualAsn.dual_asn_setup(duthosts, rand_one_dut_hostname, ptfhost, localhost, tbinfo)

    try:
        # peer range group cleanup
        bgp_peer_range_config_cleanup(duthost)

        # add first peer range group, note peer range group cleanup must be called
        # before this function
        bgp_peer_range_add_config(
            duthost,
            dualAsn.lo,
            dualAsn.lo6,
            BGPSLB,
            dualAsn.peer_subnets[0],
            BGPSLB_V6,
            dualAsn.peer_subnets_v6[0],
            NEIGHBOR_ASN_LIST[0],
        )
        # start valid bgp peer
        start_peer_ipv4_bgp_session(
            ptfhost,
            localhost,
            dualAsn.lo["addr"],
            dualAsn.local_asn,
            dualAsn.peer_addrs[0],
            NEIGHBOR_ASN_LIST[0],
            0,
            NEIGHBOR_PORT_LIST[0],
        )
        if not wait_until(
            30, 5, 10, verify_bgp_session, duthost, dualAsn.peer_addrs[0]
        ):
            pytest.fail("bgp peer %s should up" % dualAsn.peer_addrs[0])
        current_bgp_uptime = get_bgp_uptime(duthost, dualAsn.peer_addrs[0])
        current_time = time.time()
        # announce route from valid bgp peer
        announce_route(ptfhost, NEIGHBOR_PORT_LIST[0], PREFIX, dualAsn.peer_addrs[0])
        # bgp peer which is not in peer range group should not up
        start_peer_ipv4_bgp_session(
            ptfhost,
            localhost,
            dualAsn.lo["addr"],
            dualAsn.local_asn,
            dualAsn.peer_addrs[1],
            NEIGHBOR_ASN_LIST[1],
            1,
            NEIGHBOR_PORT_LIST[1],
        )
        if wait_until(30, 5, 10, verify_bgp_session, duthost, dualAsn.peer_addrs[1]):
            pytest.fail("bgp peer %s should not up" % dualAsn.peer_addrs[0])
        # double confirm valid peer announced route exists
        check_bgp_routes_exist(duthost, PREFIX)

        # add another peer range group with different ASN
        bgp_peer_range_add_config(
            duthost,
            dualAsn.lo,
            dualAsn.lo6,
            BGPSLB,
            dualAsn.peer_subnets[0],
            BGPSLB_V6,
            dualAsn.peer_subnets_v6[0],
            NEIGHBOR_ASN_LIST[0],
            BGPSLB_2,
            dualAsn.peer_subnets[1],
            None,  # ipv4 only
            None,  # ipv4 only
            NEIGHBOR_ASN_LIST[1],
        )
        # double check original valid peer announced route exists
        check_bgp_routes_exist(duthost, PREFIX)
        # bring up second valid peer
        start_peer_ipv4_bgp_session(
            ptfhost,
            localhost,
            dualAsn.lo["addr"],
            dualAsn.local_asn,
            dualAsn.peer_addrs[1],
            NEIGHBOR_ASN_LIST[1],
            1,
            NEIGHBOR_PORT_LIST[1],
        )
        if not wait_until(1, 5, 10, verify_bgp_session, duthost, dualAsn.peer_addrs[0]):
            pytest.fail("bgp peer %s should up" % dualAsn.peer_addrs[0])
        if not wait_until(
            30, 5, 10, verify_bgp_session, duthost, dualAsn.peer_addrs[1]
        ):
            pytest.fail("bgp peer %s should up" % dualAsn.peer_addrs[1])

        # announce route from second neighbor
        announce_route(ptfhost, NEIGHBOR_PORT_LIST[1], PREFIX_2, dualAsn.peer_addrs[1])
        time.sleep(5)
        # check both bgp neighbors announced routes are right there
        check_bgp_routes_exist(duthost, PREFIX)
        check_bgp_routes_exist(duthost, PREFIX_2)

        # check original bgp neighbor no flapping
        latest_time = time.time()
        latest_bgp_uptime = get_bgp_uptime(duthost, dualAsn.peer_addrs[0])
        if latest_time - current_time > latest_bgp_uptime - current_bgp_uptime:
            pytest.fail("bgp %s flapped during testing" % dualAsn.peer_addrs[0])

        # remove first peer range group configuration, check it's neighbor's bgp state
        bgp_peer_range_delete_config(
            duthost,
            BGPSLB,
            dualAsn.peer_subnets[0],
            BGPSLB_V6,
            dualAsn.peer_subnets_v6[0],
        )
        if wait_until(5, 5, 10, verify_bgp_session, duthost, dualAsn.peer_addrs[0]):
            pytest.fail("bgp peer %s should not up" % dualAsn.peer_addrs[0])

    finally:
        dualAsn.dual_asn_teardown(duthosts, rand_one_dut_hostname, ptfhost)
