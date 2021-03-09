"""Check how fast FRR or QUAGGA will send updates to neighbors."""
import contextlib
import ipaddress
import jinja2
import logging
import pytest
import requests
import tempfile
import time

from scapy.all import sniff, IP
from scapy.contrib import bgp
from tests.common.utilities import wait_tcp_connection


pytestmark = [
    pytest.mark.topology("any"),
]

PEER_COUNT = 2
BGP_SAVE_DEST_TMPL = "/tmp/bgp_%s.j2"
NEIGHBOR_SAVE_DEST_TMPL = "/tmp/neighbor_%s.j2"
BGP_LOG_TMPL = "/tmp/bgp%d.pcap"
ANNOUNCED_SUBNETS = [
    "10.10.100.0/27",
    "10.10.100.32/27",
    "10.10.100.64/27",
    "10.10.100.96/27",
    "10.10.100.128/27"
]
NEIGHBOR_ASN0 = 61000
NEIGHBOR_ASN1 = 61001
NEIGHBOR_PORT0 = 11000
NEIGHBOR_PORT1 = 11001


def _write_variable_from_j2_to_configdb(duthost, template_file, **kwargs):
    save_dest_path = kwargs.pop("save_dest_path", "/tmp/temp.j2")
    keep_dest_file = kwargs.pop("keep_dest_file", True)
    config_template = jinja2.Template(open(template_file).read())
    duthost.copy(content=config_template.render(**kwargs), dest=save_dest_path)
    duthost.shell("sonic-cfggen -j %s --write-to-db" % save_dest_path)
    if not keep_dest_file:
        duthost.file(path=save_dest_path, state="absent")


class BGPNeighbor(object):

    def __init__(self, duthost, ptfhost, name,
                 neighbor_ip, neighbor_asn,
                 dut_ip, dut_asn, port, neigh_type, is_quagga=False):
        self.duthost = duthost
        self.ptfhost = ptfhost
        self.ptfip = ptfhost.mgmt_ip
        self.name = name
        self.ip = neighbor_ip
        self.asn = neighbor_asn
        self.peer_ip = dut_ip
        self.peer_asn = dut_asn
        self.port = port
        self.type = neigh_type
        self.is_quagga = is_quagga

    def start_session(self):
        """Start the BGP session."""
        logging.debug("start bgp session %s", self.name)
        self.ptfhost.exabgp(
            name=self.name,
            state="started",
            local_ip=self.ip,
            router_id=self.ip,
            peer_ip=self.peer_ip,
            local_asn=self.asn,
            peer_asn=self.peer_asn,
            port=self.port
        )
        if not wait_tcp_connection(self.ptfhost, self.ptfip, self.port):
            raise RuntimeError("Failed to start BGP neighbor %s" % self.name)

        _write_variable_from_j2_to_configdb(
            self.duthost,
            "bgp/templates/neighbor_metadata_template.j2",
            save_dest_path=NEIGHBOR_SAVE_DEST_TMPL % self.name,
            neighbor_name=self.name,
            neighbor_lo_addr=self.ip,
            neighbor_mgmt_addr=self.ip,
            neighbor_hwsku=None,
            neighbor_type=self.type
        )

        _write_variable_from_j2_to_configdb(
            self.duthost,
            "bgp/templates/bgp_template.j2",
            save_dest_path=BGP_SAVE_DEST_TMPL % self.name,
            db_table_name="BGP_NEIGHBOR",
            peer_addr=self.ip,
            asn=self.asn,
            local_addr=self.peer_ip,
            peer_name=self.name
        )

        if self.is_quagga:
            allow_ebgp_multihop_cmd = (
                "vtysh "
                "-c 'configure terminal' "
                "-c 'router bgp %s' "
                "-c 'neighbor %s ebgp-multihop'"
            )
            allow_ebgp_multihop_cmd %= (self.peer_asn, self.ip)
            self.duthost.shell(allow_ebgp_multihop_cmd)

    def stop_session(self):
        """Stop the BGP session."""
        logging.debug("stop bgp session %s", self.name)
        self.duthost.shell("redis-cli -n 4 -c DEL 'BGP_NEIGHBOR|%s'" % self.ip)
        self.duthost.shell("redis-cli -n 4 -c DEL 'DEVICE_NEIGHBOR_METADATA|%s'" % self.name)
        self.ptfhost.exabgp(name=self.name, state="absent")

    # TODO: let's put those BGP utility functions in a common place.
    def announce_route(self, route):
        if "aspath" in route:
            msg = "announce route {prefix} next-hop {nexthop} as-path [ {aspath} ]"
        else:
            msg = "announce route {prefix} next-hop {nexthop}"
        msg = msg.format(**route)
        logging.debug("announce route: %s", msg)
        url = "http://%s:%d" % (self.ptfip, self.port)
        resp = requests.post(url, data={"commands": msg})
        logging.debug("announce return: %s", resp)
        assert resp.status_code == 200

    def withdraw_route(self, route):
        if "aspath" in route:
            msg = "withdraw route {prefix} next-hop {nexthop} as-path [ {aspath} ]"
        else:
            msg = "withdraw route {prefix} next-hop {nexthop}"
        msg = msg.format(**route)
        logging.debug("withdraw route: %s", msg)
        url = "http://%s:%d" % (self.ptfip, self.port)
        resp = requests.post(url, data={"commands": msg})
        logging.debug("withdraw return: %s", resp)
        assert resp.status_code == 200


@contextlib.contextmanager
def log_bgp_updates(duthost, iface, save_path):
    """Capture bgp packets to file."""
    start_pcap = "tcpdump -i %s -w %s port 179" % (iface, save_path)
    stop_pcap = "pkill -f '%s'" % start_pcap
    start_pcap = "nohup %s &" % start_pcap
    duthost.shell(start_pcap)
    try:
        yield
    finally:
        duthost.shell(stop_pcap, module_ignore_errors=True)


@pytest.fixture
def is_quagga(duthost):
    """Return True if current bgp is using Quagga."""
    show_res = duthost.shell("vtysh -c 'show version'")
    return "Quagga" in show_res["stdout"]


@pytest.fixture
def common_setup_teardown(duthost, is_quagga, ptfhost, setup_interfaces):
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)["ansible_facts"]
    conn0, conn1 = setup_interfaces
    dut_asn = mg_facts["minigraph_bgp_asn"]

    dut_type = ''
    for k,v in mg_facts['minigraph_devices'].iteritems():
        if k == duthost.hostname:
            dut_type = v['type']

    if dut_type == 'ToRRouter':
        neigh_type = 'LeafRouter'
    else:
        neigh_type = 'ToRRouter'

    bgp_neighbors = (
        BGPNeighbor(
            duthost,
            ptfhost,
            "pseudoswitch0",
            conn0["neighbor_addr"].split("/")[0],
            NEIGHBOR_ASN0,
            conn0["local_addr"].split("/")[0],
            dut_asn,
            NEIGHBOR_PORT0,
            neigh_type,
            is_quagga=is_quagga
        ),
        BGPNeighbor(
            duthost,
            ptfhost,
            "pseudoswitch1",
            conn1["neighbor_addr"].split("/")[0],
            NEIGHBOR_ASN1,
            conn1["local_addr"].split("/")[0],
            dut_asn,
            NEIGHBOR_PORT1,
            neigh_type,
            is_quagga=is_quagga
        )
    )

    return bgp_neighbors


@pytest.fixture
def constants(is_quagga, setup_interfaces):
    class _C(object):
        """Dummy class to save test constants."""
        pass

    _constants = _C()
    if is_quagga:
        _constants.sleep_interval = 40
        _constants.update_interval_threshold = 20
    else:
        _constants.sleep_interval = 5
        _constants.update_interval_threshold = 1

    conn0 = setup_interfaces[0]
    _constants.routes = []
    for subnet in ANNOUNCED_SUBNETS:
        _constants.routes.append(
            {"prefix": subnet, "nexthop": conn0["neighbor_addr"].split("/")[0]}
        )
    return _constants


def test_bgp_update_timer(common_setup_teardown, constants, duthost):

    def bgp_update_packets(pcap_file):
        """Get bgp update packets from pcap file."""
        packets = sniff(
            offline=pcap_file,
            lfilter=lambda p: bgp.BGPHeader in p and p[bgp.BGPHeader].type == 2
        )
        return packets

    def match_bgp_update(packet, src_ip, dst_ip, action, route):
        """Check if the bgp update packet matches."""
        if not (packet[IP].src == src_ip and packet[IP].dst == dst_ip):
            return False
        subnet = ipaddress.ip_network(route["prefix"].decode())
        _route = (subnet.prefixlen, str(subnet.network_address))
        bgp_fields = packet[bgp.BGPUpdate].fields
        if action == "announce":
            return bgp_fields["tp_len"] > 0 and _route in bgp_fields["nlri"]
        elif action == "withdraw":
            return bgp_fields["withdrawn_len"] > 0 and _route in bgp_fields["withdrawn"]
        else:
            return False

    n0, n1 = common_setup_teardown
    try:
        n0.start_session()
        n1.start_session()

        # sleep till new sessions are steady
        time.sleep(30)

        # ensure new sessions are ready
        bgp_facts = duthost.bgp_facts()["ansible_facts"]
        assert n0.ip in bgp_facts["bgp_neighbors"]
        assert n1.ip in bgp_facts["bgp_neighbors"]
        assert bgp_facts["bgp_neighbors"][n0.ip]["state"] == "established"
        assert bgp_facts["bgp_neighbors"][n1.ip]["state"] == "established"

        announce_intervals = []
        withdraw_intervals = []
        for i, route in enumerate(constants.routes):
            bgp_pcap = BGP_LOG_TMPL % i
            with log_bgp_updates(duthost, "any", bgp_pcap):
                n0.announce_route(route)
                time.sleep(constants.sleep_interval)
                n0.withdraw_route(route)
                time.sleep(constants.sleep_interval)

            with tempfile.NamedTemporaryFile() as tmp_pcap:
                duthost.fetch(src=bgp_pcap, dest=tmp_pcap.name, flat=True)
                bgp_updates = bgp_update_packets(tmp_pcap.name)

            announce_from_n0_to_dut = []
            announce_from_dut_to_n1 = []
            withdraw_from_n0_to_dut = []
            withdraw_from_dut_to_n1 = []
            for bgp_update in bgp_updates:
                if match_bgp_update(bgp_update, n0.ip, n0.peer_ip, "announce", route):
                    announce_from_n0_to_dut.append(bgp_update)
                    continue
                if match_bgp_update(bgp_update, n1.peer_ip, n1.ip, "announce", route):
                    announce_from_dut_to_n1.append(bgp_update)
                    continue
                if match_bgp_update(bgp_update, n0.ip, n0.peer_ip, "withdraw", route):
                    withdraw_from_n0_to_dut.append(bgp_update)
                    continue
                if match_bgp_update(bgp_update, n1.peer_ip, n1.ip, "withdraw", route):
                    withdraw_from_dut_to_n1.append(bgp_update)

            err_msg = "no bgp update %s route %s from %s to %s"
            no_update = False
            if not announce_from_n0_to_dut:
                err_msg %= ("announce", route, n0.ip, n0.peer_ip)
                no_update = True
            elif not announce_from_dut_to_n1:
                err_msg %= ("announce", route, n1.peer_ip, n1.ip)
                no_update = True
            elif not withdraw_from_n0_to_dut:
                err_msg %= ("withdraw", route, n0.ip, n0.peer_ip)
                no_update = True
            elif not withdraw_from_dut_to_n1:
                err_msg %= ("withdraw", route, n1.peer_ip, n1.ip)
                no_update = True
            if no_update:
                pytest.fail(err_msg)

            announce_intervals.append(
                announce_from_dut_to_n1[0].time - announce_from_n0_to_dut[0].time
            )
            withdraw_intervals.append(
                withdraw_from_dut_to_n1[0].time - withdraw_from_n0_to_dut[0].time
            )

        logging.debug("announce updates intervals: %s", announce_intervals)
        logging.debug("withdraw updates intervals: %s", withdraw_intervals)

        mi = (len(constants.routes) - 1) // 2
        announce_intervals.sort()
        withdraw_intervals.sort()
        err_msg = "%s updates interval exceeds threshold %d"
        if announce_intervals[mi] >= constants.update_interval_threshold:
            pytest.fail(err_msg % ("announce", constants.update_interval_threshold))
        if withdraw_intervals[mi] >= constants.update_interval_threshold:
            pytest.fail(err_msg % ("withdraw", constants.update_interval_threshold))

    finally:
        n0.stop_session()
        n1.stop_session()
        for route in constants.routes:
            duthost.shell("ip route flush %s" % route["prefix"])
