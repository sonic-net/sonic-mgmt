import ipaddress
import json
import logging
import random

import pytest
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf.mask import Mask

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import UPSTREAM_NEIGHBOR_MAP
from tests.common.utilities import wait_until
from tests.bgp.bgp_helpers import get_vm_name_list
from tests.common.helpers.bgp import BGPNeighbor


logger = logging.getLogger(__name__)


class PendingRoute:
    """Delay route installation through a private, unresolved connected next-hop."""

    def __init__(self, duthost, tbinfo, ptfadapter, ptfhost, announce, ports, recv_ports,
                 vrf="default", count=2):
        self.dut = duthost
        self.tbinfo = tbinfo
        self.ptfadapter = ptfadapter
        self.ptfhost = ptfhost
        self.announce_callback = announce
        self.ports = ports
        self.vrf = vrf
        self.count = count
        self.families = {}
        self.addresses = []
        self.neighbors = []
        self.announced = []
        self.sessions = []
        self.ptf_addresses = []
        self.peer_keys = []
        self.mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
        for version, port in ports.items():
            vm_offset = port - (5000 if version == 4 else 6000)
            vm = next(name for name, info in tbinfo["topo"]["properties"]["topology"]["VMs"].items()
                      if info["vm_offset"] == vm_offset)
            members = [name for name, info in self.mg_facts["minigraph_neighbors"].items()
                       if info["name"] == vm]
            pytest_assert(members, "No DUT interface found for {}".format(vm))
            member = members[0]
            interface = next(
                (name for name, info in self.mg_facts["minigraph_portchannels"].items()
                 if member in info["members"]), member)
            namespace = self.mg_facts["minigraph_neighbors"][member].get("namespace")
            ptf_ports = recv_ports[version]
            mac = ptfadapter.dataplane.get_mac(0, ptf_ports[0])
            if isinstance(mac, bytes):
                mac = mac.decode("ascii")
            neighbor = next(peer for peer in self.mg_facts["minigraph_bgp"] if peer["name"] == vm)
            self.families[version] = {
                "interface": interface, "namespace": namespace, "ptf_ports": ptf_ports, "mac": mac,
                "asn": neighbor["asn"], "neighbor_type": self.mg_facts["minigraph_devices"][vm]["type"],
            }

    def shell(self, command, namespace):
        """Run a Linux command in its owning ASIC network namespace."""
        if namespace:
            command = "sudo ip netns exec {} {}".format(namespace, command)
        return self.dut.shell(command)["stdout"]

    def configure_address(self, family, action):
        namespace = " -n {}".format(family["namespace"]) if family["namespace"] else ""
        self.dut.shell("sudo config interface{} ip {} {} {}".format(
            namespace, action, family["interface"], family["address"]))

    def db(self, database, command, namespace):
        cmd = self.dut.get_cli_cmd_for_namespace(
            "sonic-db-cli {} {}".format(database, command), namespace)
        return self.dut.shell(cmd)["stdout"].strip()

    def vty(self, command, namespace):
        cmd = self.dut.get_vtysh_cmd_for_namespace("vtysh -c '{}'".format(command), namespace)
        return json.loads(self.dut.shell(cmd)["stdout"])

    def setup(self):
        """Allocate unused subnets and prefixes without altering the BGP peer."""
        for version, family in self.families.items():
            namespace = family["namespace"]
            addresses = json.loads(self.shell("ip -j address show", namespace))
            existing = [
                ipaddress.ip_network("{}/{}".format(addr["local"], addr["prefixlen"]), strict=False)
                for interface in addresses for addr in interface["addr_info"]
                if addr["family"] == ("inet" if version == 4 else "inet6")
            ]
            ptf_addresses = json.loads(self.ptfhost.shell("ip -j address show")["stdout"])
            existing.extend(
                ipaddress.ip_network("{}/{}".format(addr["local"], addr["prefixlen"]), strict=False)
                for interface in ptf_addresses for addr in interface["addr_info"]
                if addr["family"] == ("inet" if version == 4 else "inet6"))
            afi = "ipv{}".format(version)
            rib = self.vty("show bgp vrf {} {} unicast json".format(self.vrf, afi), namespace)
            existing.extend(network for network in (
                ipaddress.ip_network(prefix) for prefix in rib.get("routes", {})) if network.prefixlen)
            existing.extend(network for network in self.asic_prefixes(namespace) if network.prefixlen)
            kernel = json.loads(self.shell(
                "ip -{} -j route show table all".format(version), namespace))
            existing.extend(ipaddress.ip_network(route["dst"], strict=False)
                            for route in kernel if route.get("dst", "default") != "default")
            for _ in range(100):
                slot = random.randrange(1, 250)
                subnet = ipaddress.ip_network(
                    "198.18.{}.0/24".format(slot) if version == 4
                    else "2001:db8:2664:{:x}::/64".format(random.randrange(1, 65535)))
                if any(subnet.overlaps(network) for network in existing):
                    continue
                pool = ipaddress.ip_network("198.19.0.0/16" if version == 4 else "2001:db8:2665::/48")
                prefixlen = 30 if version == 4 else 64
                block_size = 1 << (pool.max_prefixlen - prefixlen)
                start = random.randrange(1, pool.num_addresses // block_size - self.count)
                prefixes = [
                    str(ipaddress.ip_network(
                        "{}/{}".format(pool.network_address + (start + index) * block_size, prefixlen)))
                    for index in range(self.count)
                ]
                if any(ipaddress.ip_network(prefix).overlaps(network)
                       for prefix in prefixes for network in existing):
                    continue
                break
            else:
                pytest.fail("Could not allocate unused IPv{} test addresses".format(version))

            address = "{}/{}".format(subnet.network_address + 1, subnet.prefixlen)
            nexthop = str(subnet.network_address + 99)
            prior_neighbor = json.loads(self.shell(
                "ip -{} -j neigh show to {} dev {}".format(
                    version, nexthop, family["interface"]), namespace))
            pytest_assert(not prior_neighbor, "Refusing to overwrite neighbor {}".format(nexthop))
            family.update({"address": address, "nexthop": nexthop, "prefixes": prefixes})
            self.neighbors.append((version, family))
            logger.info("Pending-route IPv%s: interface=%s namespace=%s vrf=%s address=%s nexthop=%s prefixes=%s",
                        version, family["interface"], namespace, self.vrf, address, nexthop, prefixes)
            self.addresses.append(family)
            self.configure_address(family, "add")
            pytest_assert(wait_until(30, 2, 0, self.connected, version),
                          "Test next-hop is not routing-reachable: {}".format(nexthop))
            self.start_session(version, family, subnet, rib["localAS"])

    def start_session(self, version, family, subnet, local_asn):
        """Use a private direct peer so a transit VM cannot rewrite the next-hop."""
        peer_ip = str(subnet.network_address + 2)
        prior = json.loads(self.shell("ip -{} -j neigh show to {} dev {}".format(
            version, peer_ip, family["interface"]), family["namespace"]))
        pytest_assert(not prior, "Refusing to overwrite neighbor {}".format(peer_ip))
        self.neighbors.append((version, dict(family, nexthop=peer_ip)))
        ptf_address = "{}/{}".format(peer_ip, subnet.prefixlen)
        interface = "eth{}".format(family["ptf_ports"][0])
        self.ptf_addresses.append((ptf_address, interface))
        self.ptfhost.shell("ip address add {} dev {}".format(ptf_address, interface))
        listeners = self.ptfhost.shell("ss -H -lnt")["stdout"]
        used_ports = {int(line.split()[3].rsplit(":", 1)[1]) for line in listeners.splitlines()}
        available = set(range(20000, 30000)) - used_ports - set(self.ports.values())
        pytest_assert(available, "No free API port for the private ExaBGP peer")
        port = random.choice(sorted(available))
        name = "fibpending-{}-{}".format(version, port)
        key = "BGP_NEIGHBOR|{}{}".format("" if self.vrf == "default" else self.vrf + "|", peer_ip)
        metadata_key = "DEVICE_NEIGHBOR_METADATA|" + name
        for candidate in (key, metadata_key):
            pytest_assert(self.db("CONFIG_DB", "EXISTS '{}'".format(candidate), family["namespace"]) == "0",
                          "Refusing to overwrite {}".format(candidate))
        remote_asn = family["asn"]
        for candidate in (metadata_key, key):
            self.peer_keys.append((candidate, family["namespace"]))
        self.db("CONFIG_DB", "HSET '{}' type {}".format(
            metadata_key, family["neighbor_type"]), family["namespace"])
        self.db("CONFIG_DB",
                "HSET '{}' admin_status up asn {} local_addr {} name {} holdtime 10 keepalive 3 "
                "nhopself 0 rrclient 0".format(key, remote_asn, subnet.network_address + 1, name),
                family["namespace"])
        peer = BGPNeighbor(self.dut, self.ptfhost, name, peer_ip, remote_asn,
                           str(subnet.network_address + 1), local_asn, port,
                           namespace=family["namespace"], is_passive=True)
        self.sessions.append(peer)
        self.ports[version] = port
        family["peer_ip"] = peer_ip
        peer.start_session()
        pytest_assert(wait_until(60, 2, 0, self.session_established, version),
                      "Private IPv{} BGP peer did not establish".format(version))

    def session_established(self, version):
        family = self.families[version]
        summary = self.vty("show bgp vrf {} ipv{} unicast summary json".format(
            self.vrf, version), family["namespace"])
        return summary.get("peers", {}).get(family["peer_ip"], {}).get("state") == "Established"

    def connected(self, version):
        """Require L3 reachability before introducing the L2 resolution delay."""
        family = self.families[version]
        command = "ip -{} -j route get {}{}".format(
            version, family["nexthop"], "" if self.vrf == "default" else " vrf " + self.vrf)
        routes = json.loads(self.shell(command, family["namespace"]))
        return bool(routes) and routes[0].get("dev") == family["interface"]

    def announce(self):
        """Export fresh prefixes using an explicit next-hop distinct from the peer."""
        for version, family in self.families.items():
            if version not in self.announced:
                self.announced.append(version)
            self.announce_callback(self.tbinfo["ptf_ip"], family["prefixes"], self.ports[version],
                                   next_hop=family["nexthop"])

    def route_key(self, prefix):
        return prefix if self.vrf == "default" else "{}:{}".format(self.vrf, prefix)

    def asic_prefixes(self, namespace):
        """Read exact SAI prefix entries, not Zebra's logical offloaded flag."""
        keys = self.db("ASIC_DB", 'KEYS "ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:*"', namespace)
        return {ipaddress.ip_network(json.loads(key.split(":", 2)[2])["dest"])
                for key in keys.splitlines() if key}

    def installation_matches(self, installed):
        """Check route delivery and prefix installation in the owning ASIC."""
        for version, family in self.families.items():
            namespace = family["namespace"]
            prefixes = self.asic_prefixes(namespace)
            rib = self.vty("show bgp vrf {} ipv{} unicast json".format(self.vrf, version), namespace)
            app_routes = self.app_routes(family)
            for prefix in family["prefixes"]:
                if not any(path.get("valid") and path.get("bestpath")
                           for path in rib.get("routes", {}).get(prefix, [])):
                    return False
                nexthops = app_routes.get("ROUTE_TABLE:" + self.route_key(prefix), "")
                if family["nexthop"] not in nexthops.split(","):
                    return False
                if (ipaddress.ip_network(prefix) in prefixes) != installed:
                    return False
            neighbor = json.loads(self.shell("ip -{} -j neigh show to {} dev {}".format(
                version, family["nexthop"], family["interface"]), namespace))
            resolved = any(entry.get("lladdr") for entry in neighbor)
            if resolved != installed:
                return False
        return True

    def app_routes(self, family):
        """Read only the test's APPL_DB next-hops in one round trip."""
        keys = ["ROUTE_TABLE:" + self.route_key(prefix) for prefix in family["prefixes"]]
        script = ('local r={} for _,k in ipairs(KEYS) do '
                  'r[k]=redis.call("HGET",k,"nexthop") or "" end return cjson.encode(r)')
        output = self.db("APPL_DB", "EVAL '{}' {} {}".format(
            script, len(keys), " ".join('"{}"'.format(key) for key in keys)), family["namespace"])
        return json.loads(output)

    def check_pending(self):
        """Prove BGP selection/FPM delivery with unresolved L2 and no SAI prefix."""
        pytest_assert(wait_until(60, 2, 0, self.installation_matches, False),
                      "Expected selected, delivered routes with unresolved neighbors and absent ASIC prefixes")
        logger.info("PENDING PROVEN on %s: BGP selected, APPL_DB delivered, neighbors unresolved, ASIC prefixes absent",
                    self.dut.hostname)

    def advertisement_matches(self, duthost, exist, prefixes=None):
        """Check exact-prefix advertisement to every upstream peer in its ASIC."""
        prefixes = prefixes if prefixes is not None else {
            version: family["prefixes"] for version, family in self.families.items()}
        mg_facts = duthost.get_extended_minigraph_facts(self.tbinfo)
        upstream_type = UPSTREAM_NEIGHBOR_MAP[self.tbinfo["topo"]["type"]].upper()
        upstream_vms = set(get_vm_name_list(self.tbinfo, upstream_type))
        checked = set()
        for peer in mg_facts["minigraph_bgp"]:
            if peer["name"] not in upstream_vms:
                continue
            address = ipaddress.ip_address(peer["addr"])
            version = address.version
            if version not in prefixes:
                continue
            namespace = next(
                info.get("namespace") for info in mg_facts["minigraph_neighbors"].values()
                if info["name"] == peer["name"])
            checked.add(version)
            command = duthost.get_vtysh_cmd_for_namespace(
                "vtysh -c 'show bgp vrf {} ipv{} unicast neighbors {} advertised-routes json'".format(
                    self.vrf, version, address), namespace)
            routes = json.loads(duthost.shell(command, verbose=False)["stdout"])
            advertised = {ipaddress.ip_network(value) for value in routes.get("advertisedRoutes", {})}
            for prefix in prefixes[version]:
                if (ipaddress.ip_network(prefix) in advertised) != exist:
                    logger.info("Advertisement mismatch: DUT=%s prefix=%s peer=%s expected=%s advertisedTo=%s",
                                duthost.hostname, prefix, address, exist, advertised)
                    return False
        return checked == set(prefixes)

    def check_advertisement(self, duthost, exist, prefixes=None):
        """Poll positive checks; require sustained absence for the negative check."""
        if exist:
            pytest_assert(wait_until(60, 2, 0, self.advertisement_matches, duthost, True, prefixes),
                          "Test prefixes were not advertised to every upstream peer")
        else:
            unexpected = wait_until(
                10, 2, 0, lambda: not self.advertisement_matches(duthost, False, prefixes))
            pytest_assert(not unexpected, "Pending prefixes were unexpectedly advertised")
        logger.info("ADVERTISEMENT PROVEN on %s: exist=%s", duthost.hostname, exist)

    def resolve(self):
        """Release only this test's next-hops, using the receiving PTF port's MAC."""
        for version, family in self.families.items():
            self.shell("sudo ip -{} neigh replace {} lladdr {} nud permanent dev {}".format(
                version, family["nexthop"], family["mac"], family["interface"]), family["namespace"])
        pytest_assert(wait_until(60, 2, 0, self.installation_matches, True),
                      "Routes did not install after resolving the test next-hops")
        logger.info("INSTALLATION PROVEN on %s: resolved neighbors and ASIC prefix routes present", self.dut.hostname)

    def verify_forwarding(self, installed=True, ingress_dut=None):
        """Check no downstream forwarding while pending, then the receiving MAC."""
        ingress_dut = ingress_dut or self.dut
        mg_facts = self.mg_facts if ingress_dut == self.dut else ingress_dut.get_extended_minigraph_facts(self.tbinfo)
        upstream_ports = [
            mg_facts["minigraph_ptf_indices"][name]
            for name, info in mg_facts["minigraph_neighbors"].items()
            if info["name"].endswith(UPSTREAM_NEIGHBOR_MAP[self.tbinfo["topo"]["type"]].upper())
        ]
        pytest_assert(upstream_ports, "No upstream PTF ports available for traffic verification")
        for version, family in self.families.items():
            for prefix in family["prefixes"]:
                destination = str(next(ipaddress.ip_network(prefix).hosts()))
                if version == 4:
                    packet = testutils.simple_ip_packet(
                        eth_dst=ingress_dut.facts["router_mac"], ip_dst=destination, ip_ttl=64)
                    expected = testutils.simple_ip_packet(
                        eth_dst=family["mac"], eth_src=self.dut.facts["router_mac"],
                        ip_dst=destination, ip_ttl=63)
                else:
                    packet = testutils.simple_tcpv6_packet(
                        eth_dst=ingress_dut.facts["router_mac"], ipv6_dst=destination, ipv6_hlim=64)
                    expected = testutils.simple_tcpv6_packet(
                        eth_dst=family["mac"], eth_src=self.dut.facts["router_mac"],
                        ipv6_dst=destination, ipv6_hlim=63)
                self.ptfadapter.dataplane.flush()
                testutils.send(self.ptfadapter, upstream_ports[0], packet)
                expected = Mask(expected)
                if self.dut.is_multi_asic or ingress_dut != self.dut:
                    expected.set_do_not_care_packet(scapy.Ether, "src")
                    expected.set_do_not_care_packet(scapy.IP if version == 4 else scapy.IPv6,
                                                    "ttl" if version == 4 else "hlim")
                    if version == 4:
                        expected.set_do_not_care_packet(scapy.IP, "chksum")
                if installed:
                    testutils.verify_packet_any_port(
                        self.ptfadapter, expected, ports=family["ptf_ports"], timeout=2)
                else:
                    expected.set_do_not_care_packet(scapy.Ether, "src")
                    expected.set_do_not_care_packet(scapy.Ether, "dst")
                    testutils.verify_no_packet_any(
                        self.ptfadapter, expected, ports=family["ptf_ports"], timeout=0.1)
        logger.info("FORWARDING PROVEN on %s: downstream forwarding=%s", self.dut.hostname, installed)

    def withdrawn(self):
        for version in self.announced:
            family = self.families[version]
            namespace = family["namespace"]
            prefixes = self.asic_prefixes(namespace)
            app_routes = self.app_routes(family)
            rib = self.vty("show bgp vrf {} ipv{} unicast json".format(self.vrf, version), namespace)
            for prefix in family["prefixes"]:
                if app_routes.get("ROUTE_TABLE:" + self.route_key(prefix)):
                    return False
                if ipaddress.ip_network(prefix) in prefixes:
                    return False
                if rib.get("routes", {}).get(prefix):
                    return False
        return True

    def withdraw(self):
        """Withdraw using the same explicit next-hop and await complete removal."""
        failures = []
        for version in self.announced:
            family = self.families[version]
            try:
                self.announce_callback(self.tbinfo["ptf_ip"], family["prefixes"], self.ports[version],
                                       action="withdraw", next_hop=family["nexthop"])
            except (Exception, pytest.fail.Exception) as error:
                logger.exception("Failed to withdraw IPv%s test routes", version)
                failures.append("IPv{}: {}".format(version, error))
        pytest_assert(wait_until(60, 2, 0, self.withdrawn),
                      "Test prefixes remained in BGP/APPL_DB/ASIC_DB after withdrawal")
        pytest_assert(not failures, "Route withdrawal failed: {}".format("; ".join(failures)))
        self.announced.clear()

    def cleanup(self):
        """Attempt all removals, including when a pytest assertion raises."""
        failures = []

        def attempt(description, operation):
            try:
                operation()
            except (Exception, pytest.fail.Exception) as error:
                logger.exception("Pending-route cleanup failed: %s", description)
                failures.append("{}: {}".format(description, error))

        attempt("withdraw routes", self.withdraw)
        for peer in list(reversed(self.sessions)):
            def remove_session(p=peer):
                p.stop_session()
                self.sessions.remove(p)
            attempt("remove private ExaBGP session", remove_session)
        for key, namespace in list(reversed(self.peer_keys)):
            def remove_peer(k=key, ns=namespace):
                self.db("CONFIG_DB", "DEL '{}'".format(k), ns)
                self.peer_keys.remove((k, ns))
            attempt("remove private DUT peer configuration", remove_peer)
        for address, interface in list(reversed(self.ptf_addresses)):
            def remove_ptf_address(a=address, i=interface):
                self.ptfhost.shell("ip address del {} dev {}".format(a, i))
                self.ptf_addresses.remove((a, i))
            attempt("remove private PTF address", remove_ptf_address)
        for version, family in reversed(self.neighbors):
            def remove_neighbor(v=version, f=family):
                entries = json.loads(self.shell("ip -{} -j neigh show to {} dev {}".format(
                    v, f["nexthop"], f["interface"]), f["namespace"]))
                if entries:
                    self.shell("sudo ip -{} neigh del {} dev {}".format(
                        v, f["nexthop"], f["interface"]), f["namespace"])
                self.neighbors.remove((v, f))
            attempt("remove test neighbor", remove_neighbor)
        for family in reversed(self.addresses):
            def remove_address(f=family):
                self.configure_address(f, "remove")
                self.addresses.remove(f)
            attempt("remove test interface address", remove_address)
        pytest_assert(not failures, "Pending-route cleanup failed: {}".format("; ".join(failures)))
