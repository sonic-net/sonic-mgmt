"""
BGP confederation route-propagation tests for the management-aggregator
topologies (``lma`` = LowerMgmtAggregator, ``uma`` = UpperMgmtAggregator).

Both DUTs run inside a single BGP confederation:

    topo | DUT type             | member ASN | confed id | confed peer(s)
    -----+----------------------+------------+-----------+----------------
    lma  | LowerMgmtAggregator  | 64589      | 64582     | 64588 (UMA)
    uma  | UpperMgmtAggregator  | 64588      | 64582     | 64589 (LMA)

A BGP confederation splits one public AS (the *confederation identifier*,
64582) into several private member sub-ASes. The two behaviours this module
verifies are entirely observable on the DUT (no neighbor-VM access required),
so the tests are safe to run from any control host:

  1. AS presentation - the DUT presents its *member* AS to confederation-internal
     peers (whose remote-AS is a ``bgp confederation peers`` member) and the
     *confederation identifier* to every other (external) peer.

  2. AS-path integrity - member sub-AS numbers only ever travel inside
     AS_CONFED_SEQUENCE segments (rendered in parentheses by FRR), never as a
     normal AS-path hop, and the confederation identifier never leaks into the
     DUT's local RIB.

  3. Cross-boundary propagation - the default route originated on one side of
     the confederation boundary is learned by the DUT and re-advertised to at
     least one peer on the opposite side of that boundary.
"""
import json
import logging
import re

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('lma', 'uma'),
]

# A freshly deployed / rebooted testbed may still be converging when the test
# session starts; give every confederation session time to establish first.
BGP_ESTABLISH_TIMEOUT = 180
BGP_ESTABLISH_INTERVAL = 10


def _default_prefix(ip_version):
    return "0.0.0.0/0" if ip_version == 4 else "::/0"


def _vtysh_json(duthost, command):
    """Run a vtysh command that emits JSON and return the parsed object."""
    output = duthost.shell("vtysh -c '{}'".format(command), module_ignore_errors=True)
    pytest_assert(
        output['rc'] == 0,
        "vtysh command failed on DUT: '{}': {}".format(command, output.get('stderr')),
    )
    return json.loads(output['stdout'])


def _get_confed_config(duthost):
    """
    Parse the running BGP config for the confederation parameters.

    Returns a tuple ``(member_asn, confed_id, confed_peers)`` where
    ``confed_peers`` is a ``set`` of the member sub-AS numbers listed under
    ``bgp confederation peers``.
    """
    output = duthost.shell("vtysh -c 'show running-config bgpd'", module_ignore_errors=True)
    pytest_assert(output['rc'] == 0,
                  "Failed to read running BGP config: {}".format(output.get('stderr')))
    text = output['stdout']

    member_match = re.search(r'^router bgp (\d+)', text, re.MULTILINE)
    pytest_assert(member_match, "Could not find 'router bgp <asn>' in running config")
    member_asn = int(member_match.group(1))

    id_match = re.search(r'bgp confederation identifier (\d+)', text)
    pytest_assert(id_match,
                  "DUT is not configured as a BGP confederation member "
                  "('bgp confederation identifier' missing)")
    confed_id = int(id_match.group(1))

    peers_match = re.search(r'bgp confederation peers ([\d ]+)', text)
    pytest_assert(peers_match, "Could not find 'bgp confederation peers' in running config")
    confed_peers = {int(asn) for asn in peers_match.group(1).split()}

    return member_asn, confed_id, confed_peers


def _get_bgp_peers(duthost, ip_version):
    """Return the per-neighbor summary dict for the given address family."""
    if ip_version == 4:
        data = _vtysh_json(duthost, "show ip bgp summary json").get('ipv4Unicast', {})
    else:
        data = _vtysh_json(duthost, "show bgp ipv6 summary json").get('ipv6Unicast', {})
    return data.get('peers', {})


def _established_peers(peers):
    """Filter a summary ``peers`` dict down to the established sessions."""
    return {ip: attrs for ip, attrs in peers.items()
            if attrs.get('state') == 'Established'}


def _classify_peers(peers, confed_peers):
    """
    Split peers into (confed_internal, external) IP lists.

    A peer is confederation-internal when its remote-AS is one of the
    ``bgp confederation peers`` members; otherwise it is external to this
    DUT's sub-AS boundary.
    """
    internal, external = [], []
    for ip, attrs in peers.items():
        if attrs.get('remoteAs') in confed_peers:
            internal.append(ip)
        else:
            external.append(ip)
    return internal, external


def _split_confed_and_normal_asns(path_string):
    """
    Split an FRR AS-path string into (confed_asns, normal_asns).

    FRR renders AS_CONFED_SEQUENCE segments inside parentheses, e.g.
    ``"(64588) 65300"`` -> confed {64588}, normal {65300}.
    """
    confed_asns = set()
    for group in re.findall(r'\(([^)]*)\)', path_string):
        confed_asns.update(int(tok) for tok in group.split() if tok.isdigit())
    normal_part = re.sub(r'\([^)]*\)', ' ', path_string)
    normal_asns = {int(tok) for tok in normal_part.split() if tok.isdigit()}
    return confed_asns, normal_asns


def _get_bgp_routes(duthost, ip_version):
    """Return the DUT's local BGP RIB as a ``{prefix: [paths]}`` dict."""
    cmd = "show ip bgp json" if ip_version == 4 else "show bgp ipv6 json"
    return _vtysh_json(duthost, cmd).get('routes', {})


def _get_advertised_prefixes(duthost, neighbor_ip, ip_version):
    """Return the set of prefixes the DUT advertises to ``neighbor_ip``."""
    if ip_version == 4:
        cmd = "show ip bgp neighbors {} advertised-routes json".format(neighbor_ip)
    else:
        cmd = "show bgp ipv6 neighbors {} advertised-routes json".format(neighbor_ip)
    return set(_vtysh_json(duthost, cmd).get('advertisedRoutes', {}).keys())


@pytest.fixture(scope="module", autouse=True)
def wait_for_confed_sessions(duthost):
    """Ensure all confederation BGP sessions are established before testing."""
    def _all_established():
        facts = duthost.get_bgp_neighbors()
        return facts and all(v['state'] == 'established' for v in facts.values())

    pytest_assert(
        wait_until(BGP_ESTABLISH_TIMEOUT, BGP_ESTABLISH_INTERVAL, 0, _all_established),
        "Not all BGP sessions are established; cannot verify confederation behaviour",
    )


@pytest.mark.parametrize("ip_version", [4, 6])
def test_confed_local_as_presentation(duthost, ip_version):
    """
    The DUT must present its member AS to confederation-internal peers and the
    confederation identifier to external peers.

    This is the defining property of a confederation boundary: sub-AS numbers
    are only exchanged between confederation members, while the outside world
    sees the single confederation identifier.
    """
    member_asn, confed_id, confed_peers = _get_confed_config(duthost)
    peers = _established_peers(_get_bgp_peers(duthost, ip_version))
    pytest_assert(peers, "No established IPv{} BGP peers found on DUT".format(ip_version))

    mismatches = []
    for ip, attrs in peers.items():
        is_internal = attrs.get('remoteAs') in confed_peers
        expected = member_asn if is_internal else confed_id
        actual = attrs.get('localAs')
        if actual != expected:
            mismatches.append(
                "{} (remoteAs={}, {}): expected localAs {}, got {}".format(
                    ip, attrs.get('remoteAs'),
                    "confed-internal" if is_internal else "external",
                    expected, actual))

    pytest_assert(
        not mismatches,
        "DUT presented the wrong local-AS to some IPv{} peers:\n{}".format(
            ip_version, "\n".join(mismatches)),
    )


@pytest.mark.parametrize("ip_version", [4, 6])
def test_confed_as_path_integrity(duthost, ip_version):
    """
    Member sub-AS numbers must only appear inside AS_CONFED_SEQUENCE segments,
    the confederation identifier must never appear in the local RIB, and at
    least one route must actually carry a confederation segment (so the check
    is not vacuously satisfied on an empty table).
    """
    member_asn, confed_id, confed_peers = _get_confed_config(duthost)
    confed_members = confed_peers | {member_asn}
    routes = _get_bgp_routes(duthost, ip_version)
    pytest_assert(routes, "DUT has no IPv{} BGP routes to inspect".format(ip_version))

    violations = []
    saw_confed_segment = False
    for prefix, paths in routes.items():
        for path in paths:
            path_string = path.get('path', '')
            confed_asns, normal_asns = _split_confed_and_normal_asns(path_string)
            if confed_asns:
                saw_confed_segment = True

            leaked_members = normal_asns & confed_members
            if leaked_members:
                violations.append(
                    "{}: member AS {} appeared as a normal AS-path hop in '{}'".format(
                        prefix, sorted(leaked_members), path_string))
            if confed_id in (confed_asns | normal_asns):
                violations.append(
                    "{}: confederation identifier {} leaked into local RIB path '{}'".format(
                        prefix, confed_id, path_string))

    pytest_assert(not violations,
                  "IPv{} confederation AS-path integrity violated:\n{}".format(
                      ip_version, "\n".join(violations)))
    pytest_assert(
        saw_confed_segment,
        "No IPv{} route carried an AS_CONFED_SEQUENCE segment; confederation "
        "AS-path handling could not be verified".format(ip_version),
    )


@pytest.mark.parametrize("ip_version", [4, 6])
def test_confed_default_route_crosses_boundary(duthost, ip_version):
    """
    The default route originated on one side of the confederation boundary must
    be installed on the DUT and re-advertised to at least one peer on the
    opposite side of that boundary.

    This proves the DUT propagates routes across the sub-AS boundary rather than
    confining them to a single confederation member.
    """
    prefix = _default_prefix(ip_version)
    _, _, confed_peers = _get_confed_config(duthost)
    peers = _established_peers(_get_bgp_peers(duthost, ip_version))
    internal, external = _classify_peers(peers, confed_peers)
    pytest_assert(internal and external,
                  "Topology must have both confed-internal and external IPv{} peers "
                  "(internal={}, external={})".format(ip_version, internal, external))

    # Locate the default route and the peers it was learned from.
    default_info = _vtysh_json(duthost, "show ip bgp {} json".format(prefix) if ip_version == 4
                               else "show bgp ipv6 {} json".format(prefix))
    default_paths = default_info.get('paths', [])
    pytest_assert(default_paths,
                  "DUT has no IPv{} default route {}; cannot verify propagation".format(
                      ip_version, prefix))

    origin_peer_ips = {p.get('peer', {}).get('peerId') for p in default_paths}
    origin_internal = any(ip in internal for ip in origin_peer_ips)

    # The opposite side of the boundary from wherever the default was learned.
    opposite_side = external if origin_internal else internal
    side_name = "external" if origin_internal else "confed-internal"

    advertised_to = [ip for ip in opposite_side
                     if prefix in _get_advertised_prefixes(duthost, ip, ip_version)]

    pytest_assert(
        advertised_to,
        "IPv{} default route {} (learned from {} peers {}) was not advertised to any "
        "{} peer {}; confederation route propagation across the boundary failed".format(
            ip_version, prefix,
            "confed-internal" if origin_internal else "external",
            sorted(ip for ip in origin_peer_ips if ip),
            side_name, opposite_side),
    )
    logger.info("IPv%d default route %s propagated across confed boundary to %s peers %s",
                ip_version, prefix, side_name, advertised_to)
