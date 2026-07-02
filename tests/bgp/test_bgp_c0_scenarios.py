"""
BGP scenario tests for the standalone SONiC console-server (C0) topology.

Reference:
    docs/testplan/console/standalone_sonic_console_server_test_plan.md

The C0 (DUT, ASN 65100) has three BGP upstream peers, each advertising the
default route with a distinct AS-PATH length so that best-path selection
gives a deterministic priority order. The route prepending is configured in
``ansible/library/announce_routes.py::fib_c0``:

    role | ASN   | default-route AS-PATH | resulting priority
    -----+-------+-----------------------+----------------------------
    M1   | 64900 | (empty)               | primary  (scenario 1)
    M0   | 64800 | "64900"               | backup   (scenario 2)
    C1   | 65200 | "65300 65400"         | provision (scenarios 3/4)

This module verifies each of the four scenarios described in the HLD's
"Test topology" section. Scenarios 1, 2, 3 and 4 are implemented.
"""
import json
import logging
import os
from contextlib import contextmanager

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('c0', 'c0-lo'),
]

# Time budget for the DUT to withdraw the M1 default route and re-converge on
# the M0 backup path after we administratively shut the M1 BGP session.
BGP_RECONVERGE_TIMEOUT = 60
BGP_RECONVERGE_INTERVAL = 5

# Scenario 4 polls a cEOS neighbor (ARISTA01M1) via Ansible's network_cli
# connection plugin. On lab servers without ``ansible-pylibssh`` installed the
# plugin falls back to paramiko, which is slow enough that the default 60s
# ``command_timeout`` (see ``ansible/ansible.cfg``) is not enough for the
# first ``show ip bgp`` call. We raise both the per-Ansible-call timeout
# (via ``ANSIBLE_PERSISTENT_COMMAND_TIMEOUT``) and the surrounding
# ``wait_until`` budget for the scope of that test only.
SCENARIO4_RECONVERGE_TIMEOUT = 180
SCENARIO4_ANSIBLE_COMMAND_TIMEOUT_SECONDS = 180


@contextmanager
def _ansible_command_timeout(seconds):
    """Temporarily raise the network-CLI per-command timeout via env var."""
    var = "ANSIBLE_PERSISTENT_COMMAND_TIMEOUT"
    prev = os.environ.get(var)
    os.environ[var] = str(seconds)
    try:
        yield
    finally:
        if prev is None:
            os.environ.pop(var, None)
        else:
            os.environ[var] = prev


def _get_default_route_nexthops(duthost, ip_version):
    """Return the list of best-path nexthop IPs for the IPv4/IPv6 default route."""
    if ip_version == 4:
        cmd = "vtysh -c 'show ip route 0.0.0.0/0 json'"
        prefix = '0.0.0.0/0'
    else:
        cmd = "vtysh -c 'show ipv6 route ::/0 json'"
        prefix = '::/0'

    output = duthost.shell(cmd, module_ignore_errors=True)
    pytest_assert(output['rc'] == 0,
                  "Failed to read default route from DUT: {}".format(output.get('stderr')))

    route_info = json.loads(output['stdout'])
    pytest_assert(prefix in route_info and route_info[prefix],
                  "DUT has no installed default route {}".format(prefix))

    return [nh['ip'] for nh in route_info[prefix][0]['nexthops']]


def _get_neighbor_ip_by_role(duthost, role, ip_version):
    """
    Look up the BGP neighbor IP whose description matches the given role.

    For the c0 topo, BGP neighbor descriptions are populated from the
    neighbor hostnames (ARISTA01M1 / ARISTA01M0 / ARISTA01C1), so a
    case-insensitive substring match on the role keyword is unambiguous.
    """
    role = role.lower()
    neighbors = duthost.get_bgp_neighbors()
    candidates = [
        ip for ip, attrs in neighbors.items()
        if attrs.get('ip_version') == ip_version
        and role in attrs.get('description', '').lower()
    ]
    pytest_assert(
        len(candidates) == 1,
        "Expected exactly one BGP neighbor with role '{}' (IPv{}); got {}".format(
            role, ip_version, candidates),
    )
    return candidates[0]


def _bgp_set_neighbor_admin(duthost, neighbor_ip, admin_up):
    """Administratively bring a BGP neighbor up or down on the DUT."""
    action = "startup" if admin_up else "shutdown"
    cmd = "sudo config bgp {} neighbor {}".format(action, neighbor_ip)
    output = duthost.shell(cmd, module_ignore_errors=True)
    pytest_assert(
        output['rc'] == 0,
        "Failed to {} BGP neighbor {}: {}".format(action, neighbor_ip, output.get('stderr')),
    )


def _get_c0_link_ip_to_neighbor(tbinfo, neighbor_name, ip_version):
    """
    Return C0's IP on the link to the given neighbor (as the neighbor sees it).

    In topo_c0.yml the C0-side addresses of each link are listed in
    ``configuration[<neighbor>].bgp.peers[<dut_asn>]`` as a [v4, v6] pair.
    This is exactly the BGP next-hop a neighbor should observe for any
    route C0 forwards to it.
    """
    common = tbinfo['topo']['properties']['configuration_properties']['common']
    dut_asn = common['dut_asn']
    peers_block = tbinfo['topo']['properties']['configuration'][neighbor_name]['bgp']['peers']
    # YAML loads integer keys as ints, but be defensive against str keys too.
    peer_ips = peers_block.get(dut_asn) or peers_block.get(str(dut_asn))
    pytest_assert(
        peer_ips,
        "Could not find C0 (ASN {}) peer block under {} in tbinfo".format(dut_asn, neighbor_name),
    )
    want_v6 = (ip_version == 6)
    for ip in peer_ips:
        if (':' in ip) == want_v6:
            return ip.lower() if want_v6 else ip
    pytest_assert(False, "No IPv{} peer IP found for {}".format(ip_version, neighbor_name))


@pytest.mark.parametrize("ip_version", [4, 6])
def test_c0_bgp_scenario1_regular_data_path(duthost, ip_version):
    """
    Scenario #1 - Regular data path.

    On a healthy C0 topology the default route's best-path nexthop must be
    the M1 BGP peer, because M1 advertises the default with the shortest
    AS-PATH (empty). This verifies that the prepending policy in
    ``fib_c0`` is honored and that the M1 link is the preferred upstream.
    """
    m1_ip = _get_neighbor_ip_by_role(duthost, 'M1', ip_version)
    nexthops = _get_default_route_nexthops(duthost, ip_version)
    pytest_assert(
        m1_ip in nexthops,
        "Scenario 1: expected M1 peer {} to be a default-route nexthop on C0; got {}".format(
            m1_ip, nexthops),
    )


@pytest.mark.parametrize("ip_version", [4, 6])
def test_c0_bgp_scenario2_backup_data_path(duthost, ip_version):
    """
    Scenario #2 - Backup data path.

    With the direct C0<->M1 BGP session administratively down, M1 stops
    advertising the default route to C0. C0 must then re-select the next
    best path, which is M0 (AS-PATH "64900"), and install M0 as the
    default-route nexthop. The M1 session is unconditionally restored at
    teardown so the testbed is left in scenario-1 state.
    """
    m1_ip = _get_neighbor_ip_by_role(duthost, 'M1', ip_version)
    m0_ip = _get_neighbor_ip_by_role(duthost, 'M0', ip_version)

    def _m0_is_default_nexthop():
        return m0_ip in _get_default_route_nexthops(duthost, ip_version)

    try:
        logger.info("Scenario 2: shutting BGP neighbor M1 (%s) on DUT", m1_ip)
        _bgp_set_neighbor_admin(duthost, m1_ip, admin_up=False)

        pytest_assert(
            wait_until(BGP_RECONVERGE_TIMEOUT, BGP_RECONVERGE_INTERVAL, 0, _m0_is_default_nexthop),
            "Scenario 2: M0 peer {} did not become a default-route nexthop within {}s after "
            "shutting M1 ({}); last seen nexthops: {}".format(
                m0_ip, BGP_RECONVERGE_TIMEOUT, m1_ip,
                _get_default_route_nexthops(duthost, ip_version)),
        )
    finally:
        logger.info("Scenario 2 teardown: restoring BGP neighbor M1 (%s) on DUT", m1_ip)
        _bgp_set_neighbor_admin(duthost, m1_ip, admin_up=True)


@pytest.mark.parametrize("ip_version", [4, 6])
def test_c0_bgp_scenario3_provision_data_path_for_c0(duthost, ip_version):
    """
    Scenario #3 - Provision data path (for C0).

    With both the direct C0<->M1 and the C0<->M0 BGP sessions
    administratively down, the only remaining default-route advertiser is
    C1 (AS-PATH "65300 65400"), so C0 must re-select C1 as the
    default-route nexthop. This models the provisioning/recovery path
    where Primary Network is unreachable and management traffic flows via
    C1 on the Secondary Network. M1 and M0 are unconditionally restored
    at teardown so the testbed is left in scenario-1 state.
    """
    m1_ip = _get_neighbor_ip_by_role(duthost, 'M1', ip_version)
    m0_ip = _get_neighbor_ip_by_role(duthost, 'M0', ip_version)
    c1_ip = _get_neighbor_ip_by_role(duthost, 'C1', ip_version)

    def _c1_is_default_nexthop():
        return c1_ip in _get_default_route_nexthops(duthost, ip_version)

    try:
        logger.info("Scenario 3: shutting BGP neighbors M1 (%s) and M0 (%s) on DUT", m1_ip, m0_ip)
        _bgp_set_neighbor_admin(duthost, m1_ip, admin_up=False)
        _bgp_set_neighbor_admin(duthost, m0_ip, admin_up=False)

        pytest_assert(
            wait_until(BGP_RECONVERGE_TIMEOUT, BGP_RECONVERGE_INTERVAL, 0, _c1_is_default_nexthop),
            "Scenario 3: C1 peer {} did not become a default-route nexthop within {}s after "
            "shutting M1 ({}) and M0 ({}); last seen nexthops: {}".format(
                c1_ip, BGP_RECONVERGE_TIMEOUT, m1_ip, m0_ip,
                _get_default_route_nexthops(duthost, ip_version)),
        )
    finally:
        # Restore both sessions independently so one failure does not mask the other.
        logger.info("Scenario 3 teardown: restoring BGP neighbors M0 (%s) and M1 (%s) on DUT",
                    m0_ip, m1_ip)
        try:
            _bgp_set_neighbor_admin(duthost, m0_ip, admin_up=True)
        finally:
            _bgp_set_neighbor_admin(duthost, m1_ip, admin_up=True)


@pytest.mark.parametrize("ip_version", [4, 6])
def test_c0_bgp_scenario4_provision_data_path_for_m1(
    duthost, nbrhosts, localhost, ptfhost, tbinfo, ip_version,
):
    """
    Scenario #4 - Provision data path (for M1).

    With the C0<->M0 BGP session administratively down and M1's own
    default-route announcement withdrawn at the PTF ExaBGP, C0's only
    remaining default-route source is C1. C0 must then forward that
    default UP to M1 over the still-up C0<->M1 BGP session, acting as
    L3 transit between Secondary Network (via C1) and M1. M1 should
    install a BGP default route whose next-hop is C0's M1-facing IP.

    Teardown re-announces M1's default first (so M1 returns to its
    scenario-1 view), then restores the C0<->M0 BGP session.
    """
    prefix = '0.0.0.0/0' if ip_version == 4 else '::/0'

    m0_ip = _get_neighbor_ip_by_role(duthost, 'M0', ip_version)
    c0_ip_on_m1_link = _get_c0_link_ip_to_neighbor(tbinfo, 'ARISTA01M1', ip_version)
    m1_host = nbrhosts['ARISTA01M1']['host']

    nh_key = 'nhipv4' if ip_version == 4 else 'nhipv6'
    ptf_nh = tbinfo['topo']['properties']['configuration_properties']['common'][nh_key]
    m1_routes_to_toggle = {'ARISTA01M1': [(prefix, ptf_nh, None)]}

    def _m1_default_via_c0():
        """Poll M1's BGP table for `prefix` with C0 as the BGP next-hop."""
        try:
            route = m1_host.get_route(prefix)
        except Exception as exc:  # noqa: BLE001 - polling loop, log and retry
            logger.debug("get_route(%s) on M1 raised: %s", prefix, exc)
            return False
        try:
            paths = route['vrfs']['default']['bgpRouteEntries'][prefix]['bgpRoutePaths']
        except (KeyError, TypeError):
            return False
        nexthops = [str(p.get('nextHop', '')).lower() for p in paths]
        return c0_ip_on_m1_link.lower() in nexthops

    try:
        logger.info("Scenario 4: shutting BGP neighbor M0 (%s) on DUT", m0_ip)
        _bgp_set_neighbor_admin(duthost, m0_ip, admin_up=False)

        logger.info("Scenario 4: withdrawing %s announcement from ARISTA01M1 via PTF ExaBGP", prefix)
        localhost.announce_routes(
            topo_name=tbinfo['topo']['name'],
            adhoc=True,
            ptf_ip=ptfhost.mgmt_ip,
            action='withdraw',
            peers_routes_to_change=m1_routes_to_toggle,
            path='../ansible',
        )

        with _ansible_command_timeout(SCENARIO4_ANSIBLE_COMMAND_TIMEOUT_SECONDS):
            # Pre-warm the M1 SSH/network_cli connection so the first
            # polling call below does not pay the full SSH handshake cost
            # within the wait_until budget. A failure here is non-fatal:
            # we still try the polling loop and let it surface a real
            # M1-unreachable case as the actual assertion message.
            try:
                m1_host.eos_command(commands=['show version'])
            except Exception as exc:  # noqa: BLE001 - best-effort warm-up
                logger.warning(
                    "Scenario 4: M1 connection pre-warm failed: %s", exc)

            pytest_assert(
                wait_until(SCENARIO4_RECONVERGE_TIMEOUT, BGP_RECONVERGE_INTERVAL,
                           0, _m1_default_via_c0),
                "Scenario 4: M1 (ARISTA01M1) did not learn default route {} with C0 ({}) "
                "as next-hop within {}s after shutting C0<->M0 BGP ({}) and withdrawing "
                "M1's own {} announcement.".format(
                    prefix, c0_ip_on_m1_link, SCENARIO4_RECONVERGE_TIMEOUT, m0_ip, prefix),
            )
    finally:
        # Re-announce M1's own default first so M1 returns to its scenario-1
        # source-of-truth before C0<->M0 is brought back; then restore M0.
        # Use nested try/finally so a re-announce failure does not mask M0 restore.
        logger.info("Scenario 4 teardown: re-announcing %s from ARISTA01M1 via PTF ExaBGP", prefix)
        try:
            localhost.announce_routes(
                topo_name=tbinfo['topo']['name'],
                adhoc=True,
                ptf_ip=ptfhost.mgmt_ip,
                action='announce',
                peers_routes_to_change=m1_routes_to_toggle,
                path='../ansible',
            )
        finally:
            logger.info("Scenario 4 teardown: restoring BGP neighbor M0 (%s) on DUT", m0_ip)
            _bgp_set_neighbor_admin(duthost, m0_ip, admin_up=True)
