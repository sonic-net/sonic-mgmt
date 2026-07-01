"""
DHCPv6 relay VRF tests for the SONiC-native ``dhcp6relay``.

``dhcp6relay`` binds its upstream (server-facing) socket to a VRF via
``SO_BINDTODEVICE`` so that relay-forward messages reach the DHCPv6 servers
through the correct VRF routing table:

  * Option A -- a relay VLAN placed in a non-default VRF (``VLAN_INTERFACE``
    ``vrf_name``): the per-VLAN upstream (gua) socket is bound to that VRF
    (log ``Bound upstream socket for <vlan> to VRF <vrf>``);
  * Option B -- an explicit ``server_vrf`` on the ``DHCP_RELAY`` row (servers
    reachable in a VRF different from the VLAN's own): the relay opens a shared
    per-VRF upstream socket (log ``Created shared upstream socket for server VRF
    <vrf>``).

Because ``dhcp6relay`` applies ``DHCP_RELAY`` / ``VLAN_INTERFACE`` changes at
runtime, binding a VLAN's VRF (or setting ``server_vrf``) rebinds / opens the
socket without restarting the ``dhcp_relay`` container (the process PID is
unchanged). Every change is driven through the ``config`` CLI / CONFIG_DB; the
tests never pass arguments to the ``dhcp6relay`` binary or drive
``supervisorctl``.
"""
import ipaddress
import json
import logging
import uuid

import pytest

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.ptf_runner import ptf_runner
# Session-scoped autouse fixtures that stage the PTF test scripts and MACs on the
# ptf host; importing them (as every dhcp_relay test does) registers them so the
# data-plane ptf_runner below can find ptftests/py3 on the ptf host.
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # noqa: F401
from tests.common.fixtures.ptfhost_utils import change_mac_addresses      # noqa: F401
# Reuse the data-plane data fixtures from the existing v6 relay test so the VRF
# data-plane test drives the same PTF engine (dhcpv6_relay_test.DHCPTest).
from tests.dhcp_relay.test_dhcpv6_relay import (  # noqa: F401
    dut_dhcp_relay_data,
    validate_dut_routes_exist,
    testing_config,
)

pytestmark = [
    pytest.mark.topology('t0', 'm0', 'mx', 't0-2vlans'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

DHCP_RELAY_CONTAINER = "dhcp_relay"
DHCPV6_SERVERS_FIELD = "dhcpv6_servers@"
SERVER_VRF_FIELD = "server_vrf"

# A non-default VRF the relay VLAN is moved into (Option A) and a separate VRF
# used as an explicit server VRF (Option B). Names are test-unique so their
# syslog lines can be matched unambiguously.
CLIENT_VRF = "Vrf-d6relay-cli"
SERVER_VRF = "Vrf-d6relay-srv"


def _dhcp6relay_pid(duthost):
    """Return the dhcp6relay PID inside the dhcp_relay container, or ''."""
    return duthost.shell(
        "docker exec {} pidof dhcp6relay".format(DHCP_RELAY_CONTAINER),
        module_ignore_errors=True
    )["stdout"].strip()


def _dhcp6relay_running(duthost):
    return _dhcp6relay_pid(duthost) != ""


def _syslog_has(duthost, text):
    """True if a genuine dhcp6relay syslog line contains ``text``.

    ansible logs every ``sudo grep ... '<text>' ...`` command it runs into syslog,
    and that logged command line itself contains ``<text>`` -- so a naive
    whole-file grep self-matches the command echo and returns a false positive on
    the very next poll. Drop the ansible command-echo lines (the relay's own
    messages never carry the ``ansible`` tag). The VLAN/VRF names checked with
    this helper are test-unique, so a genuine relay line cannot belong to another
    test; where a VRF name is reused across tests, use _syslog_has_since."""
    out = duthost.shell(
        "sudo grep -aF '{}' /var/log/syslog | grep -avF ansible".format(text),
        module_ignore_errors=True
    )["stdout"]
    return out.strip() != ""


def _syslog_marker(duthost):
    """Write a unique marker line to syslog and return it. Pair with
    _syslog_has_since so a syslog assertion only considers relay messages logged
    AFTER this point -- immune to an earlier (possibly same-named) test's genuine
    log and to ansible's own echo of the grep command."""
    marker = "D6VRF-MARK-{}".format(uuid.uuid4().hex)
    duthost.shell("logger -t d6vrf {}".format(marker), module_ignore_errors=True)
    return marker


def _syslog_has_since(duthost, marker, text):
    """True if a genuine dhcp6relay syslog line containing ``text`` appears AFTER
    ``marker`` (see _syslog_marker). Lines before the marker -- including an
    earlier test's genuine log for a reused VRF name -- are ignored, and ansible
    command-echo lines (which embed ``text``) are dropped."""
    out = duthost.shell(
        "sudo awk -v m='{}' 'f; index($0, m){{f=1}}' /var/log/syslog "
        "| grep -aF '{}' | grep -avF ansible".format(marker, text),
        module_ignore_errors=True
    )["stdout"]
    return out.strip() != ""


@pytest.fixture(scope="function")
def vrf_relay_vlan(duthost):
    """Create a fresh VLAN in a non-default VRF, with a DHCPv6 relay config and an
    IPv6 address, while dhcp6relay is already running. Yields (vlan, vrf). Cleans
    up on teardown. ``config interface vrf bind`` strips the interface IPs, so the
    IPv6 address is added AFTER the bind.

    All operations go through the config CLI / CONFIG_DB; no container restart.
    """
    vlan_id = 4071
    vlan = "Vlan{}".format(vlan_id)
    vlan_ipv6 = "fc02:4071::1/64"
    servers = "2000::100,2000::200"
    vrf = CLIENT_VRF

    def _cleanup():
        duthost.shell("sudo config interface ip remove {} {}".format(vlan, vlan_ipv6),
                      module_ignore_errors=True)
        duthost.shell('sonic-db-cli CONFIG_DB DEL "DHCP_RELAY|{}"'.format(vlan),
                      module_ignore_errors=True)
        duthost.shell("sudo config interface vrf unbind {}".format(vlan),
                      module_ignore_errors=True)
        duthost.shell("sudo config vlan del {}".format(vlan_id), module_ignore_errors=True)
        duthost.shell("sudo config vrf del {}".format(vrf), module_ignore_errors=True)

    # Start clean in case a previous aborted run left state behind.
    _cleanup()

    duthost.shell("sudo config vrf add {}".format(vrf))
    duthost.shell("sudo config vlan add {}".format(vlan_id))
    # Bind the VLAN interface into the VRF first (this strips its IPs), then give
    # it a DHCPv6 relay config and an IPv6 address so the relay activates it.
    duthost.shell("sudo config interface vrf bind {} {}".format(vlan, vrf))
    duthost.shell('sonic-db-cli CONFIG_DB HSET "DHCP_RELAY|{}" "{}" "{}"'
                  .format(vlan, DHCPV6_SERVERS_FIELD, servers))
    duthost.shell("sudo config interface ip add {} {}".format(vlan, vlan_ipv6))

    yield vlan, vrf

    _cleanup()


@pytest.fixture(scope="function")
def server_vrf_relay_vlan(duthost):
    """Create a fresh VLAN (in the default VRF) whose DHCP_RELAY row names an
    explicit ``server_vrf`` reachable in a different, non-default VRF, while
    dhcp6relay is already running. Yields (vlan, server_vrf). Cleans up on
    teardown. All operations go through CONFIG_DB; no container restart."""
    vlan_id = 4072
    vlan = "Vlan{}".format(vlan_id)
    vlan_ipv6 = "fc02:4072::1/64"
    servers = "2000::100,2000::200"
    server_vrf = SERVER_VRF

    def _cleanup():
        duthost.shell("sudo config interface ip remove {} {}".format(vlan, vlan_ipv6),
                      module_ignore_errors=True)
        duthost.shell('sonic-db-cli CONFIG_DB DEL "DHCP_RELAY|{}"'.format(vlan),
                      module_ignore_errors=True)
        duthost.shell("sudo config vlan del {}".format(vlan_id), module_ignore_errors=True)
        duthost.shell("sudo config vrf del {}".format(server_vrf), module_ignore_errors=True)

    _cleanup()

    # The server VRF must exist so the relay can SO_BINDTODEVICE the shared
    # upstream socket to it.
    duthost.shell("sudo config vrf add {}".format(server_vrf))
    duthost.shell("sudo config vlan add {}".format(vlan_id))
    duthost.shell('sonic-db-cli CONFIG_DB HSET "DHCP_RELAY|{}" "{}" "{}"'
                  .format(vlan, DHCPV6_SERVERS_FIELD, servers))
    duthost.shell('sonic-db-cli CONFIG_DB HSET "DHCP_RELAY|{}" "{}" "{}"'
                  .format(vlan, SERVER_VRF_FIELD, server_vrf))
    duthost.shell("sudo config interface ip add {} {}".format(vlan, vlan_ipv6))

    yield vlan, server_vrf

    _cleanup()


def test_dhcp6relay_binds_upstream_socket_to_vlan_vrf(duthost, vrf_relay_vlan):
    """Option A: a relay VLAN in a non-default VRF makes dhcp6relay bind its
    upstream socket to that VRF, at runtime, without a container restart."""
    vlan, vrf = vrf_relay_vlan
    pid_before = _dhcp6relay_pid(duthost)
    pytest_assert(pid_before, "dhcp6relay is not running before the VRF test")

    bound_log = "Bound upstream socket for {} to VRF {}".format(vlan, vrf)
    pytest_assert(
        wait_until(60, 5, 5, _syslog_has, duthost, bound_log),
        "dhcp6relay did not bind the upstream socket for {} to VRF {} "
        "(expected syslog: '{}')".format(vlan, vrf, bound_log)
    )

    pytest_assert(_dhcp6relay_running(duthost), "dhcp6relay stopped after VRF bind")
    pytest_assert(
        _dhcp6relay_pid(duthost) == pid_before,
        "dhcp6relay PID changed after VRF bind -- the container was restarted "
        "instead of applying the VRF binding at runtime"
    )


def test_dhcp6relay_opens_shared_socket_for_server_vrf(duthost, server_vrf_relay_vlan):
    """Option B: an explicit server_vrf makes dhcp6relay open a shared upstream
    socket bound to that VRF, at runtime, without a container restart."""
    vlan, server_vrf = server_vrf_relay_vlan
    pid_before = _dhcp6relay_pid(duthost)
    pytest_assert(pid_before, "dhcp6relay is not running before the server_vrf test")

    created_log = "Created shared upstream socket for server VRF {}".format(server_vrf)
    pytest_assert(
        wait_until(60, 5, 5, _syslog_has, duthost, created_log),
        "dhcp6relay did not open a shared upstream socket for server VRF {} "
        "(expected syslog: '{}')".format(server_vrf, created_log)
    )

    pytest_assert(_dhcp6relay_running(duthost), "dhcp6relay stopped after server_vrf config")
    pytest_assert(
        _dhcp6relay_pid(duthost) == pid_before,
        "dhcp6relay PID changed after server_vrf config -- the container was "
        "restarted instead of applying the server VRF at runtime"
    )


def _vlan_master(duthost, vlan):
    """Return the VRF master device of a VLAN interface, or '' if none."""
    out = duthost.shell(
        "ip link show {} 2>/dev/null | grep -oE 'master [^ ]+' || true".format(vlan),
        module_ignore_errors=True
    )["stdout"].strip()
    return out.replace("master ", "") if out else ""


def test_dhcp6relay_vrf_change_rebinds_at_runtime(duthost):
    """Update path: changing the relay VLAN's VRF at runtime makes dhcp6relay
    tear the relay down and re-bind its upstream socket to the new VRF, without a
    container restart (exercises the reconcile teardown + re-arm path)."""
    vid, vlan, ipv6 = 4073, "Vlan4073", "fc02:4073::1/64"
    vrf_a, vrf_b = "Vrf-d6relay-a", "Vrf-d6relay-b"
    servers = "2000::100,2000::200"

    def _clean():
        duthost.shell("sudo config interface ip remove {} {}".format(vlan, ipv6), module_ignore_errors=True)
        duthost.shell('sonic-db-cli CONFIG_DB DEL "DHCP_RELAY|{}"'.format(vlan), module_ignore_errors=True)
        duthost.shell("sudo config interface vrf unbind {}".format(vlan), module_ignore_errors=True)
        duthost.shell("sudo config vlan del {}".format(vid), module_ignore_errors=True)
        for v in (vrf_a, vrf_b):
            duthost.shell("sudo config vrf del {}".format(v), module_ignore_errors=True)

    _clean()
    try:
        duthost.shell("sudo config vrf add {}".format(vrf_a))
        duthost.shell("sudo config vrf add {}".format(vrf_b))
        duthost.shell("sudo config vlan add {}".format(vid))
        duthost.shell("sudo config interface vrf bind {} {}".format(vlan, vrf_a))
        duthost.shell('sonic-db-cli CONFIG_DB HSET "DHCP_RELAY|{}" "{}" "{}"'
                      .format(vlan, DHCPV6_SERVERS_FIELD, servers))
        duthost.shell("sudo config interface ip add {} {}".format(vlan, ipv6))

        pid = _dhcp6relay_pid(duthost)
        pytest_assert(pid, "dhcp6relay is not running before the rebind test")
        pytest_assert(
            wait_until(60, 5, 5, _syslog_has, duthost,
                       "Bound upstream socket for {} to VRF {}".format(vlan, vrf_a)),
            "dhcp6relay did not bind {} to VRF {}".format(vlan, vrf_a))

        # Move the VLAN from vrf_a to vrf_b at runtime.
        duthost.shell("sudo config interface vrf unbind {}".format(vlan))
        duthost.shell("sudo config interface vrf bind {} {}".format(vlan, vrf_b))
        duthost.shell("sudo config interface ip add {} {}".format(vlan, ipv6))

        pytest_assert(
            wait_until(60, 5, 5, _syslog_has, duthost,
                       "Bound upstream socket for {} to VRF {}".format(vlan, vrf_b)),
            "dhcp6relay did not re-bind {} to VRF {} after the runtime VRF change".format(vlan, vrf_b))
        pytest_assert(_dhcp6relay_running(duthost), "dhcp6relay stopped after VRF change")
        pytest_assert(_dhcp6relay_pid(duthost) == pid,
                      "dhcp6relay PID changed after VRF change -- the container was restarted")
    finally:
        _clean()


def test_dhcp6relay_vrf_unbind_reverts_at_runtime(duthost):
    """Delete path: unbinding the relay VLAN's VRF at runtime reverts the relay to
    the global table (the upstream socket is no longer VRF-bound), without a
    container restart."""
    vid, vlan, ipv6 = 4074, "Vlan4074", "fc02:4074::1/64"
    vrf = "Vrf-d6relay-u"
    servers = "2000::100,2000::200"

    def _clean():
        duthost.shell("sudo config interface ip remove {} {}".format(vlan, ipv6), module_ignore_errors=True)
        duthost.shell('sonic-db-cli CONFIG_DB DEL "DHCP_RELAY|{}"'.format(vlan), module_ignore_errors=True)
        duthost.shell("sudo config interface vrf unbind {}".format(vlan), module_ignore_errors=True)
        duthost.shell("sudo config vlan del {}".format(vid), module_ignore_errors=True)
        duthost.shell("sudo config vrf del {}".format(vrf), module_ignore_errors=True)

    _clean()
    try:
        duthost.shell("sudo config vrf add {}".format(vrf))
        duthost.shell("sudo config vlan add {}".format(vid))
        duthost.shell("sudo config interface vrf bind {} {}".format(vlan, vrf))
        duthost.shell('sonic-db-cli CONFIG_DB HSET "DHCP_RELAY|{}" "{}" "{}"'
                      .format(vlan, DHCPV6_SERVERS_FIELD, servers))
        duthost.shell("sudo config interface ip add {} {}".format(vlan, ipv6))

        pid = _dhcp6relay_pid(duthost)
        pytest_assert(pid, "dhcp6relay is not running before the unbind test")
        pytest_assert(
            wait_until(60, 5, 5, _syslog_has, duthost,
                       "Bound upstream socket for {} to VRF {}".format(vlan, vrf)),
            "dhcp6relay did not bind {} to VRF {}".format(vlan, vrf))
        pytest_assert(_vlan_master(duthost, vlan) == vrf,
                      "{} was not enslaved to VRF {}".format(vlan, vrf))

        # Unbind the VRF at runtime and restore the IPv6 address in the global table.
        marker = _syslog_marker(duthost)
        duthost.shell("sudo config interface vrf unbind {}".format(vlan))
        duthost.shell("sudo config interface ip add {} {}".format(vlan, ipv6))

        pytest_assert(
            wait_until(60, 5, 0, lambda: _vlan_master(duthost, vlan) == ""),
            "{} is still enslaved to a VRF after unbind".format(vlan))
        # The relay re-processes the VLAN back in the global table at runtime
        # (logs "add <vlan> relay config ... vrf default"); marker-scoped so this
        # is the post-unbind re-arm, not the original VRF bind.
        pytest_assert(
            wait_until(60, 5, 5, _syslog_has_since, duthost, marker,
                       "add {} relay config".format(vlan)),
            "dhcp6relay did not re-process {} after the VRF unbind".format(vlan))
        pytest_assert(_dhcp6relay_running(duthost), "dhcp6relay stopped after VRF unbind")
        pytest_assert(_dhcp6relay_pid(duthost) == pid,
                      "dhcp6relay PID changed after VRF unbind -- the container was restarted")
    finally:
        _clean()


DP_VRF = "Vrf-d6relay-dp"
DP_CLIENT_VRF = "Vrf-d6dp-cli"
DP_SERVER_VRF = "Vrf-d6dp-srv"


def _save_interface_ip_entries(duthost, table, interface):
    """Save CONFIG_DB base + IP entries for an interface (so they can be restored
    after `config interface vrf bind` strips them). Mirrors the v4 VRF test."""
    base_raw = duthost.shell('redis-cli -n 4 --json HGETALL "{}|{}"'.format(table, interface),
                             verbose=False, module_ignore_errors=True)["stdout"].strip()
    base_fields = json.loads(base_raw) if base_raw else {}
    ip_keys_raw = duthost.shell('redis-cli -n 4 --json keys "{}|{}|*"'.format(table, interface),
                                verbose=False, module_ignore_errors=True)["stdout"].strip()
    ip_keys = json.loads(ip_keys_raw) if ip_keys_raw else []
    saved = {"{}|{}".format(table, interface): base_fields}
    for key in ip_keys:
        raw = duthost.shell('redis-cli -n 4 --json HGETALL "{}"'.format(key),
                            verbose=False, module_ignore_errors=True)["stdout"].strip()
        saved[key] = json.loads(raw) if raw else {}
    return saved


def _restore_interface_ip_entries(duthost, saved_entries):
    for key, fields in saved_entries.items():
        if not fields or fields == {"NULL": "NULL"}:
            duthost.shell('sonic-db-cli CONFIG_DB HSET "{}" "NULL" "NULL"'.format(key),
                          module_ignore_errors=True)
        else:
            for field, value in fields.items():
                duthost.shell('sonic-db-cli CONFIG_DB HSET "{}" "{}" "{}"'.format(key, field, value),
                              module_ignore_errors=True)


def _uplink_nexthop_and_local(duthost, saved_pc_ips):
    """Return ``(peer, local)`` for a directly-connected IPv6 BGP session on one
    of the uplink PortChannels: ``peer`` is the connected neighbour GUA (the
    single ``::/0`` nexthop installed inside the test VRF) and ``local`` is the
    DUT's own GUA on that uplink -- the source address the relay-forward
    egresses with, hence the address the simulated server must send its Reply
    back to in the cross-VRF (Option B) case.

    Both are *global* addresses on a connected uplink subnet (never link-local),
    so ``config route add ... nexthop vrf <vrf> <peer>`` accepts the nexthop and
    the DUT resolves it via ND once the uplink is bound into the VRF. (A
    BGP-learned route's nexthop is link-local and is rejected by
    ``config route add`` -- hence the connected peer.)"""
    uplink_ips = set()
    for key in saved_pc_ips:
        parts = key.split("|", 2)
        if len(parts) == 3:
            try:
                uplink_ips.add(str(ipaddress.ip_interface(parts[2]).ip))
            except ValueError:
                # parts[2] is not an IP-bearing INTERFACE|<port>|<prefix> row
                # (e.g. a bare INTERFACE|<port> key with no address); skip it.
                continue
    keys_raw = duthost.shell('redis-cli -n 4 --json keys "BGP_NEIGHBOR|*"',
                             verbose=False, module_ignore_errors=True)["stdout"].strip()
    keys = json.loads(keys_raw) if keys_raw else []
    for key in keys:
        nbr = key.split("|", 1)[1]
        try:
            ip = ipaddress.ip_address(nbr)
        except ValueError:
            continue
        if ip.version != 6 or ip.is_link_local:
            continue
        local_addr = duthost.shell('redis-cli -n 4 HGET "{}" local_addr'.format(key),
                                   verbose=False, module_ignore_errors=True)["stdout"].strip()
        if local_addr in uplink_ips:
            return nbr, local_addr
    return None, None


def _seed_client_neighbor(duthost, ptfhost, client_port_idx, vlan_iface):
    """Seed the simulated client's IPv6 neighbour on the relay VLAN.

    dhcp6relay delivers the DHCPv6 Advertise/Reply by *unicasting* to the
    client's link-local (unlike DHCPv4, which can broadcast the Offer), so it
    needs the client neighbour resolved. Right after a live
    ``config interface vrf bind`` the VLAN's neighbour cache is cold, so seed the
    ptf port's link-local -> MAC as a permanent neighbour to make the final hop
    deterministic."""
    mac = ptfhost.shell("cat /sys/class/net/eth{}/address".format(client_port_idx),
                        module_ignore_errors=True)["stdout"].strip()
    lla = ptfhost.shell(
        "ip -6 addr show eth{} scope link | awk '/inet6/ {{print $2}}' | cut -d/ -f1".format(client_port_idx),
        module_ignore_errors=True)["stdout"].strip()
    if mac and lla:
        duthost.shell("ip -6 neigh replace {} lladdr {} dev {} nud permanent".format(lla, mac, vlan_iface),
                      module_ignore_errors=True)


def _ipv6_route_exists(duthost, addr):
    """True if a route to ``addr`` is present in the default routing table."""
    out = duthost.shell("show ipv6 route {} json".format(addr), module_ignore_errors=True)["stdout"]
    try:
        return bool(out.strip()) and bool(json.loads(out))
    except ValueError:
        return False


def _run_dhcpv6_ptf(ptfhost, duthost, dhcp_relay, servers, relay_iface_ip, log_file):
    """Drive the standard DHCPv6 relay PTF exchange (Solicit/Advertise +
    Request/Reply + the relayed-relay cases). ``relay_iface_ip`` is the address
    the simulated server sends its replies to: the relay VLAN address when the
    relay-forward egresses the VLAN's own table, or the DUT's uplink GUA when it
    egresses an explicit server VRF (the shared per-server-VRF socket's
    source)."""
    ptf_runner(ptfhost,
               "ptftests",
               "dhcpv6_relay_test.DHCPTest",
               platform_dir="ptftests",
               params={"hostname": duthost.hostname,
                       "client_port_index": dhcp_relay['client_iface']['port_idx'],
                       "leaf_port_indices": repr(dhcp_relay['uplink_port_indices']),
                       "num_dhcp_servers": len(servers),
                       "server_ip": str(servers[0]),
                       "relay_iface_ip": str(relay_iface_ip),
                       "relay_iface_mac": str(dhcp_relay['downlink_vlan_iface']['mac']),
                       "relay_link_local": str(dhcp_relay['down_interface_link_local']),
                       "vlan_ip": str(dhcp_relay['downlink_vlan_iface']['addr']),
                       "uplink_mac": str(dhcp_relay['uplink_mac']),
                       "loopback_ipv6": str(dhcp_relay['loopback_ipv6']),
                       "is_dualtor": str(dhcp_relay['is_dualtor'])},
               log_file=log_file, is_python3=True)


@pytest.fixture
def frr_recovery_after_vrf_unbind(duthosts, rand_one_dut_hostname, loganalyzer):
    """Recover FRR after ``config vrf del`` (which implicitly unbinds every
    member interface). The implicit unbind can leave BGP-learned routes in
    FAILED_INSTALL -- zebra does not retry -- which trips monit's ``routeCheck``
    (and the next module's pre-sanity ``check_monit``). A full
    ``config bgp shutdown all`` / ``startup all`` flushes and re-installs the
    routes; we then poll ``route_check.py`` until it converges. The transient
    routeCheck ERRs are added to loganalyzer's ignore list for the duration.
    Copied from the v4 dhcp_relay non-default-VRF test."""
    duthost = duthosts[rand_one_dut_hostname]
    la = loganalyzer.get(duthost.hostname) if loganalyzer else None

    transient_ignores = [
        r".*ERR monit.*'routeCheck'.*",
        r".*ERR route_check.*Some routes have failed state in FRR.*",
        r".*ERR route_check.*Some routes are not set offloaded in FRR.*",
    ]
    saved_ignore = None
    if la is not None:
        saved_ignore = list(la.ignore_regex)
        la.ignore_regex.extend(transient_ignores)

    yield

    try:
        duthost.shell("sudo config bgp shutdown all", module_ignore_errors=True)
        duthost.shell("sudo config bgp startup all", module_ignore_errors=True)
        if not wait_until(180, 5, 0, lambda: duthost.shell(
                "sudo /usr/local/bin/route_check.py", module_ignore_errors=True)["rc"] == 0):
            logger.warning("route_check did not converge within 180s after VRF "
                           "unbind BGP shutdown/startup; continuing teardown anyway")
    finally:
        if la is not None and saved_ignore is not None:
            la.ignore_regex[:] = saved_ignore


def test_dhcp6relay_dataplane_client_server_same_vrf(
        ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,  # noqa: F811
        frr_recovery_after_vrf_unbind):
    """Data-plane (Option A): the relay VLAN AND its uplinks (servers) are in the
    SAME non-default VRF. dhcp6relay binds the per-VLAN upstream socket to that
    VRF, relays a DHCPv6 client exchange through it to the server, and relays the
    server's Reply back to the PTF client -- proving the VRF-bound socket carries
    real traffic bidirectionally. Mirrors v4 test_dhcp_relay_with_non_default_vrf.
    Invasive: temporarily moves production interfaces into a VRF and restores
    them on teardown (BGP recovery via the frr_recovery_after_vrf_unbind
    fixture)."""
    _, duthost = testing_config

    for dhcp_relay in dut_dhcp_relay_data:
        vlan_iface = str(dhcp_relay['downlink_vlan_iface']['name'])
        vlan_ip = "{}/{}".format(dhcp_relay['downlink_vlan_iface']['addr'],
                                 dhcp_relay['downlink_vlan_iface']['mask'])
        uplinks = dhcp_relay['uplink_interfaces']
        servers = dhcp_relay['downlink_vlan_iface']['dhcpv6_server_addrs']

        saved_vlan_ips = _save_interface_ip_entries(duthost, "VLAN_INTERFACE", vlan_iface)
        saved_pc_ips = {}
        for pc in uplinks:
            saved_pc_ips.update(_save_interface_ip_entries(duthost, "PORTCHANNEL_INTERFACE", pc))

        nexthop, _local = _uplink_nexthop_and_local(duthost, saved_pc_ips)
        pytest_assert(nexthop, "Could not derive a connected IPv6 uplink nexthop for the test VRF")

        def _remove_saved_ips():
            duthost.shell("sudo config interface ip remove {} {}".format(vlan_iface, vlan_ip),
                          module_ignore_errors=True)
            for pc in uplinks:
                for key in list(saved_pc_ips.keys()):
                    parts = key.split("|", 2)
                    if len(parts) == 3 and parts[1] == pc:
                        duthost.shell("sudo config interface ip remove {} {}".format(pc, parts[2]),
                                      module_ignore_errors=True)

        try:
            _remove_saved_ips()
            marker = _syslog_marker(duthost)
            duthost.shell("sudo config vrf add {}".format(DP_VRF))
            for pc in uplinks:
                duthost.shell("sudo config interface vrf bind {} {}".format(pc, DP_VRF))
            duthost.shell("sudo config interface vrf bind {} {}".format(vlan_iface, DP_VRF))
            _restore_interface_ip_entries(duthost, saved_vlan_ips)
            _restore_interface_ip_entries(duthost, saved_pc_ips)

            # A single default route inside the VRF via a connected uplink peer
            # gives the relay-forward a path to the servers (v4 test parity).
            duthost.shell("sudo config route add prefix vrf {} ::/0 nexthop vrf {} {}".format(
                DP_VRF, DP_VRF, nexthop))

            pytest_assert(
                wait_until(90, 5, 5, _syslog_has_since, duthost, marker,
                           "Bound upstream socket for {} to VRF {}".format(vlan_iface, DP_VRF)),
                "dhcp6relay did not bind {} to VRF {} before the data-plane run".format(vlan_iface, DP_VRF))

            _seed_client_neighbor(duthost, ptfhost, dhcp_relay['client_iface']['port_idx'], vlan_iface)

            _run_dhcpv6_ptf(ptfhost, duthost, dhcp_relay, servers,
                            dhcp_relay['downlink_vlan_iface']['addr'],
                            "/tmp/dhcpv6_relay_vrf.DHCPTest.log")
        finally:
            duthost.shell("sudo config route del prefix vrf {} ::/0 nexthop vrf {} {}".format(
                DP_VRF, DP_VRF, nexthop), module_ignore_errors=True)
            _remove_saved_ips()
            duthost.shell("sudo config interface vrf unbind {}".format(vlan_iface), module_ignore_errors=True)
            for pc in uplinks:
                duthost.shell("sudo config interface vrf unbind {}".format(pc), module_ignore_errors=True)
            _restore_interface_ip_entries(duthost, saved_vlan_ips)
            _restore_interface_ip_entries(duthost, saved_pc_ips)
            duthost.shell("sudo config vrf del {}".format(DP_VRF), module_ignore_errors=True)
            duthost.shell("sudo config save -y", module_ignore_errors=True)


def test_dhcp6relay_dataplane_client_server_different_vrf(
        ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,  # noqa: F811
        frr_recovery_after_vrf_unbind):
    """Data-plane (Option B): the relay VLAN (client) is in one non-default VRF
    and the DHCPv6 servers are reachable in a DIFFERENT non-default VRF, declared
    on the DHCP_RELAY row via ``server_vrf``. dhcp6relay sends the relay-forward
    on the shared per-server-VRF socket (egressing in the server VRF) and relays
    the server's Reply -- received back on that shared socket -- to the client in
    the client VRF. Mirrors v4 test_dhcp_relay_with_different_non_default_vrf.

    The relay-forward egresses the server VRF sourced from the DUT's uplink GUA,
    so the simulated server must send its Reply to that GUA (passed as
    ``relay_iface_ip``), not to the client VLAN address. Invasive: temporarily
    moves production interfaces into VRFs and restores them on teardown."""
    _, duthost = testing_config

    for dhcp_relay in dut_dhcp_relay_data:
        vlan_iface = str(dhcp_relay['downlink_vlan_iface']['name'])
        vlan_ip = "{}/{}".format(dhcp_relay['downlink_vlan_iface']['addr'],
                                 dhcp_relay['downlink_vlan_iface']['mask'])
        uplinks = dhcp_relay['uplink_interfaces']
        servers = dhcp_relay['downlink_vlan_iface']['dhcpv6_server_addrs']

        saved_vlan_ips = _save_interface_ip_entries(duthost, "VLAN_INTERFACE", vlan_iface)
        saved_pc_ips = {}
        for pc in uplinks:
            saved_pc_ips.update(_save_interface_ip_entries(duthost, "PORTCHANNEL_INTERFACE", pc))

        nexthop, local_gua = _uplink_nexthop_and_local(duthost, saved_pc_ips)
        pytest_assert(nexthop and local_gua,
                      "Could not derive a connected IPv6 uplink peer/local for the server VRF")

        def _remove_saved_ips():
            duthost.shell("sudo config interface ip remove {} {}".format(vlan_iface, vlan_ip),
                          module_ignore_errors=True)
            for pc in uplinks:
                for key in list(saved_pc_ips.keys()):
                    parts = key.split("|", 2)
                    if len(parts) == 3 and parts[1] == pc:
                        duthost.shell("sudo config interface ip remove {} {}".format(pc, parts[2]),
                                      module_ignore_errors=True)

        try:
            _remove_saved_ips()
            marker = _syslog_marker(duthost)
            # Client VLAN in one VRF; uplinks (servers) in a different VRF.
            duthost.shell("sudo config vrf add {}".format(DP_CLIENT_VRF))
            duthost.shell("sudo config vrf add {}".format(DP_SERVER_VRF))
            for pc in uplinks:
                duthost.shell("sudo config interface vrf bind {} {}".format(pc, DP_SERVER_VRF))
            duthost.shell("sudo config interface vrf bind {} {}".format(vlan_iface, DP_CLIENT_VRF))
            _restore_interface_ip_entries(duthost, saved_vlan_ips)
            _restore_interface_ip_entries(duthost, saved_pc_ips)

            # Route to the servers inside the SERVER VRF (relay-forward egress path).
            duthost.shell("sudo config route add prefix vrf {} ::/0 nexthop vrf {} {}".format(
                DP_SERVER_VRF, DP_SERVER_VRF, nexthop))

            # Declare the server VRF on the relay row -> relay opens the shared socket.
            duthost.shell('sonic-db-cli CONFIG_DB HSET "DHCP_RELAY|{}" server_vrf "{}"'.format(
                vlan_iface, DP_SERVER_VRF))

            pytest_assert(
                wait_until(90, 5, 5, _syslog_has_since, duthost, marker,
                           "Created shared upstream socket for server VRF {}".format(DP_SERVER_VRF)),
                "dhcp6relay did not open the shared socket for server VRF {}".format(DP_SERVER_VRF))

            _seed_client_neighbor(duthost, ptfhost, dhcp_relay['client_iface']['port_idx'], vlan_iface)

            _run_dhcpv6_ptf(ptfhost, duthost, dhcp_relay, servers, local_gua,
                            "/tmp/dhcpv6_relay_diffvrf.DHCPTest.log")
        finally:
            duthost.shell('sonic-db-cli CONFIG_DB HDEL "DHCP_RELAY|{}" server_vrf'.format(vlan_iface),
                          module_ignore_errors=True)
            duthost.shell("sudo config route del prefix vrf {} ::/0 nexthop vrf {} {}".format(
                DP_SERVER_VRF, DP_SERVER_VRF, nexthop), module_ignore_errors=True)
            _remove_saved_ips()
            duthost.shell("sudo config interface vrf unbind {}".format(vlan_iface), module_ignore_errors=True)
            for pc in uplinks:
                duthost.shell("sudo config interface vrf unbind {}".format(pc), module_ignore_errors=True)
            _restore_interface_ip_entries(duthost, saved_vlan_ips)
            _restore_interface_ip_entries(duthost, saved_pc_ips)
            duthost.shell("sudo config vrf del {}".format(DP_CLIENT_VRF), module_ignore_errors=True)
            duthost.shell("sudo config vrf del {}".format(DP_SERVER_VRF), module_ignore_errors=True)
            duthost.shell("sudo config save -y", module_ignore_errors=True)


def test_dhcp6relay_dataplane_client_default_server_vrf(
        ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,  # noqa: F811
        frr_recovery_after_vrf_unbind):
    """Data-plane (Option B in isolation): the relay VLAN (client) stays in the
    DEFAULT/global table while only the DHCPv6 servers are reachable in a
    non-default ``server_vrf`` -- the common deployment where the relay is global
    and the servers sit behind a services/mgmt VRF. Only the shared
    per-server-VRF socket is exercised; the per-VLAN gua socket is NOT bound to a
    VRF (Option A is not involved). Invasive: moves only the uplinks into the
    server VRF and restores them on teardown."""
    _, duthost = testing_config

    for dhcp_relay in dut_dhcp_relay_data:
        vlan_iface = str(dhcp_relay['downlink_vlan_iface']['name'])
        uplinks = dhcp_relay['uplink_interfaces']
        servers = dhcp_relay['downlink_vlan_iface']['dhcpv6_server_addrs']

        saved_pc_ips = {}
        for pc in uplinks:
            saved_pc_ips.update(_save_interface_ip_entries(duthost, "PORTCHANNEL_INTERFACE", pc))

        nexthop, local_gua = _uplink_nexthop_and_local(duthost, saved_pc_ips)
        pytest_assert(nexthop and local_gua,
                      "Could not derive a connected IPv6 uplink peer/local for the server VRF")

        def _remove_uplink_ips():
            for pc in uplinks:
                for key in list(saved_pc_ips.keys()):
                    parts = key.split("|", 2)
                    if len(parts) == 3 and parts[1] == pc:
                        duthost.shell("sudo config interface ip remove {} {}".format(pc, parts[2]),
                                      module_ignore_errors=True)

        try:
            # Only the uplinks (server path) move into the server VRF; the client
            # VLAN stays in the default table.
            _remove_uplink_ips()
            marker = _syslog_marker(duthost)
            duthost.shell("sudo config vrf add {}".format(DP_SERVER_VRF))
            for pc in uplinks:
                duthost.shell("sudo config interface vrf bind {} {}".format(pc, DP_SERVER_VRF))
            _restore_interface_ip_entries(duthost, saved_pc_ips)

            duthost.shell("sudo config route add prefix vrf {} ::/0 nexthop vrf {} {}".format(
                DP_SERVER_VRF, DP_SERVER_VRF, nexthop))

            duthost.shell('sonic-db-cli CONFIG_DB HSET "DHCP_RELAY|{}" server_vrf "{}"'.format(
                vlan_iface, DP_SERVER_VRF))

            pytest_assert(
                wait_until(90, 5, 5, _syslog_has_since, duthost, marker,
                           "Created shared upstream socket for server VRF {}".format(DP_SERVER_VRF)),
                "dhcp6relay did not open the shared socket for server VRF {}".format(DP_SERVER_VRF))

            _seed_client_neighbor(duthost, ptfhost, dhcp_relay['client_iface']['port_idx'], vlan_iface)

            _run_dhcpv6_ptf(ptfhost, duthost, dhcp_relay, servers, local_gua,
                            "/tmp/dhcpv6_relay_srvonly.DHCPTest.log")
        finally:
            duthost.shell('sonic-db-cli CONFIG_DB HDEL "DHCP_RELAY|{}" server_vrf'.format(vlan_iface),
                          module_ignore_errors=True)
            duthost.shell("sudo config route del prefix vrf {} ::/0 nexthop vrf {} {}".format(
                DP_SERVER_VRF, DP_SERVER_VRF, nexthop), module_ignore_errors=True)
            _remove_uplink_ips()
            for pc in uplinks:
                duthost.shell("sudo config interface vrf unbind {}".format(pc), module_ignore_errors=True)
            _restore_interface_ip_entries(duthost, saved_pc_ips)
            duthost.shell("sudo config vrf del {}".format(DP_SERVER_VRF), module_ignore_errors=True)
            duthost.shell("sudo config save -y", module_ignore_errors=True)


def test_dhcp6relay_dataplane_survives_runtime_vrf_unbind(
        ptfhost, dut_dhcp_relay_data, validate_dut_routes_exist, testing_config,  # noqa: F811
        frr_recovery_after_vrf_unbind):
    """Runtime continuity: relay a DHCPv6 exchange with the VLAN + uplinks in a
    non-default VRF, then UNBIND them back to the default table at runtime and
    confirm traffic is still relayed -- now in the default table -- WITHOUT
    restarting the dhcp_relay container (dhcp6relay PID unchanged). Ties the
    runtime-reconfig machinery to the VRF data path. Invasive: moves production
    interfaces into a VRF and back, with BGP recovery."""
    _, duthost = testing_config

    for dhcp_relay in dut_dhcp_relay_data:
        vlan_iface = str(dhcp_relay['downlink_vlan_iface']['name'])
        vlan_ip = "{}/{}".format(dhcp_relay['downlink_vlan_iface']['addr'],
                                 dhcp_relay['downlink_vlan_iface']['mask'])
        vlan_addr = str(dhcp_relay['downlink_vlan_iface']['addr'])
        uplinks = dhcp_relay['uplink_interfaces']
        servers = dhcp_relay['downlink_vlan_iface']['dhcpv6_server_addrs']
        client_idx = dhcp_relay['client_iface']['port_idx']

        saved_vlan_ips = _save_interface_ip_entries(duthost, "VLAN_INTERFACE", vlan_iface)
        saved_pc_ips = {}
        for pc in uplinks:
            saved_pc_ips.update(_save_interface_ip_entries(duthost, "PORTCHANNEL_INTERFACE", pc))

        nexthop, _local = _uplink_nexthop_and_local(duthost, saved_pc_ips)
        pytest_assert(nexthop, "Could not derive a connected IPv6 uplink nexthop for the test VRF")

        def _remove_saved_ips():
            duthost.shell("sudo config interface ip remove {} {}".format(vlan_iface, vlan_ip),
                          module_ignore_errors=True)
            for pc in uplinks:
                for key in list(saved_pc_ips.keys()):
                    parts = key.split("|", 2)
                    if len(parts) == 3 and parts[1] == pc:
                        duthost.shell("sudo config interface ip remove {} {}".format(pc, parts[2]),
                                      module_ignore_errors=True)

        pid = _dhcp6relay_pid(duthost)
        pytest_assert(pid, "dhcp6relay is not running at the start of the test")

        try:
            # Phase 1: VLAN + uplinks in a non-default VRF -> data-plane over VRF.
            _remove_saved_ips()
            marker = _syslog_marker(duthost)
            duthost.shell("sudo config vrf add {}".format(DP_VRF))
            for pc in uplinks:
                duthost.shell("sudo config interface vrf bind {} {}".format(pc, DP_VRF))
            duthost.shell("sudo config interface vrf bind {} {}".format(vlan_iface, DP_VRF))
            _restore_interface_ip_entries(duthost, saved_vlan_ips)
            _restore_interface_ip_entries(duthost, saved_pc_ips)
            duthost.shell("sudo config route add prefix vrf {} ::/0 nexthop vrf {} {}".format(
                DP_VRF, DP_VRF, nexthop))
            pytest_assert(
                wait_until(90, 5, 5, _syslog_has_since, duthost, marker,
                           "Bound upstream socket for {} to VRF {}".format(vlan_iface, DP_VRF)),
                "dhcp6relay did not bind {} to VRF {}".format(vlan_iface, DP_VRF))
            _seed_client_neighbor(duthost, ptfhost, client_idx, vlan_iface)
            _run_dhcpv6_ptf(ptfhost, duthost, dhcp_relay, servers, vlan_addr,
                            "/tmp/dhcpv6_relay_runtime_vrf.DHCPTest.log")

            # Phase 2: UNBIND back to the default table at runtime, re-add IPs.
            duthost.shell("sudo config route del prefix vrf {} ::/0 nexthop vrf {} {}".format(
                DP_VRF, DP_VRF, nexthop), module_ignore_errors=True)
            _remove_saved_ips()
            duthost.shell("sudo config interface vrf unbind {}".format(vlan_iface))
            for pc in uplinks:
                duthost.shell("sudo config interface vrf unbind {}".format(pc))
            _restore_interface_ip_entries(duthost, saved_vlan_ips)
            _restore_interface_ip_entries(duthost, saved_pc_ips)
            # Re-establish BGP in the default table so the route to the servers
            # returns before the second data-plane run.
            duthost.shell("sudo config bgp shutdown all", module_ignore_errors=True)
            duthost.shell("sudo config bgp startup all", module_ignore_errors=True)
            pytest_assert(
                wait_until(180, 10, 0, _ipv6_route_exists, duthost, servers[0]),
                "default-table route to {} did not return after the runtime VRF unbind".format(servers[0]))
            pytest_assert(
                wait_until(60, 5, 0, lambda: _vlan_master(duthost, vlan_iface) == ""),
                "{} still enslaved to a VRF after the runtime unbind".format(vlan_iface))
            _seed_client_neighbor(duthost, ptfhost, client_idx, vlan_iface)
            _run_dhcpv6_ptf(ptfhost, duthost, dhcp_relay, servers, vlan_addr,
                            "/tmp/dhcpv6_relay_runtime_default.DHCPTest.log")

            pytest_assert(_dhcp6relay_running(duthost),
                          "dhcp6relay stopped during the runtime VRF change")
            pytest_assert(_dhcp6relay_pid(duthost) == pid,
                          "dhcp6relay PID changed -- container restarted during the runtime VRF change")
        finally:
            duthost.shell("sudo config route del prefix vrf {} ::/0 nexthop vrf {} {}".format(
                DP_VRF, DP_VRF, nexthop), module_ignore_errors=True)
            _remove_saved_ips()
            duthost.shell("sudo config interface vrf unbind {}".format(vlan_iface), module_ignore_errors=True)
            for pc in uplinks:
                duthost.shell("sudo config interface vrf unbind {}".format(pc), module_ignore_errors=True)
            _restore_interface_ip_entries(duthost, saved_vlan_ips)
            _restore_interface_ip_entries(duthost, saved_pc_ips)
            duthost.shell("sudo config vrf del {}".format(DP_VRF), module_ignore_errors=True)
            duthost.shell("sudo config save -y", module_ignore_errors=True)
