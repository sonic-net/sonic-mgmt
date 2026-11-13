"""
Protection Next Hop Group (N:M) orchagent lifecycle test.

Lifecycle under test
--------------------
  1. Program 2 routes with a protection NHG: 2 primary + 2 standby nexthops.
  2. All links up   → traffic uses both primaries, none goes to standbys.
  3. Primary[0] down → no switchover, traffic on primary[1] only.
  4. Primary[1] down → switchover active, traffic on both standbys.
  5. Primary[0] up   → revert, traffic on primary[0] only.
  6. Primary[1] up   → both primaries active again.
  7. Throughout steps 2-6, the route's NHG OID in ASIC_DB must not change.

Routes are programmed by writing the APPL_DB ROUTE_TABLE entry directly, in
the shape fpmsyncd produces for a BGP-PIC (pic-backup) route: the leading
primary_nh_count nexthops are the primaries and the rest the standbys, and
orchagent builds a SAI_NEXT_HOP_GROUP_TYPE_PROTECTION from it.  See
_install_routes.  FRR is not involved.

The NHG membership stays pinned across the link flaps below: nothing in the
control plane owns these routes, so no producer rewrites the entry and
orchagent never sees a route update.  Every transition here is therefore a pure
in-place SAI switchover with a stable NHG OID, and there is no control-plane
reconvergence to race against -- which is what lets the assertions below pin
exact member sets and a constant OID.

Run for both IPv4 and IPv6 address families.
"""
import base64
import ipaddress
import json
import logging
import time

import pytest
import ptf.packet as scapy
import ptf.testutils as testutils

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t2"),
]

# Test prefixes (documentation range, not advertised by BGP) written to ROUTE_TABLE
TEST_ROUTES_V4 = ["192.0.2.100/32", "192.0.2.101/32"]
TEST_ROUTES_V6 = ["2001:db8::100/128", "2001:db8::101/128"]

# Prefixes for the shared-primary multi-NHG test
# NHG-A: prefix[0], NHG-B: prefix[1]
SHARED_PRIMARY_ROUTES_V4 = ["192.0.2.110/32", "192.0.2.111/32"]
SHARED_PRIMARY_ROUTES_V6 = ["2001:db8::110/128", "2001:db8::111/128"]

# Prefixes for the shared-key refcount test (two routes, IDENTICAL members)
SHARED_KEY_ROUTES_V4 = ["192.0.2.120/32", "192.0.2.121/32"]
SHARED_KEY_ROUTES_V6 = ["2001:db8::120/128", "2001:db8::121/128"]

# Prefixes for the asymmetric N:M ratio test
NM_RATIO_ROUTES_V4 = ["192.0.2.130/32", "192.0.2.131/32"]
NM_RATIO_ROUTES_V6 = ["2001:db8::130/128", "2001:db8::131/128"]

# Source IPs for test packets
SRC_IP_V4 = "10.0.0.200"
SRC_IP_V6 = "2001:db8::200"

# TTL/hop-limit for test packets
PKT_TTL = 64

# Number of distinct flows per verification burst (varied TCP sport/dport).
# Must be high enough to hit all ECMP members across different hash buckets.
FLOW_COUNT = 200

# Convergence wait after a link state change
CONVERGENCE_TIMEOUT = 60
CONVERGENCE_POLL = 2


# ---------------------------------------------------------------------------
# DB / SAI helpers
# ---------------------------------------------------------------------------

def _run_swss_py(duthost, body, **consts):
    """
    Run a Python snippet inside the swss container -- it has swsscommon and
    direct redis access, so an ASIC_DB walk costs one round trip instead of one
    per key.  Each keyword in *consts* is prepended to *body* as a
    ``NAME = repr(value)`` assignment.  The script is base64-encoded to
    sidestep all shell/heredoc quoting.
    """
    script = "".join(f"{k} = {v!r}\n" for k, v in consts.items()) + body
    b64 = base64.b64encode(script.encode()).decode()
    return duthost.shell(
        "docker exec -i swss python3 -c "
        "\"import base64; exec(base64.b64decode('{}'))\"".format(b64)
    )


# orchagent's northbound ZMQ port on a single-ASIC DUT; per-ASIC orchagents
# listen on 8100 + NAMESPACE_ID + 1 (see require_protection_nhg_support).
_ORCH_ZMQ_PORT = 8100

# Body of the ROUTE_TABLE writer, executed inside the swss container.  Prefixed
# with ZMQ_PORT and ROUTES = [(prefix, [nexthop_ip, ...] or None,
# primary_count), ...]; a None nexthop list deletes the prefix.
_APPDB_ROUTE_WRITER = r'''
import json
import subprocess
import time
from swsscommon import swsscommon

# With SYSTEM_DEFAULTS|swss_zmq enabled, RouteOrch consumes ROUTE_TABLE only
# from the ZMQ channel fpmsyncd feeds; a plain APPL_DB write would never
# reach it.
appl = swsscommon.DBConnector('APPL_DB', 0)
cfg = swsscommon.DBConnector('CONFIG_DB', 0)
zmq_on = cfg.hget('SYSTEM_DEFAULTS|swss_zmq', 'status') == 'enabled'
if zmq_on:
    client = swsscommon.ZmqClient('tcp://localhost:%d' % ZMQ_PORT)
    tbl = swsscommon.ZmqProducerStateTable(appl, 'ROUTE_TABLE', client)
else:
    tbl = swsscommon.ProducerStateTable(appl, 'ROUTE_TABLE')


def egress_ifname(ip):
    out = subprocess.check_output(['ip', '-j', 'route', 'get', ip])
    dev = json.loads(out)[0].get('dev') or ''
    if not dev.startswith(('Ethernet', 'PortChannel')):
        raise RuntimeError('nexthop %s resolves via %r, not a front-panel '
                           'interface' % (ip, dev))
    return dev


# The ZMQ route consumer keeps only the latest SET per key and never merges
# fields, so producers must send complete entries.  Mirror fpmsyncd
# (RouteTableFieldValueTupleWrapper): every field, empty where unused.
EMPTY = ['protocol', 'nexthop_group', 'mpls_nh', 'weight', 'vni_label',
         'router_mac', 'segment', 'seg_src', 'vpn_sid', 'pic_context_id',
         'segment_id']

for prefix, nexthops, primary_count in ROUTES:
    if nexthops is None:
        tbl.delete(prefix)
        continue
    fvs = [(f, '') for f in EMPTY]
    fvs += [('blackhole', 'false'),
            ('nexthop', ','.join(nexthops)),
            ('ifname', ','.join(egress_ifname(ip) for ip in nexthops)),
            ('primary_nh_count', str(primary_count))]
    tbl.set(prefix, fvs)
    print(json.dumps({'prefix': prefix, 'fvs': dict(fvs)}))

# ZmqClient sets ZMQ_LINGER=0 and a PUSH socket has no delivery ack: give the
# I/O thread time to flush before exit.
if zmq_on:
    time.sleep(1)
print(json.dumps({'zmq': zmq_on}))
'''


def _write_appdb_routes(duthost, routes, check_zmq=True):
    """
    Run _APPDB_ROUTE_WRITER for *routes*; return (zmq_on, stdout lines).

    With ZMQ on and *check_zmq* set, also require an established connection
    to orchagent's ZMQ port.  A PUSH to a port nobody consumes succeeds
    silently, and swss_zmq in CONFIG_DB says nothing about whether the running
    orchagent picked it up; this turns both into an immediate failure instead
    of a 30s ASIC_DB wait.
    """
    lines = _run_swss_py(duthost, _APPDB_ROUTE_WRITER,
                         ZMQ_PORT=_ORCH_ZMQ_PORT, ROUTES=routes)["stdout_lines"]
    zmq_on = any(line == '{"zmq": true}' for line in lines)
    if zmq_on and check_zmq:
        conns = duthost.shell(
            "ss -Htn state established '( dport = :{} )' | wc -l".format(
                _ORCH_ZMQ_PORT))["stdout"].strip()
        pytest_assert(
            conns not in ("", "0"),
            f"swss_zmq is enabled but nothing is connected to orchagent's ZMQ "
            f"port {_ORCH_ZMQ_PORT}; route ZMQ is not live (swss not "
            f"restarted since the config change?)"
        )
    return zmq_on, lines


def _install_routes(duthost, routes):
    """
    Program protection routes by writing ROUTE_TABLE directly, the way
    fpmsyncd would.  Each entry of *routes* is a (prefix, primary_ips,
    standby_ips) tuple; all of them are written in one swss exec.

    The nexthop list is primaries then standbys, and primary_nh_count marks
    the split -- the same entry fpmsyncd builds from a pic-backup route.  Each
    nexthop's ifname is resolved from the kernel route to it.  Callers wait
    for the routes in ASIC_DB.
    """
    entries = []
    for prefix, primary_ips, standby_ips in routes:
        pytest_assert(
            primary_ips and standby_ips,
            f"{prefix}: a protection NHG needs at least one primary and one "
            f"standby (got {primary_ips} / {standby_ips})"
        )
        entries.append((prefix, list(primary_ips) + list(standby_ips),
                        len(primary_ips)))
    zmq_on, lines = _write_appdb_routes(duthost, entries)
    for line in lines:
        logger.info("ROUTE_TABLE write (%s): %s",
                    "zmq" if zmq_on else "appl_db", line)


def _delete_routes(duthost, prefixes):
    """
    Best-effort ROUTE_TABLE delete used by fixture teardown.  Idempotent --
    deleting a prefix that was never written is a no-op, so a failure in route
    cleanup doesn't mask the real test result.
    """
    if not prefixes:
        return
    try:
        _write_appdb_routes(duthost, [(p, None, 0) for p in prefixes],
                            check_zmq=False)
    except Exception as exc:
        logger.warning("teardown: ROUTE_TABLE delete failed (non-fatal): %s", exc)


def _get_asic_route_nhg_oid(duthost, prefix):
    """
    Look up the NHG OID for *prefix* in ASIC_DB.
    Returns the OID string, or None if not found.
    """
    keys = duthost.shell(
        "sonic-db-cli ASIC_DB KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY:*'"
    )["stdout_lines"]

    for k in keys:
        if f'"dest":"{prefix}"' in k or f'"dest": "{prefix}"' in k:
            oid = duthost.shell(
                f"sonic-db-cli ASIC_DB HGET '{k}' SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID"
            )["stdout"].strip()
            return oid if oid else None

    return None


def _hget(duthost, key, field):
    """
    Return a single ASIC_DB attribute value via HGET, stripped, or None
    if missing/empty.  Simpler and more portable across sonic-db-cli
    versions than parsing HGETALL output (which different versions emit
    as either alternating lines or a Python dict literal).
    """
    val = duthost.shell(
        f"sonic-db-cli ASIC_DB HGET '{key}' '{field}'"
    )["stdout"].strip()
    return val if val else None


def _get_nhg_attr(duthost, nhg_oid, attr):
    """Return a single ASIC_DB attribute for a NHG OID, or None."""
    return _hget(duthost,
                 f"ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP_GROUP:{nhg_oid}", attr)


def _route_present(duthost, prefix):
    return _get_asic_route_nhg_oid(duthost, prefix) is not None


def _nhg_exists(duthost, nhg_oid):
    """
    True if a NEXT_HOP_GROUP object with *nhg_oid* still exists in ASIC_DB.
    Used by the shared-key refcount test to observe group teardown: the OID
    is retired only when the last route referencing the shared protection NHG
    is deleted (getProtNhgRefCount() -> 0).
    """
    return _get_nhg_attr(duthost, nhg_oid,
                         "SAI_NEXT_HOP_GROUP_ATTR_TYPE") is not None


# Body of the role-member walk, executed inside the swss container.  Prefixed
# at call time with TARGET / ROLE assignments (see _get_nhg_member_ips_by_role);
# no str.format here, so the braces below need no escaping.
_ROLE_MEMBERS_BODY = """
import json
from swsscommon import swsscommon

db = swsscommon.DBConnector('ASIC_DB', 0)
MEMBER = 'ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER:'
NH = 'ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP:'
NHG = 'ASIC_STATE:SAI_OBJECT_TYPE_NEXT_HOP_GROUP:'

# One pass over every NHG_MEMBER row, indexed by owning group.  The recursive
# descent below reuses this index instead of re-reading the table.
by_group = {}
total = 0
for k in db.keys(MEMBER + '*'):
    total += 1
    fv = db.hgetall(k)
    gid = fv.get('SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID')
    if not gid:
        continue
    by_group.setdefault(gid, []).append({
        'key': k,
        'role': fv.get('SAI_NEXT_HOP_GROUP_MEMBER_ATTR_CONFIGURED_ROLE'),
        'nh': fv.get('SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID'),
    })

unresolved = []


def leaves(oid, seen):
    # A plain NEXT_HOP resolves to its own IP.  A NEXT_HOP_GROUP -- the inner
    # ECMP of a role side -- resolves to the union of its members' leaf IPs.
    # seen guards against cycles; inner groups hold only leaf next-hops today,
    # so a single descent is expected.
    if oid in seen:
        return set()
    seen.add(oid)
    ip = db.hget(NH + oid, 'SAI_NEXT_HOP_ATTR_IP')
    if ip:
        return set([ip])
    if db.hget(NHG + oid, 'SAI_NEXT_HOP_GROUP_ATTR_TYPE') is None:
        unresolved.append(oid)
        return set()
    out = set()
    for m in by_group.get(oid, []):
        if m['nh']:
            out |= leaves(m['nh'], seen)
    return out


matches = by_group.get(TARGET, [])
addrs = set()
for m in matches:
    if m['role'] == ROLE and m['nh']:
        addrs |= leaves(m['nh'], set())

print(json.dumps({
    'addrs': sorted(addrs),
    'total_member_keys': total,
    'matches': matches,
    'unresolved': unresolved,
}))
"""


def _get_nhg_member_ips_by_role(duthost, nhg_oid, role):
    """
    Walk ASIC_DB and return the set of underlying NH addresses currently
    configured as members of *nhg_oid* with the given *role*.

    A role member may be a single next-hop (resolved directly to its IP) or,
    under the two-level model, an inner ECMP next-hop group whose leaf IPs are
    resolved by descending one level.

    role: "PRIMARY" or "STANDBY"

    Verifies the symmetric-dispatch invariant that the SAI nh_list members
    of a role match the up members of that role.  Use after each lifecycle
    transition.

    The whole walk runs in one shot inside the swss container rather than as a
    sequence of sonic-db-cli invocations.  Done host-side it costs one KEYS
    scan plus two to three HGETs per NHG_MEMBER row on the DUT -- every one an
    SSH-backed round trip -- and _wait_for_primary_members calls this for two
    prefixes on each of up to 30 poll ticks, so a single convergence wait
    scaled as O(30 x prefixes x all NHG members) round trips.  Inside the
    container the same reads hit a local redis socket and the whole query is
    one round trip.

    Logs at INFO when the final result set is empty (likely a test bug -- at
    least one member should normally match), dumping per-candidate group-id and
    configured-role so the actual ASIC_DB contents are visible in the test log.
    """
    role_attr = f"SAI_NEXT_HOP_GROUP_MEMBER_CONFIGURED_ROLE_{role}"
    out = _run_swss_py(duthost, _ROLE_MEMBERS_BODY,
                       TARGET=nhg_oid, ROLE=role_attr)["stdout"].strip()
    # Take the last JSON-looking line: anything the container writes ahead of
    # the result (warnings from swsscommon init, say) must not break parsing.
    payload = ""
    for line in reversed(out.splitlines()):
        if line.startswith("{"):
            payload = line
            break
    pytest_assert(
        payload,
        f"_get_nhg_member_ips_by_role: no JSON result for group={nhg_oid} "
        f"role={role_attr}; raw output was {out!r}"
    )
    result = json.loads(payload)

    addrs = set(result["addrs"])
    matches = result["matches"]

    logger.debug("ASIC_DB has %d NHG_MEMBER keys; group=%s role=%s -> %s",
                 result["total_member_keys"], nhg_oid, role_attr, addrs)

    for oid in result["unresolved"]:
        # Neither a next-hop with an IP nor a next-hop group.  Inert for the
        # route shapes this suite installs, but an onlink/unnumbered
        # nexthop resolves NEXT_HOP_ID to a ROUTER_INTERFACE OID, which lands
        # here.  Say so: dropping the leaf silently would surface downstream as
        # an unexplained member-set mismatch.
        logger.warning(
            "[_get_nhg_member_ips_by_role] OID %s is neither a NEXT_HOP with "
            "SAI_NEXT_HOP_ATTR_IP nor an existing NEXT_HOP_GROUP; "
            "resolving it to no leaf IPs", oid)

    if not addrs:
        logger.info(
            "[_get_nhg_member_ips_by_role] no addresses returned for "
            "group=%s role=%s.  total NHG_MEMBER keys=%d, group-id matches=%d",
            nhg_oid, role_attr, result["total_member_keys"], len(matches),
        )
        for m in matches[:8]:
            logger.info("  member key=%s cfg_role=%r nh_id=%s",
                        m["key"], m["role"], m["nh"])
    return addrs


# ---------------------------------------------------------------------------
# Interface abstraction
#
# Each nexthop interface is represented as a dict:
#   name      - interface name used in the route (PortChannel or Ethernet)
#   peer_ip   - neighbor IP (v4 or v6 depending on AF)
#   peer_mac  - neighbor MAC (lower-case)
#   shutdown  - list of physical interface names to shut to take this intf down
#   ptf_ids   - PTF port IDs that carry traffic for this interface
#   kind      - "portchannel" or "interface"
# ---------------------------------------------------------------------------

def _intf_oper_state(duthost, intf_info):
    """
    Return the current operational state ("up"/"down"/"") from STATE_DB for this
    interface.

    The table and field differ by interface kind:
      - PortChannel: LAG_TABLE|<name>, field 'oper_status' (populated by teamd).
      - Physical interface: PORT_TABLE|<name>.  On this platform the physical
        port oper state is exposed as 'netdev_oper_status'; there is no
        'oper_status' field on PORT_TABLE, so reading 'oper_status' always
        returns "" and the port never appears to change state.

    Multi-ASIC aware: query the default STATE_DB instance first (covers
    single-ASIC and host-level LAG_TABLE), then fall back to sweeping the
    per-ASIC namespaces (front-panel PORT_TABLE rows live in the per-ASIC
    STATE_DB on multi-ASIC platforms).  Returns "" if not found anywhere.

    A "" return still means "no state read", but a failing query is logged at
    WARNING rather than folded silently into that same "" -- see _query below.
    """
    if intf_info["kind"] == "portchannel":
        key = f"LAG_TABLE|{intf_info['name']}"
        field = "oper_status"
    else:
        key = f"PORT_TABLE|{intf_info['name']}"
        field = "netdev_oper_status"
    base = f"sonic-db-cli STATE_DB HGET '{key}' {field}"

    def _query(cmd):
        res = duthost.shell(cmd, module_ignore_errors=True)
        if res.get("rc", 0) != 0:
            # A missing key or field is rc 0 with empty stdout, so a non-zero rc
            # is a genuine query failure (redis/container unreachable, bad
            # command) rather than "not transitioned yet".  Callers poll this
            # through wait_until and only compare against "up"/"down", so
            # without this line the two collapse into the same empty string and
            # a real failure is reported as a generic "did not go down/up"
            # timeout with the root cause discarded.
            logger.warning(
                "_intf_oper_state: query failed rc=%s cmd=%s stderr=%s",
                res.get("rc"), cmd, (res.get("stderr") or "").strip())
            return ""
        return (res.get("stdout") or "").strip()

    val = _query(base)
    if val:
        return val

    for ns in duthost.get_asic_namespace_list():
        if not ns:
            continue  # DEFAULT_NAMESPACE already queried above
        val = _query(duthost.get_cli_cmd_for_namespace(base, ns))
        if val:
            return val
    return ""


def _bring_intf_down(duthost, intf_info):
    """
    Shut all physical ports backing this interface and wait for it to go down.

    Uses the namespace-aware shutdown_interface() (which resolves each port's
    ASIC via get_port_asic_instance) rather than shutdown_multiple(): on a
    multi-ASIC DUT a plain `config interface shutdown` runs without `-n <ns>`
    and is a silent no-op for ports that live on a non-default ASIC.
    """
    for port in intf_info["shutdown"]:
        duthost.shutdown_interface(port)
    pytest_assert(
        wait_until(CONVERGENCE_TIMEOUT, CONVERGENCE_POLL, 0,
                   lambda: _intf_oper_state(duthost, intf_info) == "down"),
        f"{intf_info['name']} did not go down after shutting {intf_info['shutdown']}"
    )


def _bring_intf_up(duthost, intf_info):
    """Re-enable physical ports and wait for the interface to come up."""
    for port in intf_info["shutdown"]:
        duthost.no_shutdown_interface(port)
    pytest_assert(
        wait_until(CONVERGENCE_TIMEOUT, CONVERGENCE_POLL, 0,
                   lambda: _intf_oper_state(duthost, intf_info) == "up"),
        f"{intf_info['name']} did not come up after enabling {intf_info['shutdown']}"
    )
    # Give orchagent time to process the neighbor update (pending-revert path)
    time.sleep(5)


# ---------------------------------------------------------------------------
# Interface discovery helpers
# ---------------------------------------------------------------------------

def _resolved_peer_mac(nbr_table, peer_ip):
    """
    Return the lower-case neighbor MAC for *peer_ip*, or None if there is no
    entry or the neighbor is unresolved.

    ansible/library/switch_arptable.py renders an entry with no lladdr (FAILED /
    INCOMPLETE) as the literal *string* 'None', not a null -- so a plain
    truthiness check on 'macaddress' accepts it and the interface ends up
    selected with the bogus peer MAC "none", which is then asserted as an
    expected/forbidden destination MAC for the rest of the suite.
    """
    entry = nbr_table.get(peer_ip)
    if not entry:
        return None
    mac = (entry.get("macaddress") or "").strip()
    if not mac or mac.lower() == "none":
        return None
    return mac.lower()


def _collect_portchannel_intfs(mg_facts, nbr_table, af):
    """
    Return a list of nexthop-interface dicts for PortChannels that have a
    resolved neighbor entry for the given address family.

    A PortChannel with several members is a single nexthop: the neighbor is
    reached over one LAG, so "shutdown" lists every member (the leg is down
    only once all of them are) and "ptf_ids" lists every member's PTF port
    (a flow may land on any of them). The consumers already work on those
    lists, so a multi-member LAG needs no special handling here.

    af: "ipv4" or "ipv6"
    nbr_table: arptable["v4"] for ipv4, arptable["v6"] for ipv6
    """
    pc_peer = {}
    for entry in mg_facts.get("minigraph_portchannel_interfaces", []):
        pc = entry.get("attachto", "")
        addr = entry.get("addr", "")
        peer = entry.get("peer_addr", "")
        if not pc or not peer:
            continue
        is_v6 = ":" in addr
        if af == "ipv4" and is_v6:
            continue
        if af == "ipv6" and not is_v6:
            continue
        if pc not in pc_peer:
            pc_peer[pc] = peer

    result = []
    for pc_name, peer_ip in pc_peer.items():
        members = (mg_facts.get("minigraph_portchannels", {})
                   .get(pc_name, {})
                   .get("members", []))
        if not members:
            continue
        peer_mac = _resolved_peer_mac(nbr_table, peer_ip)
        if peer_mac is None:
            continue
        ptf_ids = [mg_facts["minigraph_ptf_indices"][m]
                   for m in members if m in mg_facts["minigraph_ptf_indices"]]
        if not ptf_ids:
            continue
        result.append({
            "name":     pc_name,
            "peer_ip":  peer_ip,
            "peer_mac": peer_mac,
            "shutdown": members,
            "ptf_ids":  ptf_ids,
            "kind":     "portchannel",
        })
    return result


def _collect_regular_intfs(mg_facts, nbr_table, af, exclude_intfs):
    """
    Return a list of nexthop-interface dicts for regular (non-PortChannel)
    physical interfaces that have a resolved neighbor entry for the given AF.
    Excludes interfaces in *exclude_intfs*.

    af: "ipv4" or "ipv6"
    nbr_table: arptable["v4"] for ipv4, arptable["v6"] for ipv6
    """
    result = []
    for entry in mg_facts.get("minigraph_interfaces", []):
        intf = entry.get("attachto", "")
        addr = entry.get("addr", "")
        peer = entry.get("peer_addr", "")
        if not intf or not peer:
            continue
        is_v6 = ":" in addr
        if af == "ipv4" and is_v6:
            continue
        if af == "ipv6" and not is_v6:
            continue
        if intf in exclude_intfs:
            continue
        peer_mac = _resolved_peer_mac(nbr_table, peer)
        if peer_mac is None:
            continue
        ptf_id = mg_facts["minigraph_ptf_indices"].get(intf)
        if ptf_id is None:
            continue
        result.append({
            "name":     intf,
            "peer_ip":  peer,
            "peer_mac": peer_mac,
            "shutdown": [intf],
            "ptf_ids":  [ptf_id],
            "kind":     "interface",
        })
    return result


def _discover_candidates(mg_facts, nbr_table, af):
    """
    Return the canonical ordered list of nexthop-interface dicts with resolved
    neighbors for *af*: PortChannels first, then regular interfaces not
    already backing one of them.

    The regular interfaces are appended unconditionally rather than only when
    the PortChannel count falls short of some caller's minimum.  Every fixture
    in this module indexes into this list, and those indices must denote the
    same interface for all of them (see nh_candidates); a caller-dependent
    cutoff would hand different callers different-length lists.  Callers check
    len() and skip on their own.
    """
    candidates = _collect_portchannel_intfs(mg_facts, nbr_table, af)
    used = set()
    for c in candidates:
        used.update(c["shutdown"])
    candidates.extend(
        _collect_regular_intfs(mg_facts, nbr_table, af, exclude_intfs=used))
    return candidates


def _pick_inject_port(mg_facts, selected):
    """
    Return (src_ptf_id, src_intf) for a PTF port that does not back any of the
    *selected* nexthop interfaces, or (None, None) if none is free.
    """
    used_physical = set()
    for intf in selected:
        used_physical.update(intf["shutdown"])
    for intf, idx in mg_facts["minigraph_ptf_indices"].items():
        if intf not in used_physical:
            return idx, intf
    return None, None


# ---------------------------------------------------------------------------
# Traffic helpers
# ---------------------------------------------------------------------------

def _send_and_collect_macs(ptfadapter, src_port_id, dst_port_ids, router_mac,
                           dst_ip, n_flows, af):
    """
    Send *n_flows* routed TCP packets and collect Ether.dst MACs seen on
    *dst_port_ids*.  Uses dp_poll to drain the dataplane after the burst.

    af: "ipv4" or "ipv6"
    Returns: (seen_macs: set[str], recv_count: int)
    """
    ptfadapter.dataplane.flush()

    # Vary the source IP per flow in addition to the L4 ports. A fixed source
    # IP with only sport/dport varying carries too little hash entropy to
    # reliably cover every member of a wider ECMP group -- with a 3-member
    # group it can leave one member unhit, which made the N:M ratio cases
    # spuriously fail even though the datapath forwards correctly.
    src_base = int(ipaddress.ip_address(SRC_IP_V6 if af == "ipv6" else SRC_IP_V4))

    for flow_id in range(n_flows):
        src_ip = str(ipaddress.ip_address(src_base + flow_id))
        if af == "ipv6":
            pkt = testutils.simple_tcpv6_packet(
                eth_dst=router_mac,
                ipv6_src=src_ip,
                ipv6_dst=dst_ip,
                ipv6_hlim=PKT_TTL,
                tcp_sport=1024 + flow_id,
                tcp_dport=2000 + flow_id,
            )
        else:
            pkt = testutils.simple_tcp_packet(
                eth_dst=router_mac,
                ip_src=src_ip,
                ip_dst=dst_ip,
                ip_ttl=PKT_TTL,
                tcp_sport=1024 + flow_id,
                tcp_dport=2000 + flow_id,
            )
        testutils.send(ptfadapter, src_port_id, pkt)

    seen_macs = set()
    recv_count = 0
    deadline = time.time() + 3
    while time.time() < deadline:
        result = testutils.dp_poll(ptfadapter, device_number=0, timeout=0.1)
        if not isinstance(result, ptfadapter.dataplane.PollSuccess):
            continue
        if result.port not in dst_port_ids:
            continue
        # Only count packets that are our routed test traffic.
        # Filter on IP dst == dst_ip and TTL == PKT_TTL-1 (one hop decrement).
        # This discards control-plane frames (LACP, LLDP, STP) which share
        # the same PTF ports and would otherwise pollute seen_macs.
        try:
            pkt = scapy.Ether(result.packet)
            if af == "ipv6":
                ip_layer = pkt[scapy.IPv6]
                if ip_layer.dst != dst_ip:
                    continue
                if ip_layer.hlim != PKT_TTL - 1:
                    continue
            else:
                ip_layer = pkt[scapy.IP]
                if ip_layer.dst != dst_ip:
                    continue
                if ip_layer.ttl != PKT_TTL - 1:
                    continue
        except Exception:
            continue
        recv_count += 1
        seen_macs.add(pkt.dst.lower())

    return seen_macs, recv_count


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def require_protection_nhg_support(rand_selected_dut):
    """
    Skip the whole module on platforms this suite cannot drive.

    Capability: NhgOrch probes the SAI next-hop-group types at orchagent init
    and publishes NHG_PROTECTION_CAPABLE to STATE_DB SWITCH_CAPABILITY
    (orchagent/nhgorch.cpp; orchdaemon.cpp forces the probe during init exactly
    so the field exists before the first protected route).  An image without
    protection-NHG support has no such field, which reads empty here and skips.
    This guard matters because pytestmark is topology("t2", "any") -- "any"
    means every topology -- so without it the suite runs on non-DNX DUTs and
    dies in the setup fixture on the SAI_NEXT_HOP_GROUP_TYPE_PROTECTION
    assertion instead of skipping cleanly.

    Multi-ASIC: skipped rather than supported.  Four things here assume a
    single ASIC, and the suite has only been validated on single-ASIC DNX:
      - _run_swss_py execs into a container named literally "swss"; per-ASIC
        DUTs name it swss<N> (SonicAsic.get_docker_name).
      - the ASIC_DB helpers run sonic-db-cli with no -n <namespace>, so they
        would read the wrong ASIC's instance.
      - the ROUTE_TABLE writer connects to orchagent's ZMQ port 8100; per-ASIC
        orchagents listen on 8100 + NAMESPACE_ID + 1.
      - _send_and_collect_macs filters on a single TTL decrement, while
        multi-ASIC forwarding decrements by duthost.ttl_decr_value (3).
    """
    duthost = rand_selected_dut

    if duthost.is_multi_asic:
        pytest.skip("protection NHG suite is single-ASIC only "
                    "(see require_protection_nhg_support docstring)")

    cap = duthost.shell(
        "sonic-db-cli STATE_DB HGET 'SWITCH_CAPABILITY|switch' "
        "NHG_PROTECTION_CAPABLE",
        module_ignore_errors=True,
    )["stdout"].strip()
    if cap.lower() != "true":
        pytest.skip("platform does not advertise NHG_PROTECTION_CAPABLE "
                    f"(got {cap!r})")


@pytest.fixture(scope="module")
def nh_candidates(rand_selected_dut, tbinfo, require_protection_nhg_support):
    """
    Discover the nexthop-interface candidate list for each AF exactly once per
    module, and hand the same list to every setup fixture.

    Every fixture here selects its members by index (lifecycle takes [:4],
    shared_primary takes [0]/[1]/[2], shared_key takes [1]/[2], nm_ratio takes
    [:total]), and shared_key's isolation argument depends on those indices
    denoting the same interface in all of them.  Discovery filters on live ARP
    resolution and the tests in this module flap links, so re-deriving the list
    per fixture would let an interface whose neighbor has not re-resolved yet
    drop out and shift every later index -- silently colliding member sets that
    are supposed to be disjoint.  Discovering once, before any test has flapped
    anything, makes the indices stable by construction.
    """
    duthost = rand_selected_dut
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    arp_facts = duthost.switch_arptable()["ansible_facts"]["arptable"]

    by_af = {}
    for af in ("ipv4", "ipv6"):
        nbr_table = arp_facts["v6"] if af == "ipv6" else arp_facts["v4"]
        by_af[af] = _discover_candidates(mg_facts, nbr_table, af)
        logger.info("[%s] discovered %d nexthop candidates: %s", af,
                    len(by_af[af]), [c["name"] for c in by_af[af]])

    return {"mg_facts": mg_facts, "by_af": by_af}


@pytest.fixture(scope="module", params=["ipv4", "ipv6"])
def prot_nhg_setup(request, duthosts, rand_selected_dut, nh_candidates, ptfadapter):
    """
    Discover 4 nexthop interfaces (2 primary + 2 standby) for the given AF.
    PortChannels are preferred; regular interfaces are used to fill any gap.
    Programs two test routes as protection NHGs and yields a facts dict.
    """
    af = request.param
    duthost = rand_selected_dut
    mg_facts = nh_candidates["mg_facts"]

    test_routes = TEST_ROUTES_V6 if af == "ipv6" else TEST_ROUTES_V4

    candidates = nh_candidates["by_af"][af]

    if len(candidates) < 4:
        pytest.skip(
            f"[{af}] Need 4 nexthop interfaces with resolved neighbor; "
            f"found {len(candidates)}"
        )

    selected = candidates[:4]
    primary = selected[:2]
    standby = selected[2:4]

    logger.info("[%s] Primary:  %s (%s)  %s (%s)", af,
                primary[0]["name"], primary[0]["kind"],
                primary[1]["name"], primary[1]["kind"])
    logger.info("[%s] Standby:  %s (%s)  %s (%s)", af,
                standby[0]["name"], standby[0]["kind"],
                standby[1]["name"], standby[1]["kind"])

    # Find an inject PTF port not used by any of the 4 selected interfaces.
    used_physical = set()
    for intf in selected:
        used_physical.update(intf["shutdown"])

    src_ptf_id = None
    src_intf = None
    for intf, idx in mg_facts["minigraph_ptf_indices"].items():
        if intf not in used_physical:
            src_ptf_id = idx
            src_intf = intf
            break

    if src_ptf_id is None:
        pytest.skip(f"[{af}] No free PTF port available for packet injection")

    logger.info("[%s] Inject port: %s (ptf id %d)", af, src_intf, src_ptf_id)

    primary_ips = [i["peer_ip"] for i in primary]
    standby_ips = [i["peer_ip"] for i in standby]

    # Defensive pre-clean: remove any stale entries from a prior aborted run
    # before installing.  Idempotent -- deleting a prefix that was never
    # installed is a no-op.  Without this, a previous test that exited before
    # its teardown ran would leave routes/NHGs that conflict with this run.
    _delete_routes(duthost, test_routes)
    time.sleep(2)  # let orchagent process the deletes before recreating

    try:
        _install_routes(duthost,
                        [(prefix, primary_ips, standby_ips)
                         for prefix in test_routes])

        for prefix in test_routes:
            pytest_assert(
                wait_until(30, 1, 0, _route_present, duthost, prefix),
                f"[{af}] Route {prefix} did not appear in ASIC_DB after install"
            )

        initial_oids = {p: _get_asic_route_nhg_oid(duthost, p) for p in test_routes}
        logger.info("[%s] Initial NHG OIDs: %s", af, initial_oids)

        for prefix, oid in initial_oids.items():
            pytest_assert(oid is not None, f"[{af}] Route {prefix} missing NHG OID")
            nhg_type = _get_nhg_attr(duthost, oid, "SAI_NEXT_HOP_GROUP_ATTR_TYPE")
            pytest_assert(
                nhg_type == "SAI_NEXT_HOP_GROUP_TYPE_PROTECTION",
                f"[{af}] Route {prefix} NHG {oid} type='{nhg_type}', "
                f"expected SAI_NEXT_HOP_GROUP_TYPE_PROTECTION"
            )

        all_ptf_ids = []
        for intf in primary + standby:
            all_ptf_ids.extend(intf["ptf_ids"])

        dst_ip = test_routes[0].split("/")[0]

        yield {
            "af":           af,
            "duthost":      duthost,
            "router_mac":   duthost.facts["router_mac"],
            "src_ptf_id":   src_ptf_id,
            "dst_ip":       dst_ip,
            "primary":      primary,
            "standby":      standby,
            "all_ptf_ids":  all_ptf_ids,
            "initial_oids": initial_oids,
            "test_routes":  test_routes,
        }
    finally:
        # Always run the route delete, even if a setup-phase assertion above
        # raised before yield — that keeps NHGs from leaking across runs.
        _delete_routes(duthost, test_routes)


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestProtectionNhg:

    def _assert_traffic(self, ptfadapter, setup, expected_macs,
                        forbidden_macs, step, min_recv_ratio=0):
        """
        Send FLOW_COUNT packets and verify the expected MAC pattern.

        min_recv_ratio: if > 0, additionally assert that
            recv_count >= int(min_recv_ratio * FLOW_COUNT).  Use this on
            steps that follow a member going down while others survive, where
            the symmetric dispatch should keep forwarding the whole offered
            load.  Callers pass 0.9 rather than 1.0: the burst is sent just
            after a link flap, so a few in-flight packets can still be lost to
            the transition itself.  The check targets a *structural* blackhole
            -- the old leave-dead-member-in-FEC behavior stranded an entire
            hash share (1/N of the flows, well past 10% for the group sizes
            here), so it trips this bound comfortably while transient flap
            loss does not.
        """
        seen, recv_count = _send_and_collect_macs(
            ptfadapter,
            setup["src_ptf_id"],
            setup["all_ptf_ids"],
            setup["router_mac"],
            setup["dst_ip"],
            FLOW_COUNT,
            setup["af"],
        )
        logger.info("[%s][%s] recv=%d/%d seen=%s expected=%s forbidden=%s",
                    setup["af"], step, recv_count, FLOW_COUNT, seen,
                    expected_macs, forbidden_macs)

        pytest_assert(recv_count > 0,
                      f"[{setup['af']}][{step}] No packets received — routing broken or "
                      f"dataplane misconfigured")
        for mac in expected_macs:
            pytest_assert(mac in seen,
                          f"[{setup['af']}][{step}] Expected MAC {mac} not seen. Got: {seen}")
        for mac in forbidden_macs:
            pytest_assert(mac not in seen,
                          f"[{setup['af']}][{step}] Forbidden MAC {mac} was seen. Got: {seen}")
        if min_recv_ratio > 0:
            min_recv = int(min_recv_ratio * FLOW_COUNT)
            pytest_assert(
                recv_count >= min_recv,
                f"[{setup['af']}][{step}] only {recv_count}/{FLOW_COUNT} packets "
                f"received (need >= {min_recv}) — suggests partial-failure blackhole "
                f"that the symmetric dispatch should have eliminated"
            )

    def _assert_switchover(self, setup, expected_active, step):
        duthost = setup["duthost"]
        expected_str = "true" if expected_active else "false"
        for prefix, oid in setup["initial_oids"].items():
            val = _get_nhg_attr(
                duthost, oid, "SAI_NEXT_HOP_GROUP_ATTR_SET_SWITCHOVER"
            )
            actual = val if val is not None else "false"
            pytest_assert(
                actual == expected_str,
                f"[{setup['af']}][{step}] {prefix} NHG {oid}: switchover={actual}, "
                f"expected={expected_str}"
            )

    def _assert_oids_stable(self, setup):
        duthost = setup["duthost"]
        for prefix, initial_oid in setup["initial_oids"].items():
            current = _get_asic_route_nhg_oid(duthost, prefix)
            pytest_assert(
                current == initial_oid,
                f"[{setup['af']}] Route {prefix} NHG OID changed: {initial_oid} → {current}"
            )

    def _assert_primary_members(self, setup, expected_ips, step):
        """
        Verify each route's protection NHG has exactly *expected_ips* as its
        set of PRIMARY-role members in the SAI nh_list.

        With the symmetric dispatch the invariant is "members in nh_list of
        role r = up members of role r".  This assertion makes the invariant
        observable rather than implicit.
        """
        duthost = setup["duthost"]
        for prefix, oid in setup["initial_oids"].items():
            actual = _get_nhg_member_ips_by_role(duthost, oid, "PRIMARY")
            pytest_assert(
                actual == expected_ips,
                f"[{setup['af']}][{step}] {prefix} NHG {oid}: PRIMARY members "
                f"= {actual}, expected {expected_ips}"
            )

    def _wait_for_macs(self, ptfadapter, setup, expected_macs, step):
        # Retain the last observed (seen MACs, recv_count) so a failure can
        # report whether NO path was used (seen == empty / recv_count == 0 ->
        # PTF injection never delivered) vs only SOME paths (seen is a partial
        # subset -> distribution/observation gap). The bare issubset result
        # hides that distinction.
        last = {"seen": set(), "recv": 0}

        def _seen():
            seen, recv = _send_and_collect_macs(
                ptfadapter,
                setup["src_ptf_id"],
                setup["all_ptf_ids"],
                setup["router_mac"],
                setup["dst_ip"],
                FLOW_COUNT,
                setup["af"],
            )
            last["seen"], last["recv"] = seen, recv
            return expected_macs.issubset(seen)

        pytest_assert(
            wait_until(CONVERGENCE_TIMEOUT, CONVERGENCE_POLL, 0, _seen),
            f"[{setup['af']}][{step}] MACs {expected_macs} not seen within "
            f"{CONVERGENCE_TIMEOUT}s (last seen={last['seen'] or set()}, "
            f"recv_count={last['recv']}, src_ptf_id={setup['src_ptf_id']}, "
            f"dst_ptf_ids={setup['all_ptf_ids']})"
        )

    def test_protection_nhg_lifecycle(self, prot_nhg_setup, ptfadapter):
        setup = prot_nhg_setup
        duthost = setup["duthost"]
        af = setup["af"]

        p0, p1 = setup["primary"]
        s0, s1 = setup["standby"]
        p0_mac, p1_mac = p0["peer_mac"], p1["peer_mac"]
        s0_mac, s1_mac = s0["peer_mac"], s1["peer_mac"]

        downed = []

        try:
            p0_ip, p1_ip = p0["peer_ip"], p1["peer_ip"]

            # Step 1: All up — both primaries carry traffic.
            logger.info("[%s] Step 1: all up", af)
            self._assert_traffic(ptfadapter, setup,
                                 expected_macs={p0_mac, p1_mac},
                                 forbidden_macs=set(),
                                 step="all_up")
            self._assert_switchover(setup, expected_active=False, step="all_up")
            self._assert_oids_stable(setup)
            self._assert_primary_members(setup, {p0_ip, p1_ip}, step="all_up")

            # Step 2: Primary[0] down — partial failure, no switchover yet.
            # SET_SWITCHOVER must remain false (p1 still alive).
            # Orchagent surgically removes p0 from the SAI NHG's primary
            # nh_list (handleProtectionNhgMemberDown / partial-failure path),
            # so hardware re-hashes only over surviving primaries — no
            # blackhole share for traffic that would have hashed to p0.
            # The assertion below verifies p0_mac is not seen and p1_mac is.
            logger.info("[%s] Step 2: primary[0] down", af)
            _bring_intf_down(duthost, p0)
            downed.append(p0)
            time.sleep(CONVERGENCE_POLL * 2)

            self._assert_traffic(ptfadapter, setup,
                                 expected_macs={p1_mac},
                                 forbidden_macs={p0_mac},
                                 step="p0_down",
                                 min_recv_ratio=0.9)
            self._assert_switchover(setup, expected_active=False, step="p0_down")
            self._assert_oids_stable(setup)
            self._assert_primary_members(setup, {p1_ip}, step="p0_down")

            # Step 3: Primary[1] down — switchover to standbys.
            logger.info("[%s] Step 3: primary[1] down → switchover", af)
            _bring_intf_down(duthost, p1)
            downed.append(p1)
            time.sleep(CONVERGENCE_POLL * 2)

            self._assert_traffic(ptfadapter, setup,
                                 expected_macs={s0_mac, s1_mac},
                                 forbidden_macs={p0_mac, p1_mac},
                                 step="all_primary_down")
            self._assert_switchover(setup, expected_active=True,
                                    step="all_primary_down")
            self._assert_oids_stable(setup)
            # All primaries down + setSwitchover(true) + remove the last primary
            # -> SAI primary nh_list is empty.
            self._assert_primary_members(setup, set(), step="all_primary_down")

            # Step 4: Primary[0] up — revert (p1 still down).
            # After revert (SET_SWITCHOVER=false), hardware forwards on primaries.
            # p1 is still physically down so its MAC must not appear.
            logger.info("[%s] Step 4: primary[0] up → revert", af)
            _bring_intf_up(duthost, p0)
            downed.remove(p0)

            self._wait_for_macs(ptfadapter, setup, {p0_mac}, step="p0_back")
            self._assert_traffic(ptfadapter, setup,
                                 expected_macs={p0_mac},
                                 forbidden_macs={p1_mac},
                                 step="p0_back",
                                 min_recv_ratio=0.9)
            self._assert_switchover(setup, expected_active=False, step="p0_back")
            self._assert_oids_stable(setup)
            self._assert_primary_members(setup, {p0_ip}, step="p0_back")

            # Step 5: Primary[1] up — both primaries active again.
            logger.info("[%s] Step 5: primary[1] up → both primaries", af)
            _bring_intf_up(duthost, p1)
            downed.remove(p1)

            self._wait_for_macs(ptfadapter, setup, {p0_mac, p1_mac},
                                step="both_up_again")
            self._assert_traffic(ptfadapter, setup,
                                 expected_macs={p0_mac, p1_mac},
                                 forbidden_macs=set(),
                                 step="both_up_again")
            self._assert_switchover(setup, expected_active=False,
                                    step="both_up_again")
            self._assert_oids_stable(setup)
            self._assert_primary_members(setup, {p0_ip, p1_ip}, step="both_up_again")

        finally:
            for intf in downed:
                logger.info("[%s] Cleanup: restoring %s", af, intf["name"])
                try:
                    for port in intf["shutdown"]:
                        duthost.no_shutdown_interface(port)
                    wait_until(CONVERGENCE_TIMEOUT, CONVERGENCE_POLL, 0,
                               lambda: _intf_oper_state(duthost, intf) == "up")
                except Exception as exc:
                    logger.warning("[%s] Cleanup failed for %s: %s",
                                   af, intf["name"], exc)

    def _assert_standby_members(self, setup, expected_ips, step):
        """
        Verify each route's protection NHG has exactly *expected_ips* as its
        set of STANDBY-role members in the SAI nh_list.

        Mirror of _assert_primary_members for the standby side.  With the
        symmetric dispatch the invariant is "members in nh_list of role r = up
        members of role r"; while the group is switched over this makes the
        active standby set observable rather than implicit.
        """
        duthost = setup["duthost"]
        for prefix, oid in setup["initial_oids"].items():
            actual = _get_nhg_member_ips_by_role(duthost, oid, "STANDBY")
            pytest_assert(
                actual == expected_ips,
                f"[{setup['af']}][{step}] {prefix} NHG {oid}: STANDBY members "
                f"= {actual}, expected {expected_ips}"
            )

    def test_standby_churn_while_switched_over(self, prot_nhg_setup, ptfadapter):
        """
        Standby member churn while the group is switched over (all primaries
        down, standbys active).

        Lifecycle:
          1. Both primaries down -> switchover active, both standbys carry
             traffic, PRIMARY nh_list empty, STANDBY nh_list = {s0, s1}.
          2. Standby[0] down -> active set shrinks to standby[1] only: traffic
             re-hashes over the surviving standby with no blackhole, STANDBY
             nh_list = {s1}, switchover stays true, NHG OID stable.
          3. Standby[0] up -> active set regrows to both standbys.

        This exercises the invalidate/validateMember STANDBY-while-switched-over
        path (which must NOT be a no-op) and confirms the "never remove the last
        active standby" guard is not tripped while more than one standby is up.
        The NHG OID must stay stable throughout (in-place SAI member churn).
        """
        setup = prot_nhg_setup
        duthost = setup["duthost"]
        af = setup["af"]

        p0, p1 = setup["primary"]
        s0, s1 = setup["standby"]
        p0_mac, p1_mac = p0["peer_mac"], p1["peer_mac"]
        s0_mac, s1_mac = s0["peer_mac"], s1["peer_mac"]
        s0_ip, s1_ip = s0["peer_ip"], s1["peer_ip"]

        downed = []
        try:
            # Step 1: drive to switched-over state (both primaries down).
            logger.info("[%s] standby-churn step1: both primaries down -> switchover", af)
            _bring_intf_down(duthost, p0)
            downed.append(p0)
            _bring_intf_down(duthost, p1)
            downed.append(p1)
            time.sleep(CONVERGENCE_POLL * 2)

            self._wait_for_macs(ptfadapter, setup, {s0_mac, s1_mac},
                                step="switched_over")
            self._assert_switchover(setup, expected_active=True, step="switched_over")
            self._assert_oids_stable(setup)
            self._assert_primary_members(setup, set(), step="switched_over")
            self._assert_standby_members(setup, {s0_ip, s1_ip}, step="switched_over")

            # Step 2: standby[0] down while switched over -> shrink to standby[1].
            logger.info("[%s] standby-churn step2: standby[0] down -> shrink", af)
            _bring_intf_down(duthost, s0)
            downed.append(s0)
            time.sleep(CONVERGENCE_POLL * 2)

            self._assert_traffic(ptfadapter, setup,
                                 expected_macs={s1_mac},
                                 forbidden_macs={s0_mac, p0_mac, p1_mac},
                                 step="standby0_down",
                                 min_recv_ratio=0.9)
            self._assert_switchover(setup, expected_active=True, step="standby0_down")
            self._assert_oids_stable(setup)
            self._assert_standby_members(setup, {s1_ip}, step="standby0_down")

            # Step 3: standby[0] back up -> active set regrows to both standbys.
            logger.info("[%s] standby-churn step3: standby[0] up -> regrow", af)
            _bring_intf_up(duthost, s0)
            downed.remove(s0)

            self._wait_for_macs(ptfadapter, setup, {s0_mac, s1_mac},
                                step="standby0_back")
            self._assert_traffic(ptfadapter, setup,
                                 expected_macs={s0_mac, s1_mac},
                                 forbidden_macs={p0_mac, p1_mac},
                                 step="standby0_back")
            self._assert_switchover(setup, expected_active=True, step="standby0_back")
            self._assert_oids_stable(setup)
            self._assert_standby_members(setup, {s0_ip, s1_ip}, step="standby0_back")

        finally:
            for intf in downed:
                logger.info("[%s] Cleanup: restoring %s", af, intf["name"])
                try:
                    for port in intf["shutdown"]:
                        duthost.no_shutdown_interface(port)
                    wait_until(CONVERGENCE_TIMEOUT, CONVERGENCE_POLL, 0,
                               lambda: _intf_oper_state(duthost, intf) == "up")
                except Exception as exc:
                    logger.warning("[%s] Cleanup failed for %s: %s",
                                   af, intf["name"], exc)

    def test_all_paths_down_keeps_last_standby(self, prot_nhg_setup, ptfadapter):
        """
        All-paths-dead guard: the active role must never be emptied, not even
        when its last live member goes down.

        test_standby_churn_while_switched_over covers a standby dropping while
        another standby is still up -- there the member is removed and the
        guard deliberately stays out of the way.  This test drives the boundary
        one step past that: with both primaries already down and the group
        switched over, taking the last live standby down leaves orchagent
        nowhere to move traffic.  Rather than emptying the active subset --
        which realizes as a drop FEC, and which some SDKs reject outright when
        asked to delete the last active member -- ProtNhg keeps the dead member
        programmed and lets traffic black-hole until a path recovers
        ("all paths down; keeping the last inner member rather than emptying
        the active role").

        Both roles here have 2 nexthops, so this exercises the recursive
        (inner-ECMP) form of the guard.  The single-member form lives on the
        other branch and is not covered here.

        Lifecycle:
          1. Both primaries down         -> switched over, both standbys active.
          2. Standby[0] down             -> STANDBY nh_list shrinks to {s1}.
          3. Standby[1] down (last live) -> guard engages: STANDBY nh_list stays
             {s1} instead of going empty, switchover stays true, OID stable.
          4. Both standbys back up       -> self-heals to {s0, s1} and forwards.
        """
        setup = prot_nhg_setup
        duthost = setup["duthost"]
        af = setup["af"]

        p0, p1 = setup["primary"]
        s0, s1 = setup["standby"]
        s0_mac, s1_mac = s0["peer_mac"], s1["peer_mac"]
        s0_ip, s1_ip = s0["peer_ip"], s1["peer_ip"]

        downed = []
        try:
            # Step 1: drive to the switched-over state.
            logger.info("[%s] all-paths-down step1: both primaries down", af)
            _bring_intf_down(duthost, p0)
            downed.append(p0)
            _bring_intf_down(duthost, p1)
            downed.append(p1)
            time.sleep(CONVERGENCE_POLL * 2)

            self._wait_for_macs(ptfadapter, setup, {s0_mac, s1_mac},
                                step="switched_over")
            self._assert_switchover(setup, expected_active=True,
                                    step="switched_over")
            self._assert_standby_members(setup, {s0_ip, s1_ip},
                                         step="switched_over")

            # Step 2: standby[0] down -- one standby still live, so the guard
            # must NOT engage and the dead member is removed as usual.
            logger.info("[%s] all-paths-down step2: standby[0] down", af)
            _bring_intf_down(duthost, s0)
            downed.append(s0)
            time.sleep(CONVERGENCE_POLL * 2)

            self._assert_switchover(setup, expected_active=True,
                                    step="standby0_down")
            self._assert_standby_members(setup, {s1_ip}, step="standby0_down")

            # Step 3: standby[1] down -- the last live member of the active
            # role, with no live primary to fall back to.  The guard engages.
            #
            # A fixed settle rather than a poll: the assertion is that the
            # member set does NOT change, and a poll-until-equal would pass
            # instantly on the pre-existing value without ever giving an
            # incorrect removal the chance to land.
            logger.info("[%s] all-paths-down step3: standby[1] down -> guard", af)
            _bring_intf_down(duthost, s1)
            downed.append(s1)
            time.sleep(CONVERGENCE_POLL * 2)

            # Sampled for the log only.  The documented behavior is a
            # black-hole, but asserting recv_count == 0 is a negative check
            # that would also pass if PTF injection were simply broken; the
            # SAI-level assertions below are the real verification.
            seen, recv = _send_and_collect_macs(
                ptfadapter, setup["src_ptf_id"], setup["all_ptf_ids"],
                setup["router_mac"], setup["dst_ip"], FLOW_COUNT, af,
            )
            logger.info("[%s] all-paths-down: recv=%d/%d seen=%s "
                        "(black-hole expected)", af, recv, FLOW_COUNT, seen)

            self._assert_standby_members(setup, {s1_ip}, step="all_paths_down")
            self._assert_switchover(setup, expected_active=True,
                                    step="all_paths_down")
            self._assert_oids_stable(setup)

            # Step 4: recover both standbys -- primaries stay down, so the
            # group remains switched over and must forward on the standbys.
            logger.info("[%s] all-paths-down step4: standbys back up", af)
            _bring_intf_up(duthost, s0)
            downed.remove(s0)
            _bring_intf_up(duthost, s1)
            downed.remove(s1)

            self._wait_for_macs(ptfadapter, setup, {s0_mac, s1_mac},
                                step="standbys_back")
            self._assert_switchover(setup, expected_active=True,
                                    step="standbys_back")
            self._assert_standby_members(setup, {s0_ip, s1_ip},
                                         step="standbys_back")
            self._assert_oids_stable(setup)

        finally:
            for intf in downed:
                logger.info("[%s] Cleanup: restoring %s", af, intf["name"])
                try:
                    for port in intf["shutdown"]:
                        duthost.no_shutdown_interface(port)
                    wait_until(CONVERGENCE_TIMEOUT, CONVERGENCE_POLL, 0,
                               lambda: _intf_oper_state(duthost, intf) == "up")
                except Exception as exc:
                    logger.warning("[%s] Cleanup failed for %s: %s",
                                   af, intf["name"], exc)


# ---------------------------------------------------------------------------
# Shared-primary multi-NHG fixture and test
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", params=["ipv4", "ipv6"])
def shared_primary_setup(request, duthosts, rand_selected_dut, nh_candidates, ptfadapter):
    """
    Discover 3 nexthop interfaces for the given AF:
      primary   — the one shared nexthop
      standby_a — standby for NHG-A only
      standby_b — standby for NHG-B only

    Programs two routes:
      ROUTE-A  →  NHG-A  (primary=primary, standby=standby_a)
      ROUTE-B  →  NHG-B  (primary=primary, standby=standby_b)

    When primary goes down both NHGs must independently switchover.
    """
    af = request.param
    duthost = rand_selected_dut
    mg_facts = nh_candidates["mg_facts"]

    test_routes = SHARED_PRIMARY_ROUTES_V6 if af == "ipv6" else SHARED_PRIMARY_ROUTES_V4

    candidates = nh_candidates["by_af"][af]

    if len(candidates) < 3:
        pytest.skip(
            f"[{af}] shared_primary: need 3 nexthop interfaces with resolved neighbor; "
            f"found {len(candidates)}"
        )

    primary = candidates[0]
    standby_a = candidates[1]
    standby_b = candidates[2]

    logger.info("[%s] Shared primary : %s (%s) mac=%s",
                af, primary["name"], primary["kind"], primary["peer_mac"])
    logger.info("[%s] Standby-A      : %s (%s) mac=%s",
                af, standby_a["name"], standby_a["kind"], standby_a["peer_mac"])
    logger.info("[%s] Standby-B      : %s (%s) mac=%s",
                af, standby_b["name"], standby_b["kind"], standby_b["peer_mac"])

    # Inject port — not used by any of the 3 selected interfaces.
    used_physical = set()
    for intf in [primary, standby_a, standby_b]:
        used_physical.update(intf["shutdown"])

    src_ptf_id = None
    src_intf = None
    for intf, idx in mg_facts["minigraph_ptf_indices"].items():
        if intf not in used_physical:
            src_ptf_id = idx
            src_intf = intf
            break

    if src_ptf_id is None:
        pytest.skip(f"[{af}] shared_primary: no free PTF port for packet injection")

    logger.info("[%s] Inject port: %s (ptf id %d)", af, src_intf, src_ptf_id)

    # Defensive pre-clean: remove any stale entries from a prior aborted run.
    _delete_routes(duthost, test_routes)
    time.sleep(2)

    try:
        # ROUTE-A: primary + standby_a.  ROUTE-B: primary + standby_b.
        route_members = [
            (test_routes[0], [primary["peer_ip"]], [standby_a["peer_ip"]]),
            (test_routes[1], [primary["peer_ip"]], [standby_b["peer_ip"]]),
        ]
        _install_routes(duthost, route_members)

        for prefix in test_routes:
            pytest_assert(
                wait_until(30, 1, 0, _route_present, duthost, prefix),
                f"[{af}] shared_primary: route {prefix} did not appear in ASIC_DB"
            )

        initial_oids = {p: _get_asic_route_nhg_oid(duthost, p) for p in test_routes}
        logger.info("[%s] NHG OIDs: %s", af, initial_oids)

        for prefix, oid in initial_oids.items():
            pytest_assert(oid is not None, f"[{af}] Route {prefix} missing NHG OID")
            nhg_type = _get_nhg_attr(duthost, oid, "SAI_NEXT_HOP_GROUP_ATTR_TYPE")
            pytest_assert(
                nhg_type == "SAI_NEXT_HOP_GROUP_TYPE_PROTECTION",
                f"[{af}] Route {prefix} NHG {oid} type='{nhg_type}', "
                f"expected SAI_NEXT_HOP_GROUP_TYPE_PROTECTION"
            )

        # Verify ROUTE-A and ROUTE-B have *different* NHG OIDs (each has its own NHG).
        oid_a, oid_b = initial_oids[test_routes[0]], initial_oids[test_routes[1]]
        pytest_assert(
            oid_a != oid_b,
            f"[{af}] ROUTE-A and ROUTE-B share the same NHG OID {oid_a} — "
            f"expected distinct NHGs"
        )

        all_ptf_ids = []
        for intf in [primary, standby_a, standby_b]:
            all_ptf_ids.extend(intf["ptf_ids"])

        yield {
            "af":          af,
            "duthost":     duthost,
            "router_mac":  duthost.facts["router_mac"],
            "src_ptf_id":  src_ptf_id,
            "primary":     primary,
            "standby_a":   standby_a,
            "standby_b":   standby_b,
            "all_ptf_ids": all_ptf_ids,
            "initial_oids": initial_oids,
            "test_routes": test_routes,
            # per-route dst IPs for traffic verification
            "dst_ip_a":    test_routes[0].split("/")[0],
            "dst_ip_b":    test_routes[1].split("/")[0],
        }
    finally:
        _delete_routes(duthost, test_routes)


class TestSharedPrimaryNhg:
    """
    Two protection NHGs share the same primary nexthop but have different
    standbys.  Verifies that bringing the shared primary down causes BOTH
    NHGs to switchover, and that each NHG independently switches to its own
    standby (not the other NHG's standby).
    """

    def _traffic_macs(self, ptfadapter, setup, dst_ip):
        """Send FLOW_COUNT packets to dst_ip, return set of seen dst MACs."""
        seen, _ = _send_and_collect_macs(
            ptfadapter,
            setup["src_ptf_id"],
            setup["all_ptf_ids"],
            setup["router_mac"],
            dst_ip,
            FLOW_COUNT,
            setup["af"],
        )
        return seen

    def _assert_switchover(self, setup, prefix, expected_active, step):
        duthost = setup["duthost"]
        oid = setup["initial_oids"][prefix]
        expected_str = "true" if expected_active else "false"
        val = _get_nhg_attr(duthost, oid, "SAI_NEXT_HOP_GROUP_ATTR_SET_SWITCHOVER")
        actual = val if val is not None else "false"
        pytest_assert(
            actual == expected_str,
            f"[{setup['af']}][{step}] {prefix} NHG {oid}: switchover={actual}, "
            f"expected={expected_str}"
        )

    def _assert_oids_stable(self, setup):
        duthost = setup["duthost"]
        for prefix, initial_oid in setup["initial_oids"].items():
            current = _get_asic_route_nhg_oid(duthost, prefix)
            pytest_assert(
                current == initial_oid,
                f"[{setup['af']}] Route {prefix} NHG OID changed: "
                f"{initial_oid} → {current}"
            )

    def _wait_for_mac(self, ptfadapter, setup, dst_ip, expected_mac, step):
        def _seen():
            return expected_mac in self._traffic_macs(ptfadapter, setup, dst_ip)
        pytest_assert(
            wait_until(CONVERGENCE_TIMEOUT, CONVERGENCE_POLL, 0, _seen),
            f"[{setup['af']}][{step}] MAC {expected_mac} not seen on {dst_ip} "
            f"within {CONVERGENCE_TIMEOUT}s"
        )

    def test_shared_primary_switchover(self, shared_primary_setup, ptfadapter):
        """
        Steps:
          1. All up — both routes forward on primary MAC.
          2. Primary down — NHG-A switches to standby_a, NHG-B switches to standby_b.
             Both NHG OIDs must remain stable (no re-programming).
          3. Primary up — both NHGs revert; routes forward on primary MAC again.
        """
        setup = shared_primary_setup
        duthost = setup["duthost"]
        af = setup["af"]

        primary = setup["primary"]
        standby_a = setup["standby_a"]
        standby_b = setup["standby_b"]

        p_mac = primary["peer_mac"]
        sa_mac = standby_a["peer_mac"]
        sb_mac = standby_b["peer_mac"]

        route_a = setup["test_routes"][0]
        route_b = setup["test_routes"][1]
        dst_a = setup["dst_ip_a"]
        dst_b = setup["dst_ip_b"]

        downed = []

        try:
            # ----------------------------------------------------------------
            # Step 1: All up — both routes must use primary MAC.
            # ----------------------------------------------------------------
            logger.info("[%s] Step 1: all up", af)
            macs_a = self._traffic_macs(ptfadapter, setup, dst_a)
            macs_b = self._traffic_macs(ptfadapter, setup, dst_b)
            logger.info("[%s] Step 1: route-A macs=%s  route-B macs=%s",
                        af, macs_a, macs_b)

            pytest_assert(p_mac in macs_a,
                          f"[{af}] Step 1: primary MAC not seen on ROUTE-A")
            pytest_assert(p_mac in macs_b,
                          f"[{af}] Step 1: primary MAC not seen on ROUTE-B")
            self._assert_switchover(setup, route_a, False, "all_up")
            self._assert_switchover(setup, route_b, False, "all_up")
            self._assert_oids_stable(setup)

            # ----------------------------------------------------------------
            # Step 2: Bring primary down — both NHGs must switchover.
            # ----------------------------------------------------------------
            logger.info("[%s] Step 2: primary %s down", af, primary["name"])
            _bring_intf_down(duthost, primary)
            downed.append(primary)
            time.sleep(CONVERGENCE_POLL * 2)

            # Wait for each route to stop using primary MAC and start using
            # its own standby.
            self._wait_for_mac(ptfadapter, setup, dst_a, sa_mac, "primary_down_nhg_a")
            self._wait_for_mac(ptfadapter, setup, dst_b, sb_mac, "primary_down_nhg_b")

            macs_a = self._traffic_macs(ptfadapter, setup, dst_a)
            macs_b = self._traffic_macs(ptfadapter, setup, dst_b)
            logger.info("[%s] Step 2: route-A macs=%s  route-B macs=%s",
                        af, macs_a, macs_b)

            # Each route uses only its own standby.
            pytest_assert(p_mac not in macs_a,
                          f"[{af}] Step 2: primary MAC still seen on ROUTE-A after switchover")
            pytest_assert(sa_mac in macs_a,
                          f"[{af}] Step 2: standby-A MAC not seen on ROUTE-A")
            pytest_assert(sb_mac not in macs_a,
                          f"[{af}] Step 2: standby-B MAC incorrectly seen on ROUTE-A")

            pytest_assert(p_mac not in macs_b,
                          f"[{af}] Step 2: primary MAC still seen on ROUTE-B after switchover")
            pytest_assert(sb_mac in macs_b,
                          f"[{af}] Step 2: standby-B MAC not seen on ROUTE-B")
            pytest_assert(sa_mac not in macs_b,
                          f"[{af}] Step 2: standby-A MAC incorrectly seen on ROUTE-B")

            self._assert_switchover(setup, route_a, True, "primary_down")
            self._assert_switchover(setup, route_b, True, "primary_down")
            self._assert_oids_stable(setup)

            # ----------------------------------------------------------------
            # Step 3: Bring primary back up — both NHGs must revert.
            # ----------------------------------------------------------------
            logger.info("[%s] Step 3: primary %s up → revert", af, primary["name"])
            _bring_intf_up(duthost, primary)
            downed.remove(primary)

            self._wait_for_mac(ptfadapter, setup, dst_a, p_mac, "primary_back_nhg_a")
            self._wait_for_mac(ptfadapter, setup, dst_b, p_mac, "primary_back_nhg_b")

            macs_a = self._traffic_macs(ptfadapter, setup, dst_a)
            macs_b = self._traffic_macs(ptfadapter, setup, dst_b)
            logger.info("[%s] Step 3: route-A macs=%s  route-B macs=%s",
                        af, macs_a, macs_b)

            pytest_assert(p_mac in macs_a,
                          f"[{af}] Step 3: primary MAC not seen on ROUTE-A after revert")
            pytest_assert(p_mac in macs_b,
                          f"[{af}] Step 3: primary MAC not seen on ROUTE-B after revert")

            self._assert_switchover(setup, route_a, False, "primary_back")
            self._assert_switchover(setup, route_b, False, "primary_back")
            self._assert_oids_stable(setup)

        finally:
            for intf in downed:
                logger.info("[%s] Cleanup: restoring %s", af, intf["name"])
                try:
                    for port in intf["shutdown"]:
                        duthost.no_shutdown_interface(port)
                    wait_until(CONVERGENCE_TIMEOUT, CONVERGENCE_POLL, 0,
                               lambda: _intf_oper_state(duthost, intf) == "up")
                except Exception as exc:
                    logger.warning("[%s] Cleanup failed for %s: %s",
                                   af, intf["name"], exc)


# ---------------------------------------------------------------------------
# Shared-key refcount fixture and test
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", params=["ipv4", "ipv6"])
def shared_key_setup(request, duthosts, rand_selected_dut, nh_candidates, ptfadapter):
    """
    Discover nexthop interfaces (1 primary + 1 standby) for the given AF and
    yield the facts.  The test programs/deletes the routes itself so it can
    control refcount timing; teardown removes both prefixes.

    Interface choice matters for test isolation.  A protection NHG is keyed by
    its member set, so two routes anywhere on the DUT with the same
    (primary, standby) resolve to the SAME ref-counted SAI NHG.  The other
    fixtures here are module-scoped and stay live for the whole module, and they
    all use candidates[0] as a primary (lifecycle: {c0,c1}|{c2,c3};
    shared_primary: {c0}|{c1} and {c0}|{c2}; nm_ratio: {c0}|... and
    {c0,c1,c2}|{c3}).  If shared_key also used {c0}|{c1} it would share
    shared_primary's ROUTE-A NHG, and deleting both shared_key routes would NOT
    drop the group to refcount 0 (ROUTE-A still holds it) -- breaking the
    teardown-to-zero assertion.  We therefore use candidates[1] as primary and
    candidates[2] as standby, so this NHG's key ({c1}|{c2}) is disjoint from
    every other fixture's and is referenced only by this test's two routes.

    This reasoning is only sound because all fixtures index into one list
    discovered once per module (see nh_candidates).
    """
    af = request.param
    duthost = rand_selected_dut

    test_routes = SHARED_KEY_ROUTES_V6 if af == "ipv6" else SHARED_KEY_ROUTES_V4

    # Need >=3 so we can use candidates[1]/[2] (see isolation note above).
    candidates = nh_candidates["by_af"][af]
    if len(candidates) < 3:
        pytest.skip(
            f"[{af}] shared_key: need 3 nexthop interfaces with resolved "
            f"neighbor (to pick a collision-free member pair); "
            f"found {len(candidates)}"
        )

    primary = candidates[1]
    standby = candidates[2]
    logger.info("[%s] shared_key: primary=%s (%s) standby=%s (%s)", af,
                primary["name"], primary["kind"], standby["name"], standby["kind"])

    # Defensive pre-clean from any aborted prior run.
    _delete_routes(duthost, test_routes)
    time.sleep(2)
    try:
        yield {
            "af":          af,
            "duthost":     duthost,
            "primary":     primary,
            "standby":     standby,
            "test_routes": test_routes,
        }
    finally:
        _delete_routes(duthost, test_routes)


class TestSharedKeyRefcount:
    """
    Two routes programmed with an IDENTICAL primary+standby member set must
    resolve to a single, ref-counted protection NHG (same NHG OID).  Deleting
    the first route leaves the shared NHG intact (refcount 2 -> 1); deleting
    the second tears it down (refcount -> 0).  Exercises
    getProtNhgRefCount() / incProtNhgRefCount() / removeProtNhg().
    """

    def test_shared_key_refcount(self, shared_key_setup):
        setup = shared_key_setup
        duthost = setup["duthost"]
        af = setup["af"]
        primary = setup["primary"]
        standby = setup["standby"]
        r0, r1 = setup["test_routes"]

        primary_ips = [primary["peer_ip"]]
        standby_ips = [standby["peer_ip"]]

        try:
            # Program two routes with the SAME primary+standby members.
            _install_routes(duthost, [(r0, primary_ips, standby_ips),
                                      (r1, primary_ips, standby_ips)])
            for p in (r0, r1):
                pytest_assert(
                    wait_until(30, 1, 0, _route_present, duthost, p),
                    f"[{af}] shared_key: route {p} did not appear in ASIC_DB"
                )

            oid0 = _get_asic_route_nhg_oid(duthost, r0)
            oid1 = _get_asic_route_nhg_oid(duthost, r1)
            logger.info("[%s] shared_key: %s->%s  %s->%s", af, r0, oid0, r1, oid1)
            pytest_assert(
                oid0 is not None and oid1 is not None,
                f"[{af}] shared_key: missing NHG OID (oid0={oid0} oid1={oid1})"
            )

            # Identical member set -> one shared, ref-counted protection NHG.
            pytest_assert(
                oid0 == oid1,
                f"[{af}] shared_key: routes with identical members have distinct "
                f"NHG OIDs {oid0} != {oid1}; expected a single shared NHG"
            )
            nhg_type = _get_nhg_attr(duthost, oid0, "SAI_NEXT_HOP_GROUP_ATTR_TYPE")
            pytest_assert(
                nhg_type == "SAI_NEXT_HOP_GROUP_TYPE_PROTECTION",
                f"[{af}] shared_key: NHG {oid0} type='{nhg_type}', expected PROTECTION"
            )

            # Delete the first route -> shared NHG must survive (refcount 2 -> 1).
            logger.info("[%s] shared_key: delete %s, expect NHG %s to survive", af, r0, oid0)
            _delete_routes(duthost, [r0])
            pytest_assert(
                wait_until(30, 1, 0, lambda: not _route_present(duthost, r0)),
                f"[{af}] shared_key: route {r0} not removed from ASIC_DB"
            )
            pytest_assert(
                _route_present(duthost, r1),
                f"[{af}] shared_key: route {r1} disappeared after deleting {r0}"
            )
            pytest_assert(
                _get_asic_route_nhg_oid(duthost, r1) == oid1,
                f"[{af}] shared_key: route {r1} NHG OID changed after deleting {r0}"
            )
            pytest_assert(
                _nhg_exists(duthost, oid0),
                f"[{af}] shared_key: shared NHG {oid0} was torn down while {r1} "
                f"still references it (refcount underflow)"
            )

            # Delete the second route -> shared NHG must now be torn down (-> 0).
            logger.info("[%s] shared_key: delete %s, expect NHG %s to be removed", af, r1, oid0)
            _delete_routes(duthost, [r1])
            pytest_assert(
                wait_until(30, 1, 0, lambda: not _route_present(duthost, r1)),
                f"[{af}] shared_key: route {r1} not removed from ASIC_DB"
            )
            pytest_assert(
                wait_until(30, 1, 0, lambda: not _nhg_exists(duthost, oid0)),
                f"[{af}] shared_key: NHG {oid0} still present after both routes "
                f"deleted (leak / refcount stuck)"
            )
        finally:
            _delete_routes(duthost, setup["test_routes"])


# ---------------------------------------------------------------------------
# Asymmetric N:M ratio fixture and test
# ---------------------------------------------------------------------------

@pytest.fixture(
    scope="module",
    params=[
        (af, n_primary, n_standby)
        for af in ("ipv4", "ipv6")
        for n_primary in (1, 2)
        for n_standby in (1, 2)
    ],
    ids=lambda p: f"{p[0]}-{p[1]}p{p[2]}s",
)
def nm_ratio_setup(request, duthosts, rand_selected_dut, nh_candidates, ptfadapter):
    """
    Program 2 routes as a protection NHG across the primary:standby ratio grid
    (n_primary, n_standby each in 1..2 -> 1p1s, 1p2s, 2p1s, 2p2s) and yield the
    facts.  Role cardinality has exactly two PNHG-relevant shapes per side: a
    single next hop is a plain protection member, while >= 2 next hops become an
    inner ECMP.  So {1,2} x {1,2} covers every distinct shape (plain/ECMP on
    each side); larger member counts (n >= 3) exercise only ordinary inner-ECMP
    behavior, not a new protection path, and would also exceed this topology's
    4-nexthop budget.  The len(candidates) guard below still skips any combo
    that outruns the testbed's resolved-neighbor count.
    """
    af, n_primary, n_standby = request.param
    total = n_primary + n_standby
    duthost = rand_selected_dut
    mg_facts = nh_candidates["mg_facts"]

    test_routes = NM_RATIO_ROUTES_V6 if af == "ipv6" else NM_RATIO_ROUTES_V4

    candidates = nh_candidates["by_af"][af]
    if len(candidates) < total:
        pytest.skip(
            f"[{af}] nm_ratio {n_primary}:{n_standby}: need {total} nexthop "
            f"interfaces with resolved neighbor; found {len(candidates)}"
        )

    selected = candidates[:total]
    primary = selected[:n_primary]
    standby = selected[n_primary:total]

    logger.info("[%s] nm_ratio: %d primary %s / %d standby %s", af,
                n_primary, [i["name"] for i in primary],
                n_standby, [i["name"] for i in standby])

    src_ptf_id, src_intf = _pick_inject_port(mg_facts, selected)
    if src_ptf_id is None:
        pytest.skip(f"[{af}] nm_ratio: no free PTF port for packet injection")
    logger.info("[%s] nm_ratio: inject port %s (ptf id %d)", af, src_intf, src_ptf_id)

    primary_ips = [i["peer_ip"] for i in primary]
    standby_ips = [i["peer_ip"] for i in standby]

    _delete_routes(duthost, test_routes)
    time.sleep(2)
    try:
        _install_routes(duthost,
                        [(prefix, primary_ips, standby_ips)
                         for prefix in test_routes])

        for prefix in test_routes:
            pytest_assert(
                wait_until(30, 1, 0, _route_present, duthost, prefix),
                f"[{af}] nm_ratio: route {prefix} did not appear in ASIC_DB"
            )

        initial_oids = {p: _get_asic_route_nhg_oid(duthost, p) for p in test_routes}
        logger.info("[%s] nm_ratio: NHG OIDs %s", af, initial_oids)
        for prefix, oid in initial_oids.items():
            pytest_assert(oid is not None, f"[{af}] nm_ratio: {prefix} missing NHG OID")
            nhg_type = _get_nhg_attr(duthost, oid, "SAI_NEXT_HOP_GROUP_ATTR_TYPE")
            pytest_assert(
                nhg_type == "SAI_NEXT_HOP_GROUP_TYPE_PROTECTION",
                f"[{af}] nm_ratio: {prefix} NHG {oid} type='{nhg_type}', expected PROTECTION"
            )

        all_ptf_ids = []
        for intf in primary + standby:
            all_ptf_ids.extend(intf["ptf_ids"])

        yield {
            "af":           af,
            "n_primary":    n_primary,
            "n_standby":    n_standby,
            "duthost":      duthost,
            "router_mac":   duthost.facts["router_mac"],
            "src_ptf_id":   src_ptf_id,
            "dst_ip":       test_routes[0].split("/")[0],
            "primary":      primary,
            "standby":      standby,
            "all_ptf_ids":  all_ptf_ids,
            "initial_oids": initial_oids,
            "test_routes":  test_routes,
        }
    finally:
        _delete_routes(duthost, test_routes)


class TestNmRatio:
    """
    Asymmetric N:M protection NHGs.  Drives one generic lifecycle over every
    ratio nm_ratio_setup parametrizes -- 1:1, 1:2, 2:1 and 2:2 -- so each side
    is exercised both as a plain protection member (n == 1) and as an inner
    ECMP (n >= 2), which are the only two shapes the PNHG realization
    distinguishes:
      1. All up          -> traffic spans all primaries, no standby, no switchover.
      2. Drop primaries one at a time (all but the last) -> no switchover while
         >=1 primary is alive; traffic re-hashes over survivors, no blackhole.
      3. Drop the last primary -> switchover to all standbys.
      4. Bring one primary back -> revert to primaries.
    NHG OID must stay stable throughout.
    """

    def _assert_traffic(self, ptfadapter, setup, expected_macs, forbidden_macs,
                        step, min_recv_ratio=0):
        seen, recv_count = _send_and_collect_macs(
            ptfadapter, setup["src_ptf_id"], setup["all_ptf_ids"],
            setup["router_mac"], setup["dst_ip"], FLOW_COUNT, setup["af"],
        )
        logger.info("[%s][%s] recv=%d/%d seen=%s expected=%s forbidden=%s",
                    setup["af"], step, recv_count, FLOW_COUNT, seen,
                    expected_macs, forbidden_macs)
        pytest_assert(recv_count > 0,
                      f"[{setup['af']}][{step}] No packets received — routing broken")
        for mac in expected_macs:
            pytest_assert(mac in seen,
                          f"[{setup['af']}][{step}] Expected MAC {mac} not seen. Got: {seen}")
        for mac in forbidden_macs:
            pytest_assert(mac not in seen,
                          f"[{setup['af']}][{step}] Forbidden MAC {mac} seen. Got: {seen}")
        if min_recv_ratio > 0:
            min_recv = int(min_recv_ratio * FLOW_COUNT)
            pytest_assert(
                recv_count >= min_recv,
                f"[{setup['af']}][{step}] only {recv_count}/{FLOW_COUNT} packets "
                f"received (need >= {min_recv}) — suggests partial-failure blackhole"
            )

    def _assert_switchover(self, setup, expected_active, step):
        duthost = setup["duthost"]
        expected_str = "true" if expected_active else "false"
        for prefix, oid in setup["initial_oids"].items():
            val = _get_nhg_attr(duthost, oid, "SAI_NEXT_HOP_GROUP_ATTR_SET_SWITCHOVER")
            actual = val if val is not None else "false"
            pytest_assert(
                actual == expected_str,
                f"[{setup['af']}][{step}] {prefix} NHG {oid}: switchover={actual}, "
                f"expected={expected_str}"
            )

    def _assert_oids_stable(self, setup):
        duthost = setup["duthost"]
        for prefix, initial_oid in setup["initial_oids"].items():
            current = _get_asic_route_nhg_oid(duthost, prefix)
            pytest_assert(
                current == initial_oid,
                f"[{setup['af']}] Route {prefix} NHG OID changed: {initial_oid} → {current}"
            )

    def _assert_primary_members(self, setup, expected_ips, step):
        duthost = setup["duthost"]
        for prefix, oid in setup["initial_oids"].items():
            actual = _get_nhg_member_ips_by_role(duthost, oid, "PRIMARY")
            pytest_assert(
                actual == expected_ips,
                f"[{setup['af']}][{step}] {prefix} NHG {oid}: PRIMARY members "
                f"= {actual}, expected {expected_ips}"
            )

    def _assert_standby_members(self, setup, expected_ips, step):
        """
        Verify the STANDBY-role nh_list, the "M" side of the N:M ratio.

        Without this the standby side is only ever observed indirectly, through
        which MACs the dataplane happens to hash to: a member tagged with the
        wrong CONFIGURED_ROLE, or a stale/extra member left in the STANDBY
        nh_list, would pass every ratio case as long as hardware still forwarded
        to the right neighbors.  This asserts the symmetric-dispatch invariant
        ("members in nh_list of role r = up members of role r") on the role the
        rest of this class never inspects.
        """
        duthost = setup["duthost"]
        for prefix, oid in setup["initial_oids"].items():
            actual = _get_nhg_member_ips_by_role(duthost, oid, "STANDBY")
            pytest_assert(
                actual == expected_ips,
                f"[{setup['af']}][{step}] {prefix} NHG {oid}: STANDBY members "
                f"= {actual}, expected {expected_ips}"
            )

    def _wait_for_primary_members(self, setup, expected_ips, step):
        # Wait for the inner-ECMP shrink/grow to converge in SAI before asserting
        # on the datapath. A fixed sleep after an interface flap races the
        # member-down -> inner-ECMP-member-remove path: if traffic is sampled
        # before the dead member leaves the primary inner ECMP, flows that hash
        # to it black-hole and the min_recv_ratio check fails spuriously. Poll
        # the programmed PRIMARY member set until it matches the live set.
        duthost = setup["duthost"]
        last = {}

        def _converged():
            for prefix, oid in setup["initial_oids"].items():
                actual = _get_nhg_member_ips_by_role(duthost, oid, "PRIMARY")
                last[prefix] = actual
                if actual != expected_ips:
                    return False
            return True
        pytest_assert(
            wait_until(CONVERGENCE_TIMEOUT, CONVERGENCE_POLL, 0, _converged),
            f"[{setup['af']}][{step}] PRIMARY members did not converge to "
            f"{expected_ips} within {CONVERGENCE_TIMEOUT}s (last={last})"
        )

    def _wait_for_macs(self, ptfadapter, setup, expected_macs, step):
        # Retain the last observed (seen MACs, recv_count) so a failure can
        # report whether NO path was used (seen == empty / recv_count == 0 ->
        # PTF injection never delivered) vs only SOME paths (seen is a partial
        # subset -> distribution/observation gap). The bare issubset result
        # hides that distinction.
        last = {"seen": set(), "recv": 0}

        def _seen():
            seen, recv = _send_and_collect_macs(
                ptfadapter, setup["src_ptf_id"], setup["all_ptf_ids"],
                setup["router_mac"], setup["dst_ip"], FLOW_COUNT, setup["af"],
            )
            last["seen"], last["recv"] = seen, recv
            return expected_macs.issubset(seen)
        pytest_assert(
            wait_until(CONVERGENCE_TIMEOUT, CONVERGENCE_POLL, 0, _seen),
            f"[{setup['af']}][{step}] MACs {expected_macs} not seen within "
            f"{CONVERGENCE_TIMEOUT}s (last seen={last['seen'] or set()}, "
            f"recv_count={last['recv']}, src_ptf_id={setup['src_ptf_id']}, "
            f"dst_ptf_ids={setup['all_ptf_ids']})"
        )

    def test_nm_ratio_switchover(self, nm_ratio_setup, ptfadapter):
        setup = nm_ratio_setup
        duthost = setup["duthost"]
        af = setup["af"]
        n_primary = setup["n_primary"]
        n_standby = setup["n_standby"]

        primaries = setup["primary"]
        standbys = setup["standby"]
        primary_macs = {i["peer_mac"] for i in primaries}
        standby_macs = {i["peer_mac"] for i in standbys}
        primary_ips = {i["peer_ip"] for i in primaries}
        # Standbys are never brought down here, and both role subtrees are
        # programmed at group-creation time (not lazily on switchover), so the
        # STANDBY nh_list is the full standby set at every step below.
        standby_ips = {i["peer_ip"] for i in standbys}

        downed = []
        try:
            # Step 1: all up -> traffic spans all primaries, no standby.
            logger.info("[%s] nm %d:%d step1: all up", af, n_primary, n_standby)
            self._wait_for_macs(ptfadapter, setup, primary_macs, step="all_up")
            self._assert_traffic(ptfadapter, setup,
                                 expected_macs=primary_macs,
                                 forbidden_macs=standby_macs,
                                 step="all_up")
            self._assert_switchover(setup, expected_active=False, step="all_up")
            self._assert_primary_members(setup, primary_ips, step="all_up")
            self._assert_standby_members(setup, standby_ips, step="all_up")
            self._assert_oids_stable(setup)

            # Step 2: drop primaries one at a time, all but the last.
            live_ips = set(primary_ips)
            for idx, p in enumerate(primaries[:-1]):
                logger.info("[%s] nm %d:%d step2.%d: primary %s down",
                            af, n_primary, n_standby, idx, p["name"])
                _bring_intf_down(duthost, p)
                downed.append(p)
                live_ips.discard(p["peer_ip"])
                # Wait for the primary inner ECMP to drop the dead member before
                # sampling traffic, so the min_recv_ratio check below is not
                # racing the shrink (see _wait_for_primary_members).
                self._wait_for_primary_members(setup, live_ips,
                                               step=f"primary_{idx}_down")

                live_macs = {i["peer_mac"] for i in primaries
                             if i["peer_ip"] in live_ips}
                down_macs = {i["peer_mac"] for i in downed}
                self._assert_traffic(ptfadapter, setup,
                                     expected_macs=live_macs,
                                     forbidden_macs=down_macs | standby_macs,
                                     step=f"primary_{idx}_down",
                                     min_recv_ratio=0.9)
                self._assert_switchover(setup, expected_active=False,
                                        step=f"primary_{idx}_down")
                self._assert_primary_members(setup, live_ips, step=f"primary_{idx}_down")
                self._assert_standby_members(setup, standby_ips,
                                             step=f"primary_{idx}_down")
                self._assert_oids_stable(setup)

            # Step 3: drop the last primary -> switchover to all standbys.
            last = primaries[-1]
            logger.info("[%s] nm %d:%d step3: last primary %s down -> switchover",
                        af, n_primary, n_standby, last["name"])
            _bring_intf_down(duthost, last)
            downed.append(last)
            time.sleep(CONVERGENCE_POLL * 2)

            self._wait_for_macs(ptfadapter, setup, standby_macs, step="switched_over")
            self._assert_traffic(ptfadapter, setup,
                                 expected_macs=standby_macs,
                                 forbidden_macs=primary_macs,
                                 step="switched_over")
            self._assert_switchover(setup, expected_active=True, step="switched_over")
            # Mixed-model asymmetry: a >=2-NH primary is an inner ECMP whose
            # membership shrinks to empty as members go down, so its programmed
            # set is empty after all primaries drop. A single-NH primary is a
            # plain member of the (stable) protection NHG and persists when down
            # -- switchover only flips the active side, it does not remove the
            # member -- so the primary set stays non-empty.
            expected_primary = set() if n_primary >= 2 else primary_ips
            self._assert_primary_members(setup, expected_primary,
                                         step="switched_over")
            # The standby side is now the active role and every standby is up,
            # so its nh_list must be the full set -- this is the state where a
            # mistagged CONFIGURED_ROLE or a stale STANDBY member actually
            # steers traffic.
            self._assert_standby_members(setup, standby_ips,
                                         step="switched_over")
            self._assert_oids_stable(setup)

            # Step 4: bring the first primary back -> revert to primaries.
            first = primaries[0]
            logger.info("[%s] nm %d:%d step4: primary %s up -> revert",
                        af, n_primary, n_standby, first["name"])
            _bring_intf_up(duthost, first)
            downed.remove(first)

            self._wait_for_macs(ptfadapter, setup, {first["peer_mac"]}, step="revert")
            # Wait for the recovered primary to be (re)programmed into the primary
            # inner ECMP before the min_recv_ratio check, so it is not racing the
            # switchback + inner-membership regrow.
            self._wait_for_primary_members(setup, {first["peer_ip"]}, step="revert")
            self._assert_traffic(ptfadapter, setup,
                                 expected_macs={first["peer_mac"]},
                                 forbidden_macs=standby_macs,
                                 step="revert",
                                 min_recv_ratio=0.9)
            self._assert_switchover(setup, expected_active=False, step="revert")
            self._assert_primary_members(setup, {first["peer_ip"]}, step="revert")
            self._assert_standby_members(setup, standby_ips, step="revert")
            self._assert_oids_stable(setup)

        finally:
            for intf in downed:
                logger.info("[%s] Cleanup: restoring %s", af, intf["name"])
                try:
                    for port in intf["shutdown"]:
                        duthost.no_shutdown_interface(port)
                    wait_until(CONVERGENCE_TIMEOUT, CONVERGENCE_POLL, 0,
                               lambda: _intf_oper_state(duthost, intf) == "up")
                except Exception as exc:
                    logger.warning("[%s] Cleanup failed for %s: %s",
                                   af, intf["name"], exc)
