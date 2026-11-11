import logging
import time
from collections import defaultdict                                 # Added for multi-asic support
import pytest                                                       # Added for multi-asic support
from tabulate import tabulate
from statistics import mean
from tests.common.utilities import wait
from tests.common.helpers.assertions import pytest_assert
# Added for multi-asic support: per-ASIC / per-DUT config helpers (ported from data3)
from tests.snappi_tests.bgp.files.rib_combo_dut_setup import (
    asic_instance_from_port,
    asic_indices_for_duthost,
    affected_setup_targets,
    backup_config_dbs,
    get_config_db,
    revert_config_db as rib_revert_config_db,
    unique_duthosts_from_targets,
)
logger = logging.getLogger(__name__)

# Added for multi-asic support: state used to back up / restore per-ASIC config_db
BGP_HELPER_CONFIG_DB_BACKUP_TAG = "bgp_convergence_helper"
_bgp_config_db_backups = []

# Added for multi-asic support: tier-2 community tagging. Opt-in per call through
# ``run_rib_in_convergence_test(tag_tier2_leak_communities=True)``; reset on every call.
_tag_tier2_leak_on_routes = False


# Added for multi-asic support
def _tier2_upstream_deny_present(duthost, tgen_ports, port_count):
    targets = affected_setup_targets(tgen_ports, port_count, default_duthost=duthost)
    for _dh, asic in targets:
        try:
            res = asic.run_vtysh("-c 'show running-config'")
            text = (res.get("stdout") or "") + (res.get("stderr") or "")
        except Exception as exc:
            logger.debug("show running-config failed on asic %s: %s", asic.asic_index, exc)
            continue
        if "UPSTREAM_PREFIX_DENY" in text:
            return True
    return False


# Added for multi-asic support
def _should_tag_tier2_leak_communities(duthost, tgen_ports, port_count):
    """Tag IXIA routes so they pass FROM_TIER2 deny route-maps when needed."""
    if _tier2_upstream_deny_present(duthost, tgen_ports, port_count):
        return True
    return bool(duthost.is_multi_asic)


# Added for multi-asic support
def _apply_tier2_leak_communities(route_range):
    if not _tag_tier2_leak_on_routes:
        return
    try:
        from tests.snappi_tests.variables import COMMUNITY_LOWER_TIER_LEAK
    except ImportError:
        COMMUNITY_LOWER_TIER_LEAK = ["8075:54000"]
    for community in COMMUNITY_LOWER_TIER_LEAK:
        manual_as_community = route_range.communities.add()
        manual_as_community.type = manual_as_community.MANUAL_AS_NUMBER
        manual_as_community.as_number = int(community.split(":")[0])
        manual_as_community.as_custom = int(community.split(":")[1])


TGEN_AS_NUM = 65200
DUT_AS_NUM = 65100
TIMEOUT = 90
WAIT_INTERVAL = 30
BGP_TYPE = 'ebgp'
temp_tg_port = dict()
NG_LIST = []
aspaths = [65002, 65003]

# ``get_rib_in_convergence`` ``finally``: pre-``stop()`` sleep for ``mem_cpu_monitor`` sampling.
# Full wait only when all iterations finish without exception; short wait on failure/early exit.
MEM_CPU_MONITOR_RIB_IN_POST_SUCCESS_SEC = 300
MEM_CPU_MONITOR_RIB_IN_POST_FAILURE_SEC = 7


# Added for multi-asic support: resolve (duthost, SonicAsic) owning a tgen_ports entry
def _resolve_port_context(default_duthost, port_entry):
    duthost = port_entry.get("duthost") or default_duthost
    return duthost, asic_instance_from_port(duthost, port_entry)


# Added for multi-asic support: keys written by _duthost_bgp_config_multi_asic on every tgen_ports entry it
# configures (ASNs resolved from the DUT, else TGEN_AS_NUM / DUT_AS_NUM); __tgen_bgp_config honours them.
RESOLVED_DUT_ASN_KEY = "bgp_dut_asn"
RESOLVED_PEER_ASN_KEY = "bgp_peer_asn"


# Added for multi-asic support: running config_facts of the ASIC owning a port (host level on single-asic DUT)
def _live_config_facts(dh, asic, cache):
    key = (dh.hostname, asic.asic_index if dh.is_multi_asic else 0)
    if key not in cache:
        cache[key] = asic.config_facts(host=dh.hostname, source="running")["ansible_facts"]
    return cache[key]


# Added for multi-asic support: pure parsers over config_facts dicts
def _to_asn(value):
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _asn_from_device_metadata(config_facts):
    meta = (config_facts.get("DEVICE_METADATA") or {}).get("localhost") or {}
    return _to_asn(meta.get("bgp_asn"))


def _peer_asn_from_bgp_neighbors(config_facts, dut_ip, neighbor_ip):
    """ASN of the BGP neighbor configured on the DUT for ``neighbor_ip`` (or, failing that, for the neighbor whose
    local_addr is ``dut_ip``). None when the DUT has no such neighbor."""
    neighbors = config_facts.get("BGP_NEIGHBOR") or {}
    wanted = (neighbor_ip or "").lower()
    local = (dut_ip or "").lower()
    if wanted:
        for nbr_ip, props in neighbors.items():
            asn = _to_asn((props or {}).get("asn"))
            if nbr_ip.lower() == wanted and asn is not None:
                return asn
    if local:
        for _nbr_ip, props in neighbors.items():
            asn = _to_asn((props or {}).get("asn"))
            if ((props or {}).get("local_addr") or "").lower() == local and asn is not None:
                return asn
    return None


def _interface_addresses(config_facts, port_name):
    """IP addresses (``addr/prefix``) configured on ``port_name``."""
    addrs = []
    for key, val in (config_facts.get("INTERFACE") or {}).items():
        if "|" in key:
            name, addr = key.split("|", 1)
            if name == port_name:
                addrs.append(addr)
        elif key == port_name and isinstance(val, dict):
            addrs.extend(a for a in val if "/" in a)
    return addrs


def _groups_with_member(table, port_name):
    """Names of the PORTCHANNEL_MEMBER / VLAN_MEMBER groups that contain ``port_name``."""
    groups = []
    for key, val in (table or {}).items():
        if "|" in key:
            group, member = key.split("|", 1)
            if member == port_name:
                groups.append(group)
        else:
            members = list(val.keys()) if isinstance(val, dict) else list(val or [])
            if port_name in members:
                groups.append(key)
    return groups


def _acl_tables_with_port(config_facts, port_name):
    """Names of the ACL_TABLE entries bound to ``port_name``."""
    tables = []
    for name, props in (config_facts.get("ACL_TABLE") or {}).items():
        ports = (props or {}).get("ports") or []
        if isinstance(ports, str):
            ports = [p.strip() for p in ports.split(",")]
        if port_name in ports:
            tables.append(name)
    return tables


def _portchannel_names(config_facts):
    return set(name.split("|", 1)[0] for name in (config_facts.get("PORTCHANNEL") or {}))


def _free_portchannel_name(preferred_index, used_names):
    """``PortChannel<preferred_index>`` when free, else the next free ``PortChannel<N>``."""
    index = preferred_index
    while "PortChannel{}".format(index) in used_names:
        index += 1
    return "PortChannel{}".format(index)


# Added for multi-asic support: DUT BGP ASN of an ASIC; DEVICE_METADATA of the ASIC, then of the host (per-ASIC
# config_db may lack bgp_asn), else DUT_AS_NUM.
def _resolve_dut_asn(dh, config_facts):
    asn = _asn_from_device_metadata(config_facts)
    if asn is None and dh.is_multi_asic:
        host_facts = dh.config_facts(host=dh.hostname, source="running")["ansible_facts"]
        asn = _asn_from_device_metadata(host_facts)
    return asn if asn is not None else DUT_AS_NUM


# Added for multi-asic support: describe the first ``port_count`` tgen_ports that are bound to an ACL table or are
# VLAN members on the ASIC owning them (empty list when all are usable). ``use_saved_config=True`` reads the saved
# config_db file of the ASIC (what a reboot will load, used before the DUT is touched); otherwise the running
# config is read. Read only: nothing is changed on the DUT.
def find_blocked_ports(duthost, tgen_ports, port_count, use_saved_config=False, facts_cache=None):
    cache = facts_cache if facts_cache is not None else {}
    blocked = []
    for i in range(0, port_count):
        port = tgen_ports[i]
        dh, asic = _resolve_port_context(duthost, port)
        if use_saved_config:
            asic_idx = asic.asic_index if dh.is_multi_asic else 0
            key = (dh.hostname, asic_idx, "saved")
            if key not in cache:
                cache[key] = get_config_db(dh, asic_idx)
            cfg = cache[key]
        else:
            cfg = _live_config_facts(dh, asic, cache)
        peer = port["peer_port"]
        acl_tables = _acl_tables_with_port(cfg, peer)
        vlans = _groups_with_member(cfg.get("VLAN_MEMBER"), peer)
        if acl_tables or vlans:
            blocked.append(
                "{}/{} (asic {}): ACL table(s) {}, VLAN(s) {}".format(
                    dh.hostname, peer, asic.asic_index, acl_tables or "none", vlans or "none"))
    return blocked


# Added for multi-asic support
def _run_vtysh_lines(asic_inst, lines):
    """Run vtysh with multiple -c arguments (configure / router bgp / ...)."""
    parts = []
    for line in lines:
        parts.append("-c '{}'".format(line))
    cmdstr = " ".join(parts)
    return asic_inst.run_vtysh(cmdstr)


# Added for multi-asic support: back up per-ASIC config_db of every DUT/ASIC used by the test ports
def _backup_config_before_bgp(duthost, tgen_ports, port_count):
    global _bgp_config_db_backups
    _bgp_config_db_backups = []
    targets = affected_setup_targets(tgen_ports, port_count, default_duthost=duthost)
    for dh in unique_duthosts_from_targets(targets):
        dh.command("sudo config save -y")
        indices = asic_indices_for_duthost(dh, targets)
        backup_config_dbs(dh, indices, backup_tag=BGP_HELPER_CONFIG_DB_BACKUP_TAG)
        _bgp_config_db_backups.append((dh, indices))


# Added for multi-asic support: DUT PortChannel + BGP config done per ASIC (used when
# --bgp_pc_config is NOT passed and the DUT is multi-asic, or the ports span several DUTs / line cards).
# It (1) reads the live config of each port's ASIC (DUT / peer ASNs, existing IPs, PortChannel membership) and
# stops with a message if a port is bound to an ACL table or is a VLAN member, (2) backs up the config_db,
# (3) frees the ports, (4) builds one PortChannel per port, (5) configures BGP with the resolved ASNs.
def _duthost_bgp_config_multi_asic(duthost, tgen_ports, port_count, route_type):
    global temp_tg_port
    temp_tg_port = tgen_ports

    # Step 1 (read only): live config of the ASIC owning every port. Resolve the DUT / peer ASNs and find out what
    # has to be removed from each port. Ports bound to ACL tables or in a VLAN are not handled: all of them are
    # reported at once, before anything is changed on the DUT.
    facts_cache = {}
    pc_names_in_use = {}
    port_plan = {}
    for i in range(0, port_count):
        port = tgen_ports[i]
        dh, asic = _resolve_port_context(duthost, port)
        cfg = _live_config_facts(dh, asic, facts_cache)
        peer = port["peer_port"]
        asic_key = (dh.hostname, asic.asic_index if dh.is_multi_asic else 0)
        pc_names_in_use.setdefault(asic_key, _portchannel_names(cfg))

        port[RESOLVED_DUT_ASN_KEY] = _resolve_dut_asn(dh, cfg)
        if i >= 1:
            if route_type == "IPv4":
                found_asn = _peer_asn_from_bgp_neighbors(cfg, port.get("peer_ip"), port.get("ip"))
            else:
                found_asn = _peer_asn_from_bgp_neighbors(cfg, port.get("peer_ipv6"), port.get("ipv6"))
            port[RESOLVED_PEER_ASN_KEY] = found_asn if found_asn is not None else TGEN_AS_NUM
            logger.info(
                "%s/%s: DUT ASN %s, peer ASN %s (%s)", dh.hostname, peer, port[RESOLVED_DUT_ASN_KEY],
                port[RESOLVED_PEER_ASN_KEY], "from DUT BGP config" if found_asn is not None else "default")

        port_plan[i] = {
            "ips": _interface_addresses(cfg, peer),
            "portchannels": _groups_with_member(cfg.get("PORTCHANNEL_MEMBER"), peer),
        }

    # Safety net: the test fixture already checks the saved config before the DUT is touched (same logic).
    blocked_ports = find_blocked_ports(duthost, tgen_ports, port_count, facts_cache=facts_cache)
    if blocked_ports:
        pytest.skip(
            "Test ports cannot be used while bound to an ACL table or a VLAN. Unbind / remove them on the DUT and "
            "re-run. Nothing was changed on the DUT. Affected ports:\n  {}".format("\n  ".join(blocked_ports)))

    # Step 2: back up the config_db (only once the ports are known to be usable)
    _backup_config_before_bgp(duthost, tgen_ports, port_count)

    # Step 3: free the ports (IPs and PortChannel membership)
    for i in range(0, port_count):
        port = tgen_ports[i]
        dh, asic = _resolve_port_context(duthost, port)
        peer = port["peer_port"]
        for addr in port_plan[i]["ips"]:
            asic.config_ip_intf(peer, addr, "remove")
        for pc in port_plan[i]["portchannels"]:
            asic.config_portchannel_member(pc, peer, "del")
        logger.info(
            "Freed %s (asic %s): removed IPs %s, PortChannel(s) %s",
            peer, asic.asic_index, port_plan[i]["ips"], port_plan[i]["portchannels"])

    # Step 4: one PortChannel per port with the test IPs
    for i in range(0, port_count):
        port = tgen_ports[i]
        dh, asic = _resolve_port_context(duthost, port)
        asic_key = (dh.hostname, asic.asic_index if dh.is_multi_asic else 0)
        pc = _free_portchannel_name(i + 1, pc_names_in_use[asic_key])
        pc_names_in_use[asic_key].add(pc)
        port["pc_name"] = pc
        member = port["peer_port"]
        asic.config_portchannel(pc, "add")
        asic.config_portchannel_member(pc, member, "add")
        asic.config_ip_intf(pc, "{}/{}".format(port["peer_ip"], port["prefix"]), "add")
        asic.config_ip_intf(pc, "{}/{}".format(port["peer_ipv6"], port["ipv6_prefix"]), "add")
        logger.info(
            "Configuring %s to %s with IPs %s,%s (asic %s)",
            member, pc, port["peer_ip"], port["peer_ipv6"], asic.asic_index,
        )

    neighbors_by_asic = defaultdict(list)
    for i in range(1, port_count):
        _dh, asic = _resolve_port_context(duthost, tgen_ports[i])
        neighbors_by_asic[(_dh, asic.asic_index)].append(i)

    for (dh, asic_index), neighbor_idxs in neighbors_by_asic.items():
        asic = dh.asic_instance(asic_index)
        dut_asn = tgen_ports[neighbor_idxs[0]][RESOLVED_DUT_ASN_KEY]
        max_paths = len(neighbor_idxs)
        _run_vtysh_lines(
            asic,
            [
                "configure terminal",
                "router bgp {}".format(dut_asn),
                "no bgp ebgp-requires-policy",
                "bgp bestpath as-path multipath-relax",
                "maximum-paths {}".format(max_paths),
                "exit",
            ],
        )
        if route_type == "IPv4":
            for i in neighbor_idxs:
                nbr = tgen_ports[i]["ip"]
                _run_vtysh_lines(
                    asic,
                    [
                        "configure terminal",
                        "router bgp {}".format(dut_asn),
                        "neighbor {} remote-as {}".format(nbr, tgen_ports[i][RESOLVED_PEER_ASN_KEY]),
                        "address-family ipv4 unicast",
                        "neighbor {} activate".format(nbr),
                        "exit",
                    ],
                )
                logger.info("Configuring BGP v4 Neighbor %s on asic %s", nbr, asic_index)
        else:
            for i in neighbor_idxs:
                nbr = tgen_ports[i]["ipv6"]
                _run_vtysh_lines(
                    asic,
                    [
                        "configure terminal",
                        "router bgp {}".format(dut_asn),
                        "neighbor {} remote-as {}".format(nbr, tgen_ports[i][RESOLVED_PEER_ASN_KEY]),
                        "address-family ipv6 unicast",
                        "neighbor {} activate".format(nbr),
                        "exit",
                    ],
                )
                logger.info("Configuring BGP v6 Neighbor %s on asic %s", nbr, asic_index)


def _asn_from_port_entry(port_entry, skip_duthost_bgp_config, fixture_keys, default):
    """
    When skip_duthost_bgp_config is True, prefer ASN from tgen_ports (dut_asn / peer_asn
    from config_facts, or optional DUT_AS_NUM / TGEN_AS_NUM keys); else use module default.
    """
    # Added for multi-asic support: ASN resolved from the DUT by _duthost_bgp_config_multi_asic (set only there)
    resolved_key = {"peer_asn": RESOLVED_PEER_ASN_KEY, "dut_asn": RESOLVED_DUT_ASN_KEY}.get(fixture_keys[0])
    if resolved_key and port_entry.get(resolved_key) is not None:
        return int(port_entry[resolved_key])
    if not skip_duthost_bgp_config:
        return int(default)
    for key in fixture_keys:
        val = port_entry.get(key)
        if val is not None:
            return int(val)
    return int(default)


def run_bgp_local_link_failover_test(snappi_api,
                                     duthost,
                                     tgen_ports,
                                     iteration,
                                     multipath,
                                     number_of_routes,
                                     route_type,):
    """
    Run Local link failover test

    Args:
        snappi_api (pytest fixture): snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        iteration: number of iterations for running convergence test on a port
        multipath: ecmp value for BGP config
        number_of_routes:  Number of IPv4/IPv6 Routes
        route_type: IPv4 or IPv6 routes
    """
    port_count = multipath+1

    """ Create bgp config on dut """
    duthost_bgp_config(duthost,
                       tgen_ports,
                       port_count,
                       route_type,)

    """ Create bgp config on TGEN """
    tgen_bgp_config = __tgen_bgp_config(snappi_api,
                                        port_count,
                                        number_of_routes,
                                        route_type,)

    """
        Run the convergence test by flapping all the rx
        links one by one and calculate the convergence values
    """
    get_convergence_for_local_link_failover(snappi_api,
                                            tgen_bgp_config,
                                            iteration,
                                            multipath,
                                            number_of_routes,
                                            route_type,)


def run_bgp_remote_link_failover_test(snappi_api,
                                      duthost,
                                      tgen_ports,
                                      iteration,
                                      multipath,
                                      number_of_routes,
                                      route_type,):
    """
    Run Remote link failover test

    Args:
        snappi_api (pytest fixture): snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        iteration: number of iterations for running convergence test on a port
        multipath: ecmp value for BGP config
        route_type: IPv4 or IPv6 routes
    """
    port_count = multipath+1
    """ Create bgp config on dut """
    duthost_bgp_config(duthost,
                       tgen_ports,
                       port_count,
                       route_type,)

    """ Create bgp config on TGEN """
    tgen_bgp_config = __tgen_bgp_config(snappi_api,
                                        port_count,
                                        number_of_routes,
                                        route_type,)

    """
        Run the convergence test by withdrawing all the route ranges
        one by one and calculate the convergence values
    """
    get_convergence_for_remote_link_failover(snappi_api,
                                             tgen_bgp_config,
                                             iteration,
                                             multipath,
                                             number_of_routes,
                                             route_type,)


def run_rib_in_convergence_test(snappi_api,
                                duthost,
                                tgen_ports,
                                iteration,
                                multipath,
                                number_of_routes,
                                route_type,
                                timeout=None,
                                skip_duthost_bgp_config=False,
                                mem_cpu_monitor=None,
                                tag_tier2_leak_communities=False,       # Added for multi-asic support
                                skip_cleanup=True,):                    # Added for multi-asic support
    """
    Run RIB-IN Convergence test

    Args:
        snappi_api (pytest fixture): snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        iteration: number of iterations for running convergence test on a port
        multipath: ecmp value for BGP config
        number_of_routes:  Number of IPv4/IPv6 Routes
        route_type: IPv4 or IPv6 routes
        timeout: optional timeout in seconds for convergence steps (default: TIMEOUT)
        skip_duthost_bgp_config: Use existing config from config_db to run test.
        mem_cpu_monitor: optional ``mem_cpu_monitor`` fixture; passed to
            :func:`get_rib_in_convergence` for snapshots around RIB-IN metrics, then a **60s** wait
            followed by ``stop()`` in that helper's ``finally`` block.
        tag_tier2_leak_communities: opt-in (multi-asic support); tag IXIA routes with the tier-2
            leak community when the DUT has UPSTREAM_PREFIX_DENY or is multi-asic.
        skip_cleanup: (multi-asic support) default True keeps the previous behaviour (no DUT config
            revert here). Pass False to revert the DUT config done by ``duthost_bgp_config``.
    """

    if timeout is None:
        timeout = TIMEOUT

    port_count = multipath+1

    """ Set global temp_tg_port for __tgen_bgp_config (used by tgen BGP config) """
    global temp_tg_port
    temp_tg_port = tgen_ports

    # Added for multi-asic support: tier-2 tagging is opt-in and reset on every call
    global _tag_tier2_leak_on_routes
    _tag_tier2_leak_on_routes = (
        _should_tag_tier2_leak_communities(duthost, tgen_ports, port_count)
        if tag_tier2_leak_communities else False)

    """ Create bgp config on dut """
    if not skip_duthost_bgp_config:
        duthost_bgp_config(duthost,
                           tgen_ports,
                           port_count,
                           route_type,)

    """  Create bgp config on TGEN """
    tgen_bgp_config = __tgen_bgp_config(snappi_api,
                                        port_count,
                                        number_of_routes,
                                        route_type,
                                        skip_duthost_bgp_config=skip_duthost_bgp_config,)

    """
        Run the convergence test by withdrawing all routes at once and
        calculate the convergence values
    """
    get_rib_in_convergence(snappi_api,
                           tgen_bgp_config,
                           iteration,
                           multipath,
                           number_of_routes,
                           route_type,
                           timeout,
                           mem_cpu_monitor=mem_cpu_monitor,)

    # Added for multi-asic support: optional revert of DUT config done by duthost_bgp_config
    if not skip_cleanup:
        cleanup_config(duthost)


def run_RIB_IN_capacity_test(snappi_api,
                             duthost,
                             tgen_ports,
                             multipath,
                             start_value,
                             step_value,
                             route_type,):
    """
    Run RIB-IN Capacity test

    Args:
        snappi_api (pytest fixture): snappi API
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        multipath: ecmp value for BGP config
        start_value: start value of number of routes
        step_value: step value of routes to be incremented at every iteration
        route_type: IPv4 or IPv6 routes
    """
    port_count = multipath+1
    """ Create bgp config on dut """
    duthost_bgp_config(duthost,
                       tgen_ports,
                       port_count,
                       route_type,)

    """ Run the RIB-IN capacity test by increasig the route count step by step """
    get_RIB_IN_capacity(snappi_api,
                        multipath,
                        start_value,
                        step_value,
                        route_type,)


def duthost_bgp_config(duthost,
                       tgen_ports,
                       port_count,
                       route_type,):
    """
    Configures BGP on the DUT with N-1 ecmp

    Args:
        duthost (pytest fixture): duthost fixture
        tgen_ports (pytest fixture): Ports mapping info of T0 testbed
        port_count:multipath + 1
        multipath: ECMP value for BGP config
        route_type: IPv4 or IPv6 routes
    """
    # Added for multi-asic support: per-ASIC configuration path (single-asic flow below is unchanged). Also used
    # when tgen_ports were planned per ASIC (ports spread over several DUTs / line cards).
    if duthost.is_multi_asic or any(p.get("multi_asic_flow") for p in tgen_ports):
        _duthost_bgp_config_multi_asic(duthost, tgen_ports, port_count, route_type)
        return

    global temp_tg_port
    temp_tg_port = tgen_ports
    for i in range(0, port_count):
        intf_config = (
            "sudo config interface ip remove %s %s/%s \n"
            "sudo config interface ip remove %s %s/%s \n"
        )
        intf_config %= (tgen_ports[i]['peer_port'], tgen_ports[i]['peer_ip'], tgen_ports[i]['prefix'],
                        tgen_ports[i]['peer_port'], tgen_ports[i]['peer_ipv6'], tgen_ports[i]['ipv6_prefix'])
        logger.info('Removing configured IP and IPv6 Address from %s' %
                    (tgen_ports[i]['peer_port']))
        duthost.shell(intf_config)

    for i in range(0, port_count):
        portchannel_config = (
            "sudo config portchannel add PortChannel%s \n"
            "sudo config portchannel member add PortChannel%s %s\n"
            "sudo config interface ip add PortChannel%s %s/%s\n"
            "sudo config interface ip add PortChannel%s %s/%s\n"
        )
        portchannel_config %= (i+1, i+1, tgen_ports[i]['peer_port'], i+1, tgen_ports[i]
                               ['peer_ip'], tgen_ports[i]['prefix'], i+1, tgen_ports[i]['peer_ipv6'],
                               tgen_ports[i]['ipv6_prefix'])
        logger.info('Configuring %s to PortChannel%s with IPs %s,%s' % (
            tgen_ports[i]['peer_port'], i+1, tgen_ports[i]['peer_ip'], tgen_ports[i]['peer_ipv6']))
        duthost.shell(portchannel_config)
    bgp_config = (
        "vtysh "
        "-c 'configure terminal' "
        "-c 'router bgp %s' "
        "-c 'no bgp ebgp-requires-policy' "
        "-c 'bgp bestpath as-path multipath-relax' "
        "-c 'maximum-paths %s' "
        "-c 'exit' "
    )
    bgp_config %= (DUT_AS_NUM, port_count-1)
    duthost.shell(bgp_config)
    if route_type == 'IPv4':
        for i in range(1, port_count):
            bgp_config_neighbor = (
                "vtysh "
                "-c 'configure terminal' "
                "-c 'router bgp %s' "
                "-c 'neighbor %s remote-as %s' "
                "-c 'address-family ipv4 unicast' "
                "-c 'neighbor %s activate' "
                "-c 'exit' "
            )
            bgp_config_neighbor %= (
                DUT_AS_NUM, tgen_ports[i]['ip'], TGEN_AS_NUM, tgen_ports[i]['ip'])
            logger.info('Configuring BGP v4 Neighbor %s' % tgen_ports[i]['ip'])
            duthost.shell(bgp_config_neighbor)
    else:
        for i in range(1, port_count):
            bgp_config_neighbor = (
                "vtysh "
                "-c 'configure terminal' "
                "-c 'router bgp %s' "
                "-c 'neighbor %s remote-as %s' "
                "-c 'address-family ipv6 unicast' "
                "-c 'neighbor %s activate' "
                "-c 'exit' "
            )
            bgp_config_neighbor %= (
                DUT_AS_NUM, tgen_ports[i]['ipv6'], TGEN_AS_NUM, tgen_ports[i]['ipv6'])
            logger.info('Configuring BGP v6 Neighbor %s' %
                        tgen_ports[i]['ipv6'])
            duthost.shell(bgp_config_neighbor)


def __tgen_bgp_config(snappi_api,
                      port_count,
                      number_of_routes,
                      route_type,
                      skip_duthost_bgp_config=False,):
    """
    Creating  BGP config on TGEN

    Args:
        snappi_api (pytest fixture): snappi API
        port_count: multipath + 1
        number_of_routes:  Number of IPv4/IPv6 Routes
        route_type: IPv4 or IPv6 routes
        skip_duthost_bgp_config: boolean (true) if DUT is preconfigured
    """
    global NG_LIST  # noqa: F824
    config = snappi_api.config()

    if skip_duthost_bgp_config and port_count > 0:
        ref_dut_as = _asn_from_port_entry(
            temp_tg_port[0], True, ('dut_asn', 'DUT_AS_NUM'), DUT_AS_NUM)
        for idx in range(1, port_count):
            other = _asn_from_port_entry(
                temp_tg_port[idx], True, ('dut_asn', 'DUT_AS_NUM'), DUT_AS_NUM)
            pytest_assert(
                other == ref_dut_as,
                'tgen_ports dut_asn mismatch: index 0 has {}, index {} has {}'.format(
                    ref_dut_as, idx, other))
        logger.info(
            'TGEN BGP: DUT AS %s from tgen_ports (dut_asn / default); '
            'emulated BGP as_number per peer from peer_asn / TGEN_AS_NUM',
            ref_dut_as)

    for i in range(1, port_count+1):
        config.ports.port(name='Test_Port_%d' %
                          i, location=temp_tg_port[i-1]['location'])
        c_lag = config.lags.lag(name="lag%d" % i)[-1]
        lp = c_lag.ports.port(port_name='Test_Port_%d' % i)[-1]
        lp.ethernet.name = 'lag_eth_%d' % i
        if len(str(hex(i).split('0x')[1])) == 1:
            m = '0'+hex(i).split('0x')[1]
        else:
            m = hex(i).split('0x')[1]
        c_lag.protocol.lacp.actor_system_id = "00:10:00:00:00:%s" % m
        c_lag.protocol.lacp.actor_system_priority = int(1)
        c_lag.protocol.lacp.actor_key = int(1)
        lp.ethernet.name = "lag_Ethernet %s" % i
        lp.ethernet.mac = "00:10:01:00:00:%s" % m
        lp.lacp.actor_port_number = int(1)
        lp.lacp.actor_port_priority = int(1)
        config.devices.device(name='Topology %d' % i)

    config.options.port_options.location_preemption = True
    for index, port_data in enumerate(temp_tg_port[:port_count]):
        layer1 = config.layer1.layer1()[-1]
        layer1.name = f"{index}_settings"
        layer1.port_names = [config.ports[index].name]
        layer1.speed = port_data['speed']
        layer1.ieee_media_defaults = False
        layer1.auto_negotiation.rs_fec = port_data.get('fec', False)
        layer1.auto_negotiation.link_training = port_data.get('link_training', False)
        layer1.speed = port_data['speed']
        layer1.auto_negotiate = port_data.get('autoneg', False)

    def create_v4_topo():
        eth = config.devices[0].ethernets.add()
        eth.connection.lag_name = config.lags[0].name
        eth.name = 'Ethernet 1'
        eth.mac = "00:00:00:00:00:01"
        ipv4 = eth.ipv4_addresses.add()
        ipv4.name = 'IPv4 1'
        ipv4.address = temp_tg_port[0]['ip']
        ipv4.gateway = temp_tg_port[0]['peer_ip']
        ipv4.prefix = int(temp_tg_port[0]['prefix'])
        tx_flow_name = [ipv4.name]
        rx_flow_names = []
        for i in range(2, port_count+1):
            NG_LIST.append('Network_Group%s' % i)
            if len(str(hex(i).split('0x')[1])) == 1:
                m = '0'+hex(i).split('0x')[1]
            else:
                m = hex(i).split('0x')[1]

            ethernet_stack = config.devices[i-1].ethernets.add()
            ethernet_stack.connection.lag_name = config.lags[i-1].name
            ethernet_stack.name = 'Ethernet %d' % i
            ethernet_stack.mac = "00:00:00:00:00:%s" % m
            ipv4_stack = ethernet_stack.ipv4_addresses.add()
            ipv4_stack.name = 'IPv4 %d' % i
            ipv4_stack.address = temp_tg_port[i-1]['ip']
            ipv4_stack.gateway = temp_tg_port[i-1]['peer_ip']
            ipv4_stack.prefix = int(temp_tg_port[i-1]['prefix'])
            bgpv4 = config.devices[i-1].bgp
            bgpv4.router_id = temp_tg_port[i-1]['peer_ip']
            bgpv4_int = bgpv4.ipv4_interfaces.add()
            bgpv4_int.ipv4_name = ipv4_stack.name
            bgpv4_peer = bgpv4_int.peers.add()
            bgpv4_peer.name = 'BGP %d' % i
            bgpv4_peer.as_type = BGP_TYPE
            bgpv4_peer.peer_address = temp_tg_port[i-1]['peer_ip']
            bgpv4_peer.as_number = _asn_from_port_entry(
                temp_tg_port[i-1], skip_duthost_bgp_config,
                ('peer_asn', 'TGEN_AS_NUM'), TGEN_AS_NUM)
            route_range = bgpv4_peer.v4_routes.add(name=NG_LIST[-1])
            route_range.addresses.add(
                address='200.1.0.1', prefix=32, count=number_of_routes)
            as_path = route_range.as_path
            as_path_segment = as_path.segments.add()
            as_path_segment.type = as_path_segment.AS_SEQ
            as_path_segment.as_numbers = aspaths
            _apply_tier2_leak_communities(route_range)      # Added for multi-asic support
            rx_flow_names.append(route_range.name)
        return (tx_flow_name, rx_flow_names)

    def create_v6_topo():
        eth = config.devices[0].ethernets.add()
        eth.connection.lag_name = config.lags[0].name
        eth.name = 'Ethernet 1'
        eth.mac = "00:00:00:00:00:01"
        ipv6 = eth.ipv6_addresses.add()
        ipv6.name = 'IPv6 1'
        ipv6.address = temp_tg_port[0]['ipv6']
        ipv6.gateway = temp_tg_port[0]['peer_ipv6']
        ipv6.prefix = int(temp_tg_port[0]['ipv6_prefix'])
        tx_flow_name = [ipv6.name]
        rx_flow_names = []
        for i in range(2, port_count+1):
            NG_LIST.append('Network_Group%s' % i)
            if len(str(hex(i).split('0x')[1])) == 1:
                m = '0'+hex(i).split('0x')[1]
            else:
                m = hex(i).split('0x')[1]
            ethernet_stack = config.devices[i-1].ethernets.add()
            ethernet_stack.connection.lag_name = config.lags[i-1].name
            ethernet_stack.name = 'Ethernet %d' % i
            ethernet_stack.mac = "00:00:00:00:00:%s" % m
            ipv6_stack = ethernet_stack.ipv6_addresses.add()
            ipv6_stack.name = 'IPv6 %d' % i
            ipv6_stack.address = temp_tg_port[i-1]['ipv6']
            ipv6_stack.gateway = temp_tg_port[i-1]['peer_ipv6']
            ipv6_stack.prefix = int(temp_tg_port[i-1]['ipv6_prefix'])

            bgpv6 = config.devices[i-1].bgp
            bgpv6.router_id = temp_tg_port[i-1]['peer_ip']
            bgpv6_int = bgpv6.ipv6_interfaces.add()
            bgpv6_int.ipv6_name = ipv6_stack.name
            bgpv6_peer = bgpv6_int.peers.add()
            bgpv6_peer.name = 'BGP+_%d' % i
            bgpv6_peer.as_type = BGP_TYPE
            bgpv6_peer.peer_address = temp_tg_port[i-1]['peer_ipv6']
            bgpv6_peer.as_number = _asn_from_port_entry(
                temp_tg_port[i-1], skip_duthost_bgp_config,
                ('peer_asn', 'TGEN_AS_NUM'), TGEN_AS_NUM)
            route_range = bgpv6_peer.v6_routes.add(name=NG_LIST[-1])
            route_range.addresses.add(
                address='3000::1', prefix=64, count=number_of_routes)
            as_path = route_range.as_path
            as_path_segment = as_path.segments.add()
            as_path_segment.type = as_path_segment.AS_SEQ
            as_path_segment.as_numbers = aspaths
            _apply_tier2_leak_communities(route_range)      # Added for multi-asic support
            rx_flow_names.append(route_range.name)
        return (tx_flow_name, rx_flow_names)

    def create_v4v6_topo():
        """Create topology with 125k IPv4 and 125k IPv6 routes (250k total)."""
        num_v4 = number_of_routes // 2
        num_v6 = number_of_routes - num_v4
        eth = config.devices[0].ethernets.add()
        eth.connection.port_name = config.lags[0].name
        eth.name = 'Ethernet 1'
        eth.mac = "00:00:00:00:00:01"
        ipv4 = eth.ipv4_addresses.add()
        ipv4.name = 'IPv4 1'
        ipv4.address = temp_tg_port[0]['ip']
        ipv4.gateway = temp_tg_port[0]['peer_ip']
        ipv4.prefix = int(temp_tg_port[0]['prefix'])
        ipv6 = eth.ipv6_addresses.add()
        ipv6.name = 'IPv6 1'
        ipv6.address = temp_tg_port[0]['ipv6']
        ipv6.gateway = temp_tg_port[0]['peer_ipv6']
        ipv6.prefix = int(temp_tg_port[0]['ipv6_prefix'])
        v4_tx_flow_name = [ipv4.name]
        v6_tx_flow_name = [ipv6.name]
        v4_rx_flow_names = []
        v6_rx_flow_names = []
        for i in range(2, port_count+1):
            NG_LIST.append('Network_Group_v4_%s' % i)
            if len(str(hex(i).split('0x')[1])) == 1:
                m = '0'+hex(i).split('0x')[1]
            else:
                m = hex(i).split('0x')[1]
            ethernet_stack = config.devices[i-1].ethernets.add()
            ethernet_stack.connection.port_name = config.lags[i-1].name
            ethernet_stack.name = 'Ethernet %d' % i
            ethernet_stack.mac = "00:00:00:00:00:%s" % m
            ipv4_stack = ethernet_stack.ipv4_addresses.add()
            ipv4_stack.name = 'IPv4 %d' % i
            ipv4_stack.address = temp_tg_port[i-1]['ip']
            ipv4_stack.gateway = temp_tg_port[i-1]['peer_ip']
            ipv4_stack.prefix = int(temp_tg_port[i-1]['prefix'])
            ipv6_stack = ethernet_stack.ipv6_addresses.add()
            ipv6_stack.name = 'IPv6 %d' % i
            ipv6_stack.address = temp_tg_port[i-1]['ipv6']
            ipv6_stack.gateway = temp_tg_port[i-1]['peer_ipv6']
            ipv6_stack.prefix = int(temp_tg_port[i-1]['ipv6_prefix'])
            bgpv4 = config.devices[i-1].bgp
            bgpv4.router_id = temp_tg_port[i-1]['peer_ip']
            bgpv4_int = bgpv4.ipv4_interfaces.add()
            bgpv4_int.ipv4_name = ipv4_stack.name
            bgpv4_peer = bgpv4_int.peers.add()
            bgpv4_peer.name = 'BGP %d' % i
            bgpv4_peer.as_type = BGP_TYPE
            bgpv4_peer.peer_address = temp_tg_port[i-1]['peer_ip']
            bgpv4_peer.as_number = _asn_from_port_entry(
                temp_tg_port[i-1], skip_duthost_bgp_config,
                ('peer_asn', 'TGEN_AS_NUM'), TGEN_AS_NUM)
            route_range_v4 = bgpv4_peer.v4_routes.add(name=NG_LIST[-1])
            route_range_v4.addresses.add(
                address='200.1.0.1', prefix=32, count=num_v4)
            as_path_v4 = route_range_v4.as_path
            as_path_segment_v4 = as_path_v4.segments.add()
            as_path_segment_v4.type = as_path_segment_v4.AS_SEQ
            as_path_segment_v4.as_numbers = aspaths
            v4_rx_flow_names.append(route_range_v4.name)

            NG_LIST.append('Network_Group_v6_%s' % i)
            bgpv6 = config.devices[i-1].bgp
            bgpv6_int = bgpv6.ipv6_interfaces.add()
            bgpv6_int.ipv6_name = ipv6_stack.name
            bgpv6_peer = bgpv6_int.peers.add()
            bgpv6_peer.name = 'BGP+_%d' % i
            bgpv6_peer.as_type = BGP_TYPE
            bgpv6_peer.peer_address = temp_tg_port[i-1]['peer_ipv6']
            bgpv6_peer.as_number = _asn_from_port_entry(
                temp_tg_port[i-1], skip_duthost_bgp_config,
                ('peer_asn', 'TGEN_AS_NUM'), TGEN_AS_NUM)
            route_range_v6 = bgpv6_peer.v6_routes.add(name=NG_LIST[-1])
            route_range_v6.addresses.add(
                address='3000::1', prefix=64, count=num_v6)
            as_path_v6 = route_range_v6.as_path
            as_path_segment_v6 = as_path_v6.segments.add()
            as_path_segment_v6.type = as_path_segment_v6.AS_SEQ
            as_path_segment_v6.as_numbers = aspaths
            v6_rx_flow_names.append(route_range_v6.name)
        return (v4_tx_flow_name, v6_tx_flow_name, v4_rx_flow_names, v6_rx_flow_names)

    def createTrafficItem(traffic_name, src, dest, rate):
        flow1 = config.flows.flow(name=str(traffic_name))[-1]
        flow1.tx_rx.device.tx_names = src
        flow1.tx_rx.device.rx_names = dest
        flow1.size.fixed = 1024
        flow1.rate.percentage = rate
        flow1.metrics.enable = True
        flow1.metrics.loss = True

    if route_type == 'IPv4':
        tx_flow, rx_flow = create_v4_topo()
        createTrafficItem("IPv4 Traffic", tx_flow, rx_flow, 100)
    elif route_type == 'IPv6':
        tx_flow, rx_flow = create_v6_topo()
        createTrafficItem("IPv6 Traffic", tx_flow, rx_flow, 100)
    elif route_type == 'IPv4v6':
        v4_tx_flow, v6_tx_flow, v4_rx_flow, v6_rx_flow = create_v4v6_topo()
        createTrafficItem("IPv4 Traffic", v4_tx_flow, v4_rx_flow, 50)
        createTrafficItem("IPv6 Traffic", v6_tx_flow, v6_rx_flow, 50)
    else:
        raise Exception('Invalid route type given')
    return config


def get_flow_stats(snappi_api):
    """
    Args:
        snappi_api (pytest fixture): Snappi API
    """
    req = snappi_api.metrics_request()
    req.flow.flow_names = []
    return snappi_api.get_metrics(req).flow_metrics


def get_convergence_for_local_link_failover(snappi_api,
                                            bgp_config,
                                            iteration,
                                            multipath,
                                            number_of_routes,
                                            route_type,):
    """
    Args:
        snappi_api (pytest fixture): snappi API
        bgp_config: __tgen_bgp_config
        config: TGEN config
        iteration: number of iterations for running convergence test on a port
        number_of_routes:  Number of IPv4/IPv6 Routes
        route_type: IPv4 or IPv6 routes
    """
    rx_port_names = []
    for i in range(1, len(bgp_config.ports)):
        rx_port_names.append(bgp_config.ports[i].name)
    bgp_config.events.cp_events.enable = True
    bgp_config.events.dp_events.enable = True
    bgp_config.events.dp_events.rx_rate_threshold = 90/(multipath-1)
    snappi_api.set_config(bgp_config)
    """ Starting Protocols """
    logger.info("Starting all protocols ...")
    cs = snappi_api.control_state()
    cs.protocol.all.state = cs.protocol.all.START
    snappi_api.set_control_state(cs)
    wait(TIMEOUT, "For Protocols To start")

    def get_avg_dpdp_convergence_time(port_name):

        """
        Args:
            port_name: Name of the port
        """

        table, avg, tx_frate, rx_frate, avg_delta = [], [], [], [], []
        for i in range(0, iteration):
            logger.info(
                '|---- {} Link Flap Iteration : {} ----|'.format(port_name, i+1))

            """ Starting Traffic """
            logger.info('Starting Traffic')
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
            snappi_api.set_control_state(cs)
            wait(TIMEOUT, "For Traffic To start")
            flow_stats = get_flow_stats(snappi_api)
            tx_frame_rate = flow_stats[0].frames_tx_rate
            assert tx_frame_rate != 0, "Traffic has not started"
            """ Flapping Link """
            logger.info('Simulating Link Failure on {} link'.format(port_name))
            cs.choice = cs.PORT
            cs.port.choice = cs.port.LINK
            cs.port.link.port_names = [port_name]
            cs.port.link.state = cs.port.link.DOWN
            snappi_api.set_control_state(cs)
            wait(TIMEOUT, "For Link to go down")
            flows = get_flow_stats(snappi_api)
            for flow in flows:
                tx_frate.append(flow.frames_tx_rate)
                rx_frate.append(flow.frames_rx_rate)
            assert abs(sum(tx_frate) - sum(rx_frate)) / sum(rx_frate) < 0.00002, \
                "Traffic has not converged after link flap: TxFrameRate:{},RxFrameRate:{}"\
                .format(sum(tx_frate), sum(rx_frate))
            logger.info("Traffic has converged after link flap")
            """ Get control plane to data plane convergence value """
            request = snappi_api.metrics_request()
            request.convergence.flow_names = []
            convergence_metrics = snappi_api.get_metrics(request).convergence_metrics
            for metrics in convergence_metrics:
                logger.info('CP/DP Convergence Time (ms): {}'.format(
                    metrics.control_plane_data_plane_convergence_us/1000))
            avg.append(
                int(metrics.control_plane_data_plane_convergence_us/1000))
            avg_delta.append(int(flows[0].frames_tx)-int(flows[0].frames_rx))
            """ Performing link up at the end of iteration """
            logger.info(
                'Simulating Link Up on {} at the end of iteration {}'.format(port_name, i+1))
            cs.choice = cs.PORT
            cs.port.choice = cs.port.LINK
            cs.port.link.port_names = [port_name]
            cs.port.link.state = cs.port.link.UP
            snappi_api.set_control_state(cs)
            logger.info('Stopping Traffic')
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
            snappi_api.set_control_state(cs)
            wait(TIMEOUT-10, "For Traffic To Stop")
        table.append('%s Link Failure' % port_name)
        table.append(route_type)
        table.append(number_of_routes)
        table.append(iteration)
        table.append(mean(avg_delta))
        table.append(mean(avg))
        return table
    table = []
    """ Iterating link flap test on all the rx ports """
    for i, port_name in enumerate(rx_port_names):
        table.append(get_avg_dpdp_convergence_time(port_name))
    columns = ['Event Name', 'Route Type', 'No. of Routes', 'Iterations',
               'Delta Frames', 'Avg Calculated Data Convergence Time (ms)']
    logger.info("\n%s" % tabulate(table, headers=columns, tablefmt="psql"))


def get_convergence_for_remote_link_failover(snappi_api,
                                             bgp_config,
                                             iteration,
                                             multipath,
                                             number_of_routes,
                                             route_type,):
    """
    Args:
        snappi_api (pytest fixture): snappi API
        bgp_config: __tgen_bgp_config
        config: TGEN config
        iteration: number of iterations for running convergence test on a port
        number_of_routes:  Number of IPv4/IPv6 Routes
        route_type: IPv4 or IPv6 routes
    """
    route_names = NG_LIST
    bgp_config.events.cp_events.enable = True
    bgp_config.events.dp_events.enable = True
    bgp_config.events.dp_events.rx_rate_threshold = 90/(multipath-1)
    snappi_api.set_config(bgp_config)

    def get_avg_cpdp_convergence_time(route_name):
        """
        Args:
            route_name: name of the route

        """
        table, avg, tx_frate, rx_frate, avg_delta = [], [], [], [], []
        """ Starting Protocols """
        logger.info("Starting all protocols ...")
        cs = snappi_api.control_state()
        cs.protocol.all.state = cs.protocol.all.START
        snappi_api.set_control_state(cs)
        wait(TIMEOUT, "For Protocols To start")
        for i in range(0, iteration):
            logger.info(
                '|---- {} Route Withdraw Iteration : {} ----|'.format(route_name, i+1))
            """ Starting Traffic """
            logger.info('Starting Traffic')
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
            snappi_api.set_control_state(cs)
            wait(TIMEOUT, "For Traffic To start")
            flow_stats = get_flow_stats(snappi_api)
            tx_frame_rate = flow_stats[0].frames_tx_rate
            assert tx_frame_rate != 0, "Traffic has not started"

            """ Withdrawing routes from a BGP peer """
            logger.info('Withdrawing Routes from {}'.format(route_name))
            cs = snappi_api.control_state()
            cs.protocol.route.state = cs.protocol.route.WITHDRAW
            cs.protocol.route.names = [route_name]
            snappi_api.set_control_state(cs)
            wait(TIMEOUT, "For routes to be withdrawn")
            flows = get_flow_stats(snappi_api)
            for flow in flows:
                tx_frate.append(flow.frames_tx_rate)
                rx_frate.append(flow.frames_rx_rate)
            assert abs(sum(tx_frate) - sum(rx_frate)) / sum(rx_frate) < 0.00002, \
                "Traffic has not converged after route withdraw TxFrameRate:{},RxFrameRate:{}"\
                .format(sum(tx_frate), sum(rx_frate))
            logger.info("Traffic has converged after route withdraw")

            """ Get control plane to data plane convergence value """
            request = snappi_api.metrics_request()
            request.convergence.flow_names = []
            convergence_metrics = snappi_api.get_metrics(request).convergence_metrics
            for metrics in convergence_metrics:
                logger.info('CP/DP Convergence Time (ms): {}'.format(
                    metrics.control_plane_data_plane_convergence_us/1000))
            avg.append(
                int(metrics.control_plane_data_plane_convergence_us/1000))
            avg_delta.append(int(flows[0].frames_tx)-int(flows[0].frames_rx))
            """ Advertise the routes back at the end of iteration """
            cs = snappi_api.control_state()
            cs.protocol.route.state = cs.protocol.route.ADVERTISE
            cs.protocol.route.names = [route_name]
            snappi_api.set_control_state(cs)
            logger.info('Readvertise {} routes back at the end of iteration {}'.format(
                route_name, i+1))
            logger.info('Stopping Traffic')
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
            snappi_api.set_control_state(cs)
            wait(TIMEOUT, "For Traffic To Stop")
        table.append('%s route withdraw' % route_name)
        table.append(route_type)
        table.append(number_of_routes)
        table.append(iteration)
        table.append(mean(avg_delta))
        table.append(mean(avg))
        return table
    table = []
    """ Iterating route withdrawal on all BGP peers """
    for route in route_names:
        table.append(get_avg_cpdp_convergence_time(route))

    columns = ['Event Name', 'Route Type', 'No. of Routes', 'Iterations',
               'Frames Delta', 'Avg Control to Data Plane Convergence Time (ms)']
    logger.info("\n%s" % tabulate(table, headers=columns, tablefmt="psql"))


def get_rib_in_convergence(snappi_api,
                           bgp_config,
                           iteration,
                           multipath,
                           number_of_routes,
                           route_type,
                           timeout=None,
                           mem_cpu_monitor=None):
    """
    Args:
        snappi_api (pytest fixture): snappi API
        bgp_config: __tgen_bgp_config
        config: TGEN config
        iteration: number of iterations for running convergence test on a port
        number_of_routes:  Number of IPv4/IPv6/IPv4v6 Routes
        route_type: IPv4 or IPv6 or IPv4v6 routes
        timeout: timeout for route withdraw and advertisement.
        mem_cpu_monitor: optional controller from ``mem_cpu_monitor`` fixture; when set,
            records snapshots around RIB-IN convergence, then in ``finally`` waits
            ``MEM_CPU_MONITOR_RIB_IN_POST_SUCCESS_SEC`` before ``stop()`` if all iterations
            completed successfully, else ``MEM_CPU_MONITOR_RIB_IN_POST_FAILURE_SEC`` (pair with
            ``start()`` in the test).
    """
    if timeout is not None:
        TIMEOUT = timeout

    global NG_LIST
    route_names = NG_LIST
    logger.info('Route list:{}'.format(route_names))
    bgp_config.events.cp_events.enable = True
    bgp_config.events.dp_events.enable = True
    bgp_config.events.dp_events.rx_rate_threshold = 90/multipath
    snappi_api.set_config(bgp_config)
    # Outstanding sonic-mgmt issue 23744.
    logger.info('Setting AS-SEQ manually via restPy')
    ix = snappi_api._ixnetwork

    for topo in ix.Topology.find():
        for dg in topo.DeviceGroup.find():
            for ng in dg.NetworkGroup.find():
                for ipp in ng.Ipv4PrefixPools.find():
                    for bgp_prop in ipp.BgpIPRouteProperty.find():
                        for seg in bgp_prop.BgpAsPathSegmentList.find():
                            seg.SegmentType.Single('asseq')
                for ipp in ng.Ipv6PrefixPools.find():
                    for bgp_prop in ipp.BgpV6IPRouteProperty.find():
                        for seg in bgp_prop.BgpAsPathSegmentList.find():
                            seg.SegmentType.Single('asseq')

    table, avg, tx_frate, rx_frate, avg_delta = [], [], [], [], []
    rib_in_all_iterations_completed = False
    try:
        for i in range(0, iteration):
            logger.info(
                '|---- RIB-IN Convergence test, Iteration : {} ----|'.format(i+1))
            """ withdraw all routes before starting traffic """
            logger.info('Withdraw All Routes before starting traffic')
            cs = snappi_api.control_state()
            cs.protocol.route.names = route_names
            cs.protocol.route.state = cs.protocol.route.WITHDRAW
            snappi_api.set_control_state(cs)
            if mem_cpu_monitor is not None:
                mem_cpu_monitor.snapshot(
                    event="Route_Withdrawal_started_iter_{}".format(i + 1))
            wait(TIMEOUT, "For Routes to be withdrawn")
            """ Starting Protocols """
            logger.info("Starting all protocols ...")
            cs = snappi_api.control_state()
            cs.protocol.all.state = cs.protocol.all.START
            snappi_api.set_control_state(cs)
            if mem_cpu_monitor is not None:
                mem_cpu_monitor.snapshot(
                    event="Protocols_started_iter_{}".format(i + 1))
            wait(WAIT_INTERVAL, "For Protocols To start")
            """ Start Traffic """
            logger.info('Starting Traffic')
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
            snappi_api.set_control_state(cs)
            wait(WAIT_INTERVAL, "For Traffic To start")
            flow_stats = get_flow_stats(snappi_api)
            tx_frame_rate = flow_stats[0].frames_tx_rate
            rx_frame_rate = flow_stats[0].frames_rx_rate
            assert tx_frame_rate != 0, "Traffic has not started"
            assert rx_frame_rate == 0

            """ Advertise All Routes """
            logger.info('Advertising all Routes from {}'.format(route_names))
            if mem_cpu_monitor is not None:
                mem_cpu_monitor.snapshot(
                    event="Before_route_advertise_iter_{}".format(i + 1))
            cs = snappi_api.control_state()
            cs.protocol.route.names = route_names
            cs.protocol.route.state = cs.protocol.route.ADVERTISE
            snappi_api.set_control_state(cs)
            wait(TIMEOUT, "For all routes to be ADVERTISED")
            if mem_cpu_monitor is not None:
                mem_cpu_monitor.snapshot(
                    event="After_route_advertise_iter_{}".format(i + 1))
            flows = get_flow_stats(snappi_api)
            for flow in flows:
                tx_frate.append(flow.frames_tx_rate)
                rx_frate.append(flow.frames_rx_rate)
            assert abs(sum(tx_frate) - sum(rx_frate)) / sum(rx_frate) < 0.00002, \
                "Traffic has not converged, TxFrameRate:{},RxFrameRate:{}"\
                .format(sum(tx_frate), sum(rx_frate))
            logger.info("Traffic has converged after route advertisement")

            """ Get RIB-IN convergence """
            request = snappi_api.metrics_request()
            request.convergence.flow_names = []
            convergence_metrics = snappi_api.get_metrics(request).convergence_metrics
            for metrics in convergence_metrics:
                logger.info('RIB-IN Convergence time (ms): {}'.format(
                    metrics.control_plane_data_plane_convergence_us/1000))
            avg.append(int(metrics.control_plane_data_plane_convergence_us/1000))
            avg_delta.append(int(flows[0].frames_tx)-int(flows[0].frames_rx))
            """ Stop traffic at the end of iteration """
            logger.info('Stopping Traffic at the end of iteration{}'.format(i+1))
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
            if mem_cpu_monitor is not None:
                mem_cpu_monitor.snapshot(
                    event="After_traffic_stop_metrics_iter_{}".format(i + 1))
            snappi_api.set_control_state(cs)
            wait(WAIT_INTERVAL, "For Traffic To stop")
            """ Stopping Protocols """
            logger.info("Stopping all protocols ...")
            cs = snappi_api.control_state()
            cs.protocol.all.state = cs.protocol.all.STOP
            snappi_api.set_control_state(cs)
            wait(WAIT_INTERVAL, "For Protocols To STOP")
            if mem_cpu_monitor is not None:
                mem_cpu_monitor.snapshot(
                    event="After_protocol_stop_iter_{}".format(i + 1))
        # Only after every iteration body finishes without raising.
        rib_in_all_iterations_completed = iteration > 0
    finally:
        if mem_cpu_monitor is not None:
            try:
                if rib_in_all_iterations_completed:
                    delay = MEM_CPU_MONITOR_RIB_IN_POST_SUCCESS_SEC
                    reason = "all iterations completed"
                else:
                    delay = MEM_CPU_MONITOR_RIB_IN_POST_FAILURE_SEC
                    reason = "early exit or failure"
                if delay > 0:
                    logger.info(
                        "mem_cpu_monitor: waiting %ss before stop() for post-convergence sampling (%s)",
                        delay,
                        reason,
                    )
                    time.sleep(delay)
                mem_cpu_monitor.stop()
            except Exception:
                logger.exception("mem_cpu_monitor teardown after RIB-IN convergence")
    table.append('Advertise All BGP Routes')
    table.append(route_type)
    table.append(number_of_routes)
    table.append(iteration)
    table.append(mean(avg_delta))
    table.append(mean(avg))
    NG_LIST = []
    columns = ['Event Name', 'Route Type', 'No. of Routes',
               'Iterations', 'Frames Delta', 'Avg RIB-IN Convergence Time(ms)']
    logger.info("\n%s" % tabulate([table], headers=columns, tablefmt="psql"))


def get_RIB_IN_capacity(snappi_api,
                        multipath,
                        start_value,
                        step_value,
                        route_type,):
    """
    Args:
        snappi_api (pytest fixture): snappi API
        temp_tg_port (pytest fixture): Ports mapping info of T0 testbed
        multipath: ecmp value for BGP config
        start_value:  Start value of the number of BGP routes
        step_value: Step value of the number of BGP routes to be incremented
        route_type: IPv4 or IPv6 routes
    """
    def tgen_capacity(routes):
        config = snappi_api.config()
        config.events.cp_events.enable = True
        config.events.dp_events.enable = True
        config.events.dp_events.rx_rate_threshold = 90/(multipath-1)
        for i in range(1, 3):
            config.ports.port(name='Test_Port_%d' %
                              i, location=temp_tg_port[i-1]['location'])
            c_lag = config.lags.lag(name="lag%d" % i)[-1]
            lp = c_lag.ports.port(port_name='Test_Port_%d' % i)[-1]
            lp.ethernet.name = 'lag_eth_%d' % i
            if len(str(hex(i).split('0x')[1])) == 1:
                m = '0'+hex(i).split('0x')[1]
            else:
                m = hex(i).split('0x')[1]
            c_lag.protocol.lacp.actor_system_id = "00:10:00:00:00:%s" % m
            lp.ethernet.name = "lag_Ethernet %s" % i
            lp.ethernet.mac = "00:10:01:00:00:%s" % m
            config.devices.device(name='Topology %d' % i)

        config.options.port_options.location_preemption = True
        for index, port_data in enumerate(temp_tg_port):
            layer1 = config.layer1.layer1()[-1]
            layer1.name = f"{index}_settings"
            layer1.port_names = [config.ports[index].name]
            layer1.speed = port_data['speed']
            layer1.ieee_media_defaults = False
            layer1.auto_negotiation.rs_fec = port_data.get('fec', False)
            layer1.auto_negotiation.link_training = port_data.get('link_training', False)
            layer1.speed = port_data['speed']
            layer1.auto_negotiate = port_data.get('autoneg', False)

        def create_v4_topo():
            eth = config.devices[0].ethernets.add()
            eth.connection.lag_name = config.lags[0].name
            eth.name = 'Ethernet 1'
            eth.mac = "00:00:00:00:00:01"
            ipv4 = eth.ipv4_addresses.add()
            ipv4.name = 'IPv4 1'
            ipv4.address = temp_tg_port[0]['ip']
            ipv4.gateway = temp_tg_port[0]['peer_ip']
            ipv4.prefix = int(temp_tg_port[0]['prefix'])
            tx_flow_name = [ipv4.name]
            rx_flow_name = []
            for i in range(2, 3):
                if len(str(hex(i).split('0x')[1])) == 1:
                    m = '0'+hex(i).split('0x')[1]
                else:
                    m = hex(i).split('0x')[1]
                ethernet_stack = config.devices[i-1].ethernets.add()
                ethernet_stack.connection.lag_name = config.lags[i-1].name
                ethernet_stack.name = 'Ethernet %d' % i
                ethernet_stack.mac = "00:00:00:00:00:%s" % m
                ipv4_stack = ethernet_stack.ipv4_addresses.add()
                ipv4_stack.name = 'IPv4 %d' % i
                ipv4_stack.address = temp_tg_port[i-1]['ip']
                ipv4_stack.gateway = temp_tg_port[i-1]['peer_ip']
                ipv4_stack.prefix = int(temp_tg_port[i-1]['prefix'])
                bgpv4 = config.devices[i-1].bgp
                bgpv4.router_id = temp_tg_port[i-1]['peer_ip']
                bgpv4_int = bgpv4.ipv4_interfaces.add()
                bgpv4_int.ipv4_name = ipv4_stack.name
                bgpv4_peer = bgpv4_int.peers.add()
                bgpv4_peer.name = 'BGP %d' % i
                bgpv4_peer.as_type = BGP_TYPE
                bgpv4_peer.peer_address = temp_tg_port[i-1]['peer_ip']
                bgpv4_peer.as_number = int(TGEN_AS_NUM)
                route_range = bgpv4_peer.v4_routes.add(
                    name="Network_Group%d" % i)
                route_range.addresses.add(
                    address='200.1.0.1', prefix=32, count=routes)
                as_path = route_range.as_path
                as_path_segment = as_path.segments.add()
                as_path_segment.type = as_path_segment.AS_SEQ
                as_path_segment.as_numbers = aspaths
                rx_flow_name.append(route_range.name)
            return tx_flow_name, rx_flow_name

        def create_v6_topo():
            eth = config.devices[0].ethernets.add()
            eth.connection.lag_name = config.lags[0].name
            eth.name = 'Ethernet 1'
            eth.mac = "00:00:00:00:00:01"
            ipv6 = eth.ipv6_addresses.add()
            ipv6.name = 'IPv6 1'
            ipv6.address = temp_tg_port[0]['ipv6']
            ipv6.gateway = temp_tg_port[0]['peer_ipv6']
            ipv6.prefix = int(temp_tg_port[0]['ipv6_prefix'])
            tx_flow_name = [ipv6.name]
            rx_flow_name = []
            for i in range(2, 3):
                if len(str(hex(i).split('0x')[1])) == 1:
                    m = '0'+hex(i).split('0x')[1]
                else:
                    m = hex(i).split('0x')[1]
                ethernet_stack = config.devices[i-1].ethernets.add()
                ethernet_stack.connection.lag_name = config.lags[i-1].name
                ethernet_stack.name = 'Ethernet %d' % i
                ethernet_stack.mac = "00:00:00:00:00:%s" % m
                ipv6_stack = ethernet_stack.ipv6_addresses.add()
                ipv6_stack.name = 'IPv6 %d' % i
                ipv6_stack.address = temp_tg_port[i-1]['ipv6']
                ipv6_stack.gateway = temp_tg_port[i-1]['peer_ipv6']
                ipv6_stack.prefix = int(temp_tg_port[i-1]['ipv6_prefix'])

                bgpv6 = config.devices[i-1].bgp
                bgpv6.router_id = temp_tg_port[i-1]['peer_ip']
                bgpv6_int = bgpv6.ipv6_interfaces.add()
                bgpv6_int.ipv6_name = ipv6_stack.name
                bgpv6_peer = bgpv6_int.peers.add()
                bgpv6_peer.name = 'BGP+_%d' % i
                bgpv6_peer.as_type = BGP_TYPE
                bgpv6_peer.peer_address = temp_tg_port[i-1]['peer_ipv6']
                bgpv6_peer.as_number = int(TGEN_AS_NUM)
                route_range = bgpv6_peer.v6_routes.add(
                    name="Network Group %d" % i)
                route_range.addresses.add(
                    address='3000::1', prefix=64, count=routes)
                as_path = route_range.as_path
                as_path_segment = as_path.segments.add()
                as_path_segment.type = as_path_segment.AS_SEQ
                as_path_segment.as_numbers = aspaths
                rx_flow_name.append(route_range.name)
            return tx_flow_name, rx_flow_name

        def create_traffic_item(traffic_name, src, dest, rate):
            flow1 = config.flows.flow(name=str(traffic_name))[-1]
            flow1.tx_rx.device.tx_names = src
            flow1.tx_rx.device.rx_names = dest
            flow1.size.fixed = 1024
            flow1.rate.percentage = rate
            flow1.metrics.enable = True
            flow1.metrics.loss = True

        if route_type == 'IPv4':
            tx_flow, rx_flows = create_v4_topo()
            create_traffic_item('IPv4_Traffic_%d' % routes, tx_flow, rx_flows, 100)
        elif route_type == 'IPv6':
            tx_flow, rx_flows = create_v6_topo()
            create_traffic_item('IPv6_Traffic_%d' % routes, tx_flow, rx_flows, 100)
        else:
            raise Exception('Invalid route type given')
        return config

    def run_traffic(routes):
        logger.info(
            '|-------------------- RIB-IN Capacity test, No.of Routes : {} ----|'.format(routes))
        conv_config = tgen_capacity(routes)
        snappi_api.set_config(conv_config)
        """ Starting Protocols """
        logger.info("Starting all protocols ...")
        cs = snappi_api.control_state()
        cs.protocol.all.state = cs.protocol.all.START
        snappi_api.set_control_state(cs)
        wait(TIMEOUT, "For Protocols To start")
        """ Starting Traffic """
        logger.info('Starting Traffic')
        cs = snappi_api.control_state()
        cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.START
        snappi_api.set_control_state(cs)
        wait(TIMEOUT, "For Traffic To start")

    try:
        max_routes = 0
        for j in range(start_value, 100000000000, step_value):
            tx_frate, rx_frate = [], []
            run_traffic(j)
            flow_stats = get_flow_stats(snappi_api)
            logger.info('\n')
            logger.info('Loss% : {}'.format(flow_stats[0].loss))
            for flow in flow_stats:
                tx_frate.append(flow.frames_tx_rate)
                rx_frate.append(flow.frames_rx_rate)
            logger.info("Tx Frame Rate : {}".format(tx_frate))
            logger.info("Rx Frame Rate : {}".format(rx_frate))
            logger.info('\n')
            if float(flow_stats[0].loss) > 0.001:
                if j == start_value:
                    raise Exception(
                        'Traffic Loss Encountered in first iteration, reduce the start value and run the test')
                logger.info('Loss greater than 0.001 occured')
                logger.info('Reducing the routes and running test')
                b = j-step_value
                logger.info('Stopping Traffic')
                cs = snappi_api.control_state()
                cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
                snappi_api.set_control_state(cs)
                wait(TIMEOUT-20, "For Traffic To stop")
                break
            max_routes = j
            logger.info('Stopping Traffic')
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
            snappi_api.set_control_state(cs)
            wait(TIMEOUT-20, "For Traffic To stop")
        routes = []
        routes.append(b+int(step_value/8))
        routes.append(b+int(step_value/4))
        routes.append(b+int(step_value/2))
        routes.append(b+step_value-int(step_value/4))
        routes.append(b+step_value-int(step_value/8))
        for i in range(0, len(routes)):
            run_traffic(routes[i])
            flow_stats = get_flow_stats(snappi_api)
            logger.info('Loss% : {}'.format(flow_stats[0].loss))
            if float(flow_stats[0].loss) <= 0.001:
                max_routes = routes[i]
                pass
            else:
                max_routes = routes[i]-int(step_value/8)
                break
            logger.info('Stopping Traffic')
            cs = snappi_api.control_state()
            cs.traffic.flow_transmit.state = cs.traffic.flow_transmit.STOP
            snappi_api.set_control_state(cs)
            wait(TIMEOUT, "For Traffic To stop")
            """ Stopping Protocols """
            logger.info("Stopping all protocols ...")
            cs = snappi_api.control_state()
            cs.protocol.all.state = cs.protocol.all.STOP
            snappi_api.set_control_state(cs)
            wait(TIMEOUT, "For Protocols To STOP")
    except Exception as e:
        logger.info(e)
    finally:
        columns = ['Test Name', 'Maximum no. of Routes']
        logger.info("\n%s" % tabulate(
            [['RIB-IN Capacity Test', max_routes]], headers=columns, tablefmt="psql"))


# Added for multi-asic support: opt-in revert of the per-ASIC config_db backed up by
# _duthost_bgp_config_multi_asic (used via run_rib_in_convergence_test(skip_cleanup=False)).
# The single-asic flow of duthost_bgp_config is unchanged and takes no backup, so nothing to revert there.
def cleanup_config(duthost):
    """
    Cleaning up dut config at the end of the test (multi-asic only)

    Args:
        duthost (pytest fixture): duthost fixture
    """
    global _bgp_config_db_backups
    if _bgp_config_db_backups:      # Added for multi-asic support: also set for single-asic DUTs of a multi-DUT run
        for dh, indices in _bgp_config_db_backups:
            rib_revert_config_db(dh, indices, backup_tag=BGP_HELPER_CONFIG_DB_BACKUP_TAG)
        _bgp_config_db_backups = []
        logger.info('Convergence Test Completed')
        return
    logger.info('cleanup_config: no multi-asic config_db backup to revert')
