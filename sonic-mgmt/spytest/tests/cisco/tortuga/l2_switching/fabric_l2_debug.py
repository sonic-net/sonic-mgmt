"""Tortuga fabric L2 debug snapshots (VLAN/MAC/NPU/interface counters, BVI/SVI helpers).

Lives alongside tortuga L2 tests under ``l2_switching/`` (not ``common/``).
``bin/spytest`` adds this directory to ``sys.path`` so ``from fabric_l2_debug import ...`` works.

Tests gate instrumentation with :func:`fabric_l2_debug_enabled` at the call site::

    fabric_dbg = fabric_l2_debug_enabled(vars=vars)
    all_duts = fabric_snapshot_duts(vars) if fabric_dbg else []
    if fabric_dbg:
        fabric_snapshot_pre_traffic_state(all_duts, log_tag="...")
    # ... traffic ...
    if fabric_dbg:
        fabric_snapshot_post_traffic_npu(all_duts, log_tag="...")
        fabric_wait_counterpoll_interface_refresh(10)
        fabric_snapshot_post_traffic_counters(vars)

:func:`fabric_post_traffic_counter_snapshot` bundles NPU + counterpoll wait + interface counters
for failure paths (optional shortcut; same steps as ``test_native_vlan`` post-traffic block).

On **BVI SVI** config-unconfig failures, call :func:`fabric_failure_bvi_svi_with_counters`
(after ``if fabric_dbg:``) to log CONFIG_DB/SVI/neighbors and then interface/NPU counters.

:func:`fabric_failure_bvi_svi_with_counters` also enables **extended L2 path diagnostics**: full ``show mac``,
per-VLAN ``show mac address-table``, stream-MAC greps, ``show interfaces status`` on resolved path ports,
port-channel summary, IPv6 neighbor samples, and APP_DB FDB key listing.
"""

from spytest import st
import apis.system.basic as basic_obj

# Substring match on basic.show_version(dut)['version'] - must match c-master images only.
_FABRIC_L2_DEBUG_VERSION_SUBSTRING = "c-master"


def _sonic_image_is_c_master(dut):
    ver = basic_obj.show_version(dut, report=False) or {}
    vstr = ver.get("version") or ""
    if not vstr:
        return False
    return _FABRIC_L2_DEBUG_VERSION_SUBSTRING in vstr


def _fabric_l2_debug_reference_dut(vars):
    if vars is None:
        return None
    for name in ("D1", "D2", "D3", "D4"):
        d = getattr(vars, name, None)
        if d is not None:
            return d
    dl = getattr(vars, "dut_list", None) or []
    return dl[0] if dl else None


def fabric_l2_debug_enabled(dut=None, vars=None):
    """
    Return True if fabric L2 debug snapshots should run (c-master image on reference DUT).
    """
    if dut is None:
        dut = _fabric_l2_debug_reference_dut(vars)
    if not dut:
        return False

    return _sonic_image_is_c_master(dut)


def _fabric_resolved_duts(vars, role_names=("D1", "D2", "D3", "D4")):
    out = []
    for n in role_names:
        d = getattr(vars, n, None)
        if d is not None:
            out.append(d)
    return out


def fabric_snapshot_duts(vars, role_names=("D1", "D2", "D3", "D4")):
    return _fabric_resolved_duts(vars, role_names)


def _fabric_port_list(vars, *names):
    return [getattr(vars, n) for n in names if getattr(vars, n, None) is not None]


def fabric_default_port_map(vars):
    m = {}
    mapping = [
        (getattr(vars, "D4", None), ("D4T1P1", "D4D1P1", "D4D2P1")),
        (getattr(vars, "D1", None), ("D1D3P1", "D1D4P1")),
        (getattr(vars, "D2", None), ("D2D3P1", "D2D4P1")),
        (getattr(vars, "D3", None), ("D3T1P1", "D3D1P1", "D3D2P1")),
    ]
    for dut, name_tuple in mapping:
        if dut is not None:
            m[dut] = _fabric_port_list(vars, *name_tuple)
    return m


def fabric_default_node_labels(vars):
    m = {}
    for dut, label in (
        (getattr(vars, "D4", None), "leaf1  (D4)"),
        (getattr(vars, "D1", None), "spine0 (D1)"),
        (getattr(vars, "D2", None), "spine1 (D2)"),
        (getattr(vars, "D3", None), "leaf0  (D3)"),
    ):
        if dut is not None:
            m[dut] = label
    return m


def fabric_default_counter_dut_order(vars):
    return [
        d
        for d in (
            getattr(vars, "D4", None),
            getattr(vars, "D1", None),
            getattr(vars, "D2", None),
            getattr(vars, "D3", None),
        )
        if d is not None
    ]


def fabric_snapshot_pre_traffic_state(duts, log_tag="Pre-traffic state"):
    st.log("DEBUG: {}".format(log_tag))
    for dut in duts:
        st.show(dut, "show vlan brief", skip_tmpl=True)
        st.show(dut, "show mac", skip_tmpl=True)
        st.show(dut, "sudo show platform npu counters", skip_tmpl=True, skip_error_check=True)


def fabric_snapshot_post_traffic_npu(duts, log_tag="Post-traffic NPU counters"):
    st.log("DEBUG: {}".format(log_tag))
    for dut in duts:
        if dut is None:
            continue
        st.show(dut, "sudo show platform npu counters", skip_tmpl=True, skip_error_check=True)


def fabric_wait_counterpoll_interface_refresh(seconds=10):
    st.wait(
        seconds,
        "Waiting for counterpoll to refresh DUT interface counters",
    )


def fabric_log_bounded_traffic_snapshot(
    handles,
    d3t1port,
    d4t1port,
    data_l2_side,
    _data_l3_side,
    log_tag,
):
    """
    Log aggregate TGEN tx/rx and |tx-rx| for both directions (bounded traffic).

    Mirrors the accounting used in ``tortuga_common_utils.traffic_test_check``; read-only.
    Threshold is taken from ``data_l2_side.tgen_stats_threshold`` only (same as ``traffic_test_check`` data1).
    """
    h1 = handles.get("tg_handle_1")
    h2 = handles.get("tg_handle_2")
    ph1 = handles.get("port_handle_1")
    ph2 = handles.get("port_handle_2")
    if not all([h1, h2, ph1, ph2]):
        st.log("{} fabric_log_bounded_traffic_snapshot: incomplete handles".format(log_tag))
        return
    try:
        s1 = h1.tg_traffic_stats(port_handle=ph1, mode="aggregate")
        s2 = h2.tg_traffic_stats(port_handle=ph2, mode="aggregate")
        t1_tx = int(s1[ph1]["aggregate"]["tx"]["total_pkts"])
        t1_rx = int(s1[ph1]["aggregate"]["rx"]["total_pkts"])
        t2_tx = int(s2[ph2]["aggregate"]["tx"]["total_pkts"])
        t2_rx = int(s2[ph2]["aggregate"]["rx"]["total_pkts"])
    except Exception as ex:
        st.log("{} fabric_log_bounded_traffic_snapshot: stats failed: {}".format(log_tag, ex))
        return

    # ``traffic_test_check`` compares both directions against ``data1.tgen_stats_threshold`` only.
    thr = getattr(data_l2_side, "tgen_stats_threshold", None)
    st.banner("{} | TGEN bounded | {} <-> {}".format(log_tag, d3t1port, d4t1port))
    st.log(
        "{} TGEN {} tx={} rx={} | {} tx={} rx={}".format(
            log_tag,
            d3t1port,
            t1_tx,
            t1_rx,
            d4t1port,
            t2_tx,
            t2_rx,
        )
    )
    d_fwd = abs(t1_tx - t2_rx)
    d_rev = abs(t2_tx - t1_rx)
    fail_fwd = d_fwd > int(thr) if thr is not None else None
    fail_rev = d_rev > int(thr) if thr is not None else None
    st.log(
        "{} |{}_tx-{}_rx|={} fail_if_gt_thr={} | |{}_tx-{}_rx|={} fail_if_gt_thr={} | thr(data1)={}".format(
            log_tag,
            d3t1port,
            d4t1port,
            d_fwd,
            fail_fwd,
            d4t1port,
            d3t1port,
            d_rev,
            fail_rev,
            thr,
        )
    )


def fabric_post_traffic_counter_snapshot(vars, log_tag="Post-traffic fabric snapshot", node_ports=None):
    """
    NPU counters, counterpoll wait, then ``show interfaces counters`` (+ detail + RIF).

    For failure paths after a traffic burst. Call only when :func:`fabric_l2_debug_enabled`.
    Pass ``node_ports`` to override the default fabric port map (e.g. extra uplinks).
    """
    duts = fabric_snapshot_duts(vars)
    fabric_snapshot_post_traffic_npu(duts, log_tag=log_tag)
    fabric_wait_counterpoll_interface_refresh(10)
    fabric_snapshot_post_traffic_counters(vars, node_ports=node_ports)


def fabric_snapshot_post_traffic_counters(
    vars,
    dut_order=None,
    node_ports=None,
    node_labels=None,
):
    if dut_order is None:
        dut_order = fabric_default_counter_dut_order(vars)
    if node_ports is None:
        node_ports = fabric_default_port_map(vars)
    if node_labels is None:
        node_labels = fabric_default_node_labels(vars)

    for dut in dut_order:
        if dut is None:
            continue
        ports = node_ports.get(dut) or []
        label = node_labels.get(dut, str(dut))
        st.log("DEBUG: {} post-traffic counters".format(label))
        st.show(dut, "show interfaces counters", skip_tmpl=True, skip_error_check=True)
        for port in ports:
            st.show(
                dut,
                "show interfaces counters detailed {}".format(port),
                skip_tmpl=True,
                skip_error_check=True,
            )
        st.show(dut, "show interfaces counters rif", skip_tmpl=True, skip_error_check=True)


# --- BVI: SVI CONFIG_DB + L3 neighbors (for SVI flap / config-unconfig failure debug) ---


def _fabric_bvi_show(dut, description, command):
    st.log("[BVI dbg] {}".format(description))
    st.show(dut, command, skip_tmpl=True, skip_error_check=True)


def fabric_bvi_log_pre_second_l2_l3_burst(data_glob, data_vid_10, data_l3, log_tag):
    """
    After SVI remove/re-add, before the second L2<->L3 burst: stream parameters + SVI/ARP snapshot.

    Runs lightweight ``show`` only (always safe); complements fabric NPU/counter snapshots when enabled.
    """
    st.banner(log_tag)
    vintf = None
    vlan_ip = None
    if data_glob is not None and getattr(data_glob, "vlan_intf", None):
        vintf = data_glob.vlan_intf[0]
    if data_glob is not None and getattr(data_glob, "vlan_ip", None):
        vlan_ip = data_glob.vlan_ip[0]
    st.log(
        "{} stream: vlan={} vintf={} svi_cidr={} | VLAN leg {} ({}) | L3 TGen {} ({}) | "
        "vid10 burst={} mode={} pps={} thr={} | l3 burst={} mode={} pps={} thr={}".format(
            log_tag,
            getattr(data_vid_10, "vlan", "?"),
            vintf,
            vlan_ip,
            getattr(data_vid_10, "t1d3_ip_addr", "?"),
            getattr(data_vid_10, "t1d3_mac_addr", "?"),
            getattr(data_l3, "t1d4_ip_addr", "?"),
            getattr(data_l3, "t1d4_mac_addr", "?"),
            getattr(data_vid_10, "pkts_per_burst", "?"),
            getattr(data_vid_10, "transmit_mode", "?"),
            getattr(data_vid_10, "tgen_rate_pps", "?"),
            getattr(data_vid_10, "tgen_stats_threshold", "?"),
            getattr(data_l3, "pkts_per_burst", "?"),
            getattr(data_l3, "transmit_mode", "?"),
            getattr(data_l3, "tgen_rate_pps", "?"),
            getattr(data_l3, "tgen_stats_threshold", "?"),
        )
    )
    leaf0 = getattr(data_glob, "leaf0", None) if data_glob else None
    leaf1 = getattr(data_glob, "leaf1", None) if data_glob else None
    if leaf0:
        _fabric_bvi_show(
            leaf0,
            "leaf0 SVI after flap (full show ip interfaces)",
            "show ip interfaces",
        )
    if leaf0:
        _fabric_bvi_show(
            leaf0,
            "leaf0 ARP table (full show arp)",
            "show arp",
        )
    if leaf1:
        _fabric_bvi_show(
            leaf1,
            "leaf1 ARP table (full show arp)",
            "show arp",
        )


def _fabric_bvi_resolve_path_ports(vars, data_glob):
    """
    Resolve spine0 / leaf0 / leaf1 to interconnect + TGen ports from vars, plus Po members when present.
    """
    rows = []
    if vars is None or data_glob is None:
        return rows

    def _collect(dut, label, var_port_names, extra_member_lists):
        if dut is None:
            return
        ports = []
        seen = set()
        for n in var_port_names:
            p = getattr(vars, n, None)
            if p and p not in seen:
                seen.add(p)
                ports.append(p)
        for lst in extra_member_lists:
            if not lst:
                continue
            for p in lst:
                if p and p not in seen:
                    seen.add(p)
                    ports.append(p)
        rows.append((dut, ports, label))

    m1 = getattr(data_glob, "members_dut1", None) or []
    m2 = getattr(data_glob, "members_dut2", None) or []
    _collect(
        getattr(data_glob, "spine0", None),
        "spine0",
        ("D1D3P1", "D1D3P2", "D1D4P1", "D1D4P2"),
        [m1],
    )
    _collect(
        getattr(data_glob, "leaf0", None),
        "leaf0",
        ("D3D1P1", "D3D1P2", "D3D2P1", "D3D4P1", "D3T1P1"),
        [m2],
    )
    _collect(
        getattr(data_glob, "leaf1", None),
        "leaf1",
        ("D4D1P1", "D4D1P2", "D4D2P1", "D4D3P1", "D4T1P1"),
        [],
    )
    return rows


def _fabric_bvi_stream_macs(data_vid_10):
    """MACs used by Tortuga BVI streams (deduped) for FDB greps."""
    out = []
    seen = set()
    if not data_vid_10:
        return out
    for key in (
        "t1d3_mac_addr",
        "t1d4_mac_addr",
        "t1d3_mac_addr_mac_move",
        "t1d3_dest_mac_addr",
        "t1d4_dest_mac_addr",
    ):
        val = getattr(data_vid_10, key, None)
        if val and isinstance(val, str) and val not in seen:
            seen.add(val)
            out.append(val)
    return out


def _fabric_bvi_ipv6_neigh_grep(data_glob):
    """Loose grep for Tortuga-style ULA used in vlan_ipv6."""
    if data_glob and getattr(data_glob, "vlan_ipv6", None):
        parts = []
        for cidr in data_glob.vlan_ipv6:
            if not cidr:
                continue
            addr = cidr.split("/")[0].strip()
            if "::" in addr:
                prefix = addr.split("::", 1)[0]
            else:
                segs = addr.split(":")
                prefix = ":".join(segs[:3]) if len(segs) >= 3 else addr
            if prefix and prefix not in parts:
                parts.append(prefix.replace(":", r"\:"))
        if parts:
            return "|".join(parts)
    return r"100\:0\:1|100\:0\:2"


def _fabric_bvi_extended_l2_path_diag(phase_label, vars, data_glob, vlan_id, data_vid_10):
    """
    Extra failure-only context: MAC/FDB, link status on path ports, Po, v6 neigh, APP_DB FDB.
    """
    st.banner("BVI extended L2 path | {}".format(phase_label))
    vlan_s = str(vlan_id)
    stream_macs = _fabric_bvi_stream_macs(data_vid_10)
    v6_pat = _fabric_bvi_ipv6_neigh_grep(data_glob)
    pcn = getattr(data_glob, "portchannel_name", None) if data_glob else None

    for dut, ports, label in _fabric_bvi_resolve_path_ports(vars, data_glob):
        _fabric_bvi_show(dut, "{} show mac (full FDB)".format(label), "show mac")
        _fabric_bvi_show(
            dut,
            "{} show mac address-table vlan {}".format(label, vlan_s),
            "show mac address-table vlan {}".format(vlan_s),
        )
        for mac in stream_macs:
            safe = mac.replace('"', '\\"')
            _fabric_bvi_show(
                dut,
                '{} show mac | match "{}"'.format(label, mac),
                'show mac | grep -i "{}"'.format(safe),
            )
        _fabric_bvi_show(
            dut,
            "{} show interfaces status (summary)".format(label),
            "show interfaces status",
        )
        for port in ports:
            _fabric_bvi_show(
                dut,
                "{} show interfaces status {}".format(label, port),
                "show interfaces status {}".format(port),
            )
        if pcn:
            _fabric_bvi_show(
                dut,
                "{} show portchannel {}".format(label, pcn),
                "show portchannel {}".format(pcn),
            )
        _fabric_bvi_show(
            dut,
            "{} ip -6 neigh (test prefixes)".format(label),
            "ip -6 neigh show 2>/dev/null | grep -E '{}' || true".format(v6_pat),
        )
        _fabric_bvi_show(
            dut,
            "{} show ipv6 neighbors (test prefixes)".format(label),
            "show ipv6 neighbors 2>/dev/null | grep -E '{}' || true".format(v6_pat),
        )
        _fabric_bvi_show(
            dut,
            "{} APP_DB FDB_TABLE*Vlan{}*".format(label, vlan_s),
            "sudo redis-cli -n 0 KEYS 'FDB_TABLE*Vlan{}*' 2>/dev/null | head -n 120 || true".format(
                vlan_s
            ),
        )
        try:
            kcmd = "sudo redis-cli -n 0 KEYS 'FDB_TABLE*Vlan{}*' 2>/dev/null | head -n 1".format(vlan_s)
            kraw = st.show(dut, kcmd, skip_tmpl=True, skip_error_check=True) or ""
            first_key = ""
            for line in kraw.splitlines():
                t = line.strip()
                if t:
                    first_key = t
                    break
            if first_key:
                st.log("[BVI dbg] {} APP_DB HGETALL {}".format(label, first_key))
                sk = first_key.replace("'", "'\\''")
                st.show(
                    dut,
                    "sudo redis-cli -n 0 HGETALL '{}'".format(sk),
                    skip_tmpl=True,
                    skip_error_check=True,
                )
            else:
                st.log("[BVI dbg] {} (no FDB_TABLE key for vlan {})".format(label, vlan_s))
        except Exception as ex:
            st.log("BVI APP_DB FDB HGETALL: {}".format(ex))
        _fabric_bvi_show(
            dut,
            "{} dmesg tail".format(label),
            "dmesg 2>/dev/null | tail -n 20 || true",
        )


def fabric_snapshot_bvi_svi_configdb_neighbors(
    phase_label,
    leaf0,
    leaf1,
    spine0,
    vlan_id,
    vintf,
    vlan_cidr,
    include_l3_arp=False,
    l3_tgen_ip=None,
    diag_vars=None,
    diag_data_glob=None,
    diag_stream_vid=None,
):
    """
    ``show vlan``, CONFIG_DB ``VLAN*`` / ``VLAN_INTERFACE*``, full ``show ip interfaces``,
    ``ip neigh show``, full ``show arp``, optional ARP API for L3 TGen IP.

    When ``diag_vars``, ``diag_data_glob``, and ``diag_stream_vid`` are all set (as in
    :func:`fabric_failure_bvi_svi_with_counters`), append extended MAC/link/FDB diagnostics.
    """
    st.banner("BVI SVI CONFIG_DB+neighbors | {}".format(phase_label))
    for dut, label in ((leaf0, "leaf0"), (leaf1, "leaf1"), (spine0, "spine0")):
        if dut is None:
            continue
        _fabric_bvi_show(dut, "{} show vlan id {}".format(label, vlan_id), "show vlan id {}".format(vlan_id))

    if leaf0 is not None:
        _fabric_bvi_show(
            leaf0,
            "leaf0 CONFIG_DB keys VLAN_INTERFACE|Vlan{}*".format(vlan_id),
            "redis-cli -n 4 keys 'VLAN_INTERFACE|Vlan{}*'".format(vlan_id),
        )
        _fabric_bvi_show(
            leaf0,
            "leaf0 CONFIG_DB hgetall VLAN_INTERFACE|{}|{}".format(vintf, vlan_cidr),
            "redis-cli -n 4 hgetall 'VLAN_INTERFACE|{}|{}'".format(vintf, vlan_cidr),
        )
        _fabric_bvi_show(
            leaf0,
            "leaf0 CONFIG_DB hgetall VLAN|{}".format(vintf),
            "redis-cli -n 4 hgetall 'VLAN|{}'".format(vintf),
        )

    for dut, label in ((leaf0, "leaf0"), (leaf1, "leaf1")):
        if dut is None:
            continue
        _fabric_bvi_show(
            dut,
            "{} show ip interfaces (full)".format(label),
            "show ip interfaces",
        )

    for dut, label in ((leaf0, "leaf0"), (leaf1, "leaf1"), (spine0, "spine0")):
        if dut is None:
            continue
        _fabric_bvi_show(
            dut,
            "{} ip neigh (full)".format(label),
            "ip neigh show",
        )
        _fabric_bvi_show(
            dut,
            "{} show arp (full)".format(label),
            "show arp",
        )

    if include_l3_arp and l3_tgen_ip:
        import apis.routing.arp as arp_obj

        for dut, label in ((leaf0, "leaf0"), (leaf1, "leaf1")):
            if dut is None:
                continue
            st.log("[BVI dbg] {} ARP API L3 TGen {}".format(label, l3_tgen_ip))
            try:
                arp_obj.show_arp(dut, ipaddress=l3_tgen_ip)
            except Exception as ex:
                st.log("fabric_snapshot_bvi_svi_configdb_neighbors arp: {}".format(ex))

    if (
        diag_vars is not None
        and diag_data_glob is not None
        and diag_stream_vid is not None
    ):
        _fabric_bvi_extended_l2_path_diag(
            phase_label,
            diag_vars,
            diag_data_glob,
            vlan_id,
            diag_stream_vid,
        )


def fabric_failure_bvi_svi_with_counters(
    vars,
    log_tag,
    data_glob,
    data_vid_10,
    include_l3_arp=False,
    data_l3=None,
):
    """
    BVI SVI/CONFIG_DB/neighbor snapshot for vlan10 SVI on leaf0, then counter snapshot.

    Pass ``data_l3`` and ``include_l3_arp=True`` for L2/L3 tests (uses ``data_l3.t1d4_ip_addr``).
    """
    vintf = data_glob.vlan_intf[0]
    vlan_cidr = data_glob.vlan_ip[0]
    l3_ip = None
    if include_l3_arp and data_l3 is not None:
        l3_ip = getattr(data_l3, "t1d4_ip_addr", None)

    fabric_snapshot_bvi_svi_configdb_neighbors(
        log_tag,
        data_glob.leaf0,
        data_glob.leaf1,
        data_glob.spine0,
        data_vid_10.vlan,
        vintf,
        vlan_cidr,
        include_l3_arp=bool(l3_ip),
        l3_tgen_ip=l3_ip,
        diag_vars=vars,
        diag_data_glob=data_glob,
        diag_stream_vid=data_vid_10,
    )
    fabric_post_traffic_counter_snapshot(vars, log_tag="{} | counters".format(log_tag))
