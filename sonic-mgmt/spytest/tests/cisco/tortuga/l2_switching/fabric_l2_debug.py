"""Tortuga fabric L2 debug snapshots (VLAN/MAC/NPU/interface counters).

Lives alongside ``test_bvi`` and ``test_l2_vlan`` under ``l2_switching/`` (not ``common/``)
because these helpers are specific to those scripts, not general tortuga utilities.
``bin/spytest`` adds this directory to ``sys.path`` so ``from fabric_l2_debug import ...``
works when running SpyTest.

Call :func:`fabric_l2_debug_enabled` once at the start of a testcase (or equivalent), then
only call the snapshot helpers when it returns True - e.g. ``fabric_dbg =
fabric_l2_debug_enabled(vars=vars)`` and ``if fabric_dbg:``. The helpers themselves do not
re-check the image; they only run the CLI you ask for.
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
    Return True if fabric L2 debug snapshots (CLI instrumentation) should run.

    True only when ``basic.show_version(dut)['version']`` contains the substring
    ``c-master``. Otherwise False (no env vars; other images are ignored).

    When ``dut`` is omitted, it is resolved from ``vars`` (first of D1-D4, else first
    entry in ``vars.dut_list``).
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
        st.config(dut, "sudo show platform npu counters", skip_tmpl=True)


def fabric_snapshot_post_traffic_npu(duts, log_tag="Post-traffic NPU counters"):
    st.log("DEBUG: {}".format(log_tag))
    for dut in duts:
        if dut is None:
            continue
        st.config(dut, "sudo show platform npu counters", skip_tmpl=True)


def fabric_wait_counterpoll_interface_refresh(seconds=10):
    st.wait(
        seconds,
        "Waiting for counterpoll to refresh DUT interface counters",
    )


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
        st.show(dut, "show interfaces counters", skip_tmpl=True)
        for port in ports:
            st.show(
                dut,
                "show interfaces counters detailed {}".format(port),
                skip_tmpl=True,
            )
        st.show(dut, "show interfaces counters rif", skip_tmpl=True)
