"""Scoped dualtor-aa VM-host wiring and rollback primitives.

Only the five feature-owned host pairs are touched.  Four are disabled by the
stock topology; pair 1 is temporarily pinned upper for the single-homed host.
The MUX simulator is stopped before their flows change, every original flow is
registered for rollback before deletion, and the simulator is returned to its
original state after the flows have been restored.
"""

import json
import re
import shlex

from .topology import (
    FEATURE_PINNED_PAIRS,
    NEIGHBOR_NAMES,
    UNDERLAY_NEIGHBOR_ROLES,
)


PAIR_SIDES = {
    0: "upper",
    1: "upper",
    25: "upper",
    26: "lower",
    27: "lower",
}
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.:-]+$")
_VOLATILE_FLOW_FIELDS = (
    "duration=", "n_packets=", "n_bytes=", "idle_age=", "hard_age=",
)


class OverlayCommandError(RuntimeError):
    """A scoped runtime-overlay command failed."""


class RollbackError(RuntimeError):
    """One or more registered teardown actions failed."""


def adaptive_name(template, host, index):
    """Mirror vm_topology.py's 15-byte adaptive interface naming."""
    host_index = "-{}-{}".format(host, int(index))
    leading_length = 15 - len(host_index)
    if leading_length < 1:
        raise ValueError("vm-set name is too long for an OVS interface")
    return template.split("-", 1)[0][:leading_length] + host_index


def mux_bridge_name(vm_set_name, pair_index):
    return adaptive_name("mbr-{}-{}", vm_set_name, pair_index)


def mux_ptf_port_name(vm_set_name, pair_index):
    return adaptive_name("muxy-{}-{}", vm_set_name, pair_index)


def t1_bridge_name(eos_hostname, link_ordinal):
    return adaptive_name("br-{}-{}", eos_hostname, link_ordinal)


def t1_ptf_port_name(vm_set_name, ptf_index):
    return adaptive_name("inje-{}-{}", vm_set_name, ptf_index)


def t1_vm_port_name(eos_hostname, link_ordinal):
    return _validate_name(
        "{}-t{}".format(eos_hostname, int(link_ordinal)), "T1 VM interface"
    )


def _validate_name(value, kind):
    if not value or not _SAFE_NAME.match(str(value)):
        raise ValueError("unsafe {} name {!r}".format(kind, value))
    return str(value)


def _run(host, command, ignore_errors=False):
    method = getattr(host, "shell", None) or getattr(host, "command", None)
    if method is None:
        raise OverlayCommandError("host object has neither shell nor command")
    result = method(command, module_ignore_errors=True)
    if result is None:
        result = {"rc": 0, "stdout": ""}
    if int(result.get("rc", 0)) != 0 and not ignore_errors:
        detail = result.get("stderr") or result.get("stdout") or result.get("msg")
        raise OverlayCommandError("{}: {}".format(command, detail or "failed"))
    return result


def _stdout(host, command):
    return str(_run(host, command).get("stdout", "")).strip()


class RollbackStack:
    """LIFO teardown stack that attempts every action and aggregates errors."""

    def __init__(self):
        self._actions = []

    def defer(self, label, callback, *args, **kwargs):
        self._actions.append((label, callback, args, kwargs))

    @property
    def pending_labels(self):
        return tuple(item[0] for item in self._actions)

    def rollback(self):
        failures = []
        while self._actions:
            label, callback, args, kwargs = self._actions.pop()
            try:
                callback(*args, **kwargs)
            except Exception as error:  # teardown must attempt every action
                failures.append("{}: {}".format(label, error))
        if failures:
            raise RollbackError("; ".join(failures))


def normalize_ovs_flow_dump(output):
    """Return restorable, counter-independent OpenFlow specifications."""
    normalized = []
    for raw_line in str(output).splitlines():
        line = raw_line.strip()
        if " actions=" not in line:
            continue
        match_fields, actions = line.split(" actions=", 1)
        fields = []
        for field in match_fields.split(","):
            field = field.strip()
            if field and not field.startswith(_VOLATILE_FLOW_FIELDS):
                fields.append(field)
        normalized.append("{},actions={}".format(",".join(fields), actions.strip()))
    return tuple(sorted(normalized))


def snapshot_bridge(vmhost, bridge):
    bridge = _validate_name(bridge, "bridge")
    ports = tuple(sorted(filter(None, _stdout(
        vmhost, "sudo ovs-vsctl list-ports {}".format(bridge)
    ).splitlines())))
    if len(ports) != 3:
        raise OverlayCommandError(
            "{} must have exactly PTF, upper and lower ports (found {})".format(
                bridge, len(ports)
            )
        )
    flows = normalize_ovs_flow_dump(_stdout(
        vmhost, "sudo ovs-ofctl dump-flows {}".format(bridge)
    ))
    if not flows:
        raise OverlayCommandError("{} has no restorable OpenFlow entries".format(bridge))
    return {"bridge": bridge, "ports": ports, "flows": flows}


def restore_bridge(vmhost, snapshot):
    bridge = _validate_name(snapshot["bridge"], "bridge")
    current_ports = tuple(sorted(filter(None, _stdout(
        vmhost, "sudo ovs-vsctl list-ports {}".format(bridge)
    ).splitlines())))
    if current_ports != tuple(snapshot["ports"]):
        raise OverlayCommandError(
            "{} members changed; refusing an unsafe flow restore".format(bridge)
        )
    _run(vmhost, "sudo ovs-ofctl del-flows {}".format(bridge))
    for flow in snapshot["flows"]:
        _run(vmhost, "sudo ovs-ofctl add-flow {} {}".format(
            bridge, shlex.quote(flow)
        ))


def _ofport(vmhost, interface):
    interface = _validate_name(interface, "interface")
    value = _stdout(
        vmhost, "sudo ovs-vsctl get Interface {} ofport".format(interface)
    )
    try:
        number = int(value)
    except ValueError as error:
        raise OverlayCommandError(
            "{} has invalid ofport {!r}".format(interface, value)
        ) from error
    if number <= 0:
        raise OverlayCommandError("{} has unusable ofport {}".format(interface, number))
    return number


def _dut_hostnames_by_side(duts, tbinfo):
    """Bind fixture roles to the exact upper/lower identities in ``tbinfo``."""
    try:
        hostnames = {
            "upper": str(duts["mh_leaf0"].hostname),
            "lower": str(duts["mh_leaf1"].hostname),
        }
    except (AttributeError, KeyError, TypeError) as error:
        raise OverlayCommandError(
            "upper/lower DUT identities are unavailable"
        ) from error
    if hostnames["upper"] == hostnames["lower"]:
        raise OverlayCommandError("upper and lower DUT identities are identical")

    topology_duts = tuple(tbinfo.get("duts", ()))
    dut_indexes = tbinfo.get("duts_map", {})
    if len(topology_duts) != 2 or (
            topology_duts[0] != hostnames["upper"] or
            topology_duts[1] != hostnames["lower"] or
            dut_indexes.get(hostnames["upper"]) != 0 or
            dut_indexes.get(hostnames["lower"]) != 1):
        raise OverlayCommandError(
            "upper/lower fixtures do not match the ordered tbinfo DUT identities"
        )
    return hostnames


def _pair_vlan(vlan_map, hostname, pair_index):
    device_map = vlan_map.get(hostname)
    if not isinstance(device_map, dict):
        raise OverlayCommandError(
            "connection graph has no per-port VLAN map for {}".format(hostname)
        )
    for key in (int(pair_index), str(int(pair_index))):
        if key in device_map:
            value = device_map[key]
            try:
                return int(value)
            except (TypeError, ValueError) as error:
                raise OverlayCommandError(
                    "connection graph VLAN for {} pair {} is invalid: {!r}".format(
                        hostname, pair_index, value
                    )
                ) from error
    raise OverlayCommandError(
        "connection graph lacks {} port index {}".format(hostname, pair_index)
    )


def resolve_tor_ports(tor_ports, pair_index, duts, tbinfo, conn_graph_facts):
    """Resolve OVS upper/lower ports from inventory identity, never sort order.

    Physical dualtor VM-host interfaces are VLAN subinterfaces.  The connection
    graph is the source of truth for the host VLAN assigned to each DUT port
    index.  If that exact binding is unavailable (for example, an incomplete
    virtual inventory), the fixture fails closed instead of guessing from OVS
    interface names.
    """
    ports = tuple(tor_ports)
    if len(ports) != 2 or len(set(ports)) != 2:
        raise OverlayCommandError(
            "pair {} must expose two distinct ToR ports".format(pair_index)
        )
    hostnames = _dut_hostnames_by_side(duts, tbinfo)
    vlan_map = conn_graph_facts.get("device_vlan_map_list", {})
    if not isinstance(vlan_map, dict):
        raise OverlayCommandError("connection graph VLAN map is unavailable")

    resolved = {}
    for side in ("upper", "lower"):
        hostname = hostnames[side]
        vlan = _pair_vlan(vlan_map, hostname, pair_index)
        suffix = ".{}".format(vlan)
        matches = [port for port in ports if str(port).endswith(suffix)]
        if len(matches) != 1:
            raise OverlayCommandError(
                "pair {} {} DUT {} VLAN {} matches {} OVS ports".format(
                    pair_index, side, hostname, vlan, len(matches)
                )
            )
        resolved[side] = matches[0]
    if resolved["upper"] == resolved["lower"] or set(resolved.values()) != set(ports):
        raise OverlayCommandError(
            "pair {} inventory binding does not uniquely cover both ToR ports".format(
                pair_index
            )
        )
    return resolved


def _resolve_mux_pair(vmhost, vm_set_name, pair_index, side, duts, tbinfo,
                      conn_graph_facts):
    """Snapshot and bind one fixture-owned MUX bridge without mutating it."""
    if int(pair_index) not in FEATURE_PINNED_PAIRS:
        raise ValueError("pair {} is not fixture-owned".format(pair_index))
    if side not in ("upper", "lower"):
        raise ValueError("side must be upper or lower")
    bridge = mux_bridge_name(vm_set_name, pair_index)
    ptf_port = mux_ptf_port_name(vm_set_name, pair_index)
    snapshot = snapshot_bridge(vmhost, bridge)
    if ptf_port not in snapshot["ports"]:
        raise OverlayCommandError(
            "{} lacks expected PTF port {}".format(bridge, ptf_port)
        )
    tor_ports = tuple(port for port in snapshot["ports"] if port != ptf_port)
    bound_ports = resolve_tor_ports(
        tor_ports, pair_index, duts, tbinfo, conn_graph_facts
    )
    selected = bound_ports[side]
    blocked = bound_ports["lower" if side == "upper" else "upper"]

    return {
        "pair_index": int(pair_index),
        "side": side,
        "bridge": bridge,
        "ptf_port": ptf_port,
        "selected_tor_port": selected,
        "blocked_tor_port": blocked,
        "before": snapshot,
    }


def resolve_mux_overlay(vmhost, mux_server_info, tbinfo, duts,
                        conn_graph_facts):
    """Resolve and snapshot all five feature-owned bridges before mutation."""
    if not mux_server_info or len(mux_server_info) != 3:
        raise OverlayCommandError("mux_server_info is unavailable")
    _server_ip, _service_port, vm_set_name = mux_server_info
    if vm_set_name != tbinfo.get("group-name"):
        raise OverlayCommandError("MUX vm-set does not match tbinfo group-name")
    return {
        pair_index: _resolve_mux_pair(
            vmhost, vm_set_name, pair_index, PAIR_SIDES[pair_index],
            duts, tbinfo, conn_graph_facts,
        )
        for pair_index in FEATURE_PINNED_PAIRS
    }


def pin_bridge(vmhost, vm_set_name, pair_index, side, rollback_stack,
               duts, tbinfo, conn_graph_facts, planned=None):
    """Pin one feature-owned PTF pair to one ToR and register rollback."""
    details = planned or _resolve_mux_pair(
        vmhost, vm_set_name, pair_index, side, duts, tbinfo,
        conn_graph_facts,
    )
    if (details.get("pair_index") != int(pair_index)
            or details.get("side") != side
            or details.get("bridge") != mux_bridge_name(
                vm_set_name, pair_index)):
        raise OverlayCommandError(
            "pre-resolved MUX bridge does not match pair {} {}".format(
                pair_index, side))
    bridge = details["bridge"]
    ptf_port = details["ptf_port"]
    selected = details["selected_tor_port"]
    snapshot = details["before"]

    # Register the exact original state before the first destructive command.
    rollback_stack.defer(
        "restore OVS flows on {}".format(bridge), restore_bridge,
        vmhost, snapshot,
    )
    ptf_ofport = _ofport(vmhost, ptf_port)
    tor_ofport = _ofport(vmhost, selected)
    _run(vmhost, "sudo ovs-ofctl del-flows {}".format(bridge))
    for flow in (
            "table=0,priority=100,in_port={},actions=output:{}".format(
                ptf_ofport, tor_ofport),
            "table=0,priority=100,in_port={},actions=output:{}".format(
                tor_ofport, ptf_ofport)):
        _run(vmhost, "sudo ovs-ofctl add-flow {} {}".format(
            bridge, shlex.quote(flow)
        ))
    return details


def mux_service_active(vmhost, port):
    port = int(port)
    result = _run(
        vmhost,
        "systemctl is-active mux-simulator-{}.service".format(port),
        ignore_errors=True,
    )
    try:
        rc = int(result.get("rc", 1))
    except (TypeError, ValueError) as error:
        raise OverlayCommandError(
            "MUX simulator service-state query returned an invalid rc") from error
    state = str(result.get("stdout", "")).strip()
    if rc == 0 and state == "active":
        return True
    if rc == 3 and state == "inactive":
        return False
    raise OverlayCommandError(
        "cannot prove MUX simulator service state (rc={}, state={!r})".format(
            rc, state))


def set_mux_service(vmhost, port, active):
    action = "start" if active else "stop"
    _run(vmhost, "sudo systemctl {} mux-simulator-{}.service".format(
        action, int(port)
    ))


def prepare_mux_overlay(vmhost, mux_server_info, tbinfo, rollback_stack,
                        duts, conn_graph_facts, mapping=None):
    """Stop the task MUX service and pin only pairs 0/1/25/26/27."""
    if not mux_server_info or len(mux_server_info) != 3:
        raise OverlayCommandError("mux_server_info is unavailable")
    _server_ip, service_port, vm_set_name = mux_server_info
    if vm_set_name != tbinfo.get("group-name"):
        raise OverlayCommandError("MUX vm-set does not match tbinfo group-name")
    initially_active = mux_service_active(vmhost, service_port)
    rollback_stack.defer(
        "restore MUX simulator service",
        set_mux_service, vmhost, service_port, initially_active,
    )
    if initially_active:
        set_mux_service(vmhost, service_port, False)

    mapping = mapping or resolve_mux_overlay(
        vmhost, mux_server_info, tbinfo, duts, conn_graph_facts
    )
    for pair_index in FEATURE_PINNED_PAIRS:
        pin_bridge(
            vmhost, vm_set_name, pair_index, PAIR_SIDES[pair_index],
            rollback_stack, duts, tbinfo, conn_graph_facts,
            planned=mapping[pair_index],
        )
    return mapping


def _parse_vm_link(link):
    text = str(link)
    if "@" not in text or "." not in text.split("@", 1)[0]:
        raise OverlayCommandError("invalid stock T1 link {!r}".format(link))
    dut_port, ptf_index = text.split("@", 1)
    dut_index, port_index = dut_port.split(".", 1)
    try:
        return int(dut_index), int(port_index), int(ptf_index)
    except ValueError as error:
        raise OverlayCommandError(
            "invalid stock T1 link {!r}".format(link)
        ) from error


def resolve_vxlan_path_bridges(vmhost, vm_set_name, tbinfo, duts,
                               neighbors, conn_graph_facts):
    """Resolve the six A01--A03 DUT-facing OVS bridges from inventory facts."""
    vm_set_name = _validate_name(vm_set_name, "VM-set")
    hostnames = _dut_hostnames_by_side(duts, tbinfo)
    duts_by_index = {0: hostnames["upper"], 1: hostnames["lower"]}
    vlan_map = conn_graph_facts.get("device_vlan_map_list", {})
    if not isinstance(vlan_map, dict):
        raise OverlayCommandError("connection graph VLAN map is unavailable")
    topology = tbinfo.get("topo", {}).get("properties", {}).get(
        "topology", {}
    )
    vms = topology.get("VMs", {})
    resolved = {}
    for role in UNDERLAY_NEIGHBOR_ROLES:
        name = NEIGHBOR_NAMES[role]
        if role not in neighbors or name not in vms:
            raise OverlayCommandError("{} T1 neighbor is unavailable".format(name))
        eos_hostname = _validate_name(
            getattr(neighbors[role], "hostname", ""), "EOS hostname"
        )
        links = tuple(vms[name].get("vlans", ()))
        if len(links) != 2:
            raise OverlayCommandError(
                "{} must have exactly two DUT-facing links".format(name)
            )
        for ordinal, link in enumerate(links):
            dut_index, port_index, ptf_index = _parse_vm_link(link)
            if dut_index not in duts_by_index:
                raise OverlayCommandError(
                    "{} link {} has invalid DUT index {}".format(
                        name, ordinal, dut_index
                    )
                )
            bridge = t1_bridge_name(eos_hostname, ordinal)
            snapshot = snapshot_bridge(vmhost, bridge)
            ptf_port = t1_ptf_port_name(vm_set_name, ptf_index)
            vm_port = t1_vm_port_name(eos_hostname, ordinal)
            dut_hostname = duts_by_index[dut_index]
            dut_vlan = _pair_vlan(vlan_map, dut_hostname, port_index)
            matches = [
                port for port in snapshot["ports"]
                if str(port).endswith(".{}".format(dut_vlan))
            ]
            if len(matches) != 1:
                raise OverlayCommandError(
                    "{} {} DUT VLAN {} matches {} OVS ports".format(
                        name, dut_hostname, dut_vlan, len(matches)
                    )
                )
            dut_port = matches[0]
            if set(snapshot["ports"]) != {ptf_port, vm_port, dut_port}:
                raise OverlayCommandError(
                    "{} ports do not match VM, PTF and inventory-derived DUT"
                    .format(bridge)
                )
            resolved[(role, dut_index)] = {
                "role": role,
                "neighbor": name,
                "dut_index": dut_index,
                "dut_hostname": dut_hostname,
                "dut_port_index": port_index,
                "ptf_index": ptf_index,
                "bridge": bridge,
                "vm_port": vm_port,
                "ptf_port": ptf_port,
                "dut_port": dut_port,
                "before": snapshot,
            }
    if len(resolved) != 6:
        raise OverlayCommandError("exactly six A01--A03 VXLAN paths are required")
    return resolved


def prepare_vxlan_path_bridges(vmhost, vm_set_name, tbinfo, duts,
                               neighbors, conn_graph_facts, rollback_stack,
                               mapping=None):
    """Mirror UDP/4789 on only the six A01--A03 DUT/T1 bridges."""
    mapping = mapping or resolve_vxlan_path_bridges(
        vmhost, vm_set_name, tbinfo, duts, neighbors, conn_graph_facts)
    for details in mapping.values():
        bridge = details["bridge"]
        rollback_stack.defer(
            "restore VXLAN OVS flows on {}".format(bridge),
            restore_bridge, vmhost, details["before"],
        )
        dut_ofport = _ofport(vmhost, details["dut_port"])
        vm_ofport = _ofport(vmhost, details["vm_port"])
        ptf_ofport = _ofport(vmhost, details["ptf_port"])
        for ingress, forwarding in (
                (dut_ofport, (vm_ofport, ptf_ofport)),
                (vm_ofport, (dut_ofport, ptf_ofport))):
            flow = (
                "table=0,priority=200,udp,in_port={},tp_dst=4789,"
                "actions=output:{},output:{}"
            ).format(ingress, forwarding[0], forwarding[1])
            _run(vmhost, "sudo ovs-ofctl add-flow {} {}".format(
                bridge, shlex.quote(flow)
            ))
    return mapping


def assert_mux_overlay_restored(vmhost, mapping):
    """Prove selected bridge members and stable flow contracts match before-state."""
    failures = []
    for pair_index, details in sorted(mapping.items()):
        try:
            after = snapshot_bridge(vmhost, details["bridge"])
        except Exception as error:
            failures.append("pair {}: {}".format(pair_index, error))
            continue
        before = details["before"]
        if after["ports"] != before["ports"] or after["flows"] != before["flows"]:
            failures.append("pair {} OVS state differs from before-state".format(pair_index))
    if failures:
        raise OverlayCommandError("; ".join(failures))


def require_ptf_backplane(ptfhost):
    """Fail fast unless the stock PTF backplane exists before any mutation."""
    result = _run(ptfhost, "ip -j link show dev backplane", ignore_errors=True)
    if result.get("rc", 1) != 0:
        raise OverlayCommandError("PTF interface 'backplane' is unavailable")
    try:
        payload = json.loads(result.get("stdout", "[]"))
    except ValueError as error:
        raise OverlayCommandError("PTF backplane state is not valid JSON") from error
    if len(payload) != 1 or payload[0].get("ifname") != "backplane":
        raise OverlayCommandError("PTF backplane state is incomplete")
    return payload[0]
