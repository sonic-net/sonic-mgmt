"""Native pytest fixtures for the stock-dualtor-aa EVPN-MH overlay."""

import json
import shlex

import pytest

from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory  # noqa: F401

from .dualtor_overlay import (
    OverlayCommandError,
    RollbackError,
    RollbackStack,
    assert_mux_overlay_restored,
    mux_bridge_name,
    mux_ptf_port_name,
    mux_service_active,
    prepare_mux_overlay,
    prepare_vxlan_path_bridges,
    require_ptf_backplane,
    resolve_mux_overlay,
    resolve_tor_ports,
    resolve_vxlan_path_bridges,
    snapshot_bridge,
)
from .eos_overlay import (
    EosOverlayError,
    build_eos_overlay_plan,
    collect_remote_eos_evidence,
    configure_eos_remote_overlay,
    configure_eos_transit,
    eos_contains_value,
    eos_established_peers,
    eos_evpn_peers_ready,
    eos_svi_egress_mac,
    eos_transit_ready,
    probe_eos_overlay_capabilities,
    restore_eos_config,
    shutdown_eos_direct_peers,
    snapshot_eos_config,
)
from .lag import configure_ptf_segment, remove_ptf_segment
from .operations import wait_until
from .provision import (
    clear_evpn_mh_runtime_state,
    configure_evpn_mh,
    restart_caclmgrd,
    uses_frrcfgd,
    wait_evpn_mh_overlay,
)
from .state import (CommandJsonError, CommandUnavailableError, command_json,
                    established_peers, ethernet_segment,
                    route_nexthop_count, segment_is_remote, vni_is_present,
                    walk_json)

from .topology import (
    FEATURE_PINNED_PAIRS,
    TopologyContractError,
    ethernet_segments,
    evpn_mh_properties,
    is_evpn_mh_topology,
    resolve_dut_interfaces,
    resolve_dut_roles,
    resolve_neighbor_roles,
    resolve_ptf_ports,
    validate_stock_topology,
)
from .traffic import reap_stale_traffic_jobs


collect_ignore_glob = ["unit_tests/test_*.py"]


CHECKPOINT_NAME = "evpn_mh_16cases_before_suite"


@pytest.fixture(scope="session", autouse=True)
def evpn_mh_topology_contract(tbinfo):
    """Reject every topology except the exact stock dualtor-aa resource shape."""
    if not is_evpn_mh_topology(tbinfo):
        pytest.skip("EVPN-MH tests require the existing topo=dualtor-aa")
    try:
        return validate_stock_topology(tbinfo)
    except TopologyContractError as error:
        pytest.fail("dualtor-aa contract mismatch: {}".format(error))


@pytest.fixture(scope="session")
def evpn_mh_duts(upper_tor_host, lower_tor_host, tbinfo,
                 evpn_mh_topology_contract):
    """The local MH pair only; the remote EOS VM is never a duthost."""
    return resolve_dut_roles((upper_tor_host, lower_tor_host), tbinfo)


@pytest.fixture(scope="session")
def evpn_mh_neighbors(nbrhosts, tbinfo, evpn_mh_topology_contract):
    """Three EOS underlay roles plus ARISTA04T1 as the remote EOS leaf."""
    return resolve_neighbor_roles(nbrhosts, tbinfo)


@pytest.fixture(scope="session")
def evpn_mh_remote_eos(evpn_mh_neighbors):
    return evpn_mh_neighbors["remote_leaf"]


@pytest.fixture(scope="session")
def evpn_mh_topology(tbinfo, evpn_mh_topology_contract):
    return evpn_mh_properties(tbinfo)


@pytest.fixture(scope="session")
def evpn_mh_ptf_ports(tbinfo, evpn_mh_topology_contract):
    return resolve_ptf_ports(tbinfo)


@pytest.fixture(scope="session")
def evpn_mh_interfaces(evpn_mh_duts, evpn_mh_ptf_ports, tbinfo):
    return resolve_dut_interfaces(evpn_mh_duts, tbinfo, evpn_mh_ptf_ports)


@pytest.fixture(scope="module")
def evpn_mh_capability_preflight(ptfhost, vmhost, mux_server_info, tbinfo,
                                 evpn_mh_neighbors, evpn_mh_duts,
                                 conn_graph_facts):
    """Perform all non-mutating stock-topology/EOS feasibility checks first."""
    failures = []
    try:
        require_ptf_backplane(ptfhost)
    except OverlayCommandError as error:
        failures.append(str(error))

    if not mux_server_info or len(mux_server_info) != 3:
        failures.append("mux_server_info is unavailable")
    else:
        _server_ip, service_port, vm_set_name = mux_server_info
        if vm_set_name != tbinfo.get("group-name"):
            failures.append("MUX vm-set differs from tbinfo group-name")
        try:
            mux_service_active(vmhost, service_port)
        except OverlayCommandError as error:
            failures.append("MUX service-state binding: {}".format(error))
        for pair_index in FEATURE_PINNED_PAIRS:
            try:
                # Pure snapshot: prove membership, flows and inventory-derived
                # upper/lower identities before stopping the MUX service.
                snapshot = snapshot_bridge(
                    vmhost, mux_bridge_name(vm_set_name, pair_index)
                )
                ptf_port = mux_ptf_port_name(vm_set_name, pair_index)
                if ptf_port not in snapshot["ports"]:
                    raise OverlayCommandError(
                        "{} lacks expected PTF port {}".format(
                            snapshot["bridge"], ptf_port
                        )
                    )
                resolve_tor_ports(
                    (port for port in snapshot["ports"] if port != ptf_port),
                    pair_index, evpn_mh_duts, tbinfo, conn_graph_facts,
                )
            except OverlayCommandError as error:
                failures.append("pair {}: {}".format(pair_index, error))
        try:
            # Resolve all six A01--A03 DUT-facing bridges before any OVS
            # mutation.  This also proves exact VM/PTF/DUT port membership.
            resolve_vxlan_path_bridges(
                vmhost, vm_set_name, tbinfo, evpn_mh_duts,
                evpn_mh_neighbors, conn_graph_facts,
            )
        except OverlayCommandError as error:
            failures.append("VXLAN path binding: {}".format(error))

    failures.extend(probe_eos_overlay_capabilities(evpn_mh_neighbors))
    for role, dut in sorted(evpn_mh_duts.items()):
        if not uses_frrcfgd(dut):
            failures.append(
                "{} lacks frrcfgd; legacy FRR state is outside checkpoint "
                "ownership".format(role)
            )
        try:
            peer_states = _bgp_peer_states(dut)
            if any(state.strip().lower() != "established"
                   for state in peer_states.values()):
                failures.append("{} stock BGP peers are not established".format(
                    role))
            swss_states = _swss_process_states(dut)
            for process in ("orchagent", "intfmgrd", "portmgrd"):
                if swss_states.get(process) != "RUNNING":
                    failures.append("{} SWSS {} is not RUNNING".format(
                        role, process))
        except RuntimeError as error:
            failures.append("{} operational baseline: {}".format(role, error))
        if not _critical_services_ready(dut):
            failures.append(
                "{} critical services are not fully started".format(role))
    if failures:
        pytest.fail(
            "EVPN-MH fixture capability preflight failed before mutation: {}".format(
                "; ".join(failures)
            )
        )
    return True


@pytest.fixture(scope="module")
def evpn_mh_dualtor_wiring(vmhost, mux_server_info, tbinfo,
                           evpn_mh_capability_preflight, evpn_mh_duts,
                           conn_graph_facts, evpn_mh_config_checkpoint):
    """Create independent upper/lower PTF legs and restore exact OVS state."""
    rollback_stack = RollbackStack()
    mapping = resolve_mux_overlay(
        vmhost, mux_server_info, tbinfo, evpn_mh_duts, conn_graph_facts
    )
    initially_active = mux_service_active(vmhost, mux_server_info[1])
    try:
        mapping = prepare_mux_overlay(
            vmhost, mux_server_info, tbinfo, rollback_stack,
            evpn_mh_duts, conn_graph_facts, mapping=mapping,
        )
        yield mapping
    finally:
        cleanup_failures = []
        try:
            rollback_stack.rollback()
        except RollbackError as error:
            cleanup_failures.append(str(error))
        if mapping:
            try:
                assert_mux_overlay_restored(vmhost, mapping)
            except OverlayCommandError as error:
                cleanup_failures.append(str(error))
        try:
            restored_active = mux_service_active(
                vmhost, mux_server_info[1])
        except OverlayCommandError as error:
            cleanup_failures.append(
                "MUX simulator service state is unverifiable: {}".format(error))
        else:
            if restored_active != initially_active:
                cleanup_failures.append(
                    "MUX simulator service state was not restored")
        # A body failure must never hide rollback evidence.  pytest will report
        # this finalizer failure as an additional teardown error.
        if cleanup_failures:
            pytest.fail("EVPN-MH wiring cleanup failed: {}".format(
                "; ".join(cleanup_failures)
            ))


@pytest.fixture(scope="module")
def evpn_mh_vxlan_paths(vmhost, mux_server_info, tbinfo, evpn_mh_duts,
                        evpn_mh_neighbors, conn_graph_facts,
                        evpn_mh_capability_preflight,
                        evpn_mh_dualtor_wiring):
    """Allow and mirror UDP/4789 on only the six A01--A03 T1 links."""
    rollback_stack = RollbackStack()
    mapping = resolve_vxlan_path_bridges(
        vmhost, mux_server_info[2], tbinfo, evpn_mh_duts,
        evpn_mh_neighbors, conn_graph_facts,
    )
    try:
        mapping = prepare_vxlan_path_bridges(
            vmhost, mux_server_info[2], tbinfo, evpn_mh_duts,
            evpn_mh_neighbors, conn_graph_facts, rollback_stack,
            mapping=mapping,
        )
        yield mapping
    finally:
        cleanup_failures = []
        try:
            rollback_stack.rollback()
        except RollbackError as error:
            cleanup_failures.append(str(error))
        if mapping:
            try:
                assert_mux_overlay_restored(vmhost, mapping)
            except OverlayCommandError as error:
                cleanup_failures.append(str(error))
        if cleanup_failures:
            pytest.fail("EVPN-MH VXLAN path cleanup failed: {}".format(
                "; ".join(cleanup_failures)
            ))


def _dut_transit_paths_ready(duts, topology):
    remote_vtep = topology["vtep_ip"]["remote_leaf"]
    expected_paths = len(topology["underlay_neighbor_names"])
    try:
        for dut in duts.values():
            routes = command_json(
                dut, "show ip route {}/32 json".format(remote_vtep)
            )
            if route_nexthop_count(routes) != expected_paths:
                return False
        return True
    except CommandJsonError:
        return False


@pytest.fixture(scope="module")
def evpn_mh_eos_configured(evpn_mh_neighbors, evpn_mh_duts, tbinfo,
                           evpn_mh_topology,
                           evpn_mh_capability_preflight,
                           evpn_mh_config_checkpoint,
                           evpn_mh_vxlan_paths):
    """Snapshot, configure, and exactly restore all four stock EOS VMs.

    The SONiC checkpoint fixture is deliberately an upstream dependency: it
    captures the stock BGP baseline before A04's direct DUT peers are disabled,
    and its finalizer therefore runs only after this fixture restores EOS.
    """
    roles = ("underlay0", "underlay1", "underlay2", "remote_leaf")
    snapshots = {}
    plan = None
    setup_error = None
    try:
        for role in roles:
            snapshots[role] = snapshot_eos_config(evpn_mh_neighbors[role])
        plan = build_eos_overlay_plan(
            evpn_mh_neighbors, tbinfo, evpn_mh_topology, snapshots
        )
        configure_eos_transit(plan, evpn_mh_topology)
        if not wait_until(
                180, 5, 0, eos_transit_ready,
                plan, evpn_mh_topology, False):
            raise EosOverlayError(
                "A01-A03/A04 transit BGP and VTEP routes did not converge "
                "before direct-peer shutdown"
            )
        shutdown_eos_direct_peers(plan, evpn_mh_topology)
        if not wait_until(
                180, 5, 0, eos_transit_ready,
                plan, evpn_mh_topology, True):
            raise EosOverlayError(
                "EOS transit routes did not survive A04 direct-peer shutdown"
            )
        if not wait_until(
                180, 5, 0, _dut_transit_paths_ready,
                evpn_mh_duts, evpn_mh_topology):
            raise EosOverlayError(
                "SONiC ToRs did not install the three A01-A03 paths "
                "to the A04 VTEP after direct-peer shutdown"
            )
        configure_eos_remote_overlay(plan, evpn_mh_topology)
    except Exception as error:
        setup_error = error

    if setup_error is not None:
        cleanup_failures = []
        for role in reversed(roles):
            if role not in snapshots:
                continue
            try:
                restore_eos_config(evpn_mh_neighbors[role], snapshots[role])
            except Exception as error:
                cleanup_failures.append("{}: {}".format(role, error))
        if cleanup_failures:
            pytest.fail(
                "EOS overlay setup failed: {}; rollback also failed: {}".format(
                    setup_error, "; ".join(cleanup_failures)
                )
            )
        raise setup_error

    try:
        yield plan
    finally:
        cleanup_failures = []
        for role in reversed(roles):
            try:
                restore_eos_config(evpn_mh_neighbors[role], snapshots[role])
            except Exception as error:
                cleanup_failures.append("{}: {}".format(role, error))
        # Teardown evidence remains visible even when the test body failed.
        if cleanup_failures:
            pytest.fail("EOS overlay cleanup failed: {}".format(
                "; ".join(cleanup_failures)
            ))


@pytest.fixture(scope="module")
def evpn_mh_clean_start(ptfhost, evpn_mh_duts, evpn_mh_ptf_ports,
                        evpn_mh_topology, evpn_mh_capability_preflight,
                        evpn_mh_config_checkpoint):
    """Clear only task-owned endpoint/runtime learning from interrupted runs."""
    try:
        reap_stale_traffic_jobs(ptfhost)
    except Exception as error:
        pytest.fail("stale EVPN-MH PTF worker cleanup failed: {}".format(error))
    for segment in ethernet_segments(evpn_mh_topology).values():
        remove_ptf_segment(ptfhost, evpn_mh_ptf_ports, segment)
    segments = ethernet_segments(evpn_mh_topology)
    physical_roles = {
        role
        for segment in segments.values()
        for role in segment["ptf_member_roles"]
    }
    for endpoint_name, attachment in evpn_mh_topology.get(
            "single_homed_endpoints", {}).items():
        physical_roles.add(attachment.get(
            "ptf_port_role",
            evpn_mh_topology["endpoints"][endpoint_name].get(
                "ptf_port_role", endpoint_name),
        ))
    for role in sorted(physical_roles):
        result = ptfhost.shell(
            "ip link set eth{} up".format(evpn_mh_ptf_ports[role]),
            module_ignore_errors=True,
        )
        if result.get("rc", 1) != 0:
            pytest.fail("failed to restore PTF {} link before setup".format(role))
    backplane = ptfhost.shell(
        "ip link set backplane up", module_ignore_errors=True
    )
    if backplane.get("rc", 1) != 0:
        pytest.fail("failed to restore PTF backplane before setup")
    agent = ptfhost.shell(
        "supervisorctl restart ptf_nn_agent", module_ignore_errors=True
    )
    if agent.get("rc", 1) != 0:
        pytest.fail("failed to restart ptf_nn_agent before setup")
    clear_evpn_mh_runtime_state(evpn_mh_duts, evpn_mh_topology)
    return True


def _canonical_config_db(dut):
    result = dut.shell(
        "sonic-cfggen -d --print-data", module_ignore_errors=True
    )
    if result.get("rc", 1) != 0:
        raise RuntimeError(
            "{} CONFIG_DB snapshot failed: {}".format(
                dut.hostname,
                result.get("stderr", result.get("stdout", "")),
            )
        )
    try:
        payload = json.loads(result.get("stdout", ""))
    except (TypeError, ValueError) as error:
        raise RuntimeError(
            "{} CONFIG_DB snapshot is not JSON".format(dut.hostname)
        ) from error
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _canonical_persistent_config_db(dut):
    result = dut.shell(
        "sudo cat /etc/sonic/config_db.json", module_ignore_errors=True
    )
    if result.get("rc", 1) != 0:
        raise RuntimeError(
            "{} persistent CONFIG_DB read failed: {}".format(
                dut.hostname,
                result.get("stderr", result.get("stdout", "")),
            )
        )
    try:
        payload = json.loads(result.get("stdout", ""))
    except (TypeError, ValueError) as error:
        raise RuntimeError(
            "{} persistent CONFIG_DB is not JSON".format(dut.hostname)
        ) from error
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _bgp_peer_states(dut):
    result = dut.shell(
        "timeout --signal=TERM --kill-after=3s 25s docker exec bgp "
        "timeout --signal=TERM --kill-after=3s 20s "
        "vtysh -c 'show bgp summary json'",
        module_ignore_errors=True,
    )
    if result.get("rc", 1) != 0:
        raise RuntimeError("{} BGP summary failed".format(dut.hostname))
    try:
        payload = json.loads(result.get("stdout", ""))
    except (TypeError, ValueError) as error:
        raise RuntimeError(
            "{} BGP summary is not JSON".format(dut.hostname)) from error

    peers = {}

    def visit(value, path=()):
        if isinstance(value, dict):
            peer_table = value.get("peers")
            if isinstance(peer_table, dict):
                for peer, details in peer_table.items():
                    if not isinstance(details, dict):
                        continue
                    state = next((
                        details[key] for key in (
                            "state", "peerState", "bgpState")
                        if key in details
                    ), None)
                    if state is None and "pfxRcd" in details:
                        state = "Established"
                    peers["/".join(path + ("peers", str(peer)))] = str(
                        state or "unknown")
            for key, child in value.items():
                if key != "peers":
                    visit(child, path + (str(key),))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, path + (str(index),))

    visit(payload)
    if not peers:
        raise RuntimeError("{} BGP summary contains no peers".format(dut.hostname))
    return peers


def _swss_process_states(dut):
    result = dut.shell(
        "docker exec swss supervisorctl status", module_ignore_errors=True
    )
    if result.get("rc", 1) != 0:
        raise RuntimeError("{} SWSS supervisor query failed".format(dut.hostname))
    states = {}
    for line in result.get("stdout", "").splitlines():
        fields = line.split()
        if len(fields) >= 2:
            states[fields[0].rsplit(":", 1)[-1]] = fields[1]
    if not states:
        raise RuntimeError("{} SWSS supervisor state is empty".format(dut.hostname))
    return states


def _critical_services_ready(dut):
    check = getattr(dut, "critical_services_fully_started", None)
    if not callable(check):
        return False
    try:
        return bool(check())
    except Exception:
        return False


def _checkpoint_runtime_ready(dut, expected_config):
    try:
        if _canonical_config_db(dut) != expected_config["running"]:
            return False
        if _bgp_peer_states(dut) != expected_config["bgp_peers"]:
            return False
        if _swss_process_states(dut) != expected_config["swss_processes"]:
            return False
    except RuntimeError:
        return False
    return _critical_services_ready(dut)


def _checkpoint_restore_ready(dut, expected_config):
    if not _checkpoint_runtime_ready(dut, expected_config):
        return False
    try:
        return (
            _canonical_persistent_config_db(dut)
            == expected_config["persistent"]
        )
    except RuntimeError:
        # Persistent storage may be briefly unreadable while config save is
        # replacing the file.  Let wait_until retry instead of escaping the
        # finalizer and losing the explicit checkpoint-retention diagnostic.
        return False


def _quiesce_feature_dependencies(dut, role, topology, baseline_json):
    """Detach only newly owned ES/SVIs while their VNI parents still exist.

    Native ES deletion updates FRR before CONFIG_DB. A generic checkpoint
    delta cannot replace that lifecycle step. This ordering does not suppress
    a Zebra crash: any failed command/readback retains the checkpoint.
    """
    baseline = json.loads(baseline_json)

    def command(text):
        result = dut.shell(
            "timeout --signal=TERM --kill-after=3s 25s " + text,
            module_ignore_errors=True)
        if result.get("rc", 1) != 0:
            raise RuntimeError("{} dependency cleanup command failed: {}".format(
                dut.hostname, text))
        return result.get("stdout", "")

    def native_json(text, frr=False):
        if frr:
            text = (
                "docker exec bgp timeout --signal=TERM --kill-after=3s 20s "
                "vtysh -c " + shlex.quote(text))
        try:
            return json.loads(command(text))
        except (TypeError, ValueError) as error:
            raise RuntimeError(
                "{} dependency cleanup returned invalid JSON".format(
                    dut.hostname)) from error

    current = native_json("sonic-cfggen -d --print-data")
    owned_segments = []
    for segment in ethernet_segments(topology).values():
        if role not in segment["leaf_roles"]:
            continue
        pc = segment["portchannel"]
        baseline_es = baseline.get("EVPN_ETHERNET_SEGMENT", {})
        current_es = current.get("EVPN_ETHERNET_SEGMENT", {})
        if pc in baseline_es:
            if current_es.get(pc) != baseline_es[pc]:
                raise RuntimeError("Refusing to detach a pre-existing ES: " + pc)
            continue
        if pc in current_es and (
                current_es[pc].get("type") != "TYPE_3_MAC_BASED"
                or current.get("PORTCHANNEL", {}).get(pc, {}).get("system_mac")
                != segment["system_mac"]):
            raise RuntimeError("Feature ES ownership differs: " + pc)
        owned_segments.append(segment)

    owned_svis = {}
    for vlan, vni in ((topology["mh_vlan"], topology["l2vni"]),
                      (topology["l3vni_vlan"], topology["l3vni"]),
                      (topology["remote_vlan"], topology["remote_l2vni"])):
        alias = "Vlan{}".format(int(vlan))

        def references(table):
            return any(key == alias or key.startswith(alias + "|")
                       for key in table)
        if references(baseline.get("VLAN_INTERFACE", {})):
            continue
        if not references(current.get("VLAN_INTERFACE", {})):
            continue
        if current.get("VLAN_INTERFACE", {}).get(alias, {}).get(
                "vrf_name") != topology["vrf"]:
            raise RuntimeError("Feature SVI ownership differs: " + alias)
        if not any(row.get("vlan") == alias and str(row.get("vni")) == str(vni)
                   for row in current.get("VXLAN_TUNNEL_MAP", {}).values()):
            raise RuntimeError("Feature VNI parent is already absent: " + alias)
        if alias in baseline.get("VLAN", {}):
            raise RuntimeError("Refusing to shut down a pre-existing VLAN: " + alias)
        owned_svis[alias] = int(vni)

    def parents_alive():
        vnis = native_json("show evpn vni json", frr=True)
        return all(vni_is_present(vnis, vni) for vni in owned_svis.values())

    if owned_svis and not parents_alive():
        raise RuntimeError("Feature VNI parents are not active before cleanup")
    for segment in owned_segments:
        pc = shlex.quote(segment["portchannel"])
        if segment["portchannel"] in current.get("EVPN_ETHERNET_SEGMENT", {}):
            command("sudo config interface shutdown " + pc)
            command("sudo config interface evpn-esi del " + pc)

    def segments_detached():
        config = native_json("sonic-cfggen -d --print-data")
        observed = native_json("show evpn es json", frr=True)
        for segment in owned_segments:
            if segment["portchannel"] in config.get("EVPN_ETHERNET_SEGMENT", {}):
                return False
            entry = ethernet_segment(observed, segment["esi"])
            # A remote-only copy can remain until the other ToR detaches.
            # Unknown locality is not proof of successful local cleanup.
            if entry is not None and not segment_is_remote(entry):
                return False
        return True

    if owned_segments and not wait_until(30, 1, 0, segments_detached):
        raise RuntimeError("Feature local ES attachments did not disappear")
    # Drain SAG's intentional down/up MAC-change operation before the VLAN
    # is quiesced. Keep SAG|GLOBAL alive until its consumers finish.
    sag_svis = [alias for alias in owned_svis if str(current.get(
        "VLAN_INTERFACE", {}).get(alias, {}).get(
            "static_anycast_gateway", "false")).lower() == "true"]
    global_mac = str(current.get("DEVICE_METADATA", {}).get(
        "localhost", {}).get("mac", "")).lower()
    if sag_svis and not global_mac:
        raise RuntimeError("Global router MAC is unavailable for SAG cleanup")
    for alias in sag_svis:
        command("sudo config vlan static-anycast-gateway disable " + alias[4:])

    def sag_drained():
        config = native_json("sonic-cfggen -d --print-data")
        links = native_json("ip -j link show")
        for alias in sag_svis:
            if str(config.get("VLAN_INTERFACE", {}).get(alias, {}).get(
                    "static_anycast_gateway", "true")).lower() != "false":
                return False
            matches = [row for row in links if row.get("ifname") == alias]
            if len(matches) != 1 or matches[0].get("address", "").lower() != global_mac:
                return False
            observed = native_json(
                "show interface {} vrf all json".format(alias), frr=True)
            rows = [node[alias] for node in walk_json(observed)
                    if isinstance(node, dict) and alias in node
                    and isinstance(node[alias], dict)]
            if len(rows) != 1 or rows[0].get("hardwareAddress", "").lower() != global_mac:
                return False
        return parents_alive()

    if sag_svis and not wait_until(30, 1, 0, sag_drained):
        raise RuntimeError("Feature SAG MAC change did not drain before VLAN shutdown")

    for alias in owned_svis:
        # The generic port CLI rejects VLAN interfaces on some images.
        # Publish the native SVI field consumed by SWSS vlanmgrd instead;
        # the same CONFIG_DB/Linux/FRR readbacks below remain mandatory.
        script = (
            "from swsscommon.swsscommon import ConfigDBConnector; "
            "db = ConfigDBConnector(); db.connect(); "
            "db.mod_entry('VLAN', %r, {'admin_status': 'down'})"
            % alias)
        command("sudo python3 -c " + shlex.quote(script))

    def svis_down():
        config = native_json("sonic-cfggen -d --print-data")
        links = native_json("ip -j link show")
        for alias in owned_svis:
            if config.get("VLAN", {}).get(alias, {}).get(
                    "admin_status") != "down":
                return False
            matches = [row for row in links if row.get("ifname") == alias]
            if len(matches) != 1 or "UP" in matches[0].get("flags", []):
                return False
            observed = native_json(
                "show interface {} vrf all json".format(alias), frr=True)
            rows = [node[alias] for node in walk_json(observed)
                    if isinstance(node, dict) and alias in node
                    and isinstance(node[alias], dict)]
            if len(rows) != 1 or rows[0].get("administrativeStatus") != "down":
                return False
        return parents_alive()

    if owned_svis and not wait_until(30, 1, 0, svis_down):
        raise RuntimeError("Feature SVIs did not quiesce with live VNI parents")


@pytest.fixture(scope="module")
def evpn_mh_config_checkpoint(evpn_mh_duts, evpn_mh_capability_preflight,
                              evpn_mh_topology):
    """Capture/checkpoint the stock SONiC baseline before EOS is mutated.

    ``evpn_mh_eos_configured`` depends on this fixture so teardown order is
    EOS exact restore first, then SONiC rollback and stock BGP/SWSS proof.
    """
    snapshots = {
        role: {
            "running": _canonical_config_db(dut),
            "persistent": _canonical_persistent_config_db(dut),
            "bgp_peers": _bgp_peer_states(dut),
            "swss_processes": _swss_process_states(dut),
        }
        for role, dut in sorted(evpn_mh_duts.items())
    }
    mismatched = [
        role for role, snapshot in snapshots.items()
        if snapshot["running"] != snapshot["persistent"]
    ]
    if mismatched:
        pytest.fail(
            "running and persistent CONFIG_DB differ before mutation on {}"
            .format(", ".join(mismatched))
        )
    unhealthy = []
    required_swss = ("orchagent", "intfmgrd", "portmgrd")
    for role, dut in sorted(evpn_mh_duts.items()):
        snapshot = snapshots[role]
        down_peers = [
            peer for peer, state in snapshot["bgp_peers"].items()
            if state.strip().lower() != "established"
        ]
        if down_peers:
            unhealthy.append("{} BGP peers not established: {}".format(
                role, ", ".join(down_peers)))
        for process in required_swss:
            if snapshot["swss_processes"].get(process) != "RUNNING":
                unhealthy.append("{} SWSS {} is not RUNNING".format(
                    role, process))
        if not _critical_services_ready(dut):
            unhealthy.append("{} critical services are not fully started".format(
                role))
    if unhealthy:
        pytest.fail(
            "DUT checkpoint baseline is not operational: {}".format(
                "; ".join(unhealthy)))
    created = []
    for role, dut in evpn_mh_duts.items():
        result = dut.shell(
            "sudo config checkpoint {}".format(CHECKPOINT_NAME),
            module_ignore_errors=True,
        )
        if result.get("rc", 1) != 0:
            detail = "\n".join(
                str(result.get(field, "")) for field in ("stderr", "stdout", "msg")
            )
            cleanup_failures = []
            for _created_role, created_dut in created:
                deleted = created_dut.shell(
                    "sudo config delete-checkpoint {}".format(CHECKPOINT_NAME),
                    module_ignore_errors=True,
                )
                if deleted.get("rc", 1) != 0:
                    cleanup_failures.append(created_dut.hostname)
            cleanup_detail = (
                "; setup checkpoint deletion also failed on {}".format(
                    ", ".join(cleanup_failures)
                ) if cleanup_failures else ""
            )
            pytest.fail(
                "{} lacks required checkpoint capability: {}{}".format(
                    role, detail.strip(), cleanup_detail
                )
            )
        created.append((role, dut))

    yield

    failures = []
    for role, dut in created:
        try:
            _quiesce_feature_dependencies(
                dut, role, evpn_mh_topology, snapshots[role]["running"])
        except RuntimeError as error:
            failures.append(
                "{} dependency cleanup failed; checkpoint preserved: {}".format(
                    dut.hostname, error))
            continue
        rollback = dut.shell(
            "sudo config rollback {}".format(CHECKPOINT_NAME),
            module_ignore_errors=True,
        )
        if rollback.get("rc", 1) != 0:
            failures.append(
                "{} rollback failed; checkpoint preserved: {}".format(
                    dut.hostname,
                    rollback.get("stderr", rollback.get("stdout", "")),
                )
            )
            continue
        try:
            # Checkpoint rollback restores CONFIG_DB MUX_CABLE rows, but
            # caclmgrd does not subscribe to those CONFIG_DB changes.  Force
            # one re-render and prove readiness before accepting the restored
            # dualtor baseline.
            restart_caclmgrd(dut)
        except RuntimeError as error:
            failures.append(
                "{} restored MUX ACL rendering failed; checkpoint preserved: {}"
                .format(dut.hostname, error)
            )
            continue
        if not wait_until(
                180, 5, 0, _checkpoint_runtime_ready,
                dut, snapshots[role]):
            failures.append(
                "{} rollback did not restore exact live CONFIG_DB, stock BGP "
                "peer state, SWSS process state, and critical-service health; "
                "checkpoint preserved".format(dut.hostname)
            )
            continue
        saved = dut.shell("sudo config save -y", module_ignore_errors=True)
        if saved.get("rc", 1) != 0:
            failures.append(
                "{} restored CONFIG_DB could not be persisted; checkpoint "
                "preserved: {}".format(
                    dut.hostname,
                    saved.get("stderr", saved.get("stdout", "")),
                )
            )
            continue
        if not wait_until(
                30, 2, 0, _checkpoint_restore_ready,
                dut, snapshots[role]):
            failures.append(
                "{} persistent CONFIG_DB differs after restore; checkpoint "
                "preserved".format(dut.hostname)
            )
            continue
        deleted = dut.shell(
            "sudo config delete-checkpoint {}".format(CHECKPOINT_NAME),
            module_ignore_errors=True,
        )
        if deleted.get("rc", 1) != 0:
            failures.append("{} delete-checkpoint: {}".format(
                dut.hostname, deleted.get("stderr", deleted.get("stdout", ""))
            ))
    if failures:
        pytest.fail("EVPN-MH checkpoint cleanup failed: {}".format(
            "; ".join(failures)
        ))


@pytest.fixture(scope="module")
def evpn_mh_ptf_lags(ptfhost, evpn_mh_ptf_ports, evpn_mh_topology,
                     evpn_mh_duts, evpn_mh_dut_configured,
                     evpn_mh_dualtor_wiring):
    """Create every declared Linux bond after OVS isolation and DUT LAGs."""
    segments = ethernet_segments(evpn_mh_topology)
    configured = []
    try:
        bonds = {}
        for name, segment in segments.items():
            # Append before mutation so a partial configure is still cleaned.
            configured.append(segment)
            bonds[name] = configure_ptf_segment(
                ptfhost, evpn_mh_ptf_ports, segment,
                evpn_mh_topology["endpoints"], evpn_mh_duts,
            )
        yield bonds
    finally:
        failures = []
        for segment in reversed(configured):
            try:
                remove_ptf_segment(ptfhost, evpn_mh_ptf_ports, segment)
            except Exception as error:
                failures.append(str(error))
        agent = ptfhost.shell(
            "supervisorctl restart ptf_nn_agent", module_ignore_errors=True
        )
        if agent.get("rc", 1) != 0:
            failures.append("ptf_nn_agent restart failed")
        if failures:
            pytest.fail("PTF LAG cleanup failed: {}".format("; ".join(failures)))


@pytest.fixture(scope="module")
def evpn_mh_ptf_lag(evpn_mh_ptf_lags, evpn_mh_topology):
    """Compatibility accessor for cases that deliberately target one ES."""
    primary = evpn_mh_topology["primary_test_segment"]
    try:
        return evpn_mh_ptf_lags[primary]
    except KeyError as error:
        raise RuntimeError(
            "primary_test_segment {!r} has no configured PTF bond".format(
                primary)
        ) from error


@pytest.fixture(scope="module")
def evpn_mh_routed_egress(evpn_mh_control_plane, evpn_mh_remote_eos,
                          evpn_mh_topology):
    """Resolve remote routed egress only for cases that send routed traffic.

    Depend on the configured control plane so Vlan20 exists.  This fixture
    adds read-only packet expectation facts and never changes a device.
    """
    topology = evpn_mh_topology
    previous = topology.get("routed_egress_macs")
    present = "routed_egress_macs" in topology
    vlan = int(topology["remote_vlan"])
    mac = eos_svi_egress_mac(evpn_mh_remote_eos, vlan)
    topology["routed_egress_macs"] = {"remote_leaf": {str(vlan): mac}}
    try:
        yield topology["routed_egress_macs"]
    finally:
        if present:
            topology["routed_egress_macs"] = previous
        else:
            topology.pop("routed_egress_macs", None)


@pytest.fixture(scope="module")
def evpn_mh_control_plane(evpn_mh_duts, evpn_mh_remote_eos,
                          evpn_mh_topology, evpn_mh_configured):
    """Require local SONiC EVPN JSON support; EOS checks stay EOS-specific."""
    failures = []
    leaf_roles = ("mh_leaf0", "mh_leaf1")
    for role, duthost in evpn_mh_duts.items():
        try:
            summary = command_json(duthost, "show bgp l2vpn evpn summary json")
            command_json(duthost, "show bgp l2vpn evpn route json")
            command_json(duthost, "show evpn vni json")
            command_json(duthost, "show evpn es json")
        except CommandUnavailableError as error:
            failures.append("{}: {}".format(role, error))
            continue
        peer_role = next(item for item in leaf_roles if item != role)
        expected = {
            evpn_mh_topology["vtep_ip"][peer_role],
            evpn_mh_topology["vtep_ip"]["remote_leaf"],
        }
        missing = expected - established_peers(summary)
        if missing:
            failures.append("{} lacks established EVPN peers {}".format(
                role, ", ".join(sorted(missing))))
    try:
        evidence = collect_remote_eos_evidence(evpn_mh_remote_eos)
        expected = {
            evpn_mh_topology["vtep_ip"]["mh_leaf0"],
            evpn_mh_topology["vtep_ip"]["mh_leaf1"],
        }
        missing = expected - eos_established_peers(evidence["summary"])
        if missing:
            failures.append(
                "remote EOS lacks established EVPN peers {}".format(
                    ", ".join(sorted(missing))))
        for vni in (
                evpn_mh_topology["l2vni"],
                evpn_mh_topology["remote_l2vni"],
                evpn_mh_topology["l3vni"]):
            if not eos_contains_value(evidence["vni"], vni):
                failures.append("remote EOS lacks VNI {}".format(vni))
    except EosOverlayError as error:
        failures.append("remote EOS: {}".format(error))
    if failures:
        pytest.fail("EVPN-MH control-plane capability failed: {}".format(
            "; ".join(failures)
        ))
    return evpn_mh_duts


@pytest.fixture(scope="module")
def evpn_mh_dut_configured(evpn_mh_duts, evpn_mh_interfaces,
                           evpn_mh_topology,
                           evpn_mh_clean_start, evpn_mh_config_checkpoint,
                           evpn_mh_dualtor_wiring,
                           evpn_mh_eos_configured):
    """Configure the two SONiC MH leaves after independent legs exist.

    EOS/underlay provisioning is owned by ``evpn_mh_eos_configured``; no EOS
    object is inserted into ``evpn_mh_duts`` as a fake SONiC host.
    """
    configure_evpn_mh(evpn_mh_duts, evpn_mh_interfaces, evpn_mh_topology)
    return True


@pytest.fixture(scope="module")
def evpn_mh_configured(evpn_mh_duts, evpn_mh_ptf_lag, evpn_mh_topology,
                       evpn_mh_remote_eos):
    if not wait_evpn_mh_overlay(evpn_mh_duts, evpn_mh_topology, timeout=240):
        raise RuntimeError("EVPN-MH overlay did not converge after PTF LACP setup")
    expected_remote_peers = {
        evpn_mh_topology["vtep_ip"]["mh_leaf0"],
        evpn_mh_topology["vtep_ip"]["mh_leaf1"],
    }
    if not wait_until(
            60, 5, 0, eos_evpn_peers_ready,
            evpn_mh_remote_eos, expected_remote_peers):
        raise RuntimeError(
            "A04 did not establish EVPN peers {}".format(
                ", ".join(sorted(expected_remote_peers))))
    return True
