"""Baseline EVPN-MH dataplane cases."""

import pytest

from .eos_overlay import (collect_remote_eos_evidence, eos_aliasing_vteps,
                          eos_contains_value, eos_established_peers)
from .operations import wait_until
from .state import (CommandUnavailableError, app_db_route_nexthops,
                    command_json, contains_prefix, ethernet_segment,
                    json_contains_host, json_contains_value,
                    neighbor_matches, route_nexthop_count, segment_is_df,
                    vni_is_present)
from .traffic import run_traffic_profile


pytestmark = [
    pytest.mark.topology("dualtor"),
    pytest.mark.dualtor_skip_setup_mux_ports,
    pytest.mark.skip_check_dut_health,
    pytest.mark.sanity_check(check_items=["-check_bgp"]),
]


def _segment_df_endpoints(duts, definition):
    """Return the exact DF and NDF PTF roles for one Ethernet Segment."""
    states = {}
    for role in definition["leaf_roles"]:
        observed = ethernet_segment(
            command_json(duts[role], "show evpn es json"), definition["esi"])
        assert observed is not None, "{} is absent on {}".format(
            definition["esi"], role)
        states[role] = segment_is_df(observed)
    assert list(states.values()).count(True) == 1, (
        "{} must have exactly one DF".format(definition["esi"]))
    df_role = next(role for role, is_df in states.items() if is_df)
    ndf_role = next(role for role, is_df in states.items() if not is_df)
    role_to_member = dict(zip(
        definition["leaf_roles"], definition["ptf_member_roles"]))
    return role_to_member[df_role], role_to_member[ndf_role]


def _df_runtime(duts, topology):
    """Build same-VLAN BUM expectations for every declared local ES."""
    receive_groups = [["sh1"]]
    forbidden_endpoints = []
    for name, definition in sorted(topology["ethernet_segments"].items()):
        if int(definition["vlan"]) != int(topology["mh_vlan"]):
            continue
        df_endpoint, ndf_endpoint = _segment_df_endpoints(duts, definition)
        receive_groups.append([df_endpoint])
        forbidden_endpoints.append(ndf_endpoint)
    assert len(receive_groups) > 1, "BUM VLAN has no Ethernet Segment"
    return {
        "flow_overrides": {
            "h3_remote_broadcast": {
                "receive_groups": receive_groups,
                "forbidden_endpoints": forbidden_endpoints,
            },
            "h3_remote_multicast": {
                "receive_groups": receive_groups,
                "forbidden_endpoints": forbidden_endpoints,
            },
            "h3_remote_unknown_unicast": {
                "receive_groups": receive_groups,
                "forbidden_endpoints": forbidden_endpoints,
            },
            "h3_ipv6_broadcast": {
                "receive_groups": receive_groups,
                "forbidden_endpoints": forbidden_endpoints,
            },
            "h3_ipv6_unknown_unicast": {
                "receive_groups": receive_groups,
                "forbidden_endpoints": forbidden_endpoints,
            },
        }
    }


def _required_json(dut, command, capability):
    try:
        return command_json(dut, command)
    except CommandUnavailableError as error:
        pytest.fail("{} JSON capability unavailable: {}".format(
            capability, error))


def _assert_bum_control_plane(duts, remote_eos, topology):
    """Require the exact L2VNI, IMET and remote-VTEP state behind BUM."""
    _df_runtime(duts, topology)
    for role, dut in duts.items():
        vnis = _required_json(dut, "show evpn vni json", "EVPN VNI")
        assert vni_is_present(vnis, topology["l2vni"]), (
            "{} is missing L2VNI {}".format(role, topology["l2vni"]))
        imet = _required_json(
            dut, "show bgp l2vpn evpn route type multicast json",
            "EVPN Type-3/IMET")
        expected_remote_roles = [
            remote_role for remote_role in topology["vtep_ip"]
            if remote_role != role]
        for remote_role in expected_remote_roles:
            remote_vtep = topology["vtep_ip"][remote_role]
            assert json_contains_value(imet, remote_vtep), (
                "{} is missing Type-3/IMET VTEP {}".format(
                    role, remote_vtep))
            underlay = _required_json(
                dut, "show ip route {}/32 json".format(remote_vtep),
                "remote VTEP reachability")
            assert route_nexthop_count(underlay) > 0, (
                "{} cannot reach remote VTEP {}".format(role, remote_vtep))

    evidence = collect_remote_eos_evidence(remote_eos)
    expected = {
        topology["vtep_ip"]["mh_leaf0"],
        topology["vtep_ip"]["mh_leaf1"],
    }
    missing = expected - eos_established_peers(evidence["summary"])
    assert not missing, (
        "remote EOS lacks established EVPN peers {}".format(
            ", ".join(sorted(missing))))
    assert eos_contains_value(evidence["vni"], topology["l2vni"]), (
        "remote EOS lacks L2VNI {}".format(topology["l2vni"]))
    for role in ("mh_leaf0", "mh_leaf1"):
        assert eos_contains_value(
            evidence["routes"], topology["vtep_ip"][role]), (
                "remote EOS lacks EVPN route evidence for {}".format(role))


def _l3_control_plane_ready(duts, remote_eos, topology):
    """Return the exact Type-5, host, APP_DB, neighbor and NHG readiness."""
    mh_prefix = topology["mh_ipv4_prefix"]
    remote_prefix = topology["remote_ipv4_prefix"]
    mh_endpoints = [
        topology["endpoints"][definition["endpoint"]]
        for definition in topology["ethernet_segments"].values()
    ]
    h4 = topology["endpoints"]["h4"]

    for role in ("mh_leaf0", "mh_leaf1"):
        dut = duts[role]
        type5 = command_json(
            dut, "show bgp l2vpn evpn route type prefix json")
        if not contains_prefix(type5, remote_prefix):
            return False
        type2 = command_json(
            dut, "show bgp l2vpn evpn route type macip json")
        if not json_contains_host(type2, h4["mac"], h4["ipv4"]):
            return False
        for endpoint in mh_endpoints:
            if not neighbor_matches(
                    dut, topology["mh_vlan"], endpoint["ipv4"],
                    endpoint["mac"]):
                return False
        if app_db_route_nexthops(
                dut, topology["vrf"], remote_prefix) != {
                    topology["vtep_ip"]["remote_leaf"]}:
            return False

    evidence = collect_remote_eos_evidence(remote_eos)
    if not eos_contains_value(evidence["routes"], mh_prefix):
        return False
    expected_vteps = {
        topology["vtep_ip"]["mh_leaf0"],
        topology["vtep_ip"]["mh_leaf1"],
    }
    for endpoint in mh_endpoints:
        if not (eos_contains_value(evidence["routes"], endpoint["mac"])
                and eos_contains_value(evidence["routes"], endpoint["ipv4"])
                and eos_contains_value(evidence["fdb"], endpoint["mac"])):
            return False
        if eos_aliasing_vteps(
                evidence["routes"], endpoint["mac"],
                expected_vteps) != expected_vteps:
            return False
    return True


def _l2_control_plane_ready(duts, remote_eos, topology):
    sh1 = topology["endpoints"]["sh1"]
    leaf1_type2 = command_json(
        duts["mh_leaf1"], "show bgp l2vpn evpn route type macip json")
    if not json_contains_host(leaf1_type2, sh1["mac"], sh1["ipv4"]):
        return False
    evidence = collect_remote_eos_evidence(remote_eos)
    expected_vteps = {
        topology["vtep_ip"]["mh_leaf0"],
        topology["vtep_ip"]["mh_leaf1"],
    }
    for definition in topology["ethernet_segments"].values():
        endpoint = topology["endpoints"][definition["endpoint"]]
        if not (eos_contains_value(evidence["routes"], endpoint["mac"])
                and eos_contains_value(evidence["routes"], endpoint["ipv4"])
                and eos_contains_value(evidence["fdb"], endpoint["mac"])):
            return False
        if eos_aliasing_vteps(
                evidence["routes"], endpoint["mac"],
                expected_vteps) != expected_vteps:
            return False
    return True


def test_remote_broadcast_traffic(ptfhost, evpn_mh_ptf_lag, evpn_mh_ptf_ports,
                                  evpn_mh_control_plane, evpn_mh_remote_eos,
                                  evpn_mh_topology):
    _assert_bum_control_plane(
        evpn_mh_control_plane, evpn_mh_remote_eos, evpn_mh_topology)
    run_traffic_profile(ptfhost, "remote_broadcast", evpn_mh_ptf_ports,
                        evpn_mh_topology,
                        _df_runtime(evpn_mh_control_plane, evpn_mh_topology))


def test_remote_multicast_traffic(ptfhost, evpn_mh_ptf_lag, evpn_mh_ptf_ports,
                                  evpn_mh_control_plane, evpn_mh_remote_eos,
                                  evpn_mh_topology):
    _assert_bum_control_plane(
        evpn_mh_control_plane, evpn_mh_remote_eos, evpn_mh_topology)
    run_traffic_profile(ptfhost, "remote_multicast", evpn_mh_ptf_ports,
                        evpn_mh_topology,
                        _df_runtime(evpn_mh_control_plane, evpn_mh_topology))


def test_unknown_unicast(ptfhost, evpn_mh_ptf_lag, evpn_mh_ptf_ports,
                         evpn_mh_control_plane, evpn_mh_remote_eos,
                         evpn_mh_topology):
    _assert_bum_control_plane(
        evpn_mh_control_plane, evpn_mh_remote_eos, evpn_mh_topology)
    run_traffic_profile(ptfhost, "remote_unknown_unicast", evpn_mh_ptf_ports,
                        evpn_mh_topology,
                        _df_runtime(evpn_mh_control_plane, evpn_mh_topology))


def test_inter_subnet_ping(ptfhost, evpn_mh_ptf_lag, evpn_mh_ptf_ports,
                           evpn_mh_control_plane, evpn_mh_remote_eos,
                           evpn_mh_topology, evpn_mh_routed_egress):
    run_traffic_profile(ptfhost, "inter_subnet", evpn_mh_ptf_ports, evpn_mh_topology)
    try:
        assert wait_until(
            90, 3, 0, _l3_control_plane_ready,
            evpn_mh_control_plane, evpn_mh_remote_eos,
            evpn_mh_topology), (
                "exact Type-5, host, APP_DB route, neighbor, FDB and NHG "
                "state did not converge")
    except CommandUnavailableError as error:
        pytest.fail("EVPN Type-2/Type-5 JSON capability unavailable: {}".format(error))


def test_intra_subnet_ping(ptfhost, evpn_mh_ptf_lag, evpn_mh_ptf_ports,
                           evpn_mh_control_plane, evpn_mh_remote_eos,
                           evpn_mh_topology):
    run_traffic_profile(ptfhost, "intra_subnet", evpn_mh_ptf_ports, evpn_mh_topology)
    try:
        assert wait_until(
            90, 3, 0, _l2_control_plane_ready,
            evpn_mh_control_plane, evpn_mh_remote_eos,
            evpn_mh_topology), (
                "exact remote MAC/FDB/L2 next-hop-group state did not converge")
    except CommandUnavailableError as error:
        pytest.fail("EVPN Type-2 JSON capability unavailable: {}".format(error))
