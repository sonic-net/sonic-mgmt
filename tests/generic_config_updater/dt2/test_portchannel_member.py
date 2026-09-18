"""
GCU PortChannel member coverage for a disaggregated T2 (UT2 / LT2, non-chassis).

Adding capacity towards a neighbor means adding members to an existing PortChannel via
GCU. A test cannot create new physical links, so it exercises the same operation in
reverse first: it removes one member of the LAG towards an existing neighbor via GCU,
verifies the LAG, the BGP session and forwarding survive on the remaining members and
the removed port carries no traffic, then adds the member back via GCU and verifies it
rejoins the LAG and forwards again.

Parametrized over the uplink (T3: AZNGHub, RegionalHub) and downstream (LowerSpineRouter,
T1 LeafRouter) scenarios shared with test_add_t3.py and test_add_downstream.py; each
scenario skips unless that neighbor is reached over a PortChannel with >= 2 members.
Forwarding is probed towards the neighbor's own link address, which always egresses over
the PortChannel regardless of which BGP prefixes the neighbor forwards.
"""
import ipaddress
import logging
import pytest
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.utilities import wait_until
from tests.generic_config_updater.dt2.dt2_helpers import (
    DOWNSTREAM_SCENARIOS,
    LOGANALYZER_IGNORE_REGEX,
    T3_SCENARIOS,
    apply_patch_or_assert,
    assert_peer_config_state,
    collect_portchannel_member_entries,
    compute_egress_ptf_ports,
    json_namespace_prefix,
    pick_prefix_for_neighbor,
    pick_target_neighbor,
    pick_upstream_src_asic,
    verify_forwarding,
    verify_prefix_present,
)

pytestmark = [
    pytest.mark.topology("ut2", "t2", "lt2"),
]

logger = logging.getLogger(__name__)
allure.logger = logger

PORTCHANNEL_SCENARIOS = T3_SCENARIOS + DOWNSTREAM_SCENARIOS

LAG_SETTLE_TIMEOUT = 90


def lag_members_selected(duthost, portchannel, members, expected=True):
    """
    With ``expected=True``: every port in ``members`` is a selected, link-up member of the
    LAG according to teamd. With ``expected=False``: none of them is a member at all.
    """
    ports = duthost.get_port_channel_status(portchannel).get("ports", {})
    observed = {
        member: (
            member in ports
            and bool(ports[member].get("runner", {}).get("selected"))
            and bool(ports[member].get("link", {}).get("up"))
        )
        for member in members
    }
    logger.info("LAG %s member state (selected and up): %s", portchannel, observed)
    if expected:
        return all(observed.values())
    return not any(member in ports for member in members)


def lag_oper_status(duthost, portchannel):
    """Operational state of the LAG as programmed in APPL_DB ("up" / "down")."""
    out = duthost.shell(f'sonic-db-cli APPL_DB HGET "LAG_TABLE:{portchannel}" oper_status', module_ignore_errors=True)
    status = out["stdout"].strip().lower()
    logger.info("LAG %s oper_status=%s", portchannel, status or "<missing>")
    return status


def build_member_patch(config_facts_localhost, mg_facts, namespace, neighbor_ctx, member, op):
    """
    GCU patch that removes or adds one PORTCHANNEL_MEMBER row for ``member``. On multi-ASIC
    DUTs the row also exists in the localhost view (keyed by port alias), so the patch
    carries both, mirroring ``build_remove_patch`` / ``build_add_patches``.
    """
    portchannel = neighbor_ctx["port"]
    entry = {
        "op": op,
        "path": f"{json_namespace_prefix(namespace)}/PORTCHANNEL_MEMBER/{portchannel}|{member}",
    }
    if op == "add":
        entry["value"] = {}
    patch = [entry]
    if namespace is not None:
        alias = mg_facts["minigraph_port_name_to_alias_map"].get(member, member)
        localhost_pc = neighbor_ctx["port_localhost"]
        localhost_members = config_facts_localhost.get("PORTCHANNEL_MEMBER", {}).get(localhost_pc, {})
        if alias in localhost_members or member in localhost_members:
            localhost_entry = {"op": op, "path": f"/localhost/PORTCHANNEL_MEMBER/{localhost_pc}|{alias}"}
            if op == "add":
                localhost_entry["value"] = {}
            patch.append(localhost_entry)
    return patch


@pytest.fixture(scope="function", params=PORTCHANNEL_SCENARIOS, ids=[s["id"] for s in PORTCHANNEL_SCENARIOS])
def pc_scenario(request):
    return request.param


@pytest.fixture(scope="function")
def selected_portchannel_neighbor(mg_facts, config_facts, config_facts_localhost, pc_scenario):
    neighbor_ctx = pick_target_neighbor(config_facts, config_facts_localhost, mg_facts, pc_scenario)
    if not neighbor_ctx["is_portchannel"] or len(neighbor_ctx["member_ports"]) < 2:
        pytest.skip(
            "Peer {} is reached over {} with members {}; a PortChannel with at least two "
            "members is required".format(
                neighbor_ctx["neighbor_name"], neighbor_ctx["port"], neighbor_ctx["member_ports"],
            )
        )
    return neighbor_ctx


def test_portchannel_member_remove_and_readd(
    tbinfo,
    duthosts,
    ptfadapter,
    loganalyzer,
    enum_downstream_dut_hostname,
    enum_upstream_dut_hostname,
    enum_rand_one_frontend_asic_index,
    enum_rand_one_asic_namespace,
    mg_facts,
    config_facts,
    config_facts_localhost,
    pc_scenario,
    selected_portchannel_neighbor,
):
    """
    1. Select the scenario's neighbor, reached over a PortChannel with >= 2 members, and
       pick its last member (sorted) to cycle.
    2. Baseline: all members selected in teamd, BGP established, a prefix learned via the
       neighbor, traffic towards the neighbor's link address forwarded over the LAG.
    3. Remove the member via GCU; assert: PORTCHANNEL_MEMBER row gone, teamd no longer
       lists the port. Then, depending on the LAG's min_links:
         * remaining members >= min_links: LAG stays up, remaining members stay selected,
           BGP stays established, prefix stays present, traffic keeps flowing on the
           remaining members and none reaches the removed port;
         * remaining members < min_links: the LAG goes down by design, the BGP session
           drops and no traffic reaches any member.
    4. Add the member back via GCU; assert: row restored, LAG up, port selected again, BGP
       established, traffic forwarded across all members.
    5. ``config save`` on success; ``config_reload`` always runs in ``finally``.
    """
    duthost = duthosts[enum_downstream_dut_hostname]
    dut_basic_facts = duthost.dut_basic_facts()["ansible_facts"]["dut_basic_facts"]
    if dut_basic_facts.get("is_chassis"):
        pytest.skip("Disaggregated-T2 PortChannel member workflow is skipped on chassis systems")
    duthost_up = duthosts[enum_upstream_dut_hostname]
    dst_asic = enum_rand_one_frontend_asic_index
    namespace = enum_rand_one_asic_namespace
    neighbor_ctx = selected_portchannel_neighbor
    portchannel = neighbor_ctx["port"]
    members = list(neighbor_ctx["member_ports"])
    cycled = members[-1]
    remaining = members[:-1]
    min_links = int(config_facts.get("PORTCHANNEL", {}).get(portchannel, {}).get("min_links", 1))
    lag_survives = len(remaining) >= min_links
    logger.info(
        "scenario=%s: GCU member cycle on %s towards %s: remove/re-add %s, keep %s (min_links=%d, LAG %s removal)",
        pc_scenario["id"], portchannel, neighbor_ctx["neighbor_name"], cycled, remaining, min_links,
        "survives" if lag_survives else "goes down on",
    )

    member_rows = collect_portchannel_member_entries(config_facts, neighbor_ctx)
    cycled_key = f"{portchannel}|{cycled}"
    pytest_assert(cycled_key in member_rows, f"{cycled_key} not found in PORTCHANNEL_MEMBER config facts")
    rows_without_cycled = {key: value for key, value in member_rows.items() if key != cycled_key}

    src_asic_on_upstream = pick_upstream_src_asic(duthost_up, duthost, dst_asic)
    target = pick_prefix_for_neighbor(duthost, dst_asic, neighbor_ctx, ip_version=4)
    pytest_assert(target, f"No IPv4 BGP prefix learned via neighbor {neighbor_ctx['neighbor_name']}")
    probe_dst = next(ip for ip in neighbor_ctx["neighbor_ips"] if ipaddress.ip_address(ip).version == 4)
    ptf_all, _ = compute_egress_ptf_ports(mg_facts, neighbor_ctx)
    ptf_remaining, _ = compute_egress_ptf_ports(mg_facts, dict(neighbor_ctx, member_ports=remaining))
    ptf_cycled, _ = compute_egress_ptf_ports(mg_facts, dict(neighbor_ctx, member_ports=[cycled]))

    def send_traffic(ptf_ports, expect_traffic):
        verify_forwarding(tbinfo, duthost_up, src_asic_on_upstream, ptfadapter, neighbor_ctx, ptf_ports, probe_dst,
                          expect_traffic)

    with allure.step(f"Verify baseline LAG, BGP and forwarding state for {portchannel}"):
        pytest_assert(
            wait_until(LAG_SETTLE_TIMEOUT, 5, 0, lag_members_selected, duthost, portchannel, members),
            f"Not all members {members} of {portchannel} are selected and up before the test",
        )
        pytest_assert(
            wait_until(120, 10, 0, duthost.check_bgp_session_state, neighbor_ctx["neighbor_ips"]),
            f"BGP sessions with {neighbor_ctx['neighbor_ips']} not established before the test",
        )
        pytest_assert(
            verify_prefix_present(duthost, dst_asic, target, neighbor_ctx, should_exist=True),
            f"Expected prefix {target['prefix']} via {neighbor_ctx['neighbor_name']} before the test",
        )
        send_traffic(ptf_all, expect_traffic=True)

    la_entry = loganalyzer[duthost.hostname] if loganalyzer else None
    if la_entry:
        la_entry.ignore_regex.extend(LOGANALYZER_IGNORE_REGEX)
    try:
        with allure.step(f"Remove member {cycled} from {portchannel} via GCU and validate"):
            apply_patch_or_assert(
                duthost,
                build_member_patch(config_facts_localhost, mg_facts, namespace, neighbor_ctx, cycled, "remove"),
            )
            assert_peer_config_state(
                duthost, namespace, neighbor_ctx,
                {"PORTCHANNEL_MEMBER": rows_without_cycled},
                {"PORTCHANNEL_MEMBER": {cycled_key}},
                "post-member-remove",
            )
            pytest_assert(
                wait_until(LAG_SETTLE_TIMEOUT, 5, 0, lag_members_selected, duthost, portchannel, [cycled], False),
                f"teamd still lists {cycled} as a member of {portchannel} after GCU removal",
            )
            if lag_survives:
                pytest_assert(
                    lag_members_selected(duthost, portchannel, remaining),
                    f"Remaining members {remaining} of {portchannel} must stay selected after removing {cycled}",
                )
                pytest_assert(
                    lag_oper_status(duthost, portchannel) == "up",
                    f"{portchannel} must stay up with {len(remaining)} member(s) >= min_links {min_links}",
                )
                pytest_assert(
                    duthost.check_bgp_session_state(neighbor_ctx["neighbor_ips"]),
                    f"BGP sessions with {neighbor_ctx['neighbor_ips']} must survive removing one LAG member",
                )
                pytest_assert(
                    verify_prefix_present(duthost, dst_asic, target, neighbor_ctx, should_exist=True),
                    f"Prefix {target['prefix']} via {neighbor_ctx['neighbor_name']} must survive removing one member",
                )
                send_traffic(ptf_remaining, expect_traffic=True)
                send_traffic(ptf_cycled, expect_traffic=False)
            else:
                pytest_assert(
                    wait_until(LAG_SETTLE_TIMEOUT, 5, 0, lambda: lag_oper_status(duthost, portchannel) == "down"),
                    f"{portchannel} must go down with {len(remaining)} member(s) < min_links {min_links}",
                )
                pytest_assert(
                    wait_until(120, 10, 0, lambda: not duthost.check_bgp_session_state(neighbor_ctx["neighbor_ips"])),
                    f"BGP sessions with {neighbor_ctx['neighbor_ips']} must drop once {portchannel} is down",
                )
                send_traffic(ptf_all, expect_traffic=False)

        with allure.step(f"Add member {cycled} back to {portchannel} via GCU and validate"):
            apply_patch_or_assert(
                duthost,
                build_member_patch(config_facts_localhost, mg_facts, namespace, neighbor_ctx, cycled, "add"),
            )
            assert_peer_config_state(
                duthost, namespace, neighbor_ctx, {"PORTCHANNEL_MEMBER": member_rows}, {}, "post-member-add",
            )
            pytest_assert(
                wait_until(LAG_SETTLE_TIMEOUT, 5, 0, lag_members_selected, duthost, portchannel, members),
                f"{cycled} did not rejoin {portchannel} as a selected, link-up member after GCU add",
            )
            pytest_assert(
                wait_until(LAG_SETTLE_TIMEOUT, 5, 0, lambda: lag_oper_status(duthost, portchannel) == "up"),
                f"{portchannel} did not come up after re-adding {cycled}",
            )
            pytest_assert(
                wait_until(120, 10, 0, duthost.check_bgp_session_state, neighbor_ctx["neighbor_ips"]),
                f"BGP sessions with {neighbor_ctx['neighbor_ips']} not established after re-adding {cycled}",
            )
            pytest_assert(
                verify_prefix_present(duthost, dst_asic, target, neighbor_ctx, should_exist=True),
                f"Prefix {target['prefix']} via {neighbor_ctx['neighbor_name']} missing after re-adding {cycled}",
            )
            send_traffic(ptf_all, expect_traffic=True)

        with allure.step("Persist the restored configuration"):
            duthost.shell("config save -y")
    finally:
        # Reload the last persisted configuration even when a validation fails after the
        # member has been removed. Only the reload window is hidden from the loganalyzer.
        if la_entry:
            la_entry.add_start_ignore_mark()
        try:
            config_reload(duthost, config_source="config_db", safe_reload=True)
        finally:
            if la_entry:
                la_entry.add_end_ignore_mark()
