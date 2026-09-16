import logging
import pytest
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.utilities import wait_until
from tests.generic_config_updater.add_cluster.ut2_helpers import (
    apply_patch_or_assert,
    assert_peer_config_state,
    build_add_expectations,
    build_add_patches,
    build_remove_expectations,
    build_remove_patch,
    compute_egress_ptf_ports,
    pick_prefix_for_neighbor,
    pick_target_neighbor,
    pick_upstream_src_asic,
    send_and_verify_traffic_with_retry,
    send_v6_and_verify_with_retry,
    verify_prefix_present,
)

pytestmark = [
    pytest.mark.topology("ut2", "t2"),
]


logger = logging.getLogger(__name__)
allure.logger = logger

UT2_SCENARIOS = [
    {
        "id": "ut2_rh_ah_ebgp",
        "neighbor_role": "RH_AH",
        "device_types": ["RegionalHub", "AZNGHub"],
        "expect_ebgp": True
    },
    {
        "id": "ut2_lt2_ebgp",
        "neighbor_role": "LT2",
        "device_types": ["LowerSpineRouter"],
        "expect_ebgp": True
    },
]


@pytest.fixture(scope="function")
def initialize_random_variables(
    enum_downstream_dut_hostname,
    enum_upstream_dut_hostname,
    enum_rand_one_frontend_asic_index,
    enum_rand_one_asic_namespace,
    ip_netns_namespace_prefix,
    cli_namespace_prefix,
):
    return (
        enum_downstream_dut_hostname,
        enum_upstream_dut_hostname,
        enum_rand_one_frontend_asic_index,
        enum_rand_one_asic_namespace,
        ip_netns_namespace_prefix,
        cli_namespace_prefix,
    )


@pytest.fixture(scope="function")
def initialize_facts(mg_facts, config_facts, config_facts_localhost):
    return mg_facts, config_facts, config_facts_localhost


@pytest.fixture(scope="function", params=UT2_SCENARIOS, ids=[s["id"] for s in UT2_SCENARIOS])
def ut2_scenario(request):
    return request.param


@pytest.fixture(scope="function")
def selected_ut2_neighbor(initialize_facts, config_facts_localhost, ut2_scenario):
    mg_facts, config_facts, _ = initialize_facts
    return pick_target_neighbor(config_facts, config_facts_localhost, mg_facts, ut2_scenario)


def test_ut2_remove_and_readd_cluster_peer(
    tbinfo,
    duthosts,
    ptfadapter,
    loganalyzer,
    initialize_random_variables,
    initialize_facts,
    ut2_scenario,
    selected_ut2_neighbor,
):
    """
    Remove-and-readd-existing-cluster-peer test for add-cluster GCU coverage on UT2 / T2.
    Per parametrized scenario:
      1. Select an existing BGP neighbor of the expected type
         (RegionalHub / AZNGHub for RH_AH, LowerSpineRouter for LT2).
      2. Find one IPv4 prefix reachable through that neighbor (mandatory) and one IPv6
         prefix (best-effort: when none qualifies the IPv6 checks are skipped).
      3. Remove the peer via a two-stage GCU JSON patch; assert: cluster-peer config removed
         from all relevant tables, PORT/CABLE_LENGTH reflect the reduced state, the prefixes
         are withdrawn and traffic towards them is dropped.
      4. Re-add the same peer via GCU; assert: cluster-peer config restored across the same
         tables, the prefixes are relearned and traffic recovers.
      5. ``config save`` on success; ``config_reload`` always runs in ``finally`` so a
         mid-test failure never leaves the DUT with the peer removed.
    """
    (
        enum_downstream_dut_hostname,
        enum_upstream_dut_hostname,
        enum_rand_one_frontend_asic_index,
        enum_rand_one_asic_namespace,
        _ip_netns_namespace_prefix,
        _cli_namespace_prefix,
    ) = initialize_random_variables
    mg_facts, config_facts, config_facts_localhost = initialize_facts
    duthost = duthosts[enum_downstream_dut_hostname]
    dut_basic_facts = duthost.dut_basic_facts()["ansible_facts"]["dut_basic_facts"]
    if dut_basic_facts.get("is_chassis"):
        pytest.skip("UT2 add-cluster peer workflow is skipped on chassis systems")
    duthost_up = duthosts[enum_upstream_dut_hostname]
    dst_asic = enum_rand_one_frontend_asic_index
    neighbor_ctx = selected_ut2_neighbor
    pytest_assert(
        neighbor_ctx["device_type"] in ut2_scenario["device_types"],
        "Scenario {} expected device_type in {}, got {} for neighbor {}".format(
            ut2_scenario["id"],
            ut2_scenario["device_types"],
            neighbor_ctx["device_type"],
            neighbor_ctx["neighbor_name"],
        ),
    )
    logger.info(
        "scenario=%s role=%s: GCU remove-and-readd of cluster peer %s "
        "(device_type=%s, ebgp=%s, ports=%s)",
        ut2_scenario["id"],
        ut2_scenario["neighbor_role"],
        neighbor_ctx["neighbor_name"],
        neighbor_ctx["device_type"],
        neighbor_ctx["ebgp"],
        neighbor_ctx["neighbor_ports"],
    )
    src_asic_on_upstream = pick_upstream_src_asic(duthost_up, duthost, dst_asic)
    logger.info(
        "Ingress ASIC on upstream DUT %s for peer path to %s: %s "
        "(dst DUT=%s asic=%s)",
        duthost_up.hostname, neighbor_ctx["neighbor_name"],
        src_asic_on_upstream, duthost.hostname, dst_asic,
    )

    prefix, dst_ip, ecmp_path = pick_prefix_for_neighbor(duthost, dst_asic, neighbor_ctx, ip_version=4)
    prefix_v6, dst_ip_v6, ecmp_path_v6 = pick_prefix_for_neighbor(duthost, dst_asic, neighbor_ctx, ip_version=6)
    ptf_dst_ports, ptf_dst_interfaces = compute_egress_ptf_ports(mg_facts, neighbor_ctx)

    expected_add_state = build_add_expectations(config_facts, neighbor_ctx)
    expected_remove_present, expected_remove_absent = build_remove_expectations(config_facts, neighbor_ctx)

    with allure.step(
        f"[{ut2_scenario['id']}] Verify selected {neighbor_ctx['neighbor_role']} "
        f"neighbor and learned prefix before removal"
    ):
        # Control-plane gate: Wait for BGP sessions to establish
        logger.info("Waiting for BGP neighbor sessions to establish")
        bgp_ok = wait_until(120, 10, 0, duthost.check_bgp_session_state, neighbor_ctx["neighbor_ips"])
        pytest_assert(bgp_ok, f"BGP sessions with neighbors {neighbor_ctx['neighbor_ips']} failed to establish")

        assert_peer_config_state(
            duthost,
            enum_rand_one_asic_namespace,
            neighbor_ctx,
            expected_add_state,
            {},
            "pre-remove baseline",
        )
        if prefix:
            pytest_assert(
                verify_prefix_present(duthost, dst_asic, prefix, neighbor_ctx, should_exist=True, ecmp_path=ecmp_path),
                f"Expected learned IPv4 prefix {prefix} from neighbor {neighbor_ctx['neighbor_name']} before removal",
            )
        if prefix_v6:
            pytest_assert(
                verify_prefix_present(
                    duthost, dst_asic, prefix_v6, neighbor_ctx,
                    should_exist=True, ecmp_path=ecmp_path_v6,
                ),
                f"Expected learned IPv6 prefix {prefix_v6} from neighbor "
                f"{neighbor_ctx['neighbor_name']} before removal",
            )
        send_and_verify_traffic_with_retry(
            tbinfo,
            duthost_up,
            duthost,
            src_asic_on_upstream,
            dst_asic,
            ptfadapter,
            ptf_dst_ports=ptf_dst_ports,
            ptf_dst_interfaces=ptf_dst_interfaces,
            dst_ip=dst_ip,
            expect_error=False,
        )
        if prefix_v6:
            send_v6_and_verify_with_retry(
                tbinfo, duthost_up, src_asic_on_upstream, ptfadapter,
                ptf_dst_ports, dst_ip_v6, expect_error=False,
            )

    la_entry = loganalyzer[duthost.hostname] if loganalyzer else None
    if la_entry:
        # Expected, benign errors while a port/LAG is torn down and re-created via GCU.
        la_entry.ignore_regex.extend([
            r"querySwitchLagHashAttrCapabilities",
            r"SRV6.*unsupported",
        ])
    try:
        with allure.step(
            f"[{ut2_scenario['id']}] Remove selected cluster peer via GCU and validate route withdrawal / traffic loss"
        ):
            remove_patch_main, remove_patch_extra = build_remove_patch(
                config_facts,
                config_facts_localhost,
                mg_facts,
                enum_rand_one_asic_namespace,
                neighbor_ctx,
            )
            apply_patch_or_assert(duthost, remove_patch_main)
            if remove_patch_extra:
                apply_patch_or_assert(duthost, remove_patch_extra)
            assert_peer_config_state(
                duthost,
                enum_rand_one_asic_namespace,
                neighbor_ctx,
                expected_remove_present,
                expected_remove_absent,
                "post-remove",
            )
            if prefix:
                pytest_assert(
                    wait_until(60, 5, 0, verify_prefix_present, duthost,
                               dst_asic, prefix, neighbor_ctx, False, ecmp_path),
                    f"IPv4 prefix {prefix} still present after removing neighbor {neighbor_ctx['neighbor_name']}",
                )
            if prefix_v6:
                pytest_assert(
                    wait_until(
                        60, 5, 0, verify_prefix_present,
                        duthost, dst_asic, prefix_v6, neighbor_ctx, False, ecmp_path_v6,
                    ),
                    f"IPv6 prefix {prefix_v6} still present after removing neighbor {neighbor_ctx['neighbor_name']}",
                )

            send_and_verify_traffic_with_retry(
                tbinfo,
                duthost_up,
                duthost,
                src_asic_on_upstream,
                dst_asic,
                ptfadapter,
                ptf_dst_ports=ptf_dst_ports,
                ptf_dst_interfaces=ptf_dst_interfaces,
                dst_ip=dst_ip,
                expect_error=True,
            )
            if prefix_v6:
                send_v6_and_verify_with_retry(
                    tbinfo, duthost_up, src_asic_on_upstream, ptfadapter,
                    ptf_dst_ports, dst_ip_v6, expect_error=True,
                )

        with allure.step(
            f"[{ut2_scenario['id']}] Add selected cluster peer back via GCU and validate route / traffic recovery"
        ):
            patch_pc, patch_rest = build_add_patches(
                config_facts,
                config_facts_localhost,
                mg_facts,
                enum_rand_one_asic_namespace,
                neighbor_ctx,
            )
            if patch_pc:
                apply_patch_or_assert(duthost, patch_pc)
            apply_patch_or_assert(duthost, patch_rest)
            assert_peer_config_state(
                duthost,
                enum_rand_one_asic_namespace,
                neighbor_ctx,
                expected_add_state,
                {},
                "post-add",
            )

            # Control-plane gate: Wait for BGP sessions to establish
            logger.info("Waiting for BGP neighbor sessions to establish after re-add")
            bgp_up = wait_until(
                120, 10, 0,
                duthost.check_bgp_session_state,
                neighbor_ctx["neighbor_ips"],
            )
            pytest_assert(
                bgp_up,
                f"BGP sessions with neighbors {neighbor_ctx['neighbor_ips']} failed to establish after re-add",
            )

            if prefix:
                pytest_assert(
                    wait_until(120, 5, 0, verify_prefix_present, duthost,
                               dst_asic, prefix, neighbor_ctx, True, ecmp_path),
                    f"IPv4 prefix {prefix} did not return after re-adding neighbor {neighbor_ctx['neighbor_name']}",
                )
            if prefix_v6:
                pytest_assert(
                    wait_until(
                        120, 5, 0, verify_prefix_present,
                        duthost, dst_asic, prefix_v6, neighbor_ctx, True, ecmp_path_v6,
                    ),
                    f"IPv6 prefix {prefix_v6} did not return after re-adding neighbor {neighbor_ctx['neighbor_name']}",
                )

            send_and_verify_traffic_with_retry(
                tbinfo,
                duthost_up,
                duthost,
                src_asic_on_upstream,
                dst_asic,
                ptfadapter,
                ptf_dst_ports=ptf_dst_ports,
                ptf_dst_interfaces=ptf_dst_interfaces,
                dst_ip=dst_ip,
                expect_error=False,
            )
            if prefix_v6:
                send_v6_and_verify_with_retry(
                    tbinfo, duthost_up, src_asic_on_upstream, ptfadapter,
                    ptf_dst_ports, dst_ip_v6, expect_error=False,
                )

        with allure.step(f"[{ut2_scenario['id']}] Persist the restored configuration"):
            duthost.shell("config save -y")
    finally:
        # Reload the last persisted configuration even when a validation fails after the
        # peer has been removed. Only the reload window is hidden from the loganalyzer.
        if la_entry:
            la_entry.add_start_ignore_mark()
        try:
            config_reload(duthost, config_source="config_db", safe_reload=True)
        finally:
            if la_entry:
                la_entry.add_end_ignore_mark()
