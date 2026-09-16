"""
Scheduler / QoS coverage for the disaggregated-T2 GCU neighbor remove / re-add flow.

The remove / re-add patches built by ``dt2_helpers`` remove and restore PORT_QOS_MAP
for the neighbor's member ports and leave QUEUE and SCHEDULER untouched (PORT rows
stay, admin-down, so QUEUE leafrefs remain valid). Parametrized over the uplink (T3)
and downstream scenarios shared with ``test_add_t3.py`` and ``test_add_downstream.py``,
this test captures the QoS rows that belong to the selected neighbor, runs the same GCU
remove / re-add cycle and asserts:

* post-remove: PORT_QOS_MAP rows for the member ports are gone, QUEUE and SCHEDULER
  rows are unchanged;
* post-add: PORT_QOS_MAP, QUEUE and SCHEDULER rows are identical to the baseline.
"""
import copy
import logging
import pytest
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.generic_config_updater.add_cluster.helpers import get_cfg_info_from_dut
from tests.generic_config_updater.dt2.dt2_helpers import (
    DOWNSTREAM_SCENARIOS,
    LOGANALYZER_IGNORE_REGEX,
    T3_SCENARIOS,
    apply_patch_or_assert,
    build_add_patches,
    build_remove_patch,
    pick_target_neighbor,
)

pytestmark = [
    pytest.mark.topology("ut2", "t2", "lt2"),
]

logger = logging.getLogger(__name__)
allure.logger = logger

QOS_TABLES = ("PORT_QOS_MAP", "QUEUE", "SCHEDULER")

QOS_SCENARIOS = T3_SCENARIOS + DOWNSTREAM_SCENARIOS


def scheduler_ref(value):
    """Return the scheduler name referenced by a QoS row, accepting both the legacy
    ``[SCHEDULER|scheduler.0]`` form and the plain ``scheduler.0`` form."""
    ref = value.get("scheduler") if isinstance(value, dict) else None
    if not isinstance(ref, str) or not ref:
        return None
    return ref.strip("[]").split("|")[-1]


def capture_qos_rows(duthost, namespace, member_ports):
    """
    Snapshot the QoS rows that belong to ``member_ports``: their PORT_QOS_MAP rows, their
    ``<port>|<queue>`` QUEUE rows and every SCHEDULER row those rows reference.
    """
    members = set(member_ports)
    port_qos_map = get_cfg_info_from_dut(duthost, "PORT_QOS_MAP", namespace) or {}
    queue = get_cfg_info_from_dut(duthost, "QUEUE", namespace) or {}
    scheduler = get_cfg_info_from_dut(duthost, "SCHEDULER", namespace) or {}

    captured = {
        "PORT_QOS_MAP": {k: copy.deepcopy(v) for k, v in port_qos_map.items() if k in members},
        "QUEUE": {k: copy.deepcopy(v) for k, v in queue.items() if k.split("|")[0] in members},
    }
    referenced = {
        scheduler_ref(v)
        for v in list(captured["PORT_QOS_MAP"].values()) + list(captured["QUEUE"].values())
    }
    referenced.discard(None)
    captured["SCHEDULER"] = {k: copy.deepcopy(v) for k, v in scheduler.items() if k in referenced}
    return captured


def diff_qos_rows(duthost, namespace, baseline, expect_absent=()):
    """
    Compare the current CONFIG_DB against ``baseline``. Tables in ``expect_absent`` must
    have none of their baseline keys present; every other table must match exactly.
    Returns a list of human-readable mismatches (empty when everything matches).
    """
    mismatches = []
    for table, rows in baseline.items():
        current = get_cfg_info_from_dut(duthost, table, namespace) or {}
        for key, value in rows.items():
            if table in expect_absent:
                if key in current:
                    mismatches.append(f"{table}/{key}: expected absent, still present")
            elif key not in current:
                mismatches.append(f"{table}/{key}: missing")
            elif current[key] != value:
                mismatches.append(f"{table}/{key}: expected {value}, got {current[key]}")
    return mismatches


@pytest.fixture(scope="function", params=QOS_SCENARIOS, ids=[s["id"] for s in QOS_SCENARIOS])
def qos_scenario(request):
    return request.param


@pytest.fixture(scope="function")
def selected_qos_neighbor(mg_facts, config_facts, config_facts_localhost, qos_scenario):
    return pick_target_neighbor(config_facts, config_facts_localhost, mg_facts, qos_scenario)


def test_neighbor_remove_and_readd_scheduler(
    duthosts,
    loganalyzer,
    enum_downstream_dut_hostname,
    enum_rand_one_asic_namespace,
    mg_facts,
    config_facts,
    config_facts_localhost,
    qos_scenario,
    selected_qos_neighbor,
):
    """
    Remove and re-add one existing neighbor via GCU and verify the scheduler / QoS
    configuration attached to its member ports is dropped and restored correctly.
    """
    duthost = duthosts[enum_downstream_dut_hostname]
    dut_basic_facts = duthost.dut_basic_facts()["ansible_facts"]["dut_basic_facts"]
    if dut_basic_facts.get("is_chassis"):
        pytest.skip("Disaggregated-T2 neighbor remove/re-add workflow is skipped on chassis systems")
    namespace = enum_rand_one_asic_namespace
    neighbor_ctx = selected_qos_neighbor

    baseline = capture_qos_rows(duthost, namespace, neighbor_ctx["member_ports"])
    if not any(baseline.values()):
        pytest.skip(
            "Neighbor {} member ports {} have no PORT_QOS_MAP / QUEUE / SCHEDULER rows".format(
                neighbor_ctx["neighbor_name"], neighbor_ctx["member_ports"],
            )
        )
    logger.info(
        "scenario=%s: QoS baseline for neighbor %s: %s",
        qos_scenario["id"], neighbor_ctx["neighbor_name"],
        {table: sorted(rows) for table, rows in baseline.items()},
    )

    la_entry = loganalyzer[duthost.hostname] if loganalyzer else None
    if la_entry:
        la_entry.ignore_regex.extend(LOGANALYZER_IGNORE_REGEX)
    try:
        with allure.step(f"[{qos_scenario['id']}] Remove neighbor via GCU and verify QoS rows"):
            remove_patch_main, remove_patch_extra = build_remove_patch(
                config_facts, config_facts_localhost, mg_facts, namespace, neighbor_ctx,
            )
            apply_patch_or_assert(duthost, remove_patch_main)
            if remove_patch_extra:
                apply_patch_or_assert(duthost, remove_patch_extra)
            mismatches = diff_qos_rows(duthost, namespace, baseline, expect_absent=("PORT_QOS_MAP",))
            pytest_assert(
                not mismatches,
                "QoS rows wrong after removing neighbor {}: {}".format(
                    neighbor_ctx["neighbor_name"], "; ".join(mismatches),
                ),
            )

        with allure.step(f"[{qos_scenario['id']}] Re-add neighbor via GCU and verify QoS rows restored"):
            patch_pc, patch_rest = build_add_patches(
                config_facts, config_facts_localhost, mg_facts, namespace, neighbor_ctx,
            )
            if patch_pc:
                apply_patch_or_assert(duthost, patch_pc)
            apply_patch_or_assert(duthost, patch_rest)
            mismatches = diff_qos_rows(duthost, namespace, baseline)
            pytest_assert(
                not mismatches,
                "QoS rows not restored after re-adding neighbor {}: {}".format(
                    neighbor_ctx["neighbor_name"], "; ".join(mismatches),
                ),
            )

        with allure.step(f"[{qos_scenario['id']}] Persist the restored configuration"):
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
