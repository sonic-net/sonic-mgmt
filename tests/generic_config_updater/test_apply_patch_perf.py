"""
Test GCU apply-patch performance across multiple operation types.

Generates JSON patches at runtime based on the platform's actual port count
and configuration, then measures apply-patch wall time and verifies it
completes within a budget derived from the platform's own loadData() cost.

The budget formula is platform-agnostic:
    budget = FIXED_OVERHEAD + expected_moves * loads_per_move * measured_loaddata_time * safety_multiplier

Test scenarios cover different code paths through the GCU sort algorithm:
1. ACL port removal (REPLACE → N REMOVEs) — exercises DFS + leaf-list handling
2. ACL table addition (ADD) — exercises CreateOnlyMoveExtender
3. ACL rule addition (ADD nested) — exercises key-level move generation
4. Multi-operation patch (ADD + REPLACE + REMOVE) — exercises cross-table ordering
5. NTP server changes (simple scalar) — baseline for small config changes
6. Port MTU replace — REPLACE on existing entries without leaf-list
"""

import json
import logging
import time
import uuid

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.gu_utils import (generate_tmpfile, delete_tmpfile,
                                   create_checkpoint, delete_checkpoint,
                                   rollback_or_reload, expect_op_success,
                                   format_json_patch_for_multiasic)

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

# Safety multiplier applied to the measured baseline.
# Must be generous enough to absorb per-move overhead beyond loadData
# (JSON diff, patch simulation, move generation, config serialization).
SAFETY_MULTIPLIER = 5

# Absolute ceiling for the timeout (seconds).
MAX_TIMEOUT = 3600

# Minimum overhead floor (seconds) — even if calibration returns
# something tiny due to measurement noise, never go below this.
MIN_OVERHEAD = 3

# Conservative fallback if loadData measurement fails (seconds).
# Deliberately generous to avoid false failures.
FALLBACK_LOADDATA_TIME = 1.0


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_errors(duthosts, rand_one_dut_front_end_hostname,
                                       loganalyzer):
    """Suppress known harmless syslog ERR messages triggered by GCU config changes."""
    if loganalyzer:
        ignore_regexes = [
            # Binding ACL to LAG member port (shouldn't happen with LAG filter,
            # but suppress defensively)
            r".*ERR swss#orchagent.*processAclTablePorts.*Failed to get port.*bind port ID.*",
            r".*ERR swss#orchagent.*doAclTableTask.*Failed to process ACL table.*ports.*",
        ]
        hostname = duthosts[rand_one_dut_front_end_hostname].hostname
        if loganalyzer.get(hostname):
            loganalyzer[hostname].ignore_regex.extend(ignore_regexes)


@pytest.fixture(scope="module", autouse=True)
def setup_teardown(duthosts, rand_one_dut_front_end_hostname):
    """Create checkpoint before test module, rollback after."""
    duthost = duthosts[rand_one_dut_front_end_hostname]
    create_checkpoint(duthost)
    yield
    try:
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


@pytest.fixture(scope="module")
def perf_ctx(duthosts, rand_one_dut_front_end_hostname):
    """
    Shared performance context: discover ports and measure loadData baseline once.
    """
    duthost = duthosts[rand_one_dut_front_end_hostname]

    # Discover admin-up ports, excluding PortChannel members
    # (binding ACL tables to LAG member ports causes orchagent ERR logs
    # which trigger loganalyzer failures)
    output = duthost.shell("sonic-cfggen -d --var-json PORT")
    ports = json.loads(output['stdout'])

    pc_output = duthost.shell("sonic-db-cli CONFIG_DB keys 'PORTCHANNEL_MEMBER|*'",
                              module_ignore_errors=True)
    lag_members = set()
    for key in pc_output.get('stdout_lines', []):
        parts = key.split('|')
        if len(parts) == 3:
            lag_members.add(parts[2])
    if lag_members:
        logger.info("Excluding {} LAG member ports: {}".format(
            len(lag_members), sorted(lag_members)))

    up_ports = sorted(
        [name for name, cfg in ports.items()
         if cfg.get('admin_status', 'down') == 'up' and name not in lag_members],
        key=lambda p: int(''.join(filter(str.isdigit, p)) or 0)
    )

    if len(up_ports) < 2:
        pytest.skip("Need at least 2 admin-up ports, have {}".format(len(up_ports)))

    # Measure loadData baseline
    loaddata_time = _measure_loaddata_baseline(duthost)
    if loaddata_time is None:
        loaddata_time = FALLBACK_LOADDATA_TIME
        logger.warning("loadData measurement failed, using conservative fallback: {:.1f}s".format(
            loaddata_time))

    logger.info("Platform: {} admin-up ports, loadData baseline: {:.3f}s".format(
        len(up_ports), loaddata_time))

    # Calibrate overhead: run a trivial 1-move patch and measure wall time.
    # Overhead = total_time - expected variable cost for 1 move (2 loadData calls).
    # This captures CLI startup, YANG sort init, ConfigDB write, ansible SSH —
    # everything that's constant regardless of patch size.
    cal_patch = [{"op": "add", "path": "/NTP_SERVER/198.51.100.99", "value": {}}]
    cal_elapsed, cal_output = _apply_and_measure(
        duthost, cal_patch, label="[calibrate]")
    # Clean up calibration entry
    cal_cleanup = [{"op": "remove", "path": "/NTP_SERVER/198.51.100.99"}]
    _apply_and_measure(duthost, cal_cleanup, label="[cal cleanup]")

    expected_variable = 1 * 2 * loaddata_time  # 1 move, 2 loads/move
    measured_overhead = max(MIN_OVERHEAD, cal_elapsed - expected_variable)
    logger.info(
        "Calibrated overhead: {:.1f}s "
        "(cal={:.1f}s - variable={:.2f}s, floor={}s)".format(
            measured_overhead, cal_elapsed,
            expected_variable, MIN_OVERHEAD))

    # Generate unique table prefix per test run to avoid conflicts
    run_id = uuid.uuid4().hex[:6]
    table_prefix = "GCU_PERF_{}".format(run_id)

    return {
        'duthost': duthost,
        'up_ports': up_ports,
        'loaddata_time': loaddata_time,
        'measured_overhead': measured_overhead,
        'table_prefix': table_prefix,
    }


def _measure_loaddata_baseline(duthost):
    """Measure the cost of a single SonicYang.loadData() call on this platform."""
    script = r"""
import json, time, sonic_yang

yang_dir = '/usr/local/yang-models'
sy = sonic_yang.SonicYang(yang_dir, print_log_enabled=False)
sy.loadYangModel()

with open('/etc/sonic/config_db.json') as f:
    config = json.load(f)

# Warm up
try:
    sy.loadData(config)
except Exception:
    pass

# Measure
sy2 = sonic_yang.SonicYang(yang_dir, print_log_enabled=False)
sy2.loadYangModel()
start = time.time()
try:
    sy2.loadData(config)
except Exception:
    pass
elapsed = time.time() - start
print("LOADDATA_TIME={:.6f}".format(elapsed))
"""
    output = duthost.shell("python3 -c '{}'".format(script.replace("'", "'\\''")),
                           module_ignore_errors=True)
    if output['rc'] != 0:
        logger.warning("loadData baseline measurement failed: {}".format(
            output.get('stderr', '')))
        return None

    for line in output['stdout'].splitlines():
        if line.startswith("LOADDATA_TIME="):
            measured = float(line.split("=")[1])
            logger.info("Measured single loadData() cost: {:.3f}s".format(measured))
            return measured
    return None


def _compute_budget(expected_moves, loaddata_time, measured_overhead):
    """
    Compute the time budget for apply-patch.

    Args:
        expected_moves: Number of moves the sort algorithm is expected to produce
        loaddata_time: Measured cost of a single loadData() call (seconds)
        measured_overhead: Calibrated per-invocation overhead (seconds)

    Returns:
        Budget in seconds, capped at MAX_TIMEOUT
    """
    loads_per_move = 2  # FullConfigMoveValidator + NoDependencyMoveValidator
    raw_budget = expected_moves * loads_per_move * loaddata_time * SAFETY_MULTIPLIER
    budget = min(MAX_TIMEOUT, measured_overhead + raw_budget)
    logger.info(
        "Budget: {:.1f}s overhead + {} moves * {} loads/move * {:.3f}s/load * {}x safety = {:.1f}s "
        "(capped at {:.1f}s)".format(
            measured_overhead, expected_moves, loads_per_move, loaddata_time,
            SAFETY_MULTIPLIER, measured_overhead + raw_budget, budget))
    return budget


def _apply_and_measure(duthost, patch, label="",
                       is_asic_specific=False,
                       asic_namespaces=None):
    """Apply a patch and return (elapsed_seconds, output).

    Times only the 'config apply-patch' CLI execution, excluding file
    transfer overhead which is not part of GCU performance.
    """
    tmpfile = generate_tmpfile(duthost)
    try:
        patch = format_json_patch_for_multiasic(
            duthost=duthost, json_data=patch,
            is_host_specific=(not is_asic_specific),
            is_asic_specific=is_asic_specific,
            asic_namespaces=asic_namespaces)
        # Copy patch file BEFORE timing — file transfer is not GCU performance
        patch_content = json.dumps(patch, indent=4)
        duthost.copy(content=patch_content, dest=tmpfile)

        # Time ONLY the config apply-patch command
        start = time.time()
        output = duthost.shell("config apply-patch {}".format(tmpfile),
                               module_ignore_errors=True)
        elapsed = time.time() - start
        logger.info("{} apply-patch completed in {:.1f}s (rc={})".format(
            label, elapsed, output['rc']))
        return elapsed, output
    finally:
        delete_tmpfile(duthost, tmpfile)


def _cleanup_test_tables(duthost, table_prefix):
    """Remove all test ACL tables/rules from ConfigDB directly.

    Best-effort cleanup via direct DB deletion. The module-level
    setup_teardown fixture handles full rollback via checkpoint/restore,
    so transient inconsistency between tests is acceptable.
    """
    duthost.shell(
        "sonic-db-cli CONFIG_DB keys 'ACL_TABLE|{}*' | xargs -r -n1 sonic-db-cli CONFIG_DB del".format(
            table_prefix),
        module_ignore_errors=True)
    duthost.shell(
        "sonic-db-cli CONFIG_DB keys 'ACL_RULE|{}*' | xargs -r -n1 sonic-db-cli CONFIG_DB del".format(
            table_prefix),
        module_ignore_errors=True)


# =============================================================================
# Test 1: ACL port removal (REPLACE → N REMOVE moves)
# =============================================================================
def test_perf_acl_port_removal(perf_ctx):
    """
    Remove half the ports from an ACL table.

    GCU decomposes the REPLACE into individual REMOVE moves internally,
    exercising DFS + leaf-list handling. This is the primary O(N²) bottleneck
    on unpatched code. With BulkLeafListMoveGenerator (#4478), this collapses
    to a single REPLACE move — the budget is generous enough either way.
    """
    duthost = perf_ctx['duthost']
    up_ports = perf_ctx['up_ports']
    loaddata_time = perf_ctx['loaddata_time']
    measured_overhead = perf_ctx['measured_overhead']
    table_prefix = perf_ctx['table_prefix']
    num_ports = len(up_ports)

    table_name = "{}_PORTS".format(table_prefix)

    # Setup: create ACL table with all ports
    setup_patch = [{
        "op": "add",
        "path": "/ACL_TABLE/{}".format(table_name),
        "value": {
            "type": "L3",
            "policy_desc": "Perf test - port removal",
            "ports": up_ports,
            "stage": "ingress"
        }
    }]
    elapsed, output = _apply_and_measure(duthost, setup_patch, "[setup]")
    expect_op_success(duthost, output)

    # Test: remove half the ports
    half = num_ports // 2
    remaining = up_ports[half:]
    num_removed = half

    test_patch = [{
        "op": "replace",
        "path": "/ACL_TABLE/{}/ports".format(table_name),
        "value": remaining
    }]

    budget = _compute_budget(num_removed, loaddata_time, measured_overhead)
    elapsed = None
    try:
        elapsed, output = _apply_and_measure(duthost, test_patch, "[port removal]")
        expect_op_success(duthost, output)
    except Exception as e:
        _cleanup_test_tables(duthost, table_prefix)
        pytest.fail("apply-patch failed: {}".format(e))

    per_port = elapsed / num_removed if num_removed else 0
    logger.info(
        "Port removal: {:.2f}s total, {:.3f}s/port, {} ports removed, "
        "loads/move ratio: {:.1f}x".format(
            elapsed, per_port, num_removed,
            per_port / loaddata_time if loaddata_time > 0 else 0))

    _cleanup_test_tables(duthost, table_prefix)

    pytest_assert(
        elapsed < budget,
        "ACL port removal took {:.1f}s, budget {:.1f}s "
        "({} ports removed, {:.3f}s/port, loadData: {:.3f}s)".format(
            elapsed, budget, num_removed, per_port, loaddata_time))


# =============================================================================
# Test 2: ACL table addition (ADD operation)
# =============================================================================
def test_perf_acl_table_add(perf_ctx):
    """
    Add a new ACL table with all ports.

    Exercises ADD move generation and CreateOnlyMoveValidator validation.
    Expected: 1 move (table-level ADD).
    """
    duthost = perf_ctx['duthost']
    up_ports = perf_ctx['up_ports']
    loaddata_time = perf_ctx['loaddata_time']
    measured_overhead = perf_ctx['measured_overhead']
    table_prefix = perf_ctx['table_prefix']

    table_name = "{}_ADD".format(table_prefix)

    test_patch = [{
        "op": "add",
        "path": "/ACL_TABLE/{}".format(table_name),
        "value": {
            "type": "L3",
            "policy_desc": "Perf test - table add",
            "ports": up_ports,
            "stage": "ingress"
        }
    }]

    budget = _compute_budget(1, loaddata_time, measured_overhead)
    elapsed = None
    try:
        elapsed, output = _apply_and_measure(duthost, test_patch, "[table add]")
        expect_op_success(duthost, output)
    except Exception as e:
        _cleanup_test_tables(duthost, table_prefix)
        pytest.fail("apply-patch failed: {}".format(e))

    logger.info("Table add: {:.2f}s for 1 table with {} ports".format(elapsed, len(up_ports)))

    _cleanup_test_tables(duthost, table_prefix)

    pytest_assert(
        elapsed < budget,
        "ACL table add took {:.1f}s, budget {:.1f}s".format(elapsed, budget))


# =============================================================================
# Test 3: ACL rules addition (ADD multiple nested entries)
# =============================================================================
def test_perf_acl_rules_add(perf_ctx):
    """
    Add an ACL table with multiple rules.

    Exercises key-level move generation for adding multiple entries under
    one table. Each rule is an independent ADD move.
    """
    duthost = perf_ctx['duthost']
    up_ports = perf_ctx['up_ports']
    loaddata_time = perf_ctx['loaddata_time']
    measured_overhead = perf_ctx['measured_overhead']
    table_prefix = perf_ctx['table_prefix']

    table_name = "{}_RULES".format(table_prefix)
    num_rules = 10

    # First add the table
    table_patch = [{
        "op": "add",
        "path": "/ACL_TABLE/{}".format(table_name),
        "value": {
            "type": "L3",
            "policy_desc": "Perf test - rules",
            "ports": up_ports[:min(4, len(up_ports))],
            "stage": "ingress"
        }
    }]
    _, output = _apply_and_measure(duthost, table_patch, "[rules setup]")
    expect_op_success(duthost, output)

    # Add N rules in one patch
    rules_patch = []
    for i in range(1, num_rules + 1):
        rules_patch.append({
            "op": "add",
            "path": "/ACL_RULE/{}|RULE_{}".format(table_name, i),
            "value": {
                "PRIORITY": str(1000 + i),
                "PACKET_ACTION": "FORWARD",
                "SRC_IP": "10.0.{}.0/24".format(i)
            }
        })

    budget = _compute_budget(num_rules, loaddata_time, measured_overhead)
    elapsed = None
    try:
        elapsed, output = _apply_and_measure(duthost, rules_patch, "[rules add]")
        expect_op_success(duthost, output)
    except Exception as e:
        _cleanup_test_tables(duthost, table_prefix)
        pytest.fail("apply-patch failed: {}".format(e))

    per_rule = elapsed / num_rules
    logger.info("Rules add: {:.2f}s for {} rules, {:.3f}s/rule".format(
        elapsed, num_rules, per_rule))

    _cleanup_test_tables(duthost, table_prefix)

    pytest_assert(
        elapsed < budget,
        "ACL rules add took {:.1f}s, budget {:.1f}s ({} rules)".format(
            elapsed, budget, num_rules))


# =============================================================================
# Test 4: Multi-operation patch (ADD + REPLACE leaf-list + REMOVE in one patch)
# =============================================================================
def test_perf_multi_operation(perf_ctx):
    """
    Apply a patch combining:
    - Large leaf-list REPLACE (remove half the ports from table A) — the O(N²) case
    - Table-level REMOVE (delete table B entirely)
    - ADD rules to table A

    This is a superset of the port-removal test — it verifies performance
    when leaf-list changes are mixed with other operation types in a single
    patch, exercising cross-table dependency resolution.
    """
    duthost = perf_ctx['duthost']
    up_ports = perf_ctx['up_ports']
    loaddata_time = perf_ctx['loaddata_time']
    measured_overhead = perf_ctx['measured_overhead']
    table_prefix = perf_ctx['table_prefix']
    num_ports = len(up_ports)

    table_a = "{}_MULTI_A".format(table_prefix)
    table_b = "{}_MULTI_B".format(table_prefix)

    # Setup: create two tables — table A with ALL ports
    half = num_ports // 2
    setup_patch = [
        {
            "op": "add",
            "path": "/ACL_TABLE/{}".format(table_a),
            "value": {
                "type": "L3",
                "policy_desc": "Multi test A - large port list",
                "ports": up_ports,
                "stage": "ingress"
            }
        },
        {
            "op": "add",
            "path": "/ACL_TABLE/{}".format(table_b),
            "value": {
                "type": "L3",
                "policy_desc": "Multi test B - to be removed",
                "ports": up_ports[:min(4, len(up_ports))],
                "stage": "ingress"
            }
        }
    ]
    _, output = _apply_and_measure(duthost, setup_patch, "[multi setup]")
    expect_op_success(duthost, output)

    # Multi-op patch:
    # 1. REPLACE ports on table A — remove half
    # 2. REMOVE table B entirely
    # 3. ADD rules to table A
    num_rules = 3
    test_patch = [
        {
            "op": "replace",
            "path": "/ACL_TABLE/{}/ports".format(table_a),
            "value": up_ports[half:]
        },
        {
            "op": "remove",
            "path": "/ACL_TABLE/{}".format(table_b)
        }
    ]
    for i in range(1, num_rules + 1):
        test_patch.append({
            "op": "add",
            "path": "/ACL_RULE/{}|RULE_{}".format(table_a, i),
            "value": {
                "PRIORITY": str(1000 + i),
                "PACKET_ACTION": "FORWARD",
                "SRC_IP": "10.0.{}.0/24".format(i)
            }
        })

    # Without batching: half port REMOVEs + 1 table REMOVE + num_rules ADDs
    expected_moves = half + 1 + num_rules
    budget = _compute_budget(expected_moves, loaddata_time, measured_overhead)
    elapsed = None
    try:
        elapsed, output = _apply_and_measure(duthost, test_patch, "[multi-op]")
        expect_op_success(duthost, output)
    except Exception as e:
        _cleanup_test_tables(duthost, table_prefix)
        pytest.fail("apply-patch failed: {}".format(e))

    logger.info(
        "Multi-op: {:.2f}s for REPLACE({} ports removed) + REMOVE(table) + ADD({} rules)".format(
            elapsed, half, num_rules))

    _cleanup_test_tables(duthost, table_prefix)

    pytest_assert(
        elapsed < budget,
        "Multi-op took {:.1f}s, budget {:.1f}s ({} expected moves: {} port removals + 1 table + {} rules)".format(
            elapsed, budget, expected_moves, half, num_rules))


# =============================================================================
# Test 5: NTP server change (simple scalar config)
# =============================================================================
def test_perf_ntp_server(perf_ctx):
    """
    Add NTP servers. Simple scalar config change that should be very fast —
    serves as a sanity baseline.
    """
    duthost = perf_ctx['duthost']
    loaddata_time = perf_ctx['loaddata_time']
    measured_overhead = perf_ctx['measured_overhead']

    # Check if NTP_SERVER table exists
    output = duthost.shell("sonic-cfggen -d --var-json NTP_SERVER",
                           module_ignore_errors=True)
    existing_servers = {}
    if output['rc'] == 0 and output['stdout'].strip():
        try:
            existing_servers = json.loads(output['stdout'])
        except (json.JSONDecodeError, ValueError):
            pass

    # Add test NTP servers
    test_servers = ["198.51.100.1", "198.51.100.2", "198.51.100.3"]
    add_patch = []
    if not existing_servers:
        add_patch.append({
            "op": "add",
            "path": "/NTP_SERVER",
            "value": {k: {} for k in test_servers}
        })
    else:
        for srv in test_servers:
            add_patch.append({
                "op": "add",
                "path": "/NTP_SERVER/{}".format(srv),
                "value": {}
            })

    budget = _compute_budget(
        len(test_servers), loaddata_time, measured_overhead)
    elapsed = None
    try:
        elapsed, output = _apply_and_measure(duthost, add_patch, "[ntp add]")
        expect_op_success(duthost, output)
    except Exception as e:
        pytest.fail("NTP add failed: {}".format(e))

    logger.info("NTP add: {:.2f}s for {} servers".format(elapsed, len(test_servers)))

    # Rollback will clean up

    pytest_assert(
        elapsed < budget,
        "NTP server add took {:.1f}s, budget {:.1f}s".format(elapsed, budget))


# =============================================================================
# Test 6: Port MTU replace (REPLACE on existing entries)
# =============================================================================
def test_perf_port_mtu_replace(perf_ctx):
    """
    Set MTU on multiple ports. Tests scalar config changes on existing
    entries without leaf-list decomposition. Uses "add" operation which
    is safe whether or not mtu is already present (JSON Patch "replace"
    requires the key to exist, but mtu is optional in YANG).
    """
    duthost = perf_ctx['duthost']
    loaddata_time = perf_ctx['loaddata_time']
    measured_overhead = perf_ctx['measured_overhead']

    # On multi-ASIC, PORT is per-namespace. Discover ports from the first
    # frontend ASIC namespace to build a valid patch.
    if duthost.is_multi_asic:
        namespace = duthost.get_frontend_asic_namespace_list()[0]
        cfg = duthost.config_facts(
            host=duthost.hostname, source="running",
            namespace=namespace)['ansible_facts']
        asic_ports = sorted(
            [name for name, pcfg in cfg.get('PORT', {}).items()
             if pcfg.get('admin_status', 'down') == 'up'],
            key=lambda p: int(''.join(filter(str.isdigit, p)) or 0)
        )
        ports_to_change = asic_ports[:min(8, len(asic_ports))]
        asic_ns = [namespace]
    else:
        up_ports = perf_ctx['up_ports']
        ports_to_change = up_ports[:min(8, len(up_ports))]
        asic_ns = None

    num_ports_to_change = len(ports_to_change)
    if num_ports_to_change < 2:
        pytest.skip("Need at least 2 ports, have {}".format(
            num_ports_to_change))

    test_patch = []
    for port in ports_to_change:
        test_patch.append({
            "op": "add",
            "path": "/PORT/{}/mtu".format(port),
            "value": "9000"
        })

    budget = _compute_budget(
        num_ports_to_change, loaddata_time, measured_overhead)
    elapsed = None
    try:
        elapsed, output = _apply_and_measure(
            duthost, test_patch, "[port mtu replace]",
            is_asic_specific=(asic_ns is not None),
            asic_namespaces=asic_ns)
        expect_op_success(duthost, output)
    except Exception as e:
        pytest.fail("apply-patch failed: {}".format(e))

    per_port = elapsed / num_ports_to_change
    logger.info("Port MTU replace: {:.2f}s for {} ports, {:.3f}s/port".format(
        elapsed, num_ports_to_change, per_port))

    # Rollback will restore original MTUs

    pytest_assert(
        elapsed < budget,
        "Port MTU replace took {:.1f}s, budget {:.1f}s ({} ports)".format(
            elapsed, budget, num_ports_to_change))
