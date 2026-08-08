"""
Test DASH scale programming time.

Programs configurable numbers of DASH objects (routes, VNET mappings) via gNMI
and measures the time for all SAI objects to be created on the DPU.
Reports throughput metrics (objects/second).

This test validates the end-to-end programming pipeline performance:
gNMI SET -> APPL_DB -> orchagent -> SAI -> APPL_STATE_DB result.

Primary metric: APPL_STATE_DB result entries (each key gets a 'result'
field written back by orchagent after SAI programming completes).
Secondary metric: sairedis.rec SAI object create counts.

Config ordering follows test_fnic.py:
  1. Appliance, routing types, VNET, route group, meter policy, tunnel
  2. Routes and VNET mappings            <-- scale objects go here
  3. Route rules (inbound)
  4. ENI
  5. ENI route group binding             <-- routes must exist before this

Usage:
    pytest test_dash_scale.py \
        --num_scale_routes 1000 \
        --num_scale_vnet_mappings 500 \
        --scale_poll_timeout 300
"""

import ipaddress
import logging
import re
import time
from collections import namedtuple
from datetime import datetime

import configs.privatelink_config as pl
import pytest
from dash_api.route_type_pb2 import RoutingType
from gnmi_utils import apply_messages
from sairedis_utils import get_sairedis_line_count, parse_sairedis_changes
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("smartswitch"),
    pytest.mark.skip_check_dut_health,
]

# Polling interval for APPL_STATE_DB checks
POLL_INTERVAL = 2  # seconds between polls

# Use IP ranges that don't conflict with base privatelink_config addresses
ROUTE_BASE_IP = "172.16.0.0"
VNET_MAP_BASE_IP = "172.20.0.0"
TUNNEL_BASE_IP = "50.0.0.1"

# SAI object types corresponding to DASH tables
SAI_ROUTE_TYPE = "SAI_OBJECT_TYPE_OUTBOUND_ROUTING_ENTRY"
SAI_CA_TO_PA_TYPE = "SAI_OBJECT_TYPE_OUTBOUND_CA_TO_PA_ENTRY"

# syncd syslog function names for bulk create operations
SYNCD_BULK_CREATE_FUNCTIONS = {
    SAI_ROUTE_TYPE: "create_outbound_routing_entries",
    SAI_CA_TO_PA_TYPE: "create_outbound_ca_to_pa_entries",
}

SyncdBulkCall = namedtuple("SyncdBulkCall", ["timestamp", "end_timestamp", "count", "duration_ms"])
SyncdCycle = namedtuple(
    "SyncdCycle", ["start_ts", "end_ts", "calls", "total_objects", "processing_ms", "gap_to_next_ms"])

# Minimum expected throughput rates (objects/second), 10% below observed baseline
# Observed: gNMI ~600 obj/s, SAI ~800 obj/s (sairedis wall time, single ENI)
MIN_GNMI_THROUGHPUT = 540   # gNMI SET/DELETE rate
MIN_SAI_THROUGHPUT = 720    # sairedis create rate (orchagent -> SAI, single ENI only)

# DPU APPL_STATE_DB is hosted on NPU Redis, accessible via midplane
DPU_REDIS_HOST = "169.254.200.254"
DPU_REDIS_BASE_PORT = 6381  # dpu0=6381, dpu1=6382, ...
APPL_STATE_DB_ID = 16


@pytest.fixture(scope="module")
def num_routes(request):
    return request.config.getoption("--num_scale_routes")


@pytest.fixture(scope="module")
def num_vnet_mappings(request):
    return request.config.getoption("--num_scale_vnet_mappings")


@pytest.fixture(scope="module")
def poll_timeout(request):
    return request.config.getoption("--scale_poll_timeout")


@pytest.fixture(scope="module")
def num_enis(request):
    return request.config.getoption("--num_scale_enis")


# ---------------------------------------------------------------------------
# Scale config generators
# ---------------------------------------------------------------------------


def generate_scale_routes(route_group, num_routes, base_ip=ROUTE_BASE_IP, prefix_len=32):
    """Generate *num_routes* DASH_ROUTE_TABLE entries under *route_group*."""
    messages = {}
    base = ipaddress.IPv4Address(base_ip)
    for i in range(num_routes):
        ip = str(base + i)
        key = f"DASH_ROUTE_TABLE:{route_group}:{ip}/{prefix_len}"
        messages[key] = {
            "routing_type": RoutingType.ROUTING_TYPE_VNET,
            "vnet": pl.VNET1,
        }
    return messages


def generate_scale_vnet_mappings(vnet_name, num_mappings, base_ip=VNET_MAP_BASE_IP):
    """Generate *num_mappings* DASH_VNET_MAPPING_TABLE entries for *vnet_name*."""
    messages = {}
    base = ipaddress.IPv4Address(base_ip)
    for i in range(num_mappings):
        ip = str(base + i)
        underlay_ip = str(ipaddress.IPv4Address(TUNNEL_BASE_IP) + (i % 65536))
        mac = "00:AA:{:02X}:{:02X}:{:02X}:{:02X}".format(
            (i >> 24) & 0xFF,
            (i >> 16) & 0xFF,
            (i >> 8) & 0xFF,
            i & 0xFF,
        )
        key = f"DASH_VNET_MAPPING_TABLE:{vnet_name}:{ip}"
        messages[key] = {
            "routing_type": RoutingType.ROUTING_TYPE_VNET,
            "underlay_ip": underlay_ip,
            "mac_address": mac,
        }
    return messages


def _generate_uuid(index):
    """Generate a deterministic UUID-like string for ENI index *index*."""
    return f"497f23d7-f0ac-4c99-a98f-59b470e8{index:04x}"


def _generate_guid(prefix, index):
    """Generate a deterministic GUID string for scale config."""
    return f"{prefix}-{index:04x}-4193-b946-ccc6e8f930b2"


def generate_multi_eni_config(num_enis, routes_per_eni, mappings_per_eni):
    """Generate DASH config for *num_enis* ENIs, each with its own VNET,
    route group, routes, and VNET mappings.

    Returns:
        (infra_messages, scale_messages, post_messages, eni_route_groups)
        - infra_messages: VNETs + route groups (apply first)
        - scale_messages: routes + VNET mappings (apply second)
        - post_messages: ENIs + ENI-route-group bindings (apply last)
        - eni_route_groups: list of (eni_id, route_group) for tracking
    """
    infra = {}
    scale = {}
    post = {}
    eni_route_groups = []

    for eni_idx in range(num_enis):
        vnet_name = f"ScaleVnet{eni_idx + 1}"
        route_group = f"ScaleRouteGroup{eni_idx + 1}"
        eni_id = _generate_uuid(eni_idx + 0x100)
        vnet_vni = str(3001 + eni_idx)
        eni_mac = "F4:93:9F:{:02X}:{:02X}:{:02X}".format(
            (eni_idx >> 8) & 0xFF, eni_idx & 0xFF, 0x01)

        # VNET
        infra[f"DASH_VNET_TABLE:{vnet_name}"] = {
            "vni": vnet_vni,
            "guid": _generate_guid("559c6ce8", eni_idx),
        }

        # Route group
        infra[f"DASH_ROUTE_GROUP_TABLE:{route_group}"] = {
            "guid": _generate_guid("48af6ce8", eni_idx),
            "version": "rg_version",
        }

        # Routes — offset base IP per ENI to avoid collisions
        route_base = ipaddress.IPv4Address("172.16.0.0") + (eni_idx * routes_per_eni)
        for i in range(routes_per_eni):
            ip = str(route_base + i)
            scale[f"DASH_ROUTE_TABLE:{route_group}:{ip}/32"] = {
                "routing_type": RoutingType.ROUTING_TYPE_VNET,
                "vnet": vnet_name,
            }

        # VNET mappings — offset base IP per ENI
        map_base = ipaddress.IPv4Address("172.20.0.0") + (eni_idx * mappings_per_eni)
        for i in range(mappings_per_eni):
            ip = str(map_base + i)
            underlay_ip = str(ipaddress.IPv4Address(TUNNEL_BASE_IP) + (i % 65536))
            mac = "00:BB:{:02X}:{:02X}:{:02X}:{:02X}".format(
                eni_idx & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF)
            scale[f"DASH_VNET_MAPPING_TABLE:{vnet_name}:{ip}"] = {
                "routing_type": RoutingType.ROUTING_TYPE_VNET,
                "underlay_ip": underlay_ip,
                "mac_address": mac,
            }

        # ENI
        post[f"DASH_ENI_TABLE:{eni_id}"] = {
            "vnet": vnet_name,
            "underlay_ip": pl.VM1_PA,
            "mac_address": eni_mac,
            "eni_id": _generate_uuid(eni_idx + 0x200),
            "admin_state": pl.State.STATE_ENABLED,
            "pl_underlay_sip": pl.APPLIANCE_VIP,
            "pl_sip_encoding": f"{pl.PL_ENCODING_IP}/{pl.PL_ENCODING_MASK}",
            "eni_mode": pl.EniMode.MODE_FNIC,
            "v4_meter_policy_id": pl.METER_POLICY_V4,
        }

        # ENI route group binding
        post[f"DASH_ENI_ROUTE_TABLE:{eni_id}"] = {
            "group_id": route_group,
        }

        eni_route_groups.append((eni_id, route_group))

    return infra, scale, post, eni_route_groups


# ---------------------------------------------------------------------------
# SAI-based polling helpers (via sairedis.rec — always available)
# ---------------------------------------------------------------------------


def _parse_sairedis_timestamp(ts_str):
    """Parse a sairedis.rec timestamp like '2024-01-15.10:30:45.123456' into a datetime."""
    # Format: YYYY-MM-DD.HH:MM:SS.ffffff
    m = re.match(r'(\d{4}-\d{2}-\d{2})\.(\d{2}:\d{2}:\d{2}\.\d+)', ts_str)
    if not m:
        return None
    return datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S.%f")


def get_sai_programming_time(changes, sai_object_type):
    """Compute orchagent SAI programming window from sairedis.rec timestamps.

    Returns:
        (count, first_ts_str, last_ts_str, duration_seconds) or (0, None, None, 0.0)
    """
    creates = [c for c in changes.created if c.object_type == sai_object_type]
    if not creates:
        return 0, None, None, 0.0

    first_ts = _parse_sairedis_timestamp(creates[0].timestamp)
    last_ts = _parse_sairedis_timestamp(creates[-1].timestamp)
    if first_ts and last_ts:
        duration = (last_ts - first_ts).total_seconds()
    else:
        duration = 0.0
    return len(creates), creates[0].timestamp, creates[-1].timestamp, duration


# ---------------------------------------------------------------------------
# syncd syslog parsing — bulkCreate timing per cycle
# ---------------------------------------------------------------------------

def _parse_syslog_timestamp(line):
    """Parse syslog timestamp like '2026 May 21 16:33:25.599163'."""
    m = re.match(r'(\d{4}\s+\w+\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d+)', line)
    if not m:
        return None
    ts_str = m.group(1)
    return datetime.strptime(ts_str, "%Y %b %d %H:%M:%S.%f")


def _get_dpu_time(dpuhost):
    """Get the current time from the DPU host clock (avoids clock skew with test runner)."""
    result = dpuhost.shell("date '+%Y %b %d %H:%M:%S.%6N'", module_ignore_errors=True)
    if result['rc'] == 0:
        ts = _parse_syslog_timestamp(result['stdout'].strip())
        if ts:
            return ts
    return datetime.now()


def parse_syncd_bulk_creates(dpuhost, sai_object_type, since_timestamp=None):
    """Parse syncd syslog for bulkCreate calls of a given SAI object type.

    Reads the syncd syslog for 'bulk create' / 'bulk create successful' pairs,
    groups them into cycles (bursts separated by >500ms gaps), and computes
    per-cycle and aggregate metrics.

    Args:
        dpuhost: DPU host to run commands on
        sai_object_type: SAI object type key (e.g. SAI_ROUTE_TYPE)
        since_timestamp: Optional datetime; only include entries after this time

    Returns:
        dict with keys:
            'total_objects': int,
            'total_sai_processing_ms': float (sum of actual SAI call durations),
            'total_wall_time_s': float (first create to last create successful),
            'sai_throughput': float (total_objects / total_sai_processing_ms * 1000),
            'num_cycles': int,
            'cycles': list of SyncdCycle,
    """
    func_name = SYNCD_BULK_CREATE_FUNCTIONS.get(sai_object_type)
    if not func_name:
        logger.warning("No syncd function mapping for %s", sai_object_type)
        return None

    # Grep for both the start and successful lines
    cmd = f"sudo grep -i '{func_name}' /var/log/syslog"
    result = dpuhost.shell(cmd, module_ignore_errors=True)
    if result['rc'] != 0 or not result['stdout'].strip():
        logger.warning("No syncd bulkCreate entries found for %s", func_name)
        return None

    # Parse start/successful pairs
    # Start:      [func:577] 8 OUTBOUND_ROUTING_ENTRYs bulk create
    # Successful: [func:590] 8 OUTBOUND_ROUTING_ENTRYs bulk create successful
    start_pattern = re.compile(
        r'.*\[' + re.escape(func_name) + r':\d+\]\s+(\d+)\s+\S+\s+bulk create$'
    )
    success_pattern = re.compile(
        r'.*\[' + re.escape(func_name) + r':\d+\]\s+(\d+)\s+\S+\s+bulk create successful$'
    )

    calls = []
    lines = result['stdout'].splitlines()
    i = 0
    while i < len(lines) - 1:
        start_match = start_pattern.match(lines[i])
        if not start_match:
            i += 1
            continue
        success_match = success_pattern.match(lines[i + 1])
        if not success_match:
            i += 1
            continue

        count = int(start_match.group(1))
        start_ts = _parse_syslog_timestamp(lines[i])
        end_ts = _parse_syslog_timestamp(lines[i + 1])

        if start_ts and end_ts:
            if since_timestamp and start_ts < since_timestamp:
                i += 2
                continue
            duration_ms = (end_ts - start_ts).total_seconds() * 1000
            calls.append(SyncdBulkCall(
                timestamp=start_ts,
                end_timestamp=end_ts,
                count=count,
                duration_ms=duration_ms,
            ))
        i += 2

    if not calls:
        return None

    # Group calls into cycles (gap > 500ms between consecutive calls = new cycle)
    CYCLE_GAP_MS = 500
    cycles = []
    cycle_calls = [calls[0]]

    for j in range(1, len(calls)):
        gap = (calls[j].timestamp - calls[j - 1].timestamp).total_seconds() * 1000
        if gap > CYCLE_GAP_MS:
            # Close current cycle
            cycles.append(cycle_calls)
            cycle_calls = [calls[j]]
        else:
            cycle_calls.append(calls[j])
    cycles.append(cycle_calls)

    # Build SyncdCycle objects
    syncd_cycles = []
    for idx, cc in enumerate(cycles):
        total_objs = sum(c.count for c in cc)
        processing = sum(c.duration_ms for c in cc)
        start = cc[0].timestamp
        end = cc[-1].end_timestamp
        gap_to_next = None
        if idx < len(cycles) - 1:
            gap_to_next = (cycles[idx + 1][0].timestamp - end).total_seconds() * 1000
        syncd_cycles.append(SyncdCycle(
            start_ts=start,
            end_ts=end,
            calls=len(cc),
            total_objects=total_objs,
            processing_ms=processing,
            gap_to_next_ms=gap_to_next,
        ))

    total_objects = sum(c.total_objects for c in syncd_cycles)
    total_processing_ms = sum(c.processing_ms for c in syncd_cycles)
    wall_time = (calls[-1].end_timestamp - calls[0].timestamp).total_seconds()
    sai_throughput = (total_objects / total_processing_ms * 1000) if total_processing_ms > 0 else 0

    return {
        'total_objects': total_objects,
        'total_sai_processing_ms': total_processing_ms,
        'total_wall_time_s': wall_time,
        'sai_throughput': sai_throughput,
        'num_cycles': len(syncd_cycles),
        'cycles': syncd_cycles,
    }


# ---------------------------------------------------------------------------
# APPL_STATE_DB helpers (available when swss writes result entries)
# ---------------------------------------------------------------------------


def get_result_count(duthost, dpu_index, table_name):
    """Return the number of result entries for *table_name* in DPU APPL_STATE_DB.

    The DPU's APPL_STATE_DB is hosted on the NPU's Redis and accessed via
    midplane at port 6381 + dpu_index, database 16.
    """
    port = DPU_REDIS_BASE_PORT + dpu_index
    cmd = (f"sudo redis-cli -h {DPU_REDIS_HOST} -p {port} "
           f"-n {APPL_STATE_DB_ID} keys '{table_name}|*'")
    result = duthost.shell(cmd, module_ignore_errors=True)
    if result["rc"] != 0:
        return 0
    keys = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
    return len(keys)


def check_result_values(duthost, dpu_index, table_name, sample_size=100):
    """Spot-check that APPL_STATE_DB result entries have result=0 (success).

    Returns:
        (total_checked, success_count, failure_count, failed_keys)
    """
    port = DPU_REDIS_BASE_PORT + dpu_index
    # Get all keys
    cmd = (f"sudo redis-cli -h {DPU_REDIS_HOST} -p {port} "
           f"-n {APPL_STATE_DB_ID} keys '{table_name}|*'")
    result = duthost.shell(cmd, module_ignore_errors=True)
    if result["rc"] != 0:
        return 0, 0, 0, []

    keys = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
    if not keys:
        return 0, 0, 0, []

    # Sample keys evenly across the range
    if len(keys) > sample_size:
        step = len(keys) // sample_size
        sampled_keys = keys[::step][:sample_size]
    else:
        sampled_keys = keys

    success = 0
    failures = 0
    failed_keys = []
    for key in sampled_keys:
        cmd = (f"sudo redis-cli -h {DPU_REDIS_HOST} -p {port} "
               f"-n {APPL_STATE_DB_ID} hget '{key}' result")
        res = duthost.shell(cmd, module_ignore_errors=True)
        if res["rc"] != 0:
            failures += 1
            failed_keys.append(key)
            continue
        val = res["stdout"].strip()
        if val == "0":
            success += 1
        else:
            failures += 1
            failed_keys.append(key)

    return len(sampled_keys), success, failures, failed_keys


def log_scale_results(label, programmed, expected, gnmi_time,
                      sai_timings=None, syncd_metrics=None):
    """Pretty-print scale test results.

    *sai_timings* is an optional list of (type_label, count, first_ts, last_ts, duration)
    tuples for sairedis.rec timing.
    *syncd_metrics* is an optional list of (type_label, metrics_dict) tuples
    from parse_syncd_bulk_creates().
    """
    logger.info("=" * 60)
    logger.info("  %s SCALE PROGRAMMING RESULTS", label)
    logger.info("  Objects programmed : %d / %d", programmed, expected)
    logger.info("  gNMI send time     : %.2f s", gnmi_time)
    if sai_timings:
        for type_label, count, first_ts, last_ts, duration in sai_timings:
            sai_tput = count / duration if duration > 0 else 0
            logger.info("  SAI %s : %d objects in %.3fs (%.1f obj/s) [%s -> %s]",
                        type_label, count, duration, sai_tput,
                        first_ts or "?", last_ts or "?")
    if syncd_metrics:
        logger.info("-" * 60)
        logger.info("  SYNCD BULK CREATE ANALYSIS")
        for type_label, metrics in syncd_metrics:
            if not metrics:
                logger.info("  syncd %s : no data", type_label)
                continue
            logger.info("  syncd %s : %d objects, %d cycles, "
                        "SAI processing %.1fms (%.0f obj/s), wall %.2fs",
                        type_label,
                        metrics['total_objects'],
                        metrics['num_cycles'],
                        metrics['total_sai_processing_ms'],
                        metrics['sai_throughput'],
                        metrics['total_wall_time_s'])
            for i, cycle in enumerate(metrics['cycles']):
                gap_str = f", gap {cycle.gap_to_next_ms:.0f}ms" if cycle.gap_to_next_ms is not None else ""
                logger.info("    cycle %2d: %5d objs in %2d calls, "
                            "SAI %.1fms%s [%s]",
                            i + 1, cycle.total_objects, cycle.calls,
                            cycle.processing_ms, gap_str,
                            cycle.start_ts.strftime("%H:%M:%S.%f"))
    logger.info("=" * 60)


# ---------------------------------------------------------------------------
# Fixtures — config ordering follows test_fnic.py
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def common_setup_teardown(
    localhost,
    duthost,
    ptfhost,
    dpu_index,
    skip_config,
    dpuhosts,
    set_vxlan_udp_sport_range,
    setup_npu_dpu,  # noqa: F811
):
    """
    Program base DASH infrastructure.  Scale objects (routes / mappings) are
    NOT programmed here — each test adds them in the correct position
    (before ENI route group binding).

    Ordering matches test_fnic.py:
      1. Appliance, routing types, VNET, route group, meter policy, tunnel
      -- tests insert scale routes / mappings here --
      2. Route rules (if applicable)
      3. ENI
      4. ENI route group binding
    """
    if skip_config:
        yield
        return

    dpuhost = dpuhosts[dpu_index]

    # Clean up stale gNMI update files from prior runs to avoid
    # "Argument list too long" when gnmi_utils runs 'rm -f update*'
    ptfhost.shell("find /root -maxdepth 1 -name 'update*' -delete",
                  module_ignore_errors=True)

    # Step 1: base infrastructure (no ENI, no routes yet)
    base_config_messages = {
        **pl.APPLIANCE_FNIC_CONFIG,
        **pl.ROUTING_TYPE_PL_CONFIG,
        **pl.ROUTING_TYPE_VNET_CONFIG,
        **pl.VNET_CONFIG,
        **pl.ROUTE_GROUP1_CONFIG,
        **pl.METER_POLICY_V4_CONFIG,
        **pl.TUNNEL1_CONFIG,
    }
    logger.info("Programming base DASH infrastructure")
    apply_messages(localhost, duthost, ptfhost, base_config_messages, dpuhost.dpu_index)

    # ENI and route-group binding are deferred to the test functions
    yield

    config_reload(dpuhost, safe_reload=True, yang_validate=False)


def _apply_post_route_config(localhost, duthost, ptfhost, dpuhost):
    """
    Apply ENI + ENI route group binding AFTER routes have been programmed.
    This matches test_fnic.py ordering so orchagent accepts the routes.
    """
    # Route rules (inbound)
    if "pensando" not in dpuhost.facts["asic_type"]:
        route_rule_messages = {
            **pl.VM_VNI_ROUTE_RULE_CONFIG,
            **pl.INBOUND_VNI_ROUTE_RULE_CONFIG,
            **pl.TRUSTED_VNI_ROUTE_RULE_CONFIG,
        }
        logger.info("Programming route rules")
        apply_messages(localhost, duthost, ptfhost, route_rule_messages, dpuhost.dpu_index)

    # ENI
    logger.info("Programming ENI")
    apply_messages(localhost, duthost, ptfhost, pl.ENI_FNIC_CONFIG, dpuhost.dpu_index)

    # ENI route group binding — must come AFTER routes are in the route group
    logger.info("Binding ENI to route group")
    apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG, dpuhost.dpu_index)


def _remove_post_route_config(localhost, duthost, ptfhost, dpuhost):
    """
    Remove ENI route group binding, ENI, and route rules in reverse order.
    This must be done before deleting routes, because routes cannot be
    removed while the ENI is still bound to the route group.
    """
    # Remove ENI route group binding first
    logger.info("Removing ENI route group binding")
    apply_messages(localhost, duthost, ptfhost, pl.ENI_ROUTE_GROUP1_CONFIG,
                   dpuhost.dpu_index, set_db=False)

    # Remove ENI
    logger.info("Removing ENI")
    apply_messages(localhost, duthost, ptfhost, pl.ENI_FNIC_CONFIG,
                   dpuhost.dpu_index, set_db=False)

    # Remove route rules
    if "pensando" not in dpuhost.facts["asic_type"]:
        route_rule_messages = {
            **pl.VM_VNI_ROUTE_RULE_CONFIG,
            **pl.INBOUND_VNI_ROUTE_RULE_CONFIG,
            **pl.TRUSTED_VNI_ROUTE_RULE_CONFIG,
        }
        logger.info("Removing route rules")
        apply_messages(localhost, duthost, ptfhost, route_rule_messages,
                       dpuhost.dpu_index, set_db=False)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_combined_scale_programming_time(
    localhost, duthost, ptfhost, dpuhosts, dpu_index,
    num_routes, num_vnet_mappings, poll_timeout,
):
    """
    Program routes and VNET mappings together, measure create timing,
    then delete them and measure delete timing.

    Phase 1 (Create): Send scale objects via gNMI, apply ENI binding,
    poll APPL_STATE_DB for result entries, validate result=0.

    Phase 2 (Delete): Remove ENI binding, send gNMI DELETEs,
    poll APPL_STATE_DB for entry removal.
    """
    dpuhost = dpuhosts[dpu_index]
    total_objects = num_routes + num_vnet_mappings

    # --- Phase 1: Create ---
    sairedis_start = get_sairedis_line_count(dpuhost)
    route_baseline = get_result_count(duthost, dpuhost.dpu_index, "DASH_ROUTE_TABLE")
    mapping_baseline = get_result_count(duthost, dpuhost.dpu_index, "DASH_VNET_MAPPING_TABLE")
    test_start_time = _get_dpu_time(dpuhost)

    route_messages = generate_scale_routes(pl.ROUTE_GROUP1, num_routes)
    mapping_messages = generate_scale_vnet_mappings(pl.VNET1, num_vnet_mappings)
    combined_messages = {**route_messages, **mapping_messages}

    logger.info(
        "Phase 1: Programming %d objects (%d routes + %d mappings) via gNMI",
        total_objects, num_routes, num_vnet_mappings,
    )

    gnmi_start = time.time()
    apply_messages(
        localhost, duthost, ptfhost, combined_messages, dpuhost.dpu_index,
        wait_after_apply=0,
    )
    create_gnmi_elapsed = time.time() - gnmi_start
    logger.info("gNMI SET completed in %.2fs", create_gnmi_elapsed)

    # Steps 3-5: route rules, ENI, ENI route group binding
    _apply_post_route_config(localhost, duthost, ptfhost, dpuhost)

    # Poll APPL_STATE_DB for both tables
    expected_routes = route_baseline + num_routes
    expected_mappings = mapping_baseline + num_vnet_mappings
    start_time = time.time()
    routes_done = False
    mappings_done = False
    route_count = 0
    mapping_count = 0

    while True:
        elapsed = time.time() - start_time

        if not routes_done:
            route_count = get_result_count(duthost, dpuhost.dpu_index, "DASH_ROUTE_TABLE")
            if route_count >= expected_routes:
                routes_done = True
                logger.info("All route results received at %.2fs", elapsed)

        if not mappings_done:
            mapping_count = get_result_count(duthost, dpuhost.dpu_index, "DASH_VNET_MAPPING_TABLE")
            if mapping_count >= expected_mappings:
                mappings_done = True
                logger.info("All mapping results received at %.2fs", elapsed)

        if routes_done and mappings_done:
            break

        if elapsed >= poll_timeout:
            break

        logger.info(
            "Create progress — routes: %d/%d, mappings: %d/%d (%.1fs)",
            route_count - route_baseline, num_routes,
            mapping_count - mapping_baseline, num_vnet_mappings, elapsed,
        )
        time.sleep(POLL_INTERVAL)

    actual_routes = route_count - route_baseline
    actual_mappings = mapping_count - mapping_baseline
    total_programmed = actual_routes + actual_mappings

    # sairedis SAI timing
    changes = parse_sairedis_changes(dpuhost, sairedis_start)
    sai_route_count, rt_first, rt_last, rt_dur = get_sai_programming_time(
        changes, SAI_ROUTE_TYPE)
    sai_mapping_count, mp_first, mp_last, mp_dur = get_sai_programming_time(
        changes, SAI_CA_TO_PA_TYPE)

    # syncd syslog bulk create analysis
    syncd_route_metrics = parse_syncd_bulk_creates(
        dpuhost, SAI_ROUTE_TYPE, since_timestamp=test_start_time)
    syncd_mapping_metrics = parse_syncd_bulk_creates(
        dpuhost, SAI_CA_TO_PA_TYPE, since_timestamp=test_start_time)

    log_scale_results("CREATE", total_programmed, total_objects,
                      create_gnmi_elapsed,
                      sai_timings=[
                          ("routes", sai_route_count, rt_first, rt_last, rt_dur),
                          ("mappings", sai_mapping_count, mp_first, mp_last, mp_dur),
                      ],
                      syncd_metrics=[
                          ("routes", syncd_route_metrics),
                          ("mappings", syncd_mapping_metrics),
                      ])
    logger.info("  Breakdown — routes: %d/%d, mappings: %d/%d",
                actual_routes, num_routes, actual_mappings, num_vnet_mappings)

    # Validate result correctness (spot-check for result=0)
    for table_name, label in [("DASH_ROUTE_TABLE", "route"),
                              ("DASH_VNET_MAPPING_TABLE", "mapping")]:
        checked, success, failures, failed_keys = check_result_values(
            duthost, dpuhost.dpu_index, table_name)
        logger.info("  Result validation (%s): %d/%d success", label, success, checked)
        if failed_keys:
            logger.warning("  Failed keys (sample): %s", failed_keys[:5])
        pytest_assert(
            failures == 0,
            f"{failures}/{checked} {label} result entries had non-zero result: "
            f"{failed_keys[:5]}",
        )

    pytest_assert(
        actual_routes >= num_routes,
        f"Expected {num_routes} APPL_STATE_DB route results but only found {actual_routes}",
    )
    pytest_assert(
        actual_mappings >= num_vnet_mappings,
        f"Expected {num_vnet_mappings} APPL_STATE_DB mapping results but only found {actual_mappings}",
    )
    create_gnmi_rate = total_objects / create_gnmi_elapsed if create_gnmi_elapsed > 0 else 0
    pytest_assert(
        create_gnmi_rate >= MIN_GNMI_THROUGHPUT,
        f"gNMI create throughput {create_gnmi_rate:.0f} obj/s "
        f"below minimum {MIN_GNMI_THROUGHPUT} obj/s",
    )
    if rt_dur > 0:
        pytest_assert(
            sai_route_count / rt_dur >= MIN_SAI_THROUGHPUT,
            f"SAI route throughput {sai_route_count / rt_dur:.0f} obj/s "
            f"below minimum {MIN_SAI_THROUGHPUT} obj/s",
        )
    if mp_dur > 0:
        pytest_assert(
            sai_mapping_count / mp_dur >= MIN_SAI_THROUGHPUT,
            f"SAI mapping throughput {sai_mapping_count / mp_dur:.0f} obj/s "
            f"below minimum {MIN_SAI_THROUGHPUT} obj/s",
        )

    # --- Phase 2: Delete ---
    # Must remove ENI binding before routes can be deleted
    _remove_post_route_config(localhost, duthost, ptfhost, dpuhost)

    pre_delete_routes = get_result_count(duthost, dpuhost.dpu_index, "DASH_ROUTE_TABLE")
    pre_delete_mappings = get_result_count(duthost, dpuhost.dpu_index, "DASH_VNET_MAPPING_TABLE")
    logger.info("Phase 2: Deleting %d objects via gNMI (pre-delete: %d routes, %d mappings)",
                total_objects, pre_delete_routes, pre_delete_mappings)

    sairedis_del_start = get_sairedis_line_count(dpuhost)

    gnmi_start = time.time()
    apply_messages(
        localhost, duthost, ptfhost, combined_messages, dpuhost.dpu_index,
        set_db=False, wait_after_apply=0,
    )
    delete_gnmi_elapsed = time.time() - gnmi_start
    logger.info("gNMI DELETE completed in %.2fs", delete_gnmi_elapsed)

    # Poll for APPL_STATE_DB entry removal
    start_time = time.time()
    routes_done = False
    mappings_done = False
    route_count = pre_delete_routes
    mapping_count = pre_delete_mappings

    while True:
        elapsed = time.time() - start_time

        if not routes_done:
            route_count = get_result_count(duthost, dpuhost.dpu_index, "DASH_ROUTE_TABLE")
            if route_count <= pre_delete_routes - num_routes:
                routes_done = True
                logger.info("All route results removed")

        if not mappings_done:
            mapping_count = get_result_count(duthost, dpuhost.dpu_index, "DASH_VNET_MAPPING_TABLE")
            if mapping_count <= pre_delete_mappings - num_vnet_mappings:
                mappings_done = True
                logger.info("All mapping results removed")

        if routes_done and mappings_done:
            break

        if elapsed >= poll_timeout:
            break

        logger.info(
            "Delete progress — routes remaining: %d, mappings remaining: %d (%.1fs)",
            route_count - (pre_delete_routes - num_routes),
            mapping_count - (pre_delete_mappings - num_vnet_mappings), elapsed,
        )
        time.sleep(POLL_INTERVAL)

    routes_removed = pre_delete_routes - route_count
    mappings_removed = pre_delete_mappings - mapping_count
    total_removed = routes_removed + mappings_removed

    # sairedis SAI timing for removes
    del_changes = parse_sairedis_changes(dpuhost, sairedis_del_start)
    route_removes = len([c for c in del_changes.removed if c.object_type == SAI_ROUTE_TYPE])
    mapping_removes = len([c for c in del_changes.removed if c.object_type == SAI_CA_TO_PA_TYPE])

    log_scale_results("DELETE", total_removed, total_objects,
                      delete_gnmi_elapsed)
    logger.info("  Breakdown — routes removed: %d/%d, mappings removed: %d/%d",
                routes_removed, num_routes, mappings_removed, num_vnet_mappings)
    logger.info("  SAI removes — routes: %d, mappings: %d",
                route_removes, mapping_removes)

    pytest_assert(
        routes_removed >= num_routes,
        f"Expected {num_routes} route results removed but only {routes_removed} were removed",
    )
    pytest_assert(
        mappings_removed >= num_vnet_mappings,
        f"Expected {num_vnet_mappings} mapping results removed but only {mappings_removed} were removed",
    )
    delete_gnmi_rate = total_objects / delete_gnmi_elapsed if delete_gnmi_elapsed > 0 else 0
    pytest_assert(
        delete_gnmi_rate >= MIN_GNMI_THROUGHPUT,
        f"gNMI delete throughput {delete_gnmi_rate:.0f} obj/s "
        f"below minimum {MIN_GNMI_THROUGHPUT} obj/s",
    )


def test_multi_eni_scale_programming_time(
    localhost, duthost, ptfhost, dpuhosts, dpu_index,
    num_enis, num_routes, num_vnet_mappings, poll_timeout,
):
    """
    Program multiple ENIs, each with its own VNET, route group, routes, and
    VNET mappings.  Measures total programming time across all ENIs.

    Total objects = num_enis * (routes_per_eni + mappings_per_eni).
    """
    dpuhost = dpuhosts[dpu_index]
    pytest_assert(
        num_routes % num_enis == 0 and num_vnet_mappings % num_enis == 0,
        "num_scale_routes ({}) and num_scale_vnet_mappings ({}) must be "
        "divisible by num_scale_enis ({})".format(num_routes, num_vnet_mappings, num_enis)
    )
    routes_per_eni = num_routes // num_enis
    mappings_per_eni = num_vnet_mappings // num_enis
    total_routes = routes_per_eni * num_enis
    total_mappings = mappings_per_eni * num_enis
    total_objects = total_routes + total_mappings

    logger.info(
        "Multi-ENI test: %d ENIs, %d routes/ENI, %d mappings/ENI (%d total objects)",
        num_enis, routes_per_eni, mappings_per_eni, total_objects,
    )

    infra_messages, scale_messages, post_messages, eni_route_groups = \
        generate_multi_eni_config(num_enis, routes_per_eni, mappings_per_eni)

    # Baselines
    sairedis_start = get_sairedis_line_count(dpuhost)
    route_baseline = get_result_count(duthost, dpuhost.dpu_index, "DASH_ROUTE_TABLE")
    mapping_baseline = get_result_count(duthost, dpuhost.dpu_index, "DASH_VNET_MAPPING_TABLE")
    test_start_time = _get_dpu_time(dpuhost)

    # Step 1: additional VNETs + route groups
    logger.info("Programming %d VNETs + route groups", num_enis)
    apply_messages(localhost, duthost, ptfhost, infra_messages, dpuhost.dpu_index)

    # Step 2: scale routes + mappings across all ENIs
    logger.info("Programming %d scale objects via gNMI", len(scale_messages))
    gnmi_start = time.time()
    apply_messages(
        localhost, duthost, ptfhost, scale_messages, dpuhost.dpu_index,
        wait_after_apply=0,
    )
    gnmi_elapsed = time.time() - gnmi_start
    logger.info("gNMI SET completed in %.2fs", gnmi_elapsed)

    # Step 3: route rules (shared, already programmed if not pensando)
    if "pensando" not in dpuhost.facts["asic_type"]:
        route_rule_messages = {
            **pl.VM_VNI_ROUTE_RULE_CONFIG,
            **pl.INBOUND_VNI_ROUTE_RULE_CONFIG,
            **pl.TRUSTED_VNI_ROUTE_RULE_CONFIG,
        }
        logger.info("Programming route rules")
        apply_messages(localhost, duthost, ptfhost, route_rule_messages, dpuhost.dpu_index)

    # Step 4-5: ENIs + ENI route group bindings
    logger.info("Programming %d ENIs + route group bindings", num_enis)
    apply_messages(localhost, duthost, ptfhost, post_messages, dpuhost.dpu_index)

    # Poll APPL_STATE_DB for both tables
    expected_routes = route_baseline + total_routes
    expected_mappings = mapping_baseline + total_mappings
    start_time = time.time()
    routes_done = False
    mappings_done = False
    route_count = 0
    mapping_count = 0

    while True:
        elapsed = time.time() - start_time

        if not routes_done:
            route_count = get_result_count(duthost, dpuhost.dpu_index, "DASH_ROUTE_TABLE")
            if route_count >= expected_routes:
                routes_done = True
                logger.info("All route results received")

        if not mappings_done:
            mapping_count = get_result_count(duthost, dpuhost.dpu_index, "DASH_VNET_MAPPING_TABLE")
            if mapping_count >= expected_mappings:
                mappings_done = True
                logger.info("All mapping results received")

        if routes_done and mappings_done:
            break

        if elapsed >= poll_timeout:
            break

        logger.info(
            "Progress — routes: %d/%d, mappings: %d/%d (%.1fs)",
            route_count - route_baseline, total_routes,
            mapping_count - mapping_baseline, total_mappings, elapsed,
        )
        time.sleep(POLL_INTERVAL)

    actual_routes = route_count - route_baseline
    actual_mappings = mapping_count - mapping_baseline
    total_programmed = actual_routes + actual_mappings

    # sairedis SAI timing
    changes = parse_sairedis_changes(dpuhost, sairedis_start)
    sai_route_count, rt_first, rt_last, rt_dur = get_sai_programming_time(
        changes, SAI_ROUTE_TYPE)
    sai_mapping_count, mp_first, mp_last, mp_dur = get_sai_programming_time(
        changes, SAI_CA_TO_PA_TYPE)

    # syncd bulk create analysis
    syncd_route_metrics = parse_syncd_bulk_creates(
        dpuhost, SAI_ROUTE_TYPE, since_timestamp=test_start_time)
    syncd_mapping_metrics = parse_syncd_bulk_creates(
        dpuhost, SAI_CA_TO_PA_TYPE, since_timestamp=test_start_time)

    log_scale_results(
        f"MULTI-ENI ({num_enis} ENIs)",
        total_programmed, total_objects, gnmi_elapsed,
        sai_timings=[
            ("routes", sai_route_count, rt_first, rt_last, rt_dur),
            ("mappings", sai_mapping_count, mp_first, mp_last, mp_dur),
        ],
        syncd_metrics=[
            ("routes", syncd_route_metrics),
            ("mappings", syncd_mapping_metrics),
        ])
    logger.info("  Config: %d ENIs x (%d routes + %d mappings)",
                num_enis, routes_per_eni, mappings_per_eni)
    logger.info("  Breakdown — routes: %d/%d, mappings: %d/%d",
                actual_routes, total_routes, actual_mappings, total_mappings)

    # Validate result correctness
    for table_name, label in [("DASH_ROUTE_TABLE", "route"),
                              ("DASH_VNET_MAPPING_TABLE", "mapping")]:
        checked, success, failures, failed_keys = check_result_values(
            duthost, dpuhost.dpu_index, table_name)
        logger.info("  Result validation (%s): %d/%d success", label, success, checked)
        if failed_keys:
            logger.warning("  Failed keys (sample): %s", failed_keys[:5])
        pytest_assert(
            failures == 0,
            f"{failures}/{checked} {label} result entries had non-zero result: "
            f"{failed_keys[:5]}",
        )

    pytest_assert(
        actual_routes >= total_routes,
        f"Expected {total_routes} route results but only found {actual_routes}",
    )
    pytest_assert(
        actual_mappings >= total_mappings,
        f"Expected {total_mappings} mapping results but only found {actual_mappings}",
    )
    gnmi_rate = total_objects / gnmi_elapsed if gnmi_elapsed > 0 else 0
    pytest_assert(
        gnmi_rate >= MIN_GNMI_THROUGHPUT,
        f"gNMI throughput {gnmi_rate:.0f} obj/s "
        f"below minimum {MIN_GNMI_THROUGHPUT} obj/s",
    )
