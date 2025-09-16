import json
import logging
from tests.common.snappi_tests.snappi_helpers import StrEnum
from typing import Optional

from tests.common.helpers.assertions import pytest_assert
from tests.common.snappi_tests.snappi_test_params import SnappiTestParams
from tests.common import config_reload

logger = logging.getLogger(__name__)

class TrimMode(StrEnum):
    """
    Enum for Packet Trimming Modes
    """
    SYMMETRIC = "symmetric"
    ASYMMETRIC = "asymmetric"


"""Helper to apply packet trimming mode for Snappi based packet trimming tests.

This utility configures global switch trimming parameters and (for asymmetric
mode) ensures a TC->DSCP map is applied on the egress port used for the test.

Symmetric mode requirements:
  * Global trimming configured with explicit DSCP value (TRIM_DSCP)
  * PORT_QOS_MAP entry for egress port MUST NOT contain 'tc_to_dscp_map'

Asymmetric mode requirements:
  * Global trimming configured with dscp from-tc and TC value (TRIM_TC)
  * TC_TO_DSCP_MAP present with mapping for TRIM_TC
  * PORT_QOS_MAP entry for egress port contains 'tc_to_dscp_map'
"""

TRIM_SIZE_DEFAULT = 256
TRIM_DSCP_DEFAULT = 11          # Symmetric DSCP value
TRIM_QUEUE_DEFAULT = 4          # Queue index
TRIM_TC_DEFAULT = 5             # TC used for asymmetric from-tc mode
ASYM_MAP_NAME = "spine_trim_map"
ASYM_MAP_DSCP_VALUE = 4


def _run_cmd(duthost, cmd: str):
    """Run a shell command on the duthost with logging."""
    logger.debug(f"Running on DUT: {cmd}")
    return duthost.shell(cmd)


def _get_switch_trimming(duthost) -> Optional[dict]:
    try:
        out = _run_cmd(duthost, "show switch-trimming global --json")
        if out.get('stdout'):
            return json.loads(out['stdout'])
    except Exception as e:  # pragma: no cover
        logger.warning(f"Failed to parse switch trimming JSON: {e}")
    return None


def get_max_supported_trim_ratio(duthost):
    """Return maximum supported TX/RX link ratio for trim drop correlation.

    Currently only NVIDIA/Mellanox SN5640 (Spectrum-5) platforms are
    supported with a maximum ratio of 8. If the DUT's HwSku is not one
    of the recognized SN5640 variants, return None so that callers can
    skip ratio-based equality assertions.

    Args:
        duthost: DUT host object (expects duthost.facts['hwsku'] or uses sonic-cfggen fallback)
    Returns:
        int | None: 8 if supported platform, else None.
    """
    hwsku = None
    try:
        if hasattr(duthost, 'facts'):
            hwsku = duthost.facts.get('hwsku')
    except Exception:
        hwsku = None
    if not hwsku:
        try:
            hwsku = duthost.shell("sonic-cfggen -d -v DEVICE_METADATA.localhost.hwsku")['stdout'].strip()
        except Exception:
            hwsku = None
    if not hwsku:
        return None
    hwsku_upper = hwsku.upper()
    sn5640_hwskus = {"MELLANOX-SN5640-C512S2", "MELLANOX-SN5640-C448O16"}
    if hwsku_upper in sn5640_hwskus:
        return 8
    return None


def apply_trim_mode(duthost,
                    trim_mode=TrimMode.SYMMETRIC,
                    snappi_test_params: Optional[SnappiTestParams] = None) -> None:
    """Apply symmetric or asymmetric trimming mode.

    Args:
        duthost: Ansible host instance (DUT)
        trim_mode: TrimMode enum value
        snappi_test_params: SnappiTestParams to derive egress port (rx peer port)
    """

    # Determine egress (switch TX) port name from snappi test params
    import pdb; pdb.set_trace()
    egress_port = None
    if snappi_test_params and snappi_test_params.base_flow_config:
        try:
            egress_port = str(snappi_test_params.base_flow_config["rx_port_config"].peer_port)
        except Exception:
            logger.debug("Unable to derive egress port from snappi_test_params.base_flow_config")

    pytest_assert(egress_port is not None,
                  "Failed to determine egress port for trimming configuration")

    logger.info(f"Applying trimming mode '{trim_mode}' on egress port {egress_port}")

    if trim_mode == TrimMode.SYMMETRIC:
        # Configure symmetric trimming: explicit DSCP value
        _run_cmd(duthost, f"sudo config switch-trimming global --size {TRIM_SIZE_DEFAULT} --dscp {TRIM_DSCP_DEFAULT}"
                 f" --queue {TRIM_QUEUE_DEFAULT}")
    else:  # ASYMMETRIC
        # Ensure TC_TO_DSCP_MAP & PORT_QOS_MAP entries exist
        # Create TC_TO_DSCP_MAP if missing
        tc_map_key = f"TC_TO_DSCP_MAP|{ASYM_MAP_NAME}"
        existing = _run_cmd(duthost, f"redis-cli -n 4 EXISTS '{tc_map_key}'")['stdout'].strip()
        if existing != '1':
            _run_cmd(duthost, f"redis-cli -n 4 HSET '{tc_map_key}' '{TRIM_TC_DEFAULT}' '{ASYM_MAP_DSCP_VALUE}'")
        current_map = _run_cmd(duthost, f"redis-cli -n 4 HGET 'PORT_QOS_MAP|{egress_port}'" 
                               f"'tc_to_dscp_map'")['stdout'].strip()
        if current_map != ASYM_MAP_NAME:
            _run_cmd(duthost, f"redis-cli -n 4 HSET 'PORT_QOS_MAP|{egress_port}' 'tc_to_dscp_map'"
                     f" '{ASYM_MAP_NAME}'")
        _run_cmd(duthost, f"sudo config switch-trimming global --size {TRIM_SIZE_DEFAULT} --dscp from-tc --tc "
                 f"{TRIM_TC_DEFAULT} --queue {TRIM_QUEUE_DEFAULT}")

    # Enable trimming on every queue profile EXCEPT the designated trim queue's profile.
    pdb.set_trace()
    trim_queue_key = f"BUFFER_QUEUE|{egress_port}|{TRIM_QUEUE_DEFAULT}"
    trim_queue_profile = _run_cmd(duthost, f"redis-cli -n 4 HGET '{trim_queue_key}' 'profile'")['stdout'].strip()
    pytest_assert(trim_queue_profile, f"Failed to fetch profile for {trim_queue_key}")
    logger.info(f"Trim queue profile for {trim_queue_key}: {trim_queue_profile}")

    processed_profiles = set()
    enabled_profiles = []
    skipped_profile = trim_queue_profile

    for qi in range(0, 8):
        queue_key = f"BUFFER_QUEUE|{egress_port}|{qi}"
        profile = _run_cmd(duthost, f"redis-cli -n 4 HGET '{queue_key}' 'profile'")['stdout'].strip()
        if not profile:
            continue
        if profile == skipped_profile:
            logger.debug(f"Skipping trimming enable for trim queue {queue_key} (profile {profile})")
            action = _run_cmd(duthost, f"redis-cli -n 4 HGET 'BUFFER_PROFILE|{profile}' " 
                              f"'packet_discard_action'")['stdout'].strip()
            if action == 'trim':
                logger.info(f"Disabling trimming on trim queue profile {profile}")
                _run_cmd(duthost, f"sudo config mmu -p {profile} -t off")
            continue
        if profile in processed_profiles:
            continue
        processed_profiles.add(profile)
        logger.info(f"Enabling trimming on profile {profile} (queue {qi})")
        _run_cmd(duthost, f"sudo config mmu -p {profile} -t on")
        enabled_profiles.append(profile)
    pdb.set_trace()
    # Verification: all enabled profiles have packet_discard_action=trim; skipped profile does not.
    for profile in enabled_profiles:
        action = _run_cmd(duthost, f"redis-cli -n 4 HGET 'BUFFER_PROFILE|{profile}' "
                          f"'packet_discard_action'")['stdout'].strip()
        pytest_assert(action == 'trim', f"Profile {profile} expected packet_discard_action=trim, got '{action}'")
    trim_action = _run_cmd(duthost, f"redis-cli -n 4 HGET 'BUFFER_PROFILE|{skipped_profile}' "
                           f"'packet_discard_action'")['stdout'].strip()
    if trim_action == 'trim':
        logger.warning(f"Trim queue profile {skipped_profile} still shows packet_discard_action=trim after "
                       f"disable attempt")

    cfg = _get_switch_trimming(duthost)
    pytest_assert(cfg is not None, "Failed to fetch switch trimming configuration")

    if trim_mode == TrimMode.SYMMETRIC:
        # Validate symmetric fields
        pytest_assert(str(cfg.get("size")) == str(TRIM_SIZE_DEFAULT), "Unexpected trim size")
        pytest_assert(str(cfg.get("dscp_value")) == str(TRIM_DSCP_DEFAULT), "Unexpected DSCP value in symmetric mode")
        pytest_assert(str(cfg.get("queue_index")) == str(TRIM_QUEUE_DEFAULT), "Unexpected queue index")
        tc_map_present = _run_cmd(duthost, f"redis-cli -n 4 HGET 'PORT_QOS_MAP|{egress_port}' "
                                  f"'tc_to_dscp_map'")['stdout'].strip()
        if tc_map_present:  # Remove if lingering
            _run_cmd(duthost, f"redis-cli -n 4 HDEL 'PORT_QOS_MAP|{egress_port}' 'tc_to_dscp_map'")
            tc_map_present = _run_cmd(duthost, f"redis-cli -n 4 HGET 'PORT_QOS_MAP|{egress_port}' "
                                               f"'tc_to_dscp_map'")['stdout'].strip()
        pytest_assert(tc_map_present == '', "tc_to_dscp_map should not exist for symmetric mode")
    else:
        # Validate asymmetric fields
        pytest_assert(str(cfg.get("size")) == str(TRIM_SIZE_DEFAULT), "Unexpected trim size")
        pytest_assert(cfg.get("dscp_value") == "from-tc", "Expected dscp_value 'from-tc' in asymmetric mode")
        pytest_assert(str(cfg.get("tc_value")) == str(TRIM_TC_DEFAULT), "Unexpected tc_value in asymmetric mode")
        pytest_assert(str(cfg.get("queue_index")) == str(TRIM_QUEUE_DEFAULT), "Unexpected queue index")
        # Ensure tc_to_dscp_map present
        tc_map_present = _run_cmd(duthost, f"redis-cli -n 4 HGET 'PORT_QOS_MAP|{egress_port}' "
                                  f"'tc_to_dscp_map'")['stdout'].strip()
        pytest_assert(tc_map_present == ASYM_MAP_NAME,
                      f"Expected tc_to_dscp_map '{ASYM_MAP_NAME}' for asymmetric mode, got '{tc_map_present}'")

    logger.info(f"Successfully applied and config validated trimming mode '{trim_mode}'")


def teardown_trim_mode(duthost) -> None:
    """Teardown helper: reload configuration from minigraph to restore default state.

    Steps:
      1. Reload config from minigraph (safe reload, ensure interfaces come up).
      2. Verify switch trimming global state is reset (size / dscp / tc may revert or command returns defaults).
         We don't assert specific default values, only that the command succeeds.
    """
    logger.info("Teardown: reloading configuration from minigraph to reset trimming changes")
    try:
        config_reload(duthost, config_source='minigraph', safe_reload=True, check_intf_up_ports=True)
    except Exception as e:
        logger.error(f"Failed to reload minigraph config: {e}")
        raise
    # Best-effort status check
    status = _get_switch_trimming(duthost)
    logger.info(f"Post-reload switch trimming status: {status}")


def redis_hgetall_table_prefix(duthost, table_prefix):
    """Return mapping name->field dict for all hash keys matching prefix in DB 4."""
    keys_out = duthost.shell(f"redis-cli -n 4 KEYS '{table_prefix}|*'")['stdout'].strip().splitlines()
    result = {}
    for key in keys_out:
        if not key:
            continue
        fields = duthost.shell(f"redis-cli -n 4 HGETALL '{key}'")['stdout'].strip().splitlines()
        entry = {}
        for i in range(0, len(fields), 2):
            if i+1 < len(fields):
                entry[fields[i]] = fields[i+1]
        result[key.split('|',1)[1]] = entry
    return result


def get_port_qos_map_names(duthost, port_name):
    """Return (dscp_to_tc_map, tc_to_queue_map) names for a port."""
    port_qos = duthost.shell(f"redis-cli -n 4 HGETALL 'PORT_QOS_MAP|{port_name}'")['stdout'].splitlines()
    dscp_to_tc = tc_to_q = None
    for i in range(0, len(port_qos), 2):
        if i+1 >= len(port_qos):
            break
        k, v = port_qos[i], port_qos[i+1]
        if k == 'dscp_to_tc_map':
            dscp_to_tc = v
        elif k == 'tc_to_queue_map':
            tc_to_q = v
    return dscp_to_tc, tc_to_q


def build_expected_queues(dscp_values, dscp_to_tc_map, tc_to_queue_map, dscp_map_name, tcq_map_name):
    """Build mapping DSCP->queue index with assertions."""
    expected = {}
    for dscp in dscp_values:
        tc_str = dscp_to_tc_map.get(str(dscp))
        pytest_assert(tc_str is not None, f"DSCP {dscp} not in DSCP_TO_TC map {dscp_map_name}")
        queue = tc_to_queue_map.get(tc_str)
        pytest_assert(queue is not None, f"TC {tc_str} not in TC_TO_QUEUE map {tcq_map_name}")
        expected[dscp] = int(queue)
    return expected


def collect_trim_counters(duthost, ports, trim_queue_index):
    """Collect total drops (non-trim queues) and total packets on trim queue."""
    total_drops = 0
    trim_pkts = 0
    for port in ports:
        counters_raw = duthost.shell(f"show queue counters {port} --all -j")['stdout']
        data = json.loads(counters_raw)
        port_data = data.get(port, {})
        pytest_assert(port_data, f"Missing queue data for {port}")
        for qname, qstats in port_data.items():
            if not qname.startswith('UC'):
                continue
            idx = int(qname[2:])
            totalpacket = qstats.get('totalpacket')
            droppacket = qstats.get('droppacket')
            totalpacket = int(totalpacket.replace(',','')) if totalpacket not in (None,'N/A') else 0
            droppacket = int(droppacket.replace(',','')) if droppacket not in (None,'N/A') else 0
            if idx == trim_queue_index:
                trim_pkts += totalpacket
            else:
                total_drops += droppacket
    return total_drops, trim_pkts


def get_trim_length_bucket_count(duthost, port, trim_size):
    """Infer packet length bucket count from portstat -l output for given trim size."""
    length_out = duthost.shell(f"portstat -l -i {port}")['stdout']
    if trim_size <= 255:
        bucket_label = 'Packets Transmitted 128-255 Octets'
    elif trim_size <= 511:
        bucket_label = 'Packets Transmitted 256-511 Octets'
    elif trim_size <= 1023:
        bucket_label = 'Packets Transmitted 512-1023 Octets'
    else:
        bucket_label = 'Packets Transmitted 1024-1518 Octets'
    bucket_count = 0
    for line in length_out.splitlines():
        if bucket_label in line:
            try:
                bucket_count = int(line.rsplit('.',1)[-1].strip().replace(',',''))
            except Exception:
                bucket_count = 0
            break
    return bucket_count


def validate_expected_queue_presence(duthost, ports, expected_queues, trim_queue_index):
    """Assert each expected queue (excluding trim queue) has >0 packets on at least one port."""
    queue_presence = {q: False for q in expected_queues.values()}
    for port in ports:
        counters_raw = duthost.shell(f"show queue counters {port} --all -j")['stdout']
        port_data = json.loads(counters_raw).get(port, {})
        for qname, qstats in port_data.items():
            if not qname.startswith('UC'):
                continue
            idx = int(qname[2:])
            if idx in queue_presence:
                totalpacket = qstats.get('totalpacket')
                if totalpacket and totalpacket not in ('0','N/A'):
                    queue_presence[idx] = True
    missing = [q for q, present in queue_presence.items() if not present and q != trim_queue_index]
    pytest_assert(not missing, f"Expected traffic in queues {missing} (mapped from DSCP) but none observed")
    return queue_presence


def verify_trimmed_traffic(duthost,
                           switch_egress_ports,
                           snappi_extra_params,
                           trim_mode,
                           ):
    """Verify trimmed traffic behavior.

    Checks:
      1. Packets egress on expected queues based on DSCP->TC->QUEUE maps.
      2. Sum of dropped packets across all non-trim queues approximately equals
         packets transmitted on trim queue (1% tolerance) unless tx/rx port
         ratio exceeds supported ratio in which case we skip the equality assertion.
      3. Packets on trim queue reflect trimmed size (TRIM_SIZE_DEFAULT) and
         trim queue packet count matches drop sum (same tolerance) when ratio supported.

    Args:
        duthost: DUT host object
        switch_egress_ports (list[str]): egress port names to check
        snappi_extra_params (SnappiTestParams): test params (needs tx_dscp_values, num_tx_links, num_rx_links)
    """
    import pdb; pdb.set_trace()
    pytest_assert(switch_egress_ports, "switch_egress_ports must be non-empty")
    dscp_values = snappi_extra_params.tx_dscp_values
    pytest_assert(dscp_values, "snappi_extra_params.tx_dscp_values must be set")

    dscp_to_tc_map_name, tc_to_queue_map_name = get_port_qos_map_names(duthost, switch_egress_ports[0])
    pytest_assert(dscp_to_tc_map_name is not None, "dscp_to_tc_map not set on port")
    pytest_assert(tc_to_queue_map_name is not None, "tc_to_queue_map not set on port")

    dscp_to_tc_all = redis_hgetall_table_prefix(duthost, 'DSCP_TO_TC_MAP')
    tc_to_queue_all = redis_hgetall_table_prefix(duthost, 'TC_TO_QUEUE_MAP')
    pytest_assert(dscp_to_tc_map_name in dscp_to_tc_all, f"DSCP_TO_TC map {dscp_to_tc_map_name} missing")
    pytest_assert(tc_to_queue_map_name in tc_to_queue_all, f"TC_TO_QUEUE map {tc_to_queue_map_name} missing")

    expected_queues = build_expected_queues(dscp_values,
                                            dscp_to_tc_all[dscp_to_tc_map_name],
                                            tc_to_queue_all[tc_to_queue_map_name],
                                            dscp_to_tc_map_name,
                                            tc_to_queue_map_name)

    total_drops_all, trim_queue_packets_all = collect_trim_counters(duthost, switch_egress_ports, TRIM_QUEUE_DEFAULT)

    ratio_supported = True
    max_supported_ratio = get_max_supported_trim_ratio(duthost)
    if snappi_extra_params.num_tx_links and snappi_extra_params.num_rx_links and snappi_extra_params.num_rx_links > 0:
        ratio = snappi_extra_params.num_tx_links / snappi_extra_params.num_rx_links
        if max_supported_ratio is None or ratio > max_supported_ratio:
            ratio_supported = False
            logger.info(f"TX/RX link ratio {ratio} exceeds supported {max_supported_ratio}, "
                     f"skipping drop/trim packet equality assertion")

    if ratio_supported:
        tol = max(1, int(0.01 * max(trim_queue_packets_all, 1)))
        diff = abs(total_drops_all - trim_queue_packets_all)
        pytest_assert(
            diff <= tol,
            f"Mismatch drops ({total_drops_all}) vs trim queue packets ({trim_queue_packets_all}) "
            f"with tol {tol} (max_supported_ratio={max_supported_ratio})")

    bucket_count = get_trim_length_bucket_count(duthost, switch_egress_ports[0], TRIM_SIZE_DEFAULT)
    if ratio_supported:
        tol = max(1, int(0.01 * max(trim_queue_packets_all, 1)))
        diff = abs(bucket_count - trim_queue_packets_all)
        pytest_assert(
            diff <= tol,
            (
            f"Trimmed size bucket count {bucket_count} differs from trim queue packets "
            f"{trim_queue_packets_all} tol {tol} (max_supported_ratio={max_supported_ratio})"
            )
        )

    queue_presence = validate_expected_queue_presence(duthost,
                                                      switch_egress_ports,
                                                      expected_queues,
                                                      TRIM_QUEUE_DEFAULT,
                                                      )

    logger.info(f"verify_trimmed_traffic: drops={total_drops_all} trim_packets={trim_queue_packets_all} "
                f"ratio_supported={ratio_supported} max_ratio={max_supported_ratio} queue_presence={queue_presence}")
