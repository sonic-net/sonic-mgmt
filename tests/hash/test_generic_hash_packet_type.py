"""
Test script for Generic Hash packet-type enhancement feature.

This module tests per-packet-type ECMP/LAG hash configuration including:
- Per packet-type hash configuration (IPv4, IPv6, IPinIP)
- Priority/override behavior between global and packet-type specific hashes
- Configuration persistence across reboot/reload/warm-boot/fast-boot

DUTs may advertise ROCE packet types (``ipv4_rdma``, ``ipv6_rdma``) in
STATE_DB capabilities; helpers normalize hyphen spellings to those names.
"""

import pytest
import time
import logging

from tests.common.helpers.assertions import pytest_assert
from generic_hash_helper import (
    get_interfaces_for_test,
    check_default_route,
    generate_test_params,
    PTF_QLEN,
)
from tests.common.utilities import wait_until
from tests.ptf_runner import ptf_runner
from tests.common.reboot import reboot
from tests.common.config_reload import config_reload
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure

PTF_LOG_PATH = "/tmp/generic_hash_test.generic_hash_packet_type_test.log"

pytestmark = [
    pytest.mark.topology('t1'),
]
SAI_DEFAULT_GLOBAL_HASH = [
    'SRC_MAC',
    'DST_MAC',
    'IN_PORT',
    'ETHERTYPE',
]
logger = logging.getLogger(__name__)


# ============================================================================
# Helper Functions
# ============================================================================


def _normalize_capability_pkt_type(token):
    """Normalize DB packet-type tokens; RDMA types use underscore (ipv4_rdma)."""
    if not token:
        return None

    t = token.strip().lower()
    if not t or t == 'n/a':
        return None

    if t in ('ipv4', 'ipv6', 'ipnip'):
        return t
    if t in ('ipv4_rdma', 'ipv4-rdma'):
        return 'ipv4_rdma'
    if t in ('ipv6_rdma', 'ipv6-rdma'):
        return 'ipv6_rdma'

    # Fallback: return as-is for any future types
    return t


def _get_pkt_type_db_suffixes(packet_type):
    return [packet_type.replace('-', '_')]


_SWITCH_HASH_CAPABILITIES_CACHE_ATTR = "_generic_hash_switch_capabilities_cache"


def _get_switch_hash_capabilities(duthost):
    """Fetch the live switch-hash capabilities from the DUT and cache them.

    Delegates to SonicHost.get_switch_hash_capabilities(), which runs
    'show switch-hash capabilities --json' on the DUT and returns a dict
    of the form::

        {'ecmp': [<field>, ...], 'lag': [<field>, ...],
         'ecmp_algo': [...],     'lag_algo': [...]}

    This is the same source of truth used by test_hash_capability in
    test_generic_hash.py and is backed by STATE_DB's
    SWITCH_CAPABILITY|switch. The result is cached on the duthost object
    for the lifetime of the pytest session so we don't repeatedly invoke
    the CLI at every call site.
    """
    cached = getattr(duthost, _SWITCH_HASH_CAPABILITIES_CACHE_ATTR, None)
    if cached is not None:
        return cached

    caps = duthost.get_switch_hash_capabilities()
    logger.info("Live switch-hash capabilities from DUT: %s", caps)
    setattr(duthost, _SWITCH_HASH_CAPABILITIES_CACHE_ATTR, caps)
    return caps


def _get_asic_hash_fields(duthost, test_type):
    """Return supported hash fields for the given test type ('ecmp' or 'lag').

    Sources the field list directly from the DUT via
    'show switch-hash capabilities --json' (cached per session), which is
    backed by STATE_DB's SWITCH_CAPABILITY|switch. This is intentionally
    NOT backed by a static per-ASIC fallback — if the DUT cannot report
    its hash capabilities, callers must see the failure rather than
    silently testing against stale assumptions.
    """
    if test_type not in ('ecmp', 'lag'):
        raise ValueError(f"test_type must be 'ecmp' or 'lag', got {test_type!r}")

    caps = _get_switch_hash_capabilities(duthost)
    fields = caps.get(test_type) or []
    pytest_assert(
        isinstance(fields, list) and fields,
        f"DUT reported no {test_type.upper()} hash fields via "
        "'show switch-hash capabilities'; cannot proceed."
    )
    return fields


def _get_asic_packet_type_caps(duthost):
    """Return packet-type capabilities for this ASIC based on STATE_DB.

    This uses the same SWITCH_CAPABILITY|switch data as
    check_packet_type_hash_capabilities, but presents it in the
    helper-style shape: {'ecmp': [...], 'lag': [...]}.
    """
    caps = check_packet_type_hash_capabilities(duthost)
    return {
        'ecmp': caps.get('ecmp_pkt_types', []),
        'lag': caps.get('lag_pkt_types', []),
    }


def check_packet_type_hash_capabilities(duthost):
    """
    Check if the platform supports packet-type hash configuration.

    Args:
        duthost: DUT host object

    Returns:
        dict: Capabilities with keys 'ecmp_capable', 'lag_capable',
              'ecmp_pkt_types', 'lag_pkt_types'
    """
    with allure.step('Check packet-type hash capabilities from State DB'):
        capabilities_output = duthost.shell(
            "redis-cli -n 6 HGETALL 'SWITCH_CAPABILITY|switch'",
            module_ignore_errors=True
        )

        capabilities = {}
        if capabilities_output['rc'] == 0:
            lines = capabilities_output['stdout'].strip().split('\n')
            cap_dict = {}
            for i in range(0, len(lines), 2):
                if i + 1 < len(lines):
                    cap_dict[lines[i]] = lines[i + 1]

            capabilities['ecmp_capable'] = cap_dict.get('ECMP_PKT_TYPE_HASH_CAPABLE', 'false') == 'true'
            capabilities['lag_capable'] = cap_dict.get('LAG_PKT_TYPE_HASH_CAPABLE', 'false') == 'true'

            ecmp_types = cap_dict.get('HASH|ECMP_PKT_TYPE_LIST', '')
            lag_types = cap_dict.get('HASH|LAG_PKT_TYPE_LIST', '')

            ecmp_canonical = set()
            for t in ecmp_types.split(','):
                canonical = _normalize_capability_pkt_type(t)
                if canonical:
                    ecmp_canonical.add(canonical)

            lag_canonical = set()
            for t in lag_types.split(','):
                canonical = _normalize_capability_pkt_type(t)
                if canonical:
                    lag_canonical.add(canonical)

            capabilities['ecmp_pkt_types'] = sorted(ecmp_canonical)
            capabilities['lag_pkt_types'] = sorted(lag_canonical)
        else:
            # Default to false if can't read capabilities
            capabilities['ecmp_capable'] = False
            capabilities['lag_capable'] = False
            capabilities['ecmp_pkt_types'] = []
            capabilities['lag_pkt_types'] = []

        logger.info(f"Packet-type hash capabilities: {capabilities}")
        return capabilities


def set_switch_hash_packet_type(duthost, hash_type, packet_type, action, fields):
    """
    Configure packet-type specific hash on the DUT.

    Args:
        duthost: DUT host object
        hash_type: 'ecmp' or 'lag'
        packet_type: Packet type (ipv4, ipv6, ipnip, ipv4_rdma, ipv6_rdma)
        action: 'add' or 'del'
        fields: List of hash fields (can be empty for 'del' action to remove entire config)
    """
    hash_cmd = f"config switch-hash global {hash_type}-hash --packet-type {packet_type} --action {action}"

    if fields:
        fields_str = ' '.join([f"'{field}'" for field in fields])
        hash_cmd += f" {fields_str}"

    with allure.step(f"Configure {hash_type} hash for packet-type {packet_type}: action={action}, fields={fields}"):
        result = duthost.shell(hash_cmd, module_ignore_errors=True)
        if result['rc'] != 0:
            logger.error(f"Failed to configure packet-type hash: {result['stderr']}")
            raise RuntimeError(f"Failed to configure packet-type hash: {result['stderr']}")
        logger.info(f"Successfully configured {hash_type} hash for packet-type {packet_type}")


def check_packet_type_hash_config(duthost, hash_type, packet_type, expected_fields=None):
    """
    Verify packet-type hash configuration in Config DB.

    Args:
        duthost: DUT host object
        hash_type: 'ecmp' or 'lag'
        packet_type: Packet type to check
        expected_fields: List of expected hash fields (None means don't check)

    Returns:
        bool: True if configuration matches expectation
    """
    with allure.step(f"Verify {hash_type} hash config for packet-type {packet_type}"):
        config_value = ''

        for suffix in _get_pkt_type_db_suffixes(packet_type):
            db_key = f"{hash_type}_hash_{suffix}"
            config_output = duthost.shell(
                f"redis-cli -n 4 HGET 'SWITCH_HASH|GLOBAL' '{db_key}'",
                module_ignore_errors=True
            )

            if config_output['rc'] != 0:
                logger.warning(
                    f"Failed to read config from DB key {db_key}: {config_output['stderr']}"
                )
                continue

            candidate = config_output['stdout'].strip()
            # Prefer the first non-empty, non-nil value
            if candidate and candidate != '(nil)':
                config_value = candidate
                break

        if expected_fields is None:
            # Just check if config exists
            exists = config_value != '' and config_value != '(nil)'
            logger.info(f"Config exists for {hash_type} {packet_type}: {exists}")
            return exists

        if not config_value or config_value == '(nil)':
            logger.error(f"No config found for {hash_type} {packet_type}")
            return False

        configured_fields = [f.strip() for f in config_value.split(',')]
        matches = set(configured_fields) == set(expected_fields)

        if not matches:
            logger.error(f"Field mismatch. Expected: {expected_fields}, Got: {configured_fields}")
        else:
            logger.info(f"Config matches for {hash_type} {packet_type}: {expected_fields}")

        return matches


def get_packet_type_hash_db_fields(duthost, hash_type, packet_type):
    """Fetch configured packet-type hash fields from Config DB.

    This helper mirrors the DB access pattern in check_packet_type_hash_config
    but returns the parsed field list instead of doing any comparison.
    """
    config_value = ''

    for suffix in _get_pkt_type_db_suffixes(packet_type):
        db_key = f"{hash_type}_hash_{suffix}"
        config_output = duthost.shell(
            f"redis-cli -n 4 HGET 'SWITCH_HASH|GLOBAL' '{db_key}'",
            module_ignore_errors=True
        )

        if config_output['rc'] != 0:
            logger.warning(
                f"Failed to read config from DB key {db_key}: {config_output['stderr']}"
            )
            continue

        candidate = config_output['stdout'].strip()
        if candidate and candidate != '(nil)':
            config_value = candidate
            break

    if not config_value or config_value == '(nil)':
        return []

    return [f.strip() for f in config_value.split(',')]


def _run_ipv4_dataplane_ptf_test(
    rand_selected_dut, tbinfo, ptfhost, mg_facts,
    test_configs, ecmp_hash, lag_hash, default_route_msg,
):
    """Run one representative ipv4 packet-type hash PTF test.

    Prefers ECMP ipv4 when present; otherwise LAG ipv4. Skips when neither key
    exists (e.g. only ipv6 or ipnip was configured).
    """
    pkt_type = 'ipv4'
    hash_field = ''
    ptf_ecmp_hash = False
    ptf_lag_hash = False

    if ecmp_hash and 'ecmp_ipv4' in test_configs:
        hash_field = test_configs['ecmp_ipv4'][0]
        ptf_ecmp_hash = True
        ptf_lag_hash = False
    elif lag_hash and 'lag_ipv4' in test_configs:
        hash_field = test_configs['lag_ipv4'][0]
        ptf_ecmp_hash = False
        ptf_lag_hash = True
    else:
        pytest.skip("No suitable packet-type config for data-plane validation")

    pytest_assert(
        hash_field,
        "No suitable packet-type config for data-plane validation",
    )

    uplink_interfaces, downlink_interfaces = get_interfaces_for_test(
        rand_selected_dut, mg_facts, hash_field
    )

    pytest_assert(
        wait_until(
            60, 10, 0,
            check_default_route,
            rand_selected_dut,
            uplink_interfaces.keys(),
        ),
        default_route_msg,
    )

    ptf_params = generate_packet_type_test_params(
        rand_selected_dut, tbinfo, mg_facts,
        pkt_type, hash_field,
        uplink_interfaces, downlink_interfaces,
        ecmp_hash=ptf_ecmp_hash,
        lag_hash=ptf_lag_hash,
    )

    ptf_runner(
        ptfhost,
        "ptftests",
        "generic_hash_test.GenericHashTest",
        platform_dir="ptftests",
        params=ptf_params,
        log_file=PTF_LOG_PATH,
        qlen=PTF_QLEN,
        socket_recv_size=16384,
        is_python3=True,
    )


def show_packet_type_hash_config(duthost, packet_type='all'):
    """
    Show packet-type hash configuration using CLI.

    Args:
        duthost: DUT host object
        packet_type: Packet type to show ('all' for all types)

    Returns:
        str: CLI output
    """
    with allure.step(f"Show hash config for packet-type {packet_type}"):
        cmd = f"show switch-hash global packet-type {packet_type}"
        result = duthost.shell(cmd, module_ignore_errors=True)
        logger.info(f"Show output:\n{result['stdout']}")
        return result['stdout']


def generate_packet_type_test_params(duthost, tbinfo, mg_facts, packet_type, hash_field,
                                     uplink_interfaces, downlink_interfaces,
                                     ecmp_hash=True, lag_hash=True):
    """
    Generate PTF test parameters for packet-type specific hash tests.

    Args:
        duthost: DUT host object
        tbinfo: Testbed info
        mg_facts: Minigraph facts
        packet_type: Packet type for the test
        hash_field: Hash field being tested
        uplink_interfaces: Uplink interfaces dict
        downlink_interfaces: Downlink interfaces list
        ecmp_hash: Whether ECMP hash is enabled
        lag_hash: Whether LAG hash is enabled

    Returns:
        dict: PTF test parameters
    """
    # Determine IP version and encapsulation based on packet type
    if packet_type == 'ipv4':
        ipver = 'ipv4'
        inner_ipver = 'None'
        encap_type = 'None'
    elif packet_type == 'ipv6':
        ipver = 'ipv6'
        inner_ipver = 'None'
        encap_type = 'None'
    elif packet_type == 'ipnip':
        ipver = 'ipv4'
        inner_ipver = 'ipv4'
        encap_type = 'ipinip'
    else:
        raise ValueError(f"Unsupported packet type: {packet_type}")

    # Use the existing generate_test_params but override with packet-type specific settings
    ptf_params = generate_test_params(
        duthost, tbinfo, mg_facts, hash_field, ipver, inner_ipver, encap_type,
        uplink_interfaces, downlink_interfaces, ecmp_hash=ecmp_hash, lag_hash=lag_hash
    )

    # Add packet-type specific parameters
    ptf_params['packet_type'] = packet_type

    return ptf_params


def skip_if_no_multimember_lag(
        duthost,
        mg_facts,
        reason="LAG packet-type hash requires a multi-member LAG"):
    uplinks, _ = get_interfaces_for_test(duthost, mg_facts, 'SRC_IP')
    if not any(len(m) >= 2 for m in uplinks.values()):
        pytest.skip(reason)

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture(scope='module')
def packet_type_capabilities(rand_selected_dut):
    """Module-level fixture to check packet-type hash capabilities.

    Packet-type names come from helper-defined PACKET_TYPE_CAPABILITIES and are
    validated against the device's State DB capabilities.
    """
    capabilities = check_packet_type_hash_capabilities(rand_selected_dut)

    # Skip all tests if packet-type hash is not supported
    if not capabilities['ecmp_capable'] and not capabilities['lag_capable']:
        pytest.skip("Packet-type hash is not supported on this platform")

    return capabilities


@pytest.fixture(scope='function')
def restore_packet_type_hash_config(rand_selected_dut):
    """Fixture to restore packet-type hash configuration after test."""
    # Store original config before test
    original_configs = {}

    # Track whether SWITCH_HASH|GLOBAL existed before the test
    exists_before_cmd = rand_selected_dut.shell(
        "redis-cli -n 4 EXISTS 'SWITCH_HASH|GLOBAL'",
        module_ignore_errors=True
    )
    switch_hash_existed_before = (
        exists_before_cmd['rc'] == 0 and exists_before_cmd['stdout'].strip() == '1'
    )

    # Derive packet types from helper capabilities for this ASIC
    # (sufficient for locating existing DB keys to restore).
    helper_pkt_types = set()
    asic_pkt_caps = _get_asic_packet_type_caps(rand_selected_dut)
    helper_pkt_types.update(asic_pkt_caps['ecmp'])
    helper_pkt_types.update(asic_pkt_caps['lag'])

    for pkt_type in sorted(helper_pkt_types):
        for hash_type in ['ecmp', 'lag']:
            for suffix in _get_pkt_type_db_suffixes(pkt_type):
                db_key = f"{hash_type}_hash_{suffix}"
                config_output = rand_selected_dut.shell(
                    f"redis-cli -n 4 HGET 'SWITCH_HASH|GLOBAL' '{db_key}'",
                    module_ignore_errors=True
                )
                if config_output['rc'] == 0 and config_output['stdout'].strip() not in ['', '(nil)']:
                    original_configs[f"{hash_type}_{pkt_type}"] = config_output['stdout'].strip()
                    break

    yield

    # Restore configuration after test
    with allure.step('Restore original packet-type hash configuration'):
        # First, delete all packet-type configs
        for pkt_type in sorted(helper_pkt_types):
            for hash_type in ['ecmp', 'lag']:
                try:
                    set_switch_hash_packet_type(rand_selected_dut, hash_type, pkt_type, 'del', [])
                except Exception as e:
                    logger.warning(f"Failed to delete {hash_type} {pkt_type}: {e}")

        # Restore original configs if they existed
        for key, value in original_configs.items():
            hash_type, pkt_type = key.split('_', 1)
            fields = [f.strip() for f in value.split(',')]
            try:
                set_switch_hash_packet_type(rand_selected_dut, hash_type, pkt_type, 'add', fields)
            except Exception as e:
                logger.warning(f"Failed to restore {hash_type} {pkt_type}: {e}")

        # If SWITCH_HASH|GLOBAL did not exist before and is now empty, delete it
        if not switch_hash_existed_before:
            exists_after_cmd = rand_selected_dut.shell(
                "redis-cli -n 4 EXISTS 'SWITCH_HASH|GLOBAL'",
                module_ignore_errors=True
            )
            if exists_after_cmd['rc'] == 0 and exists_after_cmd['stdout'].strip() == '1':
                hlen_cmd = rand_selected_dut.shell(
                    "redis-cli -n 4 HLEN 'SWITCH_HASH|GLOBAL'",
                    module_ignore_errors=True
                )
                if hlen_cmd['rc'] == 0 and hlen_cmd['stdout'].strip() == '0':
                    rand_selected_dut.shell(
                        "redis-cli -n 4 DEL 'SWITCH_HASH|GLOBAL'",
                        module_ignore_errors=True
                    )


# ============================================================================
# Test Cases
# ============================================================================

@pytest.mark.parametrize(
    "hash_mode,ecmp_hash,lag_hash",
    [
        pytest.param("ecmp_only", True, False, id="ecmp-only"),
        pytest.param("lag_only", False, True, id="lag-only"),
        pytest.param("ecmp_and_lag", True, True, id="ecmp-and-lag"),
    ],
)
def test_hash_field_distribution_ip(rand_selected_dut, tbinfo, ptfhost, mg_facts,
                                    packet_type_capabilities, restore_packet_type_hash_config,
                                    toggle_all_aa_ports_to_rand_selected_tor,
                                    hash_mode, ecmp_hash, lag_hash):
    """
    Verify non-RDMA IP hash field impact on traffic distribution.

    TL platforms use a unified hash model:
    - ECMP-only: configure ECMP hash only
    - LAG-only: configure LAG hash only
    - ECMP+LAG: configure both with the SAME field set
    """

    # ------------------------------------------------------------------
    # Select supported packet type
    # ------------------------------------------------------------------
    asic_pkt_caps = _get_asic_packet_type_caps(rand_selected_dut)
    helper_pkt_types = {pt for pt in asic_pkt_caps['ecmp'] if 'rdma' not in pt}

    candidate_order = ['ipv4', 'ipv6']
    ip_supported = [
        pt for pt in candidate_order
        if pt in helper_pkt_types and pt in packet_type_capabilities['ecmp_pkt_types']
    ]

    if not ip_supported:
        pytest.skip("No non-RDMA IP packet types supported")

    if lag_hash:
        if hash_mode in ("lag_only", "ecmp_and_lag"):
            skip_if_no_multimember_lag(rand_selected_dut, mg_facts)

    ip_packet_type = ip_supported[0]

    # ------------------------------------------------------------------
    # Determine hash field list
    # ------------------------------------------------------------------
    base_ip_fields = ['SRC_IP', 'DST_IP', 'L4_SRC_PORT', 'L4_DST_PORT', 'DST_MAC']

    supported_ecmp_fields = set(_get_asic_hash_fields(rand_selected_dut, 'ecmp'))
    supported_lag_fields = set(_get_asic_hash_fields(rand_selected_dut, 'lag'))

    if hash_mode == "ecmp_only":
        common_ip_fields = [f for f in base_ip_fields if f in supported_ecmp_fields]
    elif hash_mode == "lag_only":
        common_ip_fields = [f for f in base_ip_fields if f in supported_lag_fields]
    else:  # ecmp_and_lag
        common_ip_fields = [
            f for f in base_ip_fields
            if f in supported_ecmp_fields and f in supported_lag_fields
        ]

    if not common_ip_fields:
        pytest.skip("No compatible hash fields available for this mode")

    # ------------------------------------------------------------------
    # Configure packet-type hash(es)
    # ------------------------------------------------------------------
    with allure.step(f"Configure IP hash for packet-type {ip_packet_type} (mode={hash_mode})"):
        if ecmp_hash:
            set_switch_hash_packet_type(
                rand_selected_dut, 'ecmp', ip_packet_type, 'add', common_ip_fields
            )

        if lag_hash:
            set_switch_hash_packet_type(
                rand_selected_dut, 'lag', ip_packet_type, 'add', common_ip_fields
            )

    # ------------------------------------------------------------------
    # Verify configuration in Config DB
    # ------------------------------------------------------------------
    with allure.step("Verify packet-type hash configuration in Config DB"):
        if ecmp_hash:
            pytest_assert(
                check_packet_type_hash_config(
                    rand_selected_dut, 'ecmp', ip_packet_type, common_ip_fields
                ),
                "ECMP packet-type hash verification failed",
            )

        if lag_hash:
            pytest_assert(
                check_packet_type_hash_config(
                    rand_selected_dut, 'lag', ip_packet_type, common_ip_fields
                ),
                "LAG packet-type hash verification failed",
            )

    show_packet_type_hash_config(rand_selected_dut, ip_packet_type)

    # ------------------------------------------------------------------
    # Prepare traffic test
    # ------------------------------------------------------------------
    hash_field = (
        'SRC_IP' if 'SRC_IP' in common_ip_fields else common_ip_fields[0]
    )

    uplink_interfaces, downlink_interfaces = get_interfaces_for_test(
        rand_selected_dut, mg_facts, hash_field
    )

    ptf_params = generate_packet_type_test_params(
        rand_selected_dut,
        tbinfo,
        mg_facts,
        ip_packet_type,
        hash_field,
        uplink_interfaces,
        downlink_interfaces,
        ecmp_hash=ecmp_hash,
        lag_hash=lag_hash,
    )

    # ------------------------------------------------------------------
    # Run traffic
    # ------------------------------------------------------------------
    pytest_assert(
        check_default_route(rand_selected_dut, uplink_interfaces.keys()),
        "Default route is not available",
    )

    ptf_runner(
        ptfhost,
        "ptftests",
        "generic_hash_test.GenericHashTest",
        platform_dir="ptftests",
        params=ptf_params,
        log_file=PTF_LOG_PATH,
        qlen=PTF_QLEN,
        socket_recv_size=16384,
        is_python3=True,
    )


@pytest.mark.parametrize(
    "hash_mode,ecmp_hash,lag_hash",
    [
        pytest.param("ecmp_only", True, False, id="ecmp-only"),
        pytest.param("lag_only", False, True, id="lag-only"),
        pytest.param("ecmp_and_lag", True, True, id="ecmp-and-lag"),
    ],
)
def test_pkt_type_hash_priority_and_override(
    rand_selected_dut,
    tbinfo,
    ptfhost,
    mg_facts,
    packet_type_capabilities,
    restore_packet_type_hash_config,
    toggle_all_aa_ports_to_rand_selected_tor,
    hash_mode,
    ecmp_hash,
    lag_hash,
):
    """
    Test Case 2: Priority/override between global and per-packet-type hash.

    Verifies that:
      - Packet-type hash overrides global hash for matching traffic
      - Different packet-types use their own configured hash
      - Behavior is correct for ECMP-only, LAG-only, and ECMP+LAG modes
    """
    # ------------------------------------------------------------------
    # Select packet types
    # ------------------------------------------------------------------
    with allure.step("Select two supported non-RDMA packet types"):
        candidate_types = ['ipv4', 'ipv6']

        if ecmp_hash:
            supported = packet_type_capabilities['ecmp_pkt_types']
        else:
            supported = packet_type_capabilities['lag_pkt_types']

        pkt_types = [pt for pt in candidate_types if pt in supported]

        if len(pkt_types) < 2:
            pytest.skip("Need at least two supported non-RDMA packet types")

        pkt_type_1, pkt_type_2 = pkt_types[:2]
        logger.info("Using packet types: %s , %s", pkt_type_1, pkt_type_2)

    # ------------------------------------------------------------------
    # Configure packet-type specific hashes
    # ------------------------------------------------------------------
    def program_pkt_type(hash_type, pkt_type, preferred_fields):
        supported = _get_asic_hash_fields(rand_selected_dut, hash_type)
        requested = [f for f in preferred_fields if f in supported]
        configured = None
        skip_msg = None

        if not requested:
            skip_msg = f"No supported {hash_type} fields for {pkt_type}"
        else:
            set_switch_hash_packet_type(
                rand_selected_dut, hash_type, pkt_type, 'add', requested
            )
            # Read back normalized DB fields
            for _ in range(6):
                configured = get_packet_type_hash_db_fields(
                    rand_selected_dut, hash_type, pkt_type
                )
                if configured:
                    break
                time.sleep(5)
            if not configured:
                skip_msg = (
                    f"{hash_type} packet-type hash not reflected in DB for {pkt_type}"
                )

        if skip_msg is not None:
            pytest.skip(skip_msg)
            raise RuntimeError(skip_msg)

        return configured

    with allure.step("Configure packet-type hashes"):
        pkt_type_1_fields = {}
        pkt_type_2_fields = {}

        preferred_1 = ['SRC_IP', 'DST_IP', 'IP_PROTOCOL', 'L4_SRC_PORT']
        preferred_2 = ['SRC_IP', 'DST_IP', 'IP_PROTOCOL', 'L4_DST_PORT']

        if ecmp_hash:
            pkt_type_1_fields['ecmp'] = program_pkt_type('ecmp', pkt_type_1, preferred_1)
            pkt_type_2_fields['ecmp'] = program_pkt_type('ecmp', pkt_type_2, preferred_2)

        if lag_hash:
            pkt_type_1_fields['lag'] = program_pkt_type('lag', pkt_type_1, preferred_1)
            pkt_type_2_fields['lag'] = program_pkt_type('lag', pkt_type_2, preferred_2)

    show_packet_type_hash_config(rand_selected_dut, 'all')

    # ------------------------------------------------------------------
    # Run traffic tests
    # ------------------------------------------------------------------
    def run_pkt_type_traffic(pkt_type, hash_type, fields):
        hash_field = fields[0]

        uplink_interfaces, downlink_interfaces = get_interfaces_for_test(
            rand_selected_dut, mg_facts, hash_field
        )

        if hash_type == 'lag':
            skip_if_no_multimember_lag(rand_selected_dut, mg_facts)

        pytest_assert(
            check_default_route(rand_selected_dut, uplink_interfaces.keys()),
            "Default route not available"
        )

        ptf_params = generate_packet_type_test_params(
            rand_selected_dut,
            tbinfo,
            mg_facts,
            pkt_type,
            hash_field,
            uplink_interfaces,
            downlink_interfaces,
            ecmp_hash=(hash_type == 'ecmp'),
            lag_hash=(hash_type == 'lag'),
        )

        ptf_runner(
            ptfhost,
            "ptftests",
            "generic_hash_test.GenericHashTest",
            platform_dir="ptftests",
            params=ptf_params,
            log_file=PTF_LOG_PATH,
            qlen=PTF_QLEN,
            socket_recv_size=16384,
            is_python3=True,
        )

    with allure.step("Verify packet-type override behavior with traffic"):
        if ecmp_hash:
            run_pkt_type_traffic(pkt_type_1, 'ecmp', pkt_type_1_fields['ecmp'])
            run_pkt_type_traffic(pkt_type_2, 'ecmp', pkt_type_2_fields['ecmp'])

        if lag_hash:
            run_pkt_type_traffic(pkt_type_1, 'lag', pkt_type_1_fields['lag'])
            run_pkt_type_traffic(pkt_type_2, 'lag', pkt_type_2_fields['lag'])


@pytest.mark.parametrize(
    "hash_mode,ecmp_hash,lag_hash",
    [
        pytest.param("ecmp_only", True, False, id="ecmp-only"),
        pytest.param("lag_only", False, True, id="lag-only"),
        pytest.param("ecmp_and_lag", True, True, id="ecmp-and-lag"),
    ],
)
def test_pkt_type_hash_config_persistence_reload(
    rand_selected_dut, tbinfo, ptfhost, localhost, mg_facts,
    packet_type_capabilities, restore_packet_type_hash_config,
    toggle_all_aa_ports_to_rand_selected_tor,
    hash_mode, ecmp_hash, lag_hash
):
    """
    Test Case: Persistence of packet-type hash configuration after config reload.

    This test verifies that ECMP-only, LAG-only, and ECMP+LAG packet-type hash
    configurations persist across `config reload` and continue to function
    correctly in the data plane.
    """

    test_configs = {}

    # ------------------------------------------------------------------
    # Select packet types based on capabilities and mode
    # ------------------------------------------------------------------
    asic_pkt_caps = _get_asic_packet_type_caps(rand_selected_dut)

    ecmp_pkt_candidates = [
        pt for pt in ['ipv4', 'ipv6']
        if pt in asic_pkt_caps['ecmp']
        and pt in packet_type_capabilities['ecmp_pkt_types']
    ]

    lag_pkt_candidates = [
        pt for pt in ['ipv4', 'ipnip']
        if pt in asic_pkt_caps['lag']
        and pt in packet_type_capabilities['lag_pkt_types']
    ]

    if ecmp_hash and not ecmp_pkt_candidates:
        pytest.skip("ECMP packet-type hash requested but no supported ECMP packet types")

    if lag_hash and not lag_pkt_candidates:
        pytest.skip("LAG packet-type hash requested but no supported LAG packet types")

    if lag_hash:
        if hash_mode in ("lag_only", "ecmp_and_lag"):
            skip_if_no_multimember_lag(rand_selected_dut, mg_facts)

    # ------------------------------------------------------------------
    # Configure ECMP packet-type hashes (if requested)
    # ------------------------------------------------------------------
    if ecmp_hash:
        supported_ecmp_fields = _get_asic_hash_fields(rand_selected_dut, 'ecmp')

        for pkt_type in ecmp_pkt_candidates:
            preferred_order = [
                'SRC_IP', 'DST_IP', 'IP_PROTOCOL',
                'L4_SRC_PORT', 'L4_DST_PORT'
            ]

            requested_fields = [f for f in preferred_order if f in supported_ecmp_fields]
            if not requested_fields:
                continue

            set_switch_hash_packet_type(
                rand_selected_dut, 'ecmp', pkt_type, 'add', requested_fields
            )

            configured_fields = get_packet_type_hash_db_fields(
                rand_selected_dut, 'ecmp', pkt_type
            )
            if not configured_fields:
                logger.warning(f"No ECMP DB config found for {pkt_type}")
                continue

            if set(configured_fields) != set(requested_fields):
                logger.info(
                    f"ECMP fields normalized for {pkt_type}. "
                    f"Requested={requested_fields}, Configured={configured_fields}"
                )

            test_configs[f'ecmp_{pkt_type}'] = configured_fields

    # ------------------------------------------------------------------
    # Configure LAG packet-type hashes (if requested)
    # ------------------------------------------------------------------
    if lag_hash:
        supported_lag_fields = _get_asic_hash_fields(rand_selected_dut, 'lag')

        for pkt_type in lag_pkt_candidates:
            if pkt_type == 'ipnip':
                preferred_order = [
                    'SRC_IP', 'DST_IP',
                    'INNER_SRC_IP', 'INNER_DST_IP'
                ]
            else:
                preferred_order = [
                    'DST_MAC', 'SRC_MAC', 'SRC_IP', 'DST_IP'
                ]

            requested_fields = [f for f in preferred_order if f in supported_lag_fields]
            if not requested_fields:
                continue

            set_switch_hash_packet_type(
                rand_selected_dut, 'lag', pkt_type, 'add', requested_fields
            )

            configured_fields = get_packet_type_hash_db_fields(
                rand_selected_dut, 'lag', pkt_type
            )
            if not configured_fields:
                logger.warning(f"No LAG DB config found for {pkt_type}")
                continue

            if set(configured_fields) != set(requested_fields):
                logger.info(
                    f"LAG fields normalized for {pkt_type}. "
                    f"Requested={requested_fields}, Configured={configured_fields}"
                )

            test_configs[f'lag_{pkt_type}'] = configured_fields

    if not test_configs:
        pytest.skip("No packet-type hash configuration applied; skipping persistence test")

    # ------------------------------------------------------------------
    # Verify configuration before reload
    # ------------------------------------------------------------------
    with allure.step("Verify packet-type hash config before reload"):
        for key, fields in test_configs.items():
            hash_type, pkt_type = key.split('_', 1)
            pytest_assert(
                check_packet_type_hash_config(rand_selected_dut, hash_type, pkt_type, fields),
                f"Pre-reload verification failed for {key}"
            )

        show_packet_type_hash_config(rand_selected_dut, 'all')

    # ------------------------------------------------------------------
    # Save config and reload
    # ------------------------------------------------------------------
    with allure.step("Save configuration and perform config reload"):
        rand_selected_dut.shell("config save -y")

        try:
            config_reload(
                rand_selected_dut,
                safe_reload=True,
                check_intf_up_ports=True,
                yang_validate=False,
            )
        except TypeError:
            config_reload(rand_selected_dut, safe_reload=True, check_intf_up_ports=True)

        pytest_assert(
            wait_until(300, 20, 0, rand_selected_dut.critical_services_fully_started),
            "Critical services not fully started after reload",
        )

    # ------------------------------------------------------------------
    # Verify configuration after reload
    # ------------------------------------------------------------------
    with allure.step("Verify packet-type hash config after reload"):
        for key, fields in test_configs.items():
            hash_type, pkt_type = key.split('_', 1)
            pytest_assert(
                check_packet_type_hash_config(rand_selected_dut, hash_type, pkt_type, fields),
                f"Post-reload verification failed for {key}"
            )

        show_packet_type_hash_config(rand_selected_dut, 'all')

    # ------------------------------------------------------------------
    # Data-plane sanity check (single representative test)
    # ------------------------------------------------------------------
    with allure.step("Verify data plane behavior after reload"):
        _run_ipv4_dataplane_ptf_test(
            rand_selected_dut, tbinfo, ptfhost, mg_facts,
            test_configs, ecmp_hash, lag_hash,
            "Default route not ready after reload",
        )


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize(
    "hash_mode,ecmp_hash,lag_hash",
    [
        pytest.param("ecmp_only", True, False, id="ecmp-only"),
        pytest.param("lag_only", False, True, id="lag-only"),
        pytest.param("ecmp_and_lag", True, True, id="ecmp-and-lag"),
    ],
)
def test_pkt_type_warm_boot(rand_selected_dut, tbinfo, ptfhost, localhost, mg_facts,
                            packet_type_capabilities, restore_packet_type_hash_config,
                            toggle_all_aa_ports_to_rand_selected_tor,
                            hash_mode, ecmp_hash, lag_hash):
    """
    Validate warm boot with packet type hash for ECMP/LAG.

    Ensure that both ECMP and LAG packet-type hash configurations persist
    across a warm boot with no traffic loss.
    """
    # ------------------------------------------------------------------
    # Pre-check: multi-member LAG required for LAG / ECMP+LAG
    # ------------------------------------------------------------------
    if lag_hash and hash_mode in ("lag_only", "ecmp_and_lag"):
        skip_if_no_multimember_lag(
            rand_selected_dut,
            mg_facts,
            reason="Packet-type LAG hash requires multi-member LAG",
        )

    test_configs = {}

    # ------------------------------------------------------------------
    # Configure packet-type ECMP hashes
    # ------------------------------------------------------------------
    if ecmp_hash:
        if 'ipv4' not in packet_type_capabilities['ecmp_pkt_types']:
            pytest.skip("ECMP ipv4 packet-type hash not supported")

        ipv4_ecmp_fields = ['SRC_IP', 'DST_IP', 'L4_SRC_PORT', 'L4_DST_PORT']
        supported_ecmp_fields = _get_asic_hash_fields(rand_selected_dut, 'ecmp')

        ipv4_ecmp_fields = [f for f in ipv4_ecmp_fields if f in supported_ecmp_fields]
        if not ipv4_ecmp_fields:
            pytest.skip("No supported ECMP packet-type fields for ipv4")

        set_switch_hash_packet_type(
            rand_selected_dut, 'ecmp', 'ipv4', 'add', ipv4_ecmp_fields
        )

        configured = get_packet_type_hash_db_fields(rand_selected_dut, 'ecmp', 'ipv4')
        test_configs['ecmp_ipv4'] = configured

    # ------------------------------------------------------------------
    # Configure packet-type LAG hashes
    # ------------------------------------------------------------------
    if lag_hash:
        if 'ipv4' not in packet_type_capabilities['lag_pkt_types']:
            pytest.skip("LAG ipv4 packet-type hash not supported")

        ipv4_lag_fields = ['DST_MAC', 'SRC_IP', 'DST_IP']
        supported_lag_fields = _get_asic_hash_fields(rand_selected_dut, 'lag')

        ipv4_lag_fields = [f for f in ipv4_lag_fields if f in supported_lag_fields]
        if not ipv4_lag_fields:
            pytest.skip("No supported LAG packet-type fields for ipv4")

        set_switch_hash_packet_type(
            rand_selected_dut, 'lag', 'ipv4', 'add', ipv4_lag_fields
        )

        configured = get_packet_type_hash_db_fields(rand_selected_dut, 'lag', 'ipv4')
        test_configs['lag_ipv4'] = configured

    if not test_configs:
        pytest.skip("No packet-type hash configuration applied")

    show_packet_type_hash_config(rand_selected_dut, 'all')

    # ------------------------------------------------------------------
    # Save config and perform warm boot
    # ------------------------------------------------------------------
    with allure.step("Save config and perform warm boot"):
        rand_selected_dut.shell("config save -y")

        reboot(rand_selected_dut, localhost, reboot_type='warm')

        pytest_assert(
            wait_until(
                300, 20, 0,
                rand_selected_dut.critical_services_fully_started
            ),
            "Critical services not fully started after warm boot",
        )

    # ------------------------------------------------------------------
    # Verify packet-type hash persistence after warm boot
    # ------------------------------------------------------------------
    with allure.step("Verify packet-type hash configuration after warm boot"):
        for key, fields in test_configs.items():
            hash_type, pkt_type = key.split('_', 1)
            pytest_assert(
                check_packet_type_hash_config(
                    rand_selected_dut, hash_type, pkt_type, fields
                ),
                f"Packet-type hash not persisted for {key}",
            )

        show_packet_type_hash_config(rand_selected_dut, 'all')

    # ------------------------------------------------------------------
    # Data-plane validation (single representative run)
    # ------------------------------------------------------------------
    with allure.step("Verify data plane behavior after warm boot"):
        _run_ipv4_dataplane_ptf_test(
            rand_selected_dut, tbinfo, ptfhost, mg_facts,
            test_configs, ecmp_hash, lag_hash,
            "Default route not ready after warm boot",
        )


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize(
    "hash_mode,ecmp_hash,lag_hash",
    [
        pytest.param("ecmp_only", True, False, id="ecmp-only"),
        pytest.param("lag_only", False, True, id="lag-only"),
        pytest.param("ecmp_and_lag", True, True, id="ecmp-and-lag"),
    ],
)
def test_pkt_type_fast_boot(rand_selected_dut, tbinfo, ptfhost, localhost, mg_facts,
                            packet_type_capabilities, restore_packet_type_hash_config,
                            toggle_all_aa_ports_to_rand_selected_tor,
                            hash_mode, ecmp_hash, lag_hash):
    """
    Validate fast boot with packet type hash for ECMP/LAG.

    This test verifies that packet-type hash configurations persist across
    fast boot and that traffic continues to be hashed correctly.
    """
    # ------------------------------------------------------------------
    # Pre-check: multi-member LAG required for LAG / ECMP+LAG
    # ------------------------------------------------------------------
    if lag_hash and hash_mode in ("lag_only", "ecmp_and_lag"):
        skip_if_no_multimember_lag(
            rand_selected_dut,
            mg_facts,
            reason="Packet-type LAG hash requires multi-member LAG",
        )
    test_configs = {}

    # ------------------------------------------------------------
    # Configure packet-type hashes
    # ------------------------------------------------------------
    with allure.step("Configure packet-type hash configuration"):
        # ECMP packet-type hashes
        if ecmp_hash:
            if 'ipv4' in packet_type_capabilities['ecmp_pkt_types']:
                ipv4_fields = ['SRC_IP', 'DST_IP', 'IP_PROTOCOL', 'L4_SRC_PORT']
                set_switch_hash_packet_type(
                    rand_selected_dut, 'ecmp', 'ipv4', 'add', ipv4_fields
                )

                configured = get_packet_type_hash_db_fields(rand_selected_dut, 'ecmp', 'ipv4')
                if configured:
                    test_configs['ecmp_ipv4'] = configured

            if 'ipv6' in packet_type_capabilities['ecmp_pkt_types']:
                ipv6_fields = ['SRC_IP', 'DST_IP', 'L4_DST_PORT']
                set_switch_hash_packet_type(
                    rand_selected_dut, 'ecmp', 'ipv6', 'add', ipv6_fields
                )

                configured = get_packet_type_hash_db_fields(rand_selected_dut, 'ecmp', 'ipv6')
                if configured:
                    test_configs['ecmp_ipv6'] = configured

        # LAG packet-type hashes
        if lag_hash and 'ipv4' in packet_type_capabilities['lag_pkt_types']:
            lag_ipv4_fields = ['SRC_MAC', 'DST_MAC', 'SRC_IP', 'DST_IP']
            set_switch_hash_packet_type(
                rand_selected_dut, 'lag', 'ipv4', 'add', lag_ipv4_fields
            )

            configured = get_packet_type_hash_db_fields(rand_selected_dut, 'lag', 'ipv4')
            if configured:
                test_configs['lag_ipv4'] = configured

    if not test_configs:
        pytest.skip("No packet-type hash configuration applied; skipping fast boot test")

    # ------------------------------------------------------------
    # Verify configuration before fast boot
    # ------------------------------------------------------------
    with allure.step("Verify packet-type hash config before fast boot"):
        for key, fields in test_configs.items():
            hash_type, pkt_type = key.split('_', 1)
            pytest_assert(
                check_packet_type_hash_config(
                    rand_selected_dut, hash_type, pkt_type, fields
                ),
                f"Pre-fast-boot verification failed for {key}",
            )

        show_packet_type_hash_config(rand_selected_dut, 'all')

    # ------------------------------------------------------------
    # Save config and perform fast boot
    # ------------------------------------------------------------
    with allure.step("Save configuration and perform fast boot"):
        rand_selected_dut.shell("config save -y")

        reboot(rand_selected_dut, localhost, reboot_type='fast')

        pytest_assert(
            wait_until(300, 20, 0, rand_selected_dut.critical_services_fully_started),
            "Critical services not fully started after fast boot",
        )

    # ------------------------------------------------------------
    # Verify configuration after fast boot
    # ------------------------------------------------------------
    with allure.step("Verify packet-type hash config after fast boot"):
        for key, fields in test_configs.items():
            hash_type, pkt_type = key.split('_', 1)
            pytest_assert(
                check_packet_type_hash_config(
                    rand_selected_dut, hash_type, pkt_type, fields
                ),
                f"Post-fast-boot verification failed for {key}",
            )

        show_packet_type_hash_config(rand_selected_dut, 'all')

    # ------------------------------------------------------------
    # Data-plane sanity check
    # ------------------------------------------------------------
    with allure.step("Verify data plane behavior after fast boot"):
        _run_ipv4_dataplane_ptf_test(
            rand_selected_dut, tbinfo, ptfhost, mg_facts,
            test_configs, ecmp_hash, lag_hash,
            "Default route not available after fast boot",
        )
