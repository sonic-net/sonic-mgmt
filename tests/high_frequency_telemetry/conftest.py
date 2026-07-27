import pytest
import logging
import os
import time
from datetime import datetime, timezone
from tests.high_frequency_telemetry.utilities import (
    InfluxDbSink,
    cleanup_hft_config,
    enable_otel_collector,
    ensure_countersyncd_daemon,
    install_otel_collector_config,
    render_otel_collector_config,
    restart_otel_collector,
    setup_influxdb,
    start_influxdb,
    stop_influxdb,
    stop_otel_collector,
)

logger = logging.getLogger(__name__)

OTEL_CONFIG_PATH = "/etc/sonic/otel_config.yml"
INFLUXDB_PORT = 8181
INFLUXDB_BUCKET = "hft_test"
TEST_HFT_PROFILES = (
    "port_profile",
    "queue_profile",
    "ingress_pg_profile",
    "buffer_pool_profile",
    "full_hft_profile",
    "full_port_counter_profile",
    "state_transition_profile",
    "config_deletion_profile",
    "port_shutdown_profile",
    "e2e_port_profile",
    "poll_interval_profile_1000",
    "poll_interval_profile_10000",
    "poll_interval_profile_100000",
    "poll_interval_profile_1000000",
    "poll_interval_profile_10000000",
)


@pytest.fixture(scope="function")
def hft_otel_collector(duthosts, enum_rand_one_per_hwsku_hostname, tbinfo):
    """Point OTEL at the test InfluxDB endpoint and restore its original state."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    config_result = duthost.shell(
        f"cat {OTEL_CONFIG_PATH}", module_ignore_errors=True
    )
    config_existed = config_result.get("rc") == 0
    original_config = config_result.get("stdout", "")
    feature_lines = duthost.shell(
        "redis-cli -n 4 --raw HGETALL 'FEATURE|otel'",
        module_ignore_errors=True,
    ).get("stdout_lines", [])
    original_feature = dict(zip(feature_lines[0::2], feature_lines[1::2]))
    feature_existed = bool(original_feature)
    original_state = original_feature.get("state", "disabled")

    try:
        if original_state != "enabled" or not duthost.is_container_running("otel"):
            enable_otel_collector(duthost)
        template_path = os.path.join(
            os.path.dirname(__file__), "otel_collector_influxdb.yaml.j2"
        )
        rendered_config = render_otel_collector_config(
            template_path,
            ptf_ip=str(tbinfo["ptf_ip"]).split("/", 1)[0],
            influxdb_port=INFLUXDB_PORT,
            influxdb_bucket=INFLUXDB_BUCKET,
        )
        install_otel_collector_config(duthost, rendered_config)
        ensure_countersyncd_daemon(duthost)
        yield
    finally:
        if config_existed:
            duthost.copy(content=original_config, dest=OTEL_CONFIG_PATH)
        else:
            duthost.shell(
                f"rm -f {OTEL_CONFIG_PATH}", module_ignore_errors=True
            )

        if feature_existed and original_state != "enabled":
            duthost.shell(
                f"sudo config feature state otel {original_state}",
                module_ignore_errors=True,
            )
        elif not feature_existed:
            duthost.shell(
                "sudo config feature state otel disabled",
                module_ignore_errors=True,
            )

        if feature_existed:
            current_lines = duthost.shell(
                "redis-cli -n 4 --raw HKEYS 'FEATURE|otel'",
                module_ignore_errors=True,
            ).get("stdout_lines", [])
            extra_fields = set(current_lines) - set(original_feature)
            if extra_fields:
                fields = " ".join(f"'{field}'" for field in extra_fields)
                duthost.shell(
                    f"redis-cli -n 4 HDEL 'FEATURE|otel' {fields}",
                    module_ignore_errors=False,
                )
            field_values = " ".join(
                f"'{field}' '{value}'"
                for field, value in original_feature.items()
            )
            duthost.shell(
                f"redis-cli -n 4 HSET 'FEATURE|otel' {field_values}",
                module_ignore_errors=False,
            )
            if original_state == "enabled":
                restart_otel_collector(duthost)
        else:
            duthost.shell(
                "sonic-db-cli CONFIG_DB del 'FEATURE|otel'",
                module_ignore_errors=True,
            )


@pytest.fixture(scope="function")
def hft_influxdb(ptfhost, disable_flex_counters, hft_otel_collector,
                 duthosts, enum_rand_one_per_hwsku_hostname):
    """Provide a fresh in-memory InfluxDB instance for every test invocation."""
    sink = InfluxDbSink(ptfhost, bucket=INFLUXDB_BUCKET, port=INFLUXDB_PORT)
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    pid = None
    try:
        ensure_countersyncd_daemon(duthost)
        stop_otel_collector(duthost)
        pid = start_influxdb(ptfhost, port=INFLUXDB_PORT)
        setup_influxdb(
            ptfhost, port=INFLUXDB_PORT, bucket=INFLUXDB_BUCKET
        )
        sink.clear()
        restart_otel_collector(duthost)
        # countersyncd can retain metrics while the collector is unavailable.
        # Drain those reconnect writes before establishing the test boundary.
        time.sleep(5)
        sink.clear()

        yield sink
    finally:
        # HFT test bodies remove their profile before fixture teardown. Stop the
        # collector so no delayed batch can repopulate the database while it is
        # being cleared.
        if pid is not None:
            try:
                stop_otel_collector(duthost)
                sink.clear()
            finally:
                stop_influxdb(ptfhost, pid)
        ensure_countersyncd_daemon(duthost)


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthosts, enum_rand_one_per_hwsku_hostname, loganalyzer):
    """
    Ignore expected SAI_TAM errors during HFT test execution.

    When HFT is enabled, SONiC initially sends a buffer size of 65535 for IPFIX templates,
    but SAI requires a larger buffer (e.g., 119352). SAI returns SAI_STATUS_BUFFER_OVERFLOW
    with the required size, and SONiC retries with the correct size. This is normal behavior,
    not a functional issue. The error logs can be safely ignored.

    Args:
        duthosts: list of DUTs.
        enum_rand_one_per_hwsku_hostname: Hostname of a random chosen dut
        loganalyzer: Loganalyzer utility fixture
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if loganalyzer:
        ignoreRegex = [
            # SAI prints ERR when IPFIX template buffer is too small on first probe;
            # SONiC retries with the correct size and succeeds - not a functional issue
            ".*ERR syncd#SDK.*SAI_TAM.*mlnx_generate_ipfix_templates.*Buffer size is too small"
            " to hold IPFIX template.*",
            ".*ERR syncd#SDK.*SAI_TAM.*mlnx_tam_tel_type_get_ipfix_templates.*Failed to generate"
            " IPFIX templates.*",
            ".*ERR syncd#SDK.*SAI_TAM.*mlnx_tam_tel_type_attrib_get.*Failed to get attribute.*",
            ".*ERR syncd#SDK.*SAI_UTILS.*get_dispatch_attribs_handler.*Failed Get.*IPFIX_TEMPLATES.*",
        ]
        loganalyzer[duthost.hostname].ignore_regex.extend(ignoreRegex)


@pytest.fixture(scope="function")
def ensure_swss_ready(duthosts, enum_rand_one_per_hwsku_hostname):
    """Ensure swss container is running and stable for at least 10 seconds.

    Function-level fixture that runs before each test to ensure swss is ready,
    as tests may affect the container state.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    def get_swss_uptime_seconds():
        """Get swss container uptime in seconds via docker inspect."""
        try:
            # Step 1: Get container start time from docker inspect JSON
            result = duthost.shell(
                "docker inspect swss | grep StartedAt | head -1 | cut -d'\"' -f4",
                module_ignore_errors=True
            )
            if result['rc'] != 0 or not result['stdout'].strip():
                return 0
            started_at = result['stdout'].strip()

            # Step 2: Convert start time to epoch seconds on DUT
            result = duthost.shell(
                f'date -ud "{started_at}" +%s',
                module_ignore_errors=True
            )
            if result['rc'] != 0 or not result['stdout'].strip():
                return 0

            # Step 3: Calculate uptime = current UTC epoch - start epoch
            started_epoch = int(result['stdout'].strip())
            now_epoch = int(datetime.now(timezone.utc).timestamp())
            uptime = now_epoch - started_epoch
            logger.debug(f"swss container uptime: {uptime}s")
            return uptime
        except Exception as e:
            logger.warning(f"Failed to get swss uptime: {e}")
            return 0

    logger.info("Checking swss container status...")

    # Check swss container uptime
    uptime = get_swss_uptime_seconds()
    min_uptime = 10  # Require at least 10 seconds uptime

    if uptime == 0:
        logger.warning("swss container is not running, attempting to start...")

        # Try to restart swss service
        duthost.shell('sudo systemctl restart swss',
                      module_ignore_errors=True)

        # Wait for container to start and stabilize
        max_wait = 40  # Total wait time
        logger.info(f"Waiting up to {max_wait} seconds for swss container "
                    f"to start and stabilize...")

        for i in range(max_wait):
            time.sleep(1)
            current_uptime = get_swss_uptime_seconds()
            if current_uptime >= min_uptime:
                logger.info(f"swss container is stable "
                            f"(uptime: {current_uptime}s)")
                break
        else:
            raise RuntimeError(f"swss container failed to stabilize "
                               f"after {max_wait} seconds")

    elif uptime < min_uptime:
        wait_time = min_uptime - uptime + 1  # +1 for safety margin
        logger.info(f"swss container uptime is {uptime}s, "
                    f"waiting {wait_time}s for stability...")
        time.sleep(wait_time)
    else:
        logger.info(f"swss container is already stable "
                    f"(uptime: {uptime}s)")

    # Final verification
    final_uptime = get_swss_uptime_seconds()
    if final_uptime < min_uptime:
        raise RuntimeError(
            f"swss container uptime ({final_uptime}s) is still less "
            f"than required {min_uptime}s"
        )

    logger.info(
            f"swss container is ready and stable "
            f"(uptime: {final_uptime}s)"
        )


@pytest.fixture(scope="function")
def cleanup_high_frequency_telemetry(
    duthosts, enum_rand_one_per_hwsku_hostname, ensure_swss_ready
):
    """Remove stale profiles owned by this test suite before each test."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    profile_keys = duthost.shell(
        'redis-cli -n 4 KEYS "HIGH_FREQUENCY_TELEMETRY_PROFILE|*"',
        module_ignore_errors=False,
    )["stdout_lines"]
    group_keys = duthost.shell(
        'redis-cli -n 4 KEYS "HIGH_FREQUENCY_TELEMETRY_GROUP|*"',
        module_ignore_errors=False,
    )["stdout_lines"]
    existing_profiles = {
        key.split("|", 1)[1] for key in profile_keys
        if "|" in key
    }
    existing_profiles.update(
        key.split("|", 2)[1] for key in group_keys
        if key.count("|") >= 2
    )
    for profile_name in set(TEST_HFT_PROFILES) & existing_profiles:
        cleanup_hft_config(duthost, profile_name)


@pytest.fixture(scope="function")
def disable_flex_counters(
    duthosts, enum_rand_one_per_hwsku_hostname,
    cleanup_high_frequency_telemetry
):
    """
    Function-level fixture to disable all flex counters and restore
    them after each test.
    Depends on cleanup_high_frequency_telemetry to ensure clean state.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Get all flex counter tables
    flex_counter_keys = duthost.shell(
        'redis-cli -n 4 keys "FLEX_COUNTER_TABLE|*"',
        module_ignore_errors=False
    )['stdout_lines']

    original_states = {}

    def restore_states():
        for table_name, status in original_states.items():
            if status:
                command = (
                    f'redis-cli -n 4 HSET "{table_name}" '
                    f'"FLEX_COUNTER_STATUS" "{status}"'
                )
            else:
                command = (
                    f'redis-cli -n 4 HDEL "{table_name}" '
                    '"FLEX_COUNTER_STATUS"'
                )
            duthost.shell(command, module_ignore_errors=False)

    try:
        for key in flex_counter_keys:
            if not key.strip():
                continue
            table_name = key.strip()
            status = duthost.shell(
                f'redis-cli -n 4 HGET "{table_name}" "FLEX_COUNTER_STATUS"',
                module_ignore_errors=False
            )["stdout"].strip()
            original_states[table_name] = status
            duthost.shell(
                f'redis-cli -n 4 HSET "{table_name}" '
                '"FLEX_COUNTER_STATUS" "disable"',
                module_ignore_errors=False
            )
        logger.info("Disabled %d flex counters", len(original_states))
    except Exception:
        restore_states()
        raise

    try:
        yield
    finally:
        restore_states()
        logger.info("Restored all flex counters to original states")
