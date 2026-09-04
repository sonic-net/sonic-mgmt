import itertools
import logging
import os
import sys
import time

import pytest
from _pytest.outcomes import OutcomeException
from tests.common.utilities import wait_until
from tests.high_frequency_telemetry.counter_profiles import (
    CounterObjectType,
    get_support_counter_list,
)
from tests.high_frequency_telemetry.utilities import (
    InfluxDbSink,
    cleanup_hft_config,
    enable_otel_collector,
    ensure_countersyncd_daemon,
    get_available_ports,
    get_configured_buffer_pools,
    get_configured_buffer_queue_objects,
    get_configured_queue_objects,
    install_otel_collector_config,
    is_otel_image_available,
    render_otel_collector_config,
    restart_otel_service,
    setup_influxdb,
    start_influxdb,
    stop_influxdb,
    stop_otel_collector,
)

logger = logging.getLogger(__name__)

OTEL_CONFIG_PATH = "/etc/sonic/otel_config.yml"
INFLUXDB_PORT = 8181
INFLUXDB_BUCKET_PREFIX = "hft_test"
INFLUXDB_BUCKET_IDS = itertools.count(1)
TEST_HFT_PROFILES = (
    "queue_profile",
    "ingress_pg_profile",
    "buffer_pool_profile",
    "full_port_counter_profile",
    "state_transition_profile",
    "config_deletion_profile",
    "port_shutdown_profile",
    "e2e_port_profile",
    "poll_interval_profile_1000",
)
STOPPED_COLLECTOR_STATES = {"STOPPED", "EXITED", "FATAL"}


def _collector_running_from_status(status):
    lines = [
        line.strip() for line in status.get("stdout", "").splitlines()
        if line.strip()
    ]
    fields = lines[0].split() if len(lines) == 1 else []
    state = fields[1] if len(fields) >= 2 and fields[0] == "otel" else None
    rc = status.get("rc")
    if rc == 0 and state == "RUNNING":
        return True
    if rc == 3 and state in STOPPED_COLLECTOR_STATES:
        return False
    pytest.fail(
        "Unable to determine original OTEL collector state: "
        f"rc={rc!r}, stdout={status.get('stdout', '')!r}, "
        f"stderr={status.get('stderr', '')!r}"
    )


def _run_cleanup_steps(steps):
    """Attempt every cleanup step and return the first failure."""
    first_error = None
    for step_name, callback in steps:
        try:
            callback()
        except (Exception, OutcomeException) as error:
            logger.exception("HFT cleanup step '%s' failed", step_name)
            if first_error is None:
                first_error = error
    return first_error


def _get_otel_container_running(duthost):
    result = duthost.shell(
        r"docker inspect -f \{\{.State.Running\}\} otel",
        module_ignore_errors=True,
    )
    output = result.get("stdout", "").strip().lower()
    if result.get("rc") == 0 and output in {"true", "false"}:
        return output == "true"
    error = " ".join([
        result.get("stdout", ""),
        result.get("stderr", ""),
        result.get("msg", ""),
    ]).lower()
    if result.get("rc") != 0 and (
            "no such object" in error or "no such container" in error):
        return False
    pytest.fail(f"Unable to determine OTEL container state: {result}")


def _is_otel_container_stopped(duthost):
    return not _get_otel_container_running(duthost)


@pytest.fixture(scope="module")
def skip_unsupported_hft_platform(
        duthosts, enum_rand_one_per_hwsku_hostname):
    """Validate shared HFT prerequisites without changing the DUT."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    config_exists = duthost.shell(
        f"sudo test -f {OTEL_CONFIG_PATH}", module_ignore_errors=True
    )
    if config_exists.get("rc") not in {0, 1}:
        pytest.fail(f"Failed to inspect {OTEL_CONFIG_PATH}: {config_exists}")
    config_existed = config_exists.get("rc") == 0
    original_config = ""
    if config_existed:
        original_config = duthost.shell(
            f"sudo cat {OTEL_CONFIG_PATH}", module_ignore_errors=False
        ).get("stdout", "")

    feature_result = duthost.shell(
        "redis-cli -n 4 --raw HGETALL 'FEATURE|otel'",
        module_ignore_errors=False,
    )
    feature_lines = feature_result.get("stdout_lines", [])
    if len(feature_lines) % 2:
        pytest.fail(f"Invalid FEATURE|otel response: {feature_result}")
    original_feature = dict(zip(feature_lines[0::2], feature_lines[1::2]))
    original_state = original_feature.get("state", "disabled")
    enabled_states = {"enabled", "always_enabled"}
    valid_states = enabled_states | {"disabled", "always_disabled"}
    if original_state not in valid_states:
        pytest.fail(f"Unexpected OTEL feature state: {original_state}")
    if original_state == "always_disabled":
        pytest.skip("OTEL feature is always disabled")

    original_container_running = _get_otel_container_running(duthost)
    if original_state in enabled_states and not original_container_running:
        pytest.fail("OTEL is enabled but its container is not running")
    if original_state not in enabled_states \
            and not is_otel_image_available(duthost):
        pytest.skip("docker-sonic-otel is not available on this platform")
    original_collector_running = False
    if original_container_running:
        collector_status = duthost.shell(
            "docker exec otel supervisorctl status otel",
            module_ignore_errors=True,
        )
        original_collector_running = _collector_running_from_status(
            collector_status
        )
    ensure_countersyncd_daemon(duthost)
    return {
        "config_existed": config_existed,
        "original_config": original_config,
        "original_feature": original_feature,
        "original_state": original_state,
        "original_collector_running": original_collector_running,
    }


@pytest.fixture(scope="function")
def skip_unsupported_hft_test(request, duthosts,
                              enum_rand_one_per_hwsku_hostname, tbinfo):
    """Skip unsupported cases before starting InfluxDB or changing OTEL."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    marker = request.node.get_closest_marker("hft_requirements")
    if marker is None:
        pytest.fail("Tests using hft_influxdb must declare hft_requirements")
    if len(marker.args) != 1 or not isinstance(marker.args[0], CounterObjectType):
        pytest.fail("hft_requirements requires one CounterObjectType argument")
    unknown_options = set(marker.kwargs) - {"counter", "oper_up_port"}
    if unknown_options:
        pytest.fail(
            "Unsupported hft_requirements options: "
            f"{sorted(unknown_options)}"
        )
    counter_type = marker.args[0]
    required_counter = marker.kwargs.get("counter")
    if "counter" in marker.kwargs and (
            not isinstance(required_counter, str) or not required_counter):
        pytest.fail("hft_requirements counter must be a non-empty string")
    require_oper_up_port = marker.kwargs.get("oper_up_port", False)
    if not isinstance(require_oper_up_port, bool):
        pytest.fail("hft_requirements oper_up_port must be a bool")
    if "oper_up_port" in marker.kwargs \
            and counter_type != CounterObjectType.PORT:
        pytest.fail("oper_up_port is valid only for PORT requirements")

    counters = get_support_counter_list(duthost, counter_type)
    if required_counter and required_counter not in counters:
        pytest.skip(
            f"{required_counter} is not supported on this platform"
        )
    if counter_type == CounterObjectType.INGRESS_PRIORITY_GROUP:
        objects = get_configured_buffer_queue_objects(duthost)
        if not objects:
            pytest.skip("No ingress priority groups found in COUNTERS_DB")
    elif counter_type == CounterObjectType.BUFFER_POOL:
        if not counters:
            pytest.skip("No buffer pool counters supported on this platform")
        objects = get_configured_buffer_pools(duthost)
        if not objects:
            pytest.skip("No buffer pools found in COUNTERS_DB")
    elif counter_type == CounterObjectType.QUEUE:
        objects = get_configured_queue_objects(duthost)
        if not objects:
            pytest.skip("No queue objects found in COUNTERS_DB")
    else:
        objects = get_available_ports(
            duthost, tbinfo, desired_ports=None, min_ports=1
        )
        if require_oper_up_port:
            down_ports = set(
                duthost.interface_facts(up_ports=objects)["ansible_facts"]
                ["ansible_interface_link_down_ports"]
            )
            objects = [port for port in objects if port not in down_ports]
            if not objects:
                pytest.skip("No operationally up, PTF-mapped port is available")

    if not counters:
        pytest.skip(
            f"No {counter_type.value.replace('_', ' ')} counters supported "
            "on this platform"
        )
    request.getfixturevalue("skip_unsupported_hft_platform")
    return {
        "counter_type": counter_type,
        "counters": counters,
        "objects": objects,
    }


@pytest.fixture(scope="module")
def hft_otel_collector(duthosts, enum_rand_one_per_hwsku_hostname,
                       skip_unsupported_hft_platform):
    """Prepare OTEL for the module and restore its original state afterward."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    config_existed = skip_unsupported_hft_platform["config_existed"]
    original_config = skip_unsupported_hft_platform["original_config"]
    original_feature = skip_unsupported_hft_platform["original_feature"]
    feature_existed = bool(original_feature)
    original_state = skip_unsupported_hft_platform["original_state"]
    enabled_states = {"enabled", "always_enabled"}
    original_collector_running = skip_unsupported_hft_platform[
        "original_collector_running"
    ]

    def restore_config():
        if config_existed:
            duthost.copy(content=original_config, dest=OTEL_CONFIG_PATH)
        else:
            duthost.shell(
                f"sudo rm -f {OTEL_CONFIG_PATH}", module_ignore_errors=False
            )

    def restore_feature_runtime_state():
        if original_state == "disabled":
            duthost.shell(
                "sudo config feature state otel disabled",
                module_ignore_errors=False,
            )
            if not wait_until(
                60, 2, 0, _is_otel_container_stopped, duthost
            ):
                pytest.fail("OTEL container did not stop during restoration")
        elif original_state == "enabled" \
                and not _get_otel_container_running(duthost):
            duthost.shell(
                "sudo config feature state otel enabled",
                module_ignore_errors=False,
            )
            if not wait_until(
                60, 2, 0, _get_otel_container_running, duthost
            ):
                pytest.fail("OTEL container did not start during restoration")

    def remove_extra_feature_fields():
        current_lines = duthost.shell(
            "redis-cli -n 4 --raw HKEYS 'FEATURE|otel'",
            module_ignore_errors=False,
        ).get("stdout_lines", [])
        extra_fields = set(current_lines) - set(original_feature)
        if extra_fields:
            fields = " ".join(f"'{field}'" for field in extra_fields)
            duthost.shell(
                f"redis-cli -n 4 HDEL 'FEATURE|otel' {fields}",
                module_ignore_errors=False,
            )

    def restore_feature_fields():
        field_values = " ".join(
            f"'{field}' '{value}'"
            for field, value in original_feature.items()
        )
        duthost.shell(
            f"redis-cli -n 4 HSET 'FEATURE|otel' {field_values}",
            module_ignore_errors=False,
        )

    def restore_collector_state():
        if original_collector_running:
            restart_otel_service(duthost)
        elif _get_otel_container_running(duthost):
            stop_otel_collector(duthost)

    def remove_created_feature():
        duthost.shell(
            "sudo config feature state otel disabled",
            module_ignore_errors=False,
        )
        if not wait_until(60, 2, 0, _is_otel_container_stopped, duthost):
            pytest.fail("OTEL container did not stop during restoration")
        duthost.shell(
            "sonic-db-cli CONFIG_DB del 'FEATURE|otel'",
            module_ignore_errors=False,
        )

    try:
        if original_state not in enabled_states:
            enable_otel_collector(duthost, check_image=False)
        ensure_countersyncd_daemon(duthost)
        yield
    finally:
        # Setup failures are active here; pytest reports call-phase failures
        # separately from any teardown error raised below.
        original_error = sys.exc_info()[1]
        cleanup_steps = [("restore OTEL config", restore_config)]
        if feature_existed:
            cleanup_steps.extend([
                ("restore OTEL feature runtime state",
                 restore_feature_runtime_state),
                ("remove added FEATURE|otel fields",
                 remove_extra_feature_fields),
                ("restore original FEATURE|otel fields",
                 restore_feature_fields),
                ("restore OTEL collector process state",
                 restore_collector_state),
            ])
        else:
            cleanup_steps.append(
                ("stop and remove created OTEL feature", remove_created_feature)
            )
        cleanup_error = _run_cleanup_steps(cleanup_steps)
        if cleanup_error is not None and original_error is None:
            raise cleanup_error


@pytest.fixture(scope="module")
def hft_influxdb_server(ptfhost):
    """Provide one test-owned in-memory InfluxDB process for the module."""
    pid = start_influxdb(ptfhost, port=INFLUXDB_PORT)
    try:
        yield
    finally:
        stop_influxdb(ptfhost, pid)


@pytest.fixture(scope="function")
def hft_influxdb(request, ptfhost, skip_unsupported_hft_test,
                 duthosts, enum_rand_one_per_hwsku_hostname, tbinfo):
    """Provide a unique InfluxDB database for every HFT case."""
    request.getfixturevalue("cleanup_high_frequency_telemetry")
    request.getfixturevalue("hft_influxdb_server")
    request.getfixturevalue("hft_otel_collector")
    bucket = f"{INFLUXDB_BUCKET_PREFIX}_{next(INFLUXDB_BUCKET_IDS)}"
    sink = InfluxDbSink(ptfhost, bucket=bucket, port=INFLUXDB_PORT)
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    database_created = False
    try:
        ensure_countersyncd_daemon(duthost)
        stop_otel_collector(duthost)
        setup_influxdb(ptfhost, port=INFLUXDB_PORT, bucket=bucket)
        database_created = True
        if not sink.is_empty():
            pytest.fail(f"InfluxDB database {bucket} is not empty")
        template_path = os.path.join(
            os.path.dirname(__file__), "otel_collector_influxdb.yaml.j2"
        )
        rendered_config = render_otel_collector_config(
            template_path,
            ptf_ip=str(tbinfo["ptf_ip"]).split("/", 1)[0],
            influxdb_port=INFLUXDB_PORT,
            influxdb_bucket=bucket,
        )
        install_otel_collector_config(duthost, rendered_config)
        restart_otel_service(duthost)
        yield sink
    finally:
        # Setup failures are active here; pytest reports call-phase failures
        # separately from any teardown error raised below.
        original_error = sys.exc_info()[1]
        cleanup_steps = [
            ("stop OTEL collector", lambda: stop_otel_collector(duthost)),
        ]
        if database_created:
            cleanup_steps.append(
                (f"drop InfluxDB database {bucket}", sink.drop)
            )
        cleanup_steps.append(
            ("verify countersyncd daemon",
             lambda: ensure_countersyncd_daemon(duthost))
        )
        cleanup_error = _run_cleanup_steps(cleanup_steps)
        if cleanup_error is not None and original_error is None:
            raise cleanup_error


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

    if not duthost.is_service_fully_started("swss"):
        pytest.fail("swss container is not running")

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

            # Step 2: Calculate uptime on DUT to avoid clock differences
            result = duthost.shell(
                f'started=$(date -ud "{started_at}" +%s) && '
                'echo $(($(date -u +%s) - started))',
                module_ignore_errors=True
            )
            if result['rc'] != 0 or not result['stdout'].strip():
                return 0

            uptime = int(result['stdout'].strip())
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
        pytest.fail("Failed to determine swss container uptime")
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
