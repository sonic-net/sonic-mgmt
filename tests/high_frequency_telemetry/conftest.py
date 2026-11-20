import base64
import itertools
import logging
import os
import shlex
import sys
import time
from contextlib import contextmanager
from functools import partial

import pytest
from _pytest.outcomes import OutcomeException
from tests.common.helpers.dut_utils import check_container_state, is_container_running, wait_for_container_running
from tests.common.utilities import wait_until
from tests.high_frequency_telemetry.counter_profiles import (
    CounterObjectType,
    get_support_counter_list,
)
from tests.high_frequency_telemetry.utilities import (
    InfluxDbSink,
    cleanup_hft_config,
    enable_otel_collector,
    get_available_ports,
    get_configured_buffer_pools,
    get_configured_buffer_queue_objects,
    get_configured_queue_objects,
    get_running_countersyncd_pid,
    is_otel_image_available,
    render_otel_collector_config,
    restart_countersyncd_daemon,
    restart_otel_service,
    setup_influxdb,
    start_influxdb,
    stop_influxdb,
    stop_otel_collector,
)

logger = logging.getLogger(__name__)

OTEL_CONFIG_PATH = "/etc/sonic/otel_config.yml"
HFT_WORK_PARENT = "/run/lock/sonic-mgmt-hft"
HFT_OTEL_ARGS = ("--enable-otel", "--otel-endpoint=http://localhost:4317")
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
    raise AssertionError(
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


def _read_feature(duthost, name):
    lines = duthost.command(argv=["redis-cli", "-n", "4", "--raw", "HGETALL", f"FEATURE|{name}"])["stdout_lines"]
    if len(lines) % 2:
        pytest.fail(f"Invalid FEATURE|{name} response: expected field/value pairs")
    return dict(zip(lines[::2], lines[1::2]))


def _read_test_config(duthost, path):
    """Return the file contents and mode before the tests overwrite it."""
    info = duthost.stat(path=path, follow=False, get_checksum=False, get_mime=False)["stat"]
    if not info["exists"]:
        return None, None
    # Ansible copy replaces the destination inode. Do not break a managed link
    # or apply a symlink's mode to the regular file that would replace it.
    if not info["isreg"] or info["nlink"] != 1:
        pytest.fail(f"Refusing to overwrite {path}: expected a regular file with one link")
    contents = duthost.slurp(src=path, verbose=False)["content"]
    return base64.b64decode(contents).decode("utf-8"), info["mode"]


@contextmanager
def _countersyncd_otel_export(duthost, original_hft_state):
    """Pass OTEL options as Docker CMD; restore the original container on exit."""
    work = duthost.tempfile(state="directory", path=HFT_WORK_PARENT, prefix="sonic-mgmt-hft-")["path"]
    helper = os.path.join(work, "hft_container.py")
    try:
        duthost.copy(src=os.path.join(os.path.dirname(__file__), "files", "hft_container.py"), dest=helper)
    except Exception:
        duthost.file(path=work, state="absent")
        raise
    try:
        duthost.command(argv=["python3", helper, "install", work, original_hft_state, *HFT_OTEL_ARGS])
        if not wait_until(60, 2, 0, get_running_countersyncd_pid, duthost):
            pytest.fail("countersyncd did not start in the HFT container")
        yield
    finally:
        # Leave the helper and recovery record on the DUT if restoration fails.
        duthost.command(argv=["python3", helper, "restore", work])
        if original_hft_state != "disabled" and not wait_until(60, 2, 0, duthost.critical_processes_running, "hft"):
            pytest.fail("Original hft did not become ready after restoration")
        duthost.file(path=work, state="absent")


@pytest.fixture(scope="module")
def skip_unsupported_hft_platform(
        request, duthosts, enum_rand_one_per_hwsku_hostname):
    """Claim a supported DUT before snapshotting OTEL or setting up HFT tests."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    enabled_states = {"enabled", "always_enabled"}
    valid_states = enabled_states | {"disabled", "always_disabled"}
    hft = _read_feature(duthost, "hft")
    original_hft_state = hft.get("state")
    if not original_hft_state:
        pytest.skip("Standalone hft is not configured on this image (no FEATURE|hft state)")
    if original_hft_state not in valid_states:
        pytest.fail(f"Unexpected HFT feature state: {original_hft_state}")
    if original_hft_state == "always_disabled":
        pytest.skip("HFT feature is always disabled")
    if hft.get("set_owner", "local") not in ("", "local"):
        pytest.skip("HFT tests require a locally managed hft feature")

    # A contender must not clean another module's profiles or restore its collector.
    # An incomplete HFT restore leaves its recovery directory inside the lock.
    duthost.command(argv=["mkdir", "-m", "0700", HFT_WORK_PARENT])
    request.addfinalizer(partial(duthost.command, argv=["rmdir", "--ignore-fail-on-non-empty", HFT_WORK_PARENT]))

    original_feature = _read_feature(duthost, "otel")
    original_state = original_feature.get("state", "disabled")
    if original_state not in valid_states:
        pytest.fail(f"Unexpected OTEL feature state: {original_state}")
    if original_state == "always_disabled":
        pytest.skip("OTEL feature is always disabled")

    original_container_running = is_container_running(duthost, "otel")
    if original_container_running != (original_state in enabled_states):
        pytest.fail(f"OTEL feature state {original_state!r} disagrees with "
                    f"container running={original_container_running}")
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

    if original_hft_state in enabled_states \
            and not duthost.critical_processes_running("hft"):
        pytest.fail("HFT is enabled but countersyncd is not running")
    return {
        "otel_config": _read_test_config(duthost, OTEL_CONFIG_PATH),
        "original_feature": original_feature,
        "original_state": original_state,
        "original_collector_running": original_collector_running,
        "original_hft_state": original_hft_state,
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
    original_config, config_mode = skip_unsupported_hft_platform["otel_config"]
    original_feature = skip_unsupported_hft_platform["original_feature"]
    original_state = skip_unsupported_hft_platform["original_state"]
    original_collector_running = skip_unsupported_hft_platform[
        "original_collector_running"
    ]
    original_hft_state = skip_unsupported_hft_platform["original_hft_state"]

    def restore_config():
        if original_config is not None:
            duthost.copy(content=original_config, dest=OTEL_CONFIG_PATH, mode=config_mode, verbose=False)
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
            if not wait_until(60, 2, 0, check_container_state, duthost, "otel", False):
                pytest.fail("OTEL container did not stop during restoration")
            if not original_feature:
                duthost.command(argv=["sonic-db-cli", "CONFIG_DB", "DEL", "FEATURE|otel"])
        elif not is_container_running(duthost, "otel"):
            # The feature was enabled (possibly always_enabled). Only the service needs starting.
            duthost.command(argv=["systemctl", "start", "otel.service"])
            wait_for_container_running(duthost, "otel", timeout=60, check_interval=2)

    def remove_extra_feature_fields():
        current_lines = duthost.shell(
            "redis-cli -n 4 --raw HKEYS 'FEATURE|otel'",
            module_ignore_errors=False,
        ).get("stdout_lines", [])
        extra_fields = set(current_lines) - set(original_feature)
        if extra_fields:
            duthost.shell(shlex.join(["redis-cli", "-n", "4", "HDEL", "FEATURE|otel", *sorted(extra_fields)]))

    def restore_feature_fields():
        fields = itertools.chain.from_iterable(original_feature.items())
        duthost.shell(shlex.join(["redis-cli", "-n", "4", "HSET", "FEATURE|otel", *fields]), verbose=False)

    def restore_collector_state():
        if original_collector_running:
            restart_otel_service(duthost)
        elif is_container_running(duthost, "otel"):
            stop_otel_collector(duthost)

    try:
        if original_state == "disabled":
            enable_otel_collector(duthost, feature_exists=bool(original_feature))
        with _countersyncd_otel_export(duthost, original_hft_state):
            yield
    finally:
        # Setup failures are active here; pytest reports call-phase failures
        # separately from any teardown error raised below.
        original_error = sys.exc_info()[1]
        cleanup_steps = [
            ("restore OTEL config", restore_config),
            ("restore OTEL feature runtime state", restore_feature_runtime_state),
        ]
        if original_feature:
            cleanup_steps.extend([
                ("remove added FEATURE|otel fields",
                 remove_extra_feature_fields),
                ("restore original FEATURE|otel fields",
                 restore_feature_fields),
                ("restore OTEL collector process state",
                 restore_collector_state),
            ])
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

    def verify_countersyncd():
        if get_running_countersyncd_pid(duthost) is None:
            pytest.fail("Expected supervisor-owned countersyncd to be RUNNING in hft")

    try:
        verify_countersyncd()
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
        duthost.copy(content=rendered_config, dest=OTEL_CONFIG_PATH, verbose=False)
        restart_otel_service(duthost)
        time.sleep(2)
        if not sink.is_empty():
            pytest.fail(
                f"InfluxDB database {bucket} received stale HFT data before "
                "the test configured a session: "
                f"measurements={sorted(sink.measurements())}"
            )
        yield sink
    finally:
        # Setup failures are active here; pytest reports call-phase failures
        # separately from any teardown error raised below.
        original_error = sys.exc_info()[1]
        cleanup_steps = []
        if database_created:
            # Let samples countersyncd still exports for this case reach this
            # database before the next case points the collector elsewhere.
            cleanup_steps.append(
                (f"drain HFT export into InfluxDB database {bucket}",
                 sink.wait_until_drained)
            )
        cleanup_steps.append(("stop OTEL collector", partial(stop_otel_collector, duthost)))
        if database_created:
            cleanup_steps.append(
                (f"drop InfluxDB database {bucket}", sink.drop)
            )
        cleanup_steps.append(
            ("verify countersyncd daemon", verify_countersyncd)
        )
        cleanup_error = _run_cleanup_steps(cleanup_steps)
        if cleanup_error is not None and original_error is None:
            raise cleanup_error


@pytest.fixture(scope="function")
def hft_queue_influxdb(hft_influxdb, duthosts,
                       enum_rand_one_per_hwsku_hostname):
    """Reset countersyncd after the exhaustive Queue export is removed."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    yield hft_influxdb
    cleanup_hft_config(duthost, "queue_profile", ["QUEUE"])
    restart_countersyncd_daemon(duthost)


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
