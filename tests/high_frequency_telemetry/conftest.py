import base64
import itertools
import json
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
    restart_countersyncd_daemon,
    restart_otel_service,
    setup_influxdb,
    start_influxdb,
    stop_influxdb,
    stop_otel_collector,
)

logger = logging.getLogger(__name__)

OTEL_CONFIG_PATH = "/etc/sonic/otel_config.yml"
HFT_WORK = "/var/lib/sonic-mgmt-hft"
HFT_OTEL_ARGS = ("--enable-otel", "--otel-endpoint=http://localhost:4317")
INFLUXDB_PORT = 8181
INFLUXDB_BUCKET_PREFIX = "hft_test"
INFLUXDB_BUCKET_IDS = itertools.count(1)
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
    raise AssertionError(f"Unable to determine OTEL container state: {result}")


def _is_otel_container_stopped(duthost):
    return not _get_otel_container_running(duthost)


def _feature_fields(duthost, name):
    lines = duthost.command(argv=["redis-cli", "-n", "4", "--raw", "HGETALL", f"FEATURE|{name}"],
                            strip_empty_ends=False)["stdout_lines"]
    if lines == [""]:  # redis-cli prints a newline for a missing hash.
        return {}
    if len(lines) % 2:
        pytest.fail(f"Invalid FEATURE|{name} response: expected field/value pairs")
    return dict(zip(lines[::2], lines[1::2]))


def _otel_config(duthost):
    info = duthost.stat(path=OTEL_CONFIG_PATH, follow=False, get_checksum=False, get_mime=False)["stat"]
    if not info["exists"]:
        return None
    if not info["isreg"] or info["nlink"] != 1:
        pytest.fail("Refusing to replace a managed OTEL configuration file")
    return base64.b64decode(duthost.slurp(src=OTEL_CONFIG_PATH, verbose=False)["content"]).decode()


@pytest.fixture(scope="module")
def hft_container_work(duthosts, enum_rand_one_per_hwsku_hostname):
    """Reserve hft before shared setup and keep the saved container until teardown."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.is_multi_asic:
        pytest.skip("Per-ASIC hft containers are not supported")
    hft = _feature_fields(duthost, "hft")
    if (hft.get("state") not in ("enabled", "always_enabled", "disabled") or
            hft.get("set_owner", "local") not in ("", "local")):
        pytest.skip("HFT tests require a locally managed standalone hft feature")
    duthost.command(argv=["mkdir", "-m", "0700", HFT_WORK])
    work = None
    run = {}
    try:
        work = duthost.tempfile(state="directory", path=HFT_WORK, prefix="sonic-mgmt-hft-")["path"]
        for name in ("hft_container.py", "create_hft.sh"):
            duthost.copy(src=os.path.join(os.path.dirname(__file__), "files", name), dest=f"{work}/{name}")
        run["hft_helper"] = ["flock", "-F", "-w", "120", work, "python3", "-B", f"{work}/hft_container.py"]
        yield run
    finally:
        if run.get("otel_restore_pending"):
            pytest.fail(f"OTEL recovery incomplete; inspect the saved configuration in {work}")
        if "hft_helper" in run:
            duthost.command(argv=[*run["hft_helper"], "restore"])  # Retain the recovery record if this fails.
        if work:
            duthost.file(path=work, state="absent")
        duthost.command(argv=["rmdir", HFT_WORK])


@pytest.fixture(scope="module")
def skip_unsupported_hft_platform(duthosts, enum_rand_one_per_hwsku_hostname, hft_container_work):
    """Validate shared HFT prerequisites without changing either service."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    original_feature = _feature_fields(duthost, "otel")
    original_state = original_feature.get("state", "disabled")
    enabled_states = {"enabled", "always_enabled"}
    valid_states = enabled_states | {"disabled", "always_disabled"}
    if original_state not in valid_states:
        pytest.fail(f"Unexpected OTEL feature state: {original_state}")
    if original_state == "always_disabled":
        pytest.skip("OTEL feature is always disabled")
    if original_feature.get("set_owner", "local") not in ("", "local"):
        pytest.skip("HFT tests require a locally managed OTEL collector")
    if original_state in enabled_states:
        policy = duthost.command(argv=["systemctl", "show", "otel.service", "-p", "UnitFileState", "--value"])
        if policy["stdout"].strip() in ("masked", "masked-runtime"):
            pytest.skip("The running OTEL service is masked and cannot be restarted")

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
    hft_container_work.update({
        "original_config": _otel_config(duthost),
        "original_feature": original_feature,
        "original_state": original_state,
        "original_collector_running": original_collector_running,
    })
    return hft_container_work


@pytest.fixture(scope="function")
def skip_unsupported_hft_test(request, duthosts,
                              enum_rand_one_per_hwsku_hostname, tbinfo):
    """Skip unsupported cases before starting InfluxDB or changing OTEL."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.stat(path=HFT_WORK, follow=False, get_checksum=False, get_mime=False)["stat"]["exists"]:
        request.getfixturevalue("hft_container_work")  # Report an abandoned reservation even if this case skips.
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
    original_config = skip_unsupported_hft_platform["original_config"]
    original_feature = skip_unsupported_hft_platform["original_feature"]
    feature_existed = bool(original_feature)
    original_state = skip_unsupported_hft_platform["original_state"]
    enabled_states = {"enabled", "always_enabled"}
    original_collector_running = skip_unsupported_hft_platform[
        "original_collector_running"
    ]

    def restore_config():
        current = _otel_config(duthost)
        own_configs = (skip_unsupported_hft_platform.get(k) for k in ("test_config", "pending_config"))
        if current is None or current not in own_configs:
            return  # No test config was installed, or someone replaced its contents.
        if original_config is not None:
            duthost.copy(content=original_config, dest=OTEL_CONFIG_PATH, verbose=False)
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

    def restore_collector_state():
        if "test_config" not in skip_unsupported_hft_platform:
            return
        if original_collector_running:
            duthost.command(argv=["systemctl", "restart", "otel.service"])
            if not wait_until(60, 2, 0, duthost.critical_processes_running, "otel"):
                pytest.fail("Original OTEL collector did not restart")
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

    helper = skip_unsupported_hft_platform["hft_helper"]
    backup = os.path.join(os.path.dirname(helper[-1]), "otel-before.json")
    # A failed backup cannot strand the original HFT container: neither service has been touched yet.
    duthost.copy(dest=backup, content=json.dumps(skip_unsupported_hft_platform), mode="0600", verbose=False)
    hft_id = duthost.command(argv=[*helper, "install", *HFT_OTEL_ARGS])["stdout"].strip()
    if not wait_until(60, 2, 0, ensure_countersyncd_daemon, duthost):
        pytest.fail("countersyncd did not start in the standalone hft container")
    if duthost.command(argv=["docker", "ps", "-q", "--no-trunc", "--filter", "name=^/hft$"])["stdout"] != hft_id:
        pytest.fail("hft.service did not start the test container")
    try:
        skip_unsupported_hft_platform["otel_restore_pending"] = True
        if original_state not in enabled_states:
            enable_otel_collector(duthost, check_image=False)
        skip_unsupported_hft_platform["otel_id"] = duthost.command(
            argv=["docker", "ps", "-q", "--no-trunc", "--filter", "name=^/otel$"])["stdout"]
        if not skip_unsupported_hft_platform["otel_id"]:
            pytest.fail("Expected a running OTEL container")
        yield hft_id
    finally:
        # Setup failures are active here; pytest reports call-phase failures
        # separately from any teardown error raised below.
        original_error = sys.exc_info()[1]
        if duthost.command(argv=["redis-cli", "-n", "4", "--raw", "KEYS", "HIGH_FREQUENCY_TELEMETRY_*"])["stdout"]:
            pytest.fail("HFT profiles remain; clean them before reconnecting the original collector")
        if _feature_fields(duthost, "otel").get("set_owner", "local") not in ("", "local"):
            pytest.fail("OTEL owner changed; refusing to restore another owner's configuration")
        cleanup_steps = [("restore OTEL config", restore_config)]
        if feature_existed:
            cleanup_steps.extend([
                ("restore OTEL feature runtime state",
                 restore_feature_runtime_state),
                ("restore OTEL collector process state",
                 restore_collector_state),
            ])
        else:
            cleanup_steps.append(
                ("stop and remove created OTEL feature", remove_created_feature)
            )
        cleanup_error = _run_cleanup_steps(cleanup_steps)
        if cleanup_error is None:
            skip_unsupported_hft_platform["otel_restore_pending"] = False
        elif original_error is None:
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
    request.getfixturevalue("ensure_swss_ready")
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.command(argv=["redis-cli", "-n", "4", "--raw", "KEYS", "HIGH_FREQUENCY_TELEMETRY_*"])["stdout"]:
        pytest.skip("Existing HFT profiles are not owned by this test")
    request.getfixturevalue("hft_influxdb_server")
    request.getfixturevalue("hft_otel_collector")
    baseline = request.getfixturevalue("skip_unsupported_hft_platform")
    bucket = f"{INFLUXDB_BUCKET_PREFIX}_{next(INFLUXDB_BUCKET_IDS)}"
    sink = InfluxDbSink(ptfhost, bucket=bucket, port=INFLUXDB_PORT)
    database_created = False
    configured = False

    def cleanup_stop_collector():
        if configured and _otel_config(duthost) == baseline["test_config"]:
            stop_otel_collector(duthost)

    def cleanup_verify_countersyncd():
        ensure_countersyncd_daemon(duthost)

    try:
        ensure_countersyncd_daemon(duthost)
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
        otel = _feature_fields(duthost, "otel")
        running = duthost.command(argv=["docker", "ps", "-q", "--no-trunc", "--filter", "name=^/otel$"])["stdout"]
        current = _otel_config(duthost)
        if "pending_config" in baseline and current == baseline["pending_config"]:
            baseline["test_config"] = current  # The preceding copy published its file but lost its reply.
        if (running != baseline["otel_id"] or otel.get("set_owner", "local") not in ("", "local") or
                otel.get("state") not in ("enabled", "always_enabled") or
                current != baseline.get("test_config", baseline["original_config"])):
            pytest.fail("OTEL configuration or owner changed; refusing to overwrite it")
        baseline["pending_config"] = rendered_config  # Until copy succeeds, either case's config may be on disk.
        install_otel_collector_config(duthost, rendered_config)
        baseline["test_config"] = baseline.pop("pending_config")
        configured = True
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
        cleanup_steps.append(("stop OTEL collector", cleanup_stop_collector))
        if database_created:
            cleanup_steps.append(
                (f"drop InfluxDB database {bucket}", sink.drop)
            )
        cleanup_steps.append(
            ("verify countersyncd daemon", cleanup_verify_countersyncd)
        )
        cleanup_error = _run_cleanup_steps(cleanup_steps)
        if cleanup_error is not None and original_error is None:
            raise cleanup_error


@pytest.fixture(scope="function")
def hft_queue_influxdb(request, hft_influxdb, duthosts,
                       enum_rand_one_per_hwsku_hostname):
    """Reset countersyncd after the exhaustive Queue export is removed."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    yield hft_influxdb
    cleanup_hft_config(duthost, "queue_profile", ["QUEUE"])
    restart_countersyncd_daemon(duthost, request.getfixturevalue("hft_otel_collector"))


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
