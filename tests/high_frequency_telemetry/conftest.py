import base64
import logging
import os
import sys
import time
from functools import partial

import pytest
from _pytest.outcomes import OutcomeException
from tests.common.utilities import wait_until
from tests.high_frequency_telemetry.counter_profiles import (
    CounterObjectType,
    get_support_counter_list,
)
from tests.high_frequency_telemetry import transaction
from tests.high_frequency_telemetry.utilities import (
    InfluxDbSink,
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
    stop_owned_influxdb,
)

logger = logging.getLogger(__name__)

OTEL_CONFIG_PATH = "/etc/sonic/otel_config.yml"
HFT_OTEL_ARGS = ("--enable-otel", "--otel-endpoint=http://localhost:4317")
INFLUXDB_PORT = 8181
INFLUXDB_BUCKET_PREFIX = "hft_test"
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


def _supported_hft_state(duthost):
    hft = _read_feature(duthost, "hft")
    original_hft_state = hft.get("state")
    if not original_hft_state:
        pytest.skip("Standalone hft is not configured on this image (no FEATURE|hft state)")
    if original_hft_state not in ("enabled", "always_enabled", "disabled", "always_disabled"):
        pytest.fail(f"Unexpected HFT feature state: {original_hft_state}")
    if original_hft_state == "always_disabled":
        pytest.skip("HFT feature is always disabled")
    if hft.get("set_owner", "local") not in ("", "local"):
        pytest.skip("HFT tests require a locally managed hft feature")
    return original_hft_state


def _otel_container(duthost):
    # docker ps --filter status=running also excludes paused/restarting. Neither
    # is evidence that it is safe to delete the feature's configuration.
    result = duthost.shell(r"docker ps -a --no-trunc --filter 'name=^/otel$' --format \{\{.ID\}\}:\{\{.State\}\}")
    return result["stdout"].strip().split(":") if result["stdout"].strip() else (None, "absent")


def _recover_transaction(tx, request):
    """Used by both normal teardown and a successor after a controller crash."""
    dut = tx.dut
    done = set(tx.call("close").split())
    sink = tx.load("sink.json")

    def restore_hft():
        state = tx.call("restore")
        if state in ("enabled", "always_enabled") and not wait_until(60, 2, 0, dut.critical_processes_running, "hft"):
            pytest.fail("Original hft did not become ready after restoration")

    def stop_sink():
        ptf = getattr(tx, "ptf", None)
        if not ptf:
            if str(request.getfixturevalue("tbinfo")["ptf_ip"]) != sink["ptf_ip"]:
                pytest.fail(f"Recover HFT run {tx.work.name} on its original PTF host {sink['ptf_ip']}")
            ptf = request.getfixturevalue("ptfhost")
        if not ptf:
            pytest.fail(f"Original PTF host {sink['ptf_ip']} is unavailable for HFT sink cleanup")
        stop_owned_influxdb(ptf, tx.work.name)

    def step(name, fn):
        if name not in done:
            fn()
            tx.call("done", name)
            done.add(name)

    # Never reconnect a production exporter or collector while an interrupted
    # test session may still be live. The DUT helper enforces the same invariant.
    def after(prerequisite, fn):
        if prerequisite not in done:
            pytest.fail(f"Keeping the test export path isolated: {prerequisite} cleanup is incomplete")
        fn()

    steps = [("profiles", lambda: tx.call("clean-profiles")), ("hft", partial(after, "profiles", restore_hft))]
    if tx.load("otel.json") is not None:
        steps.append(("otel", partial(after, "hft", lambda: tx.call("restore-otel"))))
    if sink:
        steps.append(("sink", stop_sink))
    error = _run_cleanup_steps([(name, partial(step, name, fn)) for name, fn in steps])
    if error is not None:
        raise error
    tx.call("finish")


@pytest.fixture(scope="module")
def skip_unsupported_hft_platform(request, duthosts, enum_rand_one_per_hwsku_hostname):
    """Recover an interrupted owner, then take the baseline under this module's lock."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if duthost.is_multi_asic:
        pytest.skip("The HFT fixture requires a single ASIC; per-ASIC hft instances are not supported")
    if transaction.active_work(duthost) is None:
        _supported_hft_state(duthost)  # fast skip on legacy images, never a recovery baseline
    tx = transaction.claim(duthost, request, partial(_recover_transaction, request=request))
    original_hft_state = _supported_hft_state(duthost)
    if duthost.command(argv=["redis-cli", "-n", "4", "--raw", "KEYS", "HIGH_FREQUENCY_TELEMETRY_*"])["stdout"]:
        pytest.skip("Existing HFT configuration is not owned by this run")
    enabled_states = {"enabled", "always_enabled"}
    valid_states = enabled_states | {"disabled", "always_disabled"}

    original_feature = _read_feature(duthost, "otel")
    original_state = original_feature.get("state", "disabled")
    if original_feature.get("set_owner", "local") not in ("", "local"):
        pytest.skip("HFT tests require a locally managed otel feature")
    if original_state not in valid_states:
        pytest.fail(f"Unexpected OTEL feature state: {original_state}")
    if original_state == "always_disabled":
        pytest.skip("OTEL feature is always disabled")

    container_id, container_state = _otel_container(duthost)
    if container_state not in ("running", "absent", "created", "exited"):
        pytest.fail(f"OTEL container is not in a stable state: {container_state}")
    original_container_running = container_state == "running"
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
        "transaction": tx,
        "otel_config": _read_test_config(duthost, OTEL_CONFIG_PATH),
        "original_feature": original_feature,
        "original_state": original_state,
        "original_collector_running": original_collector_running,
        "container_id": container_id,
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
    """Journal collector state before enabling either service. The owner restores it."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    tx = skip_unsupported_hft_platform["transaction"]
    snapshot = {k: skip_unsupported_hft_platform[k] for k in
                ("otel_config", "original_feature", "original_state", "original_collector_running", "container_id")}
    tx.record("otel.json", snapshot)
    tx.call("prepare-otel")
    tx.call("install", skip_unsupported_hft_platform["original_hft_state"], *HFT_OTEL_ARGS)
    if not wait_until(60, 2, 0, get_running_countersyncd_pid, duthost):
        pytest.fail("countersyncd did not start in the HFT container")
    return tx


@pytest.fixture(scope="module")
def hft_influxdb_server(ptfhost, tbinfo, skip_unsupported_hft_platform):
    """The transaction token identifies this sink even if the controller loses its PID."""
    if not ptfhost or not tbinfo.get("ptf_ip"):
        pytest.skip("HFT export tests require a PTF host for InfluxDB")
    tx = skip_unsupported_hft_platform["transaction"]
    tx.ptf = ptfhost
    return start_influxdb(ptfhost, tx.work.name, port=INFLUXDB_PORT,
                          before_start=partial(tx.record, "sink.json", {"ptf_ip": str(tbinfo["ptf_ip"])}))


@pytest.fixture(scope="function")
def hft_influxdb(request, ptfhost, skip_unsupported_hft_test,
                 duthosts, enum_rand_one_per_hwsku_hostname, tbinfo):
    """Provide a unique InfluxDB database for every HFT case."""
    request.getfixturevalue("hft_influxdb_server")
    request.getfixturevalue("ensure_swss_ready")
    tx = request.getfixturevalue("hft_otel_collector")
    profile = transaction.HftProfile(tx)
    bucket = f"{INFLUXDB_BUCKET_PREFIX}_{profile.case}"
    sink = InfluxDbSink(ptfhost, bucket=bucket, port=INFLUXDB_PORT, profile=profile)
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    database_created = False

    def verify_countersyncd():
        if get_running_countersyncd_pid(duthost) is None:
            pytest.fail("Expected supervisor-owned countersyncd to be RUNNING in hft")

    try:
        verify_countersyncd()
        tx.call("stop-collector")
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
        tx.configure_otel(rendered_config)
        restart_otel_service(duthost, tx)
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
        cleanup_steps = [("remove this case's HFT profile", sink.profile.remove)]
        if database_created:
            # Let samples countersyncd still exports for this case reach this
            # database before the next case points the collector elsewhere.
            cleanup_steps.append(
                (f"drain HFT export into InfluxDB database {bucket}",
                 sink.wait_until_drained)
            )
        cleanup_steps.append(("stop OTEL collector", partial(tx.call, "stop-collector")))
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
    hft_influxdb.profile.remove()
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
