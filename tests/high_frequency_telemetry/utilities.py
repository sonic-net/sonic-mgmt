"""Utilities for validating high frequency telemetry through InfluxDB."""

import itertools
import json
import logging
import re
import shlex
import sys
import threading
import time
from collections import namedtuple
from collections.abc import Iterable
from datetime import datetime

import ptf.testutils as testutils
import pytest
from _pytest.outcomes import OutcomeException
from natsort import natsorted

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.sai_ids import (
    get_sai_object_type_id,
    get_sai_stat_id,
)
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

HftSeries = namedtuple(
    "HftSeries",
    ["measurement", "object_name", "type_id", "stat_id", "counter_name"],
)


def get_available_ports(duthost, tbinfo, desired_ports=2, min_ports=None):
    """Return admin-up, PTF-mapped ports that are not PortChannel members."""
    cfg_facts = duthost.config_facts(
        host=duthost.hostname, source="persistent"
    )["ansible_facts"]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    config_ports = {
        name: values for name, values in cfg_facts["PORT"].items()
        if values.get("admin_status", "down") == "up"
    }
    ptf_indices = mg_facts["minigraph_ptf_indices"]
    disabled_ptf_indices = set()
    disabled_map = tbinfo.get("topo", {}).get("ptf_map_disabled", {})
    for ptf_map in disabled_map.values():
        disabled_ptf_indices.update(ptf_map.values())
    portchannel_members = list(itertools.chain.from_iterable(
        members.keys()
        for members in cfg_facts.get("PORTCHANNEL_MEMBER", {}).values()
    ))
    available_ports = natsorted(
        port for port in config_ports
        if port in ptf_indices
        and ptf_indices[port] not in disabled_ptf_indices
        and port not in portchannel_members
    )

    logger.info("Found %d available ports: %s", len(available_ports), available_ports)
    if min_ports is not None and len(available_ports) < min_ports:
        pytest.skip(
            f"Not enough ports: required {min_ports}, found {len(available_ports)}"
        )
    if desired_ports is None:
        return available_ports
    return available_ports[:desired_ports]


class ContinuousTraffic:
    """Continuously send packets through one PTF port until stopped."""

    def __init__(self, ptfadapter, ptf_port_index, router_mac,
                 packet_interval=0.01):
        self.ptfadapter = ptfadapter
        self.ptf_port_index = ptf_port_index
        self.router_mac = router_mac
        self.packet_interval = packet_interval
        self.packet_count = 0
        self.errors = []
        self._running = threading.Event()
        self._thread = None

    def _send(self):
        packet = testutils.simple_ip_packet(
            eth_dst=self.router_mac,
            eth_src="00:01:02:03:04:05",
            ip_src="10.0.0.1",
            ip_dst="10.0.0.2",
            ip_ttl=64,
        )
        while self._running.is_set():
            try:
                testutils.send(self.ptfadapter, self.ptf_port_index, packet)
                self.packet_count += 1
                time.sleep(self.packet_interval)
            except Exception as exc:  # noqa: B902
                self.errors.append(str(exc))
                logger.warning("Failed to send HFT test traffic: %s", exc)
                time.sleep(0.1)

    def start(self):
        self._running.set()
        self._thread = threading.Thread(target=self._send, daemon=True)
        self._thread.start()

    def stop(self):
        self._running.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        logger.info("Sent %d HFT test packets", self.packet_count)


def _format_counter_db_name_map_keys(name_map_keys):
    objects = [key.replace(":", "|") for key in natsorted(name_map_keys)]
    return list(dict.fromkeys(objects))


def _get_counter_db_name_map_keys(duthost, name_map):
    result = duthost.shell(
        f'redis-cli -n 2 --raw hgetall "{name_map}"',
        module_ignore_errors=True,
    )
    if result.get("rc", 1) != 0:
        logger.warning(
            "Failed to read %s from COUNTERS_DB: %s",
            name_map,
            result.get("stderr"),
        )
        return []
    lines = [
        line for line in (result.get("stdout", "") or "").splitlines()
        if line
    ]
    return lines[0::2]


def get_configured_queue_objects(duthost):
    """Return all queue objects as ``<port>|<queue>``."""
    return _format_counter_db_name_map_keys(
        _get_counter_db_name_map_keys(duthost, "COUNTERS_QUEUE_NAME_MAP")
    )


def get_configured_buffer_queue_objects(duthost):
    """Return all ingress priority group objects as ``<port>|<pg>``."""
    return _format_counter_db_name_map_keys(
        _get_counter_db_name_map_keys(duthost, "COUNTERS_PG_NAME_MAP")
    )


def get_configured_buffer_pools(duthost):
    """Return buffer pools that have an object mapping in COUNTERS_DB."""
    return natsorted(_get_counter_db_name_map_keys(
        duthost, "COUNTERS_BUFFER_POOL_NAME_MAP"
    ))


def _stringify_sequence(value):
    if isinstance(value, str):
        return value
    if isinstance(value, Iterable):
        return ",".join(str(item) for item in value)
    return str(value)


def _normalize_hft_group_type(group_name):
    key = re.sub(r"[\s\-]+", "_", str(group_name).strip()).upper()
    mapping = {
        "PORT": "PORT",
        "QUEUE": "QUEUE",
        "BUFFER": "BUFFER_POOL",
        "BUFFER_POOL": "BUFFER_POOL",
        "INGRESS_PRIORITY_GROUP": "INGRESS_PRIORITY_GROUP",
        "PG": "INGRESS_PRIORITY_GROUP",
        "IPG": "INGRESS_PRIORITY_GROUP",
    }
    group_type = mapping.get(key)
    pytest_assert(group_type is not None, f"Unsupported HFT group: {group_name}")
    return group_type


def _get_hft_config_keys(duthost):
    def query_keys(pattern):
        result = duthost.shell(
            f"redis-cli -n 4 --raw KEYS {shlex.quote(pattern)}",
            module_ignore_errors=True,
        )
        lines = [
            line for line in result.get("stdout_lines", []) if line
        ]
        redis_errors = [
            line for line in lines
            if line.startswith("ERR ") or line.startswith("(error)")
        ]
        pytest_assert(
            result.get("rc") == 0 and not redis_errors,
            f"Failed to query CONFIG_DB keys for {pattern}: {result}",
        )
        return lines

    return (
        query_keys("HIGH_FREQUENCY_TELEMETRY_PROFILE|*"),
        query_keys("HIGH_FREQUENCY_TELEMETRY_GROUP|*"),
    )


def _apply_hft_patch(duthost, operations):
    payload = shlex.quote(json.dumps(operations, separators=(",", ":")))
    return duthost.shell(
        "patch_file=$(mktemp /tmp/hft-test-XXXXXX.json) && "
        f"printf '%s' {payload} > \"$patch_file\" && "
        "sudo config apply-patch \"$patch_file\"; "
        "rc=$?; rm -f \"$patch_file\"; exit $rc",
        module_ignore_errors=False,
    )


def setup_hft_config(duthost, profile_name, group_name, object_names,
                     object_counters, poll_interval=10000,
                     stream_state="enabled"):
    """Create an HFT profile and group in one validated config patch."""
    state = (stream_state or "").strip().lower()
    pytest_assert(
        state in {"enabled", "disabled"},
        f"Invalid HFT stream state: {state}",
    )
    group_type = _normalize_hft_group_type(group_name)
    objects = [
        item.strip() for item in _stringify_sequence(object_names).split(",")
        if item.strip()
    ]
    counters = [
        item.strip() for item in _stringify_sequence(object_counters).split(",")
        if item.strip()
    ]
    profiles, groups = _get_hft_config_keys(duthost)
    pytest_assert(
        not profiles and not groups,
        "An HFT configuration already exists: "
        f"profiles={profiles}, groups={groups}",
    )
    result = _apply_hft_patch(duthost, [
        {
            "op": "add",
            "path": "/HIGH_FREQUENCY_TELEMETRY_PROFILE",
            "value": {
                profile_name: {
                    "stream_state": state,
                    "poll_interval": str(int(poll_interval)),
                },
            },
        },
        {
            "op": "add",
            "path": "/HIGH_FREQUENCY_TELEMETRY_GROUP",
            "value": {
                f"{profile_name}|{group_type}": {
                    "object_names": objects,
                    "object_counters": counters,
                },
            },
        },
    ])
    logger.info(
        "Created HFT profile/group %s/%s (poll_interval=%s, stream_state=%s)",
        profile_name,
        group_type,
        poll_interval,
        state,
    )
    return result


def setup_hft_stream_state(duthost, profile_name, stream_state):
    """Enable or disable an HFT profile."""
    profile_arg = shlex.quote(str(profile_name))
    state = (stream_state or "").strip().lower()
    action_map = {
        "enabled": "enable",
        "enable": "enable",
        "disabled": "disable",
        "disable": "disable",
    }
    pytest_assert(state in action_map, f"Invalid HFT stream state: {state}")
    return duthost.shell(
        f"sudo config hft {action_map[state]} {profile_arg}",
        module_ignore_errors=False,
    )


def cleanup_hft_config(duthost, profile_name, group_names=None):
    """Stop the stream, delete its groups, then delete the profile."""
    original_error = sys.exc_info()[1]
    first_cleanup_error = None

    def cleanup_step(step_name, callback):
        nonlocal first_cleanup_error
        try:
            callback()
            return True
        except (Exception, OutcomeException) as error:
            logger.exception("HFT cleanup step '%s' failed", step_name)
            if first_cleanup_error is None:
                first_cleanup_error = error
            return False

    def run_command(command, failure_message):
        result = duthost.shell(command, module_ignore_errors=True)
        pytest_assert(result.get("rc") == 0, f"{failure_message}: {result}")

    profile_arg = shlex.quote(str(profile_name))
    profile_keys = []
    group_keys = []
    config_known = False

    def inspect_config():
        nonlocal profile_keys, group_keys, config_known
        profile_keys, group_keys = _get_hft_config_keys(duthost)
        config_known = True

    cleanup_step("inspect HFT configuration", inspect_config)

    if group_names is None:
        group_names = [
            key.split("|", 2)[2] for key in group_keys
            if key.startswith(f"HIGH_FREQUENCY_TELEMETRY_GROUP|{profile_name}|")
        ]
    elif isinstance(group_names, str):
        group_names = [group_names]

    requested_groups = [
        _normalize_hft_group_type(group_name) for group_name in group_names
    ]
    if config_known:
        configured_groups = [
            group_type for group_type in requested_groups
            if f"HIGH_FREQUENCY_TELEMETRY_GROUP|{profile_name}|{group_type}"
            in group_keys
        ]
    else:
        configured_groups = requested_groups

    profile_key = f"HIGH_FREQUENCY_TELEMETRY_PROFILE|{profile_name}"
    profile_may_exist = not config_known or profile_key in profile_keys
    if profile_may_exist:
        cleanup_step(
            f"disable profile {profile_name}",
            lambda: run_command(
                f"sudo config hft disable {profile_arg}",
                f"Failed to disable HFT profile {profile_name}",
            ),
        )

    def wait_for_session_state(group_type, expected_state):
        session_key = shlex.quote(
            "HIGH_FREQUENCY_TELEMETRY_SESSION_TABLE|"
            f"{profile_name}|{group_type}"
        )
        if expected_state == "disabled":
            condition = '[ "$state" = disabled ] || [ "$state" = missing ]'
        else:
            condition = '[ "$state" = missing ]'
        command = (
            "for i in $(seq 1 30); do "
            "state=$(redis-cli -n 6 --raw EVAL "
            "'if redis.call(\"EXISTS\", KEYS[1]) == 0 then "
            "return \"missing\" end; return redis.call(\"HGET\", KEYS[1], "
            "ARGV[1]) or \"invalid\"' "
            f"1 {session_key} stream_status) || exit 2; "
            f"if {condition}; then exit 0; fi; "
            "sleep 1; done; exit 1"
        )
        run_command(
            command,
            f"HFT session {profile_name}|{group_type} did not reach "
            f"{expected_state}",
        )

    stopped_groups = {}
    for group_type in configured_groups:
        stopped_groups[group_type] = cleanup_step(
            f"wait for session {profile_name}|{group_type} to stop",
            lambda group_type=group_type: wait_for_session_state(
                group_type, "disabled"
            ),
        )
    removed_groups = {}
    for group_type in configured_groups:
        if not stopped_groups[group_type]:
            logger.error(
                "Not deleting HFT group %s|%s because its session did not stop",
                profile_name,
                group_type,
            )
            removed_groups[group_type] = False
            continue
        group_deleted = cleanup_step(
            f"delete group {profile_name}|{group_type}",
            lambda group_type=group_type: run_command(
                f"sudo config hft del group {profile_arg} {group_type}",
                f"Failed to delete HFT group {profile_name}|{group_type}",
            ),
        )
        removed_groups[group_type] = group_deleted and cleanup_step(
                f"wait for session {profile_name}|{group_type} removal",
                lambda group_type=group_type: wait_for_session_state(
                    group_type, "removed"
                ),
            )

    groups_removed = all(removed_groups.values())
    if profile_may_exist and groups_removed:
        cleanup_step(
            f"delete profile {profile_name}",
            lambda: run_command(
                f"sudo config hft del profile {profile_arg}",
                f"Failed to delete HFT profile {profile_name}",
            ),
        )
    elif profile_may_exist:
        logger.error(
            "Not deleting HFT profile %s because group cleanup was incomplete",
            profile_name,
        )

    def verify_config_removed():
        remaining_profiles, remaining_groups = _get_hft_config_keys(duthost)
        stale_groups = [
            key for key in remaining_groups
            if key.startswith(
                f"HIGH_FREQUENCY_TELEMETRY_GROUP|{profile_name}|"
            )
        ]
        pytest_assert(
            profile_key not in remaining_profiles and not stale_groups,
            f"HFT configuration remains after cleanup: profile="
            f"{profile_key in remaining_profiles}, groups={stale_groups}",
        )

    cleanup_step("verify HFT configuration removal", verify_config_removed)
    if first_cleanup_error is not None:
        if original_error is None:
            raise first_cleanup_error
        logger.error(
            "Preserving active test failure after HFT cleanup also failed: %s",
            first_cleanup_error,
        )
        return
    logger.info("Cleaned HFT profile %s", profile_name)


def ensure_countersyncd_daemon(duthost):
    """Verify the supervisor-owned countersyncd daemon is OTEL-enabled."""
    status = duthost.shell(
        "docker exec swss supervisorctl status countersyncd",
        module_ignore_errors=True,
    )
    pytest_assert(
        status.get("rc") == 0 and "RUNNING" in status.get("stdout", ""),
        "Expected supervisor-owned countersyncd to be RUNNING, got: "
        f"{status.get('stdout', '')} {status.get('stderr', '')}",
    )
    command = duthost.shell(
        "docker exec swss sh -c 'pid=$(supervisorctl pid countersyncd) && "
        "xargs -0 echo < /proc/$pid/cmdline'",
        module_ignore_errors=True,
    )
    pytest_assert(
        command.get("rc") == 0 and "--enable-otel" in command.get("stdout", ""),
        "The supervisor countersyncd must use --enable-otel, got: "
        f"{command.get('stdout', '')} {command.get('stderr', '')}",
    )
    return True


def _get_running_countersyncd_pid(duthost):
    status = duthost.shell(
        "docker exec swss supervisorctl status countersyncd",
        module_ignore_errors=True,
    )
    fields = status.get("stdout", "").split()
    if status.get("rc") != 0 or len(fields) < 2 \
            or fields[0] != "countersyncd" or fields[1] != "RUNNING":
        return None
    pid = duthost.shell(
        "docker exec swss supervisorctl pid countersyncd",
        module_ignore_errors=True,
    )
    try:
        value = int(pid.get("stdout", "").strip())
    except (TypeError, ValueError):
        return None
    return value if pid.get("rc") == 0 and value > 0 else None


def restart_countersyncd_daemon(duthost, timeout=30):
    """Restart only countersyncd and verify its supervisor-owned process."""
    old_pid = _get_running_countersyncd_pid(duthost)
    pytest_assert(
        old_pid is not None,
        "Unable to determine the running countersyncd PID before restart",
    )
    result = duthost.shell(
        "docker exec swss supervisorctl restart countersyncd",
        module_ignore_errors=True,
    )
    pytest_assert(
        result.get("rc") == 0,
        f"Failed to restart countersyncd: {result}",
    )

    def restarted():
        pid = _get_running_countersyncd_pid(duthost)
        return pid is not None and pid != old_pid

    pytest_assert(
        wait_until(timeout, 1, 0, restarted),
        f"countersyncd did not restart from PID {old_pid}",
    )
    new_pid = _get_running_countersyncd_pid(duthost)
    ensure_countersyncd_daemon(duthost)
    logger.info("Restarted countersyncd from PID %d to PID %d", old_pid, new_pid)
    return old_pid, new_pid


def render_otel_collector_config(template_path, **kwargs):
    """Render the test OTEL collector configuration."""
    from jinja2 import Environment, StrictUndefined, select_autoescape

    with open(template_path, "r") as stream:
        template = Environment(autoescape=select_autoescape(
            enabled_extensions=("html", "htm", "xml"),
            default_for_string=False,
        ), undefined=StrictUndefined).from_string(stream.read())
    return template.render(**kwargs)


def install_otel_collector_config(duthost, rendered_config,
                                  dest_path="/etc/sonic/otel_config.yml"):
    duthost.copy(content=rendered_config, dest=dest_path)


def _is_otel_collector_ready(duthost):
    if (
        not duthost.is_service_fully_started("otel")
        or not duthost.critical_processes_running("otel")
    ):
        return False

    result = duthost.shell(
        "sudo ss -lnt | grep -Eq ':4317[[:space:]]'",
        module_ignore_errors=True,
    )
    return result.get("rc") == 0


def restart_otel_service(duthost, timeout=60):
    """Restart otel.service and wait for the collector's OTLP listener."""
    duthost.shell(
        "sudo systemctl reset-failed otel && sudo systemctl restart otel",
        module_ignore_errors=False,
    )
    ready = wait_until(timeout, 2, 10, _is_otel_collector_ready, duthost)
    diagnostics = ""
    if not ready:
        status = duthost.shell(
            "systemctl status otel --no-pager",
            module_ignore_errors=True,
        )
        logs = duthost.shell(
            "docker logs --tail 200 otel",
            module_ignore_errors=True,
        )
        diagnostics = f"; service status: {status}; container logs: {logs}"

    pytest_assert(
        ready,
        "OTEL container, critical process, or OTLP listener did not become "
        f"ready after restarting otel.service{diagnostics}",
    )


def stop_otel_collector(duthost):
    """Stop only the OTEL collector process inside its container."""
    result = duthost.shell(
        "docker exec otel supervisorctl stop otel",
        module_ignore_errors=True,
    )
    pytest_assert(
        result.get("rc") == 0 or "not running" in result.get("stdout", "").lower(),
        f"Failed to stop the OTEL collector process: {result}",
    )


def is_otel_image_available(duthost, attempts=6, retry_interval=10):
    """Return whether the DUT has the OTEL container image."""
    for attempt in range(attempts):
        image = duthost.shell(
            "docker images docker-sonic-otel --format yes",
            module_ignore_errors=True,
        )
        if image.get("rc") == 0 and "yes" in image.get("stdout", ""):
            return True
        logger.info("OTEL image check attempt %d failed", attempt + 1)
        if attempt + 1 < attempts:
            time.sleep(retry_interval)
    return False


def enable_otel_collector(duthost, timeout=60, check_image=True):
    """Enable the OTEL feature and wait for its container."""
    if check_image and not is_otel_image_available(duthost):
        pytest.skip("docker-sonic-otel is not available on this platform")

    exists = duthost.shell(
        "sonic-db-cli CONFIG_DB exists 'FEATURE|otel'",
        module_ignore_errors=True,
    )
    if exists.get("stdout", "").strip() == "0":
        duthost.shell(
            "sonic-db-cli CONFIG_DB hmset 'FEATURE|otel' "
            "state enabled auto_restart enabled "
            "has_global_scope True has_per_asic_scope False",
            module_ignore_errors=False,
        )
    duthost.shell(
        "sudo config feature state otel enabled",
        module_ignore_errors=False,
    )

    end_time = time.time() + timeout
    while time.time() < end_time:
        running = duthost.shell(
            r"docker inspect -f \{\{.State.Running\}\} otel",
            module_ignore_errors=True,
        )
        if running.get("rc") == 0 \
                and running.get("stdout", "").strip() == "true":
            return True
        time.sleep(2)
    raise AssertionError("OTEL container did not become ready")


def start_influxdb(ptfhost, port=8181, timeout=30,
                   log_path="/tmp/hft_influxdb3.log"):
    """Start an owned in-memory InfluxDB 3 process and return its PID."""
    binary = ptfhost.shell("command -v influxdb3", module_ignore_errors=True)
    pytest_assert(
        binary.get("rc") == 0,
        "influxdb3 is not installed on the PTF host",
    )
    socket_tool = ptfhost.shell("command -v ss", module_ignore_errors=True)
    pytest_assert(
        socket_tool.get("rc") == 0,
        "ss is not installed on the PTF host",
    )
    listener = ptfhost.shell(
        f"ss -ltn | grep -q ':{int(port)} '", module_ignore_errors=True
    )
    pytest_assert(
        listener.get("rc") != 0,
        f"TCP port {port} is already in use on the PTF host",
    )
    result = ptfhost.shell(
        "nohup influxdb3 serve --object-store memory --node-id hft-test "
        f"--http-bind=0.0.0.0:{int(port)} --without-auth "
        f"> {shlex.quote(log_path)} 2>&1 < /dev/null & echo $!",
        module_ignore_errors=False,
    )
    try:
        pid = int(result.get("stdout", "").strip().splitlines()[-1])
    except (ValueError, IndexError) as exc:
        raise RuntimeError(f"Failed to capture InfluxDB PID: {result}") from exc

    try:
        end_time = time.time() + timeout
        while time.time() < end_time:
            health = ptfhost.shell(
                f"curl -sf --max-time 5 http://localhost:{int(port)}/health",
                module_ignore_errors=True,
            )
            if health.get("rc") == 0 and "OK" in health.get("stdout", ""):
                logger.info("InfluxDB is healthy (pid=%d)", pid)
                return pid
            time.sleep(2)
        server_log = ptfhost.shell(
            f"tail -100 {shlex.quote(log_path)}", module_ignore_errors=True
        ).get("stdout", "")
        raise RuntimeError(f"InfluxDB did not become healthy:\n{server_log}")
    except BaseException:
        ptfhost.shell(f"kill {pid}", module_ignore_errors=True)
        raise


def _influxdb_database_command(ptfhost, action, bucket, port=8181,
                               hard_delete=False):
    """Run a database command across supported InfluxDB 3 CLI syntaxes."""
    hard_delete_arg = " --hard-delete now" if hard_delete else ""
    confirmation_arg = " -y" if action == "delete" else ""
    modern = (
        f"influxdb3 {action} database --host http://127.0.0.1:{int(port)}"
        f"{hard_delete_arg}{confirmation_arg} {shlex.quote(bucket)}"
    )
    legacy = (
        f"influxdb3 {action} database {shlex.quote(bucket)} --port {int(port)}"
        f"{hard_delete_arg}{confirmation_arg}"
    )
    result = ptfhost.shell(modern, module_ignore_errors=True)
    stderr = result.get("stderr", "").lower()
    if result.get("rc") != 0 and (
        "unexpected argument '--host'" in stderr
        or "unrecognized option '--host'" in stderr
    ):
        result = ptfhost.shell(legacy, module_ignore_errors=True)
    return result


def setup_influxdb(ptfhost, port=8181, bucket="home"):
    """Create an empty InfluxDB database."""
    result = _influxdb_database_command(ptfhost, "create", bucket, port)
    pytest_assert(
        result.get("rc") == 0,
        f"Failed to create InfluxDB database {bucket}: {result}",
    )


def query_influxdb(ptfhost, influxql_query, port=8181, db="home"):
    """Execute an InfluxQL query through the v1 compatibility API."""
    command = " ".join([
        "curl -sS --max-time 60 -G",
        shlex.quote(f"http://localhost:{int(port)}/query"),
        "--data-urlencode", shlex.quote(f"db={db}"),
        "--data-urlencode", shlex.quote(f"q={influxql_query}"),
    ])
    return ptfhost.shell(command, module_ignore_errors=True)


def stop_influxdb(ptfhost, pid):
    """Stop only the InfluxDB process owned by this test."""
    process = ptfhost.shell(
        f"ps -p {int(pid)} -o args=", module_ignore_errors=True
    )
    if process.get("rc") != 0:
        return
    pytest_assert(
        "influxdb3 serve" in process.get("stdout", ""),
        f"Refusing to terminate unexpected PID {pid}: {process.get('stdout', '')}",
    )
    ptfhost.shell(f"kill {int(pid)}", module_ignore_errors=True)
    end_time = time.time() + 10
    while time.time() < end_time:
        status = ptfhost.shell(
            f"ps -p {int(pid)} -o stat=", module_ignore_errors=True
        )
        if status.get("rc") != 0 or status.get("stdout", "").lstrip().startswith("Z"):
            return
        time.sleep(1)
    ptfhost.shell(f"kill -9 {int(pid)}", module_ignore_errors=True)


def parse_influxdb_json(json_text):
    """Return InfluxDB rows grouped by measurement, preserving series tags."""
    body = json.loads(json_text)
    groups = {}
    for result in body.get("results", []):
        for series in result.get("series", []):
            name = series.get("name", "unknown")
            columns = series.get("columns", [])
            tags = series.get("tags", {})
            for values in series.get("values", []):
                row = dict(zip(columns, values))
                row.update(tags)
                groups.setdefault(name, []).append(row)
    return groups


def build_expected_series(counter_type, object_names, counter_names):
    """Build exact InfluxDB series expected for an HFT group."""
    sai_type_name = counter_type.name
    type_id = get_sai_object_type_id(f"SAI_OBJECT_TYPE_{sai_type_name}")
    expected = []
    for counter_name in counter_names:
        stat_id = get_sai_stat_id(
            f"SAI_{sai_type_name}_STAT_{counter_name}"
        )
        measurement = f"sai_counter_type_{type_id}_stat_{stat_id}"
        expected.extend(
            HftSeries(measurement, object_name, type_id, stat_id, counter_name)
            for object_name in object_names
        )
    return expected


def _parse_rfc3339_timestamp(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing RFC3339 timestamp: {value!r}")
    clean = value.strip().replace("Z", "+00:00")
    if "." in clean:
        dot_index = clean.index(".")
        offset_index = max(clean.rfind("+"), clean.rfind("-"))
        if offset_index > dot_index:
            fraction = clean[dot_index + 1:offset_index][:6]
            clean = clean[:dot_index + 1] + fraction + clean[offset_index:]
    return datetime.fromisoformat(clean).timestamp()


class InfluxDbSink:
    """Query and validate counters exported by the countersyncd daemon."""

    def __init__(self, ptfhost, bucket="hft_test", port=8181):
        self.ptfhost = ptfhost
        self.bucket = bucket
        self.port = port

    def _query(self, query):
        result = query_influxdb(
            self.ptfhost, query, port=self.port, db=self.bucket
        )
        pytest_assert(
            result.get("rc") == 0 and result.get("stdout", "").strip(),
            f"InfluxDB query failed: {query}. Result: {result}",
        )
        try:
            body = json.loads(result["stdout"])
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"Invalid InfluxDB JSON for {query}: {exc}"
            ) from exc
        errors = [body["error"]] if body.get("error") else []
        errors.extend(
            entry["error"] for entry in body.get("results", [])
            if entry.get("error")
        )
        pytest_assert(not errors, f"InfluxDB query failed: {errors}")
        return body

    def is_empty(self):
        return not self.measurements()

    def measurements(self):
        """Return all measurement names currently present in the database."""
        rows = parse_influxdb_json(json.dumps(self._query("SHOW MEASUREMENTS")))
        return {
            row["name"]
            for measurement_rows in rows.values()
            for row in measurement_rows
            if row.get("name")
        }

    def drop(self):
        """Hard-delete this sink's database."""
        result = _influxdb_database_command(
            self.ptfhost,
            "delete",
            self.bucket,
            self.port,
            hard_delete=True,
        )
        pytest_assert(
            result.get("rc") == 0,
            f"Failed to delete InfluxDB database {self.bucket}: {result}",
        )

    @staticmethod
    def _expected_map(expected_series):
        return {
            (
                series.measurement,
                series.object_name,
                str(series.type_id),
                str(series.stat_id),
            ): series
            for series in expected_series
        }

    def _where_clause(self, cutoff=None):
        return f" WHERE time <= '{cutoff}'" if cutoff else ""

    @staticmethod
    def _grouped_rows(result, measurement, value_column):
        values = {}
        for series in result.get("series", []):
            columns = series.get("columns", [])
            tags = series.get("tags", {})
            for raw_values in series.get("values", []):
                row = dict(zip(columns, raw_values))
                row.update(tags)
                object_name = row.get("object_name")
                type_id = row.get("sai_type_id")
                stat_id = row.get("sai_stat_id")
                if object_name is None or type_id is None or stat_id is None:
                    continue
                key = (
                    measurement,
                    object_name,
                    str(type_id),
                    str(stat_id),
                )
                values[key] = {
                    "time": row.get("time"),
                    "value": row.get(value_column),
                    "type_id": str(type_id),
                    "stat_id": str(stat_id),
                }
        return values

    def _grouped_values(self, measurements, expression, value_column,
                        cutoff=None):
        measurements = sorted(measurements)
        where = self._where_clause(cutoff)
        statements = [
            (
                f'SELECT {expression} AS "{value_column}" '
                f'FROM "{measurement}"{where} '
                'GROUP BY "object_name", "sai_type_id", "sai_stat_id"'
            )
            for measurement in measurements
        ]
        body = self._query(";".join(statements))
        values = {}
        for measurement, result in zip(measurements, body.get("results", [])):
            values.update(self._grouped_rows(result, measurement, value_column))
        return values

    def _statistics(self, expected_series, cutoff):
        measurements = sorted({
            series.measurement for series in expected_series
        })
        where = self._where_clause(cutoff)
        specs = (
            ('COUNT("gauge")', "sample_count"),
            ('FIRST("gauge")', "first_value"),
            ('LAST("gauge")', "last_value"),
            ('MIN("gauge")', "minimum_value"),
        )
        statements = []
        statement_specs = []
        for expression, value_column in specs:
            for measurement in measurements:
                statements.append(
                    f'SELECT {expression} AS "{value_column}" '
                    f'FROM "{measurement}"{where} '
                    'GROUP BY "object_name", "sai_type_id", "sai_stat_id"'
                )
                statement_specs.append((measurement, value_column))
        body = self._query(";".join(statements))
        values = {value_column: {} for _, value_column in specs}
        for (measurement, value_column), result in zip(
                statement_specs, body.get("results", [])):
            values[value_column].update(
                self._grouped_rows(result, measurement, value_column)
            )
        return values

    def counts(self, expected_series, cutoff=None):
        return self._grouped_values(
            {series.measurement for series in expected_series},
            'COUNT("gauge")',
            "sample_count",
            cutoff,
        )

    def latest(self, expected_series, cutoff=None):
        return self._grouped_values(
            {series.measurement for series in expected_series},
            'LAST("gauge")',
            "metric_value",
            cutoff,
        )

    def wait_for_points(self, expected_series, min_points=20, timeout=30,
                        poll_interval=1):
        expected = self._expected_map(expected_series)
        end_time = time.time() + timeout
        last_counts = {}
        cutoff = None
        missing_latest = set(expected)
        unfiltered_ready = False
        while time.time() < end_time:
            if not unfiltered_ready:
                last_counts = self.counts(expected_series)
                unfiltered_ready = expected and all(
                    key in last_counts
                    and int(last_counts[key]["value"] or 0) >= min_points
                    for key in expected
                )
            if unfiltered_ready:
                snapshot_latest = self.latest(expected_series)
                missing_latest = set(expected) - set(snapshot_latest)
                if not missing_latest:
                    cutoff = min(
                        (snapshot_latest[key]["time"] for key in expected),
                        key=_parse_rfc3339_timestamp,
                    )
                    last_counts = self.counts(expected_series, cutoff)
                    if all(
                        key in last_counts
                        and int(last_counts[key]["value"] or 0) >= min_points
                        for key in expected
                    ):
                        logger.info(
                            "All %d HFT series have at least %d points at "
                            "shared cutoff %s",
                            len(expected),
                            min_points,
                            cutoff,
                        )
                        return cutoff
            time.sleep(poll_interval)
        missing = [series for key, series in expected.items() if key not in last_counts]
        underfilled = [
            (series, int(last_counts[key]["value"] or 0))
            for key, series in expected.items()
            if key in last_counts and int(last_counts[key]["value"] or 0) < min_points
        ]
        raise AssertionError(
            f"Timed out waiting for {min_points} points per series at shared "
            f"cutoff {cutoff}. "
            f"Missing latest ({len(missing_latest)}): "
            f"{list(missing_latest)[:20]}. "
            f"Missing ({len(missing)}): {missing[:20]}. "
            f"Underfilled ({len(underfilled)}): {underfilled[:20]}"
        )

    def validate_series(self, expected_series, expected_interval_us,
                        min_points=20, interval_tolerance=0.05,
                        validate_cadence=True, cutoff=None):
        """Validate series coverage and values, optionally enforcing cadence."""
        expected = self._expected_map(expected_series)
        if cutoff is None:
            snapshot_latest = self.latest(expected_series)
            missing_latest = set(expected) - set(snapshot_latest)
            pytest_assert(
                not missing_latest,
                f"Missing latest samples for expected series: "
                f"{list(missing_latest)[:20]}",
            )
            cutoff = min(
                (snapshot_latest[key]["time"] for key in expected),
                key=_parse_rfc3339_timestamp,
            )
        else:
            _parse_rfc3339_timestamp(cutoff)
        values = self._statistics(expected_series, cutoff)
        counts = values["sample_count"]
        first = values["first_value"]
        last = values["last_value"]
        minimum = values["minimum_value"]
        violations = []

        missing = set(expected) - set(counts)
        unexpected = set(counts) - set(expected)
        if missing:
            violations.append(
                f"missing series: {list(missing)[:20]} ({len(missing)} total)"
            )
        if unexpected:
            violations.append(
                f"unexpected series: {list(unexpected)[:20]} ({len(unexpected)} total)"
            )

        expected_interval_s = expected_interval_us / 1_000_000.0
        expected_cps = 1.0 / expected_interval_s
        stats = {}
        for key, series in expected.items():
            if key not in counts or key not in first or key not in last \
                    or key not in minimum:
                continue
            count = int(counts[key]["value"] or 0)
            first_value = first[key]["value"]
            last_value = last[key]["value"]
            minimum_value = minimum[key]["value"]
            if count < min_points:
                violations.append(f"{key}: only {count} points, expected {min_points}")
                continue
            if first_value is None or last_value is None \
                    or minimum_value is None or float(minimum_value) < 0:
                violations.append(
                    f"{key}: invalid values first={first_value}, "
                    f"last={last_value}, minimum={minimum_value}"
                )
                continue
            if counts[key]["type_id"] != str(series.type_id) \
                    or counts[key]["stat_id"] != str(series.stat_id):
                violations.append(
                    f"{key}: type/stat tags are "
                    f"{counts[key]['type_id']}/{counts[key]['stat_id']}, expected "
                    f"{series.type_id}/{series.stat_id}"
                )
            try:
                first_time = _parse_rfc3339_timestamp(first[key]["time"])
                last_time = _parse_rfc3339_timestamp(last[key]["time"])
            except (TypeError, ValueError, IndexError) as exc:
                violations.append(f"{key}: invalid timestamps: {exc}")
                continue
            duration = last_time - first_time
            if duration <= 0:
                violations.append(f"{key}: non-positive duration {duration}")
                continue
            actual_interval = duration / (count - 1)
            actual_cps = (count - 1) / duration
            interval_error = abs(actual_interval - expected_interval_s) / expected_interval_s
            cps_error = abs(actual_cps - expected_cps) / expected_cps
            if validate_cadence and interval_error > interval_tolerance:
                violations.append(
                    f"{key}: interval {actual_interval * 1000:.3f}ms, expected "
                    f"{expected_interval_s * 1000:.3f}ms (+/-{interval_tolerance:.0%})"
                )
            if validate_cadence and cps_error > interval_tolerance:
                violations.append(
                    f"{key}: CPS {actual_cps:.3f}, expected "
                    f"{expected_cps:.3f} (+/-{interval_tolerance:.0%})"
                )
            stats[key] = {
                "counter_name": series.counter_name,
                "sample_count": count,
                "first_value": first_value,
                "last_value": last_value,
                "minimum_value": minimum_value,
                "average_interval_ms": actual_interval * 1000,
                "cps": actual_cps,
            }

        pytest_assert(
            not violations,
            "InfluxDB HFT validation failed:\n" + "\n".join(violations[:100]),
        )
        intervals = [entry["average_interval_ms"] for entry in stats.values()]
        rates = [entry["cps"] for entry in stats.values()]
        logger.info(
            "Validated %d HFT object/counter series; interval %.3f-%.3fms, "
            "CPS %.3f-%.3f",
            len(stats),
            min(intervals),
            max(intervals),
            min(rates),
            max(rates),
        )
        return stats

    def wait_and_validate(self, expected_series, expected_interval_us,
                          min_points=20, timeout=30,
                          interval_tolerance=0.05,
                          validate_cadence=True):
        cutoff = self.wait_for_points(expected_series, min_points, timeout)
        return self.validate_series(
            expected_series,
            expected_interval_us,
            min_points=min_points,
            interval_tolerance=interval_tolerance,
            validate_cadence=validate_cadence,
            cutoff=cutoff,
        )

    def assert_no_new_points(self, expected_series, duration=3, drain_time=2):
        time.sleep(drain_time)
        before = self.counts(expected_series)
        time.sleep(duration)
        after = self.counts(expected_series)
        expected = self._expected_map(expected_series)
        changed = {
            key: (before.get(key, {}).get("value"), after.get(key, {}).get("value"))
            for key in expected
            if before.get(key, {}).get("value") != after.get(key, {}).get("value")
        }
        pytest_assert(
            not changed,
            f"HFT series continued after disable/delete: {changed}",
        )
        return after

    def wait_for_new_points(self, expected_series, baseline, timeout=20,
                            poll_interval=1):
        expected = self._expected_map(expected_series)
        end_time = time.time() + timeout
        current = {}
        while time.time() < end_time:
            current = self.counts(expected_series)
            if all(
                int(current.get(key, {}).get("value") or 0)
                > int(baseline.get(key, {}).get("value") or 0)
                for key in expected
            ):
                return current
            time.sleep(poll_interval)
        raise AssertionError(f"HFT series did not resume: {current}")

    def wait_for_values_to_increase(self, expected_series, baseline,
                                    timeout=20, poll_interval=1):
        expected = self._expected_map(expected_series)
        end_time = time.time() + timeout
        current = {}
        while time.time() < end_time:
            current = self.latest(expected_series)
            if all(
                float(current.get(key, {}).get("value") or 0)
                > float(baseline.get(key, {}).get("value") or 0)
                for key in expected
            ):
                return current
            time.sleep(poll_interval)
        raise AssertionError(f"HFT counter values did not increase: {current}")
