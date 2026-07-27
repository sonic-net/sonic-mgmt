"""Utilities for validating high frequency telemetry through InfluxDB."""

import itertools
import json
import logging
import re
import shlex
import threading
import time
from collections import namedtuple
from collections.abc import Iterable
from datetime import datetime

import ptf.testutils as testutils
import pytest
from natsort import natsorted

from tests.common.helpers.assertions import pytest_assert
from tests.high_frequency_telemetry.counter_profiles import (
    get_sai_object_type_id,
    get_sai_stat_id,
)

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


def setup_hft_profile(duthost, profile_name, poll_interval=10000,
                      stream_state="disabled"):
    """Create an HFT profile through the supported CLI."""
    stream_state = (stream_state or "").strip().lower()
    pytest_assert(
        stream_state in {"enabled", "disabled"},
        f"Invalid HFT stream state: {stream_state}",
    )
    result = duthost.shell(
        f"sudo config hft add profile {profile_name} "
        f"--poll_interval {int(poll_interval)} "
        f"--stream_state {stream_state}",
        module_ignore_errors=False,
    )
    logger.info(
        "Created HFT profile %s (poll_interval=%s, stream_state=%s)",
        profile_name,
        poll_interval,
        stream_state,
    )
    return result


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


def setup_hft_group(duthost, profile_name, group_name,
                    object_names, object_counters):
    """Create one HFT group through the supported CLI."""
    group_type = _normalize_hft_group_type(group_name)
    object_names = _stringify_sequence(object_names)
    object_counters = _stringify_sequence(object_counters)
    result = duthost.shell(
        f"sudo config hft add group {profile_name} "
        f"--group_type {group_type} "
        f"--object_names {shlex.quote(object_names)} "
        f"--object_counters {shlex.quote(object_counters)}",
        module_ignore_errors=False,
    )
    logger.info(
        "Created HFT group %s for %s: objects=%s counters=%s",
        group_type,
        profile_name,
        object_names,
        object_counters,
    )
    return result


def setup_hft_stream_state(duthost, profile_name, stream_state):
    """Enable or disable an HFT profile."""
    state = (stream_state or "").strip().lower()
    action_map = {
        "enabled": "enable",
        "enable": "enable",
        "disabled": "disable",
        "disable": "disable",
    }
    pytest_assert(state in action_map, f"Invalid HFT stream state: {state}")
    return duthost.shell(
        f"sudo config hft {action_map[state]} {profile_name}",
        module_ignore_errors=False,
    )


def cleanup_hft_config(duthost, profile_name, group_names=None):
    """Delete groups before deleting their HFT profile."""
    if group_names is None:
        result = duthost.shell(
            f'redis-cli -n 4 KEYS "HIGH_FREQUENCY_TELEMETRY_GROUP|'
            f'{profile_name}|*"',
            module_ignore_errors=True,
        )
        group_names = []
        for key in result.get("stdout_lines", []):
            parts = (key or "").strip().split("|", 2)
            if len(parts) == 3 and parts[1] == profile_name:
                group_names.append(parts[2])
    elif isinstance(group_names, str):
        group_names = [group_names]

    for group_name in group_names:
        group_type = _normalize_hft_group_type(group_name)
        duthost.shell(
            f"sudo config hft del group {profile_name} {group_type}",
            module_ignore_errors=True,
        )
    duthost.shell(
        f"sudo config hft del profile {profile_name}",
        module_ignore_errors=True,
    )
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


def restart_otel_collector(duthost, timeout=30):
    """Reload OTEL configuration without restarting its managed container."""
    duthost.shell(
        "docker exec otel supervisorctl stop otel",
        module_ignore_errors=True,
    )
    result = duthost.shell(
        "docker exec otel supervisorctl start otel",
        module_ignore_errors=True,
    )
    pytest_assert(
        result.get("rc") == 0,
        f"Failed to restart the OTEL collector process: {result}",
    )
    end_time = time.time() + timeout
    while time.time() < end_time:
        status = duthost.shell(
            "docker exec otel supervisorctl status otel",
            module_ignore_errors=True,
        )
        if status.get("rc") == 0 and "RUNNING" in status.get("stdout", ""):
            return True
        time.sleep(1)
    raise AssertionError("OTEL collector process did not become ready")


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


def enable_otel_collector(duthost, timeout=60):
    """Enable the OTEL feature and wait for its container."""
    has_image = False
    for attempt in range(6):
        image = duthost.shell(
            "docker images docker-sonic-otel --format yes",
            module_ignore_errors=True,
        )
        if image.get("rc") == 0 and "yes" in image.get("stdout", ""):
            has_image = True
            break
        logger.info("OTEL image check attempt %d failed", attempt + 1)
        time.sleep(10)
    if not has_image:
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
    else:
        duthost.shell(
            "sudo config feature state otel enabled",
            module_ignore_errors=False,
        )

    end_time = time.time() + timeout
    while time.time() < end_time:
        running = duthost.shell(
            'docker ps -q --filter "name=otel"',
            module_ignore_errors=True,
        )
        if running.get("rc") == 0 and running.get("stdout", "").strip():
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
    type_id = get_sai_object_type_id(counter_type)
    expected = []
    for counter_name in counter_names:
        stat_id = get_sai_stat_id(counter_type, counter_name)
        measurement = f"sai_counter_type_{type_id}_stat_{stat_id}"
        expected.extend(
            HftSeries(measurement, object_name, type_id, stat_id, counter_name)
            for object_name in object_names
        )
    return expected


def _parse_rfc3339_timestamp(value):
    clean = value.replace("Z", "+00:00")
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

    def clear(self, retries=3, settle_time=2):
        """Hard-delete and recreate the database, then prove it stays empty."""
        last_measurements = None
        for attempt in range(1, retries + 1):
            deleted = _influxdb_database_command(
                self.ptfhost,
                "delete",
                self.bucket,
                self.port,
                hard_delete=True,
            )
            if deleted.get("rc") != 0:
                logger.warning(
                    "InfluxDB delete attempt %d failed: %s", attempt, deleted
                )
                time.sleep(settle_time)
                continue

            created = None
            for _ in range(10):
                created = _influxdb_database_command(
                    self.ptfhost, "create", self.bucket, self.port
                )
                if created.get("rc") == 0:
                    break
                time.sleep(1)
            if created is None or created.get("rc") != 0:
                logger.warning(
                    "InfluxDB recreate attempt %d failed: %s", attempt, created
                )
                continue
            time.sleep(settle_time)
            if self.is_empty():
                logger.info(
                    "InfluxDB database %s is empty (attempt %d)",
                    self.bucket,
                    attempt,
                )
                return
            last_measurements = self._query("SHOW MEASUREMENTS")
            logger.warning(
                "Metrics reached InfluxDB after clear attempt %d", attempt
            )
        pytest_assert(
            False,
            f"InfluxDB database {self.bucket} did not remain empty: "
            f"{last_measurements}",
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

    def _grouped_values(self, measurements, expression, value_column,
                        cutoff=None):
        values = {}
        where = f" WHERE time <= '{cutoff}'" if cutoff else ""
        for measurement in sorted(measurements):
            query = (
                f'SELECT {expression} AS "{value_column}" '
                f'FROM "{measurement}"{where} '
                'GROUP BY "object_name", "sai_type_id", "sai_stat_id"'
            )
            rows = parse_influxdb_json(json.dumps(self._query(query)))
            for row in rows.get(measurement, []):
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

    def _first(self, expected_series, cutoff=None):
        return self._grouped_values(
            {series.measurement for series in expected_series},
            'FIRST("gauge")',
            "metric_value",
            cutoff,
        )

    def _minimum(self, expected_series, cutoff=None):
        return self._grouped_values(
            {series.measurement for series in expected_series},
            'MIN("gauge")',
            "metric_value",
            cutoff,
        )

    def wait_for_points(self, expected_series, min_points=20, timeout=90,
                        poll_interval=3):
        expected = self._expected_map(expected_series)
        end_time = time.time() + timeout
        last_counts = {}
        while time.time() < end_time:
            last_counts = self.counts(expected_series)
            if expected and all(
                key in last_counts
                and int(last_counts[key]["value"] or 0) >= min_points
                for key in expected
            ):
                return last_counts
            time.sleep(poll_interval)
        missing = [series for key, series in expected.items() if key not in last_counts]
        underfilled = [
            (series, int(last_counts[key]["value"] or 0))
            for key, series in expected.items()
            if key in last_counts and int(last_counts[key]["value"] or 0) < min_points
        ]
        raise AssertionError(
            f"Timed out waiting for {min_points} points per series. "
            f"Missing ({len(missing)}): {missing[:20]}; "
            f"underfilled ({len(underfilled)}): {underfilled[:20]}"
        )

    def validate_series(self, expected_series, expected_interval_us,
                        min_points=20, interval_tolerance=0.25):
        """Validate object/counter coverage, values, interval, and CPS."""
        expected = self._expected_map(expected_series)
        expected_measurements = {
            series.measurement for series in expected_series
        }
        actual_measurements = self.measurements()
        snapshot_latest = self.latest(expected_series)
        missing_latest = set(expected) - set(snapshot_latest)
        pytest_assert(
            not missing_latest,
            f"Missing latest samples for expected series: {list(missing_latest)[:20]}",
        )
        cutoff = min(
            snapshot_latest[key]["time"] for key in expected
        )
        counts = self.counts(expected_series, cutoff)
        first = self._first(expected_series, cutoff)
        last = self.latest(expected_series, cutoff)
        minimum = self._minimum(expected_series, cutoff)
        violations = []

        missing_measurements = expected_measurements - actual_measurements
        unexpected_measurements = actual_measurements - expected_measurements
        if missing_measurements:
            violations.append(
                f"missing measurements: {sorted(missing_measurements)}"
            )
        if unexpected_measurements:
            violations.append(
                f"unexpected measurements: {sorted(unexpected_measurements)}"
            )

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
            if interval_error > interval_tolerance:
                violations.append(
                    f"{key}: interval {actual_interval * 1000:.3f}ms, expected "
                    f"{expected_interval_s * 1000:.3f}ms (+/-{interval_tolerance:.0%})"
                )
            if cps_error > interval_tolerance:
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
        logger.info("Validated %d HFT object/counter series", len(stats))
        return stats

    def wait_and_validate(self, expected_series, expected_interval_us,
                          min_points=20, timeout=90,
                          interval_tolerance=0.25):
        self.wait_for_points(expected_series, min_points + 2, timeout)
        return self.validate_series(
            expected_series,
            expected_interval_us,
            min_points,
            interval_tolerance,
        )

    def assert_no_new_points(self, expected_series, duration=5, drain_time=3):
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

    def wait_for_new_points(self, expected_series, baseline, timeout=30,
                            poll_interval=2):
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
                                    timeout=30, poll_interval=2):
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
