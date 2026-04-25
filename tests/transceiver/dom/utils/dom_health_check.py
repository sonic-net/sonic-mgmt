"""DOM pre-check and post-check helpers.

The helpers in this module implement the DOM test-plan health gates without
forcing them as autouse fixtures. Test modules can opt into these checks when
they need TC999-style xcvrd/core/log guards.
"""

import logging
import json
import re
from datetime import datetime, timezone

from tests.transceiver.dom.utils.dom_constants import (
    DOM_CORE_FILES_PATH,
    DOM_HEALTH_CHECK_SERVICES,
    DOM_POST_TEST_HEALTH_CHECK_SERVICES,
    DOM_SERVICE_MIN_UPTIME_SEC,
    STATE_DB_INFO_KEY_TEMPLATE,
    STATE_DB_SENSOR_KEY_TEMPLATE,
)
from tests.transceiver.dom.utils.dom_state_db_reader import read_state_db_hash, parse_update_time


logger = logging.getLogger(__name__)

DOM_LOG_ERROR_PATTERNS = (
    "xcvrd.*(error|exception|traceback|fail)",
    "pmon.*(error|exception|traceback|fail)",
    "transceiver.*(error|exception|traceback|fail)",
    "xcvr.*(error|exception|traceback|fail)",
    "i2c.*(error|fail|timeout)",
)
DOM_LOG_ERROR_LEVEL_PATTERN = re.compile(
    r"\b(err|error|warning|warn|crit|critical|alert|emerg|emergency)\b",
    re.IGNORECASE,
)
DOM_LOG_EXCLUDE_PATTERNS = (
    "ansible-ansible.legacy.command Invoked with _raw_params=",
)
I2C_ERROR_PATTERNS = (
    "i2c",
    "sfp",
    "xcvr",
    "transceiver",
)
LINK_UP_VALUES = ("up", "oper_up")
DOM_POLLING_ENABLED_VALUES = ("", "(nil)", "nil", "none", "enabled")


def _stdout_lines(result):
    """Return stdout lines from an Ansible command result.

    Args:
        result: Ansible command or shell result dictionary.

    Returns:
        list: Output split into individual lines.
    """
    lines = result.get("stdout_lines")
    if lines is not None:
        return lines
    stdout = result.get("stdout", "")
    return stdout.splitlines()


def _run_command(duthost, cmd, use_shell=False):
    """Run a DUT command with errors captured in the returned result.

    Args:
        duthost: DUT host fixture used to execute commands.
        cmd: Command string to execute on the DUT.
        use_shell: Whether to use ``duthost.shell`` instead of ``duthost.command``.

    Returns:
        dict: Ansible command result with errors ignored by the module call.
    """
    runner = duthost.shell if use_shell else duthost.command
    return runner(cmd, module_ignore_errors=True)


def _get_dut_epoch_seconds(duthost):
    """Return the DUT UTC epoch timestamp in seconds, or None on failure.

    Args:
        duthost: DUT host fixture used to read device time.

    Returns:
        int | None: UTC epoch seconds from the DUT, or ``None`` when unavailable.
    """
    result = _run_command(duthost, "date -u +%s")
    if result.get("rc", 1) != 0:
        return None
    value = result.get("stdout", "").strip()
    return int(value) if value.isdigit() else None


def _parse_docker_started_at(started_at):
    """Parse a Docker StartedAt timestamp into a UTC datetime.

    Args:
        started_at: Raw Docker ``StartedAt`` timestamp.

    Returns:
        datetime | None: Parsed UTC timestamp, or ``None`` when parsing fails.
    """
    raw = str(started_at).strip()
    if not raw or raw.startswith("0001-"):
        return None
    raw = re.sub(r"(\.\d{6})\d+(Z|[+-]\d\d:\d\d)$", r"\1\2", raw)
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _parse_supervisor_uptime_seconds(output):
    """Parse supervisorctl uptime text into seconds.

    Args:
        output: Raw ``supervisorctl status`` output.

    Returns:
        int | None: Parsed uptime in seconds, or ``None`` when the output does not match.
    """
    match = re.search(r"uptime\s+(?:(\d+)\s+days?,\s*)?(\d+):(\d+):(\d+)", output)
    if not match:
        return None
    days = int(match.group(1) or 0)
    hours = int(match.group(2))
    minutes = int(match.group(3))
    seconds = int(match.group(4))
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def _parse_supervisor_status_state(output):
    """Parse the supervisorctl state token from status output.

    Args:
        output: Raw ``supervisorctl status`` output.

    Returns:
        str: Uppercase process state, or an empty string when parsing fails.
    """
    lines = [line.strip() for line in str(output).splitlines() if line.strip()]
    if not lines:
        return ""

    parts = lines[0].split()
    if len(parts) < 2:
        return ""
    return parts[1].upper()


def _parse_sfputil_presence_state(output, port):
    """Parse the sfputil single-port presence state from command output.

    Args:
        output: Raw ``sfputil show presence -p <port>`` output.
        port: Interface name expected in the output.

    Returns:
        bool | None: ``True`` when present, ``False`` when explicitly not present,
        otherwise ``None`` when no exact state can be parsed.
    """
    lines = [line.strip() for line in str(output).splitlines() if line.strip()]
    if not lines:
        return None

    port_lower = str(port).strip().lower()
    for line in lines:
        normalized = " ".join(line.split())
        lowered = normalized.lower()

        if ":" in normalized:
            name, status = normalized.split(":", 1)
            if name.strip().lower() != port_lower:
                continue
            status = status.strip().lower()
            if status == "present":
                return True
            if status == "not present":
                return False

        tokens = normalized.split()
        if not tokens or tokens[0].lower() != port_lower:
            continue

        tail = " ".join(tokens[1:]).lower()
        if tail == "present":
            return True
        if tail == "not present":
            return False

    return None


def _line_count(duthost, path):
    """Return the line count for a DUT file, or None when unavailable.

    Args:
        duthost: DUT host fixture used to execute file commands.
        path: Path on the DUT whose line count should be read.

    Returns:
        int | None: File line count, or ``None`` when the command fails.
    """
    result = _run_command(duthost, "wc -l {} | awk '{{print $1}}'".format(path), use_shell=True)
    if result.get("rc", 1) != 0:
        return None
    value = result.get("stdout", "").strip()
    return int(value) if value.isdigit() else None


def list_core_files(duthost, core_dir=DOM_CORE_FILES_PATH):
    """List current core files on the DUT.

    Args:
        duthost: DUT host fixture used to list core files.
        core_dir: Directory on the DUT that stores core files.

    Returns:
        list: Core file names currently present in ``core_dir``.
    """
    result = _run_command(duthost, "ls -1 {}".format(core_dir))
    if result.get("rc", 1) != 0:
        return []
    return [line.strip() for line in _stdout_lines(result) if line.strip()]


def get_xcvrd_status(duthost):
    """Return xcvrd supervisor status and parsed uptime metadata.

    Args:
        duthost: DUT host fixture used to query ``xcvrd`` status.

    Returns:
        dict: Raw status output, running state, and parsed uptime metadata.
    """
    result = _run_command(duthost, "docker exec pmon supervisorctl status xcvrd")
    stdout = result.get("stdout", "")
    state = _parse_supervisor_status_state(stdout)
    return {
        "rc": result.get("rc", 1),
        "stdout": stdout,
        "stdout_lines": _stdout_lines(result),
        "running": result.get("rc", 1) == 0 and state == "RUNNING",
        "uptime_sec": _parse_supervisor_uptime_seconds(stdout),
    }


def _docker_container_names(duthost):
    """Return names of running Docker containers on the DUT.

    Args:
        duthost: DUT host fixture used to query Docker containers.

    Returns:
        list: Running Docker container names.
    """
    result = _run_command(duthost, "docker ps --no-trunc", use_shell=True)
    if result.get("rc", 1) != 0:
        return []

    names = []
    for line in _stdout_lines(result):
        parts = line.split()
        if not parts or parts[-1] == "NAMES":
            continue
        names.append(parts[-1])
    return names


def _resolve_container_names(duthost, service):
    """Resolve a logical service name to one or more container names.

    Args:
        duthost: DUT host fixture used to query Docker containers.
        service: Logical service name from the DOM health-check service list.

    Returns:
        list: Container names that should be checked for the service.
    """
    names = _docker_container_names(duthost)
    if service in names:
        return [service]
    if service == "syncd":
        syncd_names = sorted(name for name in names if name.startswith("syncd"))
        if syncd_names:
            return syncd_names
    return [service]


def get_container_status(duthost, container_name, current_epoch=None):
    """Return Docker running state, start time, and uptime for one container.

    Args:
        duthost: DUT host fixture used to inspect Docker state.
        container_name: Docker container name to inspect.
        current_epoch: Optional current DUT epoch seconds used to calculate uptime.

    Returns:
        dict: Container command status, running state, start time, and uptime metadata.
    """
    inspect = "docker inspect {}".format(container_name)
    result = _run_command(duthost, inspect, use_shell=True)
    stdout = result.get("stdout", "").strip()
    running = False
    uptime_sec = None
    started_at = None

    if result.get("rc", 1) == 0 and stdout:
        try:
            inspect_data = json.loads(stdout)
        except ValueError:
            inspect_data = []
        container_info = inspect_data[0] if inspect_data and isinstance(inspect_data[0], dict) else {}
        state = container_info.get("State", {})
        running = bool(state.get("Running"))
        started_at = _parse_docker_started_at(state.get("StartedAt"))
        if running and started_at is not None and current_epoch is not None:
            uptime_sec = current_epoch - int(started_at.timestamp())

    return {
        "rc": result.get("rc", 1),
        "stdout": stdout,
        "running": running,
        "started_at": started_at.isoformat() if started_at else None,
        "uptime_sec": uptime_sec,
    }


def validate_critical_services(duthost, services=DOM_HEALTH_CHECK_SERVICES, min_uptime_sec=DOM_SERVICE_MIN_UPTIME_SEC):
    """Validate that critical services are running and meet the uptime threshold.

    Args:
        duthost: DUT host fixture used to inspect services.
        services: Logical service names that must be healthy.
        min_uptime_sec: Minimum acceptable uptime in seconds; ``0`` disables this check.

    Returns:
        dict: Validation ``errors`` plus per-service ``details``.
    """
    errors = []
    details = {}
    current_epoch = _get_dut_epoch_seconds(duthost)

    for service in services:
        if service == "xcvrd":
            status = get_xcvrd_status(duthost)
            details[service] = status
            if not status["running"]:
                errors.append("xcvrd is not RUNNING: {}".format(status["stdout"]))
            elif min_uptime_sec and (status["uptime_sec"] is None or status["uptime_sec"] < min_uptime_sec):
                errors.append(
                    "xcvrd uptime is below {}s: {}".format(min_uptime_sec, status["stdout"])
                )
            continue

        container_details = {}
        for container_name in _resolve_container_names(duthost, service):
            status = get_container_status(duthost, container_name, current_epoch=current_epoch)
            container_details[container_name] = status
            if not status["running"]:
                errors.append("{} container is not running: {}".format(container_name, status["stdout"]))
            elif min_uptime_sec and (status["uptime_sec"] is None or status["uptime_sec"] < min_uptime_sec):
                errors.append(
                    "{} uptime is below {}s: {}".format(container_name, min_uptime_sec, status["uptime_sec"])
                )
        details[service] = container_details

    return {
        "errors": errors,
        "details": details,
    }


def _is_relevant_dom_log_error(line):
    """Return whether a syslog line is a real DOM health error or warning.

    Args:
        line: Candidate syslog line matched by the broad DOM grep pattern.

    Returns:
        bool: ``True`` for relevant WARN/ERROR-level DOM log entries.
    """
    if any(excluded in line for excluded in DOM_LOG_EXCLUDE_PATTERNS):
        return False
    return DOM_LOG_ERROR_LEVEL_PATTERN.search(line) is not None


def find_dom_log_errors(duthost, patterns=DOM_LOG_ERROR_PATTERNS, limit=50, since_line=None):
    """Find recent DOM-related syslog errors, optionally after a baseline line.

    Args:
        duthost: DUT host fixture used to scan syslog.
        patterns: Regular expression fragments considered DOM-related errors.
        limit: Maximum number of matching log lines to return.
        since_line: Optional syslog line cursor captured before the test.

    Returns:
        list: Matching syslog lines.
    """
    grep_pattern = "|".join(patterns)
    if since_line is None:
        cmd = "grep -Ei '{}' /var/log/syslog | tail -n {}".format(grep_pattern, limit)
    else:
        cmd = "tail -n +{} /var/log/syslog | grep -Ei '{}' | tail -n {}".format(
            int(since_line) + 1,
            grep_pattern,
            limit,
        )
    result = _run_command(duthost, cmd, use_shell=True)
    if result.get("rc", 1) not in (0, 1):
        logger.warning("Unable to scan DOM log errors: %s", result.get("stderr", ""))
        return []
    return [line for line in _stdout_lines(result) if line.strip() and _is_relevant_dom_log_error(line)]


def find_i2c_error_logs(duthost, limit=50):
    """Find recent kernel error logs related to I2C or transceiver access.

    Args:
        duthost: DUT host fixture used to scan kernel logs.
        limit: Maximum number of matching log lines to return.

    Returns:
        list: Matching kernel log lines.
    """
    grep_pattern = "|".join(I2C_ERROR_PATTERNS)
    cmd = "dmesg -T -L -lerr | grep -Ei '{}' | tail -n {}".format(grep_pattern, limit)
    result = _run_command(duthost, cmd, use_shell=True)
    if result.get("rc", 1) not in (0, 1):
        logger.warning("Unable to scan I2C error logs: %s", result.get("stderr", ""))
        return []
    return [line for line in _stdout_lines(result) if line.strip()]


def collect_dom_health_snapshot(duthost):
    """Capture core-file, syslog cursor, and xcvrd status baseline data.

    Args:
        duthost: DUT host fixture used to collect health baseline data.

    Returns:
        dict: Baseline core files, syslog line count, and ``xcvrd`` status.
    """
    return {
        "core_files": set(list_core_files(duthost)),
        "syslog_line_count": _line_count(duthost, "/var/log/syslog"),
        "xcvrd_status": get_xcvrd_status(duthost),
    }


def validate_system_health(duthost, min_uptime_sec=DOM_SERVICE_MIN_UPTIME_SEC, check_logs=True):
    """Validate DOM pre-test system health requirements from the test plan.

    Args:
        duthost: DUT host fixture used to inspect system health.
        min_uptime_sec: Minimum acceptable uptime for critical services.
        check_logs: Whether to scan existing DOM-related syslog errors.

    Returns:
        dict: Validation ``errors`` plus system health ``details``.
    """
    errors = []
    details = {}

    service_result = validate_critical_services(duthost, min_uptime_sec=min_uptime_sec)
    errors.extend(service_result["errors"])
    details["services"] = service_result["details"]

    if check_logs:
        log_errors = find_dom_log_errors(duthost)
        details["log_errors"] = log_errors
        if log_errors:
            errors.append("existing DOM-related syslog errors found:\n{}".format("\n".join(log_errors)))

    return {
        "errors": errors,
        "details": details,
    }


def get_transceiver_presence(duthost, port):
    """Return sfputil presence state for one transceiver port.

    Args:
        duthost: DUT host fixture used to query transceiver presence.
        port: Interface name to check.

    Returns:
        dict: Command status, raw output, and boolean presence state.
    """
    result = _run_command(duthost, "sudo sfputil show presence -p {}".format(port))
    stdout = result.get("stdout", "")
    present_state = _parse_sfputil_presence_state(stdout, port)
    return {
        "rc": result.get("rc", 1),
        "stdout": stdout,
        "present": result.get("rc", 1) == 0 and present_state is True,
    }


def get_interface_status(duthost, port):
    """Return operational and administrative link state for one interface.

    Args:
        duthost: DUT host fixture used to query interface status.
        port: Interface name to check.

    Returns:
        dict: Command status, raw output, operational state, and administrative state.
    """
    try:
        int_status = duthost.show_interface(command="status")["ansible_facts"]["int_status"]
        port_status = int_status.get(port, {})
        oper_state = port_status.get("oper_state") or port_status.get("oper")
        admin_state = port_status.get("admin_state") or port_status.get("admin")
        if port_status:
            return {
                "rc": 0,
                "stdout": str(port_status),
                "oper_state": str(oper_state or "").lower(),
                "admin_state": str(admin_state or "").lower(),
            }
    except Exception as exc:
        logger.debug("duthost.show_interface status lookup failed for %s: %r", port, exc)

    result = _run_command(duthost, "show interface status {}".format(port), use_shell=True)
    stdout = result.get("stdout", "")
    status = {
        "rc": result.get("rc", 1),
        "stdout": stdout,
        "oper_state": "",
        "admin_state": "",
    }

    lines = [line for line in _stdout_lines(result) if line.strip()]
    if len(lines) < 2:
        return status

    headers = lines[0].split()
    for line in lines[1:]:
        values = line.split()
        if not values or values[0] != port:
            continue
        lowered_headers = [header.lower() for header in headers]
        if "oper" in lowered_headers:
            idx = lowered_headers.index("oper")
            if idx < len(values):
                status["oper_state"] = values[idx].lower()
        if "admin" in lowered_headers:
            idx = lowered_headers.index("admin")
            if idx < len(values):
                status["admin_state"] = values[idx].lower()
        break

    return status


def is_lldp_enabled(duthost):
    """Return whether LLDP appears to be enabled on the DUT.

    Args:
        duthost: DUT host fixture used to query LLDP state.

    Returns:
        bool: ``True`` when LLDP appears active, otherwise ``False``.
    """
    container_status = get_container_status(duthost, "lldp")
    if container_status["rc"] == 0:
        return container_status["running"]

    result = _run_command(duthost, "systemctl is-active lldp", use_shell=True)
    return result.get("rc", 1) == 0 and result.get("stdout", "").strip() == "active"


def validate_lldp_neighbors(duthost, ports):
    """Validate LLDP neighbors for DOM ports when LLDP is enabled.

    Args:
        duthost: DUT host fixture used to query LLDP neighbors.
        ports: DOM port names that should have LLDP neighbors when LLDP is enabled.

    Returns:
        dict: Validation ``errors`` plus LLDP status and missing-port ``details``.
    """
    details = {
        "enabled": is_lldp_enabled(duthost),
        "missing_ports": [],
        "observed_ports": [],
    }
    if not details["enabled"]:
        return {
            "errors": [],
            "details": details,
        }

    try:
        lldp_table = duthost.show_and_parse("show lldp table") or []
    except Exception as exc:
        return {
            "errors": ["LLDP is enabled but show lldp table failed: {}".format(exc)],
            "details": details,
        }

    observed_ports = {
        str(entry.get("localport", "")).strip()
        for entry in lldp_table
        if entry.get("localport")
    }
    details["observed_ports"] = sorted(observed_ports)

    for port in ports:
        if port not in observed_ports:
            details["missing_ports"].append(port)

    errors = []
    if details["missing_ports"]:
        errors.append("LLDP neighbors missing for ports: {}".format(", ".join(details["missing_ports"])))

    return {
        "errors": errors,
        "details": details,
    }


def validate_transceiver_baseline(duthost, ports, check_lldp=True):
    """Validate DOM pre-test transceiver presence, link, I2C, and LLDP baseline.

    Args:
        duthost: DUT host fixture used to inspect transceiver baseline state.
        ports: DOM port names selected for validation.
        check_lldp: Whether to validate LLDP neighbors when LLDP is enabled.

    Returns:
        dict: Validation ``errors`` plus presence, info, link, I2C, and LLDP details.
    """
    errors = []
    details = {
        "presence": {},
        "info": {},
        "links": {},
        "i2c_errors": [],
        "lldp": {},
    }

    for port in ports:
        presence = get_transceiver_presence(duthost, port)
        details["presence"][port] = presence
        if not presence["present"]:
            errors.append("{} transceiver is not present/detected: {}".format(port, presence["stdout"]))

        info = read_state_db_hash(duthost, STATE_DB_INFO_KEY_TEMPLATE.format(port))
        details["info"][port] = info
        if not info:
            errors.append("{} missing TRANSCEIVER_INFO data in STATE_DB".format(port))

        link_status = get_interface_status(duthost, port)
        details["links"][port] = link_status
        if link_status["oper_state"] not in LINK_UP_VALUES:
            errors.append("{} link is not operationally up: {}".format(port, link_status["stdout"]))

    i2c_errors = find_i2c_error_logs(duthost)
    details["i2c_errors"] = i2c_errors
    if i2c_errors:
        errors.append("existing I2C/transceiver errors found:\n{}".format("\n".join(i2c_errors)))

    if check_lldp:
        lldp_result = validate_lldp_neighbors(duthost, ports)
        details["lldp"] = lldp_result["details"]
        errors.extend(lldp_result["errors"])

    return {
        "errors": errors,
        "details": details,
    }


def get_dom_polling_state(duthost, port, namespace=None):
    """Return CONFIG_DB DOM polling state for one port.

    Args:
        duthost: DUT host fixture used to query CONFIG_DB.
        port: Interface name whose DOM polling state should be checked.
        namespace: Optional ASIC namespace to query before generic lookup.

    Returns:
        dict: Command status, raw config value, normalized enabled state,
        and the namespace that returned the value when applicable.
    """
    commands = []

    if namespace:
        commands.append((
            namespace,
            'sonic-db-cli -n {} CONFIG_DB HGET "PORT|{}" "dom_polling"'.format(namespace, port),
        ))
    elif getattr(duthost, "is_multi_asic", False):
        for asic in getattr(duthost, "frontend_asics", []):
            commands.append((
                asic.namespace,
                'sonic-db-cli -n {} CONFIG_DB HGET "PORT|{}" "dom_polling"'.format(asic.namespace, port),
            ))

    commands.append((None, 'sonic-db-cli CONFIG_DB HGET "PORT|{}" "dom_polling"'.format(port)))

    result = {"rc": 1, "stdout": ""}
    raw = ""
    resolved_namespace = None

    for command_namespace, cmd in commands:
        result = _run_command(duthost, cmd)
        if result.get("rc", 1) != 0:
            continue
        raw = result.get("stdout", "").strip()
        resolved_namespace = command_namespace
        if raw or command_namespace is None:
            break

    return {
        "rc": result.get("rc", 1),
        "raw": raw,
        "enabled": result.get("rc", 1) == 0 and raw.lower() in DOM_POLLING_ENABLED_VALUES,
        "namespace": resolved_namespace,
    }


def validate_dom_monitoring_state(duthost, dom_port_context, now_utc=None):
    """Validate post-test DOM polling state and sensor freshness.

    Args:
        duthost: DUT host fixture used to query DOM monitoring state.
        dom_port_context: Per-port DOM context with configured DOM attributes.
        now_utc: Optional UTC timestamp used as the freshness reference.

    Returns:
        dict: Validation ``errors`` plus per-port monitoring ``details``.
    """
    errors = []
    details = {}
    if now_utc is None:
        epoch = _get_dut_epoch_seconds(duthost)
        now_utc = datetime.fromtimestamp(epoch, tz=timezone.utc) if epoch is not None else datetime.now(timezone.utc)

    for port, context in dom_port_context.items():
        dom_attrs = context.get("dom", {})
        port_details = {}

        polling = get_dom_polling_state(duthost, port)
        port_details["dom_polling"] = polling
        if not polling["enabled"]:
            errors.append("{} DOM polling is not enabled: {}".format(port, polling["raw"]))

        sensor_data = read_state_db_hash(duthost, STATE_DB_SENSOR_KEY_TEMPLATE.format(port))
        port_details["sensor_fields"] = sorted(sensor_data.keys())
        if not sensor_data:
            errors.append("{} missing TRANSCEIVER_DOM_SENSOR data after DOM tests".format(port))
            details[port] = port_details
            continue

        max_age_min = dom_attrs.get("data_max_age_min")
        if max_age_min is not None:
            parsed_time = parse_update_time(sensor_data.get("last_update_time"))
            port_details["last_update_time"] = sensor_data.get("last_update_time")
            if parsed_time is None:
                errors.append("{} last_update_time missing/unparseable after DOM tests".format(port))
            else:
                age_minutes = (now_utc - parsed_time).total_seconds() / 60.0
                port_details["last_update_age_min"] = age_minutes
                if age_minutes > float(max_age_min):
                    errors.append(
                        "{} last_update_time too old after DOM tests (age_min={:.2f}, limit={})".format(
                            port,
                            age_minutes,
                            max_age_min,
                        )
                    )

        details[port] = port_details

    return {
        "errors": errors,
        "details": details,
    }


def validate_dom_pre_test_environment(duthost, ports, check_logs=True, check_lldp=True):
    """Run combined pre-test system health and transceiver baseline validation.

    Args:
        duthost: DUT host fixture used to run pre-test checks.
        ports: DOM port names selected for validation.
        check_logs: Whether to scan existing DOM-related syslog errors.
        check_lldp: Whether to validate LLDP neighbors when LLDP is enabled.

    Returns:
        dict: Combined pre-test validation ``errors`` and grouped ``details``.
    """
    system_health = validate_system_health(duthost, check_logs=check_logs)
    baseline = validate_transceiver_baseline(duthost, ports, check_lldp=check_lldp)
    errors = system_health["errors"] + baseline["errors"]
    return {
        "errors": errors,
        "details": {
            "system_health": system_health["details"],
            "transceiver_baseline": baseline["details"],
        },
    }


def validate_dom_post_test_cleanup(duthost, dom_port_context, baseline=None, check_logs=True):
    """Run post-test DOM monitoring, service, core-file, and log validation.

    Args:
        duthost: DUT host fixture used to run post-test checks.
        dom_port_context: Per-port DOM context with configured DOM attributes.
        baseline: Optional health snapshot captured before the test.
        check_logs: Whether to scan syslog errors introduced after the baseline.

    Returns:
        dict: Post-test validation ``errors`` plus monitoring, service, and snapshot details.
    """
    errors = []
    details = {}

    monitoring = validate_dom_monitoring_state(duthost, dom_port_context)
    errors.extend(monitoring["errors"])
    details["dom_monitoring"] = monitoring["details"]

    service_result = validate_critical_services(
        duthost,
        services=DOM_POST_TEST_HEALTH_CHECK_SERVICES,
        min_uptime_sec=0,
    )
    errors.extend(service_result["errors"])
    details["services"] = service_result["details"]

    current_snapshot = collect_dom_health_snapshot(duthost)
    details["snapshot"] = current_snapshot

    if baseline is not None:
        new_core_files = sorted(current_snapshot["core_files"] - set(baseline.get("core_files", set())))
        details["new_core_files"] = new_core_files
        if new_core_files:
            errors.append("new core files detected after DOM tests: {}".format(", ".join(new_core_files)))

        if check_logs:
            since_line = baseline.get("syslog_line_count")
            log_errors = find_dom_log_errors(duthost, since_line=since_line) if since_line is not None else []
            details["new_log_errors"] = log_errors
            if log_errors:
                errors.append(
                    "DOM-related syslog errors introduced during DOM tests:\n{}".format("\n".join(log_errors))
                )

    return {
        "errors": errors,
        "details": details,
    }


def build_dom_post_test_report(precheck_result=None, cleanup_result=None):
    """Build a compact report from optional DOM precheck and cleanup results.

    Args:
        precheck_result: Optional result from ``validate_dom_pre_test_environment``.
        cleanup_result: Optional result from ``validate_dom_post_test_cleanup``.

    Returns:
        dict: Compact pass/fail report with error counts, errors, and grouped details.
    """
    precheck_errors = precheck_result.get("errors", []) if precheck_result else []
    cleanup_errors = cleanup_result.get("errors", []) if cleanup_result else []
    return {
        "passed": not precheck_errors and not cleanup_errors,
        "precheck_error_count": len(precheck_errors),
        "cleanup_error_count": len(cleanup_errors),
        "precheck_errors": precheck_errors,
        "cleanup_errors": cleanup_errors,
        "precheck_details": precheck_result.get("details", {}) if precheck_result else {},
        "cleanup_details": cleanup_result.get("details", {}) if cleanup_result else {},
    }
