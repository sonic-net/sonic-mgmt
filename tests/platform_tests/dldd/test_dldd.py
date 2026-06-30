"""Platform qualification for the device-local diagnosis daemon (DLDD).

The tests intentionally use only the installed rules and live telemetry.  They
do not inject hardware faults or execute the optional ``hardware-probe`` and
``e2e-execute`` validation modes, because vendor hooks may bind those modes to
platform-specific operations.
"""

import json
import shlex
from urllib.parse import quote

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import compose_dict_from_cli, wait_until


pytestmark = [pytest.mark.topology("any")]

FEATURE_KEY = "FEATURE|dldd"
STATUS_KEY = "DLDD_STATUS|process_state"
FAULT_PATTERN = "FAULT_INFO|*"
HEARTBEAT_TTL_SECONDS = 120
HEARTBEAT_REFRESH_SECONDS = 30
# ``featured`` may hold delayed services until its 180-second port-init
# timeout.  Leave a small margin so a valid delayed start is not reported as a
# DLDD lifecycle failure by platform qualification.
DELAYED_FEATURE_START_TIMEOUT_SECONDS = 240
UINT32_MAX = (1 << 32) - 1

ENABLED_FEATURE_STATES = ("enabled",)
DISABLED_FEATURE_STATES = ("disabled",)
SERVICE_HEALTH_STATES = ("OK", "DEGRADED", "BROKEN|FATAL")
FAULT_STATUSES = ("ACTIVE", "INACTIVE", "UNSPECIFIED")
FAULT_SEVERITIES = ("CRITICAL", "MAJOR", "WARNING", "MINOR", "UNKNOWN")
LOCAL_ACTION_STATES = ("IDLE", "COMPLETED", "FAILED", "SUPPRESSED")
REPAIR_ACTIONS = (
    "ACTION_RESEAT",
    "ACTION_WARM_REBOOT",
    "ACTION_COLD_REBOOT",
    "ACTION_POWER_CYCLE",
    "ACTION_FACTORY_RESET",
    "ACTION_REPLACE",
)
EVALUATOR_TYPES = ("mask", "comparison", "string", "boolean", "dse")
VALUE_CONFIG_TYPES = (
    "binary",
    "hex",
    "int",
    "float",
    "string",
    "boolean",
    "json",
    "bytes",
    "N/A",
)
CONFIG_FIELD_MINIMUMS = {
    "individual_max_failure_threshold": 0,
    "broken_rules_max_threshold": 0,
    "redis_monitor_polling_interval": 1,
    "file_monitor_polling_interval": 1,
    "common_monitor_polling_interval": 1,
    "source_unavailable_grace_period": 0,
    "source_recovery_samples": 1,
    "inactive_fault_retention_period": 0,
    "fault_evidence_ack_timeout": 1,
    "active_fault_recheck_interval": 1,
    "rules_inbox_settle_time": 1,
}

FAULT_REQUIRED_FIELDS = {
    "rule",
    "rule_id",
    "rule_version",
    "schema_version",
    "active_rules_checksum",
    "component_info",
    "error_type",
    "events",
    "remote_action_time_window",
    "repair_actions",
    "actions_taken",
    "local_action_state",
    "severity",
    "symptom",
    "status",
    "origin_time",
    "last_detection_time",
    "occurrences",
    "description",
}


def _read_hash(duthost, database, key):
    result = duthost.shell(
        "sonic-db-cli {} HGETALL {}".format(database, shlex.quote(key)),
        module_ignore_errors=True,
    )
    pytest_assert(
        result["rc"] == 0,
        "Unable to read {} from {}: {}".format(key, database, result.get("stderr", "")),
    )
    output = result["stdout"].strip()
    return compose_dict_from_cli(output) if output else {}


def _fault_keys(duthost):
    result = duthost.shell(
        "sonic-db-cli STATE_DB KEYS {}".format(shlex.quote(FAULT_PATTERN)),
        module_ignore_errors=True,
    )
    pytest_assert(
        result["rc"] == 0,
        "Unable to list DLDD faults: {}".format(result.get("stderr", "")),
    )
    return sorted(line.strip() for line in result["stdout_lines"] if line.strip())


def _faults(duthost):
    faults = {}
    for key in _fault_keys(duthost):
        fault = _read_hash(duthost, "STATE_DB", key)
        if _is_dldd_fault(fault):
            faults[key] = fault
    return faults


def _is_dldd_fault(fault):
    """Return whether a shared FAULT_INFO row is owned by DLDD."""
    try:
        rule_id = int(fault.get("rule_id", 0))
    except (TypeError, ValueError):
        return False
    return bool(
        rule_id
        and fault.get("rule")
        and fault.get("schema_version")
        and fault.get("active_rules_checksum")
    )


@pytest.mark.parametrize(
    "fault,expected",
    (
        (
            {
                "rule_id": "1000001",
                "rule": "PSU_OV_FAULT",
                "schema_version": "0.0.1",
                "active_rules_checksum": "sha256:test",
            },
            True,
        ),
        ({"rule_id": "not-an-integer"}, False),
        ({"rule_id": "1000001", "rule": "foreign"}, False),
        ({}, False),
    ),
)
def test_dldd_fault_ownership_predicate(fault, expected):
    assert _is_dldd_fault(fault) is expected


def _json_field(record, field, expected_type):
    try:
        value = json.loads(record[field])
    except (KeyError, TypeError, ValueError) as error:
        pytest.fail("FAULT_INFO field {!r} is not valid JSON: {}".format(field, error))
    pytest_assert(
        isinstance(value, expected_type),
        "FAULT_INFO field {!r} must decode to {}, got {}".format(
            field, expected_type.__name__, type(value).__name__
        ),
    )
    return value


def _status_ttl(duthost):
    result = duthost.shell(
        "sonic-db-cli STATE_DB TTL {}".format(shlex.quote(STATUS_KEY)),
        module_ignore_errors=True,
    )
    if result["rc"] != 0:
        return -2
    try:
        return int(result["stdout"].strip())
    except (TypeError, ValueError):
        return -2


def _service_is_active(duthost):
    result = duthost.shell(
        "systemctl is-active dldd.service", module_ignore_errors=True
    )
    return result["rc"] == 0 and result["stdout"].strip() == "active"


def _systemd_property(duthost, unit, name):
    result = duthost.shell(
        "systemctl show {} --property {} --value".format(
            shlex.quote(unit), shlex.quote(name)
        ),
        module_ignore_errors=True,
    )
    pytest_assert(
        result["rc"] == 0,
        "Unable to read systemd property {} for {}: {}".format(
            name, unit, result.get("stderr", "")
        ),
    )
    return result["stdout"].strip()


def _status_is_published(duthost):
    return bool(_read_hash(duthost, "STATE_DB", STATUS_KEY))


def _require_enabled(capabilities):
    if capabilities["feature_state"] not in ENABLED_FEATURE_STATES:
        pytest.skip(
            "DLDD FEATURE state is {!r}".format(capabilities["feature_state"])
        )


def _require_rules(capabilities):
    if not capabilities["rules_present"]:
        pytest.skip(
            "Platform does not provide a packaged, golden, or active DLDD rules source"
        )


def _require_running(duthost, capabilities):
    _require_enabled(capabilities)
    pytest_assert(
        wait_until(
            DELAYED_FEATURE_START_TIMEOUT_SECONDS,
            2,
            0,
            _service_is_active,
            duthost,
        ),
        "DLDD FEATURE is enabled but dldd.service is not active",
    )
    pytest_assert(
        wait_until(60, 2, 0, _status_is_published, duthost),
        "DLDD did not publish {}".format(STATUS_KEY),
    )


def _service_pid(duthost):
    result = duthost.shell(
        "systemctl show dldd.service --property MainPID --value",
        module_ignore_errors=True,
    )
    if result["rc"] != 0:
        return 0
    try:
        return int(result["stdout"].strip())
    except (TypeError, ValueError):
        return 0


def _restart_service(duthost):
    pid_before = _service_pid(duthost)
    result = duthost.shell(
        "sudo systemctl restart dldd.service", module_ignore_errors=True
    )
    pytest_assert(
        result["rc"] == 0,
        "Unable to restart dldd.service: {}".format(result.get("stderr", "")),
    )
    pytest_assert(
        wait_until(60, 2, 0, _service_is_active, duthost),
        "dldd.service did not become active after restart",
    )
    pid_after = _service_pid(duthost)
    pytest_assert(
        pid_after > 0 and pid_after != pid_before,
        "dldd.service did not start a new process (PID before {}, after {})".format(
            pid_before, pid_after
        ),
    )
    pytest_assert(
        wait_until(60, 2, 0, _status_is_published, duthost),
        "DLDD did not republish {} after restart".format(STATUS_KEY),
    )
    pytest_assert(
        wait_until(
            15,
            1,
            0,
            lambda: _status_ttl(duthost) >= HEARTBEAT_TTL_SECONDS - 5,
        ),
        "DLDD did not refresh the status TTL after restart",
    )


@pytest.fixture(scope="module")
def dldd_capabilities(duthosts, enum_rand_one_per_hwsku_hostname):
    """Discover DLDD support without changing DUT configuration."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    feature = _read_hash(duthost, "CONFIG_DB", FEATURE_KEY)
    pytest_assert(feature, "The image does not advertise DLDD in the FEATURE table")

    feature_state = feature.get("state", "").lower()
    pytest_assert(
        feature_state in ENABLED_FEATURE_STATES + DISABLED_FEATURE_STATES,
        "Unexpected DLDD FEATURE state {!r}".format(feature_state),
    )

    platform = duthost.facts["platform"]
    platform_dir = "/usr/share/sonic/device/{}".format(platform)
    rules_path = "{}/dld_rules.yaml".format(platform_dir)
    golden_rules_path = "{}/dld_rules_golden.yaml".format(platform_dir)
    active_rules_path = "/var/lib/sonic/dldd/rules/dld_rules.active.yaml"
    dse_path = "{}/dld_dse.yaml".format(platform_dir)
    packaged_rules_present = duthost.stat(path=rules_path)["stat"].get(
        "exists", False
    )
    golden_rules_present = duthost.stat(path=golden_rules_path)["stat"].get(
        "exists", False
    )
    active_rules_present = duthost.stat(path=active_rules_path)["stat"].get(
        "exists", False
    )
    dse_present = duthost.stat(path=dse_path)["stat"].get("exists", False)

    validation_rules_path = next(
        (
            path
            for path, present in (
                (active_rules_path, active_rules_present),
                (rules_path, packaged_rules_present),
                (golden_rules_path, golden_rules_present),
            )
            if present
        ),
        None,
    )

    return {
        "feature": feature,
        "feature_state": feature_state,
        "platform_dir": platform_dir,
        "rules_path": rules_path,
        "packaged_rules_present": packaged_rules_present,
        "golden_rules_path": golden_rules_path,
        "golden_rules_present": golden_rules_present,
        "active_rules_path": active_rules_path,
        "active_rules_present": active_rules_present,
        "rules_present": bool(validation_rules_path),
        "validation_rules_path": validation_rules_path,
        "dse_path": dse_path,
        "dse_present": dse_present,
    }


def test_feature_and_service_state(
    duthosts, enum_rand_one_per_hwsku_hostname, dldd_capabilities
):
    """Verify FEATURE scope and the corresponding host-service state."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    feature = dldd_capabilities["feature"]

    pytest_assert(
        feature.get("has_global_scope", "").lower() == "true",
        "DLDD must be a global-scope FEATURE",
    )
    pytest_assert(
        feature.get("has_per_asic_scope", "").lower() == "false",
        "DLDD must not have per-ASIC scope",
    )
    pytest_assert(
        feature.get("auto_restart", "").lower() == "enabled",
        "DLDD must use SONiC feature auto-restart",
    )
    pytest_assert(
        feature.get("delayed", "").lower() == "true",
        "DLDD must start after delayed service initialization",
    )
    requires = _systemd_property(duthost, "dldd.service", "Requires").split()
    after = _systemd_property(duthost, "dldd.service", "After").split()
    pytest_assert(
        "database.service" in requires and "database.service" in after,
        "dldd.service must require and start after the SONiC database service",
    )
    pytest_assert(
        _systemd_property(duthost, "dldd-rules-watch.timer", "LoadState")
        == "loaded",
        "The DLDD rules watcher timer is not installed",
    )

    if dldd_capabilities["feature_state"] in ENABLED_FEATURE_STATES:
        _require_running(duthost, dldd_capabilities)
    else:
        pytest_assert(
            not _service_is_active(duthost),
            "DLDD FEATURE is disabled but dldd.service is active",
        )


def test_show_commands(
    duthosts, enum_rand_one_per_hwsku_hostname, dldd_capabilities
):
    """Verify the supported operator-facing configuration and status commands."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    _require_running(duthost, dldd_capabilities)

    config_result = duthost.shell("show dldd config", module_ignore_errors=True)
    pytest_assert(
        config_result["rc"] == 0,
        "'show dldd config' failed: {}".format(config_result.get("stderr", "")),
    )
    for expected in (
        "CONFIG_DB field",
        "Effective value",
        "Individual max failure threshold",
        "Redis monitor polling interval",
    ):
        pytest_assert(
            expected in config_result["stdout"],
            "'show dldd config' is missing {!r}".format(expected),
        )

    status_result = duthost.shell("show dldd status", module_ignore_errors=True)
    pytest_assert(
        status_result["rc"] == 0,
        "'show dldd status' failed: {}".format(status_result.get("stderr", "")),
    )
    for expected in (
        "Heartbeat age",
        "Running schema",
        "Active rules checksum",
        "Active rules source",
        "Activation result",
        "Activation fallback used",
        "Previous active rules checksum",
        "Local action default timeout",
    ):
        pytest_assert(
            expected in status_result["stdout"],
            "'show dldd status' is missing {!r}".format(expected),
        )

    config_help = duthost.shell(
        "config dldd --help", module_ignore_errors=True
    )
    pytest_assert(
        config_help["rc"] == 0,
        "'config dldd --help' failed: {}".format(
            config_help.get("stderr", "")
        ),
    )
    for expected in (
        "threshold",
        "polling-interval",
        "source-unavailable-grace-period",
        "source-recovery-samples",
        "inactive-fault-retention-period",
        "fault-evidence-ack-timeout",
        "active-fault-recheck-interval",
        "rules-inbox-settle-time",
    ):
        pytest_assert(
            expected in config_help["stdout"],
            "'config dldd --help' is missing {!r}".format(expected),
        )

    faults_result = duthost.shell("show dldd faults", module_ignore_errors=True)
    pytest_assert(
        faults_result["rc"] == 0,
        "'show dldd faults' failed: {}".format(faults_result.get("stderr", "")),
    )
    for expected in ("Component", "Symptom", "Status", "Occurrences"):
        pytest_assert(
            expected in faults_result["stdout"],
            "'show dldd faults' is missing {!r}".format(expected),
        )


def test_status_and_heartbeat(
    duthosts, enum_rand_one_per_hwsku_hostname, dldd_capabilities
):
    """Verify service-health telemetry and observe a heartbeat TTL refresh."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    _require_running(duthost, dldd_capabilities)

    status = _read_hash(duthost, "STATE_DB", STATUS_KEY)
    pytest_assert(status, "{} is absent".format(STATUS_KEY))
    pytest_assert(
        status.get("state") in SERVICE_HEALTH_STATES,
        "Invalid DLDD service state {!r}".format(status.get("state")),
    )
    for field in (
        "active_rules_source",
        "activation_result",
        "activation_fallback_used",
        "previous_active_rules_checksum",
    ):
        pytest_assert(field in status, "DLDD status is missing {!r}".format(field))
    running_schema = status.get("running_schema", "")
    active_rules_checksum = status.get("active_rules_checksum", "")
    active_rules_file = status.get("active_rules_file", "")
    if active_rules_file or active_rules_checksum or running_schema:
        pytest_assert(
            running_schema == "0.0.1",
            "Unexpected running schema {!r}".format(running_schema),
        )
        pytest_assert(
            active_rules_checksum.startswith("sha256:"),
            "DLDD did not publish an active rules checksum",
        )
        pytest_assert(
            active_rules_file,
            "DLDD did not publish its active rules file",
        )
        pytest_assert(
            duthost.stat(path=active_rules_file)["stat"].get("exists", False),
            "DLDD active rules file does not exist: {}".format(active_rules_file),
        )
    else:
        pytest_assert(
            status.get("state") == "BROKEN|FATAL" and status.get("reason"),
            "DLDD without an active generation must publish BROKEN|FATAL with a reason",
        )
    for field in (
        "broken_rules",
        "source_status",
        "inflight_fault_evidence",
        "service_diagnostics",
    ):
        _json_field(status, field, list)
    for field, minimum in CONFIG_FIELD_MINIMUMS.items():
        try:
            value = int(status[field])
        except (KeyError, TypeError, ValueError) as error:
            pytest.fail("DLDD status field {!r} is not an integer: {}".format(field, error))
        pytest_assert(
            minimum <= value <= UINT32_MAX,
            "DLDD status field {!r} is outside its valid range: {}".format(
                field, value
            ),
        )

    initial_ttl = _status_ttl(duthost)
    pytest_assert(
        0 < initial_ttl <= HEARTBEAT_TTL_SECONDS,
        "{} has invalid TTL {}".format(STATUS_KEY, initial_ttl),
    )

    observed = {"previous": initial_ttl}

    def heartbeat_refreshed():
        current = _status_ttl(duthost)
        refreshed = current > observed["previous"]
        observed["previous"] = current
        return refreshed

    pytest_assert(
        wait_until(
            HEARTBEAT_REFRESH_SECONDS + 15,
            3,
            0,
            heartbeat_refreshed,
        ),
        "{} TTL was not refreshed within {} seconds".format(
            STATUS_KEY, HEARTBEAT_REFRESH_SECONDS + 15
        ),
    )


def test_healthy_no_fault_baseline(
    duthosts, enum_rand_one_per_hwsku_hostname, dldd_capabilities
):
    """Require installed vendor rules to run cleanly on a healthy platform."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    _require_rules(dldd_capabilities)
    _require_running(duthost, dldd_capabilities)
    status = _read_hash(duthost, "STATE_DB", STATUS_KEY)
    broken_rules = _json_field(status, "broken_rules", list)

    pytest_assert(
        status.get("state") == "OK",
        "DLDD is not healthy: state={!r}, reason={!r}".format(
            status.get("state"), status.get("reason")
        ),
    )
    pytest_assert(
        not broken_rules,
        "Packaged DLDD rules contain broken runtime entries: {}".format(broken_rules),
    )

    active_faults = {
        key: fault
        for key, fault in _faults(duthost).items()
        if fault.get("status") == "ACTIVE"
    }
    pytest_assert(
        not active_faults,
        "Healthy platform has active DLDD faults: {}".format(sorted(active_faults)),
    )


def test_fault_info_shape_if_present(
    duthosts, enum_rand_one_per_hwsku_hostname, dldd_capabilities
):
    """Validate every live or retained DLDD fault against the HLD payload shape."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    _require_running(duthost, dldd_capabilities)

    for key, fault in _faults(duthost).items():
        missing = FAULT_REQUIRED_FIELDS - set(fault)
        pytest_assert(
            not missing,
            "{} is missing required fields {}".format(key, sorted(missing)),
        )

        component_info = _json_field(fault, "component_info", dict)
        events = _json_field(fault, "events", list)
        repair_actions = _json_field(fault, "repair_actions", list)
        _json_field(fault, "actions_taken", list)
        local_action_state = _json_field(fault, "local_action_state", dict)
        if "healthz_artifact" in fault:
            artifact = _json_field(fault, "healthz_artifact", dict)
            pytest_assert(
                artifact.get("state") in ("REQUESTED", "RUNNING", "COMPLETED", "FAILED"),
                "{} has invalid Healthz artifact metadata: {}".format(key, artifact),
            )

        pytest_assert(
            {"component", "name", "serial_number"}.issubset(component_info),
            "{} has incomplete component_info".format(key),
        )
        expected_key = "FAULT_INFO|{}|{}".format(
            quote(component_info["name"], safe=""),
            quote(fault["symptom"], safe=""),
        )
        pytest_assert(
            key == expected_key,
            "FAULT_INFO key {!r} does not match canonical key {!r}".format(
                key, expected_key
            ),
        )
        pytest_assert(events, "{} has no triggering events".format(key))
        if fault["status"] == "ACTIVE":
            pytest_assert(
                repair_actions,
                "{} has no controller-visible remediation actions".format(key),
            )
        for event in events:
            pytest_assert(
                isinstance(event, dict)
                and {"id", "value_read", "value_configs", "condition"}.issubset(event),
                "{} contains an incomplete event: {}".format(key, event),
            )
            value_configs = event["value_configs"]
            condition = event["condition"]
            pytest_assert(
                isinstance(value_configs, dict)
                and {"type", "unit", "scaling", "encoding"}.issubset(value_configs)
                and value_configs["type"] in VALUE_CONFIG_TYPES,
                "{} contains invalid event value metadata: {}".format(key, event),
            )
            pytest_assert(
                isinstance(condition, dict)
                and {"type", "value", "value_configs"}.issubset(condition)
                and condition["type"] in EVALUATOR_TYPES,
                "{} contains an invalid event condition: {}".format(key, event),
            )
            condition_value_configs = condition["value_configs"]
            pytest_assert(
                isinstance(condition_value_configs, dict)
                and {"type", "unit", "scaling", "encoding"}.issubset(
                    condition_value_configs
                )
                and condition_value_configs["type"] in VALUE_CONFIG_TYPES,
                "{} contains invalid condition value metadata: {}".format(
                    key, event
                ),
            )
        for action in repair_actions:
            pytest_assert(
                isinstance(action, dict)
                and action.get("action") in REPAIR_ACTIONS,
                "{} contains an invalid repair action: {}".format(key, action),
            )
        pytest_assert(
            local_action_state.get("state") in LOCAL_ACTION_STATES,
            "{} has invalid local action state: {}".format(key, local_action_state),
        )
        pytest_assert(
            fault["status"] in FAULT_STATUSES,
            "{} has invalid status {!r}".format(key, fault["status"]),
        )
        pytest_assert(
            fault["severity"] in FAULT_SEVERITIES,
            "{} has invalid severity {!r}".format(key, fault["severity"]),
        )
        pytest_assert(
            int(fault["occurrences"]) >= 1,
            "{} has invalid occurrence count {!r}".format(key, fault["occurrences"]),
        )
        pytest_assert(
            int(fault["remote_action_time_window"]) > 0,
            "{} has invalid remote action time window {!r}".format(
                key, fault["remote_action_time_window"]
            ),
        )
        pytest_assert(
            float(fault["origin_time"]) > 0
            and float(fault["last_detection_time"]) >= float(fault["origin_time"]),
            "{} has invalid fault timestamps".format(key),
        )


def test_available_rules_validation(
    duthosts, enum_rand_one_per_hwsku_hostname, dldd_capabilities
):
    """Run the non-executing activation gate against an installed rules source."""
    _require_rules(dldd_capabilities)
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    command = [
        "sudo",
        "dldd",
        "validate-rules",
        "--file",
        dldd_capabilities["validation_rules_path"],
        "--platform-dir",
        dldd_capabilities["platform_dir"],
        "--mode",
        "activation-dry-run",
        "--json",
    ]
    if dldd_capabilities["dse_present"]:
        command.extend(("--dse", dldd_capabilities["dse_path"]))

    result = duthost.shell(
        " ".join(shlex.quote(item) for item in command), module_ignore_errors=True
    )
    pytest_assert(
        result["rc"] == 0,
        "DLDD rules source failed validation: stdout={!r}, stderr={!r}".format(
            result.get("stdout", ""), result.get("stderr", "")
        ),
    )
    try:
        validation = json.loads(result["stdout"])
    except (TypeError, ValueError) as error:
        pytest.fail("DLDD validator did not return valid JSON: {}".format(error))

    pytest_assert(validation.get("schema_version") == "0.0.1")
    pytest_assert(validation.get("file_level_result") == "PASSED")
    pytest_assert(validation.get("rules_parsed_successfully", 0) > 0)
    pytest_assert(validation.get("rule_level_result") == "PASSED")
    pytest_assert(
        validation.get("rules_failed_validation") == 0,
        "Installed rules contain platform materialization failures: {}".format(
            validation.get("broken_rules", [])
        ),
    )


def test_service_restart_without_active_faults(
    duthosts, enum_rand_one_per_hwsku_hostname, dldd_capabilities
):
    """Restart DLDD only when no active fault/action can make it disruptive."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    _require_running(duthost, dldd_capabilities)
    status_before = _read_hash(duthost, "STATE_DB", STATUS_KEY)
    active_before = {
        key: fault
        for key, fault in _faults(duthost).items()
        if fault.get("status") == "ACTIVE"
    }
    inflight = _json_field(status_before, "inflight_fault_evidence", list)
    if active_before or inflight:
        pytest.skip("DLDD has active/in-flight fault work; use reconciliation coverage")

    try:
        _restart_service(duthost)
        status_after = _read_hash(duthost, "STATE_DB", STATUS_KEY)
        pytest_assert(
            status_after.get("active_rules_checksum")
            == status_before.get("active_rules_checksum"),
            "DLDD changed rules generation during a service-only restart",
        )
        active_after = {
            key: fault
            for key, fault in _faults(duthost).items()
            if fault.get("status") == "ACTIVE"
        }
        pytest_assert(
            not active_after,
            "DLDD published active faults solely because it restarted: {}".format(
                sorted(active_after)
            ),
        )
    finally:
        if not _service_is_active(duthost):
            duthost.shell("sudo systemctl start dldd.service", module_ignore_errors=True)


def test_active_fault_reconciliation(
    duthosts, enum_rand_one_per_hwsku_hostname, dldd_capabilities
):
    """Verify existing active records are reconciled without a new fault lifetime."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    _require_running(duthost, dldd_capabilities)
    status_before = _read_hash(duthost, "STATE_DB", STATUS_KEY)
    active_before = {
        key: fault
        for key, fault in _faults(duthost).items()
        if fault.get("status") == "ACTIVE"
        and fault.get("active_rules_checksum")
        == status_before.get("active_rules_checksum")
    }
    if not active_before:
        pytest.skip("No current-generation active fault is available for reconciliation")

    expected_reconciliations = {
        (
            int(fault["rule_id"]),
            _json_field(fault, "component_info", dict)["name"],
        )
        for fault in active_before.values()
    }

    def reconciliation_completed():
        status = _read_hash(duthost, "STATE_DB", STATUS_KEY)
        try:
            diagnostics = json.loads(status.get("service_diagnostics", "[]"))
        except (TypeError, ValueError):
            return False
        completed = {
            (int(item.get("rule_id", 0)), item.get("component", ""))
            for item in diagnostics
            if isinstance(item, dict)
            and item.get("reason")
            == "bootstrap_fault_reconciliation_complete"
        }
        return expected_reconciliations.issubset(completed)

    try:
        _restart_service(duthost)
        pytest_assert(
            wait_until(90, 2, 0, reconciliation_completed),
            "DLDD did not report completion of bootstrap active-fault rechecks",
        )
        for key, before in active_before.items():
            after = _read_hash(duthost, "STATE_DB", key)
            pytest_assert(after, "DLDD deleted active fault {} during restart".format(key))
            pytest_assert(
                after.get("status") in ("ACTIVE", "INACTIVE"),
                "DLDD did not reconcile {} to a valid state".format(key),
            )
            pytest_assert(
                after.get("rule_id") == before.get("rule_id")
                and after.get("origin_time") == before.get("origin_time")
                and after.get("occurrences") == before.get("occurrences"),
                "DLDD created a duplicate fault lifetime while reconciling {}".format(key),
            )
    finally:
        if not _service_is_active(duthost):
            duthost.shell("sudo systemctl start dldd.service", module_ignore_errors=True)
