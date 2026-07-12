"""Platform qualification for the device-local diagnosis daemon (DLDD).

The tests intentionally use only the installed rules and live telemetry.  They
do not inject hardware faults or run the optional ``hardware-probe`` mode.  The
``e2e-execute`` test performs the documented non-remediating, single-pass rule
qualification, including runtime DSE expansion when the fixture defines it.
"""

import json
import shlex
from urllib.parse import quote

import pytest
import yaml

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
FAULT_STATUSES = ("ACTIVE", "INACTIVE")
FAULT_SEVERITIES = ("CRITICAL", "MAJOR", "WARNING", "MINOR", "UNKNOWN")
LOCAL_ACTION_STATES = ("IDLE", "COMPLETED", "FAILED")
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
    "producer",
    "rule",
    "rule_id",
    "rule_version",
    "schema_version",
    "active_rules_checksum",
    "component_type",
    "component_name",
    "component_serial_number",
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
    "reason",
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
    return fault.get("producer") == "dldd"


@pytest.mark.parametrize(
    "fault,expected",
    (
        (
            {
                "producer": "dldd",
                "rule_id": "1000001",
                "rule": "PSU_OV_FAULT",
                "schema_version": "0.0.1",
                "active_rules_checksum": "sha256:test",
            },
            True,
        ),
        ({"producer": "another-agent", "rule_id": "1000001"}, False),
        (
            {
                "rule_id": "1000001",
                "rule": "lookalike",
                "schema_version": "0.0.1",
                "active_rules_checksum": "sha256:lookalike",
            },
            False,
        ),
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


def _validate_fault_info(key, fault):
    """Validate one raw DLDD FAULT_INFO row against the published contract."""
    missing = FAULT_REQUIRED_FIELDS - set(fault)
    pytest_assert(
        not missing,
        "{} is missing required fields {}".format(key, sorted(missing)),
    )
    pytest_assert(
        fault["producer"] == "dldd",
        "{} has invalid producer {!r}".format(key, fault["producer"]),
    )
    component_type = fault["component_type"]
    component_name = fault["component_name"]
    component_serial = fault["component_serial_number"]
    pytest_assert(
        isinstance(component_type, str)
        and bool(component_type.strip())
        and isinstance(component_name, str)
        and bool(component_name.strip())
        and isinstance(component_serial, str),
        "{} has invalid component identity fields".format(key),
    )
    pytest_assert(
        int(fault["rule_id"]) > 0,
        "{} has invalid rule ID {!r}".format(key, fault["rule_id"]),
    )
    pytest_assert(
        isinstance(fault["reason"], str)
        and len(fault["reason"].encode("utf-8")) <= 512,
        "{} has invalid bounded reason {!r}".format(key, fault["reason"]),
    )

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

    expected_key = "FAULT_INFO|{}|{}".format(
        quote(component_name, safe=""),
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
            "{} contains invalid condition value metadata: {}".format(key, event),
        )
    for action in repair_actions:
        action_name = action.get("action") if isinstance(action, dict) else None
        pytest_assert(
            isinstance(action_name, str) and bool(action_name.strip()),
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


def _valid_fault_fixture():
    value_configs = {
        "type": "float",
        "unit": "celsius",
        "scaling": "N/A",
        "encoding": "N/A",
    }
    return {
        "producer": "dldd",
        "rule": "TEMPERATURE_HIGH",
        "rule_id": "1000001",
        "rule_version": "1.0.0",
        "schema_version": "0.0.1",
        "active_rules_checksum": "sha256:test",
        "component_type": "TEMPERATURE_SENSOR",
        "component_name": "SENSOR 0",
        "component_serial_number": "",
        "error_type": "THERMAL",
        "events": json.dumps([
            {
                "id": 1,
                "value_read": "91.0",
                "value_configs": value_configs,
                "condition": {
                    "type": "comparison",
                    "value": 90.0,
                    "value_configs": value_configs,
                },
            }
        ]),
        "remote_action_time_window": "3600",
        "repair_actions": json.dumps([
            {"action": "vendor-healthz:ACTION_REPAIR_FABRIC_MODULE"}
        ]),
        "actions_taken": "[]",
        "local_action_state": json.dumps({
            "state": "IDLE",
            "action_suppressed": False,
        }),
        "severity": "WARNING",
        "symptom": "SYMPTOM_OVER_THRESHOLD",
        "status": "ACTIVE",
        "origin_time": "1745614200",
        "last_detection_time": "1745614266",
        "occurrences": "1",
        "reason": "",
        "description": "Temperature exceeded its high threshold.",
    }


def test_fault_info_contract_fixture_supports_flat_components_and_vendor_action():
    fault = _valid_fault_fixture()
    key = "FAULT_INFO|SENSOR%200|SYMPTOM_OVER_THRESHOLD"
    _validate_fault_info(key, fault)


def test_fault_info_contract_rejects_unbounded_transition_reason():
    fault = _valid_fault_fixture()
    fault["reason"] = "x" * 513

    with pytest.raises(AssertionError, match="invalid bounded reason"):
        _validate_fault_info(
            "FAULT_INFO|SENSOR%200|SYMPTOM_OVER_THRESHOLD", fault
        )


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


def _load_rules_document(duthost, path):
    result = duthost.shell(
        "sudo cat -- {}".format(shlex.quote(path)), module_ignore_errors=True
    )
    pytest_assert(
        result["rc"] == 0,
        "Unable to read installed DLDD rules {}: {}".format(
            path, result.get("stderr", "")
        ),
    )
    try:
        document = yaml.safe_load(result["stdout"])
    except yaml.YAMLError as error:
        pytest.fail("Installed DLDD rules are not valid YAML: {}".format(error))
    pytest_assert(
        isinstance(document, dict),
        "Installed DLDD rules must contain a YAML mapping",
    )
    return document


def _dse_source_events(document):
    """Return the identities of DSE source events in a validated rules file."""
    signatures = document.get("signatures", ())
    pytest_assert(
        isinstance(signatures, list),
        "Installed DLDD rules must contain a signatures list",
    )
    sources = []
    for wrapped_signature in signatures:
        pytest_assert(
            isinstance(wrapped_signature, dict)
            and isinstance(wrapped_signature.get("signature"), dict),
            "Installed DLDD rules contain an invalid signature wrapper",
        )
        signature = wrapped_signature["signature"]
        metadata = signature.get("metadata", {})
        conditions = signature.get("conditions", {})
        events = conditions.get("events", ()) if isinstance(conditions, dict) else ()
        for wrapped_event in events:
            if not isinstance(wrapped_event, dict):
                continue
            event = wrapped_event.get("event")
            if not isinstance(event, dict):
                continue
            event_type = event.get("type")
            if event_type != "dse" and not (
                event_type == "platform_api" and isinstance(event.get("path"), str)
            ):
                continue
            sources.append(
                {
                    "rule": metadata.get("name"),
                    "rule_id": metadata.get("id"),
                    "event_id": event.get("id"),
                }
            )
    return sources


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
        _validate_fault_info(key, fault)


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


def test_dse_rules_e2e_execution(
    duthosts, enum_rand_one_per_hwsku_hostname, dldd_capabilities
):
    """Expand and execute every installed DSE source event without remediation."""
    _require_rules(dldd_capabilities)
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    rules = _load_rules_document(
        duthost, dldd_capabilities["validation_rules_path"]
    )
    dse_sources = _dse_source_events(rules)
    if not dse_sources:
        pytest.skip("Active DLDD rules contain no DSE-backed source event")

    command = [
        "sudo",
        "dldd",
        "validate-rules",
        "--file",
        dldd_capabilities["validation_rules_path"],
        "--platform-dir",
        dldd_capabilities["platform_dir"],
        "--mode",
        "e2e-execute",
        "--json",
    ]
    if dldd_capabilities["dse_present"]:
        command.extend(("--dse", dldd_capabilities["dse_path"]))

    result = duthost.shell(
        " ".join(shlex.quote(item) for item in command), module_ignore_errors=True
    )
    try:
        qualification = json.loads(result["stdout"])
    except (TypeError, ValueError) as error:
        pytest.fail(
            "DLDD e2e qualification did not return valid JSON: {}; stdout={!r}, "
            "stderr={!r}".format(
                error, result.get("stdout", ""), result.get("stderr", "")
            )
        )

    pytest_assert(
        result["rc"] == 0 and qualification.get("qualification_result") == "PASSED",
        "DLDD e2e qualification failed: stdout={!r}, stderr={!r}".format(
            result.get("stdout", ""), result.get("stderr", "")
        ),
    )
    probe_results = qualification.get("probe_results", ())
    rule_results = qualification.get("rule_results", ())
    pytest_assert(
        isinstance(probe_results, list) and isinstance(rule_results, list),
        "DLDD e2e qualification omitted event or rule results",
    )

    expansion_by_event = {
        (item.get("rule_id"), item.get("event_id")): item
        for item in probe_results
        if item.get("stage") == "expansion"
    }
    rule_result_by_instance = {
        (item.get("rule_id"), item.get("component")): item
        for item in rule_results
    }
    for source in dse_sources:
        identity = (source["rule_id"], source["event_id"])
        expansion = expansion_by_event.get(identity)
        executions = [
            item
            for item in probe_results
            if item.get("stage") == "execution"
            and (item.get("rule_id"), item.get("event_id")) == identity
        ]
        components = {item.get("component") for item in executions}
        if expansion is None:
            # A vendor may resolve a DSE reference to one or more direct typed
            # sources.  Those have no runtime template to expand but must still
            # complete the same live event/rule qualification.
            pytest_assert(
                executions and None not in components,
                "Directly resolved DSE event {}:{} was not executed: {}".format(
                    source["rule"], source["event_id"], executions
                ),
            )
        else:
            pytest_assert(
                expansion.get("state") == "EXPANDED"
                and expansion.get("instance_count", 0) > 0,
                "DSE event {}:{} did not discover usable instances: {}".format(
                    source["rule"], source["event_id"], expansion
                ),
            )
            pytest_assert(
                None not in components
                and len(components) == expansion["instance_count"]
                and len(executions) == expansion["instance_count"],
                "DSE event {}:{} did not execute exactly once per discovered "
                "instance: {}".format(
                    source["rule"], source["event_id"], executions
                ),
            )
        for execution in executions:
            pytest_assert(
                execution.get("state") in ("MATCH", "NO_MATCH"),
                "DSE event execution was not qualified: {}".format(execution),
            )
            rule_result = rule_result_by_instance.get(
                (source["rule_id"], execution["component"])
            )
            pytest_assert(
                rule_result is not None
                and rule_result.get("state") in ("MATCH", "NO_MATCH"),
                "DSE instance has no qualified rule result: {}".format(execution),
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
        pytest.skip("DLDD has active/in-flight fault work; use active-fault restart coverage")

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


def test_active_fault_restart_preserves_lifetime(
    duthosts, enum_rand_one_per_hwsku_hostname, dldd_capabilities
):
    """Verify restart preserves current active records without a new lifetime."""
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
        pytest.skip("No current-generation active fault is available for restart coverage")

    def fault_rows_restored():
        status = _read_hash(duthost, "STATE_DB", STATUS_KEY)
        if (
            status.get("active_rules_checksum")
            != status_before.get("active_rules_checksum")
        ):
            return False
        for key in active_before:
            fault = _read_hash(duthost, "STATE_DB", key)
            if (
                fault.get("producer") != "dldd"
                or fault.get("status") not in FAULT_STATUSES
            ):
                return False
        return True

    try:
        _restart_service(duthost)
        pytest_assert(
            wait_until(30, 2, 0, fault_rows_restored),
            "DLDD did not restore current-generation active fault state after restart",
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
