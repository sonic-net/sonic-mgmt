"""Platform qualification for the device-local diagnosis daemon (DLDD).

The tests intentionally use only the installed rules and live telemetry.  They
do not inject hardware faults or run the optional ``hardware-probe`` mode.  The
``e2e-execute`` test performs the documented non-remediating, single-pass rule
qualification, including runtime DSE expansion when the installed rules define it.
"""

import json
import shlex

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

ENABLED_FEATURE_STATES = ("enabled",)
DISABLED_FEATURE_STATES = ("disabled",)
SERVICE_HEALTH_STATES = ("OK", "DEGRADED", "BROKEN|FATAL")


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
        if fault.get("producer") == "dldd":
            faults[key] = fault
    return faults


def _operator_faults(duthost):
    result = duthost.shell(
        "show dldd faults --json", module_ignore_errors=True
    )
    pytest_assert(
        result["rc"] == 0,
        "'show dldd faults --json' failed: {}".format(result.get("stderr", "")),
    )
    try:
        faults = json.loads(result["stdout"])
    except (TypeError, ValueError) as error:
        pytest.fail("'show dldd faults --json' returned invalid JSON: {}".format(error))
    pytest_assert(
        isinstance(faults, list) and all(isinstance(fault, dict) for fault in faults),
        "'show dldd faults --json' must return a list of objects",
    )
    return faults


def _observed_faults(duthost):
    """Validate the live raw-to-operator DLDD fault projection."""

    raw_faults = _faults(duthost)
    operator_faults = _operator_faults(duthost)
    fields = ("component_name", "symptom", "status")
    raw_identities = {
        (key,) + tuple(fault.get(field) for field in fields)
        for key, fault in raw_faults.items()
    }
    operator_identities = {
        (fault.get("redis_key"),) + tuple(fault.get(field) for field in fields)
        for fault in operator_faults
    }
    pytest_assert(
        len(operator_faults) == len(raw_identities)
        and operator_identities == raw_identities,
        "Operator fault JSON does not match observed DLDD-owned rows",
    )
    return raw_faults


def _json_field(record, field, expected_type):
    try:
        value = json.loads(record[field])
    except (KeyError, TypeError, ValueError) as error:
        pytest.fail("DLDD telemetry field {!r} is not valid JSON: {}".format(field, error))
    pytest_assert(
        isinstance(value, expected_type),
        "DLDD telemetry field {!r} must decode to {}, got {}".format(
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


def _validation_rules_path(
    duthost, capabilities, required=True, allow_candidates=False
):
    selected = _read_hash(duthost, "STATE_DB", STATUS_KEY).get(
        "active_rules_file"
    )
    paths = (selected,) + (capabilities["rules_paths"] if allow_candidates else ())
    for path in dict.fromkeys(paths):
        if path and duthost.stat(path=path)["stat"].get("exists", False):
            return path
    if required:
        pytest.fail("DLDD did not publish an existing selected rules file")
    return None


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


def _rule_source_events(document):
    """Return every source-event identity and whether it uses DSE."""
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
            sources.append(
                {
                    "rule": metadata.get("name"),
                    "rule_id": metadata.get("id"),
                    "event_id": event.get("id"),
                    "dse": event_type == "dse"
                    or (
                        event_type == "platform_api"
                        and isinstance(event.get("path"), str)
                    ),
                }
            )
    return sources


def _require_running(duthost, capabilities):
    _require_enabled(capabilities)
    if (
        not _service_is_active(duthost)
        and _validation_rules_path(
            duthost, capabilities, required=False, allow_candidates=True
        ) is None
    ):
        pytest.skip("DLDD is enabled but no rules candidate is installed")
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
    inbox_rules_path = "/var/lib/sonic/dldd/inbox/dld_rules.yaml"
    active_rules_path = "/var/lib/sonic/dldd/rules/dld_rules.active.yaml"
    manifest = duthost.shell(
        "sudo cat -- /var/lib/sonic/dldd/rules/activation.json",
        module_ignore_errors=True,
    )
    try:
        previous_rules_path = json.loads(manifest.get("stdout", "")).get(
            "previous_active_generation_path"
        )
    except (AttributeError, TypeError, ValueError):
        previous_rules_path = None
    dse_path = "{}/dld_dse.yaml".format(platform_dir)
    dse_present = duthost.stat(path=dse_path)["stat"].get("exists", False)

    return {
        "feature": feature,
        "feature_state": feature_state,
        "platform_dir": platform_dir,
        "rules_paths": (
            inbox_rules_path,
            active_rules_path,
            previous_rules_path,
            rules_path,
            golden_rules_path,
        ),
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
        if _validation_rules_path(
            duthost,
            dldd_capabilities,
            required=False,
            allow_candidates=True,
        ) is None:
            pytest_assert(
                not _service_is_active(duthost),
                "DLDD has no rules candidate but dldd.service is active",
            )
            pytest_assert(
                _systemd_property(duthost, "dldd.service", "ExecMainStatus") == "0",
                "DLDD without rules did not exit successfully",
            )
        else:
            _require_running(duthost, dldd_capabilities)
    else:
        pytest_assert(
            not _service_is_active(duthost),
            "DLDD FEATURE is disabled but dldd.service is active",
        )


def test_operator_commands_smoke(
    duthosts, enum_rand_one_per_hwsku_hostname, dldd_capabilities
):
    """Smoke-test the installed read-only operator commands."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    _require_running(duthost, dldd_capabilities)

    commands = (
        (
            "show dldd config",
            "CONFIG_DB field|Effective value|Individual max failure threshold|"
            "Redis monitor polling interval".split("|"),
            (), None,
        ),
        (
            "show dldd status",
            "State|Heartbeat age|Activation|Rules source".split("|"),
            ("Running schema", "Active rules checksum", "Reason"), 3,
        ),
        (
            "show dldd status --detail",
            "Heartbeat age|Running schema|Active rules checksum|Active rules source|"
            "Activation result|Activation fallback used|Previous active rules checksum|"
            "Local action default timeout".split("|"),
            (), None,
        ),
        (
            "show dldd rules",
            ("Rule ID", "Rule", "Component", "Health", "Active faults"),
            ("Version", "Work items", "Last attempt", "Reason"), None,
        ),
        (
            "show dldd faults",
            ("Component", "Symptom", "Status", "Severity", "Last detection"),
            ("Rule", "Occurrences", "Reason", "Description"), None,
        ),
        (
            "config dldd --help",
            "threshold|polling-interval|source-unavailable-grace-period|"
            "source-recovery-samples|inactive-fault-retention-period|"
            "fault-evidence-ack-timeout|active-fault-recheck-interval|"
            "rules-inbox-settle-time".split("|"),
            (), None,
        ),
    )
    for command, required_text, forbidden_headers, expected_lines in commands:
        result = duthost.shell(command, module_ignore_errors=True)
        output = result.get("stdout", "")
        lines = [line for line in output.splitlines() if line.strip()]
        header = lines[0] if lines else ""
        pytest_assert(
            result["rc"] == 0
            and lines
            and all(text in output for text in required_text)
            and not any(text in header for text in forbidden_headers)
            and (expected_lines is None or len(lines) == expected_lines),
            "{!r} failed or omitted required output: {}".format(
                command, result.get("stderr", ""),
            ),
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
    initial_ttl = _status_ttl(duthost)
    pytest_assert(
        0 < initial_ttl <= HEARTBEAT_TTL_SECONDS,
        "{} has invalid TTL {}".format(STATUS_KEY, initial_ttl),
    )

    observed = {"previous": initial_ttl}

    def heartbeat_refreshed():
        current = _status_ttl(duthost)
        if current <= 0:
            return False
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


def test_installed_rules_health_and_observed_faults(
    duthosts, enum_rand_one_per_hwsku_hostname, dldd_capabilities
):
    """Check installed rules and operator-visible DLDD-owned fault identity."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    _require_running(duthost, dldd_capabilities)
    _validation_rules_path(duthost, dldd_capabilities)
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

    raw_faults = _observed_faults(duthost)
    active_faults = {
        key: fault
        for key, fault in raw_faults.items()
        if fault.get("status") == "ACTIVE"
    }
    pytest_assert(
        not active_faults,
        "Healthy platform has active DLDD faults: {}".format(sorted(active_faults)),
    )


def test_installed_rules_activation_dry_run(
    duthosts, enum_rand_one_per_hwsku_hostname, dldd_capabilities
):
    """Run the non-executing activation gate against an installed rules source."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    _require_running(duthost, dldd_capabilities)
    rules_path = _validation_rules_path(duthost, dldd_capabilities)

    command = [
        "sudo",
        "dldd",
        "validate-rules",
        "--file",
        rules_path,
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


def test_rules_e2e_execution(
    duthosts, enum_rand_one_per_hwsku_hostname, dldd_capabilities
):
    """Execute every installed direct and DSE source without remediation."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    _require_running(duthost, dldd_capabilities)
    rules_path = _validation_rules_path(duthost, dldd_capabilities)
    rules = _load_rules_document(duthost, rules_path)
    source_events = _rule_source_events(rules)

    command = [
        "sudo",
        "dldd",
        "validate-rules",
        "--file",
        rules_path,
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
    pytest_assert(
        len(rule_result_by_instance) == len(rule_results),
        "DLDD e2e qualification returned duplicate rule results",
    )
    executions_by_event = {}
    execution_keys = []
    for item in probe_results:
        if item.get("stage") == "execution":
            execution_keys.append(item.get("correlation_key"))
            executions_by_event.setdefault(
                (item.get("rule_id"), item.get("event_id")), []
            ).append(item)
    pytest_assert(
        None not in execution_keys and len(execution_keys) == len(set(execution_keys)),
        "DLDD e2e qualification returned missing or duplicate execution identity",
    )
    for source in source_events:
        identity = (source["rule_id"], source["event_id"])
        executions = executions_by_event.get(identity, ())
        pytest_assert(
            executions,
            "Source event {}:{} was not executed".format(
                source["rule"], source["event_id"]
            ),
        )
        for execution in executions:
            pytest_assert(
                execution.get("state") in ("MATCH", "NO_MATCH"),
                "Source event execution was not qualified: {}".format(execution),
            )
            rule_result = rule_result_by_instance.get(
                (source["rule_id"], execution["component"])
            )
            pytest_assert(
                rule_result is not None
                and rule_result.get("state") in ("MATCH", "NO_MATCH"),
                "Source instance has no qualified rule result: {}".format(execution),
            )
        if not source["dse"]:
            continue
        expansion = expansion_by_event.get(identity)
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
                and len(components) == expansion["instance_count"],
                "DSE event {}:{} did not execute every discovered component: {}".format(
                    source["rule"], source["event_id"], executions
                ),
            )
