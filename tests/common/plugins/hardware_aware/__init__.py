"""Hardware-aware collection recommendations and deselection.

This plugin is intentionally disabled by default. When enabled, it evaluates
collected pytest items against normalized test capabilities. It can either
write a JSON report or deselect unsupported tests during collection.
"""

import importlib.util
import json
import logging
import os
import re
from collections import Counter, defaultdict
from pathlib import Path

import pytest
import yaml


logger = logging.getLogger(__name__)

DEFAULT_RUN_CONTEXT_FILE = "hardware_aware/run_context.yaml"
DEFAULT_TEST_CAPABILITIES_FILE = "hardware_aware/test_capabilities.yaml"
DEFAULT_CATALOG_FILE = "hardware_aware/skip_rules.yaml"
DEFAULT_SETUP_PROFILES_FILE = "hardware_aware/setup_profiles.yaml"
DEFAULT_RUNTIME_INPUTS_GENERATOR = "hardware_aware/generate_runtime_inputs.py"
DEFAULT_REPORT_PATH = "hardware_aware/pytest_collection_hardware_aware_report.json"
CONFIDENCE_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
}
TOPOLOGY_MARKER_EVALUATION_MODES = (
    "topology_marker",
    "topology_marker_intersects_available_tags",
)


def pytest_addoption(parser):
    group = parser.getgroup("hardware-aware")
    group.addoption(
        "--hardware-aware-report-only",
        action="store_true",
        default=False,
        help=(
            "Evaluate hardware-aware test capabilities during collection "
            "and write a report without deselecting tests."
        ),
    )
    group.addoption(
        "--hardware-aware-deselect",
        action="store_true",
        default=False,
        help=(
            "Deselect tests that do not satisfy hardware-aware test capabilities "
            "during collection and write a report."
        ),
    )
    group.addoption(
        "--hardware-aware-run-context-file",
        "--hardware-aware-capabilities-file",
        action="store",
        dest="hardware_aware_run_context_file",
        default=DEFAULT_RUN_CONTEXT_FILE,
        help=(
            "YAML or JSON file containing the current run context. "
            "--hardware-aware-capabilities-file is accepted as a backward-compatible alias."
        ),
    )
    group.addoption(
        "--hardware-aware-test-capabilities-file",
        "--hardware-aware-requirements-file",
        action="store",
        dest="hardware_aware_test_capabilities_file",
        default=DEFAULT_TEST_CAPABILITIES_FILE,
        help=(
            "YAML or JSON file containing hardware-aware test capability rules. "
            "--hardware-aware-requirements-file is accepted as a backward-compatible alias."
        ),
    )
    group.addoption(
        "--hardware-aware-catalog-file",
        "--hardware-aware-catalog",
        action="store",
        dest="hardware_aware_catalog_file",
        default=DEFAULT_CATALOG_FILE,
        help=(
            "YAML skip-rule catalog used with --hardware-aware-setup or "
            "--hardware-aware-setup-input."
        ),
    )
    group.addoption(
        "--hardware-aware-setup-profiles-file",
        "--hardware-aware-setup-profiles",
        action="store",
        dest="hardware_aware_setup_profiles_file",
        default=DEFAULT_SETUP_PROFILES_FILE,
        help=(
            "YAML setup profiles used with --hardware-aware-setup or "
            "--hardware-aware-setup-input."
        ),
    )
    group.addoption(
        "--hardware-aware-setup",
        action="store",
        help=(
            "Setup key or alias from setup profiles. When provided, the plugin "
            "generates run context and test capabilities from the YAML catalog."
        ),
    )
    group.addoption(
        "--hardware-aware-setup-input",
        action="store",
        help=(
            "Optional user setup YAML. If --hardware-aware-setup is also provided, "
            "this file overrides the selected setup profile. If --hardware-aware-setup "
            "is omitted, this file must provide a complete setup."
        ),
    )
    group.addoption(
        "--hardware-aware-include-topology-rules",
        action="store_true",
        default=False,
        help=(
            "In catalog setup mode, temporarily include topology marker rules even "
            "when skip_rules.yaml marks enabled=false. By default the "
            "YAML catalog controls whether topology rules are generated."
        ),
    )
    group.addoption(
        "--hardware-aware-report-path",
        action="store",
        default=DEFAULT_REPORT_PATH,
        help="Path to write the hardware-aware collection report JSON.",
    )
    group.addoption(
        "--hardware-aware-min-confidence",
        action="store",
        default="none",
        choices=("none", "low", "medium", "high"),
        help=(
            "Only evaluate test capabilities at or above this confidence. "
            "Use high to run only high-confidence generated rules."
        ),
    )
    group.addoption(
        "--hardware-aware-candidate-status",
        action="store",
        default="any",
        help=(
            "Only evaluate test capabilities with this candidate_status, for example "
            "ready_for_report_only. Use any to disable this filter."
        ),
    )
    group.addoption(
        "--hardware-aware-missing-run-context-policy",
        "--hardware-aware-missing-capability-policy",
        action="store",
        dest="hardware_aware_missing_run_context_policy",
        default="deselect",
        choices=("deselect", "run"),
        help=(
            "How to handle test capability conditions whose run context path is not present. "
            "Use run with partial run context files to avoid deselecting on unknown facts. "
            "--hardware-aware-missing-capability-policy is accepted as a backward-compatible alias."
        ),
    )


def _candidate_paths(config, user_path):
    path = Path(user_path)
    if path.is_absolute():
        return [path]

    candidates = [Path.cwd() / path]
    root = Path(str(config.rootpath)).resolve()
    for parent in [root] + list(root.parents):
        candidates.append(parent / path)
    return candidates


def _resolve_path(config, user_path):
    for candidate in _candidate_paths(config, user_path):
        if candidate.exists():
            return candidate
    return _candidate_paths(config, user_path)[0]


def _resolve_output_path(config, user_path):
    candidates = _candidate_paths(config, user_path)
    for candidate in candidates:
        if candidate.exists() or candidate.parent.exists():
            return candidate
    return candidates[0]


def _load_yaml(config, option_name):
    user_path = config.getoption(option_name)
    return _load_yaml_path(config, user_path)


def _load_yaml_path(config, user_path):
    path = _resolve_path(config, user_path)
    if not path.exists():
        raise pytest.UsageError("Hardware-aware file not found: {}".format(user_path))
    with path.open() as f:
        return yaml.safe_load(f), path


def _catalog_setup_enabled(config):
    return bool(
        config.getoption("hardware_aware_setup")
        or config.getoption("hardware_aware_setup_input")
    )


def _explicit_runtime_files_provided(config):
    return (
        config.getoption("hardware_aware_run_context_file") != DEFAULT_RUN_CONTEXT_FILE
        or config.getoption("hardware_aware_test_capabilities_file") != DEFAULT_TEST_CAPABILITIES_FILE
    )


def _load_runtime_inputs_generator(config):
    path = _resolve_path(config, DEFAULT_RUNTIME_INPUTS_GENERATOR)
    if not path.exists():
        raise pytest.UsageError(
            "Hardware-aware runtime input generator not found: {}".format(
                DEFAULT_RUNTIME_INPUTS_GENERATOR
            )
        )

    spec = importlib.util.spec_from_file_location("hardware_aware_runtime_inputs", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, path


def _safe_getoption(config, name, default=None):
    try:
        return config.getoption(name)
    except (AttributeError, ValueError):
        return default


def _runtime_parameter_overrides(config):
    overrides = {}

    py_saithrift_url = _safe_getoption(config, "py_saithrift_url")
    if py_saithrift_url is not None:
        overrides["resources.python_saithrift_package_url.available"] = bool(py_saithrift_url)

    topology = _safe_getoption(config, "topology")
    if topology:
        topology = str(topology).lower()
        overrides["topology.is_tgen"] = any(
            token in topology
            for token in ("tgen", "ixia", "nut")
        )
        overrides["topology.is_t0_backend"] = "t0-backend" in topology

    mark_condition_files = _safe_getoption(config, "mark_conditions_files", []) or []
    mark_condition_files = [str(path).lower() for path in mark_condition_files]
    if any("cisco_sim" in path for path in mark_condition_files):
        overrides["environment.is_sim"] = True
        overrides["environment.is_vxr"] = True

    return overrides


def _load_catalog_runtime_inputs(config):
    if _explicit_runtime_files_provided(config):
        raise pytest.UsageError(
            "Do not combine --hardware-aware-setup/--hardware-aware-setup-input with "
            "--hardware-aware-run-context-file or --hardware-aware-test-capabilities-file. "
            "Catalog setup mode generates those runtime inputs internally."
        )

    catalog_doc, catalog_path = _load_yaml(config, "hardware_aware_catalog_file")
    setup_profiles_doc, setup_profiles_path = _load_yaml(config, "hardware_aware_setup_profiles_file")
    setup_input_path = None
    setup_input_doc = None
    setup_input = config.getoption("hardware_aware_setup_input")
    if setup_input:
        setup_input_doc, setup_input_path = _load_yaml_path(config, setup_input)

    generator, generator_path = _load_runtime_inputs_generator(config)
    try:
        test_capabilities_doc, run_context_doc, audit_doc, _ = generator.build_outputs(
            catalog_doc,
            setup_profiles_doc,
            config.getoption("hardware_aware_setup"),
            raw_skips=None,
            setup_input_doc=setup_input_doc,
            parameter_overrides=_runtime_parameter_overrides(config),
            include_topology_rules=config.getoption("hardware_aware_include_topology_rules"),
        )
    except SystemExit as exc:
        raise pytest.UsageError("Hardware-aware catalog setup failed: {}".format(exc))

    audit_summary = audit_doc.get("summary", {}) if isinstance(audit_doc, dict) else {}
    setup_key = audit_doc.get("setup") if isinstance(audit_doc, dict) else config.getoption("hardware_aware_setup")
    source = {
        "mode": "catalog_setup",
        "catalog": str(catalog_path),
        "setup_profiles": str(setup_profiles_path),
        "setup": setup_key,
        "setup_input": str(setup_input_path) if setup_input_path else None,
        "runtime_inputs_generator": str(generator_path),
        "include_topology_rules": config.getoption("hardware_aware_include_topology_rules"),
        "audit_summary": audit_summary,
    }

    return (
        run_context_doc,
        "catalog:run_context:{}".format(setup_key or "setup_input"),
        test_capabilities_doc,
        "catalog:test_capabilities:{}".format(setup_key or "setup_input"),
        source,
    )


def _load_runtime_inputs(config):
    if _catalog_setup_enabled(config):
        return _load_catalog_runtime_inputs(config)

    run_context_doc, run_context_path = _load_yaml(config, "hardware_aware_run_context_file")
    test_capabilities_doc, test_capabilities_path = _load_yaml(
        config,
        "hardware_aware_test_capabilities_file",
    )
    return run_context_doc, run_context_path, test_capabilities_doc, test_capabilities_path, None


def _get_path(data, dotted_path):
    cur = data
    for part in dotted_path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _normalize_identifier(value):
    return str(value).strip().lower().replace("_", "-").replace(" ", "-")


def _normalized_values(value):
    return [_normalize_identifier(item) for item in _as_list(value)]


def _condition_passed(operator, actual, expected, test_capability_id):
    if operator == "equals":
        return actual == expected
    if operator == "not_equals":
        return actual != expected

    actual_values = set(_normalized_values(actual))
    expected_values = set(_normalized_values(expected))

    if operator == "contains":
        return bool(expected_values) and expected_values.issubset(actual_values)
    if operator == "not_contains":
        return not expected_values.intersection(actual_values)
    if operator == "intersects":
        return bool(expected_values.intersection(actual_values))
    if operator == "excludes_any":
        return not expected_values.intersection(actual_values)

    raise pytest.UsageError(
        "Unsupported hardware-aware operator for {}: {}".format(test_capability_id, operator)
    )


def _format_reason(template, run_context):
    def replace(match):
        value = _get_path(run_context, match.group(1))
        if value is None:
            return "unknown"
        return str(value)

    return re.sub(r"\{([^{}]+)\}", replace, template)


def _clean_skip_reason(reason):
    if not reason:
        return None

    text = str(reason).strip()
    if text.startswith("^"):
        text = text[1:]
    if text.endswith("$"):
        text = text[:-1]

    replacements = {
        "[- ]": "-",
        "\\.": ".",
        "\\'": "'",
        '\\"': '"',
        "\\ ": " ",
        "\\-": "-",
        "\\[": "[",
        "\\]": "]",
        "\\(": "(",
        "\\)": ")",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def _format_condition_value(value):
    if isinstance(value, list):
        return "[" + ", ".join(str(item) for item in value) + "]"
    return str(value)


def _format_trigger(evaluated_condition):
    path = evaluated_condition["path"]
    operator = evaluated_condition["operator"]
    actual = _format_condition_value(evaluated_condition.get("actual"))
    expected = _format_condition_value(evaluated_condition.get("expected"))

    if operator == "not_equals":
        return "{}={} matches blocked value {}".format(path, actual, expected)
    if operator == "excludes_any":
        return "{}={} intersects unsupported values {}".format(path, actual, expected)
    if operator == "intersects":
        return "{}={} has no intersection with required values {}".format(path, actual, expected)
    if operator == "equals":
        return "{}={} did not match required value {}".format(path, actual, expected)
    if operator == "contains":
        return "{}={} does not contain required values {}".format(path, actual, expected)
    if operator == "not_contains":
        return "{}={} contains unsupported values {}".format(path, actual, expected)
    return "{}={} failed {}".format(path, actual, operator)


def _decision_triggers(decision):
    return [
        _format_trigger(condition)
        for condition in decision.get("evaluated_run_context", [])
        if not condition.get("passed")
    ]


def _normalized_nodeids(item, config):
    nodeid = item.nodeid
    root_prefix = os.path.basename(str(config.rootpath)) + "/"
    candidates = [nodeid]

    if nodeid.startswith(root_prefix):
        candidates.append(nodeid[len(root_prefix):])

    for candidate in list(candidates):
        if not candidate.startswith("tests/"):
            candidates.append("tests/" + candidate)

    return list(dict.fromkeys(candidates))


def _canonical_report_nodeid(item, config):
    for nodeid in _normalized_nodeids(item, config):
        if nodeid.startswith("tests/"):
            return nodeid
    return item.nodeid


def _selector_matches(test_capability, item, config):
    selector = test_capability["applies_to"]
    selector_type = selector["type"]

    if selector_type == "pytest_marker":
        return any(item.iter_markers(name=selector["marker"]))

    nodeids = _normalized_nodeids(item, config)
    if selector_type == "path_prefix":
        return any(nodeid.startswith(selector["prefix"]) for nodeid in nodeids)
    if selector_type == "regex":
        pattern = re.compile(selector["pattern"])
        return any(pattern.search(nodeid) for nodeid in nodeids)

    raise pytest.UsageError("Unsupported hardware-aware selector type: {}".format(selector_type))


def _topology_marker_name(test_capability):
    evaluation = test_capability.get("evaluation", {})
    selector = test_capability.get("applies_to", {})
    return evaluation.get("marker") or selector.get("marker") or "topology"


def _evaluate_topology_marker(test_capability, item, run_context):
    marker_name = _topology_marker_name(test_capability)
    marks = list(item.iter_markers(name=marker_name))
    if not marks:
        return None

    marker_args = [str(arg) for arg in marks[0].args]
    raw_available_tags = _get_path(run_context, "topology.available_tags")
    available_tags = raw_available_tags or []
    available_tags = [str(tag) for tag in available_tags]
    marker_allows_any = "any" in marker_args
    matched = marker_allows_any or bool(set(marker_args).intersection(available_tags))

    evaluated = [
        {
            "path": "marker.{}".format(marker_name),
            "operator": "intersects",
            "expected": available_tags,
            "actual": marker_args,
            "passed": matched,
            "missing": False,
        },
        {
            "path": "topology.available_tags",
            "operator": "intersects",
            "expected": marker_args,
            "actual": available_tags,
            "passed": matched,
            "missing": raw_available_tags is None,
        },
        {
            "path": "topology.name",
            "actual": _get_path(run_context, "topology.name"),
        },
        {
            "path": "topology.type",
            "actual": _get_path(run_context, "topology.type"),
        },
    ]
    return "run" if matched else "deselect", evaluated


def _evaluate_test_capability(test_capability, item, run_context, missing_run_context_policy="deselect"):
    evaluation = test_capability.get("evaluation", {})
    selector = test_capability["applies_to"]

    if evaluation.get("mode") in TOPOLOGY_MARKER_EVALUATION_MODES:
        return _evaluate_topology_marker(test_capability, item, run_context)

    if selector["type"] == "pytest_marker" and selector.get("marker") == "topology":
        return _evaluate_topology_marker(test_capability, item, run_context)

    if evaluation.get("mode") != "all":
        raise pytest.UsageError(
            "Unsupported hardware-aware evaluation mode for {}: {}".format(
                test_capability["id"], evaluation.get("mode")
            )
        )

    evaluated = []
    all_passed = True
    for condition in evaluation.get("conditions", []):
        path = condition["path"]
        operator = condition["operator"]
        expected = condition["expected"]
        actual = _get_path(run_context, path)
        missing = actual is None
        if missing and missing_run_context_policy == "run":
            passed = True
        else:
            passed = _condition_passed(operator, actual, expected, test_capability["id"])
        all_passed = all_passed and passed
        evaluated.append({
            "path": path,
            "operator": operator,
            "expected": expected,
            "actual": actual,
            "passed": passed,
            "missing": missing,
        })

    return "run" if all_passed else "deselect", evaluated


def _run_context_instance(run_context_doc):
    if isinstance(run_context_doc, dict) and "example_current_run" in run_context_doc:
        return run_context_doc["example_current_run"]
    return run_context_doc


def _test_capability_passes_confidence_filter(test_capability, min_confidence):
    if min_confidence == "none":
        return True
    confidence = test_capability.get("confidence")
    return CONFIDENCE_ORDER.get(confidence, 0) >= CONFIDENCE_ORDER[min_confidence]


def _test_capability_passes_candidate_status_filter(test_capability, candidate_status):
    if candidate_status == "any":
        return True
    return test_capability.get("candidate_status") == candidate_status


def _test_capabilities_doc_items(test_capabilities_doc):
    return test_capabilities_doc.get("test_capabilities", test_capabilities_doc.get("requirements", []))


def _filter_test_capabilities(config, test_capabilities):
    min_confidence = config.getoption("hardware_aware_min_confidence")
    candidate_status = config.getoption("hardware_aware_candidate_status")
    active = []
    filtered = []

    for test_capability in test_capabilities:
        if not _test_capability_passes_confidence_filter(test_capability, min_confidence):
            filtered.append({
                "id": test_capability.get("id"),
                "reason": "confidence_below_minimum",
                "confidence": test_capability.get("confidence"),
                "candidate_status": test_capability.get("candidate_status"),
            })
            continue
        if not _test_capability_passes_candidate_status_filter(test_capability, candidate_status):
            filtered.append({
                "id": test_capability.get("id"),
                "reason": "candidate_status_mismatch",
                "confidence": test_capability.get("confidence"),
                "candidate_status": test_capability.get("candidate_status"),
            })
            continue
        active.append(test_capability)

    return active, filtered, {
        "min_confidence": min_confidence,
        "candidate_status": candidate_status,
    }


def _build_report(
    config,
    items,
    run_context_doc,
    test_capabilities_doc,
    run_context_path,
    test_capabilities_path,
    mode,
    runtime_inputs_source=None,
):
    run_context = _run_context_instance(run_context_doc)
    test_capabilities = _test_capabilities_doc_items(test_capabilities_doc)
    active_test_capabilities, filtered_test_capabilities, test_capability_filters = _filter_test_capabilities(
        config,
        test_capabilities,
    )
    missing_run_context_policy = config.getoption("hardware_aware_missing_run_context_policy")
    decisions = []

    for item in items:
        for test_capability in active_test_capabilities:
            if not _selector_matches(test_capability, item, config):
                continue

            evaluated = _evaluate_test_capability(
                test_capability,
                item,
                run_context,
                missing_run_context_policy,
            )
            if evaluated is None:
                continue

            decision, evaluated_run_context = evaluated
            decisions.append({
                "nodeid": item.nodeid,
                "decision": decision,
                "reason": _format_reason(test_capability["decision"]["reason_template"], run_context),
                "skip_reason": _clean_skip_reason(test_capability.get("raw_skip_reason")),
                "test_capability_id": test_capability["id"],
                "bucket_id": test_capability.get("bucket_id"),
                "confidence": test_capability.get("confidence"),
                "candidate_status": test_capability.get("candidate_status"),
                "evaluated_run_context": evaluated_run_context,
            })

    by_decision = Counter(decision["decision"] for decision in decisions)
    by_test_capability = Counter(decision["test_capability_id"] for decision in decisions)
    by_bucket = Counter(decision["bucket_id"] for decision in decisions)
    collected_nodeids = sorted(_canonical_report_nodeid(item, config) for item in items)

    inputs = {
        "run_context": str(run_context_path),
        "test_capabilities": str(test_capabilities_path),
    }
    if runtime_inputs_source:
        inputs["catalog_setup"] = runtime_inputs_source

    return {
        "version": "hardware-aware-pytest-collection-report/v0.1",
        "mode": mode,
        "inputs": inputs,
        "test_capability_filters": test_capability_filters,
        "summary": {
            "collected_items": len(items),
            "test_capabilities_total": len(test_capabilities),
            "test_capabilities_active": len(active_test_capabilities),
            "test_capabilities_filtered_out": len(filtered_test_capabilities),
            "matched_items": len({decision["nodeid"] for decision in decisions}),
            "decisions": len(decisions),
            "deselect_recommendations": sum(1 for decision in decisions if decision["decision"] == "deselect"),
            "by_decision": dict(sorted(by_decision.items())),
            "by_test_capability": dict(sorted(by_test_capability.items())),
            "by_bucket": dict(sorted(by_bucket.items())),
            "missing_run_context_policy": missing_run_context_policy,
        },
        "collected_nodeids": collected_nodeids,
        "filtered_test_capabilities": filtered_test_capabilities,
        "decisions": decisions,
    }


def _write_report(config, report):
    report_path = _resolve_output_path(config, config.getoption("hardware_aware_report_path"))
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")
    summary_path = _write_text_summary(report_path, report)
    aggregate_summary_path = _write_aggregate_text_summary(report_path.parent)
    return report_path, summary_path, aggregate_summary_path


def _text_summary_path(report_path):
    return report_path.with_name("{}_summary.txt".format(report_path.stem))


def _write_text_summary(report_path, report):
    summary_path = _text_summary_path(report_path)
    summary = report.get("summary", {})
    deselected = [
        decision for decision in report.get("decisions", [])
        if decision.get("decision") == "deselect"
    ]

    lines = [
        "Hardware-aware deselect summary",
        "JSON report: {}".format(report_path),
        "mode: {}".format(report.get("mode")),
        "collected_items: {}".format(summary.get("collected_items", 0)),
        "deselected_items: {}".format(summary.get("deselected_items", 0)),
        "",
    ]

    if not deselected:
        lines.append("No tests were deselected.")
    else:
        reason_groups = defaultdict(list)
        for decision in deselected:
            reason = decision.get("skip_reason") or decision.get("reason")
            triggers = _decision_triggers(decision)
            key = (
                reason,
                decision.get("bucket_id"),
                "; ".join(triggers),
            )
            reason_groups[key].append(decision.get("nodeid"))

        lines.append("Deselect reasons:")
        for key in sorted(reason_groups, key=lambda item: (item[0] or "", item[1] or "", item[2] or "")):
            reason, bucket_id, trigger = key
            lines.append("- reason: {}".format(reason))
            lines.append("  bucket: {}".format(bucket_id))
            if trigger:
                lines.append("  trigger: {}".format(trigger))
            lines.append("  tests:")
            for nodeid in sorted(reason_groups[key]):
                lines.append("    - {}".format(nodeid))
            lines.append("")

    with summary_path.open("w") as f:
        f.write("\n".join(lines).rstrip())
        f.write("\n")
    return summary_path


def _aggregate_text_summary_path(report_dir):
    return report_dir / "hardware_aware_deselect_summary.txt"


def _load_hardware_aware_reports(report_dir):
    reports = []
    for path in sorted(report_dir.glob("*_hardware_aware.json")):
        try:
            with path.open() as f:
                report = json.load(f)
        except (IOError, ValueError) as exc:
            logger.warning("Unable to read hardware-aware report %s: %s", path, exc)
            continue
        reports.append((path, report))
    return reports


def _write_aggregate_text_summary(report_dir):
    reports = _load_hardware_aware_reports(report_dir)
    if not reports:
        return None

    total_collected = sum(
        report.get("summary", {}).get("collected_items", 0)
        for _, report in reports
    )
    total_deselected = sum(
        report.get("summary", {}).get("deselected_items", 0)
        for _, report in reports
    )
    total_decisions = sum(
        report.get("summary", {}).get("decisions", 0)
        for _, report in reports
    )

    lines = [
        "Hardware-aware aggregate deselect summary",
        "report_dir: {}".format(report_dir),
        "report_files: {}".format(len(reports)),
        "total_collected_items: {}".format(total_collected),
        "total_decisions: {}".format(total_decisions),
        "total_deselected_items: {}".format(total_deselected),
        "",
    ]

    reason_groups = defaultdict(list)
    for path, report in reports:
        for decision in report.get("decisions", []):
            if decision.get("decision") != "deselect":
                continue
            reason = decision.get("skip_reason") or decision.get("reason")
            triggers = _decision_triggers(decision)
            key = (
                reason,
                decision.get("bucket_id"),
                "; ".join(triggers),
            )
            reason_groups[key].append((decision.get("nodeid"), path.name))

    if not reason_groups:
        lines.append("No tests were deselected.")
    else:
        lines.append("Deselect reasons:")
        for key in sorted(reason_groups, key=lambda item: (item[0] or "", item[1] or "", item[2] or "")):
            reason, bucket_id, trigger = key
            entries = sorted(reason_groups[key])
            lines.append("- reason: {}".format(reason))
            lines.append("  bucket: {}".format(bucket_id))
            if trigger:
                lines.append("  trigger: {}".format(trigger))
            lines.append("  tests:")
            for nodeid, source_report in entries:
                lines.append("    - {} ({})".format(nodeid, source_report))
            lines.append("")

    lines.append("Report file overview:")
    for path, report in reports:
        summary = report.get("summary", {})
        lines.append(
            "- {}: collected={}, deselected={}".format(
                path.name,
                summary.get("collected_items", 0),
                summary.get("deselected_items", 0),
            )
        )

    summary_path = _aggregate_text_summary_path(report_dir)
    with summary_path.open("w") as f:
        f.write("\n".join(lines).rstrip())
        f.write("\n")
    return summary_path


def _deselect_items(config, items, report):
    deselect_nodeids = {
        decision["nodeid"]
        for decision in report["decisions"]
        if decision["decision"] == "deselect"
    }
    if not deselect_nodeids:
        report["summary"]["deselected_items"] = 0
        return

    deselected_items = [item for item in items if item.nodeid in deselect_nodeids]
    if not deselected_items:
        report["summary"]["deselected_items"] = 0
        return

    items[:] = [item for item in items if item.nodeid not in deselect_nodeids]
    config.hook.pytest_deselected(items=deselected_items)
    report["summary"]["deselected_items"] = len(deselected_items)


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(session, config, items):
    report_only = config.getoption("hardware_aware_report_only")
    deselect = config.getoption("hardware_aware_deselect")
    if not report_only and not deselect:
        return

    (
        run_context_doc,
        run_context_path,
        test_capabilities_doc,
        test_capabilities_path,
        runtime_inputs_source,
    ) = _load_runtime_inputs(config)
    mode = "deselect" if deselect else "report_only"
    report = _build_report(
        config,
        items,
        run_context_doc,
        test_capabilities_doc,
        run_context_path,
        test_capabilities_path,
        mode,
        runtime_inputs_source=runtime_inputs_source,
    )

    if deselect:
        _deselect_items(config, items, report)
    else:
        report["summary"]["deselected_items"] = 0

    report_path, summary_path, aggregate_summary_path = _write_report(config, report)
    logger.info(
        "Hardware-aware %s report written to %s, summary written to %s, aggregate summary written to %s: %s",
        mode,
        report_path,
        summary_path,
        aggregate_summary_path,
        report["summary"],
    )
