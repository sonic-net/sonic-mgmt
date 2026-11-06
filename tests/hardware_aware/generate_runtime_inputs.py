#!/usr/bin/env python3
"""Generate current hardware-aware inputs from catalog YAML files.

This is intentionally a converter, not a new pytest plugin. It lets us test a
human-readable catalog while continuing to use the existing hardware-aware
plugin backend. Without --raw-skips it generates setup-only inputs from the
selected setup profile. With --raw-skips it generates report-seeded inputs for
historical validation and catalog coverage work.
"""

import argparse
import copy
import json
import re
from collections import OrderedDict
from pathlib import Path

import yaml


def load_yaml(path):
    with open(str(path)) as f:
        return yaml.safe_load(f)


def load_json(path):
    with open(str(path)) as f:
        return json.load(f)


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")


def write_lines(path, lines):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for line in lines:
            f.write(line)
            f.write("\n")


def safe_id(value):
    return re.sub(r"[^a-zA-Z0-9_]+", "_", str(value)).strip("_").lower()


def exact_nodeid_regex(nodeids):
    escaped = [re.escape(nodeid) for nodeid in sorted(nodeids)]
    return "^(?:{})$".format("|".join(escaped))


def normalize_test_selector_path(value):
    value = str(value).strip()
    if value.startswith("tests/"):
        return value
    return "tests/" + value.lstrip("/")


def regex_for_test_selector(value):
    value = normalize_test_selector_path(value)
    if value.endswith("/"):
        return "^{}".format(re.escape(value))
    if "::" in value:
        if "[" in value:
            return "^{}$".format(re.escape(value))
        return "^{}(?:$|\\[|::)".format(re.escape(value))
    if value.endswith(".py"):
        return "^{}(?:::|$)".format(re.escape(value))
    return "^{}".format(re.escape(value))


def regex_for_param_selector(nodeid, param_contains=None, param_prefixes=None):
    nodeid = normalize_test_selector_path(nodeid)
    prefix = "^{}\\[".format(re.escape(nodeid))

    if param_contains:
        return "{}.*{}".format(prefix, re.escape(str(param_contains)))

    if param_prefixes:
        escaped = [re.escape(str(value)) for value in param_prefixes]
        return "{}(?:{})".format(prefix, "|".join(escaped))

    return regex_for_test_selector(nodeid)


def regex_for_prefix_param_selector(prefix, param_contains=None, param_prefixes=None):
    prefix = normalize_test_selector_path(prefix)
    if prefix.endswith("/") or ("::" not in prefix and not prefix.endswith(".py")):
        pattern = "^{}.*\\[".format(re.escape(prefix))
        fallback = "^{}".format(re.escape(prefix))
    else:
        pattern = "^{}(?=$|\\[|::).*\\[".format(re.escape(prefix))
        fallback = "^{}(?=$|\\[|::)".format(re.escape(prefix))

    if param_contains:
        return "{}.*{}".format(pattern, re.escape(str(param_contains)))

    if param_prefixes:
        escaped = [re.escape(str(value)) for value in param_prefixes]
        return "{}(?:{})".format(pattern, "|".join(escaped))

    return fallback


def regex_for_path_prefix_with_excludes(path_prefix, exclude_nodeids):
    path_prefix = normalize_test_selector_path(path_prefix)
    relative_excludes = []
    for nodeid in exclude_nodeids or []:
        nodeid = normalize_test_selector_path(nodeid)
        if not nodeid.startswith(path_prefix):
            raise SystemExit(
                "exclude_nodeid {} is not under path_prefix {}".format(nodeid, path_prefix)
            )
        relative_excludes.append(re.escape(nodeid[len(path_prefix):]))

    if not relative_excludes:
        return "^{}".format(re.escape(path_prefix))

    return "^{}(?!(?:{})(?:$|\\[|::))".format(
        re.escape(path_prefix),
        "|".join(relative_excludes),
    )


def selector_from_catalog_tests(rule):
    tests = rule.get("tests") or []
    if not tests:
        return None, None

    markers = []
    prefixes = []
    regexes = []

    for entry in tests:
        if isinstance(entry, str):
            value = normalize_test_selector_path(entry)
            if value.endswith("/"):
                prefixes.append(value)
            else:
                regexes.append(regex_for_test_selector(value))
            continue

        if not isinstance(entry, dict):
            raise SystemExit("Unsupported tests selector entry in rule {}: {}".format(rule, entry))

        if "marker" in entry:
            markers.append(str(entry["marker"]))
        elif "path_prefix" in entry:
            if entry.get("param_contains") or entry.get("param_prefixes"):
                regexes.append(regex_for_prefix_param_selector(
                    entry["path_prefix"],
                    param_contains=entry.get("param_contains"),
                    param_prefixes=entry.get("param_prefixes"),
                ))
            elif entry.get("exclude_nodeids"):
                regexes.append(regex_for_path_prefix_with_excludes(
                    entry["path_prefix"],
                    entry.get("exclude_nodeids"),
                ))
            else:
                prefixes.append(normalize_test_selector_path(entry["path_prefix"]))
        elif "nodeid_prefix" in entry:
            regexes.append(regex_for_prefix_param_selector(
                entry["nodeid_prefix"],
                param_contains=entry.get("param_contains"),
                param_prefixes=entry.get("param_prefixes"),
            ))
        elif "nodeid" in entry:
            regexes.append(regex_for_param_selector(
                entry["nodeid"],
                param_contains=entry.get("param_contains"),
                param_prefixes=entry.get("param_prefixes"),
            ))
        elif "nodeids" in entry:
            for nodeid in entry["nodeids"]:
                regexes.append(regex_for_param_selector(
                    nodeid,
                    param_contains=entry.get("param_contains"),
                    param_prefixes=entry.get("param_prefixes"),
                ))
        elif "regex" in entry:
            regexes.append(entry["regex"])
        else:
            raise SystemExit("Unsupported tests selector mapping in rule {}: {}".format(rule, entry))

    if len(markers) == 1 and not prefixes and not regexes:
        return {"type": "pytest_marker", "marker": markers[0]}, "catalog_pytest_marker"

    if markers:
        raise SystemExit("Cannot combine marker selectors with path/regex selectors: {}".format(markers))

    if len(prefixes) == 1 and not regexes:
        return {"type": "path_prefix", "prefix": prefixes[0]}, "catalog_path_prefix"

    selector_patterns = ["^{}".format(re.escape(prefix)) for prefix in prefixes]
    selector_patterns.extend(regexes)
    return {
        "type": "regex",
        "pattern": "(?:{})".format("|".join(selector_patterns)),
    }, "catalog_readable_tests"


def selector_from_observed_nodeids(nodeids):
    return {
        "type": "regex",
        "pattern": exact_nodeid_regex(nodeids),
    }, "exact_observed_nodeids_from_report"


def selector_for_setup_only_rule(rule):
    selector, selector_strategy = selector_from_catalog_tests(rule)
    if selector is not None:
        return selector, selector_strategy

    if evaluation_mode(rule) == "topology_marker_intersects_available_tags":
        return {"type": "pytest_marker", "marker": "topology"}, "catalog_pytest_marker"

    return None, None


def resolve_setup(setup_profiles, setup_key):
    if not setup_profiles:
        raise SystemExit("--setup requires --setup-profiles or a catalog containing setups")

    setups = setup_profiles.get("setups", {})
    if setup_key in setups:
        return setup_key, setups[setup_key]

    alias_matches = [
        (key, setup)
        for key, setup in setups.items()
        if setup_key in (setup.get("aliases") or [])
    ]
    if len(alias_matches) == 1:
        return alias_matches[0]
    if not alias_matches:
        raise SystemExit("setup not found in setup profiles: {}".format(setup_key))

    raise SystemExit(
        "setup alias matched multiple setups: {}".format(
            ", ".join(key for key, _ in alias_matches)
        )
    )


def setup_from_input_doc(setup_input_doc, setup_key=None):
    if not isinstance(setup_input_doc, dict):
        raise SystemExit("--setup-input must be a YAML mapping")

    if "setups" in setup_input_doc:
        setups = setup_input_doc.get("setups") or {}
        if setup_key and setup_key in setups:
            return setup_key, setups[setup_key]

        user_setup_keys = [key for key in setups if key != "_template"]
        if len(user_setup_keys) == 1:
            key = user_setup_keys[0]
            return key, setups[key]

        if setup_key:
            raise SystemExit("--setup-input does not contain setup key: {}".format(setup_key))

        raise SystemExit(
            "--setup-input with setups must contain exactly one setup or be used with --setup"
        )

    if "parameters" in setup_input_doc or "metadata" in setup_input_doc:
        key = setup_input_doc.get("key") or setup_key or "user_setup"
        setup = {
            k: v for k, v in setup_input_doc.items()
            if k not in ("key", "version")
        }
        return key, setup

    raise SystemExit(
        "--setup-input must either contain top-level metadata/parameters or a setups mapping"
    )


def merge_setup(base_setup, override_setup):
    merged = copy.deepcopy(base_setup or {})
    override = copy.deepcopy(override_setup or {})

    for key, value in override.items():
        if key in ("metadata", "parameters"):
            base_value = merged.get(key) or {}
            if not isinstance(base_value, dict) or not isinstance(value, dict):
                merged[key] = value
                continue
            updated = copy.deepcopy(base_value)
            updated.update(value)
            merged[key] = updated
        else:
            merged[key] = value

    return merged


def normalize_lookup_value(value):
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    return value.lower()


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def unique_values(values):
    result = []
    seen = set()
    for value in values:
        if value is None:
            continue
        value = str(value).strip()
        if not value:
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def split_setup_platform_key(setup_key):
    if not setup_key:
        return None
    return str(setup_key).split(":", 1)[0]


def platform_catalog_lookup_values(entry_key, entry):
    values = [
        entry_key,
        entry.get("sonic_platform"),
        entry.get("pid"),
        entry.get("hwsku"),
        entry.get("internal_name"),
    ]
    values.extend(as_list(entry.get("aliases")))
    values.extend(as_list(entry.get("external_aliases")))
    values.extend(as_list(entry.get("internal_aliases")))
    return unique_values(values)


def platform_catalog_rule_identifiers(entry_key, entry):
    """Return identifiers safe to expose to skip rules.

    Internal aliases such as Superbolt are intentionally excluded here. They are
    accepted for setup resolution only, so external-facing rules can use SONiC
    platform, PID, chip, ASIC type, or vendor family instead.
    """
    values = [
        entry.get("sonic_platform"),
        entry_key,
        entry.get("pid"),
        entry.get("hwsku"),
        entry.get("chip"),
    ]
    values.extend(as_list(entry.get("identifiers")))
    values.extend(as_list(entry.get("external_aliases")))
    return unique_values(values)


def setup_platform_candidates(setup_key, setup):
    metadata = setup.get("metadata") or {}
    parameters = setup.get("parameters") or {}
    values = [
        split_setup_platform_key(setup_key),
        metadata.get("platform"),
        metadata.get("sonic_platform"),
        metadata.get("pid"),
        metadata.get("hwsku"),
        metadata.get("platform_alias"),
        metadata.get("internal_platform"),
        parameters.get("platform.sonic_platform"),
        parameters.get("platform.pid"),
        parameters.get("platform.hwsku"),
    ]
    values.extend(as_list(parameters.get("platform.identifiers")))
    return unique_values(values)


def resolve_platform_catalog_entry(setup_profiles, setup_key, setup):
    catalog = (setup_profiles or {}).get("platform_catalog") or {}
    if not catalog:
        return None

    lookup = {}
    for entry_key, entry in sorted(catalog.items()):
        entry = entry or {}
        for value in platform_catalog_lookup_values(entry_key, entry):
            norm = normalize_lookup_value(value)
            if norm:
                lookup.setdefault(norm, []).append((entry_key, entry))

    matches = OrderedDict()
    for value in setup_platform_candidates(setup_key, setup):
        norm = normalize_lookup_value(value)
        for entry_key, entry in lookup.get(norm, []):
            matches[entry_key] = entry

    if not matches:
        return None
    if len(matches) > 1:
        raise SystemExit(
            "setup platform matched multiple platform_catalog entries: {}".format(
                ", ".join(matches.keys())
            )
        )

    entry_key, entry = next(iter(matches.items()))
    return entry_key, entry


def fill_missing(mapping, key, value):
    if value is None:
        return
    if key not in mapping or mapping.get(key) in (None, ""):
        mapping[key] = value


def merge_identifier_parameter(parameters, values):
    existing = as_list(parameters.get("platform.identifiers"))
    parameters["platform.identifiers"] = unique_values(existing + values)


def apply_platform_catalog(setup_profiles, setup_key, setup):
    setup = copy.deepcopy(setup or {})
    resolved = resolve_platform_catalog_entry(setup_profiles, setup_key, setup)
    if not resolved:
        return setup, None

    catalog_key, entry = resolved
    sonic_platform = entry.get("sonic_platform")
    platform_identity = sonic_platform or entry.get("pid") or catalog_key
    platform_family = entry.get("platform_family") or entry.get("asic_type")

    metadata = setup.setdefault("metadata", {})
    parameters = setup.setdefault("parameters", {})

    fill_missing(metadata, "platform", platform_identity)
    fill_missing(metadata, "sonic_platform", sonic_platform)
    fill_missing(metadata, "pid", entry.get("pid"))
    fill_missing(metadata, "chip", entry.get("chip"))
    fill_missing(metadata, "hwsku", entry.get("hwsku"))
    fill_missing(metadata, "hbm", entry.get("hbm"))
    fill_missing(metadata, "speed", entry.get("speed"))
    fill_missing(metadata, "configuration", entry.get("configuration"))
    fill_missing(metadata, "sonic_support_roles", entry.get("sonic_support_roles"))
    fill_missing(metadata, "vendor_family", entry.get("vendor_family"))
    fill_missing(metadata, "asic_type", entry.get("asic_type"))
    fill_missing(metadata, "platform_family", platform_family)

    fill_missing(parameters, "platform.sonic_platform", sonic_platform)
    fill_missing(parameters, "platform.platform", sonic_platform or catalog_key)
    fill_missing(parameters, "platform.pid", entry.get("pid"))
    fill_missing(parameters, "platform.chip", entry.get("chip"))
    fill_missing(parameters, "platform.hwsku", entry.get("hwsku"))
    fill_missing(parameters, "platform.hbm", entry.get("hbm"))
    fill_missing(parameters, "platform.speed", entry.get("speed"))
    fill_missing(parameters, "platform.configuration", entry.get("configuration"))
    fill_missing(parameters, "platform.sonic_support_roles", entry.get("sonic_support_roles"))
    fill_missing(parameters, "platform.vendor_family", entry.get("vendor_family"))
    fill_missing(parameters, "platform.asic_type", entry.get("asic_type"))
    fill_missing(parameters, "platform.platform_family", platform_family)
    merge_identifier_parameter(parameters, platform_catalog_rule_identifiers(catalog_key, entry))

    return setup, {
        "catalog_key": catalog_key,
        "sonic_platform": sonic_platform,
        "pid": entry.get("pid"),
        "chip": entry.get("chip"),
        "hbm": entry.get("hbm"),
        "speed": entry.get("speed"),
        "configuration": entry.get("configuration"),
        "asic_type": entry.get("asic_type"),
        "platform_family": platform_family,
    }


def setup_topology_candidates(setup_key, setup):
    metadata = setup.get("metadata") or {}
    parameters = setup.get("parameters") or {}
    values = []

    if setup_key and ":" in str(setup_key):
        values.append(str(setup_key).split(":", 1)[1])

    values.extend([
        metadata.get("topology"),
        parameters.get("topology.name"),
        parameters.get("topology.type"),
    ])
    values.extend(as_list(parameters.get("topology.identifiers")))
    values.extend(as_list(parameters.get("topology.available_tags")))
    return unique_values(values)


def infer_topology_fact_values(topology_candidates):
    lowered = [str(value).lower() for value in topology_candidates]
    return {
        "topology.is_tgen": any(
            token in value
            for value in lowered
            for token in ("tgen", "ixia", "nut")
        ),
        "topology.is_t0_backend": any("t0-backend" in value for value in lowered),
    }


def apply_topology_inferences(setup_key, setup):
    setup = copy.deepcopy(setup or {})
    parameters = setup.setdefault("parameters", {})
    candidates = setup_topology_candidates(setup_key, setup)
    if not candidates:
        return setup, None

    inferred = infer_topology_fact_values(candidates)
    for path, value in sorted(inferred.items()):
        fill_missing(parameters, path, value)

    return setup, {
        "topology_candidates": candidates,
        "inferred": inferred,
    }


def apply_parameter_overrides(setup, parameter_overrides):
    if not parameter_overrides:
        return setup

    return merge_setup(setup, {
        "parameters": parameter_overrides,
    })


def materialize_setup(setup_profiles, setup_key=None, setup_input_doc=None):
    if not setup_key and setup_input_doc is None:
        raise SystemExit("provide --setup, --setup-input, or both")

    resolved_key = setup_key
    setup = None

    if setup_key:
        resolved_key, setup = resolve_setup(setup_profiles, setup_key)

    if setup_input_doc is not None:
        input_key, input_setup = setup_from_input_doc(setup_input_doc, resolved_key)
        if setup is None:
            resolved_key = input_key
            setup = input_setup
        else:
            setup = merge_setup(setup, input_setup)

    return resolved_key, setup


def setup_profiles_for_resolution(catalog, setup_profiles, setup_key):
    if setup_profiles is not None:
        return setup_profiles
    if setup_key:
        return catalog
    return {"version": None, "setups": {}}


def evaluation_mode(rule):
    evaluation = rule.get("evaluation")
    if isinstance(evaluation, dict):
        return evaluation.get("mode")
    return evaluation


def rule_enabled(rule):
    if "enabled" not in rule:
        return True
    enabled = rule["enabled"]
    if isinstance(enabled, bool):
        return enabled
    if isinstance(enabled, str):
        return enabled.strip().lower() in ("1", "true", "yes", "on")
    return bool(enabled)


def rule_disabled_reason(rule):
    return rule.get("disabled_reason") or "enabled is false"


def is_topology_marker_rule(rule):
    return evaluation_mode(rule) == "topology_marker_intersects_available_tags"


def set_path(data, dotted_path, value):
    cur = data
    parts = dotted_path.split(".")
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


def build_run_context(
    catalog,
    setup_profiles,
    setup_key,
    setup,
    setup_input_used=False,
    setup_merge_mode="profile_only",
    platform_decode=None,
):
    run_context = OrderedDict()
    run_context["version"] = "hardware-aware-run-context/v0.1"
    run_context["status"] = "resolved_from_catalog"
    run_context["source"] = {
        "catalog_schema": catalog.get("version"),
        "setup_profiles_schema": setup_profiles.get("version"),
        "setup": setup_key,
        "setup_input_used": setup_input_used,
        "setup_merge_mode": setup_merge_mode,
        "platform_decode": platform_decode,
    }

    metadata = setup.get("metadata", {})
    parameters = setup.get("parameters") or {}
    if metadata or parameters:
        run_context["run"] = {
            "platform": metadata.get("platform"),
            "sonic_platform": metadata.get("sonic_platform"),
            "pid": metadata.get("pid"),
            "chip": metadata.get("chip"),
            "hwsku": metadata.get("hwsku"),
            "hbm": metadata.get("hbm"),
            "speed": metadata.get("speed"),
            "configuration": metadata.get("configuration"),
            "sonic_support_roles": metadata.get("sonic_support_roles"),
            "vendor_family": metadata.get("vendor_family"),
            "asic_type": metadata.get("asic_type"),
            "platform_family": metadata.get("platform_family"),
            "topology": metadata.get("topology"),
            "branch": metadata.get("branch"),
        }

        run_parameter_overrides = {
            "platform.sonic_platform": "sonic_platform",
            "platform.pid": "pid",
            "platform.chip": "chip",
            "platform.hwsku": "hwsku",
            "platform.hbm": "hbm",
            "platform.speed": "speed",
            "platform.configuration": "configuration",
            "platform.sonic_support_roles": "sonic_support_roles",
            "platform.vendor_family": "vendor_family",
            "platform.asic_type": "asic_type",
            "platform.platform_family": "platform_family",
        }
        for path, run_key in sorted(run_parameter_overrides.items()):
            if path in parameters and parameters[path] is not None:
                run_context["run"][run_key] = parameters[path]
        if parameters.get("platform.sonic_platform") is not None:
            run_context["run"]["platform"] = parameters["platform.sonic_platform"]

    for path, value in sorted(parameters.items()):
        set_path(run_context, path, value)

    return run_context


def values_equal(actual, expected):
    if isinstance(expected, list):
        if isinstance(actual, list):
            return bool(set(str(v) for v in actual).intersection(str(v) for v in expected))
        return str(actual) in set(str(v) for v in expected)
    return actual == expected


def setup_matches_parameters(setup_parameters, rule_parameters):
    missing = []
    mismatched = []
    for path, expected in sorted((rule_parameters or {}).items()):
        actual = setup_parameters.get(path)
        if path not in setup_parameters:
            missing.append({"path": path, "expected": expected})
            continue
        if not values_equal(actual, expected):
            mismatched.append({"path": path, "expected": expected, "actual": actual})
    return not missing and not mismatched, missing, mismatched


def condition_from_trigger_parameter(path, value):
    if isinstance(value, list):
        return {
            "path": path,
            "operator": "excludes_any",
            "expected": value,
        }
    return {
        "path": path,
        "operator": "not_equals",
        "expected": value,
    }


def source_areas(nodeids):
    areas = {}
    for nodeid in nodeids:
        path = nodeid.split("::", 1)[0]
        if path.startswith("tests/"):
            path = path[len("tests/"):]
        area = path.split("/", 1)[0] if "/" in path else path.rsplit(".", 1)[0]
        areas[area] = areas.get(area, 0) + 1
    return dict(sorted(areas.items()))


def reason_matches_rule(reason, rule):
    for pattern in rule.get("reason_patterns", []):
        if re.search(pattern, reason, flags=re.DOTALL):
            return pattern
    return None


def normalize_raw_skips(raw):
    """Accept raw reason -> nodeids or reason -> area -> nodeids."""
    normalized = {}
    for reason, value in raw.items():
        nodeids = []
        if isinstance(value, list):
            nodeids = list(value)
        elif isinstance(value, dict):
            for area_nodeids in value.values():
                if isinstance(area_nodeids, list):
                    nodeids.extend(area_nodeids)
        normalized[reason] = sorted(dict.fromkeys(nodeids))
    return normalized


def build_test_capability(
    rule_id,
    rule,
    nodeids,
    raw_reasons,
    matched_patterns,
    selector=None,
    selector_strategy=None,
    source_mode="report_seeded",
):
    confidence = rule.get("confidence", "high")
    candidate_status = rule.get("candidate_status", "ready_for_report_only")
    source_instances = len(nodeids)
    if selector is None:
        selector, selector_strategy = selector_from_catalog_tests(rule)
    if selector is None:
        selector, selector_strategy = selector_from_observed_nodeids(nodeids)

    selector_note = (
        "Generated from catalog setup-only rules."
        if source_mode == "setup_only"
        else "Generated from hardware-aware catalog readable tests when present; otherwise observed Allure nodeids."
    )

    if evaluation_mode(rule) == "topology_marker_intersects_available_tags":
        conditions = [
            {
                "path": "topology.available_tags",
                "operator": "intersects",
                "expected_source": "pytest.mark.topology args or test-required topology tags",
            }
        ]
        return {
            "id": "candidate_{}_requires_topology_available_tags".format(safe_id(rule_id)),
            "bucket_id": rule_id,
            "source_normalized_reason_id": rule_id,
            "raw_skip_reason": raw_reasons[0],
            "raw_skip_reason_variants": raw_reasons if len(raw_reasons) > 1 else None,
            "candidate_status": candidate_status,
            "confidence": confidence,
            "approved_for": "catalog",
            "selector_strategy": "{}_with_dynamic_topology_marker".format(selector_strategy),
            "selector_note": selector_note,
            "source_areas": source_areas(nodeids),
            "source_skipped_test_instances": source_instances,
            "applies_to": selector,
            "decision": {
                "deselect_when": "pytest.mark.topology args do not intersect run_context.topology.available_tags",
                "reason_template": (
                    "requires pytest.mark.topology args to intersect topology.available_tags, "
                    "current topology.available_tags={topology.available_tags}."
                ),
            },
            "evaluation": {
                "mode": "topology_marker_intersects_available_tags",
                "marker": "topology",
                "conditions": conditions,
            },
            "catalog": {
                "source_mode": source_mode,
                "matched_reason_patterns": sorted(matched_patterns),
            },
        }

    conditions = [
        condition_from_trigger_parameter(path, value)
        for path, value in sorted((rule.get("parameters") or {}).items())
    ]
    reason_template = "matches hardware-aware catalog rule {}; current setup has triggering parameters.".format(rule_id)
    if conditions:
        first = conditions[0]
        reason_template = "skip rule {} triggered by {{{}}}.".format(rule_id, first["path"])

    return {
        "id": "candidate_{}_from_catalog".format(safe_id(rule_id)),
        "bucket_id": rule_id,
        "source_normalized_reason_id": rule_id,
        "raw_skip_reason": raw_reasons[0],
        "raw_skip_reason_variants": raw_reasons if len(raw_reasons) > 1 else None,
        "candidate_status": candidate_status,
        "confidence": confidence,
        "approved_for": "catalog",
        "selector_strategy": selector_strategy,
        "selector_note": selector_note,
        "source_areas": source_areas(nodeids),
        "source_skipped_test_instances": source_instances,
        "applies_to": selector,
        "decision": {
            "deselect_when": "current run context matches hardware-aware catalog trigger parameters",
            "reason_template": reason_template,
        },
        "evaluation": {
            "mode": "all",
            "conditions": conditions,
        },
        "catalog": {
            "source_mode": source_mode,
            "matched_reason_patterns": sorted(matched_patterns),
        },
    }


def nodeid_to_file(nodeid):
    path = nodeid.split("::", 1)[0]
    if path.startswith("tests/"):
        path = path[len("tests/"):]
    return path


def build_setup_only_outputs(
    catalog,
    setup_profiles,
    setup_key,
    setup_input_doc=None,
    parameter_overrides=None,
    run_id=None,
    source_report_url=None,
    include_topology_rules=False,
):
    setup_profiles = setup_profiles_for_resolution(catalog, setup_profiles, setup_key)
    requested_setup_key = setup_key
    setup_key, setup = materialize_setup(
        setup_profiles,
        setup_key=setup_key,
        setup_input_doc=setup_input_doc,
    )
    setup_merge_mode = (
        "override_profile" if setup_input_doc is not None and requested_setup_key
        else "input_only" if setup_input_doc is not None
        else "profile_only"
    )
    setup, platform_decode = apply_platform_catalog(setup_profiles, setup_key, setup)
    setup, topology_inference = apply_topology_inferences(setup_key, setup)
    setup = apply_parameter_overrides(setup, parameter_overrides)
    setup_parameters = setup.get("parameters") or {}
    rules = catalog.get("skip_rules", {})

    test_capabilities = []
    not_applicable = []
    missing_selectors = []
    skipped_topology_rules = []

    for rule_id, rule in sorted(rules.items()):
        if not rule_enabled(rule):
            if is_topology_marker_rule(rule) and include_topology_rules:
                pass
            else:
                skipped_topology_rules.append({
                    "rule_id": rule_id,
                    "reason": rule_disabled_reason(rule),
                })
                continue

        if (
            is_topology_marker_rule(rule)
            and "enabled" not in rule
            and not include_topology_rules
        ):
            skipped_topology_rules.append({
                "rule_id": rule_id,
                "reason": (
                    "setup-only generation skips topology marker rules without explicit "
                    "enabled=true because existing SONiC custom markers already "
                    "handle topology gating"
                ),
            })
            continue

        matched, missing, mismatched = setup_matches_parameters(
            setup_parameters,
            rule.get("parameters") or {},
        )
        if not matched:
            not_applicable.append({
                "rule_id": rule_id,
                "missing_parameters": missing,
                "mismatched_parameters": mismatched,
            })
            continue

        selector, selector_strategy = selector_for_setup_only_rule(rule)
        if selector is None:
            missing_selectors.append({
                "rule_id": rule_id,
                "reason_patterns": rule.get("reason_patterns") or [],
                "note": "setup-only generation needs tests selectors or a supported structured evaluation mode",
            })
            continue

        reason_patterns = sorted(rule.get("reason_patterns") or [rule_id])
        test_capabilities.append(build_test_capability(
            rule_id,
            rule,
            [],
            reason_patterns,
            reason_patterns,
            selector=selector,
            selector_strategy=selector_strategy,
            source_mode="setup_only",
        ))

    test_capabilities_doc = OrderedDict()
    test_capabilities_doc["version"] = "hardware-aware-test-capabilities/v0.1"
    test_capabilities_doc["status"] = "candidate_test_capabilities_from_catalog_setup_only"
    test_capabilities_doc["source"] = {
        "mode": "setup_only",
        "catalog_schema": catalog.get("version"),
        "setup_profiles_schema": setup_profiles.get("version"),
        "setup": setup_key,
        "setup_input_used": setup_input_doc is not None,
        "setup_merge_mode": setup_merge_mode,
        "platform_decode": platform_decode,
        "topology_inference": topology_inference,
        "parameter_overrides": sorted((parameter_overrides or {}).keys()),
        "run_id": run_id,
        "allure_report_url": source_report_url,
    }
    test_capabilities_doc["notes"] = [
        "Generated from catalog setup profiles and skip rules only.",
        "No skipped-reason report was used. source_skipped_test_instances is 0 by design.",
        "This is a compatibility artifact for the current hardware-aware pytest plugin.",
    ]
    test_capabilities_doc["summary"] = {
        "generated_test_capabilities": len(test_capabilities),
        "source_skipped_test_instances": 0,
        "unmapped_reasons": 0,
        "not_applicable_rules": len(not_applicable),
        "missing_selector_rules": len(missing_selectors),
        "skipped_topology_rules": len(skipped_topology_rules),
        "ambiguous_reasons": 0,
    }
    test_capabilities_doc["test_capabilities"] = test_capabilities

    run_context = build_run_context(
        catalog,
        setup_profiles,
        setup_key,
        setup,
        setup_input_used=setup_input_doc is not None,
        setup_merge_mode=setup_merge_mode,
        platform_decode=platform_decode,
    )
    if run_id:
        run_context.setdefault("run", {})
        run_context["run"]["id"] = run_id

    audit = {
        "version": "hardware-aware-catalog-audit/v0.1",
        "setup": setup_key,
        "mode": "setup_only",
        "setup_input_used": setup_input_doc is not None,
        "platform_decode": platform_decode,
        "topology_inference": topology_inference,
        "parameter_overrides": sorted((parameter_overrides or {}).keys()),
        "summary": {
            "raw_reasons": 0,
            "generated_test_capabilities": len(test_capabilities),
            "generated_source_instances": 0,
            "unmapped_reasons": 0,
            "not_applicable_rules": len(not_applicable),
            "missing_selector_rules": len(missing_selectors),
            "skipped_topology_rules": len(skipped_topology_rules),
            "ambiguous_reasons": 0,
            "target_files": 0,
        },
        "not_applicable_rules": not_applicable,
        "missing_selector_rules": missing_selectors,
        "skipped_topology_rules": skipped_topology_rules,
        "matched_rules": [
            {
                "rule_id": tc["bucket_id"],
                "selector_strategy": tc["selector_strategy"],
                "source_mode": "setup_only",
            }
            for tc in test_capabilities
        ],
    }

    return test_capabilities_doc, run_context, audit, []


def build_outputs(
    catalog,
    setup_profiles,
    setup_key,
    raw_skips,
    setup_input_doc=None,
    parameter_overrides=None,
    run_id=None,
    source_report_url=None,
    include_topology_rules=False,
):
    if raw_skips is None:
        return build_setup_only_outputs(
            catalog,
            setup_profiles,
            setup_key,
            setup_input_doc=setup_input_doc,
            parameter_overrides=parameter_overrides,
            run_id=run_id,
            source_report_url=source_report_url,
            include_topology_rules=include_topology_rules,
        )

    setup_profiles = setup_profiles_for_resolution(catalog, setup_profiles, setup_key)
    requested_setup_key = setup_key
    setup_key, setup = materialize_setup(
        setup_profiles,
        setup_key=setup_key,
        setup_input_doc=setup_input_doc,
    )
    setup_merge_mode = (
        "override_profile" if setup_input_doc is not None and requested_setup_key
        else "input_only" if setup_input_doc is not None
        else "profile_only"
    )
    setup, platform_decode = apply_platform_catalog(setup_profiles, setup_key, setup)
    setup, topology_inference = apply_topology_inferences(setup_key, setup)
    setup = apply_parameter_overrides(setup, parameter_overrides)
    setup_parameters = setup.get("parameters") or {}
    rules = catalog.get("skip_rules", {})
    normalized_raw = normalize_raw_skips(raw_skips)

    per_rule = {}
    unmapped = []
    not_applicable = []
    ambiguous = []

    for reason, nodeids in sorted(normalized_raw.items()):
        matches = []
        for rule_id, rule in sorted(rules.items()):
            pattern = reason_matches_rule(reason, rule)
            if pattern:
                matches.append((rule_id, rule, pattern))

        if not matches:
            unmapped.append({
                "reason": reason,
                "count": len(nodeids),
                "sample_tests": nodeids[:5],
            })
            continue
        if len(matches) > 1:
            ambiguous.append({
                "reason": reason,
                "count": len(nodeids),
                "matched_rules": [rule_id for rule_id, _, _ in matches],
            })

        for rule_id, rule, pattern in matches[:1]:
            matched, missing, mismatched = setup_matches_parameters(
                setup_parameters,
                rule.get("parameters") or {},
            )
            if not matched:
                not_applicable.append({
                    "reason": reason,
                    "count": len(nodeids),
                    "rule_id": rule_id,
                    "missing_parameters": missing,
                    "mismatched_parameters": mismatched,
                })
                continue

            bucket = per_rule.setdefault(rule_id, {
                "rule": rule,
                "nodeids": [],
                "raw_reasons": [],
                "matched_patterns": [],
            })
            bucket["nodeids"].extend(nodeids)
            if reason not in bucket["raw_reasons"]:
                bucket["raw_reasons"].append(reason)
            if pattern not in bucket["matched_patterns"]:
                bucket["matched_patterns"].append(pattern)

    test_capabilities = []
    target_files = set()
    for rule_id, bucket in sorted(per_rule.items()):
        nodeids = sorted(dict.fromkeys(bucket["nodeids"]))
        if not nodeids:
            continue
        for nodeid in nodeids:
            target_files.add(nodeid_to_file(nodeid))
        test_capabilities.append(build_test_capability(
            rule_id,
            bucket["rule"],
            nodeids,
            sorted(bucket["raw_reasons"]),
            sorted(bucket["matched_patterns"]),
        ))

    test_capabilities_doc = OrderedDict()
    test_capabilities_doc["version"] = "hardware-aware-test-capabilities/v0.1"
    test_capabilities_doc["status"] = "candidate_test_capabilities_from_catalog"
    test_capabilities_doc["source"] = {
        "mode": "report_seeded",
        "catalog_schema": catalog.get("version"),
        "setup_profiles_schema": setup_profiles.get("version"),
        "setup": setup_key,
        "setup_input_used": setup_input_doc is not None,
        "setup_merge_mode": setup_merge_mode,
        "platform_decode": platform_decode,
        "topology_inference": topology_inference,
        "parameter_overrides": sorted((parameter_overrides or {}).keys()),
        "run_id": run_id,
        "allure_report_url": source_report_url,
    }
    test_capabilities_doc["notes"] = [
        "Generated from catalog YAML and observed skipped-reason nodeids.",
        "This is a compatibility artifact for the current hardware-aware pytest plugin.",
    ]
    test_capabilities_doc["summary"] = {
        "generated_test_capabilities": len(test_capabilities),
        "source_skipped_test_instances": sum(tc["source_skipped_test_instances"] for tc in test_capabilities),
        "unmapped_reasons": len(unmapped),
        "not_applicable_reasons": len(not_applicable),
        "ambiguous_reasons": len(ambiguous),
    }
    test_capabilities_doc["test_capabilities"] = test_capabilities

    run_context = build_run_context(
        catalog,
        setup_profiles,
        setup_key,
        setup,
        setup_input_used=setup_input_doc is not None,
        setup_merge_mode=setup_merge_mode,
        platform_decode=platform_decode,
    )
    if run_id:
        run_context.setdefault("run", {})
        run_context["run"]["id"] = run_id

    audit = {
        "version": "hardware-aware-catalog-audit/v0.1",
        "setup": setup_key,
        "mode": "report_seeded",
        "setup_input_used": setup_input_doc is not None,
        "platform_decode": platform_decode,
        "topology_inference": topology_inference,
        "parameter_overrides": sorted((parameter_overrides or {}).keys()),
        "summary": {
            "raw_reasons": len(normalized_raw),
            "generated_test_capabilities": len(test_capabilities),
            "generated_source_instances": test_capabilities_doc["summary"]["source_skipped_test_instances"],
            "unmapped_reasons": len(unmapped),
            "not_applicable_reasons": len(not_applicable),
            "ambiguous_reasons": len(ambiguous),
            "target_files": len(target_files),
        },
        "unmapped_reasons": unmapped,
        "not_applicable_reasons": not_applicable,
        "ambiguous_reasons": ambiguous,
        "matched_rules": [
            {
                "rule_id": tc["bucket_id"],
                "source_skipped_test_instances": tc["source_skipped_test_instances"],
                "raw_skip_reason": tc["raw_skip_reason"],
            }
            for tc in test_capabilities
        ],
    }

    return test_capabilities_doc, run_context, audit, sorted(target_files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True, help="Hardware-aware skip-rule catalog YAML.")
    parser.add_argument(
        "--setup-profiles",
        help="Setup profiles YAML. If omitted, setups are read from --catalog for backward compatibility.",
    )
    parser.add_argument(
        "--setup",
        help=(
            "Setup key or setup alias from setup profiles. Optional when --setup-input "
            "provides a complete setup."
        ),
    )
    parser.add_argument(
        "--setup-input",
        help=(
            "Optional user setup YAML. If --setup is also provided, this file overrides "
            "the selected setup profile. If --setup is omitted, this file must provide a complete setup."
        ),
    )
    parser.add_argument(
        "--raw-skips",
        help=(
            "Optional raw skipped-reasons JSON from Allure extraction. "
            "When omitted, generate setup-only inputs from setup profiles and skip rules."
        ),
    )
    parser.add_argument(
        "--include-topology-rules",
        action="store_true",
        help=(
            "In setup-only mode, also generate topology marker rules. "
            "By default these are skipped because SONiC custom markers already handle topology gating."
        ),
    )
    parser.add_argument("--run-id", help="Run id recorded in generated artifacts.")
    parser.add_argument("--source-report-url", help="Allure report URL recorded in generated artifacts.")
    parser.add_argument("--test-capabilities-output", required=True)
    parser.add_argument("--run-context-output")
    parser.add_argument("--audit-output")
    parser.add_argument("--target-files-output")
    args = parser.parse_args()

    catalog = load_yaml(args.catalog)
    setup_profiles = load_yaml(args.setup_profiles) if args.setup_profiles else None
    setup_input_doc = load_yaml(args.setup_input) if args.setup_input else None
    raw_skips = load_json(args.raw_skips) if args.raw_skips else None
    test_capabilities, run_context, audit, target_files = build_outputs(
        catalog,
        setup_profiles,
        args.setup,
        raw_skips,
        setup_input_doc=setup_input_doc,
        run_id=args.run_id,
        source_report_url=args.source_report_url,
        include_topology_rules=args.include_topology_rules,
    )

    write_json(args.test_capabilities_output, test_capabilities)
    if args.run_context_output:
        write_json(args.run_context_output, run_context)
    if args.audit_output:
        write_json(args.audit_output, audit)
    if args.target_files_output:
        write_lines(args.target_files_output, target_files)

    print(json.dumps(audit["summary"], indent=2, sort_keys=True))
    print("wrote {}".format(args.test_capabilities_output))
    if args.run_context_output:
        print("wrote {}".format(args.run_context_output))
    if args.audit_output:
        print("wrote {}".format(args.audit_output))
    if args.target_files_output:
        print("wrote {}".format(args.target_files_output))


if __name__ == "__main__":
    main()
