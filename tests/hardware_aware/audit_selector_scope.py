#!/usr/bin/env python3
"""Audit whether catalog test selectors are too narrow or too broad.

This script does not generate runtime inputs and does not change deselection
behavior. It compares the human-maintained tests selectors in
skip_rules.yaml with observed skipped nodeids from an Allure
extraction and, when available, collected nodeids from a hardware-aware
report-only/deselect JSON.
"""

import argparse
import json
import re
import sys
from collections import OrderedDict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from generate_runtime_inputs import (  # noqa: E402
    load_json,
    load_yaml,
    normalize_raw_skips,
    reason_matches_rule,
    selector_from_catalog_tests,
    selector_from_observed_nodeids,
    setup_matches_parameters,
)


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")


def normalize_nodeid(nodeid):
    nodeid = str(nodeid)
    if nodeid.startswith("tests/"):
        return nodeid
    return "tests/" + nodeid


def base_nodeid(nodeid):
    """Return nodeid without the final parametrization bracket.

    This is intentionally a secondary audit key. Exact nodeids catch parameter
    over-selection, while base nodeids help distinguish real over-selection from
    run-specific parameter labels such as sup-t0-dut vs superbolt-01.
    """
    return re.sub(r"\[[^\]]*\]$", "", normalize_nodeid(nodeid))


def selector_matches(selector, nodeid):
    nodeid = normalize_nodeid(nodeid)
    candidates = [nodeid, nodeid[len("tests/"):]]

    selector_type = selector["type"]
    if selector_type == "path_prefix":
        prefix = selector["prefix"]
        return any(candidate.startswith(prefix) for candidate in candidates)
    if selector_type == "regex":
        pattern = re.compile(selector["pattern"])
        return any(pattern.search(candidate) for candidate in candidates)
    if selector_type == "pytest_marker":
        return None

    raise SystemExit("Unsupported selector type in audit: {}".format(selector_type))


def resolve_setup(setup_profiles, setup_key):
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


def load_collected_nodeids(report_paths):
    collected = []
    reports = []

    for path in report_paths or []:
        report = load_json(path)
        nodeids = report.get("collected_nodeids")
        source = "collected_nodeids"

        if nodeids is None:
            decisions = report.get("decisions") or []
            nodeids = [decision["nodeid"] for decision in decisions if decision.get("nodeid")]
            source = "decisions_nodeids_only"

        nodeids = [normalize_nodeid(nodeid) for nodeid in nodeids or []]
        collected.extend(nodeids)
        reports.append({
            "path": str(path),
            "nodeids": len(nodeids),
            "source": source,
        })

    return sorted(dict.fromkeys(collected)), reports


def build_observed_by_rule(catalog, normalized_raw):
    observed_by_rule = OrderedDict()
    unmapped_reasons = []
    ambiguous_reasons = []

    for reason, nodeids in sorted(normalized_raw.items()):
        matches = []
        for rule_id, rule in sorted((catalog.get("skip_rules") or {}).items()):
            pattern = reason_matches_rule(reason, rule)
            if pattern:
                matches.append((rule_id, rule, pattern))

        if not matches:
            unmapped_reasons.append({
                "reason": reason,
                "count": len(nodeids),
                "sample_tests": nodeids[:5],
            })
            continue

        if len(matches) > 1:
            ambiguous_reasons.append({
                "reason": reason,
                "count": len(nodeids),
                "matched_rules": [rule_id for rule_id, _, _ in matches],
            })

        rule_id, _, _ = matches[0]
        bucket = observed_by_rule.setdefault(rule_id, {
            "raw_reasons": [],
            "nodeids": [],
        })
        bucket["raw_reasons"].append(reason)
        bucket["nodeids"].extend(normalize_nodeid(nodeid) for nodeid in nodeids)

    for bucket in observed_by_rule.values():
        bucket["raw_reasons"] = sorted(dict.fromkeys(bucket["raw_reasons"]))
        bucket["nodeids"] = sorted(dict.fromkeys(bucket["nodeids"]))

    return observed_by_rule, unmapped_reasons, ambiguous_reasons


def audit_rule(rule_id, rule, observed_nodeids, setup_parameters, collected_nodeids):
    matched, missing, mismatched = setup_matches_parameters(
        setup_parameters,
        rule.get("parameters") or {},
    )
    selector, selector_strategy = selector_from_catalog_tests(rule)
    if selector is None:
        selector, selector_strategy = selector_from_observed_nodeids(observed_nodeids)

    result = OrderedDict()
    result["rule_id"] = rule_id
    result["selector_strategy"] = selector_strategy
    result["selector"] = selector
    result["observed_skipped_nodeids"] = len(observed_nodeids)
    result["setup_applicable"] = matched
    result["missing_parameters"] = missing
    result["mismatched_parameters"] = mismatched

    if selector["type"] == "pytest_marker":
        result["status"] = "marker_selector_not_checked_by_nodeid"
        result["note"] = (
            "Marker selectors need pytest collection metadata. Validate this rule "
            "with the hardware-aware report decisions instead of nodeid prefix checks."
        )
        return result

    under_matched = [
        nodeid for nodeid in observed_nodeids
        if not selector_matches(selector, nodeid)
    ]
    result["under_matched_observed_nodeids"] = len(under_matched)
    result["under_matched_examples"] = under_matched[:10]

    if collected_nodeids:
        selected_collected = [
            nodeid for nodeid in collected_nodeids
            if selector_matches(selector, nodeid)
        ]
        observed_set = set(observed_nodeids)
        observed_base_set = set(base_nodeid(nodeid) for nodeid in observed_nodeids)
        over_selected = [
            nodeid for nodeid in selected_collected
            if nodeid not in observed_set
        ]
        base_over_selected = [
            nodeid for nodeid in selected_collected
            if base_nodeid(nodeid) not in observed_base_set
        ]
        result["selected_collected_nodeids"] = len(selected_collected)
        result["over_selected_collected_nodeids"] = len(over_selected)
        result["over_selected_examples"] = over_selected[:10]
        result["base_over_selected_collected_nodeids"] = len(base_over_selected)
        result["base_over_selected_examples"] = base_over_selected[:10]
    else:
        result["selected_collected_nodeids"] = None
        result["over_selected_collected_nodeids"] = None
        result["over_selected_examples"] = []
        result["base_over_selected_collected_nodeids"] = None
        result["base_over_selected_examples"] = []

    if under_matched:
        result["status"] = "under_match"
    elif result["base_over_selected_collected_nodeids"]:
        result["status"] = "over_select_review"
    elif collected_nodeids:
        result["status"] = "ok"
    else:
        result["status"] = "under_match_checked_only"

    return result


def build_audit(catalog, setup_profiles, setup_key, raw_skips, collected_nodeids, report_inputs):
    setup_profiles = setup_profiles or catalog
    resolved_setup_key, setup = resolve_setup(setup_profiles, setup_key)
    setup_parameters = setup.get("parameters") or {}
    normalized_raw = normalize_raw_skips(raw_skips)
    observed_by_rule, unmapped, ambiguous = build_observed_by_rule(catalog, normalized_raw)

    rules = []
    skipped_not_applicable = []
    for rule_id, observed in sorted(observed_by_rule.items()):
        rule = (catalog.get("skip_rules") or {})[rule_id]
        audit = audit_rule(
            rule_id,
            rule,
            observed["nodeids"],
            setup_parameters,
            collected_nodeids,
        )
        audit["raw_reasons"] = observed["raw_reasons"]
        rules.append(audit)

        if not audit["setup_applicable"]:
            skipped_not_applicable.append(rule_id)

    status_counts = {}
    for rule in rules:
        status_counts[rule["status"]] = status_counts.get(rule["status"], 0) + 1

    summary = OrderedDict()
    summary["setup"] = resolved_setup_key
    summary["raw_reasons"] = len(normalized_raw)
    summary["rules_with_observed_skips"] = len(rules)
    summary["rules_not_applicable_to_setup"] = len(skipped_not_applicable)
    summary["collected_nodeids"] = len(collected_nodeids)
    summary["status_counts"] = dict(sorted(status_counts.items()))
    summary["under_match_rules"] = sum(1 for rule in rules if rule["status"] == "under_match")
    summary["over_select_review_rules"] = sum(1 for rule in rules if rule["status"] == "over_select_review")
    summary["exact_over_select_debug_rules"] = sum(
        1 for rule in rules
        if rule.get("over_selected_collected_nodeids")
    )
    summary["base_over_select_review_rules"] = sum(
        1 for rule in rules
        if rule.get("base_over_selected_collected_nodeids")
    )
    summary["marker_selector_rules"] = sum(
        1 for rule in rules if rule["status"] == "marker_selector_not_checked_by_nodeid"
    )
    summary["unmapped_reasons"] = len(unmapped)
    summary["ambiguous_reasons"] = len(ambiguous)

    return OrderedDict([
        ("version", "hardware-aware-selector-scope-audit/v0.1"),
        ("summary", summary),
        ("inputs", {
            "setup": setup_key,
            "resolved_setup": resolved_setup_key,
            "catalog_schema": catalog.get("version"),
            "setup_profiles_schema": setup_profiles.get("version"),
            "collected_reports": report_inputs,
        }),
        ("rules", rules),
        ("unmapped_reasons", unmapped),
        ("ambiguous_reasons", ambiguous),
    ])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True, help="catalog YAML file.")
    parser.add_argument(
        "--setup-profiles",
        help="Setup profiles YAML. If omitted, setups are read from --catalog for backward compatibility.",
    )
    parser.add_argument("--setup", required=True, help="Setup key or alias from setup profiles.")
    parser.add_argument("--raw-skips", required=True, help="Raw skipped-reasons JSON from Allure extraction.")
    parser.add_argument(
        "--collected-report",
        action="append",
        default=[],
        help="Hardware-aware report-only/deselect JSON containing collected_nodeids. Can be repeated.",
    )
    parser.add_argument("--output", required=True, help="Path to write selector scope audit JSON.")
    args = parser.parse_args()

    catalog = load_yaml(args.catalog)
    setup_profiles = load_yaml(args.setup_profiles) if args.setup_profiles else None
    raw_skips = load_json(args.raw_skips)
    collected_nodeids, report_inputs = load_collected_nodeids(args.collected_report)
    audit = build_audit(catalog, setup_profiles, args.setup, raw_skips, collected_nodeids, report_inputs)
    write_json(args.output, audit)

    print(json.dumps(audit["summary"], indent=2, sort_keys=True))
    print("wrote {}".format(args.output))


if __name__ == "__main__":
    main()
