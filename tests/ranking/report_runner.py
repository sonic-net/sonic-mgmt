"""Build offline Ranking reports from archived controller artifacts."""

import argparse
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import uuid

if __package__:
    from .report import aggregate_capability, render_capability, render_spec
else:
    from report import aggregate_capability, render_capability, render_spec


INPUTS = ("spec_registry.json", "skeleton.json", "enum_values.json", "attr_map.json")
MANDATORY_RUN_FILES = (
    "outcome.json", "stdout.log", "stderr.log", *INPUTS,
    "case-id.txt", "collection-status.json",
)
COLLECTION_STATUS_FIELDS = frozenset({
    "schema_version", "environment_id", "run_id", "case",
    "outcome_fetched", "stdout_fetched", "stderr_fetched",
    "case_id_fetched", "collector", "batch_inputs", "collection_errors",
})
ROLE_OUTCOME_FIELDS = frozenset({
    "schema_version", "environment_id", "run_id", "case", "collected",
    "collection_errors", "case_rc", "case_error",
})
COLLECTOR_STATUS_FIELDS = frozenset({"name", "present", "fetched"})
CASE_ID = re.compile(r"^[A-Za-z_]\w*\.[A-Za-z_]\w*$")
COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
SKELETON_OPS = frozenset(("create", "set", "read"))
COLLECTOR_FIELDS = {
    "test_module": str,
    "test_class": str,
    "timestamp": str,
    "duration_seconds": (int, float, type(None)),
    "overall_result": str,
    "error_message": (str, type(None)),
    "metadata": dict,
    "spec_results": list,
    "attr_records": list,
}


class InputError(ValueError):
    """An archived artifact violates the report input contract."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: {}".format(key))
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("invalid JSON constant: {}".format(value))


def _read_json(path):
    try:
        with path.open(encoding="utf-8") as stream:
            value = json.load(stream, object_pairs_hook=_unique_object,
                              parse_constant=_reject_constant)
        _strict_value(value)
        return value
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        raise InputError("cannot load {}: {}".format(path, error)) from error


def _strict_value(value):
    if value is None or type(value) in (bool, int, str):
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return
    if type(value) is list:
        for child in value:
            _strict_value(child)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for child in value.values():
            _strict_value(child)
        return
    raise ValueError("unsupported JSON value")


def _json_text(value):
    _strict_value(value)
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True,
                      allow_nan=False) + "\n"


def _atomic_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=".{}-".format(path.name), dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _atomic_json(path, value):
    _atomic_text(path, _json_text(value))


def _safe_directory(path, create=False):
    if create:
        path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir() or path.is_symlink() or path.resolve() != path:
        raise InputError("unsafe directory: {}".format(path))


def _remove_tree(path):
    """Remove a tree without following any symlink found in it."""
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
        os.unlink(path)
        return
    with os.scandir(path) as entries:
        for entry in entries:
            _remove_tree(Path(entry.path))
    os.rmdir(path)


def _is_report_path(path, root):
    relative = path.relative_to(root)
    if not relative.parts:
        return False
    first = relative.parts[0]
    return first in ("report", "report-input") or first.startswith(
        ".report-input-")


def _source_files(root, name):
    files = []
    for path in root.rglob(name):
        if _is_report_path(path, root):
            continue
        if path.is_symlink() or not path.is_file() or path.resolve() != path:
            raise InputError("unsafe artifact path: {}".format(path))
        files.append(path)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def _require_fields(value, fields, label):
    if type(value) is not dict:
        raise InputError("{} is not an object".format(label))
    for name, types in fields.items():
        if name not in value or not isinstance(value[name], types):
            raise InputError("{}.{} is missing or has the wrong type".format(
                label, name))


def _exact_fields(value, fields, label):
    if type(value) is not dict or set(value) != fields:
        raise InputError("{} must have exact fields: {}".format(
            label, ", ".join(sorted(fields))))


def _error_map(value, label):
    if type(value) is not dict:
        raise InputError("{} must be an object".format(label))
    for name, message in value.items():
        if type(name) is not str or not name or type(message) is not str or not message:
            raise InputError("{} must map non-empty names to messages".format(label))


def _regular_sibling(run_dir, name):
    path = run_dir / name
    if (not os.path.lexists(path) or path.is_symlink() or not path.is_file() or
            path.resolve() != path):
        raise InputError("required run artifact is not a regular sibling file: {}".format(
            path))
    return path


def _validate_outcome(value, path):
    _require_fields(value, {
        "phase": str,
        "argv": list,
        "timeout_s": int,
        "rc": (int, type(None)),
        "timed_out": bool,
        "process_exited": bool,
    }, "outcome")
    if value["phase"] != "ptf":
        raise InputError("{} has a non-PTF phase".format(path))
    if (not value["argv"] or
            any(type(argument) is not str for argument in value["argv"])):
        raise InputError("{} has invalid argv".format(path))
    if type(value["timeout_s"]) is not int or value["timeout_s"] <= 0:
        raise InputError("{} has invalid timeout_s".format(path))
    if (value["rc"] is not None and type(value["rc"]) is not int) or \
            (value["rc"] is None and value["process_exited"]):
        raise InputError("{} has invalid rc".format(path))
    if "container_id" in value and (
            type(value["container_id"]) is not str or
            re.fullmatch(r"[0-9a-f]{64}", value["container_id"]) is None):
        raise InputError("{} has invalid container provenance".format(path))
    if "error" in value and not isinstance(value["error"], str):
        raise InputError("{} has invalid error".format(path))


def _case_from_outcome(outcome, path):
    indexes = [index for index, value in enumerate(outcome["argv"])
               if value == "--test-dir"]
    if len(indexes) != 1 or indexes[0] + 2 >= len(outcome["argv"]):
        raise InputError("{} does not identify one PTF case".format(path))
    case = outcome["argv"][indexes[0] + 2]
    if CASE_ID.fullmatch(case) is None:
        raise InputError("{} has invalid case identity: {}".format(path, case))
    return case


def _validate_collector(value, case, path):
    _require_fields(value, COLLECTOR_FIELDS, "collector")
    identity = "{}.{}".format(value["test_module"], value["test_class"])
    if identity != case:
        raise InputError("collector case identity differs from {}: {}".format(
            case, path))
    expected_name = "{}_{}.json".format(value["test_module"], value["test_class"])
    if path.name != expected_name:
        raise InputError("collector filename does not match its case: {}".format(path))
    if value["overall_result"] not in ("PASS", "FAIL"):
        raise InputError("collector.overall_result is invalid: {}".format(path))
    if isinstance(value["duration_seconds"], bool):
        raise InputError("collector.duration_seconds is invalid: {}".format(path))

    for index, spec in enumerate(value["spec_results"]):
        label = "spec_results[{}]".format(index)
        _require_fields(spec, {
            "spec_name": str,
            "operation": (str, type(None)),
            "value": (str, int, float, type(None)),
            "threshold": (int, float, type(None)),
            "details": dict,
        }, label)
        if isinstance(spec["threshold"], bool):
            raise InputError("{}.threshold is invalid: {}".format(label, path))

    for index, row in enumerate(value["attr_records"]):
        label = "attr_records[{}]".format(index)
        _require_fields(row, {
            "case": str,
            "attr": str,
            "op": str,
            "value": (str, int, float, bool, type(None)),
        }, label)
        if row["case"] != case:
            raise InputError("{}.case differs from {}: {}".format(label, case, path))


def _run_identity(root, outcome_path, outcome):
    relative = outcome_path.relative_to(root)
    if len(relative.parts) != 4 or relative.parts[-1] != "outcome.json":
        raise InputError(
            "outcome path must be <run>/<environment>/<run>/outcome.json: {}".format(
                outcome_path))
    outer_run_id, environment_id, run_id, _ = relative.parts
    for label, value in (("outer run", outer_run_id),
                         ("environment", environment_id), ("run", run_id)):
        if COMPONENT.fullmatch(value) is None:
            raise InputError("invalid {} identity in {}".format(label, outcome_path))
    if outer_run_id != run_id:
        raise InputError("outer and inner run identities differ in {}".format(
            outcome_path))
    if "run_id" in outcome and outcome["run_id"] != run_id:
        raise InputError("outcome run identity differs from its path: {}".format(
            outcome_path))
    if ("environment_id" in outcome and
            outcome["environment_id"] != environment_id):
        raise InputError(
            "outcome environment identity differs from its path: {}".format(
                outcome_path))
    return outer_run_id, environment_id, run_id


def _validate_collection_status(value, identity, case, path):
    _exact_fields(value, COLLECTION_STATUS_FIELDS, "collection-status")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise InputError("collection-status has an unsupported schema: {}".format(path))
    _, environment_id, run_id = identity
    expected = {
        "environment_id": environment_id,
        "run_id": run_id,
        "case": case,
    }
    for name, expected_value in expected.items():
        if type(value[name]) is not str or value[name] != expected_value:
            raise InputError(
                "collection-status.{} differs from path/case identity: {}".format(
                    name, path))
    flag_names = (
        "outcome_fetched", "stdout_fetched", "stderr_fetched", "case_id_fetched",
    )
    for name in flag_names:
        if type(value[name]) is not bool or not value[name]:
            raise InputError("collection-status.{} is not true: {}".format(name, path))
    batch = value["batch_inputs"]
    if type(batch) is not dict or set(batch) != set(INPUTS):
        raise InputError("collection-status.batch_inputs has invalid fields: {}".format(
            path))
    for name in INPUTS:
        if type(batch[name]) is not bool or not batch[name]:
            raise InputError(
                "collection-status.batch_inputs.{} is not true: {}".format(name, path))
    collector = value["collector"]
    _exact_fields(collector, COLLECTOR_STATUS_FIELDS, "collection-status.collector")
    expected_collector = case.replace(".", "_") + ".json"
    if collector["name"] != expected_collector:
        raise InputError("collection-status collector name differs from case: {}".format(
            path))
    for name in ("present", "fetched"):
        if type(collector[name]) is not bool:
            raise InputError("collection-status.collector.{} is not boolean: {}".format(
                name, path))
    if collector["present"] != collector["fetched"]:
        raise InputError("collection-status collector presence/fetch mismatch: {}".format(
            path))
    _error_map(value["collection_errors"], "collection-status.collection_errors")
    if value["collection_errors"]:
        raise InputError("collection-status reports collection errors: {}".format(path))


def _validate_role_outcome(value, identity, case, status, path):
    _exact_fields(value, ROLE_OUTCOME_FIELDS, "role-outcome")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise InputError("role-outcome has an unsupported schema: {}".format(path))
    _, environment_id, run_id = identity
    expected = {
        "environment_id": environment_id,
        "run_id": run_id,
        "case": case,
    }
    for name, expected_value in expected.items():
        if type(value[name]) is not str or value[name] != expected_value:
            raise InputError(
                "role-outcome.{} differs from path/case identity: {}".format(
                    name, path))
    if type(value["case_rc"]) is not int or type(value["case_error"]) is not str:
        raise InputError("role-outcome has invalid case result fields: {}".format(path))
    collector_name = status["collector"]["name"]
    required_flags = set(MANDATORY_RUN_FILES) | {collector_name}
    collected = value["collected"]
    if type(collected) is not dict or set(collected) != required_flags:
        raise InputError("role-outcome.collected has invalid fields: {}".format(path))
    for name, flag in collected.items():
        if type(flag) is not bool:
            raise InputError("role-outcome.collected.{} is not boolean: {}".format(
                name, path))
    for name in MANDATORY_RUN_FILES:
        if not collected[name]:
            raise InputError("role-outcome.collected.{} is not true: {}".format(name, path))
    if collected[collector_name] != status["collector"]["fetched"]:
        raise InputError("role-outcome collector flag differs from collection-status: {}".format(
            path))
    status_flags = {
        "outcome.json": status["outcome_fetched"],
        "stdout.log": status["stdout_fetched"],
        "stderr.log": status["stderr_fetched"],
        "case-id.txt": status["case_id_fetched"],
    }
    status_flags.update(status["batch_inputs"])
    for name, flag in status_flags.items():
        if collected[name] != flag:
            raise InputError("role-outcome flag differs from collection-status for {}: {}".format(
                name, path))
    _error_map(value["collection_errors"], "role-outcome.collection_errors")
    if value["collection_errors"]:
        raise InputError("role-outcome reports collection errors: {}".format(path))


def _log_text(run_dir):
    chunks = []
    for name in ("stdout.log", "stderr.log"):
        path = _regular_sibling(run_dir, name)
        try:
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError as error:
            raise InputError("cannot read {}: {}".format(path, error)) from error
    return "\n".join(chunks)


def _outcome_label(outcome, logs):
    if outcome["timed_out"] or outcome["rc"] == 124:
        return "TIMEOUT"
    if outcome.get("error") or not outcome["process_exited"]:
        return "ERROR"
    failed = re.search(r"(?m)^FAILED[^\r\n]*", logs)
    if failed and aggregate_capability.classify_outcome(failed.group(0)) == \
            aggregate_capability.NOT_SUPPORTED:
        return failed.group(0)
    skipped = re.search(r"skipped=(\d+)", logs)
    if skipped is None:
        skipped = re.search(r"(?m)^Skipped (\d+) tests?\b", logs)
    if skipped:
        return "skipped={}".format(skipped.group(1))
    if outcome["rc"] == 0:
        return "OK"
    return "ERROR (rc={})".format(outcome["rc"])


def _collector_for_run(run_dir, case, status):
    expected_name = status["collector"]["name"]
    allowed_names = {name for name in MANDATORY_RUN_FILES if name.endswith('.json')}
    allowed_names.add(expected_name)
    for candidate in run_dir.rglob('*.json'):
        if (candidate.parent != run_dir or candidate.name not in allowed_names or
                candidate.is_symlink() or not candidate.is_file() or
                candidate.resolve() != candidate):
            raise InputError("unexpected or unsafe JSON artifact: {}".format(candidate))
    path = run_dir / expected_name
    exists = os.path.lexists(path)
    expected = status["collector"]["present"]
    if exists != expected:
        raise InputError("collector file presence differs from collection-status: {}".format(
            path))
    if not exists:
        return None, None
    if path.is_symlink() or not path.is_file() or path.resolve() != path:
        raise InputError("unsafe collector artifact path: {}".format(path))
    collector = _read_json(path)
    _validate_collector(collector, case, path)
    return path, collector


def _role_outcomes(root):
    roles = {}
    for path in _source_files(root, "role-outcome.json"):
        value = _read_json(path)
        has_run_id = "run_id" in value if type(value) is dict else False
        has_case = "case" in value if type(value) is dict else False
        if not has_run_id and not has_case:
            continue
        if not has_run_id or not has_case:
            raise InputError("partial run identity in role outcome: {}".format(path))
        relative = path.relative_to(root)
        if len(relative.parts) != 2 or relative.parts[-1] != "role-outcome.json":
            raise InputError(
                "run role outcome path must be <run>/role-outcome.json: {}".format(
                    path))
        outer_run_id = relative.parts[0]
        if COMPONENT.fullmatch(outer_run_id) is None:
            raise InputError("invalid run identity in {}".format(path))
        if outer_run_id in roles:
            raise InputError("duplicate role outcome for run {}".format(outer_run_id))
        roles[outer_run_id] = (path, value)
    return roles


def _discover_runs(root):
    outcome_paths = _source_files(root, "outcome.json")
    if not outcome_paths:
        raise InputError("no archived outcome.json records")
    roles = _role_outcomes(root)
    runs = []
    identities = set()
    cases = set()
    used_roles = set()
    for path in outcome_paths:
        outcome = _read_json(path)
        _validate_outcome(outcome, path)
        identity = _run_identity(root, path, outcome)
        if identity in identities:
            raise InputError("duplicate run identity: {} / {} / {}".format(*identity))
        identities.add(identity)
        case = _case_from_outcome(outcome, path)
        if case in cases:
            raise InputError("duplicate case record: {}".format(case))
        cases.add(case)
        run_dir = path.parent
        siblings = {name: _regular_sibling(run_dir, name)
                    for name in MANDATORY_RUN_FILES}
        try:
            case_id = siblings["case-id.txt"].read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise InputError("cannot read {}: {}".format(
                siblings["case-id.txt"], error)) from error
        if case_id != case + "\n":
            raise InputError("case-id.txt does not exactly match {}: {}".format(
                case, siblings["case-id.txt"]))
        status_path = siblings["collection-status.json"]
        status = _read_json(status_path)
        _validate_collection_status(status, identity, case, status_path)
        outer_run_id = identity[0]
        if outer_run_id not in roles:
            raise InputError("missing role outcome for run {}".format(outer_run_id))
        role_path, role = roles[outer_run_id]
        _validate_role_outcome(role, identity, case, status, role_path)
        used_roles.add(outer_run_id)
        collector_path, collector = _collector_for_run(run_dir, case, status)
        runs.append({
            "identity": identity,
            "case": case,
            "outcome": outcome,
            "outcome_path": path,
            "collector": collector,
            "collector_path": collector_path,
            "label": _outcome_label(outcome, _log_text(run_dir)),
        })
    unused_roles = sorted(set(roles) - used_roles)
    if unused_roles:
        raise InputError("role outcomes without matching runs: {}".format(
            ", ".join(unused_roles)))
    return runs


def _validate_skeleton(value):
    if type(value) is not dict or type(value.get("cells")) is not list:
        raise InputError("skeleton.json has an invalid cell set")
    cells = value["cells"]
    if "denominator" in value:
        denominator = value["denominator"]
        if type(denominator) is not int or denominator != len(cells):
            raise InputError("skeleton.json has an invalid denominator")
    for index, cell in enumerate(cells):
        label = "skeleton.json cells[{}]".format(index)
        if type(cell) is not dict:
            raise InputError("{} is not an object".format(label))
        if "attr" not in cell or type(cell["attr"]) is not str:
            raise InputError("{}.attr is missing or has the wrong type".format(label))
        if cell.get("op") not in SKELETON_OPS or type(cell.get("op")) is not str:
            raise InputError("{}.op is invalid".format(label))
        if "value" not in cell or type(cell["value"]) not in (
                type(None), bool, int, float, str):
            raise InputError("{}.value is not a JSON scalar or null".format(label))
        if type(cell["value"]) is float and not math.isfinite(cell["value"]):
            raise InputError("{}.value is not finite".format(label))
        if "enum_type" not in cell or type(cell["enum_type"]) not in (
                type(None), str):
            raise InputError("{}.enum_type is missing or has the wrong type".format(
                label))


def _load_inputs(root):
    values = {}
    for name in INPUTS:
        paths = _source_files(root, name)
        if not paths:
            raise InputError("missing copied batch input: {}".format(name))
        documents = [_read_json(path) for path in paths]
        canonical = [_json_text(document) for document in documents]
        if any(text != canonical[0] for text in canonical[1:]):
            raise InputError("{} differs across archived copies".format(name))
        values[name] = documents[0]
    _validate_skeleton(values["skeleton.json"])
    if type(values["enum_values.json"]) is not dict:
        raise InputError("enum_values.json is not an object")
    if type(values["spec_registry.json"]) is not dict:
        raise InputError("spec_registry.json is not an object")
    if type(values["attr_map.json"]) is not dict:
        raise InputError("attr_map.json is not an object")
    return values


def _validated_expected(expected_cases):
    if expected_cases is None:
        return None
    result = list(expected_cases)
    if len(result) != len(set(result)):
        raise InputError("expected cases contain duplicates")
    for case in result:
        if not isinstance(case, str) or CASE_ID.fullmatch(case) is None:
            raise InputError("invalid expected case: {!r}".format(case))
    return result


def _publish_inputs(input_dir, runs, inputs):
    parent = input_dir.parent
    _safe_directory(parent)
    had_existing = os.path.lexists(input_dir)
    if had_existing:
        _safe_directory(input_dir)
    staging = Path(tempfile.mkdtemp(prefix=".report-input-stage-", dir=str(parent)))
    _safe_directory(staging)
    try:
        outcomes = {}
        for index, run in enumerate(runs):
            outcomes[run["case"]] = run["label"]
            if run["collector"] is not None:
                name = "case-{:06d}-{}".format(index, run["collector_path"].name)
                _atomic_json(staging / name, run["collector"])
        for name, value in inputs.items():
            _atomic_json(staging / name, value)
        _atomic_json(staging / "ptf_results.json", outcomes)
    except Exception:
        _remove_tree(staging)
        raise

    backup = None
    try:
        if had_existing:
            while True:
                candidate = parent / (
                    ".report-input-backup-" + uuid.uuid4().hex)
                if not os.path.lexists(candidate):
                    backup = candidate
                    break
            os.rename(input_dir, backup)
        try:
            os.rename(staging, input_dir)
        except Exception:
            if backup is not None:
                os.rename(backup, input_dir)
                backup = None
            raise
    except Exception:
        _remove_tree(staging)
        raise
    if backup is not None:
        _remove_tree(backup)


def _capability_document(input_dir, inputs, outcomes):
    rows = aggregate_capability.load_records(str(input_dir))
    skeleton = inputs["skeleton.json"]["cells"]
    enums = inputs["enum_values.json"]
    enum_by_attr = {}
    for cell in skeleton:
        if cell.get("enum_type"):
            enum_by_attr[cell["attr"]] = cell["enum_type"]
    hits = {}
    unjoined = 0
    for row in rows:
        case = row.get("case")
        if case not in outcomes:
            unjoined += 1
            continue
        value = aggregate_capability.resolve_value(
            row.get("value"), enum_by_attr.get(row["attr"]), enums)
        key = (row["attr"], row["op"], value)
        hits.setdefault(key, []).append(
            {"case": case, "outcome": outcomes[case]})
    cells = []
    counts = {
        aggregate_capability.SUPPORTED: 0,
        aggregate_capability.PARTIALLY_SUPPORTED: 0,
        aggregate_capability.NOT_SUPPORTED: 0,
        aggregate_capability.NOT_TESTED: 0,
    }
    for cell in skeleton:
        key = (cell["attr"], cell["op"], cell.get("value"))
        sources = hits.get(key, [])
        verdict = aggregate_capability.aggregate([
            aggregate_capability.classify_outcome(source["outcome"])
            for source in sources
        ])
        counts[verdict] += 1
        cells.append(dict(cell, verdict=verdict, sources=sources))
    if unjoined:
        raise InputError(
            "{} capability records have no matching case outcome".format(unjoined))
    return {
        "cells": cells,
        "summary": dict(counts, total=len(cells), unjoined_records=unjoined),
    }


def _render(input_dir, report_dir, inputs, runs):
    outcomes = {run["case"]: run["label"] for run in runs}
    actual = render_spec.load_actual_specs(str(input_dir))
    definitions = render_spec.load_registry_definitions(str(input_dir))
    expected = {key: definition for key, definition in definitions.items()
                if definition.get("result_type") != "incidental"}
    fill_rows = render_spec.load_fill_rate_rows(str(input_dir))
    rows = render_spec.build_spec_rows(actual, expected, definitions)
    summary = render_spec.summarize(rows, None, None)
    spec_page = render_spec.generate_html_report(
        summary, rows, actual, fill_rows, cap_report_name="capability.html",
        result_report_name=None)
    capability = _capability_document(input_dir, inputs, outcomes)
    capability_page = render_capability.render(capability)
    _atomic_text(report_dir / "spec.html", spec_page)
    _atomic_json(report_dir / "capability.json", capability)
    _atomic_text(report_dir / "capability.html", capability_page)


def _remove_stale_reports(report_dir):
    for name in ("spec.html", "capability.json", "capability.html"):
        path = report_dir / name
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_file():
                raise InputError("unsafe report output: {}".format(path))
            path.unlink()


def _save_status(report_dir, status, reasons, missing_measurements):
    _safe_directory(report_dir, create=True)
    if status != "complete":
        _remove_stale_reports(report_dir)
    result = {
        "status": status,
        "reasons": list(reasons),
        "cases_without_measurements": sorted(missing_measurements),
    }
    _atomic_json(report_dir / "report_status.json", result)
    return result


def build_report(artifact_root, expected_cases=None):
    """Build and atomically publish reports below one controller artifact root."""
    try:
        root = Path(os.path.abspath(os.fspath(artifact_root)))
    except TypeError as error:
        raise ValueError("artifact_root must be a local path") from error
    if not root.exists() or not root.is_dir() or root.is_symlink() or root.resolve() != root:
        raise ValueError("artifact_root must be an existing canonical directory")

    report_dir = root / "report"
    input_dir = root / "report-input"
    missing_measurements = []
    try:
        _safe_directory(report_dir, create=True)
        _save_status(report_dir, "incomplete", ["report rebuild in progress"], [])
        expected = _validated_expected(expected_cases)
        runs = _discover_runs(root)
        inputs = _load_inputs(root)
        measured_cases = {run["case"] for run in runs if run["collector"] is not None}
        missing_measurements = [run["case"] for run in runs
                                if run["collector"] is None]
        reasons = []
        if expected is not None:
            observed = {run["case"] for run in runs}
            missing = sorted(set(expected) - observed)
            extra = sorted(observed - set(expected))
            if missing:
                reasons.append("selected cases without a run: " + ", ".join(missing))
            if extra:
                reasons.append("unexpected archived cases: " + ", ".join(extra))
            missing_measurements.extend(sorted(set(expected) - measured_cases))
        _publish_inputs(input_dir, runs, inputs)
        if reasons:
            return _save_status(report_dir, "incomplete", reasons,
                                set(missing_measurements))
        _render(input_dir, report_dir, inputs, runs)
        return _save_status(report_dir, "complete", [], set(missing_measurements))
    except InputError as error:
        try:
            return _save_status(report_dir, "incomplete", [str(error)],
                                set(missing_measurements))
        except Exception:
            raise error
    except Exception as error:
        try:
            return _save_status(report_dir, "failed", [str(error)],
                                set(missing_measurements))
        except Exception:
            raise error


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Build offline reports from Ranking controller artifacts.")
    parser.add_argument("--artifact-root", required=True,
                        help="controller artifact tree to report")
    parser.add_argument("--expected-case", action="append", default=None,
                        help="expected module.Class identity; repeat as needed")
    arguments = parser.parse_args(argv)
    try:
        status = build_report(arguments.artifact_root, arguments.expected_case)
    except (OSError, ValueError, TypeError) as error:
        print("report_runner: {}".format(error), file=sys.stderr)
        return 1
    if status["status"] != "complete":
        for reason in status["reasons"]:
            print("report_runner: {}".format(reason), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
