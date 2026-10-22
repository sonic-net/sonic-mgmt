"""Build offline Ranking reports from archived controller artifacts."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile

from tests.ranking.common.case_selection import (
    load_case_manifest,
    validate_source_identity,
)
from tests.ranking.report import (
    aggregate_capability,
    render_capability,
    render_result,
    render_spec,
)


INPUTS = ("spec_registry.json", "skeleton.json", "enum_values.json")
METADATA_ROOT = Path(__file__).with_name("metadata")
METADATA_MANIFEST = "metadata_manifest.json"
CASES_ROOT = Path(__file__).resolve().parents[1] / "cases"
MANIFEST_PATH = CASES_ROOT / "manifest.json"
SOURCE_IDENTITY_PATH = CASES_ROOT / "source_identity.json"
CASE_ID = re.compile(r"^[A-Za-z_]\w*\.[A-Za-z_]\w*$")
MODULE_ID = re.compile(r"^[A-Za-z_]\w*$")
SKELETON_OPS = frozenset(("create", "set", "read"))
RESULT_FIELDS = {
    "case": str,
    "status": str,
    "rc": (int, type(None)),
    "duration_seconds": (int, float, type(None)),
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


def _safe_directory(path, create=False):
    if create:
        path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir() or path.is_symlink() or path.resolve() != path:
        raise InputError("unsafe directory: {}".format(path))


def _require_fields(value, fields, label):
    if type(value) is not dict:
        raise InputError("{} is not an object".format(label))
    for name, types in fields.items():
        if name not in value or not isinstance(value[name], types):
            raise InputError("{}.{} is missing or has the wrong type".format(
                label, name))


def _regular_sibling(run_dir, name):
    path = run_dir / name
    if (not os.path.lexists(path) or path.is_symlink() or not path.is_file() or
            path.resolve() != path):
        raise InputError(
            "required run artifact is not a regular sibling file: {}".format(
                path))
    return path


def _validate_result(value, path):
    _require_fields(value, RESULT_FIELDS, "result")
    case = value["case"]
    if CASE_ID.fullmatch(case) is None:
        raise InputError("{} has invalid case identity: {}".format(path, case))
    if value["status"] not in ("passed", "failed", "skipped", "timeout"):
        raise InputError("{} has invalid status".format(path))
    if value["rc"] is not None and type(value["rc"]) is not int:
        raise InputError("{} has invalid rc".format(path))
    if (isinstance(value["duration_seconds"], bool) or
            (value["duration_seconds"] is not None and
             value["duration_seconds"] < 0)):
        raise InputError("{} has invalid duration_seconds".format(path))
    scalar = (str, int, float, bool, type(None))
    for index, spec in enumerate(value["spec_results"]):
        label = "spec_results[{}]".format(index)
        _require_fields(spec, {
            "spec_name": str,
            "operation": (str, type(None)),
            "count": (int, type(None)),
            "actual_value": scalar,
            "unit": str,
            "baseline": scalar,
            "result": str,
            "result_type": str,
            "direction": str,
            "extra": dict,
        }, label)
        if type(spec["count"]) is bool:
            raise InputError("{}.count is invalid: {}".format(label, path))
        if "duration_seconds" in spec and (
                not isinstance(spec["duration_seconds"], (int, float)) or
                isinstance(spec["duration_seconds"], bool)):
            raise InputError(
                "{}.duration_seconds is invalid: {}".format(label, path))

    for index, row in enumerate(value["attr_records"]):
        label = "attr_records[{}]".format(index)
        _require_fields(row, {
            "case": str,
            "attr": str,
            "op": str,
            "value": scalar,
        }, label)
        if row["case"] != case:
            raise InputError("{}.case differs from {}: {}".format(
                label, case, path))


def _regular_file(path):
    if (not os.path.lexists(path) or path.is_symlink() or not path.is_file() or
            path.resolve() != path):
        raise InputError(
            "required run artifact is not a regular file: {}".format(path))
    return path


def _discover_runs(root):
    case_root = root / "cases"
    if not os.path.lexists(case_root):
        return []
    _safe_directory(case_root)
    runs = []
    for module_dir in sorted(case_root.iterdir()):
        if module_dir.name.startswith('.'):
            continue
        if MODULE_ID.fullmatch(module_dir.name) is None:
            raise InputError(
                "invalid module output directory: {}".format(module_dir))
        _safe_directory(module_dir)
        results_dir = module_dir / "results"
        logs_dir = module_dir / "logs"
        _safe_directory(results_dir)
        _safe_directory(logs_dir)
        for path in sorted(results_dir.iterdir()):
            if path.suffix != ".json":
                raise InputError("unexpected result artifact: {}".format(path))
            _regular_file(path)
            result = _read_json(path)
            _validate_result(result, path)
            case = result["case"]
            module, cls = case.split(".")
            if module != module_dir.name or cls != path.stem:
                raise InputError(
                    "result case identity differs from its output path: "
                    "{}".format(path))
            log_path = _regular_file(logs_dir / (cls + ".log"))
            runs.append({
                "case": case,
                "result": result,
                "result_path": path,
                "log_path": log_path,
            })
    return runs


def _validate_skeleton(value):
    if type(value) is not dict or type(value.get("cells")) is not list:
        raise InputError("skeleton.json has an invalid cell set")
    if "attr_dirs" in value or "enum_dirs" in value:
        raise InputError("skeleton.json contains non-runtime source paths")
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
            raise InputError(
                "{}.attr is missing or has the wrong type".format(label))
        if (cell.get("op") not in SKELETON_OPS or
                type(cell.get("op")) is not str):
            raise InputError("{}.op is invalid".format(label))
        if "value" not in cell or type(cell["value"]) not in (
                type(None), bool, int, float, str):
            raise InputError(
                "{}.value is not a JSON scalar or null".format(label))
        if type(cell["value"]) is float and not math.isfinite(cell["value"]):
            raise InputError("{}.value is not finite".format(label))
        if "enum_type" not in cell or type(cell["enum_type"]) not in (
                type(None), str):
            raise InputError(
                "{}.enum_type is missing or has the wrong type".format(label))


def _load_inputs(root):
    directory = Path(root)
    _safe_directory(directory)
    values = load_verified_metadata(directory)
    _validate_skeleton(values["skeleton.json"])
    for name in ("enum_values.json", "spec_registry.json"):
        if type(values[name]) is not dict:
            raise InputError("{} is not an object".format(name))
    return values


def load_verified_metadata(metadata_root=None):
    """Load report schemas only after provenance and hash validation."""
    directory = METADATA_ROOT if metadata_root is None else Path(metadata_root)
    _safe_directory(directory)
    manifest = _read_json(_regular_sibling(directory, METADATA_MANIFEST))
    expected_manifest_fields = {
        "schema_version", "source_identity", "source_files", "files",
        "transforms",
    }
    if (type(manifest) is not dict or manifest.get("schema_version") != 2 or
            set(manifest) != expected_manifest_fields):
        raise InputError("metadata manifest has an invalid envelope")
    try:
        validate_source_identity(manifest["source_identity"])
    except (KeyError, ValueError) as error:
        raise InputError(
            "metadata manifest source identity is invalid") from error
    files = manifest.get("files")
    source_files = manifest.get("source_files")
    for label, hashes in (("files", files), ("source_files", source_files)):
        if type(hashes) is not dict or set(hashes) != set(INPUTS):
            raise InputError(
                "metadata manifest {} must describe the report inputs".format(
                    label))
        for name, value in hashes.items():
            if (type(value) is not str or
                    re.fullmatch(r"[0-9a-f]{64}", value) is None):
                raise InputError(
                    "metadata manifest {} hash is invalid: {}".format(
                        label, name))
    for name in set(INPUTS) - {"skeleton.json"}:
        if source_files[name] != files[name]:
            raise InputError("unexpected metadata transform: " + name)
    transforms = manifest.get("transforms")
    if type(transforms) is not dict or set(transforms) != {"skeleton.json"}:
        raise InputError("metadata transform declaration is invalid")
    transform = transforms["skeleton.json"]
    expected_transform = {
        "schema_version": 1,
        "name": "drop-non-runtime-source-paths",
        "input_sha256": source_files["skeleton.json"],
        "output_sha256": files["skeleton.json"],
        "removed_fields": ["attr_dirs", "enum_dirs"],
    }
    if transform != expected_transform:
        raise InputError("metadata transform chain is invalid: skeleton.json")
    values = {}
    for name in INPUTS:
        expected = files[name]
        path = _regular_sibling(directory, name)
        try:
            payload = path.read_bytes()
        except OSError as error:
            raise InputError(
                "cannot read metadata {}: {}".format(path, error)) from error
        actual = hashlib.sha256(payload).hexdigest()
        if actual != expected:
            raise InputError("metadata hash mismatch: " + name)
        values[name] = _read_json(path)
    values[METADATA_MANIFEST] = manifest
    return values


def _manifest_cases(manifest):
    return [
        '{}.{}'.format(module, case)
        for module, entry in manifest['modules'].items()
        for case in entry['cases']
    ]


def _render(report_dir, inputs, runs, manifest_cases):
    # Reports are reproducible build artifacts. Generation wall-clock time is
    # not a durable input, so omit it consistently from the HTML renderers.
    generated_at = None
    statuses = {run["case"]: run["result"]["status"] for run in runs}
    results = [run["result"] for run in runs]
    runs_by_case = {run['case']: run for run in runs}
    result_rows = []
    for case in manifest_cases:
        run = runs_by_case.get(case)
        result_rows.append({
            'case': case,
            'status': run['result']['status'] if run else 'not_tested',
            'duration_seconds': (
                run['result']['duration_seconds'] if run else None),
            'log_href': (
                '../cases/{}/logs/{}.log'.format(*case.split('.'))
                if run else None),
        })
    actual = render_spec.build_actual_specs(results)
    definitions = render_spec.build_registry_definitions(
        inputs["spec_registry.json"])
    expected = {key: definition for key, definition in definitions.items()
                if definition.get("result_type") != "incidental"}
    fill_rows = render_spec.build_fill_rate_rows(results)
    rows = render_spec.build_spec_rows(actual, expected, definitions)
    summary = render_spec.summarize(
        rows, None, None, generated_at=generated_at)
    spec_page = render_spec.generate_html_report(
        summary, rows, actual, fill_rows, cap_report_name="capability.html",
        result_report_name="result.html")
    capability = aggregate_capability.build_document(
        [row for result in results for row in result.get('attr_records', [])],
        inputs['skeleton.json']['cells'], inputs['enum_values.json'], statuses)
    capability_page = render_capability.render(
        capability, generated_at=generated_at)
    result_page = render_result.render(result_rows)
    _atomic_text(report_dir / "result.html", result_page)
    _atomic_text(report_dir / "spec.html", spec_page)
    _atomic_text(report_dir / "capability.html", capability_page)


def _remove_stale_reports(report_dir):
    for name in (
            "result.html", "spec.html", "capability.html", "capability.json",
            "report_status.json"):
        path = report_dir / name
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_file():
                raise InputError("unsafe report output: {}".format(path))
            path.unlink()


def _build_report_unlocked(output_root):
    """Build offline reports from the manifest and final case outputs."""
    try:
        root = Path(os.path.abspath(os.fspath(output_root)))
    except TypeError as error:
        raise ValueError("output_root must be a local path") from error
    if (not root.exists() or not root.is_dir() or root.is_symlink() or
            root.resolve() != root):
        raise ValueError("output_root must be an existing canonical directory")

    report_dir = root / "report"
    try:
        _safe_directory(report_dir, create=True)
        _remove_stale_reports(report_dir)
        inputs = _load_inputs(METADATA_ROOT)
        try:
            manifest = load_case_manifest(MANIFEST_PATH, SOURCE_IDENTITY_PATH)
        except ValueError as error:
            raise InputError(str(error)) from error
        if (manifest['source_identity'] !=
                inputs[METADATA_MANIFEST]['source_identity']):
            raise InputError(
                'case and report metadata source identity mismatch')
        manifest_cases = _manifest_cases(manifest)
        runs = _discover_runs(root)
        observed = {run["case"] for run in runs}
        extra = sorted(observed - set(manifest_cases))
        if extra:
            raise InputError(
                'observed case is not present in the case manifest: ' +
                ', '.join(extra))
        inputs = {name: inputs[name] for name in INPUTS}
        _render(report_dir, inputs, runs, manifest_cases)
    except Exception:
        try:
            _remove_stale_reports(report_dir)
        except Exception:
            pass
        raise


def build_report(output_root):
    """Render one offline snapshot while excluding concurrent batch writers."""
    from tests.ranking.common.artifact_store import exclusive
    with exclusive(output_root):
        return _build_report_unlocked(output_root)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Build offline reports from Ranking controller output.")
    parser.add_argument("--ranking-output", dest="output_root", required=True,
                        help="controller output directory to report")
    arguments = parser.parse_args(argv)
    try:
        build_report(arguments.output_root)
    except (OSError, ValueError, TypeError, RuntimeError) as error:
        print("report_generate: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
