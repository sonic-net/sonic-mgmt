"""Build offline Ranking reports from archived controller artifacts."""

import argparse
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile

import yaml

from tests.ranking.common.case_selection import load_case_manifest
from tests.ranking.report import (
    aggregate_capability,
    render_capability,
    render_report,
    render_result,
    render_spec,
)


INPUTS = ("spec_registry.json", "skeleton.json", "enum_values.json")
METADATA_ROOT = Path(__file__).with_name("metadata")
CASES_ROOT = Path(__file__).resolve().parents[1] / "cases"
MANIFEST_PATH = CASES_ROOT / "manifest.json"
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


def _report_environment(path):
    """Return the four public environment fields displayed by the report."""
    if path is None:
        return None
    try:
        config_path = Path(path).expanduser().resolve(strict=True)
        if config_path.is_symlink() or not config_path.is_file():
            raise ValueError('not a regular file')
        with config_path.open(encoding='utf-8') as stream:
            value = yaml.safe_load(stream)
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as error:
        raise InputError(
            'cannot load ranking config {}: {}'.format(path, error)) from error

    def field(keys):
        current = value
        for key in keys:
            if not isinstance(current, dict) or key not in current:
                raise InputError(
                    'ranking config is missing {}'.format('.'.join(keys)))
            current = current[key]
        if (not isinstance(current, str) or not current.strip() or
                any(ord(character) < 32 or ord(character) == 127
                    for character in current)):
            raise InputError(
                'ranking config {} must be a non-empty string'.format(
                    '.'.join(keys)))
        return current.strip()

    return {
        'asic': field(('asic',)),
        'platform': field(('dut', 'platform')),
        'dut_ip': field(('hosts', 'dut', 'address')),
        'ptf_ip': field(('hosts', 'ptf', 'address')),
    }


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
            _regular_file(logs_dir / (cls + ".log"))
            runs.append({
                "case": case,
                "result": result,
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
    values = {name: _read_json(_regular_file(directory / name))
              for name in INPUTS}
    _validate_skeleton(values["skeleton.json"])
    for name in ("enum_values.json", "spec_registry.json"):
        if type(values[name]) is not dict:
            raise InputError("{} is not an object".format(name))
    return values


def _manifest_cases(manifest):
    return [
        '{}.{}'.format(module, case)
        for module, entry in manifest['modules'].items()
        for case in entry['cases']
    ]


def _render(report_dir, inputs, runs, manifest_cases, environment_summary=None):
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
    summary = render_spec.summarize(rows)
    capability = aggregate_capability.build_document(
        [row for result in results for row in result.get('attr_records', [])],
        inputs['skeleton.json']['cells'], inputs['enum_values.json'], statuses)
    page = render_report.render(
        result_section=render_result.render_section(result_rows),
        capability_section=render_capability.render_section(capability),
        spec_section=render_spec.render_section(
            summary, rows, actual, fill_rows),
        styles={
            'report-results-panel': render_result.styles(),
            'report-capability-panel': render_capability.styles(),
            'report-specification-panel': render_spec.styles(),
        },
        scripts=[render_capability.script()],
        environment_summary=environment_summary,
    )
    _atomic_text(report_dir / "report.html", page)


def _remove_stale_reports(report_dir):
    for name in (
            "report.html", "result.html", "spec.html", "capability.html",
            "capability.json", "report_status.json"):
        path = report_dir / name
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_file():
                raise InputError("unsafe report output: {}".format(path))
            path.unlink()


def _build_report_unlocked(output_root, environment_summary=None):
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
            manifest = load_case_manifest(MANIFEST_PATH)
        except ValueError as error:
            raise InputError(str(error)) from error
        manifest_cases = _manifest_cases(manifest)
        runs = _discover_runs(root)
        observed = {run["case"] for run in runs}
        extra = sorted(observed - set(manifest_cases))
        if extra:
            raise InputError(
                'observed case is not present in the case manifest: ' +
                ', '.join(extra))
        _render(report_dir, inputs, runs, manifest_cases, environment_summary)
    except Exception:
        try:
            _remove_stale_reports(report_dir)
        except Exception:
            pass
        raise


def build_report(output_root, ranking_config=None):
    """Render one offline snapshot while excluding concurrent batch writers."""
    from tests.ranking.common.artifact_store import exclusive
    environment_summary = _report_environment(ranking_config)
    with exclusive(output_root):
        return _build_report_unlocked(output_root, environment_summary)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Build offline reports from Ranking controller output.")
    parser.add_argument("--ranking-output", dest="output_root", required=True,
                        help="controller output directory to report")
    parser.add_argument(
        "--ranking-config", default=None,
        help="optional environment YAML for DUT ASIC/platform and DUT/PTF IPs")
    arguments = parser.parse_args(argv)
    try:
        build_report(arguments.output_root, arguments.ranking_config)
    except (OSError, ValueError, TypeError, RuntimeError) as error:
        print("report_generate: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
