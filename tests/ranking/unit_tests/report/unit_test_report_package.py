import json
from pathlib import Path
import subprocess
import sys

import pytest


def test_report_generator_has_canonical_package_path():
    from tests.ranking.report import generate

    assert callable(generate.build_report)
    assert not Path('tests/ranking/report_runner.py').exists()
    assert not Path('tests/ranking/pipeline').exists()


def _metadata(root):
    values = {
        'spec_registry.json': {},
        'skeleton.json': {'cells': [], 'denominator': 0},
        'enum_values.json': {},
    }
    for name, value in values.items():
        (root / name).write_text(json.dumps(value))
    return values


def test_runtime_loads_metadata_directly_without_a_manifest(tmp_path):
    from tests.ranking.report import generate

    values = _metadata(tmp_path)

    assert generate._load_inputs(tmp_path) == values


@pytest.mark.parametrize('name', (
    'spec_registry.json', 'skeleton.json', 'enum_values.json'))
def test_runtime_requires_each_metadata_file(tmp_path, name):
    from tests.ranking.report import generate

    _metadata(tmp_path)
    (tmp_path / name).unlink()

    with pytest.raises(generate.InputError, match=name):
        generate._load_inputs(tmp_path)


@pytest.mark.parametrize('payload', (
    '{', '{"duplicate": 1, "duplicate": 2}', '{"value": NaN}',
    '{"value": 1e999}',
))
def test_runtime_rejects_invalid_metadata_json(tmp_path, payload):
    from tests.ranking.report import generate

    _metadata(tmp_path)
    (tmp_path / 'enum_values.json').write_text(payload)

    with pytest.raises(generate.InputError, match='cannot load.*enum_values'):
        generate._load_inputs(tmp_path)


@pytest.mark.parametrize(('name', 'value', 'message'), (
    ('spec_registry.json', [], 'spec_registry.json is not an object'),
    ('enum_values.json', [], 'enum_values.json is not an object'),
    ('skeleton.json', {}, 'invalid cell set'),
    ('skeleton.json', {'cells': [], 'denominator': 1}, 'invalid denominator'),
    ('skeleton.json', {'cells': [], 'attr_dirs': []}, 'source paths'),
    ('skeleton.json', {'cells': [
        {'attr': 'SAI_PORT_ATTR_ADMIN_STATE', 'op': 'invalid',
         'value': None, 'enum_type': None},
    ]}, 'op is invalid'),
))
def test_runtime_rejects_invalid_metadata_schema(tmp_path, name, value, message):
    from tests.ranking.report import generate

    _metadata(tmp_path)
    (tmp_path / name).write_text(json.dumps(value))

    with pytest.raises(generate.InputError, match=message):
        generate._load_inputs(tmp_path)


def test_committed_metadata_passes_runtime_schema_validation():
    from tests.ranking.report import generate

    values = generate._load_inputs(generate.METADATA_ROOT)
    assert set(values) == set(generate.INPUTS)
    assert 'attr_dirs' not in values['skeleton.json']
    assert 'enum_dirs' not in values['skeleton.json']


def test_report_package_has_no_host_or_transport_dependency():
    root = Path('tests/ranking/report')
    source = '\n'.join(path.read_text(encoding='utf-8')
                       for path in root.rglob('*.py'))
    for forbidden in ('duthost', 'ptfhost', 'ansible_adhoc',
                      'pytest_ansible', 'paramiko', 'ssh ',
                      'tests.ranking.run'):
        assert forbidden not in source


def test_renderers_do_not_read_wall_clock():
    root = Path('tests/ranking/report')
    for name in ('render_report.py', 'render_result.py', 'render_spec.py',
                 'render_capability.py'):
        source = (root / name).read_text(encoding='utf-8')
        for forbidden in ('datetime.now', 'time.strftime', 'time.time'):
            assert forbidden not in source


def test_standalone_module_builds_from_controller_output(tmp_path):
    case = 'sairoute.multipleRoutesTest'
    module = tmp_path / 'cases/sairoute'
    (module / 'results').mkdir(parents=True)
    (module / 'logs').mkdir()
    (module / 'logs/multipleRoutesTest.log').write_text(
        '===== PTF console output =====\nOK\n\n'
        '===== PTF internal log =====\n')
    (module / 'results/multipleRoutesTest.json').write_text(json.dumps({
        'case': case,
        'status': 'passed',
        'rc': 0,
        'duration_seconds': 0.1,
        'error_message': None,
        'metadata': {},
        'spec_results': [],
        'attr_records': [],
    }))
    result = subprocess.run([
        sys.executable, '-m', 'tests.ranking.report.generate',
        '--ranking-output', str(tmp_path),
    ], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert sorted(path.name for path in (tmp_path / 'report').iterdir()) == [
        'report.html']
    page = (tmp_path / 'report/report.html').read_text()
    assert 'role="tab"' in page
    assert 'role="tabpanel"' in page
    assert not (tmp_path / 'report-input').exists()
