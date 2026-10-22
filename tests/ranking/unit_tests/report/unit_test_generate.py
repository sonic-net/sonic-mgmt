import hashlib
import json

import pytest

from tests.ranking.common.artifact_contract import CONSOLE_HEADER, INTERNAL_HEADER
from tests.ranking.report import generate


CASE = 'saisanity.L2SanityTest'
ATTR = 'SAI_PORT_ATTR_ADMIN_STATE'
SOURCE = {'repo': 'SONiC/SAI', 'commit': 'abc'}


def _write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def _metadata(root):
    values = {
        'spec_registry.json': {
            'ipv4_route_scale': {
                'description': 'IPv4 route scale',
                'direction': 'higher_better',
                'operations': ['create'],
                'result_type': 'scale',
                'unit': 'entries',
            },
        },
        'skeleton.json': {
            'cells': [{'attr': ATTR, 'op': 'set', 'value': 'false',
                       'enum_type': None}], 'denominator': 1},
        'enum_values.json': {},
    }
    source_hashes = {}
    files = {}
    for name, value in values.items():
        _write(root / name, value)
        files[name] = hashlib.sha256((root / name).read_bytes()).hexdigest()
        source_hashes[name] = files[name]
    source_hashes['skeleton.json'] = 'f' * 64
    _write(root / 'metadata_manifest.json', {
        'schema_version': 2,
        'source_identity': SOURCE,
        'source_files': source_hashes,
        'files': files,
        'transforms': {'skeleton.json': {
            'schema_version': 1,
            'name': 'drop-non-runtime-source-paths',
            'input_sha256': source_hashes['skeleton.json'],
            'output_sha256': files['skeleton.json'],
            'removed_fields': ['attr_dirs', 'enum_dirs'],
        }},
    })


def _manifest(root, cases):
    modules = {}
    for name in cases:
        module, cls = name.split('.')
        modules.setdefault(module, {'cases': {}})['cases'][cls] = {
            'priority': 'P0',
        }
    manifest = root / 'manifest.json'
    identity = root / 'source_identity.json'
    _write(manifest, {
        'schema_version': 2,
        'source_identity': SOURCE,
        'modules': modules,
    })
    _write(identity, SOURCE)
    return manifest, identity


def _case(root, case=CASE, rc=0, measurements=True):
    module, cls = case.split('.')
    module_dir = root / 'cases' / module
    _write(module_dir / 'results' / (cls + '.json'), {
        'case': case,
        'status': 'passed' if rc == 0 else 'failed',
        'rc': rc,
        'duration_seconds': 0.1,
        'error_message': None,
        'metadata': {},
        'spec_results': [{
            'spec_name': 'ipv4_route_scale',
            'operation': 'create',
            'count': 100,
            'actual_value': 100,
            'unit': 'entries',
            'baseline': None,
            'result': 'PASS',
            'result_type': 'scale',
            'direction': 'higher_better',
            'duration_seconds': 0.1,
            'extra': {'mask_length': 24},
        }] if measurements else [],
        'attr_records': ([{'case': case, 'attr': ATTR, 'op': 'set',
                           'value': False}] if measurements else []),
    })
    log = module_dir / 'logs' / (cls + '.log')
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(
        CONSOLE_HEADER + ('OK' if rc == 0 else 'FAILED') + INTERNAL_HEADER)
    return module_dir


@pytest.fixture
def output_root(tmp_path, monkeypatch):
    metadata = tmp_path / 'metadata'
    metadata.mkdir()
    _metadata(metadata)
    monkeypatch.setattr(generate, 'METADATA_ROOT', metadata)
    manifest, identity = _manifest(
        tmp_path, [CASE, 'sairoute.MissingCase'])
    monkeypatch.setattr(generate, 'MANIFEST_PATH', manifest)
    monkeypatch.setattr(generate, 'SOURCE_IDENTITY_PATH', identity)
    _case(tmp_path)
    return tmp_path


def test_report_renders_final_case_results_to_exact_html_outputs(output_root):
    assert generate.build_report(output_root) is None
    assert not (output_root / 'report-input').exists()
    assert not (output_root / 'report/report_status.json').exists()
    assert not (output_root / 'report/capability.json').exists()
    assert sorted(path.name for path in (output_root / 'report').iterdir()) == [
        'capability.html', 'result.html', 'spec.html']
    page = (output_root / 'report/result.html').read_text()
    assert CASE in page and '>PASS<' in page
    assert 'sairoute.MissingCase' in page and '>NOT TESTED<' in page


def test_report_ignores_hidden_incomplete_staging(output_root):
    hidden = output_root / 'cases' / '.sairoute.Case-deadbeef'
    hidden.mkdir()
    (hidden / 'partial').write_text('incomplete')
    assert generate.build_report(output_root) is None


def test_manifest_cases_without_a_run_are_not_an_error(output_root):
    generate.build_report(output_root)
    page = (output_root / 'report/result.html').read_text()
    assert 'sairoute.MissingCase' in page
    assert '>NOT TESTED<' in page


def test_successful_case_requires_its_log(output_root):
    (output_root / 'cases/saisanity/logs/L2SanityTest.log').unlink()
    with pytest.raises(generate.InputError, match='required run artifact'):
        generate.build_report(output_root)
    assert not any((output_root / 'report').iterdir())


def test_failed_case_without_measurements_is_still_a_complete_observation(
        output_root):
    result = output_root / 'cases/saisanity/results/L2SanityTest.json'
    result.unlink()
    _case(output_root, rc=1, measurements=False)
    assert generate.build_report(output_root) is None
    assert '>FAIL<' in (output_root / 'report/result.html').read_text()


def test_report_accepts_older_results_with_extra_metadata(output_root):
    path = output_root / 'cases/saisanity/results/L2SanityTest.json'
    result = json.loads(path.read_text())
    result['metadata']['port_count'] = 32
    _write(path, result)

    assert generate.build_report(output_root) is None


def test_nonhidden_unknown_case_directory_fails_closed(output_root):
    (output_root / 'cases' / 'invalid-name').mkdir()
    with pytest.raises(generate.InputError, match='invalid module output directory'):
        generate.build_report(output_root)


def test_observed_case_must_exist_in_the_manifest(output_root):
    _case(output_root, case='sairoute.UnregisteredCase')
    with pytest.raises(generate.InputError, match='not present in the case manifest'):
        generate.build_report(output_root)


def test_manifest_only_report_marks_every_case_not_tested(
        tmp_path, monkeypatch):
    metadata = tmp_path / 'metadata'
    metadata.mkdir()
    _metadata(metadata)
    manifest, identity = _manifest(tmp_path, [CASE])
    monkeypatch.setattr(generate, 'METADATA_ROOT', metadata)
    monkeypatch.setattr(generate, 'MANIFEST_PATH', manifest)
    monkeypatch.setattr(generate, 'SOURCE_IDENTITY_PATH', identity)

    assert generate.build_report(tmp_path) is None
    page = (tmp_path / 'report/result.html').read_text()
    assert CASE in page and '>NOT TESTED<' in page


def test_report_renders_directly_from_merged_case_results(output_root):
    generate.build_report(output_root)
    page = (output_root / 'report/spec.html').read_text()
    assert 'ipv4_route_scale' in page
    assert '>100<' in page
    source = json.loads(
        (output_root / 'cases/saisanity/results/L2SanityTest.json').read_text())
    spec = source['spec_results'][0]
    assert spec['count'] == 100
    assert spec['actual_value'] == 100
    assert spec['extra'] == {'mask_length': 24}
