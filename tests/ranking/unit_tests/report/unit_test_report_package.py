import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest


EXPECTED_SOURCE = {
    'repo': 'SONiC/SAI',
    'branch': 'v1.10-pdx-capability',
    'commit': '3e2e3631b57d8ce9f461ece2e14e451295cb520b',
}

EXPECTED_SOURCE_HASHES = {
    'spec_registry.json': '085c27d36a1213328ac97351cc6ceca57672da2b6eccfffbd0d70ae00efb6d61',
    'skeleton.json': 'cf90c62114ffeba39d5bb23acd3e94c9b99fb97d2d81ac4b8f704ec93a576cc8',
    'enum_values.json': '404079193705378168fdd919b9e89e4244b092563cf569f72f8cc34de469edc9',
}
EXPECTED_COMMITTED_HASHES = dict(
    EXPECTED_SOURCE_HASHES,
    **{'skeleton.json': 'b6117b87f330356b96bbf23c074c6178b5c1fe16eae648608f2040756aaa7952'})


def test_report_generator_has_canonical_package_path():
    from tests.ranking.report import generate

    assert callable(generate.build_report)
    assert not Path('tests/ranking/report_runner.py').exists()
    assert not Path('tests/ranking/pipeline').exists()


@pytest.mark.parametrize('name', sorted(EXPECTED_COMMITTED_HASHES))
def test_committed_metadata_matches_verified_source(name):
    root = Path('tests/ranking/report/metadata')
    manifest = json.loads((root / 'metadata_manifest.json').read_text())
    payload = (root / name).read_bytes()
    assert isinstance(json.loads(payload), dict)
    assert manifest['schema_version'] == 2
    assert manifest['source_identity'] == EXPECTED_SOURCE
    assert manifest['source_files'] == EXPECTED_SOURCE_HASHES
    assert manifest['files'] == EXPECTED_COMMITTED_HASHES
    assert hashlib.sha256(payload).hexdigest() == EXPECTED_COMMITTED_HASHES[name]


def test_skeleton_manifest_records_raw_to_normalized_chain():
    root = Path('tests/ranking/report/metadata')
    manifest = json.loads((root / 'metadata_manifest.json').read_text())
    transform = manifest['transforms']['skeleton.json']
    assert transform == {
        'schema_version': 1,
        'name': 'drop-non-runtime-source-paths',
        'input_sha256': EXPECTED_SOURCE_HASHES['skeleton.json'],
        'output_sha256': EXPECTED_COMMITTED_HASHES['skeleton.json'],
        'removed_fields': ['attr_dirs', 'enum_dirs'],
    }
    skeleton_text = (root / 'skeleton.json').read_text()
    skeleton = json.loads(skeleton_text)
    assert 'attr_dirs' not in skeleton
    assert 'enum_dirs' not in skeleton
    assert '/private/' not in skeleton_text


def test_runtime_rejects_metadata_hash_mismatch(tmp_path):
    from tests.ranking.report import generate

    metadata = tmp_path / 'metadata'
    metadata.mkdir()
    source = Path('tests/ranking/report/metadata')
    for name in EXPECTED_COMMITTED_HASHES:
        (metadata / name).write_bytes((source / name).read_bytes())
    (metadata / 'metadata_manifest.json').write_bytes(
        (source / 'metadata_manifest.json').read_bytes())
    (metadata / 'enum_values.json').write_text('{}')
    with pytest.raises(generate.InputError, match='hash'):
        generate.load_verified_metadata(metadata)


def test_runtime_rejects_broken_normalization_chain(tmp_path):
    from tests.ranking.report import generate

    metadata = tmp_path / 'metadata'
    metadata.mkdir()
    source = Path('tests/ranking/report/metadata')
    for name in EXPECTED_COMMITTED_HASHES:
        (metadata / name).write_bytes((source / name).read_bytes())
    manifest = json.loads((source / 'metadata_manifest.json').read_text())
    manifest['transforms']['skeleton.json']['input_sha256'] = '0' * 64
    (metadata / 'metadata_manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(generate.InputError, match='transform'):
        generate.load_verified_metadata(metadata)


def test_committed_metadata_passes_runtime_schema_validation():
    from tests.ranking.report import generate

    values = generate._load_inputs(generate.METADATA_ROOT)
    assert set(values) == set(EXPECTED_COMMITTED_HASHES) | {'metadata_manifest.json'}


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
    for name in ('render_result.py', 'render_spec.py', 'render_capability.py'):
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
        'capability.html', 'result.html', 'spec.html']
    assert not (tmp_path / 'report-input').exists()
