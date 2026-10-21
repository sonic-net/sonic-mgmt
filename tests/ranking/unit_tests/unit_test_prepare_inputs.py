import copy
import json
import os
import sys

import pytest

from tests.ranking.prepare_inputs import compile_inputs, main


EXPECTED_MAPPING = [
    {'dut_port': 'Ethernet40', 'lanes': [40, 41, 42, 43],
     'fanout_host': 'fanout-a', 'fanout_port': 'Ethernet19',
     'transport_vlan': 3018, 'ptf_port_id': 18, 'ptf_interface': 'eth18'},
    {'dut_port': 'Ethernet8', 'lanes': [8, 9, 10, 11],
     'fanout_host': 'fanout-a', 'fanout_port': 'Ethernet2',
     'transport_vlan': 3007, 'ptf_port_id': 7, 'ptf_interface': 'eth7'},
]
OUTPUT_NAMES = ('inputs.json', 'port-mapping.json', 'ptf-config-db.json')


def _staging_debris(directory):
    return [entry.name for entry in directory.iterdir() if 'staging' in entry.name]


def test_compile_inputs_has_consistent_mapping(tmp_path, sample_request):
    target = tmp_path / 'prepared'
    result = compile_inputs(sample_request, target)
    assert result['selected_cases'] == ['sairoute.RouteA']
    assert result['interface_args'] == [
        '--interface', '0-18@eth18', '--interface', '0-7@eth7']
    assert set(result) == {
        'schema_version', 'runtime', 'selector', 'selected_cases',
        'interface_args', 'mapping_hash', 'source_identity', 'manifest'}
    assert result['source_identity'] == sample_request['source_identity']
    assert result['source_identity'] is not sample_request['source_identity']
    assert result['manifest'] == sample_request['manifest']
    assert result['manifest'] is not sample_request['manifest']
    assert sorted(entry.name for entry in target.iterdir()) == sorted(OUTPUT_NAMES)
    saved_inputs = json.loads((target / 'inputs.json').read_text())
    saved_mapping = json.loads((target / 'port-mapping.json').read_text())
    saved_view = json.loads((target / 'ptf-config-db.json').read_text())
    assert saved_inputs == result
    assert saved_inputs['mapping_hash'] == result['mapping_hash']
    assert saved_inputs['schema_version'] == 1
    assert saved_mapping == EXPECTED_MAPPING
    assert list(saved_view['PORT']) == ['Ethernet40', 'Ethernet8']
    assert saved_view['DEVICE_METADATA'] == {'localhost': {'hostname': 'dut-a'}}
    assert 'password' not in json.dumps([saved_inputs, saved_mapping, saved_view])


def test_compiled_manifest_is_detached_original_snapshot(tmp_path, sample_request):
    sample_request['manifest']['metadata'] = {'origin': ['original']}
    original = copy.deepcopy(sample_request['manifest'])
    target = tmp_path / 'prepared'
    result = compile_inputs(sample_request, target)
    saved = json.loads((target / 'inputs.json').read_text())
    assert result['manifest'] == saved['manifest'] == original
    assert result['manifest']['source_identity'] is not result['source_identity']
    sample_request['manifest']['modules']['sairoute']['cases'].reverse()
    sample_request['manifest']['modules']['saivlan']['priority'] = 'P0'
    sample_request['manifest']['source_identity']['repo'] = 'OTHER'
    sample_request['manifest']['metadata']['origin'].append('changed')
    assert result['manifest'] == original
    assert json.loads((target / 'inputs.json').read_text())['manifest'] == original
    result['manifest']['modules']['sairoute']['cases'].clear()
    result['manifest']['source_identity']['repo'] = 'RESULT'
    assert result['source_identity']['repo'] == 'SAI'
    assert json.loads((target / 'inputs.json').read_text())['manifest'] == original


def test_ptf_config_db_preserves_port_key_order(tmp_path, sample_request, inputs):
    _, _, selected_ports, _, _ = inputs
    sample_request['dut_ports'] = list(reversed(selected_ports))
    target = tmp_path / 'prepared'
    result = compile_inputs(sample_request, target)
    assert result['interface_args'] == [
        '--interface', '0-7@eth7', '--interface', '0-18@eth18']
    saved_view = json.loads((target / 'ptf-config-db.json').read_text())
    saved_mapping = json.loads((target / 'port-mapping.json').read_text())
    assert list(saved_view['PORT']) == ['Ethernet8', 'Ethernet40']
    assert list(saved_view['PORT']) == [row['dut_port'] for row in saved_mapping]


def test_invalid_request_does_not_publish_outputs(tmp_path, sample_request):
    sample_request['runtime']['expected_connected_ports'] = 32
    target = tmp_path / 'prepared'
    with pytest.raises(ValueError):
        compile_inputs(sample_request, target)
    assert not target.exists()
    assert _staging_debris(tmp_path) == []


def test_existing_output_rejected(tmp_path, sample_request):
    target = tmp_path / 'prepared'
    target.mkdir()
    marker = target / 'marker.txt'
    marker.write_text('keep')
    with pytest.raises(ValueError):
        compile_inputs(sample_request, target)
    assert marker.read_text() == 'keep'
    assert [entry.name for entry in target.iterdir()] == ['marker.txt']
    assert _staging_debris(tmp_path) == []


def test_dangling_symlink_output_rejected(tmp_path, sample_request):
    target = tmp_path / 'prepared'
    os.symlink(tmp_path / 'missing', target)
    with pytest.raises(ValueError):
        compile_inputs(sample_request, target)
    assert target.is_symlink()
    assert _staging_debris(tmp_path) == []


def test_missing_parent_directory_rejected(tmp_path, sample_request):
    with pytest.raises(ValueError):
        compile_inputs(sample_request, tmp_path / 'missing' / 'prepared')
    assert not (tmp_path / 'missing').exists()


@pytest.mark.parametrize('mutation', [
    lambda request: request.update(
        selector={'single': 'sairoute.RouteA', 'priority': 'P0'}),
    lambda request: request.update(
        source_identity={'repo': 'OTHER', 'commit': 'a' * 40}),
    lambda request: request.update(unexpected='value'),
    lambda request: request.pop('graph'),
])
def test_invalid_requests_rejected_before_any_write(
        tmp_path, sample_request, mutation):
    mutation(sample_request)
    target = tmp_path / 'prepared'
    with pytest.raises(ValueError):
        compile_inputs(sample_request, target)
    assert not target.exists()
    assert _staging_debris(tmp_path) == []


@pytest.mark.parametrize('identity', [
    {1: 'revision'}, {'repo': 'SAI', 1: 'revision'},
])
def test_source_identity_requires_string_keys(tmp_path, sample_request, identity):
    sample_request['source_identity'] = identity
    sample_request['manifest']['source_identity'] = {
        str(key): value for key, value in identity.items()}
    with pytest.raises(ValueError, match='identity'):
        compile_inputs(sample_request, tmp_path / 'prepared')
    assert not (tmp_path / 'prepared').exists()
    assert _staging_debris(tmp_path) == []


def test_inputs_are_not_mutated(tmp_path, sample_request):
    original = copy.deepcopy(sample_request)
    compile_inputs(sample_request, tmp_path / 'prepared')
    assert sample_request == original


def test_cli_rejects_bad_count_without_publishing(
        tmp_path, sample_request, capsys):
    sample_request['runtime']['expected_connected_ports'] = 32
    source = tmp_path / 'request.json'
    source.write_text(json.dumps(sample_request))
    target = tmp_path / 'prepared'
    assert main(['--request', str(source), '--output', str(target)]) != 0
    captured = capsys.readouterr()
    assert captured.err.startswith('error:')
    assert captured.out == ''
    assert not target.exists()
    assert _staging_debris(tmp_path) == []


def test_cli_success_publishes(tmp_path, sample_request, capsys):
    source = tmp_path / 'request.json'
    source.write_text(json.dumps(sample_request))
    target = tmp_path / 'prepared'
    assert main(['--request', str(source), '--output', str(target)]) == 0
    captured = capsys.readouterr()
    assert captured.out == ''
    assert captured.err == ''
    for name in OUTPUT_NAMES:
        assert (target / name).is_file()


@pytest.mark.parametrize('text', [
    '[]',
    '{"selector": {"single": "sairoute.RouteA"}, "selector": null}',
    '{"selector": {"single": NaN}}',
])
def test_cli_rejects_invalid_request_json(tmp_path, text):
    source = tmp_path / 'request.json'
    source.write_text(text)
    target = tmp_path / 'prepared'
    assert main(['--request', str(source), '--output', str(target)]) != 0
    assert not target.exists()
    assert _staging_debris(tmp_path) == []


def test_compiler_does_not_import_ptf_runtime(tmp_path, sample_request):
    before = set(sys.modules)
    compile_inputs(sample_request, tmp_path / 'prepared')
    offenders = [
        name for name in set(sys.modules) - before
        if name == 'paramiko' or name == 'sai_base_test'
        or name.startswith('sai_thrift')
    ]
    assert offenders == []


@pytest.mark.parametrize('graph', ['missing', {}, None])
def test_virtual_compile_without_fanout(tmp_path, sample_request, graph):
    from tests.ranking.port_mapping import interface_args, ptf_config_view

    request = copy.deepcopy(sample_request)
    request['runtime']['backend'] = 'vsonic_ovs'
    if graph == 'missing':
        request.pop('graph')
    else:
        request['graph'] = graph
    original = copy.deepcopy(request)
    target = tmp_path / 'virtual'
    result = compile_inputs(request, target)
    rows = json.loads((target / 'port-mapping.json').read_text())
    assert [row['dut_port'] for row in rows] == ['Ethernet40', 'Ethernet8']
    assert all(set(row) == {
        'dut_port', 'lanes', 'ptf_port_id', 'ptf_interface'} for row in rows)
    assert result['interface_args'] == interface_args(rows)
    assert result['source_identity'] == request['source_identity']
    assert list(ptf_config_view(request['config_db'], rows)['PORT']) == [
        'Ethernet40', 'Ethernet8']
    assert request == original


@pytest.mark.parametrize('backend', ['physical_fanout', 'vsonic_ovs'])
def test_bad_ports_never_fall_back(tmp_path, sample_request, backend):
    sample_request['runtime']['backend'] = backend
    sample_request['ptf_port_map']['Ethernet40']['id'] = 7
    with pytest.raises(ValueError):
        compile_inputs(sample_request, tmp_path / 'invalid')
    assert not (tmp_path / 'invalid').exists()
    assert _staging_debris(tmp_path) == []


@pytest.mark.parametrize('value', [float('nan'), float('inf'), {'unsupported'}])
def test_invalid_config_json_rejected_before_staging(tmp_path, sample_request, value):
    from unittest.mock import patch

    sample_request['config_db']['EXTRA'] = value
    target = tmp_path / 'invalid'
    with patch('tests.ranking.prepare_inputs.tempfile.mkdtemp',
               side_effect=AssertionError('invalid JSON must fail before staging')) as stage:
        with pytest.raises(ValueError):
            compile_inputs(sample_request, target)
        stage.assert_not_called()
    assert not target.exists()
    assert _staging_debris(tmp_path) == []
