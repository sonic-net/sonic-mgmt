import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
from unittest.mock import patch

import pytest

from tests.ranking.unit_tests.ranking_samples import execution_api

from tests.ranking.execution_config import build_ptf_request
from tests.ranking.prepare_inputs import compile_inputs
from tests.ranking.unit_tests.unit_test_ptf_params import parse_ptf_params


EXECUTION_KEYS = {
    'runtime', 'execution', 'artifact_dir', 'input_dir', 'selected_cases',
    'selector', 'interface_args', 'mapping_hash', 'source_identity',
    'port_mapping', 'ptf_config_db', 'port_config_ini', 'profile_hash',
    'source_hash',
    'pipeline_dir', 'runner_path',
}


def _assembled(request, tmp_path):
    target = tmp_path / 'compiled'
    bundle = compile_inputs(request, target)
    bundle.update(
        input_dir=str(target),
        port_mapping=json.loads((target / 'port-mapping.json').read_text()),
        ptf_config_db=json.loads((target / 'ptf-config-db.json').read_text()),
    )
    return bundle


def test_execution_exact_shape_and_detachment(execution_spec, prepared_request):
    spec = execution_spec
    assert set(spec) == EXECUTION_KEYS
    assert spec['selected_cases'] == ['sairoute.RouteA']
    assert spec['source_identity'] == prepared_request['source_identity']
    canonical = json.dumps(spec['port_mapping'], sort_keys=True,
                           separators=(',', ':'), ensure_ascii=True)
    assert spec['mapping_hash'] == hashlib.sha256(canonical.encode()).hexdigest()
    assert not Path(spec['artifact_dir']).exists()
    assert spec['execution'] == spec['runtime']['execution']
    assert spec['execution'] is not spec['runtime']['execution']
    spec['runtime']['execution']['env']['CHANGED'] = 'yes'
    spec['source_identity']['repo'] = 'changed'
    assert spec['execution']['env'] == {}
    assert prepared_request['source_identity']['repo'] == 'SAI'


def test_missing_execution_fails_first_without_launch(tmp_path, sample_request):
    compiled = compile_inputs(sample_request, tmp_path / 'compiled')
    original = copy.deepcopy(compiled)
    with patch('subprocess.run') as run, patch('subprocess.Popen') as popen:
        with pytest.raises(ValueError, match='execution'):
            execution_api().validate_execution_config(compiled, tmp_path / 'artifacts')
        run.assert_not_called()
        popen.assert_not_called()
    assert compiled == original
    assert not (tmp_path / 'artifacts').exists()


def test_bare_compiled_bundle_cannot_execute(tmp_path, prepared_request):
    bundle = compile_inputs(prepared_request, tmp_path / 'compiled')
    with pytest.raises(ValueError):
        execution_api().validate_execution_config(bundle, tmp_path / 'artifacts')
    assert not (tmp_path / 'artifacts').exists()


@pytest.mark.parametrize('backend', ['physical_fanout', 'vsonic_ovs'])
def test_port_config_uses_actual_index_speed_and_order(
        tmp_path, prepared_request, backend):
    prepared_request['runtime']['backend'] = backend
    if backend == 'vsonic_ovs':
        prepared_request.pop('graph')
    assembled = _assembled(prepared_request, tmp_path)
    original = copy.deepcopy(assembled)
    api = execution_api()
    result = api.validate_execution_config(assembled, tmp_path / 'artifacts')
    assert result['port_config_ini'].splitlines() == [
        '# name lanes index speed',
        'Ethernet40 40,41,42,43 11 400000',
        'Ethernet8 8,9,10,11 3 400000',
    ]
    assert api.render_port_config(
        assembled['port_mapping'], assembled['ptf_config_db']) == result['port_config_ini']
    assert assembled == original


@pytest.mark.parametrize('field,value', [
    ('speed', None), ('speed', True), ('speed', '0'), ('speed', '-1'),
    ('speed', 1.5), ('speed', '400000\n'), ('index', None), ('index', False),
    ('index', '-1'), ('index', '3.0'), ('index', ' 3'), ('index', -1),
])
def test_ini_rejects_invalid_numbers(tmp_path, prepared_request, field, value):
    assembled = _assembled(prepared_request, tmp_path)
    assembled['ptf_config_db']['PORT']['Ethernet40'][field] = value
    with pytest.raises(ValueError):
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')
    assert not (tmp_path / 'artifacts').exists()


def test_ini_accepts_integer_zero_index(tmp_path, prepared_request):
    assembled = _assembled(prepared_request, tmp_path)
    assembled['ptf_config_db']['PORT']['Ethernet40'].update(speed=400000, index=0)
    assert execution_api().render_port_config(
        assembled['port_mapping'], assembled['ptf_config_db']).splitlines()[1] == (
            'Ethernet40 40,41,42,43 0 400000')


def test_launcher_binding_is_literal(prepared_request):
    api = execution_api()
    argv = prepared_request['runtime']['start_argv']
    original = list(argv)
    values = {'saiserver_container': 'saiserverv2',
              'saiserver_image_id': 'sha256:' + 'd' * 64}
    assert api.bind_launcher_argv(argv, values) == [
        '/usr/bin/docker', 'run', '--pull=never', '--detach', '--name',
        'saiserverv2', 'sha256:' + 'd' * 64]
    assert api.bind_launcher_argv(
        ['stop', '{saiserver_container_id}'],
        {'saiserver_container_id': 'b' * 64}) == ['stop', 'b' * 64]
    assert api.bind_launcher_argv(['literal with spaces', '$HOME', ';'], {}) == [
        'literal with spaces', '$HOME', ';']
    assert argv == original


@pytest.mark.parametrize('argv,values', [
    (['{unknown}'], {}), (['--name={saiserver_container}'], {'saiserver_container': 'x'}),
    (['{saiserver_container'], {}), (['{{saiserver_container}}'], {}),
    (['}'], {}), (['{saiserver_container}'], {}),
    (['{saiserver_container}'], {'saiserver_container': 'x;id'}),
    (['{saiserver_image_id}'], {'saiserver_image_id': 'latest'}),
    (['{saiserver_image_id}'], {'saiserver_image_id': 'sha256:' + 'd' * 63}),
    (['{saiserver_container_id}'], {'saiserver_container_id': 'sha256:' + 'd' * 64}),
    (['{saiserver_container_id}'], {'saiserver_container_id': 'z' * 64}),
    (['ok'], {'API_TOKEN': 'redacted'}), (['ok'], {'extra': 'value'}),
    ([], {}), (['bad\n'], {}),
])
def test_launcher_rejects_invalid_binding(argv, values):
    with pytest.raises(ValueError):
        execution_api().bind_launcher_argv(argv, values)


@pytest.mark.parametrize('mutation', [
    lambda a: a['port_mapping'][0].update(ptf_port_id=123),
    lambda a: a['port_mapping'][0].update(extra='bad'),
    lambda a: a['runtime'].update(backend='vsonic_ovs'),
    lambda a: a['runtime'].update(expected_connected_ports=3),
    lambda a: a.update(interface_args=['--interface', '0-0@eth0']),
    lambda a: a.update(mapping_hash='d' * 64),
    lambda a: a.update(source_identity={}),
    lambda a: a.update(source_identity={'repo': 'OTHER'}),
    lambda a: a.pop('manifest'),
    lambda a: a.update(manifest={}),
    lambda a: a['manifest'].update(schema_version=True),
    lambda a: a['manifest']['modules']['saivlan'].update(priority='P9'),
    lambda a: a.update(selected_cases=[]),
    lambda a: a.update(selected_cases=('sairoute.RouteA',)),
    lambda a: a.update(selector={'single': 'saivlan.VlanA'}),
    lambda a: a.update(selector={'explicit': 'sairoute.RouteB'}),
    lambda a: a.update(selector={'modules': 'saivlan'}),
    lambda a: a.update(selector={'priority': 'P9'}),
    lambda a: a.update(selected_cases=['saivlan.VlanA']),
    lambda a: a.update(selected_cases=['sairoute.RouteA', 'sairoute.RouteA']),
    lambda a: a.update(schema_version=True),
    lambda a: a.update(unexpected='x'),
    lambda a: a['ptf_config_db'].update(PORT=dict(reversed(list(a['ptf_config_db']['PORT'].items())))),
    lambda a: a['ptf_config_db']['PORT']['Ethernet40'].update(lanes='0,1'),
    lambda a: a['ptf_config_db']['PORT'].pop('Ethernet40'),
])
def test_assembled_corruption_rejected_without_mutation(
        tmp_path, prepared_request, mutation):
    assembled = _assembled(prepared_request, tmp_path)
    mutation(assembled)
    original = copy.deepcopy(assembled)
    with patch('subprocess.run') as run, patch('subprocess.Popen') as popen:
        with pytest.raises(ValueError):
            execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')
        run.assert_not_called()
        popen.assert_not_called()
    assert assembled == original
    assert not (tmp_path / 'artifacts').exists()


def test_priority_tamper_rejected(tmp_path, prepared_request):
    prepared_request['selector'] = {'priority': 'P2'}
    assembled = _assembled(prepared_request, tmp_path)
    assert assembled['selected_cases'] == ['saivlan.VlanA']
    assembled['selector'] = {'priority': 'P0'}
    original = copy.deepcopy(assembled)
    with pytest.raises(ValueError, match='selector'):
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')
    assert assembled == original
    assert not (tmp_path / 'artifacts').exists()


def test_module_tamper_rejects_incomplete_cases(tmp_path, prepared_request):
    assembled = _assembled(prepared_request, tmp_path)
    assert assembled['selected_cases'] == ['sairoute.RouteA']
    assembled['selector'] = {'modules': 'sairoute'}
    original = copy.deepcopy(assembled)
    with pytest.raises(ValueError, match='selector'):
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')
    assert assembled == original
    assert not (tmp_path / 'artifacts').exists()


def test_explicit_selected_case_order_tamper_rejected(tmp_path, prepared_request):
    prepared_request['selector'] = {'explicit': 'sairoute.RouteA,sairoute.RouteB'}
    assembled = _assembled(prepared_request, tmp_path)
    assert assembled['selected_cases'] == ['sairoute.RouteA', 'sairoute.RouteB']
    assembled['selected_cases'].reverse()
    original = copy.deepcopy(assembled)
    with pytest.raises(ValueError, match='selector'):
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')
    assert assembled == original
    assert not (tmp_path / 'artifacts').exists()


@pytest.mark.parametrize('selector,expected', [
    ({'single': 'saivlan.VlanA'}, ['saivlan.VlanA']),
    ({'explicit': 'sairoute.RouteA,sairoute.RouteB'},
     ['sairoute.RouteB', 'sairoute.RouteA']),
    ({'modules': 'sairoute'}, ['sairoute.RouteB', 'sairoute.RouteA']),
    ({'modules': 'sairoute,saivlan'},
     ['saivlan.VlanA', 'sairoute.RouteB', 'sairoute.RouteA']),
    ({'priority': 'P0'}, ['sairoute.RouteB', 'sairoute.RouteA']),
    ({'priority': 'P2'}, ['saivlan.VlanA']),
])
def test_saved_original_manifest_drives_selection(tmp_path, prepared_request, selector, expected):
    prepared_request['manifest']['modules'] = dict(
        reversed(list(prepared_request['manifest']['modules'].items())))
    prepared_request['manifest']['modules']['sairoute']['cases'].reverse()
    prepared_request['selector'] = selector
    target = tmp_path / 'compiled'
    bundle = compile_inputs(prepared_request, target)
    saved = json.loads((target / 'inputs.json').read_text())
    assert list(saved['manifest']['modules']) == ['saivlan', 'sairoute']
    assert saved['manifest'] == prepared_request['manifest']
    assert bundle['selected_cases'] == expected
    spec = execution_api().load_execution_inputs(target, tmp_path / 'artifacts')
    assert spec['selected_cases'] == expected
    assert set(spec) == EXECUTION_KEYS


@pytest.mark.parametrize('identity', [
    {'repo': 'OTHER', 'commit': 'a' * 40},
    {'repo': 'SAI', 'commit': 'a' * 40, 'revision': True},
    {'repo': 'SAI', 'commit': 'a' * 40, 'revision': 1.0},
    {'repo': 'SAI', 'commit': 'a' * 40, 'revision': '1'},
])
def test_manifest_source_identity_mismatch_rejected(tmp_path, prepared_request, identity):
    prepared_request['source_identity']['revision'] = 1
    contract_path = tmp_path / 'case_source' / 'ranking-contract.json'
    contract = json.loads(contract_path.read_text())
    contract['source_identity'] = copy.deepcopy(prepared_request['source_identity'])
    contract_path.write_text(json.dumps(contract))
    assembled = _assembled(prepared_request, tmp_path)
    assembled['manifest']['source_identity'] = identity
    original = copy.deepcopy(assembled)
    with pytest.raises(ValueError, match='manifest source identity mismatch'):
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')
    assert assembled == original
    assert not (tmp_path / 'artifacts').exists()


@pytest.mark.parametrize('mutation', [
    lambda e: e.update(extra=1), lambda e: e.pop('profile_id'),
    lambda e: e.update(dut_host='dut-b'), lambda e: e.update(dut_host='dut-*'),
    lambda e: e.update(ptf_host='server-b'), lambda e: e.update(ptf_host='all,*'),
    lambda e: e.update(rpc_host='user:password@example.invalid'),
    lambda e: e.update(rpc_host='example.invalid\n'),
    lambda e: e.update(profile_id='../escape'), lambda e: e.update(ptf_argv=[]),
    lambda e: e.update(test_params={'nested': {'x': 1}}),
    lambda e: e.update(test_params={'x': float('inf')}),
    lambda e: e.update(test_params={'x': 'bad\n'}),
    lambda e: e.update(env={'API_TOKEN': 'redacted'}),
    lambda e: e.update(env={'BAD-KEY': 'value'}),
    lambda e: e.update(env={'GOOD': 1}), lambda e: e.update(env={'GOOD': 'bad\x00'}),
    lambda e: e.update(dut_files={}),
])
def test_invalid_execution_boundary(tmp_path, prepared_request, mutation):
    assembled = _assembled(prepared_request, tmp_path)
    mutation(assembled['runtime']['execution'])
    original = copy.deepcopy(assembled)
    with pytest.raises(ValueError):
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')
    assert assembled == original
    assert not (tmp_path / 'artifacts').exists()


@pytest.mark.parametrize('key', [
    'thrift_server', 'rpc_port', 'config_db_json', 'port_config_ini', 'result_output_dir',
])
def test_test_params_reserved(tmp_path, prepared_request, key):
    assembled = _assembled(prepared_request, tmp_path)
    assembled['runtime']['execution']['test_params'][key] = 'override'
    with pytest.raises(ValueError):
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')


def test_credentials_rejected_by_compiler_before_stage(tmp_path, prepared_request):
    prepared_request['runtime']['execution']['env']['API_TOKEN'] = 'redacted'
    original = copy.deepcopy(prepared_request)
    with pytest.raises(ValueError):
        compile_inputs(prepared_request, tmp_path / 'compiled')
    assert prepared_request == original
    assert not (tmp_path / 'compiled').exists()


@pytest.mark.parametrize('location', [
    'case_source', 'header_dir', 'adapter_path', 'inventory', 'binding_dir', 'prebuilt_dir',
])
def test_missing_local_source(tmp_path, prepared_request, location):
    assembled = _assembled(prepared_request, tmp_path)
    runtime = assembled['runtime']
    owner = runtime['execution'] if location in ('binding_dir', 'prebuilt_dir') else runtime
    owner[location] = str(tmp_path / 'missing')
    with pytest.raises(ValueError):
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')


@pytest.mark.parametrize('root', ['case_source', 'header_dir', 'binding_dir', 'prebuilt_dir'])
def test_source_tree_symlink_escape(tmp_path, prepared_request, root):
    assembled = _assembled(prepared_request, tmp_path)
    outside = tmp_path / 'outside'
    outside.write_text('must not read')
    (tmp_path / root / 'escape').symlink_to(outside)
    with pytest.raises(ValueError, match='symlink'):
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')
    assert outside.read_text() == 'must not read'


@pytest.mark.parametrize('mutation', [
    lambda c: c.update(schema_version=True), lambda c: c.update(extra=1),
    lambda c: c.update(requires_dut_credentials=True),
    lambda c: c.update(requires_dut_credentials=0),
    lambda c: c.update(rpc_port=9093), lambda c: c.update(rpc_port='9092'),
    lambda c: c.update(rpc_port=True), lambda c: c.update(rpc_port='CONFIGURABLE'),
    lambda c: c.update(source_identity={'repo': 'OTHER'}),
    lambda c: c.update(switch_owner='launcher'),
    lambda c: c.update(dataplane_validation='before_create_switch'),
])
def test_incompatible_prepared_contract(tmp_path, prepared_request, mutation):
    path = tmp_path / 'case_source' / 'ranking-contract.json'
    contract = json.loads(path.read_text())
    mutation(contract)
    path.write_text(json.dumps(contract))
    assembled = _assembled(prepared_request, tmp_path)
    with pytest.raises(ValueError):
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')
    assert not (tmp_path / 'artifacts').exists()


@pytest.mark.parametrize('name', ['ranking-contract.json', 'sairoute.py'])
def test_prepared_contract_and_selected_module_required(tmp_path, prepared_request, name):
    (tmp_path / 'case_source' / name).unlink()
    assembled = _assembled(prepared_request, tmp_path)
    with pytest.raises(ValueError):
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')


def test_configurable_rpc_and_json_type_identity(tmp_path, prepared_request):
    prepared_request['source_identity']['revision'] = 1
    path = tmp_path / 'case_source' / 'ranking-contract.json'
    contract = json.loads(path.read_text())
    contract.update(rpc_port='configurable', source_identity=prepared_request['source_identity'])
    path.write_text(json.dumps(contract))
    assembled = _assembled(prepared_request, tmp_path)
    execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')
    contract['source_identity']['revision'] = True
    path.write_text(json.dumps(contract))
    with pytest.raises(ValueError, match='identity'):
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')


@pytest.mark.parametrize('name', [
    'inputs.json', 'port-mapping.json', 'ptf-config-db.json', 'ranking-contract.json',
])
@pytest.mark.parametrize('text', [
    '{"duplicate": 1, "duplicate": 2}', '{"invalid": NaN}',
    '{"invalid": Infinity}', '{"invalid": 1e999}', '[',
])
def test_strict_json_at_every_boundary(tmp_path, prepared_request, name, text):
    target = tmp_path / 'compiled'
    compile_inputs(prepared_request, target)
    path = (tmp_path / 'case_source' / name) if name == 'ranking-contract.json' else target / name
    path.write_text(text)
    with pytest.raises(ValueError):
        execution_api().load_execution_inputs(target, tmp_path / 'artifacts')
    assert not (tmp_path / 'artifacts').exists()


@pytest.mark.parametrize('name', ['inputs.json', 'port-mapping.json', 'ptf-config-db.json'])
def test_loader_requires_three_sidecars(tmp_path, prepared_request, name):
    target = tmp_path / 'compiled'
    compile_inputs(prepared_request, target)
    (target / name).unlink()
    with pytest.raises(ValueError):
        execution_api().load_execution_inputs(target, tmp_path / 'artifacts')


def test_saved_mapping_hash_corruption(tmp_path, prepared_request):
    target = tmp_path / 'compiled'
    compile_inputs(prepared_request, target)
    path = target / 'port-mapping.json'
    rows = json.loads(path.read_text())
    rows[0]['ptf_port_id'] = 123
    path.write_text(json.dumps(rows))
    with pytest.raises(ValueError, match='mapping'):
        execution_api().load_execution_inputs(target, tmp_path / 'artifacts')
    assert not (tmp_path / 'artifacts').exists()


@pytest.mark.parametrize('kind', ['relative', 'traversal', 'existing', 'missing_parent', 'symlink'])
def test_artifact_path_is_canonical_fresh_local(tmp_path, prepared_request, kind):
    assembled = _assembled(prepared_request, tmp_path)
    target = tmp_path / 'artifacts'
    if kind == 'relative':
        argument = 'artifacts'
    elif kind == 'traversal':
        argument = str(tmp_path) + '/child/../artifacts'
    elif kind == 'existing':
        target.mkdir()
        argument = target
    elif kind == 'missing_parent':
        argument = tmp_path / 'missing' / 'artifacts'
    else:
        target.symlink_to(tmp_path / 'missing')
        argument = target
    with pytest.raises(ValueError):
        execution_api().validate_execution_config(assembled, argument)


@pytest.mark.parametrize('mutation', [
    lambda r: r.update(start_argv=['/bin/launcher', '{saiserver_container}']),
    lambda r: r.update(start_argv=['/bin/launcher', '{saiserver_image_id}']),
    lambda r: r['start_argv'].append('{unknown}'),
    lambda r: r['stop_argv'].append('--name={saiserver_container}'),
])
def test_launcher_start_requires_explicit_binding(tmp_path, prepared_request, mutation):
    assembled = _assembled(prepared_request, tmp_path)
    mutation(assembled['runtime'])
    with pytest.raises(ValueError):
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')


def _with_declared_launcher(assembled, tmp_path):
    source = tmp_path / 'launcher.py'
    source.write_text('prepared = True\n')
    assembled['runtime']['start_argv'].insert(1, '/opt/ranking/launcher.py')
    assembled['runtime']['execution']['dut_files'] = [
        {'source': str(source), 'destination': '/opt/ranking/launcher.py'}]
    return source


def test_declared_launcher_file_and_hashes(tmp_path, prepared_request):
    assembled = _assembled(prepared_request, tmp_path)
    source = _with_declared_launcher(assembled, tmp_path)
    api = execution_api()
    first = api.validate_execution_config(assembled, tmp_path / 'artifacts')
    assert first == api.validate_execution_config(assembled, tmp_path / 'artifacts')
    assert len(first['profile_hash']) == len(first['source_hash']) == 64
    assert first['profile_hash'] == hashlib.sha256(json.dumps(
        {'runtime': first['runtime'], 'execution': first['execution']},
        sort_keys=True, separators=(',', ':'), ensure_ascii=True,
        allow_nan=False).encode()).hexdigest()
    source.write_text('prepared = False\n')
    second = api.validate_execution_config(assembled, tmp_path / 'artifacts')
    assert second['profile_hash'] == first['profile_hash']
    assert second['source_hash'] != first['source_hash']


@pytest.mark.parametrize('location', [
    'case_source/sairoute.py', 'case_source/ranking-contract.json', 'header_dir/sai.h',
    'binding_dir/sai_thrift/__init__.py', 'prebuilt_dir/attr_map.json', 'adapter.py', 'inventory',
])
def test_all_source_bytes_are_fingerprinted(tmp_path, prepared_request, location):
    assembled = _assembled(prepared_request, tmp_path)
    api = execution_api()
    first = api.validate_execution_config(assembled, tmp_path / 'artifacts')
    path = tmp_path / location
    path.write_text(path.read_text() + '\n')
    if location == 'adapter.py':
        (tmp_path / 'binding_dir' / 'sai_thrift' / 'sai_adapter.py').write_bytes(path.read_bytes())
    second = api.validate_execution_config(assembled, tmp_path / 'artifacts')
    assert second['source_hash'] != first['source_hash']
    assert second['profile_hash'] == first['profile_hash']


@pytest.mark.parametrize('mutation', [
    lambda files, p: files.append(copy.deepcopy(files[0])),
    lambda files, p: files[0].update(extra=1),
    lambda files, p: files[0].update(destination='/opt/ranking/../launcher.py'),
    lambda files, p: files[0].update(destination='/etc/sonic/config_db.json'),
    lambda files, p: files[0].update(destination='/boot/image'),
    lambda files, p: files[0].update(destination='/opt/ranking/undeclared.py'),
    lambda files, p: files[0].update(destination='/opt/ranking\\launcher.py'),
    lambda files, p: files[0].update(source=str(p / 'missing')),
    lambda files, p: files[0].update(source=str(p)),
])
def test_dut_file_boundaries(tmp_path, prepared_request, mutation):
    assembled = _assembled(prepared_request, tmp_path)
    _with_declared_launcher(assembled, tmp_path)
    mutation(assembled['runtime']['execution']['dut_files'], tmp_path)
    with pytest.raises(ValueError):
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')
    assert not (tmp_path / 'artifacts').exists()


@pytest.mark.parametrize('kind', ['pathlike', 'trailing_slash', 'double_root', 'backslash'])
def test_input_dir_path_boundary(tmp_path, prepared_request, kind):
    assembled = _assembled(prepared_request, tmp_path)
    directory = assembled['input_dir']
    if kind == 'pathlike':
        assembled['input_dir'] = Path(directory)
        original = copy.deepcopy(assembled)
        result = execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')
        assert result['input_dir'] == directory
        assert assembled == original
    else:
        assembled['input_dir'] = {
            'trailing_slash': directory + '/',
            'double_root': '/' + directory,
            'backslash': directory + '\\escape',
        }[kind]
        with pytest.raises(ValueError):
            execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')
    assert not (tmp_path / 'artifacts').exists()


SAI_CONFIG_DESTINATIONS = [
    '/usr/share/sonic/device/platform-a/hwsku-a/sai.profile',
    '/usr/share/sonic/device/platform-a/hwsku-a/sai.config',
    '/usr/share/sonic/device/platform-a/hwsku-a/simconfig.json',
    '/etc/sai.d/sai.profile',
    '/usr/share/sonic/device/x86_64-platform.a-r0/HwSku_1/sai.profile',
]


def _spec_with_dut_file(spec, source, destination):
    spec = copy.deepcopy(spec)
    spec['runtime']['execution']['dut_files'] = [
        {'source': str(source), 'destination': destination}]
    spec['runtime']['start_argv'].append(destination)
    assembled = json.loads((Path(spec['input_dir']) / 'inputs.json').read_text())
    assembled.update({field: spec[field] for field in (
        'runtime', 'input_dir', 'port_mapping', 'ptf_config_db')})
    return assembled


@pytest.mark.parametrize('destination', SAI_CONFIG_DESTINATIONS)
def test_declared_sai_config_destination_allowed(tmp_path, execution_spec, destination):
    import os

    source = tmp_path / 'sai-runtime-config'
    source.write_text('SAI_INIT_CONFIG_FILE=simconfig.json\n')
    original_spec = copy.deepcopy(execution_spec)
    assembled = _spec_with_dut_file(execution_spec, source, destination)
    original = copy.deepcopy(assembled)
    original_lstat, original_open = os.lstat, os.open

    def local_lstat(path, *args, **kwargs):
        assert str(path) != destination
        return original_lstat(path, *args, **kwargs)

    def local_open(path, flags, *args, **kwargs):
        assert str(path) != destination
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
        return original_open(path, flags, *args, **kwargs)

    with patch('os.lstat', side_effect=local_lstat), \
            patch('os.open', side_effect=local_open), \
            patch('subprocess.run') as run, patch('subprocess.Popen') as popen:
        result = execution_api().validate_execution_config(assembled, execution_spec['artifact_dir'])
        run.assert_not_called()
        popen.assert_not_called()
    assert result['execution']['dut_files'] == assembled['runtime']['execution']['dut_files']
    assert set(result) == EXECUTION_KEYS
    assert assembled == original
    assert execution_spec == original_spec
    assert not Path(result['artifact_dir']).exists()


@pytest.mark.parametrize('destination', SAI_CONFIG_DESTINATIONS)
@pytest.mark.parametrize('declaration', ['undeclared', 'embedded', 'sibling'])
def test_sai_config_requires_exact_launcher_literal(
        tmp_path, execution_spec, destination, declaration):
    source = tmp_path / 'sai-runtime-config'
    source.write_text('prepared = True\n')
    assembled = _spec_with_dut_file(execution_spec, source, destination)
    argv = assembled['runtime']['start_argv']
    argv.pop()
    if declaration == 'embedded':
        argv.append('--config=' + destination)
    elif declaration == 'sibling':
        argv.append(destination + '.other')
    with pytest.raises(ValueError):
        execution_api().validate_execution_config(assembled, execution_spec['artifact_dir'])
    assert not Path(execution_spec['artifact_dir']).exists()


@pytest.mark.parametrize('destination', SAI_CONFIG_DESTINATIONS)
def test_sai_config_duplicate_destination_rejected(tmp_path, execution_spec, destination):
    source = tmp_path / 'sai-runtime-config'
    source.write_text('prepared = True\n')
    assembled = _spec_with_dut_file(execution_spec, source, destination)
    files = assembled['runtime']['execution']['dut_files']
    files.append(copy.deepcopy(files[0]))
    with pytest.raises(ValueError, match='duplicate dut_files destination'):
        execution_api().validate_execution_config(assembled, execution_spec['artifact_dir'])


@pytest.mark.parametrize('kind', ['missing', 'directory', 'symlink'])
def test_sai_config_source_must_be_local_regular_file(tmp_path, execution_spec, kind):
    source = tmp_path / 'sai-runtime-config'
    if kind == 'directory':
        source.mkdir()
    elif kind == 'symlink':
        source.symlink_to(tmp_path / 'adapter.py')
    assembled = _spec_with_dut_file(execution_spec, source, '/etc/sai.d/sai.profile')
    with pytest.raises(ValueError):
        execution_api().validate_execution_config(assembled, execution_spec['artifact_dir'])


@pytest.mark.parametrize('destination', [
    '/etc/sonic/config_db.json', '/boot/image', '/host/image',
    '/usr/bin/docker', '/usr/lib64/image', '/',
    '/etc/other/sai.profile',
    '/usr/share/sonic/device/platform-a/./sai.profile',
    '/usr/share/sonic/device/platform-a/../sai.profile',
    '/usr/share/sonic/device/platform-a/hwsku-a/../hwsku-a/sai.profile',
    '/usr/share/sonic/device/platform-a//hwsku-a/sai.profile',
    '//usr/share/sonic/device/platform-a/hwsku-a/sai.profile',
    '/usr/share/sonic/device/platform-a/hwsku-a/sai.profile/',
    '/usr/share/sonic/device/platform-a/hwsku-a\\sai.profile',
])
def test_protected_dut_path_even_when_declared(tmp_path, prepared_request, destination):
    assembled = _assembled(prepared_request, tmp_path)
    source = _with_declared_launcher(assembled, tmp_path)
    assembled['runtime']['start_argv'].insert(1, destination)
    assembled['runtime']['execution']['dut_files'] = [
        {'source': str(source), 'destination': destination}]
    with pytest.raises(ValueError):
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')
    assert not (tmp_path / 'artifacts').exists()


@pytest.mark.parametrize('destination', [
    '/etc/sai.d/sai.config', '/etc/sai.d/simconfig.json', '/etc/sai.d/launcher.py',
    '/usr/share/sonic/device/platform-a/hwsku-a/config_db.json',
])
def test_profile_config_roots_allow_explicitly_declared_launcher_files(
        tmp_path, prepared_request, destination):
    assembled = _assembled(prepared_request, tmp_path)
    source = _with_declared_launcher(assembled, tmp_path)
    assembled['runtime']['start_argv'].insert(1, destination)
    files = [{'source': str(source), 'destination': destination}]
    assembled['runtime']['execution']['dut_files'] = files
    spec = execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')
    assert spec['execution']['dut_files'] == files


def test_adapter_must_match_the_binding_used_by_cases(tmp_path, prepared_request):
    assembled = _assembled(prepared_request, tmp_path)
    (tmp_path / 'binding_dir' / 'sai_thrift' / 'sai_adapter.py').write_text('different=True\n')
    with pytest.raises(ValueError, match='byte-identical'):
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')


@pytest.mark.parametrize('kind', ['directory', 'contained', 'adapter', 'declared'])
def test_all_undeclared_source_links_rejected(tmp_path, prepared_request, kind):
    assembled = _assembled(prepared_request, tmp_path)
    if kind == 'directory':
        (tmp_path / 'binding_dir' / 'escape').symlink_to(tmp_path / 'header_dir', target_is_directory=True)
    elif kind == 'contained':
        (tmp_path / 'case_source' / 'link.py').symlink_to(tmp_path / 'case_source' / 'sairoute.py')
    elif kind == 'adapter':
        link = tmp_path / 'adapter-link.py'
        link.symlink_to(tmp_path / 'adapter.py')
        assembled['runtime']['adapter_path'] = str(link)
    else:
        source = _with_declared_launcher(assembled, tmp_path)
        link = tmp_path / 'launcher-link.py'
        link.symlink_to(source)
        assembled['runtime']['execution']['dut_files'][0]['source'] = str(link)
    with pytest.raises(ValueError, match='symlink'):
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')


@pytest.mark.parametrize('name', ['inputs.json', 'port-mapping.json', 'ptf-config-db.json'])
def test_loader_rejects_symlink_sidecars(tmp_path, prepared_request, name):
    target = tmp_path / 'compiled'
    compile_inputs(prepared_request, target)
    path = target / name
    outside = tmp_path / name
    path.rename(outside)
    path.symlink_to(outside)
    with pytest.raises(ValueError, match='symlink'):
        execution_api().load_execution_inputs(target, tmp_path / 'artifacts')


def test_legacy_password_tree_requires_preparation(tmp_path, prepared_request):
    assembled = _assembled(prepared_request, tmp_path)
    (tmp_path / 'case_source' / 'legacy.py').write_text(
        'SONIC_PASSWORD = None\n')
    with pytest.raises(ValueError, match='SONIC_PASSWORD'):
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')


def test_source_hash_has_sorted_relative_paths(tmp_path, prepared_request):
    assembled = _assembled(prepared_request, tmp_path)
    root = tmp_path / 'prebuilt_dir'
    first_file = root / 'z.dat'
    second_file = root / 'a.dat'
    first_file.write_bytes(b'\x00\xffz')
    second_file.write_bytes(b'a')
    api = execution_api()
    first = api.validate_execution_config(assembled, tmp_path / 'artifacts')
    first_file.unlink()
    second_file.unlink()
    second_file.write_bytes(b'a')
    first_file.write_bytes(b'\x00\xffz')
    second = api.validate_execution_config(assembled, tmp_path / 'artifacts')
    assert first['source_hash'] == second['source_hash']


def test_validation_never_writes_or_spawns(tmp_path, prepared_request):
    import builtins

    assembled = _assembled(prepared_request, tmp_path)
    original = copy.deepcopy(assembled)
    original_open = builtins.open

    def read_only(file, mode='r', *args, **kwargs):
        assert not any(flag in mode for flag in ('w', 'a', 'x', '+'))
        return original_open(file, mode, *args, **kwargs)

    with patch('builtins.open', side_effect=read_only), patch('os.mkdir') as mkdir, \
            patch('subprocess.run') as run, patch('subprocess.Popen') as popen:
        execution_api().validate_execution_config(assembled, tmp_path / 'artifacts')
        mkdir.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()
    assert assembled == original
    assert not (tmp_path / 'artifacts').exists()


def test_real_ptf_request_layout_and_configuration(execution_spec):
    request = build_ptf_request(execution_spec, 'env-a', 'sairoute.RouteA', 'run-a')
    root = PurePosixPath(execution_spec['runtime']['ptf_root']) / 'env-a'
    assert request['cwd'] == str(root)
    assert request['run_dir'] == str(root / 'runs' / 'run-a')
    argv = request['argv']
    assert argv[argv.index('--test-dir') + 1] == str(root / 'ptf')
    assert argv.count('--interface') == 2
    params = argv[argv.index('--test-params') + 1]
    assert str(root / 'resources' / 'ptf-config-db.json') in params
    assert str(root / 'resources' / 'port_config.ini') in params
    assert str(root / 'runs' / 'run-a') in params
    assert request['env']['PYTHONPATH'].split(':')[:2] == [
        str(root / 'binding'), str(root / 'ptf')]


def _request_params(execution_spec):
    request = build_ptf_request(execution_spec, 'env-a', 'sairoute.RouteA', 'run-a')
    argv = request['argv']
    return parse_ptf_params(argv[argv.index('--test-params') + 1])


def test_ptf_request_embeds_reserved_params_bound_to_owned_tree(execution_spec):
    root = PurePosixPath(execution_spec['runtime']['ptf_root']) / 'env-a'
    params = _request_params(execution_spec)
    assert params['thrift_server'] == execution_spec['execution']['rpc_host']
    assert params['rpc_port'] == execution_spec['runtime']['rpc_port']
    assert params['config_db_json'] == str(root / 'resources' / 'ptf-config-db.json')
    assert params['port_config_ini'] == str(root / 'resources' / 'port_config.ini')
    assert params['result_output_dir'] == str(root / 'runs' / 'run-a')


def test_ptf_request_merges_case_params_and_reserved_win(execution_spec):
    execution_spec['execution']['test_params'] = {
        'router_id': '10.0.0.1', 'retries': 2, 'verbose': True, 'note': None}
    params = _request_params(execution_spec)
    assert params['router_id'] == '10.0.0.1'
    assert params['retries'] == 2
    assert params['verbose'] is True
    assert params['note'] is None
    execution_spec['execution']['test_params']['thrift_server'] = 'evil.invalid'
    execution_spec['execution']['test_params']['result_output_dir'] = '/evil'
    overridden = _request_params(execution_spec)
    root = PurePosixPath(execution_spec['runtime']['ptf_root']) / 'env-a'
    assert overridden['thrift_server'] == execution_spec['execution']['rpc_host']
    assert overridden['result_output_dir'] == str(root / 'runs' / 'run-a')


def test_ptf_request_argv_shape_and_env_ordering(execution_spec):
    execution_spec['execution']['env'] = {'PYTHONPATH': '/custom', 'PTF_MODE': 'strict'}
    request = build_ptf_request(execution_spec, 'env-a', 'sairoute.RouteA', 'run-a')
    root = PurePosixPath(execution_spec['runtime']['ptf_root']) / 'env-a'
    params = request['argv'][request['argv'].index('--test-params') + 1]
    assert request['argv'] == (
        execution_spec['execution']['ptf_argv'] +
        ['--test-dir', str(root / 'ptf'), 'sairoute.RouteA', '--platform', 'eth'] +
        execution_spec['interface_args'] + ['--test-params', params])
    assert request['argv'] is not execution_spec['execution']['ptf_argv']
    assert request['timeout_s'] == execution_spec['runtime']['timeout_s']
    assert request['env'] == {
        'PYTHONPATH': '{}:{}:{}'.format(
            root / 'binding', root / 'ptf', '/custom'),
        'PTF_MODE': 'strict'}
    execution_spec['execution']['env'].pop('PYTHONPATH')
    bare = build_ptf_request(execution_spec, 'env-a', 'sairoute.RouteA', 'run-a')
    assert bare['env']['PYTHONPATH'].endswith(':')
    assert bare['env']['PYTHONPATH'].split(':')[:2] == [str(root / 'binding'), str(root / 'ptf')]


@pytest.mark.parametrize('mutation', [
    lambda spec: spec['runtime'].update(ptf_root='../escape'),
    lambda spec: spec['runtime'].update(timeout_s=0),
    lambda spec: spec['runtime'].pop('rpc_port'),
    lambda spec: spec['execution'].update(ptf_argv=[]),
    lambda spec: spec['execution'].pop('rpc_host'),
    lambda spec: spec.update(interface_args='--interface'),
    lambda spec: spec.update(interface_args=['--interface', 7]),
    lambda spec: spec.pop('execution'),
    lambda spec: spec.pop('runtime'),
])
def test_ptf_request_rejects_unknown_execution_shapes(execution_spec, mutation):
    mutation(execution_spec)
    with pytest.raises(ValueError):
        build_ptf_request(execution_spec, 'env-a', 'sairoute.RouteA', 'run-a')


@pytest.mark.parametrize('environment_id', ['../x', 'env a', 'env/a', '', None, 12, '.env'])
@pytest.mark.parametrize('run_id', ['run-a', '../x', 'run a', 'run/a', '', None, 12])
def test_ptf_request_rejects_bad_identifiers(execution_spec, environment_id, run_id):
    with pytest.raises(ValueError):
        build_ptf_request(execution_spec, environment_id, 'sairoute.RouteA', run_id)


@pytest.mark.parametrize('case', [
    'sairoute', 'RouteA', '', '.RouteA', 'sairoute.', 'sairoute.RouteA;rm',
    None, 123, 'sairoute.RouteA..Extra', 'saivlan.VlanA',
])
def test_ptf_request_case_identifier_boundary(execution_spec, case):
    if case == 'saivlan.VlanA':
        request = build_ptf_request(execution_spec, 'env-a', case, 'run-a')
        assert request['argv'][request['argv'].index('--platform') - 1] == case
    else:
        with pytest.raises(ValueError):
            build_ptf_request(execution_spec, 'env-a', case, 'run-a')
