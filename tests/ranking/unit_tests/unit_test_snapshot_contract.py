import copy

import pytest

from tests.ranking.snapshot_contract import plan_restore, validate_snapshot


@pytest.fixture
def snapshot():
    return {
        'schema_version': 1,
        'identity': {
            'environment_id': 'env-a', 'dut_id': 'dut-a',
            'image_id': 'sha256:' + 'a' * 64,
            'profile_id': 'profile-a', 'mapping_hash': 'b' * 64,
        },
        'services': {'swss': 'active', 'syncd': 'active',
                     'bgp': 'inactive', 'acms': 'absent'},
        'files': {},
        'saiserver': {'exists': False, 'running': False},
    }


def test_validate_normalizes_without_aliasing_or_mutating(snapshot):
    before = copy.deepcopy(snapshot)
    expected = copy.deepcopy(snapshot['identity'])
    validated = validate_snapshot(snapshot, expected)
    assert validated['saiserver']['container_name'] == 'saiserverv2'
    assert snapshot == before
    assert expected == before['identity']
    validated['identity']['dut_id'] = 'changed'
    validated['services']['swss'] = 'absent'
    assert snapshot == before


@pytest.mark.parametrize('field', ['environment_id', 'dut_id', 'image_id',
                                   'profile_id', 'mapping_hash'])
def test_all_identity_fields_must_match(snapshot, field):
    expected = dict(snapshot['identity'])
    expected[field] = ('sha256:' + 'c' * 64 if field == 'image_id' else
                       'c' * 64 if field == 'mapping_hash' else 'other')
    with pytest.raises(ValueError):
        validate_snapshot(snapshot, expected)


@pytest.mark.parametrize('expected', [None, {}, [], {'environment_id': 'env-a'}])
def test_expected_identity_must_be_complete(snapshot, expected):
    with pytest.raises(ValueError):
        validate_snapshot(snapshot, expected)


@pytest.mark.parametrize('value', [None, [], '', True, float('nan')])
def test_snapshot_must_be_object(value):
    with pytest.raises(ValueError):
        validate_snapshot(value, {})
    with pytest.raises(ValueError):
        plan_restore(value, [])


@pytest.mark.parametrize('key,value', [
    ('schema_version', True), ('schema_version', 1.0),
    ('schema_version', 2), ('schema_version', float('nan')),
    ('identity', None), ('services', []), ('files', []),
    ('saiserver', None),
])
def test_invalid_top_level_fields(snapshot, key, value):
    snapshot[key] = value
    with pytest.raises(ValueError):
        validate_snapshot(snapshot, snapshot.get('identity'))


@pytest.mark.parametrize('field,value', [
    ('environment_id', '../bad'), ('dut_id', 'host alias'),
    ('profile_id', None), ('image_id', 'latest'),
    ('image_id', 'sha256:' + 'A' * 64), ('mapping_hash', 'b' * 63),
    ('mapping_hash', float('nan')), ('environment_id', True),
])
def test_invalid_identity(snapshot, field, value):
    snapshot['identity'][field] = value
    with pytest.raises(ValueError):
        validate_snapshot(snapshot, dict(snapshot['identity']))


@pytest.mark.parametrize('section', [None, 'identity', 'saiserver'])
def test_unknown_fields_rejected(snapshot, section):
    target = snapshot if section is None else snapshot[section]
    target['unknown'] = 'unexpected'
    with pytest.raises(ValueError):
        validate_snapshot(snapshot, snapshot['identity'])


@pytest.mark.parametrize('services', [
    {'swss': True}, {'swss': 'stopped'}, {'../swss': 'active'},
    {'swss': float('nan')}, {1: 'active'},
])
def test_invalid_services(snapshot, services):
    snapshot['services'] = services
    with pytest.raises(ValueError):
        validate_snapshot(snapshot, snapshot['identity'])


@pytest.mark.parametrize('container', [
    {'exists': True, 'running': False}, {'exists': True, 'running': True},
    {'exists': False, 'running': True}, {'exists': 0, 'running': False},
    {'exists': False, 'running': 0},
    {'exists': False, 'running': False, 'container_name': '../bad'},
    {'exists': False},
])
def test_preexisting_or_invalid_container_rejected(snapshot, container):
    snapshot['saiserver'] = container
    with pytest.raises(ValueError):
        validate_snapshot(snapshot, snapshot['identity'])


def test_actual_restore_examples(snapshot):
    assert plan_restore(snapshot, []) == []
    assert plan_restore(snapshot, ['stop:swss']) == [('start_service', 'swss')]
    assert plan_restore(snapshot, ['stop:swss', 'stop:syncd', 'start:saiserver']) == [
        ('stop_test_container', 'saiserverv2'),
        ('start_service', 'syncd'), ('start_service', 'swss'),
    ]
    assert plan_restore(snapshot, ['stop:bgp', 'stop:acms']) == []


def test_attempt_markers_restore_without_assuming_stop_success(snapshot):
    assert plan_restore(snapshot, ['stop:swss', 'stop:swss']) == [
        ('start_service', 'swss'),
    ]


def test_other_services_follow_snapshot_order(snapshot):
    snapshot['services'] = {'zebra': 'active', 'swss': 'active',
                            'teamd': 'active', 'syncd': 'active'}
    actions = plan_restore(snapshot, ['stop:teamd', 'stop:swss',
                                      'stop:zebra', 'stop:syncd'])
    assert actions == [('start_service', 'syncd'), ('start_service', 'swss'),
                       ('start_service', 'zebra'), ('start_service', 'teamd')]
    assert all('reload' not in action and 'reboot' not in action
               for action in actions)


@pytest.mark.parametrize('changes', [
    ['reload'], ['reboot'], ['stop:undeclared'], ['start:swss'],
    ['restore:/etc/sonic/undeclared'], ['start:saiserverv2'],
    [True], [float('nan')], 'stop:swss', None,
])
def test_unknown_or_malformed_changes_rejected(snapshot, changes):
    with pytest.raises(ValueError):
        plan_restore(snapshot, changes)


def test_file_states_restore_order_and_content(snapshot):
    files = {
        '/etc/sonic/config_db.json': {
            'state': 'regular', 'content_b64': 'eyJhIjoxfQo=', 'mode': 0o640,
        },
        '/etc/sonic/current.json': {
            'state': 'symlink', 'target': 'config_db.saved.json',
        },
        '/etc/sonic/test.json': {'state': 'absent'},
        '/etc/sonic/untouched': {'state': 'regular', 'content_b64': '', 'mode': 0},
    }
    snapshot['files'] = copy.deepcopy(files)
    before = copy.deepcopy(snapshot)
    changes = ['stop:swss', 'restore:/etc/sonic/current.json',
               'start:saiserver', 'restore:/etc/sonic/test.json',
               'stop:syncd', 'restore:/etc/sonic/config_db.json']
    actions = plan_restore(snapshot, changes)
    assert actions == [
        ('stop_test_container', 'saiserverv2'),
        ('restore_files', {path: value for path, value in files.items()
                           if path != '/etc/sonic/untouched'}),
        ('start_service', 'syncd'), ('start_service', 'swss'),
    ]
    assert snapshot == before
    assert changes[0] == 'stop:swss'
    actions[1][1]['/etc/sonic/config_db.json']['content_b64'] = ''
    assert snapshot == before


@pytest.mark.parametrize('path', ['', 'etc/sonic/x', '/', '/etc/../x',
                                  '/etc//x', '/etc/./x', '/etc/x/',
                                  '/etc/x\x00', '/etc/x\\y', 1])
def test_invalid_declared_paths(snapshot, path):
    snapshot['files'] = {path: {'state': 'absent'}}
    with pytest.raises(ValueError):
        validate_snapshot(snapshot, snapshot['identity'])


@pytest.mark.parametrize('state', [
    {}, {'state': 'directory'}, {'state': True},
    {'state': 'absent', 'content_b64': ''},
    {'state': 'regular', 'content_b64': '?', 'mode': 0o644},
    {'state': 'regular', 'content_b64': 'YR==', 'mode': 0o644},
    {'state': 'regular', 'content_b64': '', 'mode': True},
    {'state': 'regular', 'content_b64': '', 'mode': -1},
    {'state': 'regular', 'content_b64': '', 'mode': 0o10000},
    {'state': 'regular', 'content_b64': float('nan'), 'mode': 0o644},
    {'state': 'regular', 'content_b64': '', 'mode': float('nan')},
    {'state': 'regular', 'content_b64': ''},
    {'state': 'symlink', 'target': ''},
    {'state': 'symlink', 'target': 123},
    {'state': 'symlink', 'target': 'a\x00b'},
    {'state': 'symlink', 'target': True},
])
def test_invalid_file_states(snapshot, state):
    snapshot['files'] = {'/etc/sonic/x': state}
    with pytest.raises(ValueError):
        validate_snapshot(snapshot, snapshot['identity'])


@pytest.mark.parametrize('target', [
    '../device/platform/hwsku', './original', '/etc//original',
    '../outside', '/var/run/sonic/original',
])
def test_symlink_target_preserved_verbatim(snapshot, target):
    snapshot['files'] = {'/etc/sonic/x': {'state': 'symlink', 'target': target}}
    validated = validate_snapshot(snapshot, snapshot['identity'])
    assert validated['files']['/etc/sonic/x']['target'] == target


def test_plan_restore_preserves_relative_symlink_target(snapshot):
    snapshot['files'] = {'/etc/sonic/x': {'state': 'symlink',
                                          'target': '../device/platform/hwsku'}}
    actions = plan_restore(snapshot, ['restore:/etc/sonic/x'])
    assert actions == [('restore_files',
                        {'/etc/sonic/x': {'state': 'symlink',
                                          'target': '../device/platform/hwsku'}})]


def test_absolute_symlink_target_and_custom_container(snapshot):
    snapshot['files'] = {'/etc/sonic/x': {'state': 'symlink',
                                          'target': '/etc/sonic/original'}}
    snapshot['saiserver']['container_name'] = 'saiserver-ranking'
    assert plan_restore(snapshot, ['start:saiserver', 'restore:/etc/sonic/x']) == [
        ('stop_test_container', 'saiserver-ranking'),
        ('restore_files', snapshot['files']),
    ]
