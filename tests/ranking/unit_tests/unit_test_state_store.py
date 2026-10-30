import base64
import copy
import hashlib
import json
import logging
import os
from unittest.mock import Mock

import pytest

from tests.ranking.environment_ownership import OwnershipError, ResourceStore
from tests.ranking.snapshot_contract import plan_restore
from tests.ranking.state_store import StateStore


RESOURCE = 'dut:machine-a'
ENV = 'env-a'
HASH = 'a' * 64
IMAGE = 'sha256:' + HASH


@pytest.fixture(autouse=True)
def standard_logging(monkeypatch):
    for handler in logging.getLogger().handlers:
        monkeypatch.setattr(handler, 'formatter', logging.Formatter('%(message)s'))


@pytest.fixture
def owned_state(tmp_path):
    ownership = ResourceStore(tmp_path / 'ownership')
    handle = ownership.claim(RESOURCE, ENV, 'op-a')
    return StateStore(tmp_path / 'state', ownership, RESOURCE), ownership, handle


def snapshot(files=None):
    return dict(schema_version=1,
                identity=dict(environment_id=ENV, dut_id='alias-a', image_id=IMAGE,
                              profile_id='profile-a', mapping_hash=HASH),
                services={'swss': 'active', 'syncd': 'inactive'}, files=files or {},
                saiserver=dict(exists=False, running=False, container_name='saiserverv2'))


def ledger():
    return dict(schema_version=1, environment_id=ENV, resource=RESOURCE,
                attempted=[], completed=[])


def persist(state, handle, files=None):
    state.write(handle, 'snapshot.json', snapshot(files))
    state.write(handle, 'ledger.json', ledger())


def state_dir(state, resource=RESOURCE):
    return os.path.join(state.root, hashlib.sha256(resource.encode()).hexdigest(), ENV)


def test_capture_and_restore_leaf_states(owned_state, tmp_path):
    state, ownership, handle = owned_state
    regular, link, absent = (tmp_path / name for name in ('regular', 'link', 'absent'))
    regular.write_bytes(b'\x00\xfforiginal\n')
    regular.chmod(0o6751)
    link.symlink_to('../etc//./original')
    originals = state.capture_files(handle, [str(regular), str(link), str(absent)])
    assert originals == {
        str(regular): dict(state='regular', content_b64=base64.b64encode(
            b'\x00\xfforiginal\n').decode(), mode=0o6751),
        str(link): dict(state='symlink', target='../etc//./original'),
        str(absent): dict(state='absent'),
    }
    persist(state, handle, originals)
    ownership.mark_mutated(handle)
    regular.unlink()
    regular.symlink_to(link)
    link.unlink()
    link.write_bytes(b'replacement')
    absent.write_text('owned replacement')
    state.restore_files(handle, originals)
    assert regular.read_bytes() == b'\x00\xfforiginal\n'
    assert regular.stat().st_mode & 0o7777 == 0o6751
    assert os.readlink(link) == '../etc//./original'
    assert not absent.exists()


@pytest.mark.parametrize('action', ['read', 'write', 'capture_files', 'restore_files',
                                    'mark_attempt', 'complete_attempt', 'path'])
@pytest.mark.parametrize('wrong', ['env', 'operation', 'resource'])
def test_wrong_handle_before_any_environment_access(owned_state, action, wrong):
    state, ownership, handle = owned_state
    persist(state, handle)
    bad = dict(handle)
    if wrong == 'resource':
        bad = ownership.claim('dut:other-machine', ENV, 'op-b')
    elif wrong == 'env':
        bad['environment_id'] = 'env-other'
    else:
        bad['operation_id'] = 'op-old'
    state._open_environment = Mock(side_effect=AssertionError('unauthorized access'))
    args = {'read': ('snapshot.json',), 'write': ('ledger.json', ledger()),
            'capture_files': ([],), 'restore_files': ({},),
            'mark_attempt': ('start:saiserver',), 'complete_attempt': ('start:saiserver',),
            'path': ('snapshot.json',)}
    with pytest.raises(OwnershipError):
        getattr(state, action)(bad, *args[action])
    state._open_environment.assert_not_called()


def test_attempt_is_durable_before_role_failure(owned_state, tmp_path):
    state, _, handle = owned_state
    path = str(tmp_path / 'original')
    persist(state, handle, {path: {'state': 'absent'}})
    with pytest.raises(RuntimeError):
        state.mark_attempt(handle, 'restore:' + path)
        raise RuntimeError('role action failed')
    result = state.read(handle, 'ledger.json')
    assert result['attempted'] == ['restore:' + path]
    assert result['completed'] == []
    assert plan_restore(state.read(handle, 'snapshot.json'), result['attempted']) == [
        ('restore_files', {path: {'state': 'absent'}})]
    state.complete_attempt(handle, 'restore:' + path)
    assert state.read(handle, 'ledger.json')['completed'] == ['restore:' + path]


def test_original_is_immutable_and_read_detached(owned_state):
    state, ownership, handle = owned_state
    persist(state, handle)
    original = state.read(handle, 'snapshot.json')
    original['services']['swss'] = 'absent'
    with pytest.raises(OwnershipError):
        state.write(handle, 'snapshot.json', original)
    assert state.read(handle, 'snapshot.json') == snapshot()
    ownership.keep(handle)
    resumed = ownership.resume(RESOURCE, ENV, 'op-b')
    assert state.read(resumed, 'snapshot.json') == snapshot()
    state.write(resumed, 'snapshot.json', snapshot())


@pytest.mark.parametrize('name', ['../snapshot.json', 'x/snapshot.json', '/snapshot.json',
                                  'other.json', '', None])
def test_names_are_whitelisted_without_mutation(owned_state, name):
    state, ownership, handle = owned_state
    with pytest.raises(OwnershipError):
        state.write(handle, name, snapshot())
    assert not os.path.exists(state.root)
    with ownership.authorized(handle):
        pass


@pytest.mark.parametrize('change', [
    {'schema_version': True}, {'extra': 'unknown'}, {'identity': {}},
    {'services': {'swss': True}}, {'saiserver': {'exists': 0, 'running': False}},
])
def test_malformed_records_do_not_mutate(owned_state, change):
    state, ownership, handle = owned_state
    persist(state, handle)
    before = state.read(handle, 'snapshot.json')
    with pytest.raises(OwnershipError):
        state.write(handle, 'snapshot.json', dict(before, **change))
    assert state.read(handle, 'snapshot.json') == before
    with ownership.authorized(handle):
        pass


@pytest.mark.parametrize('raw', ['[]', '{', '{"schema_version":1,"schema_version":1}',
                                 '{"x":NaN}', '{"x":Infinity}'])
def test_strict_json_read(owned_state, raw):
    state, _, handle = owned_state
    persist(state, handle)
    with open(os.path.join(state_dir(state), 'ledger.json'), 'w') as stream:
        stream.write(raw)
    with pytest.raises(OwnershipError):
        state.read(handle, 'ledger.json')


def test_missing_ledger_is_not_silently_created(owned_state):
    state, _, handle = owned_state
    state.write(handle, 'snapshot.json', snapshot())
    with pytest.raises(OwnershipError):
        state.mark_attempt(handle, 'start:saiserver')
    assert not os.path.exists(os.path.join(state_dir(state), 'ledger.json'))


def test_state_and_ownership_roots_must_be_separate(tmp_path):
    ownership = ResourceStore(tmp_path / 'protected')
    for root in (ownership.root, ownership.root + '/state', str(tmp_path)):
        with pytest.raises(ValueError):
            StateStore(root, ownership, RESOURCE)


def baseline():
    original = snapshot()
    digest = hashlib.sha256(json.dumps(original, sort_keys=True, separators=(',', ':'),
                                       ensure_ascii=True).encode('ascii')).hexdigest()
    return dict(schema_version=1, environment_id=ENV, resource=RESOURCE,
                snapshot_identity=original['identity'], snapshot_sha256=digest,
                ports={'Ethernet0': dict(admin_state='up', oper_state='down', speed='100G')})


def environment(state, handle):
    ptf_id = 'b' * 64
    return dict(schema_version=1, environment_id=ENV, resource=RESOURCE,
                backend='physical_fanout', dut_id='alias-a', dut_image_fingerprint=IMAGE,
                saiserver_image_id='sha256:' + 'c' * 64, saiserver_container_name='saiserverv2',
                current_saiserver_container_id=None, ptf_host_id='ptf-a', ptf_container_id=ptf_id,
                profile_id='profile-a', profile_hash=HASH,
                source_identity={'repo': 'SAI', 'commit': 'd' * 40, 'metadata': {'branch': 1}},
                source_hash='e' * 64, mapping_hash=HASH,
                snapshot_path=state.path(handle, 'snapshot.json'),
                baseline_path=state.path(handle, 'baseline.json'),
                peer_resource='ptf:ptf-a:' + ptf_id, snapshot_complete=False)


def run(state, handle, run_id='run-a', **changes):
    value = dict(schema_version=1, environment_id=ENV, run_id=run_id, phase='prepared',
                 process_exited=False, collected=False,
                 outcome_path=state_dir(state) + '/runs/' + run_id + '/outcome.json')
    value.update(changes)
    return value


def ptf_run(staging_path, run_id='run-a', **changes):
    value = dict(schema_version=1, environment_id=ENV, run_id=run_id, phase='prepared',
                 process_exited=False, collected=False,
                 outcome_path=staging_path + '/runs/' + run_id + '/outcome.json')
    value.update(changes)
    return value


@pytest.mark.parametrize('name', ['environment.json', 'baseline.json', 'ledger.json', 'run-state.json'])
@pytest.mark.parametrize('change', [{'schema_version': True}, {'extra': 1}, {'environment_id': 'wrong'}])
def test_invalid_first_record_does_not_create_state(owned_state, name, change):
    state, ownership, handle = owned_state
    values = {'environment.json': environment(state, handle), 'baseline.json': baseline(),
              'ledger.json': ledger(), 'run-state.json': run(state, handle)}
    with pytest.raises(OwnershipError):
        state.write(handle, name, dict(values[name], **change))
    assert not os.path.exists(state.root)
    with ownership.authorized(handle):
        pass


@pytest.mark.parametrize('name', ['environment.json', 'baseline.json', 'ledger.json'])
def test_all_records_exact_roundtrip_and_bound_reads(owned_state, name):
    state, _, handle = owned_state
    persist(state, handle)
    values = {'environment.json': environment(state, handle), 'baseline.json': baseline(),
              'ledger.json': ledger()}
    value = values[name]
    state.write(handle, name, value)
    assert state.read(handle, name) == value
    value['environment_id'] = 'wrong'
    with open(os.path.join(state_dir(state), name), 'w') as stream:
        json.dump(value, stream)
    with pytest.raises(OwnershipError):
        state.read(handle, name)


@pytest.mark.parametrize('change', [
    {'dut_image_fingerprint': 'sha256:' + 'b' * 64}, {'profile_id': 'other'},
    {'mapping_hash': 'b' * 64}, {'ptf_container_id': 'c' * 64},
    {'profile_hash': 'not-a-hash'}, {'snapshot_path': '/outside/snapshot.json'},
    {'baseline_path': None}, {'snapshot_complete': 1}, {'source_identity': {}},
    {'current_saiserver_container_id': 'short'}, {'saiserver_image_id': HASH},
    {'dut_id': 'machine-a'}, {'saiserver_container_name': 'other'},
])
def test_environment_rejects_bad_metadata(owned_state, change):
    state, _, handle = owned_state
    persist(state, handle)
    value = environment(state, handle)
    with pytest.raises(OwnershipError):
        state.write(handle, 'environment.json', dict(value, **change))


@pytest.mark.parametrize('field', ['profile_hash', 'source_hash', 'saiserver_image_id', 'source_identity'])
def test_metadata_hashes_pinned_after_enrollment(owned_state, field):
    state, _, handle = owned_state
    persist(state, handle)
    value = environment(state, handle)
    state.write(handle, 'environment.json', value)
    changed = dict(value)
    changed[field] = {'repo': 'OTHER'} if field == 'source_identity' else (
        'sha256:' + 'f' * 64 if field == 'saiserver_image_id' else 'f' * 64)
    with pytest.raises(OwnershipError):
        state.write(handle, 'environment.json', changed)
    assert state.read(handle, 'environment.json') == value


def test_snapshot_completeness_requires_local_proofs(owned_state):
    state, _, handle = owned_state
    persist(state, handle)
    value = environment(state, handle)
    with pytest.raises(OwnershipError):
        state.write(handle, 'environment.json', dict(value, snapshot_complete=True))
    state.write(handle, 'environment.json', value)
    with pytest.raises(OwnershipError):
        state.write(handle, 'environment.json', dict(value, snapshot_complete=True))
    state.write(handle, 'baseline.json', baseline())
    complete = dict(value, snapshot_complete=True, current_saiserver_container_id='f' * 64)
    state.write(handle, 'environment.json', complete)
    assert state.read(handle, 'environment.json') == complete
    with pytest.raises(OwnershipError):
        state.write(handle, 'environment.json', value)
    with open(os.path.join(state_dir(state), 'baseline.json'), 'w') as stream:
        json.dump(dict(baseline(), snapshot_sha256='0' * 64), stream)
    with pytest.raises(OwnershipError):
        state.read(handle, 'environment.json')


@pytest.mark.parametrize('change', [
    {'snapshot_sha256': 'b' * 64}, {'snapshot_identity': {}}, {'ports': []},
    {'ports': {'Ethernet0': dict(admin_state=True, oper_state='up', speed='100G')}},
    {'ports': {'Ethernet0': dict(admin_state='up', oper_state='unknown', speed='100G')}},
    {'ports': {'Ethernet0': dict(admin_state='up', oper_state='up', speed='')}},
    {'ports': {'Ethernet0': dict(admin_state='up', oper_state='up', speed='100G', extra=1)}},
])
def test_baseline_rejects_invalid_proof_and_port_states(owned_state, change):
    state, _, handle = owned_state
    persist(state, handle)
    state.write(handle, 'baseline.json', baseline())
    with pytest.raises(OwnershipError):
        state.write(handle, 'baseline.json', dict(baseline(), **change))
    assert state.read(handle, 'baseline.json') == baseline()


def test_baseline_immutable(owned_state):
    state, _, handle = owned_state
    persist(state, handle)
    state.write(handle, 'baseline.json', baseline())
    changed = copy.deepcopy(baseline())
    changed['ports']['Ethernet0']['oper_state'] = 'up'
    with pytest.raises(OwnershipError):
        state.write(handle, 'baseline.json', changed)


@pytest.mark.parametrize('change', [
    {'attempted': ['unknown']}, {'attempted': ['stop:notdeclared']},
    {'attempted': ['start:saiserver', 'start:saiserver']}, {'attempted': 'start:saiserver'},
    {'completed': ['start:saiserver']}, {'attempted': [True]}, {'resource': 'dut:other'},
])
def test_ledger_rejects_malformed_markers(owned_state, change):
    state, _, handle = owned_state
    persist(state, handle)
    with pytest.raises(OwnershipError):
        state.write(handle, 'ledger.json', dict(ledger(), **change))
    assert state.read(handle, 'ledger.json') == ledger()


def test_ledger_monotonic_and_nonattempted_completion(owned_state):
    state, _, handle = owned_state
    persist(state, handle)
    with pytest.raises(OwnershipError):
        state.complete_attempt(handle, 'start:saiserver')
    for marker in ('stop:swss', 'start:saiserver'):
        state.mark_attempt(handle, marker)
        state.mark_attempt(handle, marker)
        state.complete_attempt(handle, marker)
    current = state.read(handle, 'ledger.json')
    for changed in (ledger(), dict(current, attempted=current['attempted'][::-1]),
                    dict(current, completed=[])):
        with pytest.raises(OwnershipError):
            state.write(handle, 'ledger.json', changed)
    assert state.read(handle, 'ledger.json') == current


@pytest.mark.parametrize('change', [
    {'phase': 'unknown'}, {'phase': True}, {'process_exited': 1}, {'collected': 1},
    {'collected': True}, {'phase': 'collected'}, {'run_id': '../bad'},
    {'outcome_path': '/outside/outcome.json'}, {'schema_version': True},
])
def test_run_state_strict(ptf_state, change):
    state, handle, value = ptf_state
    state.write(handle, 'snapshot.json', value)
    with pytest.raises(OwnershipError):
        state.write(handle, 'run-state.json', ptf_run(value['staging_path'], **change))


def test_run_state_requires_existing_snapshot(ptf_state):
    state, handle, value = ptf_state
    with pytest.raises(OwnershipError):
        state.write(handle, 'run-state.json', ptf_run(value['staging_path']))
    assert not os.path.exists(state.root)
    state.write(handle, 'snapshot.json', value)
    state.write(handle, 'run-state.json', ptf_run(value['staging_path']))
    assert state.read(handle, 'run-state.json')['run_id'] == 'run-a'


def test_run_state_is_ptf_only(owned_state):
    state, _, handle = owned_state
    value = dict(schema_version=1, environment_id=ENV, run_id='run-a', phase='prepared',
                 process_exited=False, collected=False,
                 outcome_path='/tmp/stage/runs/run-a/outcome.json')
    with pytest.raises(ValueError):
        state._validate(None, handle, 'run-state.json', value)
    with pytest.raises(OwnershipError):
        state.write(handle, 'run-state.json', value)
    assert not os.path.exists(state.root)


def test_run_state_lifecycle_and_outcome_binding(ptf_state):
    state, handle, value = ptf_state
    staging = value['staging_path']
    state.write(handle, 'snapshot.json', value)
    chain = (ptf_run(staging), ptf_run(staging, phase='running', process_exited=True),
             ptf_run(staging, phase='collecting', process_exited=True),
             ptf_run(staging, phase='collected', process_exited=True, collected=True))
    for record in chain:
        state.write(handle, 'run-state.json', record)
    assert state.read(handle, 'run-state.json') == chain[-1]
    state.write(handle, 'run-state.json', ptf_run(staging, run_id='run-b'))
    assert state.read(handle, 'run-state.json') == ptf_run(staging, run_id='run-b')


def test_run_state_outcome_must_match_staging(ptf_state):
    state, handle, value = ptf_state
    staging = value['staging_path']
    state.write(handle, 'snapshot.json', value)
    directory = state_dir(state, handle['resource'])
    for outcome in (directory + '/runs/run-a/outcome.json',
                    '/tmp/other-stage/runs/run-a/outcome.json',
                    staging + '/run-a/outcome.json',
                    staging + '/runs/run-x/outcome.json'):
        with pytest.raises(OwnershipError):
            state.write(handle, 'run-state.json', ptf_run(staging, outcome_path=outcome))
    with open(os.path.join(directory, 'run-state.json'), 'w') as stream:
        json.dump(ptf_run(staging, outcome_path=staging + '/runs/run-a/other.json'), stream)
    with pytest.raises(OwnershipError):
        state.read(handle, 'run-state.json')
    assert not os.path.exists(os.path.join(directory, 'runs'))


def test_run_state_transitions(ptf_state):
    state, handle, value = ptf_state
    staging = value['staging_path']
    state.write(handle, 'snapshot.json', value)
    state.write(handle, 'run-state.json', ptf_run(staging))
    state.write(handle, 'run-state.json', ptf_run(staging, phase='running'))
    with pytest.raises(OwnershipError):
        state.write(handle, 'run-state.json', ptf_run(staging, phase='prepared'))
    state.write(handle, 'run-state.json',
                ptf_run(staging, phase='failed', process_exited=True))
    with pytest.raises(OwnershipError):
        state.write(handle, 'run-state.json',
                    ptf_run(staging, phase='running', process_exited=True))
    assert state.read(handle, 'run-state.json')['phase'] == 'failed'


def test_run_state_collected_is_terminal(ptf_state):
    state, handle, value = ptf_state
    staging = value['staging_path']
    state.write(handle, 'snapshot.json', value)
    for record in (ptf_run(staging), ptf_run(staging, phase='running', process_exited=True),
                   ptf_run(staging, phase='collecting', process_exited=True),
                   ptf_run(staging, phase='collected', process_exited=True, collected=True)):
        state.write(handle, 'run-state.json', record)
    with pytest.raises(OwnershipError):
        state.write(handle, 'run-state.json',
                    ptf_run(staging, phase='running', process_exited=True, collected=True))
    with pytest.raises(OwnershipError):
        state.write(handle, 'run-state.json',
                    ptf_run(staging, phase='failed', process_exited=True))
    assert state.read(handle, 'run-state.json')['phase'] == 'collected'


def test_run_state_roundtrip_and_bound_read(ptf_state):
    state, handle, value = ptf_state
    state.write(handle, 'snapshot.json', value)
    record = ptf_run(value['staging_path'])
    state.write(handle, 'run-state.json', record)
    assert state.read(handle, 'run-state.json') == record
    record['environment_id'] = 'wrong'
    with open(os.path.join(state_dir(state, handle['resource']), 'run-state.json'), 'w') as stream:
        json.dump(record, stream)
    with pytest.raises(OwnershipError):
        state.read(handle, 'run-state.json')


def test_run_cannot_reset_uncollected_or_same_run_progress(ptf_state):
    state, handle, value = ptf_state
    staging = value['staging_path']
    state.write(handle, 'snapshot.json', value)
    state.write(handle, 'run-state.json', ptf_run(staging, phase='running'))
    with pytest.raises(OwnershipError):
        state.write(handle, 'run-state.json', ptf_run(staging, run_id='run-b'))
    with pytest.raises(OwnershipError):
        state.write(handle, 'run-state.json', ptf_run(staging))
    state.write(handle, 'run-state.json',
                ptf_run(staging, phase='failed', process_exited=True))
    with pytest.raises(OwnershipError):
        state.write(handle, 'run-state.json', ptf_run(staging, run_id='run-b'))
    with pytest.raises(OwnershipError):
        state.write(handle, 'run-state.json', ptf_run(staging, phase='collected',
                                                      process_exited=True, collected=True))
    assert state.read(handle, 'run-state.json')['phase'] == 'failed'


@pytest.mark.parametrize('kind', ['symlink', 'fifo', 'hardlink', 'unknown', 'directory', 'unprotected'])
def test_unsafe_state_entries_fail_closed(owned_state, tmp_path, kind):
    state, ownership, handle = owned_state
    persist(state, handle)
    path = os.path.join(state_dir(state), 'ledger.json')
    if kind == 'unprotected':
        os.chmod(path, 0o644)
    elif kind == 'unknown':
        with open(os.path.join(state_dir(state), 'unknown.json'), 'w') as stream:
            stream.write('{}')
    else:
        os.unlink(path)
        if kind == 'symlink':
            os.symlink(tmp_path / 'outside', path)
        elif kind == 'fifo':
            os.mkfifo(path, 0o600)
        elif kind == 'directory':
            os.mkdir(path, 0o700)
        else:
            source = tmp_path / 'outside'
            source.write_text('{}')
            source.chmod(0o600)
            os.link(source, path)
    with pytest.raises(OwnershipError):
        state.read(handle, 'snapshot.json')
    with pytest.raises(OwnershipError):
        state.write(handle, 'ledger.json', ledger())
    with ownership.authorized(handle):
        pass


@pytest.mark.parametrize('level', ['root', 'resource', 'environment'])
def test_state_directory_symlink_substitution(owned_state, tmp_path, level):
    state, ownership, handle = owned_state
    persist(state, handle)
    path = {'root': state.root, 'resource': os.path.dirname(state_dir(state)),
            'environment': state_dir(state)}[level]
    os.rename(path, path + '-original')
    outside = tmp_path / 'outside'
    outside.mkdir()
    os.symlink(outside, path)
    with pytest.raises(OwnershipError):
        state.read(handle, 'snapshot.json')
    assert list(outside.iterdir()) == []
    with ownership.authorized(handle):
        pass


@pytest.mark.parametrize('kind', ['fifo', 'hardlink', 'directory', 'socket'])
def test_capture_rejects_unsafe_leaves(owned_state, tmp_path, kind):
    import socket
    import tempfile
    state, _, handle = owned_state
    path = tmp_path / 'original'
    server = None
    socket_directory = None
    try:
        if kind == 'fifo':
            os.mkfifo(path)
        elif kind == 'directory':
            path.mkdir()
        elif kind == 'socket':
            server = socket.socket(socket.AF_UNIX)
            socket_directory = tempfile.TemporaryDirectory()
            path = os.path.realpath(socket_directory.name) + '/s'
            server.bind(path)
        else:
            source = tmp_path / 'source'
            source.write_bytes(b'original')
            os.link(source, path)
        with pytest.raises(OwnershipError):
            state.capture_files(handle, [str(path)])
    finally:
        if server is not None:
            server.close()
        if socket_directory is not None:
            socket_directory.cleanup()


def test_capture_detects_same_inode_mutation(owned_state, tmp_path, monkeypatch):
    state, _, handle = owned_state
    path = tmp_path / 'original'
    path.write_bytes(b'original')
    real_fdopen = os.fdopen

    def mutating_fdopen(file_fd, *args, **kwargs):
        stream = real_fdopen(file_fd, *args, **kwargs)
        real_read = stream.read

        def read(*arguments):
            content = real_read(*arguments)
            with open(path, 'ab') as mutated:
                mutated.write(b'-extra')
            return content

        stream.read = read
        return stream

    monkeypatch.setattr(os, 'fdopen', mutating_fdopen)
    with pytest.raises(OwnershipError):
        state.capture_files(handle, [str(path)])


def test_capture_detects_symlink_swap(owned_state, tmp_path, monkeypatch):
    state, _, handle = owned_state
    path = tmp_path / 'original'
    path.symlink_to('first')
    real_readlink = os.readlink

    def swap(target, *args, **kwargs):
        value = real_readlink(target, *args, **kwargs)
        os.unlink(target, dir_fd=kwargs.get('dir_fd'))
        os.symlink('second', target, dir_fd=kwargs.get('dir_fd'))
        return value

    monkeypatch.setattr(os, 'readlink', swap)
    with pytest.raises(OwnershipError):
        state.capture_files(handle, [str(path)])
    assert os.readlink(path) == 'second'


def test_capture_accepts_unchanged_leaf_after_recheck(owned_state, tmp_path, monkeypatch):
    state, _, handle = owned_state
    path = tmp_path / 'original'
    path.write_bytes(b'stable')
    path.chmod(0o600)
    real_fdopen = os.fdopen

    def rereading_fdopen(file_fd, *args, **kwargs):
        stream = real_fdopen(file_fd, *args, **kwargs)
        real_read = stream.read

        def read(*arguments):
            content = real_read(*arguments)
            real_read(*arguments)
            return content

        stream.read = read
        return stream

    monkeypatch.setattr(os, 'fdopen', rereading_fdopen)
    assert state.capture_files(handle, [str(path)]) == {
        str(path): dict(state='regular', content_b64=base64.b64encode(b'stable').decode(),
                        mode=0o600)}


@pytest.mark.parametrize('action', ['capture', 'restore'])
def test_source_parent_nofollow(owned_state, tmp_path, action):
    state, _, handle = owned_state
    directory = tmp_path / 'parent'
    directory.mkdir()
    path = directory / 'original'
    path.write_text('original')
    originals = state.capture_files(handle, [str(path)])
    persist(state, handle, originals)
    directory.rename(tmp_path / 'moved')
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'original').write_text('outside')
    directory.symlink_to(outside, target_is_directory=True)
    with pytest.raises(OwnershipError):
        if action == 'capture':
            state.capture_files(handle, [str(path)])
        else:
            state.restore_files(handle, originals)
    assert (outside / 'original').read_text() == 'outside'


@pytest.mark.parametrize('mode', [0, 0o600, 0o777, 0o1755, 0o2750, 0o4755, 0o7777])
def test_full_mode_range_restore(owned_state, tmp_path, mode):
    state, _, handle = owned_state
    path = tmp_path / 'original'
    original = {'state': 'regular', 'content_b64': 'AP8=', 'mode': mode}
    persist(state, handle, {str(path): original})
    state.restore_files(handle, {str(path): original})
    assert path.stat().st_mode & 0o7777 == mode
    path.chmod(mode | 0o400)
    assert path.read_bytes() == b'\x00\xff'


@pytest.mark.parametrize('original', [
    {'state': 'regular', 'content_b64': 'Zh==', 'mode': 0o600},
    {'state': 'regular', 'content_b64': 'Zg==\n', 'mode': 0o600},
    {'state': 'regular', 'content_b64': '!!!!', 'mode': 0o600},
    {'state': 'regular', 'content_b64': 'Zg==', 'mode': True},
    {'state': 'regular', 'content_b64': 'Zg==', 'mode': 0o10000},
    {'state': 'regular', 'content_b64': 'Zg==', 'mode': -1},
    {'state': 'symlink', 'target': ''}, {'state': 'symlink', 'target': 'x\x00y'},
    {'state': 'absent', 'extra': True},
])
def test_file_state_validator_reused(owned_state, tmp_path, original):
    state, _, handle = owned_state
    path = str(tmp_path / 'original')
    with pytest.raises(OwnershipError):
        state.write(handle, 'snapshot.json', snapshot({path: original}))
    assert not os.path.exists(state.root)


@pytest.mark.parametrize('original', [{'state': 'absent'},
                                      {'state': 'symlink', 'target': '../original'}])
def test_restore_never_recurses_into_unknown_directories(owned_state, tmp_path, original):
    state, _, handle = owned_state
    path = tmp_path / 'original'
    persist(state, handle, {str(path): original})
    path.mkdir()
    (path / 'unknown').write_text('retain')
    with pytest.raises(OwnershipError):
        state.restore_files(handle, {str(path): original})
    assert (path / 'unknown').read_text() == 'retain'


def test_restore_rejects_undeclared_and_forged_originals(owned_state, tmp_path):
    state, _, handle = owned_state
    path = str(tmp_path / 'original')
    persist(state, handle, {path: {'state': 'absent'}})
    for originals in ({str(tmp_path / 'outside'): {'state': 'absent'}},
                      {path: {'state': 'symlink', 'target': '../original'}}):
        with pytest.raises(OwnershipError):
            state.restore_files(handle, originals)


def test_restore_rejects_writable_parent_directory(owned_state, tmp_path):
    state, _, handle = owned_state
    directory = tmp_path / 'parent'
    directory.mkdir()
    directory.chmod(0o772)
    path = str(directory / 'original')
    original = {'state': 'regular', 'content_b64': 'AP8=', 'mode': 0o600}
    persist(state, handle, {path: original})
    with pytest.raises(OwnershipError):
        state.restore_files(handle, {path: original})
    assert not os.path.exists(directory / 'original')


def test_restore_allows_shared_readable_parent_directory(owned_state, tmp_path):
    state, _, handle = owned_state
    directory = tmp_path / 'parent'
    directory.mkdir()
    directory.chmod(0o755)
    path = str(directory / 'original')
    original = {'state': 'regular', 'content_b64': 'AP8=', 'mode': 0o600}
    persist(state, handle, {path: original})
    state.restore_files(handle, {path: original})
    assert (directory / 'original').read_bytes() == b'\x00\xff'


def test_restore_detects_leaf_change_before_commit(owned_state, tmp_path, monkeypatch):
    state, _, handle = owned_state
    path = tmp_path / 'original'
    path.write_bytes(b'original')
    originals = state.capture_files(handle, [str(path)])
    persist(state, handle, originals)
    real_open = os.open

    def swap_during_temporary_creation(*args, **kwargs):
        result = real_open(*args, **kwargs)
        if isinstance(args[0], str) and args[0].startswith('.ranking-restore-'):
            with open(path, 'wb') as mutated:
                mutated.write(b'replaced-content')
        return result

    monkeypatch.setattr(os, 'open', swap_during_temporary_creation)
    with pytest.raises(OwnershipError):
        state.restore_files(handle, originals)
    assert path.read_bytes() == b'replaced-content'
    assert not any(name.startswith('.ranking-restore-') for name in os.listdir(tmp_path))


def test_restore_detects_absent_leaf_appearance_before_commit(owned_state, tmp_path,
                                                              monkeypatch):
    state, _, handle = owned_state
    path = tmp_path / 'original'
    declared = {str(path): {'state': 'symlink', 'target': 'gone'}}
    persist(state, handle, declared)
    real_symlink = os.symlink

    def appear_during_temporary_creation(target, temporary, *args, **kwargs):
        real_symlink(target, temporary, *args, **kwargs)
        if isinstance(temporary, str) and temporary.startswith('.ranking-restore-'):
            path.write_bytes(b'unexpected')

    monkeypatch.setattr(os, 'symlink', appear_during_temporary_creation)
    with pytest.raises(OwnershipError):
        state.restore_files(handle, declared)
    assert path.read_bytes() == b'unexpected'
    assert not any(name.startswith('.ranking-restore-') for name in os.listdir(tmp_path))


@pytest.mark.parametrize('failure', ['write', 'fsync', 'replace'])
def test_atomic_failure_retains_record_and_active_owner(owned_state, monkeypatch, failure):
    state, ownership, handle = owned_state
    persist(state, handle)
    path = os.path.join(state_dir(state), 'ledger.json')
    with open(path, 'rb') as stream:
        before = stream.read()

    def fail(*args, **kwargs):
        raise OSError('injected JSON ' + failure)
    if failure == 'write':
        monkeypatch.setattr(state, '_atomic_json', fail)
    else:
        monkeypatch.setattr(os, failure, fail)
    with pytest.raises(OwnershipError):
        state.mark_attempt(handle, 'start:saiserver')
    with open(path, 'rb') as stream:
        assert stream.read() == before
    owner_dir = os.path.join(ownership.root, hashlib.sha256(RESOURCE.encode()).hexdigest())
    with open(os.path.join(owner_dir, 'owner.json')) as stream:
        assert json.load(stream)['operation_id'] == handle['operation_id']
    assert os.path.exists(os.path.join(owner_dir, 'transition.json'))


def test_atomic_failure_cleans_temporary_entry(owned_state, monkeypatch):
    state, ownership, handle = owned_state
    persist(state, handle)
    real_replace = os.replace

    def fail(*args, **kwargs):
        if str(args[0]).startswith('.state-'):
            raise OSError('injected replace failure')
        return real_replace(*args, **kwargs)

    monkeypatch.setattr(os, 'replace', fail)
    with pytest.raises(OwnershipError):
        state.mark_attempt(handle, 'start:saiserver')
    assert not any(name.startswith('.state-') for name in os.listdir(state_dir(state)))
    monkeypatch.setattr(os, 'replace', real_replace)
    owner_dir = os.path.join(ownership.root, hashlib.sha256(RESOURCE.encode()).hexdigest())
    os.unlink(os.path.join(owner_dir, 'transition.json'))
    value = state.read(handle, 'ledger.json')
    value['attempted'].append('start:saiserver')
    state.write(handle, 'ledger.json', value)
    assert state.read(handle, 'ledger.json') == value
    assert not any(name.startswith('.state-') for name in os.listdir(state_dir(state)))


@pytest.fixture
def ptf_state(tmp_path):
    ownership = ResourceStore(tmp_path / 'ownership')
    resource = 'ptf:ptf-a:' + 'b' * 64
    handle = ownership.claim(resource, ENV, 'op-a')
    state = StateStore(tmp_path / 'state', ownership, resource)
    value = dict(schema_version=1, environment_id=ENV, resource=resource,
                 peer_resource=RESOURCE, container_id='b' * 64, running=True,
                 interfaces=[{'id': 1, 'name': 'eth1'}, {'id': 0, 'name': 'eth0'}],
                 staging_path=os.path.dirname(state.path(handle, 'snapshot.json')) + '/ptf-stage',
                 staging_state='absent')
    return state, handle, value


def test_ptf_snapshot_metadata_and_ledger(ptf_state):
    state, handle, value = ptf_state
    state.write(handle, 'snapshot.json', value)
    assert state.read(handle, 'snapshot.json') == value
    entry = dict(ledger(), resource=handle['resource'])
    state.write(handle, 'ledger.json', entry)
    state.mark_attempt(handle, 'stage:ptf')
    state.complete_attempt(handle, 'stage:ptf')
    assert state.read(handle, 'ledger.json')['attempted'] == ['stage:ptf']
    with pytest.raises(OwnershipError):
        state.mark_attempt(handle, 'start:saiserver')
    with pytest.raises(OwnershipError):
        state.write(handle, 'baseline.json', baseline())


@pytest.mark.parametrize('change', [
    {'container_id': 'c' * 64}, {'container_id': 'short'}, {'running': False}, {'running': 1},
    {'interfaces': [{'id': True, 'name': 'eth0'}]},
    {'interfaces': [{'id': -1, 'name': 'eth0'}]},
    {'interfaces': [{'id': 0, 'name': '../eth0'}]},
    {'interfaces': [{'id': 0, 'name': 'eth0', 'extra': 1}]},
    {'interfaces': [{'id': 0, 'name': 'eth0'}, {'id': 0, 'name': 'eth1'}]},
    {'staging_path': '/root/ptf'}, {'staging_state': 'regular'},
    {'peer_resource': 'ptf:ptf-a:' + 'b' * 64}, {'extra': 1}, {'schema_version': True},
])
def test_ptf_rejects_unsafe_original_metadata(ptf_state, change):
    state, handle, value = ptf_state
    with pytest.raises(OwnershipError):
        state.write(handle, 'snapshot.json', dict(value, **change))
    assert not os.path.exists(state.root)


def test_ptf_environment_complete_without_dut_baseline(ptf_state):
    state, handle, original = ptf_state
    state.write(handle, 'snapshot.json', original)
    value = environment(state, handle)
    value.update(resource=handle['resource'], peer_resource=RESOURCE, baseline_path=None)
    state.write(handle, 'environment.json', value)
    state.write(handle, 'environment.json', dict(value, snapshot_complete=True))
    assert state.read(handle, 'environment.json')['snapshot_complete'] is True


@pytest.mark.parametrize('action', ['capture', 'persist', 'restore'])
@pytest.mark.parametrize('reserved', ['ownership', 'state'])
def test_source_files_cannot_bypass_reserved_record_authorization(owned_state, action, reserved):
    state, ownership, handle = owned_state
    persist(state, handle)
    if reserved == 'ownership':
        path = os.path.join(ownership.root, hashlib.sha256(RESOURCE.encode()).hexdigest(), 'owner.json')
    else:
        path = os.path.join(state_dir(state), 'snapshot.json')
    with open(path, 'rb') as stream:
        before = stream.read()
    with pytest.raises(OwnershipError):
        if action == 'capture':
            state.capture_files(handle, [path])
        elif action == 'persist':
            state.write(handle, 'snapshot.json', snapshot({path: {'state': 'absent'}}))
        else:
            state.restore_files(handle, {path: {'state': 'absent'}})
    with open(path, 'rb') as stream:
        assert stream.read() == before


def test_individual_state_read_serializes_ownership_transition(owned_state, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from tests.ranking.environment_ownership import ResourceBusy
    state, ownership, handle = owned_state
    persist(state, handle)
    entered, proceed = Event(), Event()
    original = state._load

    def delayed(*args):
        entered.set()
        assert proceed.wait(timeout=5)
        return original(*args)
    monkeypatch.setattr(state, '_load', delayed)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(state.read, handle, 'snapshot.json')
        try:
            assert entered.wait(timeout=5)
            with pytest.raises(ResourceBusy):
                ownership.keep(handle)
            with pytest.raises(ResourceBusy):
                ownership.resume(RESOURCE, ENV, 'op-b')
        finally:
            proceed.set()
        assert future.result(timeout=5) == snapshot()
    ownership.keep(handle)


@pytest.mark.parametrize('level', ['root', 'resource', 'environment'])
def test_state_directories_must_remain_protected(owned_state, level):
    state, ownership, handle = owned_state
    persist(state, handle)
    path = {'root': state.root, 'resource': os.path.dirname(state_dir(state)),
            'environment': state_dir(state)}[level]
    os.chmod(path, 0o755)
    with pytest.raises(OwnershipError):
        state.read(handle, 'snapshot.json')
    with ownership.authorized(handle):
        pass


def test_unknown_root_entries_are_not_ignored(owned_state):
    state, _, handle = owned_state
    persist(state, handle)
    with open(state.root + '/unknown', 'w') as stream:
        stream.write('untrusted')
    with pytest.raises(OwnershipError):
        state.read(handle, 'snapshot.json')


def test_initial_directory_fsync_failure_keeps_uncertain_transition(owned_state, monkeypatch):
    state, ownership, handle = owned_state
    original = os.fsync
    import stat

    def fail_directory(descriptor):
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError('directory fsync failed')
        return original(descriptor)
    monkeypatch.setattr(os, 'fsync', fail_directory)
    with pytest.raises(OwnershipError):
        state.write(handle, 'snapshot.json', snapshot())
    owner_dir = os.path.join(ownership.root, hashlib.sha256(RESOURCE.encode()).hexdigest())
    assert os.path.exists(os.path.join(owner_dir, 'transition.json'))
    assert os.path.isdir(state.root)


def test_handle_is_detached_before_authorization_yields(owned_state, monkeypatch):
    from contextlib import contextmanager
    state, ownership, handle = owned_state
    persist(state, handle)
    original = ownership.authorized

    @contextmanager
    def mutate_external_handle(validated):
        with original(validated) as transaction:
            handle['environment_id'] = 'env-other'
            yield transaction
    monkeypatch.setattr(ownership, 'authorized', mutate_external_handle)
    assert state.read(handle, 'snapshot.json') == snapshot()


def test_write_input_is_detached_before_validation(owned_state, monkeypatch):
    state, _, handle = owned_state
    persist(state, handle)
    value = ledger()
    original = state._validate

    def mutate_external_input(descriptor, active, name, detached):
        value['environment_id'] = 'env-other'
        return original(descriptor, active, name, detached)
    monkeypatch.setattr(state, '_validate', mutate_external_input)
    state.write(handle, 'ledger.json', value)
    assert state.read(handle, 'ledger.json') == ledger()


def test_baseline_digest_is_derived_by_the_store_when_omitted(owned_state):
    state, _, handle = owned_state
    persist(state, handle)
    value = baseline()
    digest = value.pop('snapshot_sha256')
    state.write(handle, 'baseline.json', value)
    stored = state.read(handle, 'baseline.json')
    assert stored == baseline()
    assert stored['snapshot_sha256'] == digest
    with open(os.path.join(state_dir(state), 'baseline.json')) as stream:
        assert json.load(stream)['snapshot_sha256'] == digest


def test_baseline_with_a_wrong_digest_is_rejected(owned_state):
    state, _, handle = owned_state
    persist(state, handle)
    value = dict(baseline(), snapshot_sha256='0' * 64)
    with pytest.raises(OwnershipError):
        state.write(handle, 'baseline.json', value)
    assert not os.path.exists(os.path.join(state_dir(state), 'baseline.json'))


def test_baseline_digest_derivation_requires_the_original_snapshot(owned_state):
    state, _, handle = owned_state
    value = baseline()
    value.pop('snapshot_sha256')
    with pytest.raises(OwnershipError):
        state.write(handle, 'baseline.json', value)
    assert not os.path.exists(state.root)
