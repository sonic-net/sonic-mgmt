import hashlib
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event

import pytest

from tests.ranking.environment_ownership import (
    OwnershipError, ResourceBusy, ResourceStore,
)


RESOURCE = 'dut:dut-a'


@pytest.fixture(autouse=True)
def standard_logging(monkeypatch):
    # --noconftest omits SONiC's custom LogRecord fields.
    for handler in logging.getLogger().handlers:
        monkeypatch.setattr(handler, 'formatter', logging.Formatter('%(message)s'))


def resource_dir(root, resource=RESOURCE):
    return root / hashlib.sha256(resource.encode('utf-8')).hexdigest()


def claim(store, env='env-a', op='op-a'):
    return store.claim(RESOURCE, env, op)


def test_lifecycle_and_explicit_restore(tmp_path):
    store = ResourceStore(tmp_path / 'store')
    handle = claim(store)
    assert handle == dict(resource=RESOURCE, environment_id='env-a',
                          operation_id='op-a', created=True)
    store.mark_mutated(handle)
    store.keep(handle)
    with pytest.raises(ResourceBusy):
        claim(store, 'env-b', 'op-b')
    resumed = store.resume(RESOURCE, 'env-a', 'op-c')
    assert resumed == dict(handle, operation_id='op-c', created=False)
    with pytest.raises(ResourceBusy):
        store.resume(RESOURCE, 'env-a', 'op-d')
    store.keep(resumed)
    with pytest.raises(ResourceBusy):
        claim(ResourceStore(tmp_path / 'store'), 'env-b', 'op-b')
    restored = store.resume(RESOURCE, 'env-a', 'op-e')
    store.release_restored(restored)
    fresh = claim(store, 'env-b', 'op-b')
    store.abort_unmodified(fresh)
    assert list((tmp_path / 'store').iterdir()) == []


def test_same_environment_claim_requires_resume(tmp_path):
    store = ResourceStore(tmp_path / 'store')
    handle = claim(store)
    with pytest.raises(ResourceBusy):
        claim(store)
    store.keep(handle)
    with pytest.raises(ResourceBusy):
        claim(store, op='op-b')
    assert store.resume(RESOURCE, 'env-a', 'op-b')['created'] is False


@pytest.mark.parametrize('method', [
    'mark_mutated', 'keep', 'abort_unmodified', 'release_restored',
])
@pytest.mark.parametrize('field,value', [
    ('operation_id', 'op-other'), ('environment_id', 'env-other'),
    ('resource', 'dut:dut-other'),
])
def test_wrong_handle_never_changes_owner(tmp_path, method, field, value):
    root = tmp_path / 'store'
    store = ResourceStore(root)
    handle = claim(store)
    before = (resource_dir(root) / 'owner.json').read_bytes()
    with pytest.raises(OwnershipError):
        getattr(store, method)(dict(handle, **{field: value}))
    assert (resource_dir(root) / 'owner.json').read_bytes() == before
    with pytest.raises(ResourceBusy):
        claim(store, 'env-b', 'op-b')
    store.abort_unmodified(handle)


def test_abort_rejects_mutated_and_resumed_even_with_forged_created(tmp_path):
    store = ResourceStore(tmp_path / 'store')
    handle = claim(store)
    store.mark_mutated(handle)
    with pytest.raises(OwnershipError):
        store.abort_unmodified(handle)
    store.keep(handle)
    resumed = store.resume(RESOURCE, 'env-a', 'op-a')
    with pytest.raises(OwnershipError):
        store.abort_unmodified(dict(resumed, created=True))
    store.release_restored(resumed)
    handle = claim(store)
    store.keep(handle)
    resumed = store.resume(RESOURCE, 'env-a', 'op-b')
    with pytest.raises(OwnershipError):
        store.abort_unmodified(dict(resumed, created=True))
    store.release_restored(resumed)


def test_resume_wrong_environment_or_missing_owner(tmp_path):
    store = ResourceStore(tmp_path / 'store')
    with pytest.raises(OwnershipError):
        store.resume(RESOURCE, 'env-a', 'op-a')
    handle = claim(store)
    store.keep(handle)
    with pytest.raises(OwnershipError):
        store.resume(RESOURCE, 'env-b', 'op-b')
    store.resume(RESOURCE, 'env-a', 'op-c')


def test_resume_is_idempotent_for_the_active_operation(tmp_path):
    root = tmp_path / 'store'
    store = ResourceStore(root)
    store.keep(claim(store))
    resumed = store.resume(RESOURCE, 'env-a', 'op-b')
    before = (resource_dir(root) / 'owner.json').read_bytes()
    repeated = store.resume(RESOURCE, 'env-a', 'op-b')
    assert repeated == dict(resumed, created=False)
    assert (resource_dir(root) / 'owner.json').read_bytes() == before
    with pytest.raises(ResourceBusy):
        store.resume(RESOURCE, 'env-a', 'op-c')
    peer = ResourceStore(root)
    assert peer.resume(RESOURCE, 'env-a', 'op-b')['created'] is False
    with pytest.raises(ResourceBusy):
        claim(store, 'env-b', 'op-c')
    store.release_restored(repeated)


@pytest.mark.parametrize('resume', [False, True])
@pytest.mark.parametrize('iteration', range(12))
def test_competing_requests_have_one_winner(tmp_path, resume, iteration):
    root = tmp_path / 'store'
    store = ResourceStore(root)
    if resume:
        store.keep(claim(store))
    barrier = Barrier(2)

    def compete(index):
        peer = ResourceStore(root)
        barrier.wait(timeout=5)
        try:
            if resume:
                return peer.resume(RESOURCE, 'env-a', 'op-{}'.format(index))
            return peer.claim(RESOURCE, 'env-{}'.format(index),
                              'op-{}'.format(index))
        except ResourceBusy:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(compete, range(2)))
    assert sum(result is not None for result in results) == 1
    with pytest.raises(ResourceBusy):
        claim(store, 'env-new', 'op-new')


def test_initialization_window_is_not_reclaimed(tmp_path, monkeypatch):
    store = ResourceStore(tmp_path / 'store')
    entered, proceed = Event(), Event()
    original = store._write_owner

    def delayed(*args):
        entered.set()
        assert proceed.wait(timeout=5)
        return original(*args)

    monkeypatch.setattr(store, '_write_owner', delayed)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(claim, store)
        try:
            assert entered.wait(timeout=5)
            with pytest.raises(ResourceBusy):
                claim(ResourceStore(tmp_path / 'store'), 'env-b', 'op-b')
        finally:
            proceed.set()
        handle = future.result(timeout=5)
    store.abort_unmodified(handle)


@pytest.mark.parametrize('state', ['empty', 'broken-json', 'unknown-file',
                                   'owner-link', 'operation-link',
                                   'resource-link', 'owner-hardlink',
                                   'transition-link'])
def test_unknown_states_fail_closed(tmp_path, state):
    root = tmp_path / 'store'
    store = ResourceStore(root)
    handle = claim(store)
    directory = resource_dir(root)
    external = tmp_path / 'external'
    external.write_text('external data')
    if state == 'empty':
        for path in directory.iterdir():
            path.unlink()
    elif state == 'broken-json':
        (directory / 'owner.json').write_text('{')
    elif state == 'unknown-file':
        (directory / 'unexpected').write_text('unknown')
    elif state == 'resource-link':
        for path in directory.iterdir():
            path.unlink()
        directory.rmdir()
        directory.symlink_to(tmp_path, target_is_directory=True)
    else:
        filename = {'operation-link': 'operation.json',
                    'transition-link': 'transition.json'}.get(state, 'owner.json')
        if (directory / filename).exists():
            (directory / filename).unlink()
        if state == 'owner-hardlink':
            os.link(external, directory / filename)
        else:
            (directory / filename).symlink_to(external)
    with pytest.raises(ResourceBusy):
        claim(store, 'env-b', 'op-b')
    with pytest.raises(OwnershipError):
        store.mark_mutated(handle)
    with pytest.raises(OwnershipError):
        store.resume(RESOURCE, 'env-a', 'op-c')
    assert external.read_text() == 'external data'
    assert directory.exists()


@pytest.mark.parametrize('field,value', [
    ('resource', 'dut:other'), ('environment_id', '../bad'),
    ('operation_id', '../bad'), ('mutated', 1), ('abortable', 1),
    ('schema_version', True), ('environment_id', None),
])
def test_invalid_identity_records_rejected(tmp_path, field, value):
    root = tmp_path / 'store'
    store = ResourceStore(root)
    handle = claim(store)
    path = resource_dir(root) / 'owner.json'
    record = json.loads(path.read_text())
    record[field] = value
    path.write_text(json.dumps(record))
    with pytest.raises(OwnershipError):
        store.keep(handle)
    with pytest.raises(OwnershipError):
        store.resume(RESOURCE, 'env-a', 'op-b')
    with pytest.raises(ResourceBusy):
        claim(store, 'env-b', 'op-b')


@pytest.mark.parametrize('resource', [
    '', '../dut', 'dut:', 'dut:../x', 'dut:a/b', 'dut:a\\b', 'DUT:a',
    'ptf:server', 'ptf:server:', 'ptf:server:../x', 'dut:a:extra',
    'dut:a\x00', 'dut:a b', None, 1, True,
])
def test_invalid_resource_keys(tmp_path, resource):
    store = ResourceStore(tmp_path / 'store')
    with pytest.raises(ValueError):
        store.claim(resource, 'env-a', 'op-a')
    with pytest.raises(ValueError):
        store.resume(resource, 'env-a', 'op-a')
    assert list((tmp_path / 'store').iterdir()) == []


@pytest.mark.parametrize('value', ['', '../bad', 'a/b', 'a\\b', 'a:b',
                                   '.', '..', 'a b', None, 1, True])
@pytest.mark.parametrize('field', ['env', 'op'])
def test_invalid_tokens(tmp_path, value, field):
    store = ResourceStore(tmp_path / 'store')
    env, op = (value, 'op-a') if field == 'env' else ('env-a', value)
    with pytest.raises(ValueError):
        store.claim(RESOURCE, env, op)
    with pytest.raises(ValueError):
        store.resume(RESOURCE, env, op)


@pytest.mark.parametrize('method', ['mark_mutated', 'keep',
                                    'abort_unmodified', 'release_restored'])
@pytest.mark.parametrize('handle', [None, {}, {'created': 1}])
def test_malformed_handles_rejected(tmp_path, method, handle):
    store = ResourceStore(tmp_path / 'store')
    with pytest.raises(OwnershipError):
        getattr(store, method)(handle)


def test_root_and_ancestor_symlinks_rejected(tmp_path):
    external = tmp_path / 'external'
    external.mkdir()
    link = tmp_path / 'link'
    link.symlink_to(external, target_is_directory=True)
    for root in (link, link / 'store'):
        with pytest.raises(OwnershipError):
            ResourceStore(root)
    assert list(external.iterdir()) == []


def test_failed_owner_write_retains_reservation(tmp_path, monkeypatch):
    root = tmp_path / 'store'
    store = ResourceStore(root)

    def fail(*args):
        raise OSError('write failure')

    monkeypatch.setattr(store, '_write_owner', fail)
    with pytest.raises(OwnershipError):
        claim(store)
    with pytest.raises(ResourceBusy):
        claim(ResourceStore(root), 'env-b', 'op-b')


def test_failed_release_retains_unknown_lock(tmp_path, monkeypatch):
    root = tmp_path / 'store'
    store = ResourceStore(root)
    handle = claim(store)
    original = os.rmdir

    def fail(path, *args, **kwargs):
        if path == resource_dir(root).name:
            raise OSError('rmdir failure')
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, 'rmdir', fail)
    with pytest.raises(OwnershipError):
        store.release_restored(handle)
    with pytest.raises(ResourceBusy):
        claim(store, 'env-b', 'op-b')


def test_record_recheck_after_resume_operation_creation(tmp_path, monkeypatch):
    root = tmp_path / 'store'
    store = ResourceStore(root)
    store.keep(claim(store))
    original = store._create_operation

    def tamper(*args):
        original(*args)
        path = resource_dir(root) / 'owner.json'
        record = json.loads(path.read_text())
        record['environment_id'] = 'env-other'
        path.write_text(json.dumps(record))

    monkeypatch.setattr(store, '_create_operation', tamper)
    with pytest.raises(OwnershipError):
        store.resume(RESOURCE, 'env-a', 'op-b')
    with pytest.raises(ResourceBusy):
        claim(store, 'env-new', 'op-new')


def test_aged_record_has_no_automatic_reclaim(tmp_path):
    root = tmp_path / 'store'
    store = ResourceStore(root)
    handle = claim(store)
    store.keep(handle)
    path = resource_dir(root) / 'owner.json'
    os.utime(path, (1, 1))
    with pytest.raises(ResourceBusy):
        claim(ResourceStore(root), 'env-b', 'op-b')
    assert store.resume(RESOURCE, 'env-a', 'op-c')['created'] is False


@pytest.mark.parametrize('root', [None, True, 1, b'/store', 'relative',
                                  '/', 'traversal'])
def test_invalid_roots(tmp_path, root):
    if root == b'/store':
        root = bytes(tmp_path / 'store')
    elif root == 'traversal':
        root = str(tmp_path / '..' / 'store')
    with pytest.raises(ValueError):
        ResourceStore(root)


@pytest.mark.parametrize('method', ['mark_mutated', 'keep',
                                    'abort_unmodified', 'release_restored'])
def test_missing_handle_directory_never_creates_state(tmp_path, method):
    root = tmp_path / 'store'
    store = ResourceStore(root)
    handle = dict(resource=RESOURCE, environment_id='env-a',
                  operation_id='op-a', created=True)
    with pytest.raises(OwnershipError):
        getattr(store, method)(handle)
    assert list(root.iterdir()) == []


def test_release_does_not_delete_new_claim(tmp_path, monkeypatch):
    root = tmp_path / 'store'
    store = ResourceStore(root)
    old = claim(store)
    original = os.rmdir
    successors = []

    def interleave(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if path == resource_dir(root).name:
            successors.append(claim(ResourceStore(root), 'env-b', 'op-b'))
        return result

    monkeypatch.setattr(os, 'rmdir', interleave)
    store.release_restored(old)
    with pytest.raises(ResourceBusy):
        claim(store, 'env-c', 'op-c')
    with pytest.raises(OwnershipError):
        store.release_restored(old)
    monkeypatch.setattr(os, 'rmdir', original)
    store.abort_unmodified(successors[0])


@pytest.mark.parametrize('method', ['mark_mutated', 'keep', 'resume'])
def test_failed_atomic_replace_keeps_owner_and_lock(tmp_path, monkeypatch, method):
    root = tmp_path / 'store'
    store = ResourceStore(root)
    handle = claim(store)
    if method == 'resume':
        store.keep(handle)
    owner = resource_dir(root) / 'owner.json'
    before = owner.read_bytes()

    def fail(*args, **kwargs):
        raise OSError('replace failure')

    monkeypatch.setattr(os, 'replace', fail)
    with pytest.raises(OwnershipError):
        if method == 'resume':
            store.resume(RESOURCE, 'env-a', 'op-b')
        else:
            getattr(store, method)(handle)
    assert owner.read_bytes() == before
    with pytest.raises(ResourceBusy):
        claim(ResourceStore(root), 'env-new', 'op-new')
    with pytest.raises((OwnershipError, ResourceBusy)):
        store.resume(RESOURCE, 'env-a', 'op-new')


@pytest.mark.parametrize('corruption', ['missing-field', 'extra-field',
                                        'duplicate-field', 'nan',
                                        'operation-missing', 'operation-empty',
                                        'operation-mismatch', 'owner-array',
                                        'retained-with-marker'])
def test_malformed_persistent_records_never_release(tmp_path, corruption):
    root = tmp_path / 'store'
    store = ResourceStore(root)
    handle = claim(store)
    owner = resource_dir(root) / 'owner.json'
    operation = resource_dir(root) / 'operation.json'
    record = json.loads(owner.read_text())
    if corruption == 'missing-field':
        del record['mutated']
    elif corruption == 'extra-field':
        record['timestamp'] = 0
    elif corruption == 'duplicate-field':
        owner.write_text(owner.read_text().replace(
            '"mutated": false', '"mutated": false, "mutated": true'))
    elif corruption == 'nan':
        owner.write_text(owner.read_text().replace('"mutated": false', '"mutated": NaN'))
    elif corruption == 'operation-missing':
        operation.unlink()
    elif corruption == 'operation-empty':
        operation.write_text('')
    elif corruption == 'operation-mismatch':
        operation.write_text(json.dumps(dict(record, operation_id='op-other')))
    elif corruption == 'owner-array':
        owner.write_text('[]')
    elif corruption == 'retained-with-marker':
        record.update(operation_id=None, abortable=False)
    if corruption in ('missing-field', 'extra-field', 'retained-with-marker'):
        owner.write_text(json.dumps(record))
    before = owner.read_bytes()
    with pytest.raises(OwnershipError):
        store.release_restored(handle)
    with pytest.raises(OwnershipError):
        store.resume(RESOURCE, 'env-a', 'op-b')
    assert owner.read_bytes() == before
    with pytest.raises(ResourceBusy):
        claim(store, 'env-new', 'op-new')


def test_root_replaced_with_symlink_after_construction(tmp_path):
    root = tmp_path / 'store'
    store = ResourceStore(root)
    handle = claim(store)
    moved = tmp_path / 'moved'
    root.rename(moved)
    external = tmp_path / 'external'
    external.mkdir()
    root.symlink_to(external, target_is_directory=True)
    for method in ('mark_mutated', 'keep', 'abort_unmodified', 'release_restored'):
        with pytest.raises(OwnershipError):
            getattr(store, method)(handle)
    with pytest.raises(OwnershipError):
        claim(store)
    with pytest.raises(OwnershipError):
        store.resume(RESOURCE, 'env-a', 'op-b')
    assert list(external.iterdir()) == []
    assert resource_dir(moved).exists()


def test_authorized_serializes_state_io_and_keep(tmp_path):
    store = ResourceStore(tmp_path / 'store')
    handle = claim(store)
    with store.authorized(handle) as state:
        assert state['changed'] is False
        assert state['record']['operation_id'] == handle['operation_id']
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(store.keep, handle)
            with pytest.raises(ResourceBusy):
                future.result(timeout=5)
        with pytest.raises(ResourceBusy):
            store.mark_mutated(handle)
    store.keep(handle)
    with pytest.raises(OwnershipError):
        with store.authorized(handle):
            pytest.fail('stale handle yielded')


def test_authorized_failure_after_change_retains_transition(tmp_path):
    root = tmp_path / 'store'
    store = ResourceStore(root)
    handle = claim(store)
    with pytest.raises(OwnershipError):
        with store.authorized(handle) as state:
            state['changed'] = True
            raise OwnershipError('state write failed')
    assert (resource_dir(root) / 'transition.json').exists()
    assert json.loads((resource_dir(root) / 'owner.json').read_text())['operation_id'] == 'op-a'
    with pytest.raises(ResourceBusy):
        store.keep(handle)


@pytest.mark.parametrize('mode', [0o777, 0o750, 0o707, 0o1777])
def test_precreated_unprotected_store_root_rejected(tmp_path, mode):
    root = tmp_path / 'store'
    root.mkdir(mode=mode)
    with pytest.raises(OwnershipError):
        ResourceStore(root)
    assert list(root.iterdir()) == []


@pytest.mark.parametrize('mode', [0o700, 0o500])
def test_precreated_protected_store_root_accepted(tmp_path, mode):
    root = tmp_path / 'store'
    root.mkdir(mode=mode)
    ResourceStore(root)
    assert root.stat().st_mode & 0o777 == mode


@pytest.mark.parametrize('mask', [0o022, 0o027, 0o077])
def test_store_root_and_resource_directory_creation_defeats_umask(tmp_path, mask):
    root = tmp_path / 'store'
    previous = os.umask(mask)
    try:
        store = ResourceStore(root)
        handle = claim(store)
    finally:
        os.umask(previous)
    assert root.stat().st_mode & 0o777 == 0o700
    assert resource_dir(root).stat().st_mode & 0o777 == 0o700
    store.mark_mutated(handle)


def test_precreated_foreign_owned_store_root_rejected(tmp_path):
    if os.geteuid() != 0:
        pytest.skip('foreign ownership requires root')
    import shutil
    root = tmp_path / 'store'
    root.mkdir(mode=0o700)
    shutil.chown(root, user='nobody')
    with pytest.raises(OwnershipError):
        ResourceStore(root)


def test_unprotected_resource_directory_rejected(tmp_path):
    root = tmp_path / 'store'
    store = ResourceStore(root)
    handle = claim(store)
    directory = resource_dir(root)
    owner = directory / 'owner.json'
    before = owner.read_bytes()
    for mode in (0o777, 0o730):
        os.chmod(directory, mode)
        with pytest.raises(OwnershipError):
            store.mark_mutated(handle)
        with pytest.raises(OwnershipError):
            store.resume(RESOURCE, 'env-a', 'op-b')
        assert owner.read_bytes() == before
    os.chmod(directory, 0o700)
    store.mark_mutated(handle)


def test_foreign_owned_resource_directory_rejected(tmp_path):
    if os.geteuid() != 0:
        pytest.skip('foreign ownership requires root')
    import shutil
    root = tmp_path / 'store'
    store = ResourceStore(root)
    handle = claim(store)
    directory = resource_dir(root)
    owner = directory / 'owner.json'
    before = owner.read_bytes()
    shutil.chown(directory, user='nobody')
    with pytest.raises(OwnershipError):
        store.mark_mutated(handle)
    assert owner.read_bytes() == before
    shutil.chown(directory, user='root')
    store.mark_mutated(handle)


@pytest.mark.parametrize('error', [ValueError('body failure'), KeyboardInterrupt(),
                                   RuntimeError('body failure')])
def test_transaction_marker_cleaned_on_unexpected_exception(tmp_path, error):
    root = tmp_path / 'store'
    store = ResourceStore(root)
    handle = claim(store)
    with pytest.raises(type(error)):
        with store.authorized(handle):
            raise error
    assert not (resource_dir(root) / 'transition.json').exists()
    store.mark_mutated(handle)
    store.keep(handle)
    assert store.resume(RESOURCE, 'env-a', 'op-b')['created'] is False


@pytest.mark.parametrize('error', [ValueError('uncertain'), KeyboardInterrupt()])
def test_transaction_marker_retained_after_change_on_unexpected_exception(tmp_path, error):
    root = tmp_path / 'store'
    store = ResourceStore(root)
    handle = claim(store)
    with pytest.raises(type(error)):
        with store.authorized(handle) as state:
            state['changed'] = True
            raise error
    assert (resource_dir(root) / 'transition.json').exists()
    with pytest.raises(ResourceBusy):
        store.mark_mutated(handle)
    with pytest.raises(ResourceBusy):
        store.resume(RESOURCE, 'env-a', 'op-b')
    with pytest.raises(ResourceBusy):
        claim(store, 'env-b', 'op-b')
