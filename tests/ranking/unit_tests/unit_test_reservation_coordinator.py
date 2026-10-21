import logging
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event
from unittest.mock import Mock, call

import pytest

from tests.ranking.environment_ownership import (
    OwnershipError, ResourceBusy, ResourceStore,
)
from tests.ranking.reservation_coordinator import (
    ReservationReleaseError, ReservationRollbackError, release_verified,
    reserve_all, resource_keys, resume_all,
)


DUT = 'dut:dut-a'
PTF = 'ptf:server-a:container-a'


@pytest.fixture(autouse=True)
def standard_logging(monkeypatch):
    # --noconftest omits SONiC's custom LogRecord fields.
    for handler in logging.getLogger().handlers:
        monkeypatch.setattr(handler, 'formatter', logging.Formatter('%(message)s'))


class Client:
    def __init__(self, fail_at=None, cleanup_failures=(), retained=()):
        self.calls = []
        self.fail_at = fail_at
        self.cleanup_failures = cleanup_failures
        self.retained = retained
        self.primary = ResourceBusy('primary claim failure')

    def claim(self, resource, environment_id, operation_id):
        self.calls.append(('claim', resource, environment_id, operation_id))
        if resource == self.fail_at:
            raise self.primary
        return dict(resource=resource, environment_id=environment_id,
                    operation_id=operation_id, created=resource not in self.retained)

    def abort_unmodified(self, handle):
        self.calls.append(('abort', handle['resource']))
        if handle['resource'] in self.cleanup_failures:
            raise OwnershipError('cleanup failed for ' + handle['resource'])


def test_sorted_claims_and_handles():
    client = Client()
    handles = reserve_all([PTF, DUT], 'env-a', 'op-a', client)
    assert [handle['resource'] for handle in handles] == [DUT, PTF]
    assert client.calls == [('claim', DUT, 'env-a', 'op-a'),
                            ('claim', PTF, 'env-a', 'op-a')]


def test_empty_resources_and_input_immutability():
    client = Client()
    assert reserve_all([], 'env-a', 'op-a', client) == []
    resources = [PTF, DUT]
    reserve_all(resources, 'env-a', 'op-a', client)
    assert resources == [PTF, DUT]


@pytest.mark.parametrize('resources', [[DUT, DUT], [DUT, '../bad'],
                                       'dut:dut-a', None])
def test_invalid_resources_rejected_before_claim(resources):
    client = Client()
    with pytest.raises(ValueError):
        reserve_all(resources, 'env-a', 'op-a', client)
    assert client.calls == []


@pytest.mark.parametrize('env,op', [('../bad', 'op-a'), ('env-a', '../bad'),
                                    (None, 'op-a'), ('env-a', True)])
def test_invalid_tokens_even_for_empty_request(env, op):
    client = Client()
    with pytest.raises(ValueError):
        reserve_all([], env, op, client)
    assert client.calls == []


def test_local_peer_is_not_released(tmp_path):
    store = ResourceStore(tmp_path / 'store')
    peer = store.claim(PTF, 'env-peer', 'op-peer')
    with pytest.raises(ResourceBusy):
        reserve_all([PTF, DUT], 'env-a', 'op-a', store)
    own = store.claim(DUT, 'env-new', 'op-new')
    store.abort_unmodified(own)
    with pytest.raises(ResourceBusy):
        store.claim(PTF, 'env-new', 'op-new')
    store.abort_unmodified(peer)


def test_reverse_rollback_and_primary_preserved():
    client = Client(fail_at=PTF)
    with pytest.raises(ResourceBusy) as error:
        reserve_all([PTF, 'dut:b', 'dut:a'], 'env-a', 'op-a', client)
    assert error.value is client.primary
    assert client.calls[-2:] == [('abort', 'dut:b'), ('abort', 'dut:a')]


def test_cleanup_errors_preserve_cause_and_continue():
    client = Client(fail_at=PTF, cleanup_failures=('dut:a', 'dut:b'))
    with pytest.raises(ReservationRollbackError) as error:
        reserve_all([PTF, 'dut:b', 'dut:a'], 'env-a', 'op-a', client)
    failure = error.value
    assert failure.primary is client.primary
    assert failure.__cause__ is client.primary
    assert [handle['resource'] for handle, _ in failure.cleanup_errors] == [
        'dut:b', 'dut:a',
    ]
    assert all(isinstance(exc, OwnershipError)
               for _, exc in failure.cleanup_errors)
    assert 'primary claim failure' in str(failure)
    assert 'cleanup failed' in str(failure)
    assert client.calls[-2:] == [('abort', 'dut:b'), ('abort', 'dut:a')]


def test_retained_handles_are_never_aborted():
    client = Client(fail_at=PTF, retained=(DUT,))
    with pytest.raises(ResourceBusy):
        reserve_all([PTF, DUT], 'env-a', 'op-a', client)
    assert not any(call[0] == 'abort' for call in client.calls)


@pytest.mark.parametrize('field,value', [
    ('resource', 'dut:other'), ('environment_id', 'env-other'),
    ('operation_id', 'op-other'), ('created', 1),
])
def test_mismatching_returned_handle_not_released(field, value):
    class WrongClient(Client):
        def claim(self, resource, environment_id, operation_id):
            return dict(super().claim(resource, environment_id, operation_id),
                        **{field: value})

    client = WrongClient()
    with pytest.raises(OwnershipError):
        reserve_all([DUT], 'env-a', 'op-a', client)
    assert not any(call[0] == 'abort' for call in client.calls)


def test_aliases_use_actual_host_identity(tmp_path):
    first = ResourceStore(tmp_path / 'store')
    second = ResourceStore(tmp_path / 'store')
    left = resource_keys('a' * 32 + '\n', 'b' * 32, 'c' * 64)
    right = resource_keys('a' * 32, 'b' * 32 + '\n', 'c' * 64)
    assert left == right
    first.claim(left[0], 'env-a', 'controller-a')
    with pytest.raises(ResourceBusy):
        second.claim(right[0], 'env-b', 'controller-b')


def test_resume_partial_failure_only_keeps_operation(tmp_path):
    store = ResourceStore(tmp_path / 'store')
    dut, ptf = resource_keys('a' * 32, 'b' * 32, 'c' * 64)
    for resource in (dut, ptf):
        store.keep(store.claim(resource, 'env-a', 'initial'))
    client = Mock(wraps=store)

    def resume(resource, environment_id, operation_id):
        if resource == ptf:
            raise ResourceBusy('busy')
        return store.resume(resource, environment_id, operation_id)

    client.resume.side_effect = resume
    with pytest.raises(ResourceBusy):
        resume_all([ptf, dut], 'env-a', 'resume-a', client)
    client.keep.assert_called_once()
    assert client.keep.call_args.args[0]['resource'] == dut
    client.abort_unmodified.assert_not_called()
    client.release_restored.assert_not_called()
    assert store.resume(dut, 'env-a', 'retry')['created'] is False


@pytest.mark.parametrize('dut_end', ['', '\n', '\r\n'])
@pytest.mark.parametrize('ptf_end', ['', '\n', '\r\n'])
def test_resource_keys_canonicalize_hex_and_machine_line_endings(dut_end, ptf_end):
    dut_id = '0123456789AbCdEf' * 2
    ptf_id = 'fedcba9876543210' * 2
    container_id = '0123456789ABCDEF' * 4
    assert resource_keys(dut_id + dut_end, ptf_id + ptf_end, container_id) == (
        'dut:' + dut_id.lower(),
        'ptf:{}:{}'.format(ptf_id, container_id.lower()),
    )


@pytest.mark.parametrize('index,length', [(0, 32), (1, 32), (2, 64)])
@pytest.mark.parametrize('offset', [-64, -1, 1])
def test_resource_keys_reject_wrong_lengths(index, length, offset):
    identities = ['a' * 32, 'b' * 32, 'c' * 64]
    identities[index] = 'a' * max(0, length + offset)
    with pytest.raises(ValueError):
        resource_keys(*identities)


@pytest.mark.parametrize('index', [0, 1, 2])
@pytest.mark.parametrize('value', [
    None, True, False, 123, 0.0, b'a' * 32, [], {},
    '192.0.2.1', '2001:db8::1', 'dut-alias', 'ptf-host-alias',
])
def test_resource_keys_reject_types_ips_and_aliases(index, value):
    identities = ['a' * 32, 'b' * 32, 'c' * 64]
    identities[index] = value
    with pytest.raises(ValueError):
        resource_keys(*identities)


@pytest.mark.parametrize('index,length', [(0, 32), (1, 32), (2, 64)])
@pytest.mark.parametrize('prefix,suffix', [
    ('0x', ''), ('sha256:', ''), ('../', ''), ('', '/'), ('', ':a'),
    (' ', ''), ('', ' '), ('\t', ''), ('', '\t'), ('\n', ''),
    ('', '\r'), ('', '\n\n'), ('', '\r\n\r\n'), ('', '\x00'),
    ('', '\v'), ('', '\f'), ('', '\u2028'), ('', '\u00a0'),
])
def test_resource_keys_do_not_strip_unrelated_whitespace(index, length, prefix, suffix):
    identities = ['a' * 32, 'b' * 32, 'c' * 64]
    identities[index] = prefix + 'a' * length + suffix
    with pytest.raises(ValueError):
        resource_keys(*identities)


@pytest.mark.parametrize('index,length', [(0, 32), (1, 32), (2, 64)])
@pytest.mark.parametrize('character', ['g', '/', ':', '\x00', '\n', '\r', '\t', 'ａ'])
def test_resource_keys_reject_nonhex_inside_identity(index, length, character):
    identities = ['a' * 32, 'b' * 32, 'c' * 64]
    identities[index] = 'a' * (length - 1) + character
    with pytest.raises(ValueError):
        resource_keys(*identities)


@pytest.mark.parametrize('suffix', ['\n', '\r\n'])
def test_resource_keys_container_must_not_have_line_ending(suffix):
    with pytest.raises(ValueError):
        resource_keys('a' * 32, 'b' * 32, 'c' * 64 + suffix)


def test_resource_keys_use_full_container_and_both_host_identities():
    base = resource_keys('a' * 32, 'b' * 32, 'c' * 64)
    other_dut = resource_keys('d' * 32, 'b' * 32, 'c' * 64)
    other_host = resource_keys('a' * 32, 'd' * 32, 'c' * 64)
    other_container = resource_keys('a' * 32, 'b' * 32, 'c' * 63 + 'd')
    assert base == ('dut:' + 'a' * 32, 'ptf:' + 'b' * 32 + ':' + 'c' * 64)
    assert base[0] != other_dut[0]
    assert base[1] == other_dut[1]
    assert base[0] == other_host[0] == other_container[0]
    assert base[1] != other_host[1]
    assert base[1] != other_container[1]


def test_resource_keys_do_not_access_files_or_network(monkeypatch):
    forbidden = Mock(side_effect=AssertionError('Identity conversion must be pure'))
    for target in ('builtins.open', 'os.open', 'pathlib.Path.read_text',
                   'pathlib.Path.read_bytes', 'socket.socket', 'socket.create_connection'):
        monkeypatch.setattr(target, forbidden)
    assert resource_keys('a' * 32, 'b' * 32, 'c' * 64)[0] == 'dut:' + 'a' * 32
    forbidden.assert_not_called()


@pytest.mark.parametrize('index', [0, 1])
def test_aliases_share_actual_dut_and_ptf_reservations(tmp_path, index):
    first = ResourceStore(tmp_path / 'store')
    second = ResourceStore(tmp_path / 'store')
    left = resource_keys('A' * 32 + '\r\n', 'B' * 32 + '\n', 'C' * 64)
    right = resource_keys('a' * 32, 'b' * 32, 'c' * 64)
    first.claim(left[index], 'env-a', 'controller-a')
    with pytest.raises(ResourceBusy):
        second.claim(right[index], 'env-b', 'controller-b')


@pytest.fixture
def resuming_client():
    client = Mock()

    def resume(resource, environment_id, operation_id):
        return dict(resource=resource, environment_id=environment_id,
                    operation_id=operation_id, created=False)

    client.resume.side_effect = resume
    return client


@pytest.mark.parametrize('resources', [[PTF, DUT], (PTF, DUT)])
def test_sorted_resumes_and_exact_return_order(resources, resuming_client):
    original = resources[:]
    handles = resume_all(resources, 'env-a', 'op-a', resuming_client)
    assert handles == [
        dict(resource=resource, environment_id='env-a', operation_id='op-a', created=False)
        for resource in (DUT, PTF)
    ]
    assert resources == original
    assert resuming_client.mock_calls == [
        call.resume(DUT, 'env-a', 'op-a'), call.resume(PTF, 'env-a', 'op-a'),
    ]


@pytest.mark.parametrize('resources', [[], ()])
def test_empty_resume_has_no_client_calls(resources, resuming_client):
    assert resume_all(resources, 'env-a', 'op-a', resuming_client) == []
    assert resuming_client.mock_calls == []


@pytest.mark.parametrize('resources', [
    [DUT, DUT], (PTF, PTF), [DUT, '../bad'], [DUT, None], [DUT, True], [DUT, 1],
    [DUT, 'dut:a:b'], [DUT, 'ptf:host'], [DUT, 'ptf:host:container:extra'],
    [DUT, 'DUT:a'], [DUT, 'dut:a\n'], [DUT, 'dut:a '], [DUT, 'dut:../a'],
    [DUT, 'dut:a\x00'], [DUT, 'dut:'], [DUT, 'ptf:host:'],
    DUT, None, True, 1, {DUT}, {'resource': DUT}, iter([DUT]),
])
def test_invalid_resume_resources_rejected_before_io(resources, resuming_client):
    with pytest.raises(ValueError):
        resume_all(resources, 'env-a', 'op-a', resuming_client)
    assert resuming_client.mock_calls == []


@pytest.mark.parametrize('resources', [[], [DUT]])
@pytest.mark.parametrize('index', [0, 1])
@pytest.mark.parametrize('value', [None, True, 1, '', '../bad', 'a:b', 'a\n', ' a', 'a\x00'])
def test_invalid_resume_ids_rejected_even_for_empty_request(
        resources, index, value, resuming_client):
    identities = ['env-a', 'op-a']
    identities[index] = value
    with pytest.raises(ValueError):
        resume_all(resources, *identities, resuming_client)
    assert resuming_client.mock_calls == []


@pytest.mark.parametrize('field,value', [
    ('resource', 'dut:other'), ('environment_id', 'env-other'),
    ('operation_id', 'op-other'), ('created', True), ('created', 1),
    ('created', 0), ('created', None), ('resource', None),
    ('environment_id', True), ('operation_id', ''),
])
def test_invalid_resumed_handle_keeps_only_prior_valid_handle(field, value, resuming_client):
    valid = dict(resource=DUT, environment_id='env-a', operation_id='op-a', created=False)
    invalid = dict(valid, resource=PTF)
    invalid[field] = value
    resuming_client.resume.side_effect = [valid, invalid]
    with pytest.raises(OwnershipError):
        resume_all([PTF, DUT], 'env-a', 'op-a', resuming_client)
    assert resuming_client.mock_calls == [
        call.resume(DUT, 'env-a', 'op-a'), call.resume(PTF, 'env-a', 'op-a'),
        call.keep(valid),
    ]


@pytest.mark.parametrize('handle', [
    None, True, 1, [], (), {},
    dict(resource=DUT, environment_id='env-a', operation_id='op-a'),
    dict(environment_id='env-a', operation_id='op-a', created=False),
    dict(resource=DUT, operation_id='op-a', created=False),
    dict(resource=DUT, environment_id='env-a', created=False),
    dict(resource=DUT, environment_id='env-a', operation_id='op-a', created=False, extra=1),
    dict(resource=PTF, environment_id='env-a', operation_id='op-a', created=False),
    dict(resource=DUT, environment_id='env-other', operation_id='op-a', created=False),
    dict(resource=DUT, environment_id='env-a', operation_id='op-other', created=False),
    dict(resource=DUT, environment_id='env-a', operation_id='op-a', created=True),
])
def test_first_resume_invalid_handle_is_never_cleaned(handle, resuming_client):
    resuming_client.resume.side_effect = None
    resuming_client.resume.return_value = handle
    with pytest.raises(OwnershipError):
        resume_all([PTF, DUT], 'env-a', 'op-a', resuming_client)
    assert resuming_client.mock_calls == [call.resume(DUT, 'env-a', 'op-a')]


def test_first_resume_failure_preserves_primary_without_cleanup(resuming_client):
    primary = ResourceBusy('first resource busy')
    resuming_client.resume.side_effect = primary
    with pytest.raises(ResourceBusy) as error:
        resume_all([PTF, DUT], 'env-a', 'op-a', resuming_client)
    assert error.value is primary
    assert resuming_client.mock_calls == [call.resume(DUT, 'env-a', 'op-a')]


def test_reverse_keep_order_and_primary_preserved(resuming_client):
    handles = [dict(resource=resource, environment_id='env-a',
                    operation_id='op-a', created=False)
               for resource in ('dut:a', 'dut:b', 'dut:c')]
    primary = ResourceBusy('last resource busy')
    resuming_client.resume.side_effect = handles + [primary]
    with pytest.raises(ResourceBusy) as error:
        resume_all([PTF, 'dut:c', 'dut:a', 'dut:b'], 'env-a', 'op-a', resuming_client)
    assert error.value is primary
    assert resuming_client.mock_calls == [
        call.resume(resource, 'env-a', 'op-a')
        for resource in ('dut:a', 'dut:b', 'dut:c', PTF)
    ] + [call.keep(handle) for handle in reversed(handles)]


def test_resume_cleanup_failures_collect_all_and_preserve_cause(resuming_client, caplog):
    handles = [dict(resource=resource, environment_id='env-a',
                    operation_id='op-a', created=False)
               for resource in ('dut:a', 'dut:b')]
    primary = ResourceBusy('primary resume failure')
    failures = [OwnershipError('keep b failed'), OwnershipError('keep a failed')]
    resuming_client.resume.side_effect = handles + [primary]
    resuming_client.keep.side_effect = failures
    with pytest.raises(ReservationRollbackError) as error:
        resume_all([PTF, 'dut:b', 'dut:a'], 'env-a', 'op-a', resuming_client)
    failure = error.value
    assert failure.primary is primary
    assert failure.__cause__ is primary
    assert failure.cleanup_errors == tuple(zip(reversed(handles), failures))
    assert all(handle is not original
               for (handle, _), original in zip(failure.cleanup_errors, reversed(handles)))
    assert str(failure).startswith('Resume failed: ')
    assert str(failure).count(str(primary)) == 1
    assert all(str(exc) in str(failure) for exc in failures)
    assert resuming_client.mock_calls == [
        call.resume('dut:a', 'env-a', 'op-a'), call.resume('dut:b', 'env-a', 'op-a'),
        call.resume(PTF, 'env-a', 'op-a'), call.keep(handles[1]), call.keep(handles[0]),
    ]
    assert sum(record.levelno == logging.ERROR for record in caplog.records) == 2


def test_claim_rollback_error_message_is_unchanged():
    primary = ResourceBusy('busy')
    handle = dict(resource=DUT, environment_id='env-a', operation_id='op-a', created=True)
    failure = ReservationRollbackError(primary, [(handle, OwnershipError('cleanup'))])
    assert str(failure) == 'Claim failed: busy; rollback failures: dut:dut-a: cleanup'


def test_successful_resume_retains_all_active_ownership_without_device_changes(tmp_path):
    store = ResourceStore(tmp_path / 'store')
    peer = ResourceStore(tmp_path / 'store')
    dut, ptf = resource_keys('a' * 32, 'b' * 32, 'c' * 64)
    for resource in (dut, ptf):
        store.keep(store.claim(resource, 'env-a', 'initial'))
    client = Mock(wraps=store)
    handles = resume_all([ptf, dut], 'env-a', 'resume-a', client)
    assert handles == [dict(resource=resource, environment_id='env-a',
                            operation_id='resume-a', created=False)
                       for resource in (dut, ptf)]
    assert client.mock_calls == [
        call.resume(dut, 'env-a', 'resume-a'), call.resume(ptf, 'env-a', 'resume-a'),
    ]
    for handle in handles:
        with pytest.raises(ResourceBusy):
            peer.resume(handle['resource'], 'env-a', 'other-operation')
        with pytest.raises(ResourceBusy):
            peer.claim(handle['resource'], 'env-b', 'other-operation')
    for handle in handles:
        store.keep(handle)
        assert store.resume(handle['resource'], 'env-a', 'retry')['created'] is False


@pytest.mark.parametrize('corruption', ['resource', 'environment_id', 'operation_id',
                                        'created', 'missing', 'extra', 'not-dict'])
def test_unknown_resumed_handle_retains_real_operation(tmp_path, corruption):
    store = ResourceStore(tmp_path / 'store')
    peer = ResourceStore(tmp_path / 'store')
    dut, ptf = resource_keys('a' * 32, 'b' * 32, 'c' * 64)
    for resource in (dut, ptf):
        store.keep(store.claim(resource, 'env-a', 'initial'))
    client = Mock(wraps=store)

    def resume(resource, environment_id, operation_id):
        handle = store.resume(resource, environment_id, operation_id)
        if resource == ptf:
            if corruption == 'not-dict':
                return None
            if corruption == 'missing':
                del handle['operation_id']
            elif corruption == 'extra':
                handle['extra'] = True
            else:
                handle[corruption] = {
                    'resource': 'dut:other', 'environment_id': 'env-other',
                    'operation_id': 'op-other', 'created': True,
                }[corruption]
        return handle

    client.resume.side_effect = resume
    with pytest.raises(OwnershipError):
        resume_all([ptf, dut], 'env-a', 'resume-a', client)
    valid = dict(resource=dut, environment_id='env-a', operation_id='resume-a', created=False)
    assert client.mock_calls == [
        call.resume(dut, 'env-a', 'resume-a'), call.resume(ptf, 'env-a', 'resume-a'),
        call.keep(valid),
    ]
    assert peer.resume(dut, 'env-a', 'retry')['created'] is False
    with pytest.raises(ResourceBusy):
        peer.resume(ptf, 'env-a', 'steal')
    with pytest.raises(ResourceBusy):
        peer.claim(ptf, 'env-other', 'steal')


def test_resume_keep_failure_retains_failed_operation_and_continues(tmp_path):
    store = ResourceStore(tmp_path / 'store')
    peer = ResourceStore(tmp_path / 'store')
    dut, ptf = resource_keys('a' * 32, 'b' * 32, 'c' * 64)
    other_dut = resource_keys('d' * 32, 'b' * 32, 'c' * 64)[0]
    for resource in (dut, other_dut, ptf):
        store.keep(store.claim(resource, 'env-a', 'initial'))
    peer.resume(ptf, 'env-a', 'peer-active')
    client = Mock(wraps=store)
    cleanup_error = OwnershipError('injected keep failure')

    def keep(handle):
        if handle['resource'] == other_dut:
            raise cleanup_error
        store.keep(handle)

    client.keep.side_effect = keep
    with pytest.raises(ReservationRollbackError) as error:
        resume_all([ptf, other_dut, dut], 'env-a', 'resume-a', client)
    failed_handle = dict(resource=other_dut, environment_id='env-a',
                         operation_id='resume-a', created=False)
    valid_handle = dict(failed_handle, resource=dut)
    failure = error.value
    assert isinstance(failure.primary, ResourceBusy)
    assert failure.__cause__ is failure.primary
    assert failure.cleanup_errors == ((failed_handle, cleanup_error),)
    assert client.mock_calls == [
        call.resume(dut, 'env-a', 'resume-a'), call.resume(other_dut, 'env-a', 'resume-a'),
        call.resume(ptf, 'env-a', 'resume-a'), call.keep(failed_handle), call.keep(valid_handle),
    ]
    assert peer.resume(dut, 'env-a', 'retry')['created'] is False
    for resource in (other_dut, ptf):
        with pytest.raises(ResourceBusy):
            peer.resume(resource, 'env-a', 'steal')
        with pytest.raises(ResourceBusy):
            peer.claim(resource, 'env-other', 'steal')


def test_second_resource_busy_race_keeps_only_request_operation(tmp_path):
    store = ResourceStore(tmp_path / 'store')
    peer = ResourceStore(tmp_path / 'store')
    dut, ptf = resource_keys('a' * 32, 'b' * 32, 'c' * 64)
    for resource in (dut, ptf):
        store.keep(store.claim(resource, 'env-a', 'initial'))
    client = Mock(wraps=store)
    winner = []

    def resume(resource, environment_id, operation_id):
        if resource == ptf:
            winner.append(peer.resume(ptf, 'env-a', 'request-b'))
        return store.resume(resource, environment_id, operation_id)

    client.resume.side_effect = resume
    with pytest.raises(ResourceBusy):
        resume_all([ptf, dut], 'env-a', 'request-a', client)
    assert winner == [dict(resource=ptf, environment_id='env-a',
                           operation_id='request-b', created=False)]
    client.keep.assert_called_once_with(dict(resource=dut, environment_id='env-a',
                                             operation_id='request-a', created=False))
    client.abort_unmodified.assert_not_called()
    client.release_restored.assert_not_called()
    client.mark_mutated.assert_not_called()
    assert peer.resume(dut, 'env-a', 'retry')['created'] is False
    with pytest.raises(ResourceBusy):
        store.resume(ptf, 'env-a', 'request-c')
    assert store.resume(ptf, 'env-a', 'request-b') == dict(
        resource=ptf, environment_id='env-a', operation_id='request-b',
        created=False)


def test_same_environment_concurrent_resume_only_one_request_gets_all(tmp_path):
    root = tmp_path / 'store'
    store = ResourceStore(root)
    dut, ptf = resource_keys('a' * 32, 'b' * 32, 'c' * 64)
    for resource in (dut, ptf):
        store.keep(store.claim(resource, 'env-a', 'initial'))
    start = Barrier(2)
    loser_done = Event()
    wait_limit = 5
    stores = {operation: ResourceStore(root) for operation in ('request-a', 'request-b')}
    clients = {operation: Mock(wraps=request_store) for operation, request_store in stores.items()}

    def request(operation_id):
        client = clients[operation_id]
        request_store = stores[operation_id]

        def resume(resource, environment_id, operation_id):
            if resource == dut:
                start.wait(timeout=wait_limit)
                try:
                    handle = request_store.resume(resource, environment_id, operation_id)
                except ResourceBusy:
                    loser_done.set()
                    raise
                assert loser_done.wait(timeout=wait_limit), 'Contender did not finish'
                return handle
            return request_store.resume(resource, environment_id, operation_id)

        client.resume.side_effect = resume
        return resume_all([ptf, dut], 'env-a', operation_id, client)

    successes, failures = [], []
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {operation: executor.submit(request, operation) for operation in clients}
        for operation, future in futures.items():
            try:
                successes.append((operation, future.result(timeout=wait_limit)))
            except ResourceBusy as error:
                failures.append((operation, error))
    assert len(successes) == len(failures) == 1
    winner, handles = successes[0]
    loser, _ = failures[0]
    assert handles == [dict(resource=resource, environment_id='env-a',
                            operation_id=winner, created=False)
                       for resource in (dut, ptf)]
    assert clients[winner].mock_calls == [
        call.resume(dut, 'env-a', winner), call.resume(ptf, 'env-a', winner),
    ]
    assert clients[loser].mock_calls == [call.resume(dut, 'env-a', loser)]
    for resource in (dut, ptf):
        with pytest.raises(ResourceBusy):
            store.resume(resource, 'env-a', loser)
        with pytest.raises(ResourceBusy):
            store.claim(resource, 'env-other', loser)
    for handle in handles:
        store.keep(handle)
        assert store.resume(handle['resource'], 'env-a', 'retry')['created'] is False


def test_restore_failure_releases_neither_resource(tmp_path):
    store = ResourceStore(tmp_path / 'store')
    resources = ('dut:dut-a', 'ptf:server-a:ptf-a')
    handles = [store.claim(r, 'env-a', 'op-a') for r in resources]
    client = Mock(wraps=store)
    with pytest.raises(OwnershipError):
        release_verified(handles, client,
                         lambda _: {resources[0]: False, resources[1]: True}, Mock())
    client.release_restored.assert_not_called()
    for resource in resources:
        with pytest.raises(ResourceBusy):
            store.claim(resource, 'other', 'other-op')


def test_partial_release_preserves_receipts():
    resources = ('dut:dut-a', 'ptf:server-a:ptf-a')
    handles = [dict(resource=r, environment_id='env-a',
                    operation_id='op-a', created=False) for r in resources]
    client, journal = Mock(), []
    client.release_restored.side_effect = [None, OSError('response lost')]
    with pytest.raises(ReservationReleaseError) as failure:
        release_verified(handles, client,
                         lambda _: dict.fromkeys(resources, True), journal.append)
    assert failure.value.released == (resources[0],)
    assert failure.value.remaining == (resources[1],)
    assert failure.value.uncertain is True
    assert [e['event'] for e in journal] == [
        'verified', 'release_pending', 'released', 'release_pending']
    client.claim.assert_not_called()


@pytest.mark.parametrize('verdicts', [
    {DUT: True},
    {DUT: True, PTF: False},
    {DUT: True, PTF: 1},
    {DUT: True, PTF: 'yes'},
    {DUT: True, PTF: None},
    {DUT: 1, PTF: True},
    {DUT: 'true', PTF: True},
    {},
    None,
])
def test_release_requires_exact_true_verdicts_on_every_resource(verdicts):
    handles = [dict(resource=resource, environment_id='env-a',
                    operation_id='op-a', created=False)
               for resource in (DUT, PTF)]
    client, persist = Mock(), Mock()
    with pytest.raises(OwnershipError):
        release_verified(handles, client, lambda _: verdicts, persist)
    client.release_restored.assert_not_called()
    persist.assert_not_called()


def test_release_journal_failure_stops_before_any_release():
    handles = [dict(resource=DUT, environment_id='env-a',
                    operation_id='op-a', created=False)]
    client, persist = Mock(), Mock(side_effect=OSError('journal unavailable'))
    with pytest.raises(OSError):
        release_verified(handles, client, lambda _: {DUT: True}, persist)
    client.release_restored.assert_not_called()


def test_release_journal_failure_after_a_release_stops_the_rest():
    handles = [dict(resource=resource, environment_id='env-a',
                    operation_id='op-a', created=False)
               for resource in (DUT, PTF)]
    client = Mock()
    journal = []

    def persist(entry):
        if entry['event'] == 'released':
            raise OSError('journal lost after release')
        journal.append(entry)

    with pytest.raises(OSError):
        release_verified(handles, client, lambda _: {DUT: True, PTF: True}, persist)
    assert [entry['event'] for entry in journal] == ['verified', 'release_pending']
    released_handles = [invocation.args[0]
                        for invocation in client.release_restored.call_args_list]
    assert [handled['resource'] for handled in released_handles] == [DUT]
    client.claim.assert_not_called()


@pytest.mark.parametrize('handles', [
    [dict(resource=DUT, environment_id='env-a', operation_id='op-a', created=False)] * 2,
    [dict(resource=DUT, environment_id='env-a', operation_id='op-a', created=False),
     dict(resource=PTF, environment_id='env-other', operation_id='op-a', created=False)],
    [dict(resource=DUT, environment_id='env-a', operation_id='op-other', created=False),
     dict(resource=PTF, environment_id='env-a', operation_id='op-a', created=False)],
    'dut:dut-a', None, {'resource': DUT},
])
def test_release_rejects_invalid_handle_lists(handles):
    client, persist = Mock(), Mock()
    with pytest.raises(ValueError):
        release_verified(handles, client, lambda _: {}, persist)
    client.release_restored.assert_not_called()
    persist.assert_not_called()


def test_full_release_returns_resources_in_canonical_order(tmp_path):
    store = ResourceStore(tmp_path / 'store')
    handles = [store.claim(resource, 'env-a', 'op-a') for resource in (PTF, DUT)]
    client, journal = Mock(wraps=store), []
    released = release_verified(handles, client,
                                lambda _: {DUT: True, PTF: True}, journal.append)
    assert released == (DUT, PTF)
    assert [entry['event'] for entry in journal] == [
        'verified', 'release_pending', 'released', 'release_pending', 'released']
    for resource in (DUT, PTF):
        assert store.claim(resource, 'env-b', 'op-b')['resource'] == resource


def test_release_failure_retains_both_ends_locally(tmp_path):
    store = ResourceStore(tmp_path / 'store')
    handles = [store.claim(resource, 'env-a', 'op-a') for resource in (DUT, PTF)]
    client = Mock(wraps=store)
    client.release_restored.side_effect = [None, OwnershipError('agent rejected release')]

    def verify(_):
        return {DUT: True, PTF: True}

    with pytest.raises(ReservationReleaseError) as failure:
        release_verified(handles, client, verify, Mock())
    assert failure.value.released == (DUT,)
    assert failure.value.remaining == (PTF,)
    assert failure.value.uncertain is True
    with pytest.raises(ResourceBusy):
        store.claim(PTF, 'env-other', 'op-other')


def test_resume_failure_warning_names_the_failing_resource(caplog):
    client = Mock()
    primary = ResourceBusy('first resource busy')
    client.resume.side_effect = primary
    with pytest.raises(ResourceBusy) as error:
        resume_all([DUT, PTF], 'env-a', 'op-a', client)
    assert error.value is primary
    warnings = [record for record in caplog.records
                if record.levelno == logging.WARNING and
                'unvalidated ownership retained' in record.getMessage()]
    assert len(warnings) == 1
    assert DUT in warnings[0].getMessage()
