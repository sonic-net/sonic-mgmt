import argparse
import json
import logging
import os
import stat
import sys
from contextlib import contextmanager

if not __package__:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    __package__ = 'ranking'

from .environment_ownership import (
    ACTION_ROOT, OwnershipError, ResourceBusy, ResourceStore, _identity, _invalid_constant,
    _unique_object, _validate_component, _validate_handle,
)
from .snapshot_contract import _validate_path, validate_snapshot
from .state_store import StateStore


OWNERSHIP_ROOT = '/var/tmp/ranking-ownership'
STATE_ROOT = '/var/tmp/ranking-state'
_REQUEST_KEYS = {
    'claim': {'resource', 'environment_id', 'operation_id'},
    'resume': {'resource', 'environment_id', 'operation_id'},
    'keep': {'handle'}, 'abort': {'handle'}, 'release': {'handle'}, 'validate': {'handle'},
    'read': {'handle', 'name'}, 'write': {'handle', 'name', 'value'},
    'capture_files': {'handle', 'paths'}, 'restore_files': {'handle', 'originals'},
    'mark_attempt': {'handle', 'marker'}, 'complete_attempt': {'handle', 'marker'},
    'snapshot': {'handle', 'identity', 'services', 'paths', 'saiserver'},
    'begin_action': {'handle', 'action_id'}, 'end_action': {'handle'},
}


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def _request(value):
    if type(value) is not dict or type(value.get('action')) is not str:
        raise ValueError('Request must be an action object')
    action = value['action']
    if action not in _REQUEST_KEYS or set(value) != _REQUEST_KEYS[action] | {'action'}:
        raise ValueError('Unknown action or invalid request fields')
    if action in ('claim', 'resume'):
        _identity(value['resource'], value['environment_id'], value['operation_id'])
    else:
        _validate_handle(value['handle'])
    if action == 'begin_action':
        _validate_component(value['action_id'])
    if action in ('read', 'write'):
        StateStore._name(value['name'])
    if action in ('capture_files', 'snapshot'):
        paths = value['paths']
        if type(paths) is not list or any(type(path) is not str for path in paths):
            raise ValueError('Paths must be a list')
        if len(set(paths)) != len(paths):
            raise ValueError('Duplicate capture path')
        for path in paths:
            _validate_path(path)
            if any(path == root or path.startswith(root + '/')
                   for root in (OWNERSHIP_ROOT, STATE_ROOT, ACTION_ROOT)):
                raise ValueError('Source file cannot be an ownership or state record')
    if action == 'snapshot':
        if not value['handle']['resource'].startswith('dut:'):
            raise ValueError('snapshot action is DUT-only; PTF uses validated write')
        candidate = dict(schema_version=1, identity=value['identity'], services=value['services'],
                         files={path: {'state': 'absent'} for path in value['paths']},
                         saiserver=value['saiserver'])
        validate_snapshot(candidate, value['identity'])
        if (type(value['saiserver']) is not dict or set(value['saiserver']) != {
                'exists', 'running', 'container_name'}):
            raise ValueError('Snapshot requires explicit saiserver fields')
        if value['identity']['environment_id'] != value['handle']['environment_id']:
            raise ValueError('Snapshot environment mismatch')
    if action in ('mark_attempt', 'complete_attempt') and type(value['marker']) is not str:
        raise ValueError('Marker must be a string')
    return value


def _snapshot(state, request):
    handle = request['handle']
    with state._authorized(handle) as transaction:
        handle = transaction['handle']
        with state._open_environment(handle, create=True, transaction=transaction) as descriptor:
            if 'snapshot.json' in os.listdir(descriptor):
                original = state._read(descriptor, handle, 'snapshot.json')
                if (original['identity'] != request['identity'] or
                        original['services'] != request['services'] or
                        set(original['files']) != set(request['paths']) or
                        original['saiserver'] != request['saiserver']):
                    raise OwnershipError('Snapshot request does not match immutable original')
                return original
            files = state._capture_files(request['paths'])
            value = dict(schema_version=1, identity=request['identity'],
                         services=request['services'], files=files, saiserver=request['saiserver'])
            state._write(descriptor, handle, 'snapshot.json', value, transaction)
            return state._read(descriptor, handle, 'snapshot.json')


def _dispatch(request):
    action = request['action']
    if action == 'end_action':
        ResourceStore(ACTION_ROOT).abort_unmodified(request['handle'])
        return {}
    ownership = ResourceStore(OWNERSHIP_ROOT)
    if action in ('claim', 'resume'):
        return getattr(ownership, action)(request['resource'], request['environment_id'],
                                          request['operation_id'])
    handle = request['handle']
    if action == 'begin_action':
        actions = ResourceStore(ACTION_ROOT)
        with ownership.authorized(handle):
            guard = actions.claim(handle['resource'], handle['environment_id'], request['action_id'])
        try:
            with ownership.authorized(handle):
                pass
        except Exception:
            actions.abort_unmodified(guard)
            raise
        return guard
    if action == 'validate':
        with ownership.authorized(handle) as transaction:
            return dict(transaction['record'])
    if action in ('keep', 'abort', 'release'):
        methods = {'keep': 'keep', 'abort': 'abort_unmodified', 'release': 'release_restored'}
        method = methods[action]
        getattr(ownership, method)(handle)
        return {}
    state = StateStore(STATE_ROOT, ownership, handle['resource'])
    if action == 'snapshot':
        return _snapshot(state, request)
    args = {
        'read': ('name',), 'write': ('name', 'value'), 'capture_files': ('paths',),
        'restore_files': ('originals',), 'mark_attempt': ('marker',),
        'complete_attempt': ('marker',),
    }[action]
    result = getattr(state, action)(handle, *(request[key] for key in args))
    return {} if result is None else result


def _load_request(path):
    _validate_path(path)
    for root in (OWNERSHIP_ROOT, STATE_ROOT, ACTION_ROOT):
        if path == root or path.startswith(root + '/'):
            raise ValueError('Request must not be an ownership or state record')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = path[1:].split('/')
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                          dir_fd=descriptor)
        with os.fdopen(file_fd, 'r', encoding='utf-8') as stream:
            metadata = os.fstat(stream.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or
                    metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022):
                raise ValueError('Unsafe request file')
            return json.load(stream, object_pairs_hook=_unique_object,
                             parse_constant=_invalid_constant)
    finally:
        os.close(descriptor)


@contextmanager
def _protocol_logs():
    loggers = [logging.getLogger(ResourceStore.__module__),
               logging.getLogger(StateStore.__module__)]
    previous = [(logger.handlers, logger.propagate) for logger in loggers]
    try:
        for logger in loggers:
            logger.handlers = [logging.NullHandler()]
            logger.propagate = False
        yield
    finally:
        for logger, (handlers, propagate) in zip(loggers, previous):
            logger.handlers = handlers
            logger.propagate = propagate


def main(argv=None):
    try:
        parser = _Parser(add_help=False, allow_abbrev=False)
        parser.add_argument('--request', required=True)
        arguments = parser.parse_args(argv)
        request = _request(_load_request(arguments.request))
        with _protocol_logs():
            result = _dispatch(request)
        response = {'schema_version': 1, 'action': request['action'], 'result': result}
        sys.stdout.write(json.dumps(response, sort_keys=True, allow_nan=False) + '\n')
        return 0
    except (OwnershipError, ResourceBusy, OSError, ValueError, TypeError, UnicodeError,
            RecursionError) as error:
        message = ' '.join(str(error).splitlines())
        sys.stderr.write('ranking-agent: ' + message + '\n')
        return 1


if __name__ == '__main__':
    sys.exit(main())
