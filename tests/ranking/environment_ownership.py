import hashlib
import json
import logging
import os
import re
import stat
import uuid
from contextlib import contextmanager


LOGGER = logging.getLogger(__name__)
ACTION_ROOT = '/var/tmp/ranking-actions'
_COMPONENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*')
_OWNER = 'owner.json'
_OPERATION = 'operation.json'
_TRANSITION = 'transition.json'
_RECORD_KEYS = {'schema_version', 'resource', 'environment_id',
                'operation_id', 'mutated', 'abortable'}
_HANDLE_KEYS = {'resource', 'environment_id', 'operation_id', 'created'}
_IDENTITY_KEYS = {'resource', 'environment_id', 'operation_id'}


class ResourceBusy(RuntimeError):
    pass


class OwnershipError(RuntimeError):
    pass


def _validate_component(value):
    if not isinstance(value, str) or _COMPONENT.fullmatch(value) is None:
        raise ValueError('Invalid identity component: {!r}'.format(value))
    return value


def _validate_resource(resource):
    if not isinstance(resource, str):
        raise ValueError('Resource must be a canonical string')
    parts = resource.split(':')
    if not ((len(parts) == 2 and parts[0] == 'dut') or
            (len(parts) == 3 and parts[0] == 'ptf')):
        raise ValueError('Invalid resource key: {!r}'.format(resource))
    for part in parts[1:]:
        _validate_component(part)
    return resource


def _identity(resource, environment_id, operation_id):
    return {'resource': _validate_resource(resource),
            'environment_id': _validate_component(environment_id),
            'operation_id': _validate_component(operation_id)}


def _validate_handle(handle):
    try:
        if not isinstance(handle, dict) or set(handle) != _HANDLE_KEYS:
            raise ValueError('Invalid handle fields')
        if type(handle['created']) is not bool:
            raise ValueError('created must be boolean')
        _identity(handle['resource'], handle['environment_id'],
                  handle['operation_id'])
    except ValueError as error:
        raise OwnershipError('Invalid ownership handle') from error
    return dict(handle)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate record field')
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError('Non-finite record value: ' + value)


class ResourceStore:
    """Local reservations with explicit recovery, without leases or force release."""

    def __init__(self, root):
        try:
            root = os.fspath(root)
        except TypeError as error:
            raise ValueError('Store root must be an absolute directory path') from error
        if (not isinstance(root, str) or not os.path.isabs(root) or root == '/' or
                os.path.normpath(root) != root):
            raise ValueError('Store root must be an absolute canonical directory')
        self.root = root
        with self._io_errors(), self._root_fd(create=True):
            pass

    @contextmanager
    def _io_errors(self):
        try:
            yield
        except OSError as error:
            LOGGER.error('Storage failure; reservation retained: %s', error)
            raise OwnershipError(
                'Storage failure; unknown reservation retained') from error

    @contextmanager
    def _root_fd(self, create=False):
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open('/', flags)
        try:
            parts = self.root.strip('/').split('/')
            for index, part in enumerate(parts):
                created = False
                if create and index == len(parts) - 1:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                    else:
                        created = True
                        os.chmod(part, 0o700, dir_fd=descriptor)
                child = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                if index == len(parts) - 1:
                    if created:
                        os.fchmod(descriptor, 0o700)
                    self._protected(descriptor)
            yield descriptor
        finally:
            os.close(descriptor)

    @staticmethod
    def _protected(descriptor):
        metadata = os.fstat(descriptor)
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or
                metadata.st_mode & 0o077):
            raise OwnershipError('Unprotected reservation directory')

    @staticmethod
    def _resource_name(resource):
        return hashlib.sha256(resource.encode('utf-8')).hexdigest()

    @contextmanager
    def _directory(self, root_fd, resource):
        descriptor = os.open(self._resource_name(resource),
                             os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=root_fd)
        try:
            self._protected(descriptor)
            yield descriptor
        finally:
            os.close(descriptor)

    @staticmethod
    def _check_layout(descriptor, extra=()):
        allowed = {_OWNER, _OPERATION, _TRANSITION}.union(extra)
        for name in os.listdir(descriptor):
            if name not in allowed:
                raise OwnershipError('Unknown reservation entry: ' + name)
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OwnershipError('Unsafe reservation entry: ' + name)

    @staticmethod
    def _read_json(descriptor, name):
        try:
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                              dir_fd=descriptor)
        except FileNotFoundError as error:
            raise OwnershipError('Missing reservation record: ' + name) from error
        with os.fdopen(file_fd, 'r', encoding='utf-8') as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OwnershipError('Unsafe reservation record: ' + name)
            try:
                return json.load(stream, object_pairs_hook=_unique_object,
                                 parse_constant=_invalid_constant)
            except (ValueError, UnicodeError) as error:
                raise OwnershipError('Invalid reservation JSON: ' + name) from error

    @staticmethod
    def _create_json(descriptor, name, value):
        file_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                          0o600, dir_fd=descriptor)
        with os.fdopen(file_fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, allow_nan=False, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())

    def _write_owner(self, descriptor, record):
        temporary = '.owner-' + uuid.uuid4().hex
        self._create_json(descriptor, temporary, record)
        self._check_layout(descriptor, extra=(temporary,))
        os.replace(temporary, _OWNER, src_dir_fd=descriptor, dst_dir_fd=descriptor)

    def _create_operation(self, descriptor, identity):
        self._create_json(descriptor, _OPERATION, identity)

    def _read_owner(self, descriptor, resource):
        self._check_layout(descriptor)
        record = self._read_json(descriptor, _OWNER)
        try:
            if not isinstance(record, dict) or set(record) != _RECORD_KEYS:
                raise ValueError('Invalid owner fields')
            if (type(record['schema_version']) is not int or
                    record['schema_version'] != 1):
                raise ValueError('Invalid owner schema')
            if _validate_resource(record['resource']) != resource:
                raise ValueError('Resource identity mismatch')
            _validate_component(record['environment_id'])
            if record['operation_id'] is not None:
                _validate_component(record['operation_id'])
            if (type(record['mutated']) is not bool or
                    type(record['abortable']) is not bool):
                raise ValueError('Invalid owner state')
            if record['abortable'] and (record['mutated'] or
                                        record['operation_id'] is None):
                raise ValueError('Invalid abort eligibility')
        except ValueError as error:
            raise OwnershipError('Invalid owner record') from error
        return record

    def _check_operation(self, descriptor, record):
        if record['operation_id'] is None:
            if _OPERATION in os.listdir(descriptor):
                raise OwnershipError('Incomplete operation acquisition')
            return
        operation = self._read_json(descriptor, _OPERATION)
        expected = {key: record[key] for key in _IDENTITY_KEYS}
        if not isinstance(operation, dict) or operation != expected:
            raise OwnershipError('Operation marker does not match owner')

    @contextmanager
    def _transaction(self, descriptor, identity):
        try:
            self._create_json(descriptor, _TRANSITION, identity)
        except FileExistsError as error:
            try:
                metadata = os.stat(_TRANSITION, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                raise ResourceBusy('Reservation transition just completed') from error
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OwnershipError('Unsafe transition marker') from error
            raise ResourceBusy('Reservation transition is active or incomplete') from error
        state = {'changed': False, 'removed': False}
        try:
            self._check_layout(descriptor)
            yield state
        except BaseException:
            if not state['changed'] and not state['removed']:
                try:
                    os.unlink(_TRANSITION, dir_fd=descriptor)
                except FileNotFoundError:
                    pass
                except OSError as error:
                    LOGGER.error('Transition cleanup failure; reservation retained: %s', error)
            raise
        else:
            if not state['removed']:
                os.unlink(_TRANSITION, dir_fd=descriptor)

    def claim(self, resource, environment_id, operation_id):
        identity = _identity(resource, environment_id, operation_id)
        with self._io_errors(), self._root_fd() as root_fd:
            try:
                os.mkdir(self._resource_name(resource), mode=0o700, dir_fd=root_fd)
            except FileExistsError as error:
                raise ResourceBusy('Resource already reserved: ' + resource) from error
            os.chmod(self._resource_name(resource), 0o700, dir_fd=root_fd)
            with self._directory(root_fd, resource) as descriptor:
                os.fchmod(descriptor, 0o700)
                self._check_layout(descriptor)
                self._create_operation(descriptor, identity)
                record = dict(identity, schema_version=1, mutated=False, abortable=True)
                self._write_owner(descriptor, record)
        LOGGER.info('Claimed %s for environment %s operation %s',
                    resource, environment_id, operation_id)
        return dict(identity, created=True)

    def resume(self, resource, environment_id, operation_id):
        identity = _identity(resource, environment_id, operation_id)
        with self._io_errors(), self._root_fd() as root_fd:
            with self._directory(root_fd, resource) as descriptor:
                with self._transaction(descriptor, identity) as state:
                    record = self._read_owner(descriptor, resource)
                    if record['environment_id'] != environment_id:
                        raise OwnershipError('Environment identity mismatch')
                    self._check_operation(descriptor, record)
                    if record['operation_id'] is not None:
                        if record['operation_id'] != operation_id:
                            raise ResourceBusy('Environment has an active operation')
                        LOGGER.info('Re-entered %s for environment %s operation %s',
                                    resource, environment_id, operation_id)
                        return dict(identity, created=False)
                    state['changed'] = True
                    self._create_operation(descriptor, identity)
                    if self._read_owner(descriptor, resource) != record:
                        raise OwnershipError('Owner changed during resume')
                    record.update(operation_id=operation_id, abortable=False)
                    self._write_owner(descriptor, record)
        LOGGER.info('Resumed %s for environment %s operation %s',
                    resource, environment_id, operation_id)
        return dict(identity, created=False)

    def _modify(self, handle, action):
        handle = _validate_handle(handle)
        identity = {key: handle[key] for key in _IDENTITY_KEYS}
        with self._io_errors(), self._root_fd() as root_fd:
            with self._directory(root_fd, handle['resource']) as descriptor:
                with self._transaction(descriptor, identity) as state:
                    record = self._read_owner(descriptor, handle['resource'])
                    self._check_operation(descriptor, record)
                    if any(record[key] != identity[key] for key in _IDENTITY_KEYS):
                        raise OwnershipError('Handle does not hold the current operation')
                    if action == 'abort' and (not handle['created'] or
                                              not record['abortable'] or record['mutated']):
                        raise OwnershipError('Only a new, unmodified reservation can abort')
                    state['changed'] = True
                    if action == 'mutate':
                        record.update(mutated=True, abortable=False)
                        self._write_owner(descriptor, record)
                    elif action == 'keep':
                        record.update(operation_id=None, abortable=False)
                        self._write_owner(descriptor, record)
                        os.unlink(_OPERATION, dir_fd=descriptor)
                    else:
                        self._check_layout(descriptor)
                        os.unlink(_OWNER, dir_fd=descriptor)
                        os.unlink(_OPERATION, dir_fd=descriptor)
                        os.unlink(_TRANSITION, dir_fd=descriptor)
                        state['removed'] = True
                        # No path-based cleanup after rmdir: a new claim may already exist.
                        os.rmdir(self._resource_name(handle['resource']), dir_fd=root_fd)
        LOGGER.info('Ownership %s: %s environment %s operation %s',
                    action, handle['resource'], handle['environment_id'],
                    handle['operation_id'])

    @contextmanager
    def authorized(self, handle):
        handle = _validate_handle(handle)
        identity = {key: handle[key] for key in _IDENTITY_KEYS}
        with self._io_errors(), self._root_fd() as root_fd:
            with self._directory(root_fd, handle['resource']) as descriptor:
                with self._transaction(descriptor, identity) as state:
                    record = self._read_owner(descriptor, handle['resource'])
                    self._check_operation(descriptor, record)
                    if any(record[key] != identity[key] for key in _IDENTITY_KEYS):
                        raise OwnershipError('Handle does not hold the current operation')
                    state['record'] = dict(record)

                    def mark_mutated():
                        state['changed'] = True
                        record.update(mutated=True, abortable=False)
                        self._write_owner(descriptor, record)
                        state['record'] = dict(record)
                    state['mark_mutated'] = mark_mutated
                    yield state

    def mark_mutated(self, handle):
        self._modify(handle, 'mutate')

    def keep(self, handle):
        self._modify(handle, 'keep')

    def abort_unmodified(self, handle):
        self._modify(handle, 'abort')

    def release_restored(self, handle):
        """Caller attests verified restoration; this method performs no readiness checks."""
        self._modify(handle, 'release')
