import base64
import copy
import hashlib
import json
import logging
import os
import re
import stat
import uuid
from contextlib import contextmanager

from .environment_ownership import (
    ACTION_ROOT, OwnershipError, _invalid_constant, _unique_object, _validate_component,
    _validate_handle, _validate_resource,
)
from .snapshot_contract import (
    _validate_file, _validate_identity, _validate_path, validate_snapshot,
)


LOGGER = logging.getLogger(__name__)
_NAMES = {'snapshot.json', 'environment.json', 'baseline.json', 'ledger.json',
          'run-state.json'}
_HASH = re.compile(r'[0-9a-f]{64}')
_IMAGE = re.compile(r'sha256:[0-9a-f]{64}')
_INTERFACE = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:-]*')
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_ENVIRONMENT_KEYS = {
    'schema_version', 'environment_id', 'resource', 'backend', 'dut_id',
    'dut_image_fingerprint', 'saiserver_image_id', 'saiserver_container_name',
    'current_saiserver_container_id', 'ptf_host_id', 'ptf_container_id',
    'profile_id', 'profile_hash', 'source_identity', 'source_hash', 'mapping_hash',
    'snapshot_path', 'baseline_path', 'peer_resource', 'snapshot_complete',
}
_PTF_KEYS = {'schema_version', 'environment_id', 'resource', 'peer_resource',
             'container_id', 'running', 'interfaces', 'staging_path', 'staging_state'}
_LEDGER_KEYS = {'schema_version', 'environment_id', 'resource', 'attempted', 'completed'}
_BASELINE_KEYS = {'schema_version', 'environment_id', 'resource', 'snapshot_identity',
                  'ports', 'snapshot_sha256'}
_RUN_KEYS = {'schema_version', 'environment_id', 'run_id', 'phase',
             'process_exited', 'collected', 'outcome_path'}
_PHASES = {'prepared', 'running', 'collecting', 'collected', 'failed'}
_TRANSITIONS = {
    'prepared': {'running', 'failed'},
    'running': {'collecting', 'failed'},
    'collecting': {'collected', 'failed'},
    'collected': set(),
    'failed': set(),
}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False)


def _digest(value):
    return hashlib.sha256(_canonical(value).encode('ascii')).hexdigest()


def _fields(value, keys):
    if type(value) is not dict or set(value) != keys:
        raise ValueError('Invalid state fields')
    if type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ValueError('Unsupported state schema')


def _match(value, pattern, label):
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError('Invalid ' + label)


def _json_value(value):
    if value is None or type(value) in (bool, int, str):
        return
    if type(value) is float:
        _canonical(value)
        return
    if type(value) is list:
        for child in value:
            _json_value(child)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for child in value.values():
            _json_value(child)
        return
    raise ValueError('State must contain only JSON values')


class StateStore:
    def __init__(self, root, ownership, resource):
        root = os.fspath(root)
        _validate_path(root)
        if root == '/' or os.path.normpath(root) != root:
            raise ValueError('State root must be canonical and absolute')
        self.root = root
        if not hasattr(ownership, 'authorized') or not hasattr(ownership, 'root'):
            raise ValueError('Ownership store is required')
        if ownership.root == root or ownership.root.startswith(root + '/') or root.startswith(
                ownership.root + '/'):
            raise ValueError('State and ownership roots must be separate')
        self.ownership = ownership
        self.resource = _validate_resource(resource)

    @contextmanager
    def _errors(self):
        try:
            yield
        except (OSError, ValueError, UnicodeError, RecursionError) as error:
            LOGGER.error('State failure; ownership and diagnostics retained: %s', error)
            raise OwnershipError('State failure; ownership and diagnostics retained: ' +
                                 str(error)) from error

    @contextmanager
    def _authorized(self, handle):
        handle = _validate_handle(handle)
        if handle['resource'] != self.resource:
            raise OwnershipError('State resource does not match handle')
        with self.ownership.authorized(handle) as transaction:
            with self._errors():
                transaction['handle'] = handle
                yield transaction

    @staticmethod
    def _protected(descriptor):
        metadata = os.fstat(descriptor)
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or
                metadata.st_mode & 0o077):
            raise OwnershipError('Unprotected state directory')

    @staticmethod
    def _mkdir(parent, name, transaction):
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
            return
        except FileNotFoundError:
            pass
        if transaction is not None:
            transaction['changed'] = True
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass

    @contextmanager
    def _walk(self, path, create_leaf=False, protected_leaf=False, transaction=None):
        _validate_path(path)
        descriptor = os.open('/', _DIRECTORY_FLAGS)
        try:
            parts = path[1:].split('/')
            for index, part in enumerate(parts):
                if create_leaf and index == len(parts) - 1:
                    self._mkdir(descriptor, part, transaction)
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            if protected_leaf:
                self._protected(descriptor)
            yield descriptor
        finally:
            os.close(descriptor)

    @contextmanager
    def _child(self, parent, name, create, transaction=None):
        if create:
            self._mkdir(parent, name, transaction)
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
        try:
            self._protected(descriptor)
            yield descriptor
        finally:
            os.close(descriptor)

    @staticmethod
    def _layout(descriptor, extra=()):
        for name in os.listdir(descriptor):
            if name not in _NAMES.union(extra):
                raise OwnershipError('Unknown state entry: ' + name)
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or
                    metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077):
                raise OwnershipError('Unsafe state entry: ' + name)

    @contextmanager
    def _open_environment(self, handle, create=False, transaction=None):
        resource_name = _digest_resource(self.resource)
        environment_id = handle['environment_id']
        with self._walk(self.root, create, True, transaction) as root_fd:
            self._directory_layout(root_fd, hashed=True)
            with self._child(root_fd, resource_name, create, transaction) as resource_fd:
                self._directory_layout(resource_fd)
                with self._child(resource_fd, environment_id, create, transaction) as descriptor:
                    self._layout(descriptor)
                    yield descriptor

    @staticmethod
    def _directory_layout(descriptor, hashed=False):
        for name in os.listdir(descriptor):
            if hashed:
                _match(name, _HASH, 'state resource directory')
            else:
                _validate_component(name)
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or
                    metadata.st_mode & 0o077):
                raise OwnershipError('Unsafe state directory entry: ' + name)

    @staticmethod
    def _name(name):
        if not isinstance(name, str) or name not in _NAMES:
            raise OwnershipError('State filename is not whitelisted')
        return name

    def _environment_path(self, handle):
        return self.root + '/' + _digest_resource(self.resource) + '/' + handle['environment_id']

    def path(self, handle, name):
        with self._authorized(handle) as transaction:
            self._name(name)
            return self._environment_path(transaction['handle']) + '/' + name

    @staticmethod
    def _load(descriptor, name):
        try:
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                              dir_fd=descriptor)
        except FileNotFoundError as error:
            raise OwnershipError('Missing state record: ' + name) from error
        with os.fdopen(file_fd, 'r', encoding='utf-8') as stream:
            metadata = os.fstat(stream.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or
                    metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077):
                raise OwnershipError('Unsafe state record: ' + name)
            return json.load(stream, object_pairs_hook=_unique_object,
                             parse_constant=_invalid_constant)

    def _read(self, descriptor, handle, name):
        value = self._load(descriptor, name)
        return self._validate(descriptor, handle, name, value)

    def _bound(self, value, handle):
        if value['environment_id'] != handle['environment_id']:
            raise ValueError('State environment identity mismatch')
        if 'resource' in value and value['resource'] != self.resource:
            raise ValueError('State resource identity mismatch')

    def _peer(self, peer):
        _validate_resource(peer)
        if peer.split(':')[0] == self.resource.split(':')[0]:
            raise ValueError('Peer must be the opposite resource kind')

    def _ptf_snapshot(self, value, handle):
        _fields(value, _PTF_KEYS)
        self._bound(value, handle)
        self._peer(value['peer_resource'])
        _match(value['container_id'], _HASH, 'PTF container ID')
        if value['container_id'] != self.resource.split(':')[2]:
            raise ValueError('PTF container does not match resource')
        if type(value['running']) is not bool or not value['running']:
            raise ValueError('Original PTF container must already be running')
        interfaces = value['interfaces']
        if type(interfaces) is not list:
            raise ValueError('Interfaces must be an ordered list')
        ids, names = set(), set()
        for interface in interfaces:
            if type(interface) is not dict or set(interface) != {'id', 'name'}:
                raise ValueError('Invalid PTF interface fields')
            if type(interface['id']) is not int or interface['id'] < 0:
                raise ValueError('Invalid PTF interface ID')
            _match(interface['name'], _INTERFACE, 'PTF interface name')
            if interface['id'] in ids or interface['name'] in names:
                raise ValueError('Duplicate PTF interface')
            ids.add(interface['id'])
            names.add(interface['name'])
        _validate_path(value['staging_path'])
        if (handle['environment_id'] not in value['staging_path'].split('/')[1:] or
                value['staging_state'] != 'absent'):
            raise ValueError('Staging path must be an absent environment-specific stage')
        return copy.deepcopy(value)

    def _environment(self, descriptor, handle, value):
        _fields(value, _ENVIRONMENT_KEYS)
        self._bound(value, handle)
        self._peer(value['peer_resource'])
        for key in ('backend', 'dut_id', 'ptf_host_id', 'profile_id', 'saiserver_container_name'):
            _validate_component(value[key])
        for key in ('dut_image_fingerprint', 'saiserver_image_id'):
            _match(value[key], _IMAGE, key)
        for key in ('profile_hash', 'source_hash', 'mapping_hash', 'ptf_container_id'):
            _match(value[key], _HASH, key)
        if value['current_saiserver_container_id'] is not None:
            _match(value['current_saiserver_container_id'], _HASH, 'saiserver container ID')
        if (type(value['source_identity']) is not dict or not value['source_identity'] or
                any(not key for key in value['source_identity'])):
            raise ValueError('Source identity must be a nonempty JSON object with nonempty keys')
        if type(value['snapshot_complete']) is not bool:
            raise ValueError('snapshot_complete must be boolean')
        directory = self._environment_path(handle)
        if value['snapshot_path'] != directory + '/snapshot.json':
            raise ValueError('Snapshot path does not match owned state')
        dut = self.resource.startswith('dut:')
        expected_baseline = directory + '/baseline.json' if dut else None
        if value['baseline_path'] != expected_baseline:
            raise ValueError('Baseline path does not match owned state')
        ptf_resource = value['peer_resource'] if dut else self.resource
        if ptf_resource != 'ptf:' + value['ptf_host_id'] + ':' + value['ptf_container_id']:
            raise ValueError('PTF metadata resource mismatch')
        if descriptor is None:
            return copy.deepcopy(value)
        original = self._read(descriptor, handle, 'snapshot.json')
        if dut:
            identity = original['identity']
            expected = {'environment_id': handle['environment_id'],
                        'dut_id': value['dut_id'], 'image_id': value['dut_image_fingerprint'],
                        'profile_id': value['profile_id'], 'mapping_hash': value['mapping_hash']}
            if identity != expected:
                raise ValueError('Environment does not match original snapshot identity')
            if value['saiserver_container_name'] != original['saiserver']['container_name']:
                raise ValueError('Saiserver name does not match original')
            if value['snapshot_complete']:
                # Peer validation is the role's attestation; only local proof is checked here.
                self._read(descriptor, handle, 'baseline.json')
        elif (original['container_id'] != value['ptf_container_id'] or
              original['peer_resource'] != value['peer_resource']):
            raise ValueError('PTF metadata does not match original snapshot')
        return copy.deepcopy(value)

    def _baseline(self, descriptor, handle, value):
        if not self.resource.startswith('dut:'):
            raise ValueError('PTF cannot have a DUT baseline')
        _fields(value, _BASELINE_KEYS)
        self._bound(value, handle)
        _match(value['snapshot_sha256'], _HASH, 'snapshot digest')
        _validate_identity(value['snapshot_identity'])
        if type(value['ports']) is not dict:
            raise ValueError('Baseline ports must be an object')
        for name, port in value['ports'].items():
            _validate_component(name)
            if type(port) is not dict or set(port) != {'admin_state', 'oper_state', 'speed'}:
                raise ValueError('Invalid baseline port fields')
            if any(type(port[key]) is not str for key in port):
                raise ValueError('Port states must be strings')
            if (port['admin_state'] not in ('up', 'down') or
                    port['oper_state'] not in ('up', 'down') or not port['speed']):
                raise ValueError('Invalid baseline port state')
        if descriptor is not None:
            original = self._read(descriptor, handle, 'snapshot.json')
            if (value['snapshot_identity'] != original['identity'] or
                    value['snapshot_sha256'] != _digest(original)):
                raise ValueError('Baseline original snapshot proof mismatch')
        return copy.deepcopy(value)

    def _markers(self, descriptor, handle):
        original = self._read(descriptor, handle, 'snapshot.json')
        if self.resource.startswith('ptf:'):
            return {'stage:ptf'}
        return ({'stop:' + service for service in original['services']} |
                {'restore:' + path for path in original['files']} | {'start:saiserver'})

    def _ledger(self, descriptor, handle, value):
        _fields(value, _LEDGER_KEYS)
        self._bound(value, handle)
        for key in ('attempted', 'completed'):
            markers = value[key]
            if (type(markers) is not list or any(type(marker) is not str for marker in markers) or
                    len(set(markers)) != len(markers)):
                raise ValueError('Invalid ledger marker list')
        if not set(value['completed']).issubset(value['attempted']):
            raise ValueError('Completed marker must have been attempted')
        if descriptor is not None:
            allowed = self._markers(descriptor, handle)
            if not set(value['attempted']).issubset(allowed):
                raise ValueError('Unknown or undeclared ledger marker')
        return copy.deepcopy(value)

    def _run(self, descriptor, handle, value):
        _fields(value, _RUN_KEYS)
        self._bound(value, handle)
        if not self.resource.startswith('ptf:'):
            raise ValueError('Run state is a PTF companion record')
        _validate_component(value['run_id'])
        if type(value['phase']) is not str or value['phase'] not in _PHASES:
            raise ValueError('Invalid run phase')
        for key in ('process_exited', 'collected'):
            if type(value[key]) is not bool:
                raise ValueError('Run flags must be boolean')
        if value['collected'] and not value['process_exited']:
            raise ValueError('Collection requires process exit')
        if value['phase'] == 'collected' and not value['collected']:
            raise ValueError('Collected phase requires collected result')
        if descriptor is not None:
            snapshot = self._read(descriptor, handle, 'snapshot.json')
            expected = (snapshot['staging_path'] + '/runs/' + value['run_id'] +
                        '/outcome.json')
            if value['outcome_path'] != expected:
                raise ValueError('Outcome must use the staging run path')
        return copy.deepcopy(value)

    def _validate(self, descriptor, handle, name, value):
        _json_value(value)
        if name == 'snapshot.json':
            if self.resource.startswith('ptf:'):
                return self._ptf_snapshot(value, handle)
            if type(value) is not dict:
                raise ValueError('Snapshot must be an object')
            if type(value.get('saiserver')) is not dict or set(value['saiserver']) != {
                    'exists', 'running', 'container_name'}:
                raise ValueError('Frozen snapshot requires explicit container name')
            result = validate_snapshot(value, value.get('identity'))
            if result['identity']['environment_id'] != handle['environment_id']:
                raise ValueError('Snapshot environment mismatch')
            for path in result['files']:
                self._source_path(path)
            return result
        if name == 'environment.json':
            return self._environment(descriptor, handle, value)
        if name == 'baseline.json':
            return self._baseline(descriptor, handle, value)
        if name == 'ledger.json':
            return self._ledger(descriptor, handle, value)
        return self._run(descriptor, handle, value)

    @staticmethod
    def _atomic_json(descriptor, name, value):
        temporary = '.state-' + uuid.uuid4().hex
        file_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                          0o600, dir_fd=descriptor)
        replaced = False
        try:
            with os.fdopen(file_fd, 'w', encoding='utf-8') as stream:
                stream.write(_canonical(value))
                stream.flush()
                os.fsync(stream.fileno())
            StateStore._layout(descriptor, (temporary,))
            os.replace(temporary, name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
            replaced = True
        finally:
            if not replaced:
                try:
                    os.unlink(temporary, dir_fd=descriptor)
                except FileNotFoundError:
                    pass
                except OSError as error:
                    LOGGER.error('Temporary cleanup failure; environment retained: %s', error)
        os.fsync(descriptor)

    def _write(self, descriptor, handle, name, value, transaction):
        validated = self._validate(descriptor, handle, name, value)
        if name in os.listdir(descriptor):
            previous = self._read(descriptor, handle, name)
            if name in ('snapshot.json', 'baseline.json'):
                if _canonical(previous) != _canonical(validated):
                    raise OwnershipError('Original state is immutable: ' + name)
                return
            if name == 'environment.json':
                mutable = {'current_saiserver_container_id', 'snapshot_complete'}
                if any(_canonical(previous[key]) != _canonical(validated[key])
                       for key in previous if key not in mutable):
                    raise OwnershipError('Environment identity metadata is immutable')
                if previous['snapshot_complete'] and not validated['snapshot_complete']:
                    raise OwnershipError('Snapshot completeness cannot be reset')
            if name == 'ledger.json':
                for key in ('attempted', 'completed'):
                    if validated[key][:len(previous[key])] != previous[key]:
                        raise OwnershipError('Ledger updates must append monotonically')
            if name == 'run-state.json':
                if previous['run_id'] != validated['run_id']:
                    if not previous['collected'] or not previous['process_exited']:
                        raise OwnershipError('Previous run has not exited and been collected')
                elif (validated['phase'] not in _TRANSITIONS[previous['phase']] or
                      (previous['process_exited'] and not validated['process_exited']) or
                      (previous['collected'] and not validated['collected'])):
                    raise OwnershipError('Run progress cannot be reset')
        elif name == 'environment.json' and validated['snapshot_complete']:
            raise OwnershipError('Initial environment must not attest snapshot completeness')
        transaction['changed'] = True
        self._atomic_json(descriptor, name, validated)
        LOGGER.info('Persisted %s for %s environment %s', name, self.resource,
                    handle['environment_id'])

    def read(self, handle, name):
        with self._authorized(handle) as transaction:
            handle = transaction['handle']
            self._name(name)
            with self._open_environment(handle) as descriptor:
                return self._read(descriptor, handle, name)

    def write(self, handle, name, value):
        with self._authorized(handle) as transaction:
            handle = transaction['handle']
            self._name(name)
            value = copy.deepcopy(value)
            _json_value(value)
            if name == 'baseline.json':
                value = self._derived_baseline(handle, value)
            self._validate(None, handle, name, value)
            create = name == 'snapshot.json'
            with self._open_environment(handle, create=create, transaction=transaction) as descriptor:
                self._write(descriptor, handle, name, value, transaction)

    def _derived_baseline(self, handle, value):
        """The role cannot reproduce the canonical digest; the store derives it."""
        if (not isinstance(value, dict) or 'snapshot_sha256' in value or
                set(value) != _BASELINE_KEYS - {'snapshot_sha256'}):
            return value
        with self._open_environment(handle) as descriptor:
            original = self._read(descriptor, handle, 'snapshot.json')
        return dict(value, snapshot_sha256=_digest(original))

    def _attempt(self, handle, marker, complete):
        with self._authorized(handle) as transaction:
            handle = transaction['handle']
            with self._open_environment(handle) as descriptor:
                value = self._read(descriptor, handle, 'ledger.json')
                if type(marker) is not str or marker not in self._markers(descriptor, handle):
                    raise ValueError('Unknown or undeclared attempt marker')
                if complete and marker not in value['attempted']:
                    raise ValueError('Cannot complete a nonattempted marker')
                if not complete:
                    transaction['mark_mutated']()
                key = 'completed' if complete else 'attempted'
                if marker not in value[key]:
                    value[key].append(marker)
                    self._write(descriptor, handle, 'ledger.json', value, transaction)

    def mark_attempt(self, handle, marker):
        self._attempt(handle, marker, False)

    def complete_attempt(self, handle, marker):
        self._attempt(handle, marker, True)

    def _source_path(self, path):
        _validate_path(path)
        for root in (self.root, self.ownership.root, ACTION_ROOT):
            if path == root or path.startswith(root + '/'):
                raise ValueError('Source file cannot be an ownership or state record')
        return path

    @contextmanager
    def _parent(self, path, protected=False):
        self._source_path(path)
        parent, leaf = os.path.split(path)
        if parent == '/':
            descriptor = os.open('/', _DIRECTORY_FLAGS)
            try:
                if protected:
                    self._restorable(descriptor)
                yield descriptor, leaf
            finally:
                os.close(descriptor)
        else:
            with self._walk(parent) as descriptor:
                if protected:
                    self._restorable(descriptor)
                yield descriptor, leaf

    @staticmethod
    def _restorable(descriptor):
        metadata = os.fstat(descriptor)
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or
                metadata.st_mode & 0o022):
            raise OwnershipError('Unsafe parent directory for restore')

    @staticmethod
    def _leaf(descriptor, leaf):
        try:
            metadata = os.stat(leaf, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if metadata.st_nlink != 1 or not (stat.S_ISREG(metadata.st_mode) or
                                          stat.S_ISLNK(metadata.st_mode)):
            raise OwnershipError('Unsafe original or replacement file')
        return metadata

    @staticmethod
    def _verify_leaf(parent, leaf, metadata):
        current = StateStore._leaf(parent, leaf)
        if metadata is None:
            if current is not None:
                raise OwnershipError('Original file changed during restore')
            return
        if (current is None or current.st_uid != os.geteuid() or
                (current.st_dev, current.st_ino, current.st_mode, current.st_uid,
                 current.st_size, current.st_mtime_ns, current.st_ctime_ns) !=
                (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
                 metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)):
            raise OwnershipError('Original file changed during restore')

    def capture_files(self, handle, paths):
        with self._authorized(handle):
            return self._capture_files(paths)

    def _capture_files(self, paths):
        paths = copy.deepcopy(paths)
        if type(paths) is not list or any(type(path) is not str for path in paths):
            raise ValueError('Paths must be a list of canonical paths')
        if len(set(paths)) != len(paths):
            raise ValueError('Duplicate captured path')
        for path in paths:
            self._source_path(path)
        result = {}
        for path in paths:
            with self._parent(path) as (descriptor, leaf):
                metadata = self._leaf(descriptor, leaf)
                if metadata is None:
                    original = {'state': 'absent'}
                elif stat.S_ISLNK(metadata.st_mode):
                    target = os.readlink(leaf, dir_fd=descriptor)
                    after = os.stat(leaf, dir_fd=descriptor, follow_symlinks=False)
                    if ((after.st_dev, after.st_ino, after.st_mode, after.st_size,
                         after.st_mtime_ns, after.st_ctime_ns) !=
                            (metadata.st_dev, metadata.st_ino, metadata.st_mode,
                             metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)):
                        raise OwnershipError('Original file changed during capture')
                    original = {'state': 'symlink', 'target': target}
                else:
                    file_fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                      dir_fd=descriptor)
                    with os.fdopen(file_fd, 'rb') as stream:
                        current = os.fstat(stream.fileno())
                        if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1 or
                                (current.st_dev, current.st_ino) !=
                                (metadata.st_dev, metadata.st_ino)):
                            raise OwnershipError('Original file changed during capture')
                        content = stream.read()
                        after = os.stat(leaf, dir_fd=descriptor, follow_symlinks=False)
                        if ((after.st_dev, after.st_ino, after.st_mode, after.st_size,
                             after.st_mtime_ns, after.st_ctime_ns) !=
                                (current.st_dev, current.st_ino, current.st_mode,
                                 current.st_size, current.st_mtime_ns, current.st_ctime_ns)):
                            raise OwnershipError('Original file changed during capture')
                        original = {'state': 'regular',
                                    'mode': stat.S_IMODE(current.st_mode),
                                    'content_b64': base64.b64encode(content).decode('ascii')}
                _validate_file(original)
                result[path] = original
        return result

    def restore_files(self, handle, originals):
        with self._authorized(handle) as transaction:
            handle = transaction['handle']
            originals = copy.deepcopy(originals)
            if type(originals) is not dict:
                raise ValueError('Originals must be an object')
            for path, original in originals.items():
                self._source_path(path)
                _validate_file(original)
            with self._open_environment(handle) as descriptor:
                snapshot = self._read(descriptor, handle, 'snapshot.json')
                if not self.resource.startswith('dut:'):
                    raise ValueError('PTF snapshot declares no file restorations')
                declared = snapshot['files']
                if any(path not in declared or _canonical(original) != _canonical(declared[path])
                       for path, original in originals.items()):
                    raise ValueError('Restore must use declared original file states')
                for path, original in originals.items():
                    with self._parent(path, protected=True) as (parent, leaf):
                        metadata = self._leaf(parent, leaf)
                        if metadata is not None and metadata.st_uid != os.geteuid():
                            raise OwnershipError('Unowned replacement file')
                        transaction['changed'] = True
                        if original['state'] == 'absent':
                            if metadata is not None:
                                self._verify_leaf(parent, leaf, metadata)
                                os.unlink(leaf, dir_fd=parent)
                        else:
                            temporary = '.ranking-restore-' + uuid.uuid4().hex
                            committed = False
                            try:
                                if original['state'] == 'symlink':
                                    os.symlink(original['target'], temporary, dir_fd=parent)
                                else:
                                    file_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT |
                                                      os.O_EXCL | os.O_NOFOLLOW, 0o600,
                                                      dir_fd=parent)
                                    with os.fdopen(file_fd, 'wb') as stream:
                                        content = base64.b64decode(original['content_b64'],
                                                                   validate=True)
                                        stream.write(content)
                                        stream.flush()
                                        os.fchmod(stream.fileno(), original['mode'])
                                        os.fsync(stream.fileno())
                                self._verify_leaf(parent, leaf, metadata)
                                os.replace(temporary, leaf, src_dir_fd=parent,
                                           dst_dir_fd=parent)
                                committed = True
                            finally:
                                if not committed:
                                    try:
                                        os.unlink(temporary, dir_fd=parent)
                                    except FileNotFoundError:
                                        pass
                                    except OSError as error:
                                        LOGGER.error('Temporary cleanup failure; original '
                                                     'retained: %s', error)
                        os.fsync(parent)
                        LOGGER.info('Restored declared file %s for %s', path, self.resource)


def _digest_resource(resource):
    return hashlib.sha256(resource.encode('utf-8')).hexdigest()
