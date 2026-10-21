import base64
import binascii
import copy
import re

from .environment_ownership import _validate_component


_IDENTITY_KEYS = {'environment_id', 'dut_id', 'image_id',
                  'profile_id', 'mapping_hash'}
_SNAPSHOT_KEYS = {'schema_version', 'identity', 'services', 'files', 'saiserver'}
_HASH = re.compile(r'[0-9a-f]{64}')
_IMAGE = re.compile(r'sha256:[0-9a-f]{64}')
_SERVICE_STATES = ('absent', 'inactive', 'active')
_FILE_FIELDS = {'absent': {'state'},
                'regular': {'state', 'content_b64', 'mode'},
                'symlink': {'state', 'target'}}
_DEFAULT_CONTAINER = 'saiserverv2'


def _fields(value, required, optional=()):
    if (not isinstance(value, dict) or not required.issubset(value) or
            set(value).difference(required).difference(optional)):
        raise ValueError('Invalid object fields')


def _validate_identity(value):
    _fields(value, _IDENTITY_KEYS)
    for key in ('environment_id', 'dut_id', 'profile_id'):
        _validate_component(value[key])
    for key, pattern in (('image_id', _IMAGE), ('mapping_hash', _HASH)):
        if not isinstance(value[key], str) or pattern.fullmatch(value[key]) is None:
            raise ValueError('Invalid identity field: ' + key)


def _validate_path(value, absolute=True):
    if not isinstance(value, str) or not value or '\\' in value or '\x00' in value:
        raise ValueError('Invalid file path')
    if absolute and not value.startswith('/'):
        raise ValueError('File path must be absolute')
    parts = value[1:].split('/') if value.startswith('/') else value.split('/')
    for part in parts:
        if not part or part in ('.', '..'):
            raise ValueError('File path must be canonical without traversal')
        _validate_component(part)


def _validate_file(value):
    if not isinstance(value, dict) or not isinstance(value.get('state'), str):
        raise ValueError('Invalid file state')
    state = value['state']
    if state not in _FILE_FIELDS:
        raise ValueError('Unsupported file type')
    _fields(value, _FILE_FIELDS[state])
    if state == 'regular':
        mode, content = value['mode'], value['content_b64']
        if type(mode) is not int or not 0 <= mode <= 0o7777:
            raise ValueError('Invalid original file mode')
        if not isinstance(content, str):
            raise ValueError('File content must be canonical base64')
        try:
            decoded = base64.b64decode(content, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError('Invalid file content encoding') from error
        if base64.b64encode(decoded).decode('ascii') != content:
            raise ValueError('Noncanonical file content encoding')
    elif state == 'symlink':
        target = value['target']
        if not isinstance(target, str) or not target or '\x00' in target:
            raise ValueError('Invalid original symlink target')


def validate_snapshot(value, expected_identity):
    """Return a detached schema-1 dict with the default container name filled in."""
    _fields(value, _SNAPSHOT_KEYS)
    if type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ValueError('Unsupported snapshot schema')
    _validate_identity(expected_identity)
    _validate_identity(value['identity'])
    if value['identity'] != expected_identity:
        raise ValueError('Snapshot identity mismatch')
    if not isinstance(value['services'], dict) or not isinstance(value['files'], dict):
        raise ValueError('Services and files must be objects')
    for service, state in value['services'].items():
        _validate_component(service)
        if not isinstance(state, str) or state not in _SERVICE_STATES:
            raise ValueError('Invalid original service state')
    for path, original in value['files'].items():
        _validate_path(path)
        _validate_file(original)
    container = value['saiserver']
    _fields(container, {'exists', 'running'}, {'container_name'})
    if type(container['exists']) is not bool or type(container['running']) is not bool:
        raise ValueError('Container state must be boolean')
    if container['exists']:
        raise ValueError('Preexisting containers cannot be adopted in phase 1')
    if container['running']:
        raise ValueError('An absent container cannot be running')
    _validate_component(container.get('container_name', _DEFAULT_CONTAINER))
    result = copy.deepcopy(value)
    result['saiserver'].setdefault('container_name', _DEFAULT_CONTAINER)
    return result


def plan_restore(snapshot, completed_changes):
    """Plan attempted ledger markers; restore_files carries detached original states."""
    if not isinstance(snapshot, dict):
        raise ValueError('Snapshot must be an object')
    validated = validate_snapshot(snapshot, snapshot.get('identity'))
    if not isinstance(completed_changes, (list, tuple)):
        raise ValueError('Change ledger must be a list or tuple')
    allowed = {'stop:' + service for service in validated['services']}
    allowed.update('restore:' + path for path in validated['files'])
    allowed.add('start:saiserver')
    for change in completed_changes:
        if not isinstance(change, str) or change not in allowed:
            raise ValueError('Unknown or undeclared change: {!r}'.format(change))
    marked = set(completed_changes)
    actions = []
    if 'start:saiserver' in marked:
        actions.append(('stop_test_container',
                        validated['saiserver']['container_name']))
    originals = {path: original for path, original in validated['files'].items()
                 if 'restore:' + path in marked}
    if originals:
        actions.append(('restore_files', originals))
    services = validated['services']
    ordered = ['syncd', 'swss'] + [service for service in services
                                   if service not in ('syncd', 'swss')]
    for service in ordered:
        if services.get(service) == 'active' and 'stop:' + service in marked:
            actions.append(('start_service', service))
    return actions
