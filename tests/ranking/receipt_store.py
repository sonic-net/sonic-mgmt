import json
import os
import uuid
from copy import deepcopy
from pathlib import Path

from tests.ranking.environment_ownership import (
    OwnershipError, _HANDLE_KEYS, _invalid_constant, _unique_object,
    _validate_component, _validate_resource,
)


ACTIONS = frozenset({'setup', 'status', 'run', 'teardown', 'keep'})
RECEIPT_FILE = 'environment-receipt.json'
RECEIPT_SCHEMA_VERSION = 1
RECEIPT_KEYS = frozenset({
    'schema_version', 'environment_id', 'operation_id', 'action',
    'execution_contract', 'resources', 'phase', 'primary_error', 'cleanup_errors',
})
RESOURCE_ENTRY_KEYS = frozenset({
    'resource', 'host', 'machine_id', 'container_id', 'handle', 'snapshot_path',
    'environment_path', 'identity_hash', 'acquired', 'restored', 'released',
    'uncertain',
})
RECEIPT_PHASES = frozenset({'created', 'prepared', 'kept', 'released', 'failed'})


class ReceiptError(Exception):
    """The environment receipt is missing, invalid, or cannot be rewritten."""


def _receipt_text(receipt):
    try:
        return json.dumps(receipt, sort_keys=True, indent=2, ensure_ascii=True,
                          allow_nan=False) + '\n'
    except (TypeError, ValueError) as error:
        raise ReceiptError('environment receipt must contain strict JSON values') \
            from error


def validate_host_alias(host):
    if not isinstance(host, str) or not host:
        raise ValueError('host must be a single inventory alias')
    if ',' in host or any(character.isspace() for character in host):
        raise ValueError('host must be a single inventory alias')
    return host


def validate_receipt_handle(handle, resource, environment_id):
    if not isinstance(handle, dict) or set(handle) != _HANDLE_KEYS:
        raise ValueError('handle must declare the ownership handle fields')
    if handle['resource'] != resource or \
            handle['environment_id'] != environment_id:
        raise ValueError('handle identity does not match the receipt entry')
    if handle['operation_id'] is not None:
        _validate_component(handle['operation_id'])
    if type(handle['created']) is not bool:
        raise ValueError('handle created flag must be a boolean')
    return handle


def _validate_resource_entry(entry, environment_id):
    if not isinstance(entry, dict) or set(entry) != RESOURCE_ENTRY_KEYS:
        raise ValueError('resource entry must declare the receipt fields exactly')
    resource = _validate_resource(entry['resource'])
    validate_host_alias(entry['host'])
    parts = resource.split(':')
    if entry['machine_id'] != parts[1]:
        raise ValueError('machine identity does not match the resource key')
    if len(parts) == 2:
        if entry['container_id'] is not None:
            raise ValueError('DUT entries do not carry a container identity')
    elif entry['container_id'] != parts[2]:
        raise ValueError('container identity does not match the resource key')
    for key in ('snapshot_path', 'environment_path', 'identity_hash'):
        if entry[key] is not None and (not isinstance(entry[key], str) or
                                       not entry[key]):
            raise ValueError('{} must be a path string or null'.format(key))
    for key in ('acquired', 'restored', 'released', 'uncertain'):
        if type(entry[key]) is not bool:
            raise ValueError('{} must be a boolean'.format(key))
    if entry['handle'] is not None:
        validate_receipt_handle(entry['handle'], resource, environment_id)
    if entry['handle'] is None and entry['acquired']:
        raise ValueError('acquired entries must record a reservation handle')
    return entry


def validate_receipt(value):
    try:
        if not isinstance(value, dict) or set(value) != RECEIPT_KEYS:
            raise ValueError('environment receipt must declare its fields exactly')
        if type(value['schema_version']) is not int or \
                value['schema_version'] != RECEIPT_SCHEMA_VERSION:
            raise ValueError('unsupported environment receipt schema version')
        environment_id = _validate_component(value['environment_id'])
        _validate_component(value['operation_id'])
        if value['action'] not in ACTIONS:
            raise ValueError('unknown ranking action: {!r}'.format(value['action']))
        if not isinstance(value['execution_contract'], dict) or \
                not value['execution_contract']:
            raise ValueError('execution contract must be the execution inputs object')
        if value['phase'] not in RECEIPT_PHASES:
            raise ValueError('unknown environment receipt phase')
        if value['primary_error'] is not None and (
                not isinstance(value['primary_error'], str) or
                not value['primary_error']):
            raise ValueError('primary error must be a message or null')
        if not isinstance(value['cleanup_errors'], list):
            raise ValueError('cleanup errors must be a list')
        for error in value['cleanup_errors']:
            if not isinstance(error, str) or not error:
                raise ValueError('cleanup errors must be messages')
        if not isinstance(value['resources'], list):
            raise ValueError('resources must be a list of entries')
        for entry in value['resources']:
            _validate_resource_entry(entry, environment_id)
        keys = [entry['resource'] for entry in value['resources']]
        if keys != sorted(keys) or len(set(keys)) != len(keys):
            raise ValueError('resources must be ordered by canonical key')
    except (ValueError, OwnershipError) as error:
        raise ReceiptError(str(error)) from error
    return value


def _receipt_identity(environment_id, operation_id, action, execution):
    try:
        _validate_component(environment_id)
        _validate_component(operation_id)
    except ValueError as error:
        raise ReceiptError(str(error)) from error
    if action not in ACTIONS:
        raise ReceiptError('unknown ranking action: {!r}'.format(action))
    if not isinstance(execution, dict) or not execution:
        raise ReceiptError('execution contract must be the execution inputs object')
    return environment_id, operation_id


class ReceiptStore:
    """Strict receipt persistence without lifecycle transition decisions."""

    def __init__(self, path):
        self.path = Path(path)

    def create(self, environment_id, operation_id, action, execution):
        environment_id, operation_id = _receipt_identity(
            environment_id, operation_id, action, execution)
        receipt = {
            'schema_version': RECEIPT_SCHEMA_VERSION,
            'environment_id': environment_id,
            'operation_id': operation_id,
            'action': action,
            'execution_contract': deepcopy(execution),
            'resources': [],
            'phase': 'created',
            'primary_error': None,
            'cleanup_errors': [],
        }
        text = _receipt_text(receipt)
        try:
            self.path.parent.mkdir(parents=True, mode=0o700)
        except OSError as error:
            raise ReceiptError(
                'environment receipt directory cannot be created: {}'.format(error)) \
                from error
        try:
            descriptor = os.open(
                self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as error:
            raise ReceiptError(
                'environment receipt already exists: {}'.format(self.path)) from error
        except OSError as error:
            raise ReceiptError(
                'environment receipt cannot be written: {}'.format(error)) from error
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            handle.write(text)
        return receipt

    def load(self):
        try:
            text = self.path.read_text(encoding='utf-8')
        except (OSError, UnicodeError) as error:
            raise ReceiptError(
                'environment receipt cannot be read: {}'.format(self.path)) from error
        try:
            value = json.loads(text, object_pairs_hook=_unique_object,
                               parse_constant=_invalid_constant)
        except ValueError as error:
            raise ReceiptError('environment receipt is not valid strict JSON') from error
        return validate_receipt(value)

    def save(self, receipt):
        validated = validate_receipt(receipt)
        if not self.path.is_file():
            raise ReceiptError('environment receipt is missing: {}'.format(self.path))
        text = _receipt_text(validated)
        temporary = self.path.parent / ('.' + self.path.name + '-' + uuid.uuid4().hex)
        try:
            descriptor = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        except OSError as error:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise ReceiptError(
                'environment receipt cannot be rewritten: {}'.format(error)) from error
        return validated
