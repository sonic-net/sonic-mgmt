import copy
import importlib
import json
import os
from unittest.mock import patch

import pytest


MODULE = 'tests.ranking.receipt_store'
DUT = 'dut:' + 'a' * 32
PTF = 'ptf:' + 'b' * 32 + ':' + 'c' * 64


def store_api():
    return importlib.import_module(MODULE)


def create_store(tmp_path, execution=None):
    api = store_api()
    store = api.ReceiptStore(tmp_path / 'environment' / api.RECEIPT_FILE)
    receipt = store.create('env-a', 'op-a', 'setup', execution or {'runtime': {}})
    return api, store, receipt


def resource_entry(resource=DUT):
    parts = resource.split(':')
    return {
        'resource': resource, 'host': 'host-a', 'machine_id': parts[1],
        'container_id': parts[2] if len(parts) == 3 else None,
        'handle': {'resource': resource, 'environment_id': 'env-a',
                   'operation_id': 'op-a', 'created': True},
        'snapshot_path': None, 'environment_path': None, 'identity_hash': None,
        'acquired': True, 'restored': False, 'released': False, 'uncertain': False,
    }


def test_create_preserves_schema_permissions_and_detaches_execution(tmp_path):
    execution = {'runtime': {'inventory': 'inventory.ini'}}
    api, store, receipt = create_store(tmp_path, execution)
    expected = {
        'schema_version': 1, 'environment_id': 'env-a', 'operation_id': 'op-a',
        'action': 'setup', 'execution_contract': copy.deepcopy(execution),
        'resources': [], 'phase': 'created', 'primary_error': None,
        'cleanup_errors': [],
    }
    assert receipt == expected
    assert store.load() == expected
    assert store.path.stat().st_mode & 0o777 == 0o600
    assert set(receipt) == api.RECEIPT_KEYS
    execution['runtime']['inventory'] = 'changed.ini'
    assert receipt == expected
    receipt['execution_contract']['runtime']['inventory'] = 'caller-changed.ini'
    assert store.load() == expected


def test_create_refuses_to_replace_an_existing_receipt(tmp_path):
    api, store, receipt = create_store(tmp_path)
    with pytest.raises(api.ReceiptError):
        store.create('env-a', 'op-b', 'teardown', {'runtime': {}})
    assert store.load() == receipt


@pytest.mark.parametrize('environment,operation,action,execution', [
    ('../env', 'op-a', 'setup', {'runtime': {}}),
    ('env-a', 'bad/operation', 'setup', {'runtime': {}}),
    ('env-a', 'op-a', 'explode', {'runtime': {}}),
    ('env-a', 'op-a', 'setup', {}),
    ('env-a', 'op-a', 'setup', {'value': float('nan')}),
    ('env-a', 'op-a', 'setup', {'value': object()}),
])
def test_create_rejects_invalid_input_before_creating_a_receipt(
        tmp_path, environment, operation, action, execution):
    api = store_api()
    path = tmp_path / 'invalid' / api.RECEIPT_FILE
    with pytest.raises(api.ReceiptError):
        api.ReceiptStore(path).create(environment, operation, action, execution)
    assert not path.exists()


@pytest.mark.parametrize('contents', [
    b'{"schema_version": 1, "schema_version": 1}',
    b'{"execution_contract": {"value": NaN}}',
    b'{"execution_contract": {"value": Infinity}}',
    b'[]', b'{', b'\xff',
])
def test_load_rejects_malformed_or_non_strict_json(tmp_path, contents):
    api, store, _ = create_store(tmp_path)
    store.path.write_bytes(contents)
    with pytest.raises(api.ReceiptError):
        store.load()


def test_load_rejects_missing_receipt(tmp_path):
    api = store_api()
    with pytest.raises(api.ReceiptError, match='cannot be read'):
        api.ReceiptStore(tmp_path / api.RECEIPT_FILE).load()


@pytest.mark.parametrize('field,value', [
    ('schema_version', True), ('schema_version', 2), ('phase', 'unknown'),
    ('environment_id', 'bad/id'), ('operation_id', 'bad/id'),
    ('action', 'unknown'), ('execution_contract', {}), ('primary_error', 3),
    ('cleanup_errors', 'failed'), ('cleanup_errors', ['']), ('resources', {}),
])
def test_load_rejects_invalid_receipt_fields(tmp_path, field, value):
    api, store, receipt = create_store(tmp_path)
    receipt[field] = value
    store.path.write_text(json.dumps(receipt), encoding='utf-8')
    with pytest.raises(api.ReceiptError):
        store.load()


@pytest.mark.parametrize('change', ['missing', 'extra'])
def test_load_requires_exact_schema_fields(tmp_path, change):
    api, store, receipt = create_store(tmp_path)
    if change == 'missing':
        del receipt['phase']
    else:
        receipt['extra'] = True
    store.path.write_text(json.dumps(receipt), encoding='utf-8')
    with pytest.raises(api.ReceiptError):
        store.load()


@pytest.mark.parametrize('field,value', [
    ('resource', 'not-canonical'), ('host', 'host-a,host-b'),
    ('machine_id', 'different'), ('container_id', 'unexpected'),
    ('snapshot_path', ''), ('environment_path', 1), ('identity_hash', False),
    ('acquired', 1), ('restored', 0), ('released', None), ('uncertain', 'false'),
    ('handle', None),
])
def test_save_rejects_invalid_resource_entries_without_changing_file(
        tmp_path, field, value):
    api, store, receipt = create_store(tmp_path)
    original = store.path.read_bytes()
    receipt['resources'] = [dict(resource_entry(), **{field: value})]
    with pytest.raises(api.ReceiptError):
        store.save(receipt)
    assert store.path.read_bytes() == original


@pytest.mark.parametrize('field,value', [
    ('resource', PTF), ('environment_id', 'env-b'),
    ('operation_id', 'bad/id'), ('created', 1),
])
def test_save_rejects_resource_handles_with_mismatched_identity(tmp_path, field, value):
    api, store, receipt = create_store(tmp_path)
    entry = resource_entry()
    entry['handle'][field] = value
    receipt['resources'] = [entry]
    with pytest.raises(api.ReceiptError):
        store.save(receipt)


@pytest.mark.parametrize('resources', [
    [resource_entry(PTF), resource_entry(DUT)],
    [resource_entry(DUT), resource_entry(DUT)],
])
def test_save_requires_resources_sorted_by_unique_canonical_key(tmp_path, resources):
    api, store, receipt = create_store(tmp_path)
    receipt['resources'] = resources
    with pytest.raises(api.ReceiptError):
        store.save(receipt)


def test_save_preserves_data_and_permissions_with_atomic_replace(tmp_path):
    _, store, receipt = create_store(tmp_path)
    receipt['phase'] = 'prepared'
    receipt['resources'] = [resource_entry(DUT), resource_entry(PTF)]
    receipt['cleanup_errors'] = ['previous cleanup failed']
    original_replace = os.replace
    replacements = []

    def capture_replace(source, destination):
        assert source.parent == destination.parent
        assert source.stat().st_mode & 0o777 == 0o600
        replacements.append((source, destination))
        original_replace(source, destination)

    with patch(MODULE + '.os.replace', side_effect=capture_replace), \
            patch(MODULE + '.os.fsync', wraps=os.fsync) as sync:
        assert store.save(receipt) == receipt
    assert len(replacements) == 1
    sync.assert_called_once()
    assert store.load() == receipt
    assert store.path.stat().st_mode & 0o777 == 0o600
    assert list(store.path.parent.iterdir()) == [store.path]


@pytest.mark.parametrize('operation', ['fsync', 'replace'])
def test_save_failure_retains_original_and_removes_temporary_file(tmp_path, operation):
    api, store, receipt = create_store(tmp_path)
    original = store.path.read_bytes()
    receipt['phase'] = 'prepared'
    with patch(MODULE + '.os.' + operation, side_effect=OSError('disk failure')):
        with pytest.raises(api.ReceiptError, match='cannot be rewritten'):
            store.save(receipt)
    assert store.path.read_bytes() == original
    assert list(store.path.parent.iterdir()) == [store.path]


@pytest.mark.parametrize('value', [float('nan'), object()])
def test_save_rejects_non_json_values_without_leaving_temporary_files(tmp_path, value):
    api, store, receipt = create_store(tmp_path)
    original = store.path.read_bytes()
    receipt['execution_contract']['value'] = value
    with pytest.raises(api.ReceiptError, match='strict JSON'):
        store.save(receipt)
    assert store.path.read_bytes() == original
    assert list(store.path.parent.iterdir()) == [store.path]


def test_save_does_not_create_a_missing_receipt(tmp_path):
    api, _, receipt = create_store(tmp_path)
    store = api.ReceiptStore(tmp_path / 'missing' / api.RECEIPT_FILE)
    with pytest.raises(api.ReceiptError, match='missing'):
        store.save(receipt)
    assert not store.path.exists()


def test_shared_validators_accept_kept_handles_and_single_host_aliases(tmp_path):
    api, _, receipt = create_store(tmp_path)
    entry = resource_entry()
    entry['handle'].update(operation_id=None, created=False)
    receipt['resources'] = [entry]
    assert api.validate_host_alias('dut-a') == 'dut-a'
    assert api.validate_receipt_handle(entry['handle'], DUT, 'env-a') == entry['handle']
    assert api.validate_receipt(receipt) == receipt
    for alias in ('', 'dut-a,dut-b', 'dut-a\ndut-b'):
        with pytest.raises(ValueError):
            api.validate_host_alias(alias)
