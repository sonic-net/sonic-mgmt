import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


RANKING_ROOT = Path(__file__).resolve().parents[2]
ADMIN_STATE = 'SAI_PORT_ATTR_ADMIN_STATE'
OPER_STATUS = 'SAI_PORT_ATTR_OPER_STATUS'
FEC_MODE = 'SAI_PORT_ATTR_FEC_MODE'


def _load_module(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, RANKING_ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def capture():
    return _load_module('ranking_capture_contract', 'cases/ptf/sai_capture.py')


@pytest.fixture
def result_module():
    return _load_module('ranking_result_contract', 'cases/ptf/sai_test_result.py')


@pytest.fixture
def capability():
    return _load_module('ranking_capability_contract', 'report/aggregate_capability.py')


def _mapping():
    return {
        'entries': {
            'sai_thrift_get_port_attribute|admin_state': {
                'attr': ADMIN_STATE, 'op': 'read', 'union': 'booldata',
            },
            'sai_thrift_get_port_attribute|oper_status': {
                'attr': OPER_STATUS, 'op': 'read', 'union': 's32',
            },
            'sai_thrift_set_port_attribute|admin_state': {
                'attr': ADMIN_STATE, 'op': 'set', 'union': 'booldata',
            },
            'sai_thrift_set_port_attribute|fec_mode': {
                'attr': FEC_MODE, 'op': 'set', 'union': 's32',
            },
        },
        'signatures': {
            'sai_thrift_get_port_attribute': ['client', 'port_id', 'admin_state', 'oper_status'],
            'sai_thrift_set_port_attribute': ['client', 'port_id', 'admin_state', 'fec_mode'],
        },
    }


def _adapter(capture, sink):
    adapter = SimpleNamespace(
        sai_thrift_get_port_attribute=Mock(return_value=None, _sai_capture=False),
        sai_thrift_set_port_attribute=Mock(return_value=0, _sai_capture=False),
    )
    capture.load_map_dict(_mapping())
    capture.set_case('saiport', 'ContractTest')
    capture.set_sink(sink)
    assert capture.install(adapter) == 2
    return adapter


def _row(attr=ADMIN_STATE, operation='read', value=None, case='saiport.ContractTest'):
    return {'case': case, 'attr': attr, 'op': operation, 'value': value}


def test_expected_negative_adapter_call_is_supported_when_the_case_passes(capture, capability):
    rows = []
    adapter = _adapter(capture, rows.append)
    adapter.status = -7
    assert adapter.sai_thrift_get_port_attribute(object(), 11, admin_state=True) is None
    assert adapter.status == -7
    assert rows == [_row(value=True)]
    assert set(rows[0]) == {'case', 'attr', 'op', 'value'}
    assert capability.aggregate([capability.classify_status('passed')]) == 'supported'


@pytest.mark.parametrize('raw, expected', [
    ('passed', 'supported'),
    ('failed', 'not_supported'),
    ('skipped', 'not_tested'),
    ('timeout', 'not_tested'),
    (None, 'not_tested'),
])
def test_only_case_outcomes_determine_evidence(capability, raw, expected):
    assert capability.classify_status(raw) == expected


@pytest.mark.parametrize('outcomes, expected', [
    (['passed'], 'supported'),
    (['passed', 'skipped'], 'supported'),
    (['failed'], 'not_supported'),
    (['failed', 'timeout'], 'not_supported'),
    (['passed', 'failed'], 'partially_supported'),
    (['failed', 'passed'], 'partially_supported'),
    (['skipped', 'timeout'], 'not_tested'),
    ([], 'not_tested'),
])
def test_mixed_case_evidence_has_four_states(capability, outcomes, expected):
    assert capability.aggregate([capability.classify_status(raw) for raw in outcomes]) == expected


def test_capture_uses_signature_without_treating_the_object_id_as_an_attribute(capture):
    rows = []
    adapter = _adapter(capture, rows.append)
    client = object()
    adapter.sai_thrift_get_port_attribute(client, 9876)
    assert rows == []
    adapter.sai_thrift_set_port_attribute(client, 9876, False, 1)
    assert rows == [_row(operation='set', value=False), _row(FEC_MODE, 'set', 1)]


def test_installing_capture_twice_does_not_record_twice(capture):
    rows = []
    adapter = _adapter(capture, rows.append)
    assert capture.install(adapter) == 0
    adapter.sai_thrift_get_port_attribute(object(), 1, admin_state=True)
    assert rows == [_row(value=True)]


def test_disabled_capture_still_returns_the_adapter_result(capture):
    rows = []
    adapter = _adapter(capture, rows.append)
    capture.set_sink(None)
    assert adapter.sai_thrift_set_port_attribute(object(), 1, admin_state=True) == 0
    assert rows == []


def test_capture_sink_failure_does_not_change_the_original_result(capture):
    sink = Mock(side_effect=RuntimeError('collector unavailable'))
    adapter = _adapter(capture, sink)
    assert adapter.sai_thrift_set_port_attribute(object(), 1, admin_state=True) == 0
    sink.assert_called_once()


@pytest.mark.parametrize('sink_fails', [False, True])
def test_wrapper_preserves_the_original_case_exception(capture, sink_fails):
    original_error = ValueError('expected adapter failure')
    adapter = SimpleNamespace(sai_thrift_get_port_attribute=Mock(
        side_effect=original_error, _sai_capture=False))
    sink = Mock(side_effect=RuntimeError('capture failed') if sink_fails else None)
    capture.load_map_dict(_mapping())
    capture.set_case('saiport', 'NegativeTest')
    capture.set_sink(sink)
    capture.install(adapter)
    with pytest.raises(ValueError) as caught:
        adapter.sai_thrift_get_port_attribute(object(), 11, admin_state=True)
    assert caught.value is original_error
    sink.assert_called_once()


@pytest.mark.parametrize('union, raw, expected', [
    ('booldata', False, [False]),
    ('booldata', True, [True]),
    ('s32', 0, [0]),
    ('s32', 3, [3]),
    ('s32list', SimpleNamespace(int32list=[0, 2]), [0, 2]),
    ('s32list', SimpleNamespace(int32list=[]), []),
    ('aclaction', SimpleNamespace(enable=False), []),
    ('aclaction', SimpleNamespace(enable=True, parameter=SimpleNamespace(s32=0)), [0]),
    ('aclfield', SimpleNamespace(enable=True, data=SimpleNamespace(booldata=False)), [False]),
    ('oid', 1234, [None]),
])
def test_capture_preserves_enum_and_boolean_payloads(capture, union, raw, expected):
    assert capture.extract_values(union, raw) == expected


@pytest.mark.parametrize('raw, enum_type, expected', [
    (False, None, 'false'), (True, None, 'true'),
    (0, 'sai_port_fec_mode_t', 'SAI_PORT_FEC_MODE_NONE'),
    (1, 'sai_port_fec_mode_t', 'SAI_PORT_FEC_MODE_RS'),
    (9, 'sai_port_fec_mode_t', None), (None, 'sai_port_fec_mode_t', None),
])
def test_report_resolves_values_without_losing_false_or_zero(capability, raw, enum_type, expected):
    enums = {'sai_port_fec_mode_t': {'0': 'SAI_PORT_FEC_MODE_NONE', '1': 'SAI_PORT_FEC_MODE_RS'}}
    assert capability.resolve_value(raw, enum_type, enums) == expected


def test_collector_deduplicates_only_identical_attribute_operation_value(result_module, tmp_path):
    collector = result_module.TestResultCollector('ContractTest', 'saiport', output_dir=str(tmp_path))
    rows = [_row(), _row(), _row(operation='set', value=False),
            _row(operation='set', value=True), _row(FEC_MODE, 'set', 0)]
    for row in rows:
        collector.record_attr_row(row)
    document = json.loads(Path(collector.write_json()).read_text())
    assert document['attr_records'] == [rows[0], rows[2], rows[3], rows[4]]
    assert document['overall_result'] == 'PASS'
    assert len(collector.attr_rows) == 5
    assert all(set(row) == {'case', 'attr', 'op', 'value'} for row in document['attr_records'])


def test_capture_collector_and_aggregate_keep_the_case_level_contract(
        capture, result_module, capability, tmp_path):
    records_dir = tmp_path / 'per-case'
    adapter = _adapter(capture, None)
    statuses = {}

    def case(name, status):
        collector = result_module.TestResultCollector(name, 'saiport', output_dir=str(records_dir))
        capture.set_case('saiport', name)
        capture.set_sink(collector.record_attr_row)
        statuses['saiport.' + name] = status
        return collector

    negative = case('ExpectedNegative', 'passed')
    adapter.status = -7
    assert adapter.sai_thrift_get_port_attribute(object(), 11, admin_state=True) is None
    negative.write_json()

    positive = case('Positive', 'passed')
    adapter.sai_thrift_get_port_attribute(object(), 1, oper_status=True)
    adapter.sai_thrift_set_port_attribute(object(), 1, admin_state=False)
    adapter.sai_thrift_set_port_attribute(object(), 1, admin_state=False)
    positive.write_json()

    failed = case('AssertionFailure', 'failed')
    adapter.sai_thrift_get_port_attribute(object(), 1, oper_status=True)
    adapter.sai_thrift_set_port_attribute(object(), 1, fec_mode=1)
    failed.mark_fail('packet assertion failed')
    failed.write_json()

    skeleton = [
        {'attr': ADMIN_STATE, 'op': 'read', 'value': 'true'},
        {'attr': ADMIN_STATE, 'op': 'set', 'value': 'false'},
        {'attr': OPER_STATUS, 'op': 'read', 'value': 'true'},
        {'attr': FEC_MODE, 'op': 'set', 'value': 'SAI_PORT_FEC_MODE_RS',
         'enum_type': 'sai_port_fec_mode_t'},
        {'attr': FEC_MODE, 'op': 'set', 'value': 'SAI_PORT_FEC_MODE_NONE',
         'enum_type': 'sai_port_fec_mode_t'},
    ]
    records = []
    for path in records_dir.glob('*.json'):
        records.extend(json.loads(path.read_text())['attr_records'])
    document = capability.build_document(
        records, skeleton, {
            'sai_port_fec_mode_t': {
                '0': 'SAI_PORT_FEC_MODE_NONE',
                '1': 'SAI_PORT_FEC_MODE_RS',
            },
        }, statuses)
    assert [cell['verdict'] for cell in document['cells']] == [
        'supported', 'supported', 'partially_supported', 'not_supported', 'not_tested',
    ]
    assert document['summary'] == {
        'supported': 2, 'partially_supported': 1, 'not_supported': 1,
        'not_tested': 1, 'total': 5, 'unjoined_records': 0,
    }
    assert document['cells'][0]['sources'] == [
        {'case': 'saiport.ExpectedNegative', 'outcome': 'passed'}]
    assert len(document['cells'][1]['sources']) == 1


def test_unjoined_case_records_fail_closed(capability):
    records = [_row(case='saiport.MissingOutcome')]
    skeleton = [{'attr': ADMIN_STATE, 'op': 'read', 'value': None}]
    with pytest.raises(ValueError, match='no matching case status'):
        capability.build_document(records, skeleton, {}, {})
