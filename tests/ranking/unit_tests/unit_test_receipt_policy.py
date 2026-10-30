import copy
import importlib
from dataclasses import FrozenInstanceError

import pytest

from tests.ranking.receipt_store import validate_receipt


DUT = 'dut:' + 'a' * 32
PTF = 'ptf:' + 'b' * 32 + ':' + 'c' * 64


def policy():
    return importlib.import_module('tests.ranking.receipt_policy')


def entry(resource):
    parts = resource.split(':')
    return {
        'resource': resource, 'host': 'host-a', 'machine_id': parts[1],
        'container_id': parts[2] if len(parts) == 3 else None,
        'handle': {'resource': resource, 'environment_id': 'env-a',
                   'operation_id': 'op-a', 'created': True},
        'snapshot_path': None, 'environment_path': None, 'identity_hash': None,
        'acquired': True, 'restored': False, 'released': False, 'uncertain': False,
    }


def receipt(resources=True, phase='prepared', primary_error=None):
    return {
        'schema_version': 1, 'environment_id': 'env-a', 'operation_id': 'op-a',
        'action': 'setup', 'execution_contract': {'runtime': {}},
        'resources': [entry(DUT), entry(PTF)] if resources else [],
        'phase': phase, 'primary_error': primary_error, 'cleanup_errors': [],
    }


def outcome(action='teardown', **changes):
    value = {
        'schema_version': 1, 'environment_id': 'env-a', 'action': action,
        'restored': action == 'teardown',
        'released': [DUT, PTF] if action == 'teardown' else [],
        'kept': action == 'keep', 'uncertain': False,
    }
    value.update(changes)
    return value


def attestation():
    return {'resources': [{key: item[key] for key in ('resource', 'host', 'handle')}
                          for item in (entry(PTF), entry(DUT))]}


def test_setup_attests_sorted_resources_without_mutating_inputs():
    original = receipt(resources=False, phase='created')
    evidence = attestation()
    before = copy.deepcopy((original, evidence))
    decision = policy().apply_outcome(original, 'setup', 0, evidence)
    assert decision.complete and decision.reason is None
    assert decision.receipt['phase'] == 'prepared'
    assert [item['resource'] for item in decision.receipt['resources']] == [DUT, PTF]
    assert validate_receipt(decision.receipt) == decision.receipt
    decision.receipt['resources'][0]['handle']['operation_id'] = 'changed'
    assert (original, evidence) == before


def test_failed_setup_with_known_resources_remains_prepared_for_rollback():
    original = receipt(resources=False, phase='created')
    decision = policy().apply_outcome(original, 'setup', 7, attestation())
    assert not decision.complete and decision.reason
    assert decision.receipt['phase'] == 'prepared'
    assert all(item['acquired'] for item in decision.receipt['resources'])
    assert decision.receipt['primary_error'] == decision.reason


@pytest.mark.parametrize('defect', ['missing', 'one-resource', 'duplicate', 'wrong-operation', 'wrong-host'])
def test_successful_setup_requires_valid_complete_attestation(defect):
    original = receipt(resources=False, phase='created')
    evidence = attestation()
    if defect == 'missing':
        evidence = None
    elif defect == 'one-resource':
        evidence['resources'].pop()
    elif defect == 'duplicate':
        evidence['resources'][1] = copy.deepcopy(evidence['resources'][0])
    elif defect == 'wrong-operation':
        evidence['resources'][0]['handle']['operation_id'] = 'op-other'
    else:
        evidence['resources'][0]['host'] = 'host-a,host-b'
    decision = policy().apply_outcome(original, 'setup', 0, evidence)
    assert not decision.complete and decision.reason
    assert decision.receipt == original


def test_failed_setup_without_attestation_records_failure_and_preserves_primary_error():
    original = receipt(resources=False, phase='created', primary_error='original failure')
    decision = policy().apply_outcome(original, 'setup', 7, None)
    assert not decision.complete
    assert decision.receipt['phase'] == 'failed'
    assert decision.receipt['primary_error'] == 'original failure'
    assert decision.reason in decision.receipt['cleanup_errors']


def test_teardown_completion_preserves_original_failure_and_confirmed_facts():
    original = receipt(primary_error='case failed')
    evidence = outcome()
    before = copy.deepcopy((original, evidence))
    decision = policy().apply_outcome(original, 'teardown', 0, evidence)
    assert decision.complete and decision.reason is None
    assert decision.receipt['phase'] == 'released'
    assert decision.receipt['primary_error'] == 'case failed'
    assert all(item['restored'] and item['released'] for item in decision.receipt['resources'])
    assert (original, evidence) == before
    with pytest.raises(FrozenInstanceError):
        decision.complete = False


@pytest.mark.parametrize('rc,uncertain', [(7, False), (0, True)])
def test_teardown_records_release_evidence_even_when_completion_is_uncertain(rc, uncertain):
    original = receipt(primary_error='case failed')
    decision = policy().apply_outcome(original, 'teardown', rc, outcome(uncertain=uncertain))
    assert not decision.complete and decision.reason
    assert decision.receipt['phase'] == 'failed'
    assert all(item['restored'] and item['released'] and item['uncertain']
               for item in decision.receipt['resources'])
    assert decision.receipt['primary_error'] == 'case failed'
    assert decision.reason in decision.receipt['cleanup_errors']


def test_known_partial_teardown_can_later_finish_without_invented_uncertainty():
    original = receipt()
    decision = policy().apply_outcome(original, 'teardown', 0, outcome(released=[DUT]))
    assert not decision.complete and decision.reason
    assert decision.receipt['phase'] == 'failed'
    assert [item['released'] for item in decision.receipt['resources']] == [True, False]
    assert all(item['restored'] and not item['uncertain'] for item in decision.receipt['resources'])


@pytest.mark.parametrize('evidence', [
    None, {}, outcome(schema_version=True), outcome(schema_version=2),
    outcome(environment_id='env-other'), outcome(action='keep'),
    outcome(restored=1), outcome(kept=0), outcome(uncertain='false'),
    outcome(released=None), outcome(released=[DUT, DUT]),
    outcome(released=[DUT, 'dut:foreign']), outcome(released=['not-canonical']),
    outcome(restored=False), outcome(kept=True),
])
def test_untrustworthy_teardown_marks_uncertainty_without_adopting_new_facts(evidence):
    original = receipt()
    original['resources'][0].update(restored=True, released=True)
    before = copy.deepcopy(original)
    decision = policy().apply_outcome(original, 'teardown', 0, evidence)
    assert not decision.complete and decision.reason
    assert decision.receipt['phase'] == 'failed'
    assert all(item['uncertain'] for item in decision.receipt['resources'])
    assert [(item['restored'], item['released']) for item in decision.receipt['resources']] == [
        (True, True), (False, False)]
    assert original == before


def test_preexisting_uncertainty_cannot_be_cleared_by_a_later_success():
    original = receipt()
    original['resources'][0]['uncertain'] = True
    decision = policy().apply_outcome(original, 'teardown', 0, outcome())
    assert not decision.complete
    assert decision.receipt['phase'] == 'failed'
    assert decision.receipt['resources'][0]['uncertain'] is True


def test_keep_success_ends_handles_without_fabricating_release():
    original = receipt(primary_error='case failed')
    before = copy.deepcopy(original)
    decision = policy().apply_outcome(original, 'keep', 0, outcome('keep'))
    assert decision.complete and decision.reason is None
    assert decision.receipt['phase'] == 'kept'
    assert decision.receipt['primary_error'] == 'case failed'
    for item in decision.receipt['resources']:
        assert item['handle']['operation_id'] is None
        assert item['handle']['created'] is False
        assert not item['restored'] and not item['released'] and not item['uncertain']
    assert original == before


@pytest.mark.parametrize('rc,uncertain', [(7, False), (0, True)])
def test_attested_keep_records_ended_handles_despite_later_completion_failure(rc, uncertain):
    decision = policy().apply_outcome(receipt(), 'keep', rc, outcome('keep', uncertain=uncertain))
    assert not decision.complete and decision.receipt['phase'] == 'failed'
    assert all(item['handle']['operation_id'] is None and item['uncertain']
               for item in decision.receipt['resources'])


@pytest.mark.parametrize('evidence', [None, outcome('keep', kept=False), outcome('keep', restored=True)])
def test_unconfirmed_keep_does_not_end_handles(evidence):
    original = receipt()
    decision = policy().apply_outcome(original, 'keep', 0, evidence)
    assert not decision.complete and decision.reason
    assert all(item['handle']['operation_id'] == 'op-a' for item in decision.receipt['resources'])


def test_keep_refuses_unprepared_receipt_without_transition():
    original = receipt(resources=False, phase='created')
    decision = policy().apply_outcome(original, 'keep', 0, outcome('keep'))
    assert not decision.complete and decision.reason
    assert decision.receipt == original


def test_empty_receipt_completion_requires_two_resource_attestation_without_inventing_entries():
    original = receipt(resources=False)
    decision = policy().apply_outcome(original, 'teardown', 0, outcome())
    assert decision.complete and decision.receipt['phase'] == 'released'
    assert decision.receipt['resources'] == []


@pytest.mark.parametrize('released', [[], [DUT], [DUT, 'dut:second'], [DUT, PTF, 'dut:third']])
def test_empty_receipt_cannot_complete_with_incomplete_resource_evidence(released):
    decision = policy().apply_outcome(receipt(resources=False), 'teardown', 0, outcome(released=released))
    assert not decision.complete and decision.receipt['phase'] == 'failed'
    assert decision.receipt['resources'] == []


def test_direct_release_uses_attested_receipt_completion_and_preserves_primary_error():
    original = receipt(primary_error='earlier failure')
    for item in original['resources']:
        item.update(restored=True, released=True)
    before = copy.deepcopy(original)
    decision = policy().complete_release(original)
    assert decision.complete and decision.reason is None
    assert decision.receipt['phase'] == 'released'
    assert decision.receipt['primary_error'] == 'earlier failure'
    assert original == before


@pytest.mark.parametrize('defect', ['empty', 'not-acquired', 'not-restored', 'not-released', 'uncertain'])
def test_direct_release_cannot_invent_missing_completion_evidence(defect):
    original = receipt()
    for item in original['resources']:
        item.update(restored=True, released=True)
    if defect == 'empty':
        original['resources'] = []
    elif defect == 'not-acquired':
        for item in original['resources']:
            item['acquired'] = False
    else:
        field = {'not-restored': 'restored', 'not-released': 'released', 'uncertain': 'uncertain'}[defect]
        original['resources'][0][field] = defect == 'uncertain'
    decision = policy().complete_release(original)
    assert not decision.complete and decision.reason
    assert decision.receipt['phase'] == 'failed'


def test_guard_uncertainty_marks_only_participating_acquired_resources_and_preserves_facts():
    original = receipt(primary_error='case failed')
    original['resources'][0].update(restored=True, released=True)
    before = copy.deepcopy(original)
    changed = policy().mark_uncertain(original, [DUT], 'guard completion failed')
    assert changed['phase'] == 'failed'
    assert [item['uncertain'] for item in changed['resources']] == [True, False]
    assert changed['resources'][0]['restored'] and changed['resources'][0]['released']
    assert changed['primary_error'] == 'case failed'
    assert changed['cleanup_errors'] == ['guard completion failed']
    assert original == before
