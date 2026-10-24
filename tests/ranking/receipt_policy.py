from copy import deepcopy
from dataclasses import dataclass
from typing import Optional

from tests.ranking.environment_ownership import OwnershipError, _validate_resource
from tests.ranking.receipt_store import (
    ReceiptError, validate_host_alias, validate_receipt, validate_receipt_handle,
)


@dataclass(frozen=True)
class ReceiptDecision:
    receipt: dict
    complete: bool
    reason: Optional[str]


def _record_error(receipt, message):
    if receipt['primary_error'] is None:
        receipt['primary_error'] = message
    else:
        receipt['cleanup_errors'].append(message)


def mark_uncertain(receipt, resources, message):
    changed = deepcopy(validate_receipt(receipt))
    participating = set(resources)
    for entry in changed['resources']:
        if entry['acquired'] and entry['resource'] in participating:
            entry['uncertain'] = True
    changed['phase'] = 'failed'
    _record_error(changed, message)
    return changed


def _incomplete(receipt, reason, uncertain=False):
    if uncertain:
        receipt = mark_uncertain(
            receipt, [entry['resource'] for entry in receipt['resources']], reason)
    else:
        receipt['phase'] = 'failed'
        _record_error(receipt, reason)
    return ReceiptDecision(receipt, False, reason)


def _release_complete(receipt):
    acquired = [entry for entry in receipt['resources'] if entry['acquired']]
    return bool(acquired) and \
        all(entry['restored'] and entry['released'] for entry in acquired) and \
        not any(entry['uncertain'] for entry in receipt['resources'])


def complete_release(receipt):
    changed = deepcopy(validate_receipt(receipt))
    if not _release_complete(changed):
        return _incomplete(changed, 'release completion is not fully attested')
    changed['phase'] = 'released'
    return ReceiptDecision(changed, True, None)


def _attested_resource_entry(item, environment_id, operation_id):
    try:
        if not isinstance(item, dict) or set(item) != {'resource', 'host', 'handle'}:
            raise ValueError('setup outcome resource entries must declare resource, host, and handle')
        resource = _validate_resource(item['resource'])
        host = validate_host_alias(item['host'])
        handle = validate_receipt_handle(item['handle'], resource, environment_id)
    except (ValueError, OwnershipError) as error:
        raise ReceiptError('invalid setup outcome resource entry: {}'.format(error)) from error
    if handle['operation_id'] != operation_id:
        raise ReceiptError('attested handle does not match the setup operation')
    parts = resource.split(':')
    return {
        'resource': resource, 'host': host,
        'machine_id': parts[1],
        'container_id': parts[2] if len(parts) == 3 else None,
        'handle': deepcopy(handle), 'snapshot_path': None, 'environment_path': None,
        'identity_hash': None, 'acquired': True, 'restored': False,
        'released': False, 'uncertain': False,
    }


def _setup_outcome(receipt, rc, outcome):
    resources = outcome.get('resources') if isinstance(outcome, dict) else None
    entries = None
    attestation_error = None
    if isinstance(resources, list) and resources:
        try:
            entries = [_attested_resource_entry(
                item, receipt['environment_id'], receipt['operation_id']) for item in resources]
            entries.sort(key=lambda entry: entry['resource'])
            kinds = [entry['resource'].split(':', 1)[0] for entry in entries]
            if len(entries) != 2 or set(kinds) != {'dut', 'ptf'}:
                raise ReceiptError('setup must attest exactly one DUT and one PTF reservation')
        except ReceiptError as error:
            attestation_error = str(error)
            entries = None
    if rc == 0 and entries is None:
        return ReceiptDecision(receipt, False, attestation_error or
                               'successful setup must attest its acquired resources')
    if entries is not None:
        receipt['resources'] = entries
        receipt['phase'] = 'prepared'
    else:
        receipt['phase'] = 'failed'
    if rc == 0:
        return ReceiptDecision(receipt, True, None)
    reason = 'setup playbook failed with rc {}'.format(rc)
    _record_error(receipt, reason)
    if attestation_error is not None:
        receipt['cleanup_errors'].append('setup resource attestation rejected: ' + attestation_error)
    return ReceiptDecision(receipt, False, reason)


def _validate_finalizer_outcome(receipt, action, outcome):
    if not isinstance(outcome, dict):
        raise ValueError('outcome is missing or unreadable')
    if type(outcome.get('schema_version')) is not int or outcome['schema_version'] != 1:
        raise ValueError('outcome schema version is invalid')
    if outcome.get('environment_id') != receipt['environment_id'] or outcome.get('action') != action:
        raise ValueError('outcome identity does not match the requested action')
    if any(type(outcome.get(key)) is not bool for key in ('restored', 'kept', 'uncertain')):
        raise ValueError('outcome flags must be booleans')
    released = outcome.get('released')
    if not isinstance(released, list):
        raise ValueError('outcome must report a released resources list')
    for resource in released:
        _validate_resource(resource)
    if len(set(released)) != len(released):
        raise ValueError('outcome repeats a released resource')
    known = {entry['resource'] for entry in receipt['resources']}
    if known and not set(released).issubset(known):
        raise ValueError('outcome releases an unrecorded resource')
    if (released and not outcome['restored']) or (outcome['kept'] and (outcome['restored'] or released)):
        raise ValueError('outcome contains contradictory restoration and release evidence')
    if (action == 'keep' and (outcome['restored'] or released)) or (action == 'teardown' and outcome['kept']):
        raise ValueError('outcome evidence contradicts the requested action')
    if not known and action == 'teardown':
        kinds = [resource.split(':', 1)[0] for resource in released]
        if len(released) != 2 or set(kinds) != {'dut', 'ptf'}:
            raise ValueError('empty receipt requires one DUT and one PTF release attestation')


def apply_outcome(receipt, action, rc, outcome):
    changed = deepcopy(validate_receipt(receipt))
    if action == 'setup':
        return _setup_outcome(changed, rc, outcome)
    if action not in ('keep', 'teardown'):
        raise ValueError('receipt outcome action must be setup, keep, or teardown')
    if action == 'keep' and changed['phase'] == 'created':
        return ReceiptDecision(changed, False, 'keep requires a prepared environment receipt')
    try:
        _validate_finalizer_outcome(changed, action, outcome)
    except ValueError as error:
        return _incomplete(changed, '{} outcome rejected: {}'.format(action, error), uncertain=True)
    acquired = [entry for entry in changed['resources'] if entry['acquired']]
    if action == 'keep' and outcome['kept']:
        for entry in acquired:
            if not entry['released']:
                entry['handle'] = dict(entry['handle'], operation_id=None, created=False)
    elif action == 'teardown' and outcome['restored']:
        for entry in acquired:
            entry['restored'] = True
            if entry['resource'] in outcome['released']:
                entry['released'] = True
    if rc != 0:
        return _incomplete(changed, '{} playbook failed with rc {}'.format(action, rc), uncertain=True)
    if outcome['uncertain']:
        return _incomplete(changed, '{} completion is uncertain'.format(action), uncertain=True)
    if any(entry['uncertain'] for entry in changed['resources']):
        return _incomplete(changed, '{} cannot complete while recorded reservations are uncertain'.format(action))
    if action == 'keep':
        if not outcome['kept']:
            return _incomplete(changed, 'keep outcome does not attest retained reservations')
        changed['phase'] = 'kept'
    elif _release_complete(changed) or (not changed['resources'] and outcome['restored']):
        changed['phase'] = 'released'
    else:
        return _incomplete(changed, 'teardown outcome does not attest complete restoration and release')
    return ReceiptDecision(changed, True, None)
