import logging
import re

from .environment_ownership import (
    OwnershipError, _validate_component, _validate_handle, _validate_resource,
)


LOGGER = logging.getLogger(__name__)
_MACHINE_ID = re.compile(r'[0-9a-fA-F]{32}(?:\r?\n)?')
_CONTAINER_ID = re.compile(r'[0-9a-fA-F]{64}')


class ReservationRollbackError(RuntimeError):
    def __init__(self, primary, cleanup_errors, *, action='Claim'):
        self.primary = primary
        self.cleanup_errors = tuple(cleanup_errors)
        details = '; '.join('{}: {}'.format(handle['resource'], error)
                            for handle, error in self.cleanup_errors)
        super().__init__('{} failed: {}; rollback failures: {}'.format(
            action, primary, details))


class ReservationReleaseError(RuntimeError):
    def __init__(self, primary, released, remaining, uncertain):
        self.primary = primary
        self.released = tuple(released)
        self.remaining = tuple(remaining)
        self.uncertain = uncertain
        super().__init__(
            'Release failed: {}; released: [{}]; retained: [{}]; uncertain: {}'.format(
                primary, ', '.join(self.released), ', '.join(self.remaining),
                uncertain))


def resource_keys(dut_machine_id, ptf_machine_id, ptf_container_id) -> tuple[str, str]:
    identities = []
    for value, pattern in ((dut_machine_id, _MACHINE_ID),
                           (ptf_machine_id, _MACHINE_ID),
                           (ptf_container_id, _CONTAINER_ID)):
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            raise ValueError('Invalid resource identity: {!r}'.format(value))
        identities.append(value.rstrip('\r\n').lower())
    dut, ptf, container = identities
    return 'dut:' + dut, 'ptf:{}:{}'.format(ptf, container)


def reserve_all(resources, environment_id, operation_id, client):
    """Claim canonical keys in order; rollback only this request's new reservations."""
    if not isinstance(resources, (list, tuple)):
        raise ValueError('Resources must be a list or tuple of canonical keys')
    _validate_component(environment_id)
    _validate_component(operation_id)
    ordered = sorted(_validate_resource(resource) for resource in resources)
    if len(set(ordered)) != len(ordered):
        raise ValueError('Duplicate resource keys')
    handles = []
    try:
        for resource in ordered:
            handle = _validate_handle(
                client.claim(resource, environment_id, operation_id))
            if (handle['resource'] != resource or
                    handle['environment_id'] != environment_id or
                    handle['operation_id'] != operation_id):
                raise OwnershipError('Client returned a mismatching reservation handle')
            handles.append(handle)
    except Exception as primary:
        cleanup_errors = []
        for handle in reversed(handles):
            if not handle['created']:
                continue
            try:
                client.abort_unmodified(handle)
            except Exception as error:
                cleanup_errors.append((dict(handle), error))
                LOGGER.error('Rollback retained reservation %s: %s', handle['resource'], error)
        if cleanup_errors:
            raise ReservationRollbackError(primary, cleanup_errors) from primary
        raise
    return handles


def resume_all(resources, environment_id, operation_id, client) -> list[dict]:
    """Resume in canonical order; failure ends only validated operations, not ownership."""
    if not isinstance(resources, (list, tuple)):
        raise ValueError('Resources must be a list or tuple of canonical keys')
    _validate_component(environment_id)
    _validate_component(operation_id)
    ordered = sorted(_validate_resource(resource) for resource in resources)
    if len(set(ordered)) != len(ordered):
        raise ValueError('Duplicate resource keys')
    handles = []
    failing = None
    try:
        for resource in ordered:
            failing = resource
            handle = _validate_handle(
                client.resume(resource, environment_id, operation_id))
            if (handle['resource'] != resource or
                    handle['environment_id'] != environment_id or
                    handle['operation_id'] != operation_id or
                    handle['created'] is not False):
                raise OwnershipError('Client returned a mismatching resume handle')
            handles.append(handle)
    except Exception as primary:
        LOGGER.warning('Resume failed for %s; unvalidated ownership retained: %s',
                       failing, primary)
        cleanup_errors = []
        for handle in reversed(handles):
            try:
                client.keep(handle)
            except Exception as error:
                cleanup_errors.append((dict(handle), error))
                LOGGER.error('Resume rollback retained operation %s: %s',
                             handle['resource'], error)
        if cleanup_errors:
            raise ReservationRollbackError(
                primary, cleanup_errors, action='Resume') from primary
        raise
    return handles


def release_verified(handles, client, verify_all, persist):
    """Release both ends only after every handle is attested exactly restored."""
    if not isinstance(handles, (list, tuple)):
        raise ValueError('Handles must be a list or tuple of reservation handles')
    ordered = [_validate_handle(handle) for handle in handles]
    if len({handle['resource'] for handle in ordered}) != len(ordered):
        raise ValueError('Duplicate reservation handles')
    identities = {(handle['environment_id'], handle['operation_id'])
                  for handle in ordered}
    if len(identities) > 1:
        raise ValueError('Handles must share one environment and operation')
    ordered.sort(key=lambda handle: handle['resource'])
    if not ordered:
        return ()
    verdicts = verify_all(ordered)
    if not isinstance(verdicts, dict):
        raise OwnershipError('Verification must return per-resource attestations')
    for handle in ordered:
        verdict = verdicts.get(handle['resource'])
        if type(verdict) is not bool or verdict is not True:
            raise OwnershipError(
                'Verified restoration is required before release: ' +
                handle['resource'])
    persist({'event': 'verified', 'environment_id': ordered[0]['environment_id'],
             'operation_id': ordered[0]['operation_id'],
             'resources': tuple(handle['resource'] for handle in ordered)})
    released = []
    for index, handle in enumerate(ordered):
        persist({'event': 'release_pending', 'resource': handle['resource']})
        try:
            client.release_restored(handle)
        except Exception as primary:
            remaining = tuple(candidate['resource'] for candidate in ordered[index:])
            raise ReservationReleaseError(
                primary, tuple(released), remaining, True) from primary
        persist({'event': 'released', 'resource': handle['resource']})
        released.append(handle['resource'])
    return tuple(released)
