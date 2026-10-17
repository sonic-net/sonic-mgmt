import re
import uuid
from pathlib import Path

from .ranking_infra import (
    PLAYBOOKS, RECEIPT_FILE, ReceiptError, read_receipt, update_receipt,
)


IDENTITY_PATTERN = re.compile(r'[A-Za-z0-9_-]+')


class RankingSetupError(RuntimeError):
    def __init__(self, action, result):
        self.action = action
        self.result = result
        self.cleanup_errors = []
        super().__init__('ranking {} failed with rc {}'.format(action, result.rc))


class RankingCaseError(RuntimeError):
    def __init__(self, case, result):
        self.case = case
        self.result = result
        super().__init__('ranking case {} failed with rc {}'.format(case, result.rc))


def _identity(value, description):
    if not isinstance(value, str) or IDENTITY_PATTERN.fullmatch(value) is None:
        raise ValueError('{} must be a plain identifier'.format(description))
    return value


class RankingSession:
    """Controller-side ranking lifecycle: one setup, ordered cases, one finalizer."""

    def __init__(self, infra, *, environment_id, keep, skip_setup,
                 execution=None, operation_id=None, artifacts_root=None):
        if not callable(getattr(infra, 'call', None)):
            raise ValueError('infra must expose a callable ranking action boundary')
        self._infra = infra
        self._environment_id = _identity(environment_id, 'environment_id')
        self._keep = bool(keep)
        self._skip_setup = bool(skip_setup)
        self._execution = execution
        self._operation_id = _identity(
            operation_id if operation_id is not None else 'op-' + uuid.uuid4().hex,
            'operation_id')
        self._artifacts_root = artifacts_root
        self._receipt = None
        self._started = False
        self._closed = False
        self._sequence = 0

    def start(self):
        if self._closed:
            raise RuntimeError('ranking session is already closed')
        if self._started:
            return
        action = 'status' if self._skip_setup else 'setup'
        result = self._invoke(action, None, None)
        if result.rc != 0:
            setup_error = RankingSetupError(action, result)
            self._closed = True
            if action == 'setup' and self._receipt_has_acquired_resources():
                try:
                    cleanup = self._invoke('teardown', None, None)
                except Exception as error:
                    detail = ' '.join(str(error).splitlines()) or 'no diagnostics'
                    self._preserve_cleanup_failure(
                        setup_error, 'automatic teardown raised {}: {}'.format(
                            type(error).__name__, detail))
                else:
                    if cleanup.rc != 0:
                        self._preserve_cleanup_failure(
                            setup_error,
                            'automatic teardown failed with rc {}'.format(cleanup.rc))
            raise setup_error
        self._started = True

    def run(self, case):
        if self._closed:
            raise RuntimeError('ranking session is already closed')
        if not self._started:
            raise RuntimeError('ranking session has not started')
        run_id = 'run-' + uuid.uuid4().hex
        result = self._invoke('run', case, run_id)
        if result.rc != 0:
            raise RankingCaseError(case, result)
        return result

    def close(self):
        if self._closed:
            return
        self._closed = True
        if not self._started:
            return
        action = 'keep' if self._keep else 'teardown'
        result = self._invoke(action, None, None)
        if result.rc != 0:
            raise RuntimeError(
                'ranking {} failed with rc {}'.format(action, result.rc))

    def _receipt_has_acquired_resources(self):
        if self._receipt is None:
            return False
        try:
            receipt = read_receipt(self._receipt)
        except (ReceiptError, OSError):
            return False
        return receipt['phase'] == 'prepared' and any(
            entry['acquired'] and not entry['released']
            for entry in receipt['resources'])

    def _preserve_cleanup_failure(self, setup_error, message):
        setup_error.cleanup_errors.append(message)
        try:
            receipt = read_receipt(self._receipt)
            receipt['cleanup_errors'].append(message)
            update_receipt(self._receipt, receipt)
        except Exception as error:
            setup_error.cleanup_errors.append(
                'cleanup diagnostic could not be recorded: {}'.format(error))

    def _invoke(self, action, case, run_id):
        if action not in PLAYBOOKS:
            raise ValueError('unknown ranking action: {!r}'.format(action))
        self._sequence += 1
        artifacts = None
        if self._artifacts_root is not None:
            leaf = '{}-{}'.format(action, self._sequence)
            if run_id is not None:
                leaf = run_id
            artifacts = str(self._artifacts_root / leaf)
        if action == 'setup' and artifacts is not None:
            self._receipt = Path(artifacts) / self._environment_id / RECEIPT_FILE
        kwargs = {'execution': self._execution,
                  'environment_id': self._environment_id,
                  'operation_id': self._operation_id, 'case': case,
                  'run_id': run_id, 'artifacts': artifacts}
        if action in ('keep', 'teardown') and self._receipt is not None:
            kwargs['receipt'] = str(self._receipt)
        return self._infra.call(action, **kwargs)
