"""Execute, collect, publish and clean one Ranking case."""

import json
import time
import uuid

from tests.ranking.common.artifact_contract import OUTCOME_FILE, RUN_LOG_FILE
from tests.ranking.run import artifact_collection, ptf_container, ptf_protocol
from tests.ranking.run.live_console import LiveConsole


class InfrastructureError(RuntimeError):
    """The environment or artifact state could not be confirmed."""


def _collector(path, case):
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, ValueError) as error:
        raise InfrastructureError(
            'collector is invalid: {}'.format(error)) from error
    module, cls = case.split('.')
    if (not isinstance(value, dict) or value.get('test_module') != module or
            value.get('test_class') != cls):
        raise InfrastructureError(
            'collector case identity differs from requested case')
    for field in ('metadata', 'spec_results', 'attr_records'):
        if field not in value:
            raise InfrastructureError('collector is missing ' + field)
    if (not isinstance(value['metadata'], dict) or
            not isinstance(value['spec_results'], list) or
            not isinstance(value['attr_records'], list)):
        raise InfrastructureError('collector payload has invalid field types')
    return value


def _merged_result(case, status, terminal, duration, collector):
    result_status = 'timeout' if (
        terminal.get('timed_out') or terminal.get('rc') == 124) else status
    metadata = dict(collector.get('metadata', {})) if collector else {}
    metadata.pop('port_count', None)
    error_message = collector.get('error_message') if collector else None
    if error_message is None:
        error_message = terminal.get('error') or terminal.get('log_error')
    return {
        'case': case,
        'status': result_status,
        'rc': terminal.get('rc'),
        'duration_seconds': duration,
        'error_message': error_message,
        'metadata': metadata,
        'spec_results': collector.get('spec_results', []) if collector else [],
        'attr_records': collector.get('attr_records', []) if collector else [],
    }


def execute(
        host, config, session, case, output_root, live_log='compact',
        sink=None):
    """Return one case result; raise only for infrastructure failures."""
    run_id = uuid.uuid4().hex
    run_dir = session['root'] + '/runs/' + run_id
    staging = None
    published = None
    console = LiveConsole(live_log, case, sink)
    started = time.monotonic()
    cleanup_needed = False
    try:
        artifact_collection.create_run(host, session, run_id)
        cleanup_needed = True
        request = ptf_protocol.build_request(config, session, case, run_dir)
        ptf_container.dispatch(host, session, request)
        console, duration = ptf_container.wait(
            host, session, run_id, request, case, mode=live_log,
            sink=sink, console=console)

        staging = artifact_collection.create_staging(output_root, case, run_id)
        manifest = artifact_collection.collect(host, session, run_id, staging)
        artifact_collection.verify(staging, manifest, case)
        terminal = ptf_protocol.parse(staging / OUTCOME_FILE)
        if (terminal.get('container_id') != session['container_id'] or
                terminal['argv'] != request['argv'] or
                terminal['timeout_s'] != request['timeout_s']):
            raise InfrastructureError('runner outcome provenance differs')
        log_text = (staging / RUN_LOG_FILE).read_text(
            encoding='utf-8', errors='replace')
        status = ptf_protocol.classify(terminal, log_text)
        if status == 'infrastructure':
            raise InfrastructureError(
                terminal.get('error') or terminal.get('log_error') or
                'runner exit was not confirmed')
        collector_path = staging / (case.replace('.', '_') + '.json')
        if collector_path.exists():
            collector = _collector(collector_path, case)
        elif status == 'passed':
            raise InfrastructureError(
                'successful case did not publish a collector')
        else:
            collector = None
        merged = _merged_result(case, status, terminal, duration, collector)
        published = artifact_collection.publish(staging, case, merged)
        staging = None
        artifact_collection.cleanup(host, session, run_id)
        cleanup_needed = False
        normalized = {
            'passed': 'PASS', 'failed': 'FAIL', 'skipped': 'SKIP',
        }[status]
        log_path = published['log']
        console.finish(normalized, duration, log_path)
        return {
            'case': case,
            'status': status,
            'log_path': log_path,
        }
    except Exception as error:
        cleanup_error = None
        if cleanup_needed:
            try:
                artifact_collection.cleanup(host, session, run_id)
            except Exception as item:
                cleanup_error = item
        if staging is not None:
            try:
                artifact_collection.discard(staging)
            except Exception as item:
                cleanup_error = cleanup_error or item
        if published is not None:
            log_path = published['log']
        elif staging is not None and (staging / RUN_LOG_FILE).is_file():
            log_path = staging / RUN_LOG_FILE
        else:
            log_path = None
        console.finish('ERROR', time.monotonic() - started, log_path)
        message = str(error)
        if cleanup_error is not None:
            message += '; rollback failed: {}'.format(cleanup_error)
        if isinstance(error, InfrastructureError) and cleanup_error is None:
            raise
        raise InfrastructureError(message) from error
