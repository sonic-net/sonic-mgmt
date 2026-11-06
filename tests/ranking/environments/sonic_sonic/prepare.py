"""Preparation profile for the checked-in SONiC-to-SONiC environment."""

from collections.abc import Mapping
import json
from pathlib import Path
import re
import time
import uuid


SAI_CONTAINER = 'saiserverv2'
SAI_PROCESS_NAMES = ('saiserver', 'saiserverv2')
PROFILE_ROOT = Path(__file__).resolve().parent
SAFE_HOSTNAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}\Z')


class SonicSonicProfileError(RuntimeError):
    """A role-specific SONiC-to-SONiC operation could not be confirmed."""


def _profile_file(root, relative, description):
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise SonicSonicProfileError(
            '{} must be a regular file: {}'.format(description, path))
    return path.resolve()


def describe(context):
    """Parse this SONiC-to-SONiC package and describe its controller and sync inputs."""
    root = Path(context.environment_root).resolve()
    environment_file = Path(context.environment_file).resolve()
    if root != environment_file.parent:
        raise SonicSonicProfileError(
            'environment.yml must be directly inside the selected SONiC-to-SONiC package')
    environment_api = getattr(context, 'environment_api', None)
    if environment_api is None:
        raise SonicSonicProfileError('SONiC-to-SONiC environment API is unavailable')
    environment = environment_api.load_environment(environment_file)
    if environment.get('type') != 'sonic_sonic':
        raise SonicSonicProfileError('SONiC-to-SONiC environment type is required')
    if environment['ptf']['container'] != SAI_CONTAINER:
        raise SonicSonicProfileError(
            'SONiC-to-SONiC Prepare requires ptf.container to be {}'.format(
                SAI_CONTAINER))
    runtime = {
        'rpc_host': environment['hosts']['dut']['address'],
        'rpc_port': environment['dut']['rpc_port'],
        'timeout_s': environment['ptf']['timeout_s'],
        'ptf_container': environment['ptf']['container'],
    }
    return {
        'type': 'sonic_sonic',
        'environment': environment,
        'controller_spec': environment_api.controller_spec(environment),
        'runtime': runtime,
        'case_sync': {
            'container': environment['ptf']['container'],
            'target': environment['ptf']['case_dir'],
            'overlays': (
                {
                    'source': _profile_file(
                        root, Path('dut') / 'config_db.json', 'DUT config_db.json'),
                    'target': 'resources/config_db.json',
                },
                {
                    'source': _profile_file(
                        root, Path('dut') / 'port_config.ini', 'DUT port_config.ini'),
                    'target': 'resources/port_config.ini',
                },
            ),
        },
    }


def _validate_context(context, description):
    environment = description.get('environment')
    if not isinstance(environment, dict):
        raise SonicSonicProfileError(
            'SONiC-to-SONiC description is incomplete')
    tbinfo = context.tbinfo
    if not isinstance(tbinfo, dict):
        raise SonicSonicProfileError(
            'SONiC-to-SONiC preparation requires standard tbinfo')
    hosts = environment['hosts']
    dut_name = getattr(context.duthost, 'hostname', None)
    ptf_name = getattr(context.ptfhost, 'hostname', None)
    if (tbinfo.get('duts') != [hosts['dut']['name']]
            or dut_name != hosts['dut']['name']):
        raise SonicSonicProfileError('standard duthost does not match the SONiC-to-SONiC package')
    if tbinfo.get('ptf') != hosts['ptf']['name'] or ptf_name != hosts['ptf']['name']:
        raise SonicSonicProfileError('standard ptfhost does not match the SONiC-to-SONiC package')
    topology = tbinfo.get('topo')
    expected = 'ptf{}'.format(len(environment['ports']))
    if (not isinstance(topology, dict) or topology.get('name') != expected
            or topology.get('type') != 'ptf'):
        raise SonicSonicProfileError(
            'SONiC-to-SONiC package requires the standard {} topology'.format(expected))


def configure_env(context, description):
    """Apply this package's PTF mutations before its DUT mutations."""
    _validate_context(context, description)
    runtime = description['runtime']
    prepare_ptf(context.ptfhost, runtime)
    prepare_dut(context.duthost, runtime)


def check_env(context, description):
    """Read back the state promised by configure_env without mutating devices."""
    _validate_context(context, description)
    verify(context.duthost, context.ptfhost, description['runtime'])


def _context(host, role, operation):
    try:
        hostname = host.hostname
    except Exception:
        hostname = None
    if isinstance(hostname, str) and SAFE_HOSTNAME.fullmatch(hostname):
        return '{} {} on host {}'.format(role, operation, hostname)
    return '{} {}'.format(role, operation)


def _command(host, role, operation, argv, accepted=(0,)):
    context = _context(host, role, operation)
    try:
        result = host.command(argv=list(argv), module_ignore_errors=True)
    except Exception as error:
        raise SonicSonicProfileError('{} could not complete'.format(context)) from error
    if (not isinstance(result, Mapping) or result.get('unreachable') or result.get('skipped')
            or type(result.get('rc')) is not int or result['rc'] < 0
            or not isinstance(result.get('stdout', ''), str)
            or not isinstance(result.get('stderr', ''), str)
            or (result['rc'] == 0 and result.get('failed'))):
        raise SonicSonicProfileError(
            '{} returned an invalid or unreachable result'.format(context))
    if accepted is not None and result['rc'] not in accepted:
        detail = _result_detail(result)
        raise SonicSonicProfileError(
            '{} failed with rc {}{}'.format(
                context, result['rc'], ': ' + detail if detail else ''))
    return result


def _result_detail(result):
    for field in ('stderr', 'stdout'):
        value = result.get(field, '')
        if isinstance(value, str):
            lines = [line.strip() for line in value.splitlines() if line.strip()]
            if lines:
                return lines[-1][-300:]
    return ''


def _copy(host, role, operation, source, destination, mode):
    context = _context(host, role, operation)
    try:
        result = host.copy(src=str(source), dest=destination, mode=mode)
    except Exception as error:
        raise SonicSonicProfileError('{} could not complete'.format(context)) from error
    if (not isinstance(result, Mapping) or not result or result.get('failed')
            or result.get('unreachable') or result.get('skipped')
            or result.get('dest') != destination):
        raise SonicSonicProfileError('{} failed without matching destination evidence'.format(context))


def _process_ids(host, role, name):
    operation = 'inspect exact {} process'.format(name)
    context = _context(host, role, operation)
    result = _command(
        host, role, operation,
        ['docker', 'exec', SAI_CONTAINER, 'pgrep', '-x', name],
        accepted=(0, 1))
    if result['rc'] == 1:
        if result['stdout'].strip() or result['stderr'].strip():
            raise SonicSonicProfileError(
                '{} absence is unconfirmed'.format(context))
        return []
    pids = result['stdout'].split()
    if not pids or any(not pid.isdigit() or int(pid) <= 0 for pid in pids):
        raise SonicSonicProfileError(
            '{} list is invalid'.format(context))
    if len(pids) != len(set(pids)):
        raise SonicSonicProfileError(
            '{} list contains duplicates'.format(context))
    return pids


def _supervisor_state(ptfhost):
    result = _command(
        ptfhost, 'PTF', 'inspect SAIserver supervisor state',
        ['docker', 'exec', SAI_CONTAINER, 'supervisorctl',
         'status', 'saiserver'], accepted=(0, 3))
    fields = result['stdout'].split()
    if len(fields) < 2 or fields[0] != 'saiserver':
        raise SonicSonicProfileError(
            '{} returned an invalid state'.format(
                _context(ptfhost, 'PTF', 'inspect SAIserver supervisor state')))
    return fields[1]


def _stop_ptf_server(ptfhost):
    if _supervisor_state(ptfhost) != 'STOPPED':
        _command(
            ptfhost, 'PTF', 'stop SAIserver through supervisor',
            ['docker', 'exec', SAI_CONTAINER, 'supervisorctl',
             'stop', 'saiserver'])
        if _supervisor_state(ptfhost) != 'STOPPED':
            raise SonicSonicProfileError(
                '{} did not reach STOPPED'.format(
                    _context(ptfhost, 'PTF', 'SAIserver supervisor state')))
    pids = []
    for name in SAI_PROCESS_NAMES:
        pids.extend(_process_ids(ptfhost, 'PTF', name))
    if len(pids) != len(set(pids)):
        raise SonicSonicProfileError(
            '{} identities overlap'.format(
                _context(ptfhost, 'PTF', 'inspect exact SAI processes')))
    if pids:
        _command(
            ptfhost, 'PTF', 'terminate orphaned SAI processes',
            ['docker', 'exec', SAI_CONTAINER, 'kill', '-TERM', '--'] + pids)
    remaining = []
    for name in SAI_PROCESS_NAMES:
        remaining.extend(_process_ids(ptfhost, 'PTF', name))
    if remaining:
        _command(
            ptfhost, 'PTF', 'force terminate orphaned SAI processes',
            ['docker', 'exec', SAI_CONTAINER, 'kill', '-KILL', '--'] + remaining)
        for name in SAI_PROCESS_NAMES:
            if _process_ids(ptfhost, 'PTF', name):
                raise SonicSonicProfileError(
                    '{} is still running'.format(
                        _context(
                            ptfhost, 'PTF',
                            'inspect exact {} process'.format(name))))
    if _supervisor_state(ptfhost) != 'STOPPED':
        raise SonicSonicProfileError(
            '{} did not remain STOPPED'.format(
                _context(ptfhost, 'PTF', 'SAIserver supervisor state')))


def _wait_for_bcmcmd(ptfhost, timeout_s):
    deadline = time.monotonic() + timeout_s
    while True:
        result = _command(
            ptfhost, 'PTF', 'bcmcmd readiness',
            ['docker', 'exec', 'syncd', 'bcmcmd', '-c', 'ps'],
            accepted=None)
        if result['rc'] == 0:
            return
        if time.monotonic() >= deadline:
            detail = _result_detail(result)
            raise SonicSonicProfileError(
                '{} failed with rc {}{}'.format(
                    _context(ptfhost, 'PTF', 'bcmcmd readiness'),
                    result['rc'], ': ' + detail if detail else ''))
        time.sleep(1)


def _prepare_mirror(ptfhost):
    token = uuid.uuid4().hex
    script = '/tmp/ranking-sonic-sonic-{}-mirror.py'.format(token)
    port_config = '/tmp/ranking-sonic-sonic-{}-ports.ini'.format(token)
    source_script = PROFILE_ROOT / 'ptf' / 'mirror_port.py'
    source_config = PROFILE_ROOT / 'ptf' / 'port_config.ini'
    primary_error = None
    try:
        _copy(ptfhost, 'PTF', 'stage mirror script', source_script, script, '0755')
        _copy(ptfhost, 'PTF', 'stage mirror port config', source_config, port_config, '0644')
        _command(
            ptfhost, 'PTF', 'mirror configuration',
            ['python3', script, 'ingress', '--port-config', port_config,
             '--container', 'syncd'])
    except SonicSonicProfileError as error:
        primary_error = error
    try:
        _command(
            ptfhost, 'PTF', 'remove owned mirror files',
            ['rm', '-f', '--', script, port_config])
    except SonicSonicProfileError as cleanup_error:
        if primary_error is None:
            raise
        raise SonicSonicProfileError(
            '{}; cleanup also failed: {}'.format(primary_error, cleanup_error)) from primary_error
    if primary_error is not None:
        raise primary_error


def prepare_ptf(ptfhost, config):
    """Make the PTF SONiC device a packet host without giving its ASIC to SAIserver."""
    _command(
        ptfhost, 'PTF', 'start tooling container',
        ['/usr/bin/saiserverv2.sh', 'start'])
    _stop_ptf_server(ptfhost)
    _command(ptfhost, 'PTF', 'restart swss', ['service', 'swss', 'restart'])
    _wait_for_bcmcmd(ptfhost, config.get('timeout_s', 180))
    _prepare_mirror(ptfhost)


def prepare_dut(duthost, config):
    """Give the DUT ASIC to SAIserver and intentionally preserve that state."""
    _command(duthost, 'DUT', 'stop swss', ['service', 'swss', 'stop'])
    _command(
        duthost, 'DUT', 'start SAIserver',
        ['/usr/bin/saiserverv2.sh', 'start'])


def _service_active(host, role, expected):
    accepted = (0,) if expected else (3,)
    result = _command(
        host, role, 'inspect swss state',
        ['systemctl', 'is-active', '--', 'swss'], accepted=accepted)
    state = result['stdout'].strip()
    wanted = 'active' if expected else 'inactive'
    if state != wanted or result['stderr'].strip():
        raise SonicSonicProfileError(
            '{} state is {!r}, expected {!r}'.format(
                _context(host, role, 'inspect swss'), state, wanted))


def _rpc_reachable(ptfhost, config):
    host = config.get('rpc_host')
    if not isinstance(host, str) or not host.strip():
        raise SonicSonicProfileError(
            '{} has an unresolved DUT endpoint; derive it from the standard duthost fixture'.format(
                _context(ptfhost, 'PTF', 'RPC reachability check')))
    try:
        result = ptfhost.wait_for(
            host=host, port=config.get('rpc_port', 9092), state='started',
            timeout=config.get('timeout_s', 180), module_ignore_errors=True)
    except Exception as error:
        raise SonicSonicProfileError(
            '{} could not complete'.format(
                _context(ptfhost, 'PTF', 'RPC reachability check'))) from error
    if (not isinstance(result, Mapping) or not result or result.get('failed')
            or result.get('unreachable') or result.get('skipped')
            or result.get('state') != 'started'):
        raise SonicSonicProfileError(
            '{} did not confirm the DUT endpoint'.format(
                _context(ptfhost, 'PTF', 'RPC reachability check')))


def _container_running(host, role):
    inspected = _command(
        host, role, 'inspect SAIserver container',
        ['docker', 'container', 'inspect', SAI_CONTAINER])
    try:
        containers = json.loads(inspected['stdout'])
    except (TypeError, ValueError) as error:
        raise SonicSonicProfileError(
            '{} returned malformed JSON'.format(
                _context(host, role, 'inspect SAIserver container'))) from error
    if (inspected['stderr'].strip() or not isinstance(containers, list)
            or len(containers) != 1 or not isinstance(containers[0], Mapping)
            or containers[0].get('Name') != '/' + SAI_CONTAINER
            or not isinstance(containers[0].get('State'), Mapping)
            or containers[0]['State'].get('Running') is not True):
        raise SonicSonicProfileError(
            '{} did not confirm one running exact container'.format(
                _context(host, role, 'inspect SAIserver container')))


def verify(duthost, ptfhost, config):
    """Read back the prepared role states without changing either device."""
    _container_running(ptfhost, 'PTF')
    if _supervisor_state(ptfhost) != 'STOPPED':
        raise SonicSonicProfileError(
            '{} must remain STOPPED'.format(
                _context(ptfhost, 'PTF', 'SAIserver supervisor state')))
    for name in SAI_PROCESS_NAMES:
        if _process_ids(ptfhost, 'PTF', name):
            raise SonicSonicProfileError(
                '{} must confirm absence'.format(
                    _context(ptfhost, 'PTF', 'inspect exact {} process'.format(name))))
    _service_active(ptfhost, 'PTF', expected=True)
    _wait_for_bcmcmd(ptfhost, config.get('timeout_s', 180))
    _service_active(duthost, 'DUT', expected=False)
    _container_running(duthost, 'DUT')
    if not any(_process_ids(duthost, 'DUT', name) for name in SAI_PROCESS_NAMES):
        raise SonicSonicProfileError(
            '{} did not find a running exact process'.format(
                _context(duthost, 'DUT', 'inspect SAIserver process')))
    _rpc_reachable(ptfhost, config)
