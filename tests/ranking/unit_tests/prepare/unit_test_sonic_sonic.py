import json
import importlib
import importlib.util
import ipaddress
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
import yaml


EXAMPLE = Path(__file__).resolve().parents[2] / 'environments' / 'sonic_sonic'


class RecordingHost:
    def __init__(self, role, events):
        self.role = role
        self.hostname = '{}-host'.format(role)
        self.events = events
        self._ptf_processes = {
            'saiserver': ['101', '102'],
            'saiserverv2': [],
        }
        self._ptf_supervisor_state = 'RUNNING'

    def command(self, argv, module_ignore_errors=False, **kwargs):
        argv = tuple(argv)
        self.events.append((self.role, 'command', argv))
        if argv[:4] == ('docker', 'exec', 'saiserverv2', 'pgrep'):
            name = argv[-1]
            pids = self._ptf_processes.get(name, []) if self.role == 'ptf' else ['201']
            return _result(0, '\n'.join(pids) + ('\n' if pids else '')) if pids else _result(1)
        if argv == ('docker', 'exec', 'saiserverv2', 'supervisorctl',
                    'status', 'saiserver'):
            return _result(
                0 if self._ptf_supervisor_state == 'RUNNING' else 3,
                'saiserver {} pid 101, uptime 0:00:10\n'.format(
                    self._ptf_supervisor_state))
        if argv == ('docker', 'exec', 'saiserverv2', 'supervisorctl',
                    'stop', 'saiserver'):
            self._ptf_supervisor_state = 'STOPPED'
            self._ptf_processes['saiserver'] = []
            self._ptf_processes['saiserverv2'] = []
            return _result(0, 'saiserver: stopped\n')
        if argv == ('docker', 'exec', 'syncd', 'bcmcmd', '-c', 'ps'):
            return _result(0, 'drivshell> ps\n')
        if argv[:4] == ('docker', 'exec', 'saiserverv2', 'kill'):
            self._ptf_processes['saiserver'] = []
            self._ptf_processes['saiserverv2'] = []
            return _result(0)
        if argv[:3] == ('systemctl', 'is-active', '--'):
            if self.role == 'ptf':
                return _result(0, 'active\n')
            return _result(3, 'inactive\n')
        if argv[:4] == ('docker', 'container', 'inspect', 'saiserverv2'):
            return _result(0, json.dumps([{
                'Name': '/saiserverv2',
                'State': {'Running': True},
            }]))
        return _result(0)

    def copy(self, **kwargs):
        self.events.append((self.role, 'copy', kwargs['src'], kwargs['dest'], kwargs.get('mode')))
        return {'changed': True, 'failed': False, 'dest': kwargs['dest']}

    def wait_for(self, **kwargs):
        self.events.append((self.role, 'wait_for', kwargs))
        return {'changed': False, 'failed': False, 'state': 'started'}


def _result(rc, stdout='', stderr=''):
    return {'rc': rc, 'stdout': stdout, 'stderr': stderr, 'failed': rc != 0}


def _prepare_context(dut=None, ptf=None, tbinfo=None):
    environment_api = importlib.import_module(
        'tests.ranking.environments.sonic_sonic.environment')
    return SimpleNamespace(
        environment_root=EXAMPLE,
        environment_file=EXAMPLE / 'environment.yml',
        duthost=dut,
        ptfhost=ptf,
        tbinfo=tbinfo,
        environment_api=environment_api,
    )


def test_environment_package_exposes_the_fixed_prepare_interface():
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')

    assert all(callable(getattr(profile, name, None)) for name in (
        'describe', 'configure_env', 'check_env'))


def test_environment_package_does_not_import_ranking_framework_modules():
    source = (EXAMPLE / 'prepare.py').read_text(encoding='utf-8')

    assert 'tests.ranking.common' not in source
    assert 'tests.ranking.prepare' not in source
    assert 'tests.ranking.run' not in source
    assert 'tests.ranking.report' not in source
    assert 'tests.ranking.environments.sonic_sonic' not in source


def test_describe_owns_sonic_sonic_paths_and_case_overlays():
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')

    description = profile.describe(_prepare_context())

    assert description['type'] == 'sonic_sonic'
    assert description['environment']['controller']['connection'] == 'ssh'
    assert description['environment']['hosts']['dut']['name'] == 'sonic-dut'
    assert description['controller_spec']['testbed_name'] == 'ranking'
    assert description['case_sync']['container'] == 'saiserverv2'
    assert description['case_sync']['target'] == '/SAI-TEST/ptf'
    assert description['case_sync']['overlays'] == (
        {
            'source': EXAMPLE / 'dut' / 'config_db.json',
            'target': 'resources/config_db.json',
        },
        {
            'source': EXAMPLE / 'dut' / 'port_config.ini',
            'target': 'resources/port_config.ini',
        },
    )


def test_prepare_rejects_a_container_other_than_saiserverv2():
    environment_api = importlib.import_module(
        'tests.ranking.environments.sonic_sonic.environment')
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')
    environment = environment_api.load_environment(EXAMPLE / 'environment.yml')
    environment['ptf']['container'] = 'other-container'
    context = _prepare_context()
    context.environment_api = SimpleNamespace(
        load_environment=lambda path: environment,
        controller_spec=environment_api.controller_spec,
    )

    with pytest.raises(
            profile.SonicSonicProfileError, match='requires.*saiserverv2'):
        profile.describe(context)


def test_configure_env_runs_ptf_before_dut(monkeypatch):
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')
    events = []
    dut = SimpleNamespace(hostname='sonic-dut')
    ptf = SimpleNamespace(hostname='sonic-ptf')
    context = _prepare_context(dut, ptf, {
        'duts': ['sonic-dut'], 'ptf': 'sonic-ptf',
        'topo': {'name': 'ptf32', 'type': 'ptf'},
    })
    description = profile.describe(context)
    monkeypatch.setattr(
        profile, 'prepare_ptf', lambda host, config: events.append(('ptf', host, config)))
    monkeypatch.setattr(
        profile, 'prepare_dut', lambda host, config: events.append(('dut', host, config)))

    profile.configure_env(context, description)

    assert [event[0] for event in events] == ['ptf', 'dut']
    assert events[0][1] is ptf
    assert events[1][1] is dut


def test_check_env_is_a_read_only_verify_hook(monkeypatch):
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')
    dut = SimpleNamespace(hostname='sonic-dut')
    ptf = SimpleNamespace(hostname='sonic-ptf')
    context = _prepare_context(dut, ptf, {
        'duts': ['sonic-dut'], 'ptf': 'sonic-ptf',
        'topo': {'name': 'ptf32', 'type': 'ptf'},
    })
    description = profile.describe(context)
    received = []
    monkeypatch.setattr(
        profile, 'verify',
        lambda actual_dut, actual_ptf, config: received.append(
            (actual_dut, actual_ptf, config)))

    profile.check_env(context, description)

    assert received == [(dut, ptf, description['runtime'])]


@pytest.fixture
def runtime():
    from tests.ranking.environments.sonic_sonic.environment import load_config

    value = load_config(EXAMPLE / 'environment.yml')
    value['rpc_host'] = '192.0.2.10'
    return value


@pytest.mark.parametrize('topology', [
    {'name': 'ptf32', 'type': 't0'},
    {'name': 't0', 'type': 'ptf'},
    {'name': 't0', 'type': 't0'},
])
def test_sonic_sonic_fixture_requires_exact_ptf32_name_and_type(topology):
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')
    dut = SimpleNamespace(hostname='dut')
    ptf = SimpleNamespace(hostname='ptf')
    description = {
        'environment': {
            'hosts': {'dut': {'name': 'dut'}, 'ptf': {'name': 'ptf'}},
            'ports': {str(index): {} for index in range(32)},
        },
    }
    context = SimpleNamespace(
        duthost=dut, ptfhost=ptf,
        tbinfo={'duts': ['dut'], 'ptf': 'ptf', 'topo': topology})
    with pytest.raises(profile.SonicSonicProfileError, match='ptf32'):
        profile._validate_context(context, description)


def test_concrete_profile_executes_exact_ptf_then_dut_mutations(runtime):
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')
    events = []
    ptf = RecordingHost('ptf', events)
    dut = RecordingHost('dut', events)

    profile.prepare_ptf(ptf, runtime)
    profile.prepare_dut(dut, runtime)

    mutations = [event for event in events if event[1] == 'copy' or (
        event[1] == 'command' and _is_mutation(event[2]))]
    assert mutations[0] == (
        'ptf', 'command', ('/usr/bin/saiserverv2.sh', 'start'))
    assert mutations[1] == (
        'ptf', 'command',
        ('docker', 'exec', 'saiserverv2', 'supervisorctl', 'stop', 'saiserver'))
    assert mutations[2] == ('ptf', 'command', ('service', 'swss', 'restart'))
    assert mutations[3][0:2] == ('ptf', 'copy')
    assert mutations[3][2] == str(EXAMPLE / 'ptf' / 'mirror_port.py')
    assert mutations[4][0:2] == ('ptf', 'copy')
    assert mutations[4][2] == str(EXAMPLE / 'ptf' / 'port_config.ini')
    assert mutations[5][0:2] == ('ptf', 'command')
    assert mutations[5][2][:1] == ('python3',)
    assert '--port-config' in mutations[5][2]
    assert mutations[6][0:2] == ('ptf', 'command')
    assert mutations[6][2][:1] == ('rm',)
    assert mutations[7] == ('dut', 'command', ('service', 'swss', 'stop'))
    assert mutations[8] == ('dut', 'command', ('/usr/bin/saiserverv2.sh', 'start'))


def test_concrete_profile_leaves_an_already_stopped_ptf_server_stopped(runtime):
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')
    events = []
    ptf = RecordingHost('ptf', events)
    ptf._ptf_supervisor_state = 'STOPPED'
    ptf._ptf_processes = {'saiserver': [], 'saiserverv2': []}

    profile.prepare_ptf(ptf, runtime)

    commands = [event[2] for event in events if event[1] == 'command']
    assert ('docker', 'exec', 'saiserverv2', 'supervisorctl',
            'status', 'saiserver') in commands
    assert ('docker', 'exec', 'saiserverv2', 'supervisorctl',
            'stop', 'saiserver') not in commands
    assert not any(command[:4] == ('docker', 'exec', 'saiserverv2', 'kill')
                   for command in commands)


def test_concrete_profile_cleans_orphan_after_supervisor_stop(runtime):
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')
    events = []

    class OrphaningHost(RecordingHost):
        def command(self, argv, module_ignore_errors=False, **kwargs):
            if tuple(argv) == ('docker', 'exec', 'saiserverv2', 'supervisorctl',
                              'stop', 'saiserver'):
                self.events.append((self.role, 'command', tuple(argv)))
                self._ptf_supervisor_state = 'STOPPED'
                return _result(0, 'saiserver: stopped\n')
            return super().command(argv, module_ignore_errors=module_ignore_errors, **kwargs)

    ptf = OrphaningHost('ptf', events)

    profile.prepare_ptf(ptf, runtime)

    commands = [event[2] for event in events if event[1] == 'command']
    stop = ('docker', 'exec', 'saiserverv2', 'supervisorctl',
            'stop', 'saiserver')
    terminate = ('docker', 'exec', 'saiserverv2', 'kill',
                 '-TERM', '--', '101', '102')
    assert stop in commands
    assert terminate in commands
    assert commands.index(stop) < commands.index(terminate)
    assert ptf._ptf_supervisor_state == 'STOPPED'


def test_concrete_profile_waits_for_bcmcmd_before_mirror(runtime, monkeypatch):
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')
    events = []

    class DelayedBcmHost(RecordingHost):
        def __init__(self, role, recorded):
            super().__init__(role, recorded)
            self.readiness_attempts = 0

        def command(self, argv, module_ignore_errors=False, **kwargs):
            if tuple(argv) == ('docker', 'exec', 'syncd', 'bcmcmd', '-c', 'ps'):
                self.events.append((self.role, 'command', tuple(argv)))
                self.readiness_attempts += 1
                if self.readiness_attempts < 3:
                    return _result(1, stderr='bcmcmd is not ready')
                return _result(0, 'drivshell> ps\n')
            return super().command(argv, module_ignore_errors=module_ignore_errors, **kwargs)

    monkeypatch.setattr(
        profile, 'time', SimpleNamespace(
            monotonic=lambda: 0, sleep=lambda seconds: None), raising=False)
    ptf = DelayedBcmHost('ptf', events)

    profile.prepare_ptf(ptf, runtime)

    assert ptf.readiness_attempts == 3
    readiness_index = max(
        index for index, event in enumerate(events)
        if event[1] == 'command'
        and event[2] == ('docker', 'exec', 'syncd', 'bcmcmd', '-c', 'ps'))
    mirror_index = next(
        index for index, event in enumerate(events)
        if event[1] == 'command' and event[2][:1] == ('python3',))
    assert readiness_index < mirror_index


def test_concrete_profile_reports_bcmcmd_readiness_timeout(runtime, monkeypatch):
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')
    events = []

    class UnreadyBcmHost(RecordingHost):
        def command(self, argv, module_ignore_errors=False, **kwargs):
            if tuple(argv) == ('docker', 'exec', 'syncd', 'bcmcmd', '-c', 'ps'):
                self.events.append((self.role, 'command', tuple(argv)))
                return _result(1, stderr='bcmcmd is not ready')
            return super().command(argv, module_ignore_errors=module_ignore_errors, **kwargs)

    monkeypatch.setattr(
        profile, 'time', SimpleNamespace(
            monotonic=lambda: 0, sleep=lambda seconds: None), raising=False)
    runtime['timeout_s'] = 0

    with pytest.raises(profile.SonicSonicProfileError, match='PTF bcmcmd readiness.*bcmcmd is not ready'):
        profile.prepare_ptf(UnreadyBcmHost('ptf', events), runtime)


def test_concrete_profile_cleans_only_owned_temporary_files_on_failure(runtime):
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')
    events = []

    class FailingMirrorHost(RecordingHost):
        def command(self, argv, module_ignore_errors=False, **kwargs):
            result = super().command(argv, module_ignore_errors=module_ignore_errors, **kwargs)
            if tuple(argv)[:1] == ('python3',):
                return _result(7, stderr='mirror failed')
            return result

    with pytest.raises(profile.SonicSonicProfileError, match='PTF mirror.*mirror failed'):
        profile.prepare_ptf(FailingMirrorHost('ptf', events), runtime)

    cleanup = [event for event in events if event[1] == 'command' and event[2][:1] == ('rm',)]
    assert len(cleanup) == 1
    assert cleanup[0][2][0:3] == ('rm', '-f', '--')
    assert len(cleanup[0][2][3:]) == 2
    assert all(path.startswith('/tmp/ranking-sonic-sonic-') for path in cleanup[0][2][3:])


def test_mirror_cleanup_error_preserves_the_primary_failure(runtime):
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')
    events = []

    class DoubleFailureHost(RecordingHost):
        def command(self, argv, module_ignore_errors=False, **kwargs):
            result = super().command(argv, module_ignore_errors=module_ignore_errors, **kwargs)
            if tuple(argv)[:1] in (('python3',), ('rm',)):
                return _result(7, stderr='injected failure')
            return result

    with pytest.raises(profile.SonicSonicProfileError) as error:
        profile.prepare_ptf(DoubleFailureHost('ptf', events), runtime)

    message = str(error.value)
    assert 'PTF mirror configuration on host ptf-host failed with rc 7' in message
    assert 'cleanup also failed' in message
    assert 'PTF remove owned mirror files on host ptf-host failed with rc 7' in message


def test_concrete_profile_always_copies_checked_in_assets(runtime):
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')
    events = []
    runtime['mirror_script'] = '/tmp/operator-selected.py'
    runtime['ptf_port_config_ini'] = '/tmp/operator-selected.ini'

    profile.prepare_ptf(RecordingHost('ptf', events), runtime)

    sources = [event[2] for event in events if event[1] == 'copy']
    assert sources == [
        str(EXAMPLE / 'ptf' / 'mirror_port.py'),
        str(EXAMPLE / 'ptf' / 'port_config.ini'),
    ]


def test_verify_is_read_only_and_checks_both_roles(runtime):
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')
    events = []
    ptf = RecordingHost('ptf', events)
    ptf._ptf_processes = {'saiserver': [], 'saiserverv2': []}
    ptf._ptf_supervisor_state = 'STOPPED'
    dut = RecordingHost('dut', events)

    profile.verify(dut, ptf, runtime)

    assert not any(event[1] == 'copy' for event in events)
    assert all(not (event[1] == 'command' and _is_mutation(event[2])) for event in events)
    assert ('ptf', 'command', ('docker', 'container', 'inspect', 'saiserverv2')) in events
    assert ('ptf', 'command', (
        'docker', 'exec', 'saiserverv2', 'supervisorctl',
        'status', 'saiserver')) in events
    assert ('ptf', 'command', ('docker', 'exec', 'syncd', 'bcmcmd', '-c', 'ps')) in events
    assert ('ptf', 'command', ('systemctl', 'is-active', '--', 'swss')) in events
    assert ('dut', 'command', ('systemctl', 'is-active', '--', 'swss')) in events
    assert ('dut', 'command', ('docker', 'container', 'inspect', 'saiserverv2')) in events
    assert not any('{{' in argument or '}}' in argument
                   for event in events if event[1] == 'command' for argument in event[2])
    assert any(event[0:2] == ('ptf', 'wait_for') for event in events)


@pytest.mark.parametrize('payload', [
    '',
    'not-json',
    '{}',
    '[]',
    '[{}, {}]',
    '[{"Name": "/other", "State": {"Running": true}}]',
    '[{"Name": "/saiserverv2", "State": {"Running": false}}]',
    '[{"Name": "/saiserverv2", "State": {"Running": "true"}}]',
])
def test_verify_rejects_malformed_or_unconfirmed_dut_container(runtime, payload):
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')
    events = []
    ptf = RecordingHost('ptf', events)
    ptf._ptf_processes = {'saiserver': [], 'saiserverv2': []}
    ptf._ptf_supervisor_state = 'STOPPED'

    class InspectHost(RecordingHost):
        def command(self, argv, module_ignore_errors=False, **kwargs):
            if tuple(argv)[:4] == ('docker', 'container', 'inspect', 'saiserverv2'):
                self.events.append((self.role, 'command', tuple(argv)))
                return _result(0, payload)
            return super().command(argv, module_ignore_errors=module_ignore_errors, **kwargs)

    with pytest.raises(profile.SonicSonicProfileError, match='DUT.*container'):
        profile.verify(InspectHost('dut', events), ptf, runtime)


@pytest.mark.parametrize('result', [
    {},
    {'skipped': True, 'dest': '/tmp/expected'},
    {'unreachable': True, 'dest': '/tmp/expected'},
    {'failed': True, 'dest': '/tmp/expected'},
    {'changed': True},
    {'changed': True, 'dest': '/tmp/other'},
])
def test_copy_fails_closed_without_matching_destination_evidence(result):
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')

    class CopyHost:
        hostname = 'sonic-ptf'

        def copy(self, **kwargs):
            return result

    with pytest.raises(profile.SonicSonicProfileError, match='PTF stage.*host sonic-ptf'):
        profile._copy(
            CopyHost(), 'PTF', 'stage asset', '/source', '/tmp/expected', '0644')


@pytest.mark.parametrize('result', [
    {},
    {'failed': False},
    {'state': None},
    {'state': 'stopped'},
    {'state': 'started', 'skipped': True},
    {'state': 'started', 'unreachable': True},
    {'state': 'started', 'failed': True},
])
def test_rpc_check_fails_closed_without_explicit_started_result(runtime, result):
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')

    class RpcHost:
        hostname = 'sonic-ptf'

        def wait_for(self, **kwargs):
            return result

    with pytest.raises(profile.SonicSonicProfileError, match='PTF RPC.*host sonic-ptf'):
        profile._rpc_reachable(RpcHost(), runtime)


def test_role_operation_error_includes_safe_hostname():
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')

    class FailingHost:
        hostname = 'sonic-dut'

        def command(self, **kwargs):
            return {}

    with pytest.raises(profile.SonicSonicProfileError, match='DUT inspect.*host sonic-dut'):
        profile._command(FailingHost(), 'DUT', 'inspect state', ['false'])


def test_role_operation_error_ignores_unsafe_or_unreadable_hostname():
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')

    class UnsafeHost:
        hostname = 'root:credential@sonic-dut'

        def command(self, **kwargs):
            return {}

    class UnreadableHost:
        @property
        def hostname(self):
            raise RuntimeError('hostname lookup failed')

        def command(self, **kwargs):
            return {}

    with pytest.raises(profile.SonicSonicProfileError) as unsafe:
        profile._command(UnsafeHost(), 'DUT', 'inspect state', ['false'])
    with pytest.raises(profile.SonicSonicProfileError) as unreadable:
        profile._command(UnreadableHost(), 'DUT', 'inspect state', ['false'])

    assert 'credential' not in str(unsafe.value)
    assert 'host ' not in str(unsafe.value)
    assert str(unreadable.value).startswith('DUT inspect state')


def test_process_validation_error_includes_safe_hostname():
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')

    class InvalidProcessHost:
        hostname = 'sonic-ptf'

        def command(self, **kwargs):
            return _result(0, 'not-a-pid\n')

    with pytest.raises(profile.SonicSonicProfileError, match='PTF.*host sonic-ptf'):
        profile._process_ids(InvalidProcessHost(), 'PTF', 'saiserver')


def test_profile_never_uses_forbidden_device_operations(runtime):
    profile = importlib.import_module('tests.ranking.environments.sonic_sonic.prepare')
    events = []
    ptf = RecordingHost('ptf', events)
    dut = RecordingHost('dut', events)

    profile.prepare_ptf(ptf, runtime)
    profile.prepare_dut(dut, runtime)
    commands = [event[2] for event in events if event[1] == 'command']

    forbidden = ('reboot', 'shutdown', 'containerd', 'restore')
    assert not any(any(token in argument.lower() for token in forbidden for argument in argv)
                   for argv in commands)
    assert not any(argv[:2] in (('service', 'syncd'), ('systemctl', 'syncd'))
                   for argv in commands)
    assert not any(argv[:2] in (('docker', 'restart'), ('docker', 'stop'), ('docker', 'rm'))
                   for argv in commands)


def _controller_adapter(tmp_path):
    from tests.ranking.common.sonic_mgmt_adapter import create_controller_adapter
    from tests.ranking.environments.sonic_sonic.environment import (
        controller_spec, load_environment,
    )

    return create_controller_adapter(
        controller_spec(load_environment(EXAMPLE / 'environment.yml')),
        temp_parent=tmp_path)


def test_environment_generates_standard_sonic_and_ptf_inventory(tmp_path):
    adapter = _controller_adapter(tmp_path)
    try:
        inventory = yaml.safe_load(adapter.inventory.read_text(encoding='utf-8'))
        groups = inventory['all']['children']

        assert list(groups['sonic']['hosts']) == ['sonic-dut']
        assert list(groups['ptf']['hosts']) == ['sonic-ptf']
        assert 'hosts' not in inventory['all']
        for group in ('sonic', 'ptf'):
            for variables in groups[group]['hosts'].values():
                assert set(variables) == {
                    'ansible_host', 'ansible_user', 'ansible_connection'}
                assert variables['ansible_connection'] == 'ssh'
    finally:
        adapter.cleanup()


def test_generated_adapter_is_parsed_by_real_standard_testbed_info(monkeypatch, tmp_path):
    monkeypatch.setitem(
        sys.modules, 'ipaddr', SimpleNamespace(IPNetwork=ipaddress.ip_interface))
    source = EXAMPLE.parents[2] / 'common' / 'testbed.py'
    specification = importlib.util.spec_from_file_location('ranking_testbed_parser', source)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)

    adapter = _controller_adapter(tmp_path)
    try:
        parsed = module.TestbedInfo(str(adapter.testbed_file)).testbed_topo
        record = parsed['ranking']

        assert record['topo']['name'] == 'ptf32'
        assert record['duts'] == ['sonic-dut']
        assert record['ptf'] == 'sonic-ptf'
        assert record['inv_name'] == str(adapter.inventory)
    finally:
        adapter.cleanup()


def test_testbed_parser_preserves_external_topology_precedence(monkeypatch, tmp_path):
    monkeypatch.setitem(
        sys.modules, 'ipaddr', SimpleNamespace(IPNetwork=ipaddress.ip_interface))
    source = EXAMPLE.parents[2] / 'common' / 'testbed.py'
    specification = importlib.util.spec_from_file_location('ranking_external_testbed_parser', source)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    adapter = _controller_adapter(tmp_path)
    try:
        local_topology = adapter.testbed_file.parent / 'vars' / 'topo_ptf32.yml'
        local_topology.write_text(
            'topology:\n  host_interfaces: [7]\n', encoding='utf-8')
        record = module.TestbedInfo(str(adapter.testbed_file)).testbed_topo['ranking']

        assert dict(record['topo']['ptf_map']) == {'0': {'7': 7}}
    finally:
        adapter.cleanup()


def test_standard_testbed_parser_does_not_fallback_to_checkout_for_external_input(
        monkeypatch, tmp_path):
    """A normal sonic-mgmt testbed must keep its existing relative-path contract."""
    monkeypatch.setitem(
        sys.modules, 'ipaddr', SimpleNamespace(IPNetwork=ipaddress.ip_interface))
    source = EXAMPLE.parents[2] / 'common' / 'testbed.py'
    specification = importlib.util.spec_from_file_location(
        'ranking_non_ranking_testbed_parser', source)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    external = tmp_path / 'external' / 'testbed.yaml'
    external.parent.mkdir()
    external.write_text(yaml.safe_dump([{
        'conf-name': 'ordinary',
        'group-name': 'ordinary',
        'topo': 'ptf32',
        'ptf_image_name': 'docker-ptf',
        'ptf': 'ptf-host',
        'ptf_ip': '192.0.2.2/32',
        'ptf_ipv6': None,
        'server': 'server_1',
        'vm_base': None,
        'dut': ['dut-host'],
        'inv_name': 'inventory.yml',
        'auto_recover': 'False',
        'comment': 'ordinary external testbed',
    }], sort_keys=False), encoding='utf-8')

    with pytest.raises(FileNotFoundError):
        module.TestbedInfo(str(external))


def test_standard_testbed_validator_accepts_generated_adapter(monkeypatch, tmp_path):
    repository = EXAMPLE.parents[3]
    source = repository / 'ansible' / 'verify_config.py'
    specification = importlib.util.spec_from_file_location(
        'ranking_verify_config', source)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    monkeypatch.chdir(repository / 'ansible')
    adapter = _controller_adapter(tmp_path)
    try:
        module.Config.TESTBED_FILE = str(adapter.testbed_file)

        validator = module.TestbedValidator()
        validator.validate()

        assert validator.assertion.pass_validation
    finally:
        adapter.cleanup()


def _is_mutation(argv):
    if argv[:1] in (('/usr/bin/saiserverv2.sh',), ('service',), ('python3',), ('rm',)):
        return True
    return (argv[:4] == ('docker', 'exec', 'saiserverv2', 'kill')
            or argv[:5] == (
                'docker', 'exec', 'saiserverv2', 'supervisorctl', 'stop'))
