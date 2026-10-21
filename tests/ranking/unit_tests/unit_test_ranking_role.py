import base64
import hashlib
import json
import re
from pathlib import Path

import pytest
import yaml

from tests.ranking.runtime_config import DEFAULT_SERVICES


ROOT = Path(__file__).resolve().parents[3]
ANSIBLE = ROOT / 'ansible'
ROLE = ANSIBLE / 'roles' / 'ranking'
TASKS = ROLE / 'tasks'
DEFAULTS = ROLE / 'defaults' / 'main.yml'
PLAYBOOK_FILES = [
    ANSIBLE / 'setup_ranking.yml',
    ANSIBLE / 'run_ranking.yml',
    ANSIBLE / 'teardown_ranking.yml',
]
TASK_FILES = [
    'main.yml', 'preflight.yml', 'ownership.yml', 'validate.yml', 'setup.yml',
    'bootstrap.yml', 'abort_setup.yml', 'begin_action.yml', 'begin_action_resource.yml',
    'end_action.yml', 'end_action_resource.yml', 'setup_vsonic.yml', 'prepare_ptf.yml', 'status.yml',
    'prepare_case.yml', 'run.yml', 'collect.yml', 'stop_service.yml',
    'rollback_marker.yml', 'teardown.yml', 'teardown_service.yml',
]
MODULES = (
    'ansible.builtin.command', 'ansible.builtin.copy', 'ansible.builtin.slurp',
    'ansible.builtin.set_fact', 'ansible.builtin.fail', 'ansible.builtin.service_facts',
    'ansible.builtin.stat', 'ansible.builtin.fetch', 'ansible.builtin.file',
    'ansible.builtin.wait_for',
)
VENDORS = ('broadcom', 'cisco', 'nvidia', 'mellanox', 'marvell')


def test_validation_outside_run_always_block():
    tasks = yaml.safe_load((TASKS / 'run.yml').read_text())
    assert tasks[0]['ansible.builtin.include_tasks'] == 'validate.yml'
    authorized = tasks[1]
    assert authorized['when'] == 'ranking_ownership_acquired | bool'
    assert authorized['block'][0]['ansible.builtin.include_tasks'] == 'prepare_case.yml'
    assert 'ansible.builtin.command' in authorized['block'][1]
    collect = authorized['always'][0]
    assert collect['ansible.builtin.include_tasks'] == 'collect.yml'
    assert collect['when'] == 'ranking_ownership_acquired | bool'


def test_role_does_not_create_switch_or_reboot():
    texts = [path.read_text() for path in TASKS.glob('*.yml')]
    assert texts
    for text in texts:
        assert 'create_switch' not in text
        assert 'ansible.builtin.reboot' not in text
        assert 'config reload' not in text


def test_root_playbooks_have_the_required_single_play():
    for playbook in PLAYBOOK_FILES:
        plays = yaml.safe_load(playbook.read_text())
        assert isinstance(plays, list) and len(plays) == 1
        play = plays[0]
        assert play['hosts'] == '{{ ranking_dut_host }}'
        assert play['gather_facts'] is False
        assert play['become'] is True
        assert play['roles'] == ['ranking']
        assert set(play) == {'hosts', 'gather_facts', 'become', 'roles'}


def test_role_task_files_parse_into_task_lists():
    for name in TASK_FILES:
        tasks = yaml.safe_load((TASKS / name).read_text())
        assert isinstance(tasks, list) and tasks
        for task in tasks:
            assert isinstance(task, dict)
            assert any(key in task for key in MODULES + (
                'ansible.builtin.include_tasks', 'block'))


def test_defaults_are_neutral_and_fix_the_ownership_root():
    defaults = yaml.safe_load(DEFAULTS.read_text())
    assert isinstance(defaults, dict)
    assert defaults['ranking_ownership_root'] == '/var/tmp/ranking-ownership'
    assert defaults['ranking_state_root'] == '/var/tmp/ranking-state'
    assert defaults['ranking_ownership_acquired'] is False
    assert set(defaults) == {
        'ranking_ownership_root', 'ranking_state_root', 'ranking_request_base',
        'ranking_ownership_acquired',
    }


def test_role_yaml_contains_no_private_addresses_or_vendor_profiles():
    texts = [(path.name, path.read_text())
             for path in list(TASKS.glob('*.yml')) + [DEFAULTS] + PLAYBOOK_FILES]
    assert len(texts) == len(TASK_FILES) + 1 + len(PLAYBOOK_FILES)
    ipv4 = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')
    hex64 = re.compile(r'\b[0-9a-f]{64}\b')
    for name, text in texts:
        assert ipv4.search(text) is None, name
        assert hex64.search(text) is None, name
        lowered = text.lower()
        for vendor in VENDORS:
            assert vendor not in lowered, (name, vendor)


def _load_tasks(name):
    tasks = yaml.safe_load((TASKS / name).read_text())
    assert isinstance(tasks, list)
    return tasks


def _walk(tasks):
    for task in tasks:
        if 'block' in task:
            for section in ('block', 'rescue', 'always'):
                for child in task.get(section) or []:
                    yield from _walk([child])
        else:
            yield task


def _command_argv(task):
    module = task.get('ansible.builtin.command')
    if isinstance(module, dict) and isinstance(module.get('argv'), list):
        return [str(argument) for argument in module['argv']]
    return None


def _is_agent_invocation(task):
    argv = _command_argv(task)
    return bool(argv) and any(str(token).endswith('remote_agent.py') or token == 'ranking.remote_agent'
                              for token in argv)


def _agent_request_name(task):
    argv = _command_argv(task)
    position = argv.index('--request')
    return str(argv[position + 1]).rsplit('/', 1)[-1]


def _is_agent_mark(task):
    if not _is_agent_invocation(task):
        return False
    return _agent_request_name(task).startswith('mark-')


def _is_service_stop(task):
    argv = _command_argv(task)
    return bool(argv) and argv[0].rsplit('/', 1)[-1] == 'systemctl' and \
        len(argv) > 1 and argv[1] == 'stop'


def _is_docker_image_inspect(task):
    argv = _command_argv(task)
    return bool(argv) and argv[0].rsplit('/', 1)[-1] == 'docker' and \
        argv[1:3] == ['image', 'inspect']


def _is_mutating(task):
    if _is_agent_invocation(task):
        return False
    module = task.get('ansible.builtin.command')
    if isinstance(module, dict):
        argv_value = module.get('argv')
        if isinstance(argv_value, str):
            return any(name in argv_value for name in (
                'start_argv', 'stop_argv', 'stop_tokens'))
        argv = _command_argv(task)
        if argv:
            first = argv[0].rsplit('/', 1)[-1]
            if first == 'systemctl' and len(argv) > 1 and argv[1] in ('stop', 'start'):
                return True
            if first == 'docker' and len(argv) > 1:
                if argv[1] in ('stop', 'start', 'run', 'rm'):
                    return True
                if argv[1] == 'cp' and len(argv) > 3 and ':' in argv[-1]:
                    return True
            if first == 'rm':
                return True
    file_module = task.get('ansible.builtin.file')
    if isinstance(file_module, dict) and file_module.get('state') in (
            'directory', 'absent', 'touch', 'link', 'hard'):
        return True
    copy_module = task.get('ansible.builtin.copy')
    if isinstance(copy_module, dict):
        destination = str(copy_module.get('dest', ''))
        if destination and 'ranking_request_root' not in destination:
            return True
    return False


def test_every_mutating_task_is_preceded_by_a_marker_attempt():
    for name in TASK_FILES:
        if name == 'bootstrap.yml':
            continue
        marker_seen = False
        for task in _walk(_load_tasks(name)):
            if _is_agent_mark(task):
                marker_seen = True
            elif _is_mutating(task):
                assert marker_seen, (name, task.get('name'))


def test_agent_request_files_are_staged_with_mode_0600():
    for name in TASK_FILES:
        staged = set()
        for task in _walk(_load_tasks(name)):
            copy_module = task.get('ansible.builtin.copy')
            if isinstance(copy_module, dict) and 'content' in copy_module:
                destination = str(copy_module.get('dest', ''))
                assert copy_module.get('mode') == '0600', (name, task.get('name'))
                assert ('ranking_request_root' in destination or
                        ('ranking_runtime.ptf_root' in destination and
                         '/requests/' in destination) or 'ranking_collect_run_dir' in destination), (name, destination)
                staged.add(destination)
            elif _is_agent_invocation(task):
                argv = _command_argv(task)
                request = str(argv[argv.index('--request') + 1])
                assert request in staged, (name, request)


def test_prepare_case_resets_the_current_container_instead_of_refusing():
    walk = list(_walk(_load_tasks('prepare_case.yml')))
    messages = [str(task['ansible.builtin.fail']['msg']) for task in walk
                if 'ansible.builtin.fail' in task]
    assert not [message for message in messages
                if 'current saiserver container is still running' in message]
    request_names = [_agent_request_name(task) for task in walk
                     if _is_agent_invocation(task)]
    assert 'read-environment.json' in request_names
    assert 'write-environment-case-container.json' in request_names
    assert 'mark-case-start-saiserver.json' in request_names


def test_prepare_case_stages_the_run_request_exclusively():
    walk = list(_walk(_load_tasks('prepare_case.yml')))
    copies = [task['ansible.builtin.copy'] for task in walk
              if isinstance(task.get('ansible.builtin.copy'), dict)]
    staged = [module for module in copies
              if 'content' in module and 'ranking_bound_ptf_request' in
              str(module.get('content'))]
    assert len(staged) == 1
    assert str(staged[0]['dest']) == ('{{ ranking_runtime.ptf_root }}/'
                                      '{{ ranking_environment_id }}/requests/'
                                      '{{ ranking_run_id }}.json')
    assert staged[0]['mode'] == '0600'
    stats = [task['ansible.builtin.stat'] for task in walk
             if isinstance(task.get('ansible.builtin.stat'), dict)]
    assert any(str(module['path']).endswith(
        '/requests/{{ ranking_run_id }}.json') for module in stats)
    refusals = [task for task in walk if 'ansible.builtin.fail' in task and
                'request already exists' in
                str(task['ansible.builtin.fail']['msg'])]
    assert len(refusals) == 1
    assert 'ranking_case_request_existing.stat.exists | default(false)' in \
        str(refusals[0].get('when'))
    facts = [task['ansible.builtin.set_fact'] for task in walk
             if isinstance(task.get('ansible.builtin.set_fact'), dict)]
    assert any('ranking_ptf_runner_path' in module and
               'ranking_run_request_path' in module for module in facts)


def test_prepare_ptf_stages_the_runner_from_the_package_dir():
    walk = list(_walk(_load_tasks('prepare_ptf.yml')))
    copies = [task['ansible.builtin.copy'] for task in walk
              if isinstance(task.get('ansible.builtin.copy'), dict)]
    runner = [module for module in copies
              if 'src' in module and str(module['dest']).endswith('ptf_runner.py')]
    assert len(runner) == 1
    assert str(runner[0]['src']) == '{{ ranking_runner_path }}'
    assert str(runner[0]['dest']) == ('{{ ranking_runtime.ptf_root }}/'
                                      '{{ ranking_environment_id }}/runner/'
                                      'ptf_runner.py')
    assert runner[0]['mode'] == '0600'
    runner_tasks = [task for task in walk
                    if isinstance(task.get('ansible.builtin.copy'), dict) and
                    str(task['ansible.builtin.copy'].get('dest', '')).endswith(
                        'ptf_runner.py')]
    assert runner_tasks[0].get('delegate_to') == '{{ ranking_ptf_host }}'
    facts = [task['ansible.builtin.set_fact'] for task in walk
             if isinstance(task.get('ansible.builtin.set_fact'), dict)]
    assert any('ranking_staging_binding' in module for module in facts)


def test_collect_uses_the_env_run_layout_and_preserves_primary_error():
    walk = list(_walk(_load_tasks('collect.yml')))
    fetches = [task['ansible.builtin.fetch'] for task in walk
               if isinstance(task.get('ansible.builtin.fetch'), dict)]
    artifact_fetches = [module for module in fetches
                        if 'ranking_collect_run_dir' in str(module['src'])]
    assert len(artifact_fetches) == 2
    assert str(artifact_fetches[0]['dest']).startswith(
        '{{ ranking_artifacts_dir }}/{{ ranking_environment_id }}/'
        '{{ ranking_run_id }}/')
    stats = [task['ansible.builtin.stat'] for task in walk
             if isinstance(task.get('ansible.builtin.stat'), dict)]
    assert stats and all(('{{ ranking_environment_id }}/{{ ranking_run_id }}' in str(
        module['path']) or 'ranking_collect_run_dir' in str(module['path'])) for module in stats)
    outcomes = [task['ansible.builtin.set_fact']['ranking_role_outcome']
                for task in walk
                if isinstance(task.get('ansible.builtin.set_fact'), dict) and
                'ranking_role_outcome' in task['ansible.builtin.set_fact']]
    assert len(outcomes) == 1
    assert set(outcomes[0]) == {'schema_version', 'environment_id', 'run_id',
                                'case', 'collected', 'collection_errors',
                                'case_rc', 'case_error'}
    assert 'ranking_case_run.rc | default(-1)' in str(outcomes[0]['case_rc'])
    assert 'ranking_case_run.stderr' in str(outcomes[0]['case_error'])
    final = next(task for task in walk if task.get('name') == 'Record the final ranking run state')
    assert final['when'] == 'ranking_collect_authorized | bool'


def test_main_dispatches_actions_in_the_approved_order():
    tasks = list(_walk(_load_tasks('main.yml')))
    includes = [task['ansible.builtin.include_tasks'] for task in tasks
                if 'ansible.builtin.include_tasks' in task]
    assert includes == [
        'bootstrap.yml', 'preflight.yml', 'ownership.yml', 'validate.yml', 'begin_action.yml',
        'setup.yml', 'prepare_ptf.yml', 'status.yml', 'run.yml', 'teardown.yml', 'end_action.yml',
    ]
    for task in tasks:
        if ('ansible.builtin.include_tasks' in task and
                task['ansible.builtin.include_tasks'] not in ('bootstrap.yml', 'begin_action.yml')):
            assert 'when' in task
    action_block = next(task for task in _load_tasks('main.yml') if 'block' in task)
    assert action_block['block'][0]['ansible.builtin.include_tasks'] == 'begin_action.yml'
    assert action_block['always'][0]['ansible.builtin.include_tasks'] == 'end_action.yml'


def test_validation_and_snapshot_precede_every_mutating_include():
    includes = [task['ansible.builtin.include_tasks'] for task in _walk(_load_tasks('main.yml'))
                if 'ansible.builtin.include_tasks' in task]
    assert includes.index('validate.yml') < includes.index('setup.yml')
    assert includes.index('validate.yml') < includes.index('prepare_ptf.yml')
    assert includes.index('ownership.yml') < includes.index('setup.yml')
    assert includes.index('validate.yml') < includes.index('begin_action.yml') < includes.index('setup.yml')
    setup = list(_walk(_load_tasks('setup.yml')))
    snapshot_positions = [index for index, task in enumerate(setup)
                          if _is_agent_invocation(task) and
                          _agent_request_name(task).startswith('snapshot-')]
    mutation_positions = [index for index, task in enumerate(setup) if _is_mutating(task)]
    assert snapshot_positions and mutation_positions
    assert min(snapshot_positions) < min(mutation_positions)


def test_preflight_inspects_the_saiserver_image_before_any_service_stop():
    includes = [task['ansible.builtin.include_tasks'] for task in _walk(_load_tasks('main.yml'))
                if 'ansible.builtin.include_tasks' in task]
    assert includes.index('preflight.yml') < includes.index('setup.yml')
    preflight = list(_walk(_load_tasks('preflight.yml')))
    inspects = [task for task in preflight if _is_docker_image_inspect(task)]
    assert len(inspects) == 1
    assert not [task for task in preflight if _is_service_stop(task)]
    assert not [task for task in preflight if _is_mutating(task)]


def test_service_stop_loop_uses_the_runtime_services_variable():
    setup = list(_walk(_load_tasks('setup.yml')))
    stop_includes = [task for task in setup
                     if task.get('ansible.builtin.include_tasks') == 'stop_service.yml']
    assert len(stop_includes) == 1
    assert 'ranking_original_services' in stop_includes[0]['loop']
    assert 'selectattr("value", "equalto", "active")' in stop_includes[0]['loop']
    for name in TASK_FILES:
        for task in _walk(_load_tasks(name)):
            loop = task.get('loop')
            if isinstance(loop, list):
                assert not [item for item in loop if str(item) in DEFAULT_SERVICES], (
                    name, task.get('name'))


def test_ptf_side_tasks_delegate_to_the_ptf_host():
    for name in TASK_FILES:
        for task in _walk(_load_tasks(name)):
            delegate = task.get('delegate_to')
            if delegate is not None:
                assert delegate in ('{{ ranking_ptf_host }}', 'localhost', '{{ item }}', '{{ item.host }}'), (
                    name, task.get('name'))
    for task in _walk(_load_tasks('prepare_ptf.yml')):
        if any(key in task for key in (
                'ansible.builtin.copy', 'ansible.builtin.command',
                'ansible.builtin.file', 'ansible.builtin.fetch')):
            assert task.get('delegate_to') == '{{ ranking_ptf_host }}', task.get('name')
    run_tasks = _load_tasks('run.yml')
    runner = run_tasks[1]['block'][1]
    assert runner['delegate_to'] == '{{ ranking_ptf_host }}'


def test_teardown_dispatch_replaces_the_explicit_fail_gate():
    tasks = list(_walk(_load_tasks('main.yml')))
    assert not [task for task in tasks if 'ansible.builtin.fail' in task]
    teardown = [task for task in tasks
                if task.get('ansible.builtin.include_tasks') == 'teardown.yml']
    assert len(teardown) == 1
    when = teardown[0]['when']
    assert "ranking_action | default('') == 'teardown'" in when
    assert "ranking_action | default('') == 'keep'" in when
    validate = [task for task in tasks
                if task.get('ansible.builtin.include_tasks') == 'validate.yml'][0]
    assert "ranking_action | default('') == 'setup'" in validate['when']
    assert "ranking_action | default('') == 'status'" in validate['when']
    assert "ranking_action | default('') == 'teardown'" in validate['when']
    assert "ranking_action | default('') == 'keep'" in validate['when']
    preflight = [task for task in tasks
                 if task.get('ansible.builtin.include_tasks') == 'preflight.yml'][0]
    ownership = [task for task in tasks
                 if task.get('ansible.builtin.include_tasks') == 'ownership.yml'][0]
    for gate in (preflight, ownership):
        assert "teardown'" not in gate['when']
        assert "keep'" not in gate['when']


def test_teardown_writes_role_outcomes_for_every_action():
    expectations = {
        'teardown.yml': {'schema_version', 'environment_id', 'action', 'restored',
                         'released', 'kept', 'uncertain'},
        'setup.yml': {'schema_version', 'environment_id', 'action', 'restored',
                      'released', 'kept', 'uncertain', 'rollback_attempted',
                      'ownership_state', 'resources'},
        'status.yml': {'schema_version', 'environment_id', 'action', 'restored',
                       'released', 'kept', 'uncertain'},
    }
    for name, fields in expectations.items():
        walk = list(_walk(_load_tasks(name)))
        outcomes = [task['ansible.builtin.set_fact']['ranking_role_outcome']
                    for task in walk
                    if isinstance(task.get('ansible.builtin.set_fact'), dict) and
                    'ranking_role_outcome' in task['ansible.builtin.set_fact']]
        assert len(outcomes) == 1, name
        assert set(outcomes[0]) == fields, name
        assert '{{ ranking_environment_id }}' in str(outcomes[0]['environment_id'])
        staged = [task for task in walk
                  if isinstance(task.get('ansible.builtin.copy'), dict) and
                  str(task['ansible.builtin.copy'].get('dest', '')).endswith(
                      '/role-outcome.json')]
        assert staged and staged[0]['ansible.builtin.copy']['mode'] == '0600', name
        fetched = [task for task in walk
                   if isinstance(task.get('ansible.builtin.fetch'), dict) and
                   str(task['ansible.builtin.fetch'].get('src', '')).endswith(
                       '/role-outcome.json')]
        assert fetched, name
    teardown_outcome = [
        task['ansible.builtin.set_fact']['ranking_role_outcome']
        for task in _walk(_load_tasks('teardown.yml'))
        if isinstance(task.get('ansible.builtin.set_fact'), dict) and
        'ranking_role_outcome' in task['ansible.builtin.set_fact']][0]
    assert str(teardown_outcome['action']) == "{{ ranking_action }}"
    assert "ranking_teardown_restored | default(false)" in \
        str(teardown_outcome['restored'])
    assert "ranking_teardown_released | default([])" in \
        str(teardown_outcome['released'])
    assert "ranking_teardown_kept | default(false)" in str(teardown_outcome['kept'])
    assert "ranking_teardown_uncertain | default(true)" in \
        str(teardown_outcome['uncertain'])


def test_teardown_outcome_is_written_from_an_always_section():
    outer = [task for task in _load_tasks('teardown.yml') if 'block' in task]
    assert len(outer) == 1
    assert outer[0].get('when') is None
    assert outer[0].get('rescue') is None
    assert outer[0]['always'], 'the role outcome must survive any teardown failure'
    sections = [task for task in outer[0]['block'] if 'block' in task]
    assert [section.get('when') for section in sections] == [
        "ranking_action == 'keep'", "ranking_action == 'teardown' and not ranking_teardown_unmodified | bool"]
    setup_outer = [task for task in _load_tasks('setup.yml') if 'block' in task]
    assert len(setup_outer) == 1
    assert setup_outer[0]['always']


def test_teardown_gates_on_the_previous_run_state_before_any_restore():
    walk = list(_walk(_load_tasks('teardown.yml')))
    messages = [str(task['ansible.builtin.fail']['msg']) for task in walk
                if 'ansible.builtin.fail' in task]
    assert 'previous ranking run has not exited' in messages
    assert 'previous ranking run has not been collected' in messages
    read_run_state = [task for task in walk if _is_agent_invocation(task) and
                      _agent_request_name(task) == 'read-teardown-run-state.json']
    assert len(read_run_state) == 1
    assert read_run_state[0].get('failed_when') == 'ranking_teardown_run_state_read.rc != 0'
    mutating = [task for task in walk if _is_mutating(task)]
    first_mutating = walk.index(mutating[0])
    gates = [task for task in walk if 'ansible.builtin.fail' in task and
             'previous ranking run' in str(task['ansible.builtin.fail']['msg'])]
    assert max(walk.index(gate) for gate in gates) < first_mutating


def test_teardown_container_removal_matches_the_persisted_environment():
    walk = list(_walk(_load_tasks('teardown.yml')))
    removes = [task for task in walk if _is_mutating(task) and
               _command_argv(task) and _command_argv(task)[0] == 'docker' and
               _command_argv(task)[1] == 'rm']
    assert len(removes) == 1
    assert _command_argv(removes[0]) == [
        'docker', 'rm',
        '{{ ranking_teardown_environment.current_saiserver_container_id }}']
    messages = [str(task['ansible.builtin.fail']['msg']) for task in walk
                if 'ansible.builtin.fail' in task]
    assert 'ranking saiserver container record is missing' in messages
    assert 'ranking saiserver container does not match the persisted environment' \
        in messages
    assert 'ranking saiserver container name does not match the persisted ' \
        'environment' in messages
    assert 'ranking saiserver container image does not match the persisted ' \
        'environment' in messages
    facts = [task['ansible.builtin.set_fact'] for task in walk
             if isinstance(task.get('ansible.builtin.set_fact'), dict)]
    attested = [module for module in facts
                if 'ranking_teardown_container_attested' in module]
    assert len(attested) == 1
    assert 'current_saiserver_container_id | default("", true) != ""' in \
        str(attested[0]['ranking_teardown_container_attested'])


def test_teardown_clears_the_removed_container_record_for_retries():
    walk = list(_walk(_load_tasks('teardown.yml')))
    removes = [task for task in walk if _is_mutating(task) and
               _command_argv(task) and _command_argv(task)[:2] == ['docker', 'rm']]
    assert len(removes) == 1
    requests = [
        task['ansible.builtin.set_fact']['ranking_teardown_environment_clear_request']
        for task in walk
        if isinstance(task.get('ansible.builtin.set_fact'), dict) and
        'ranking_teardown_environment_clear_request' in
        task['ansible.builtin.set_fact']]
    assert len(requests) == 1
    assert requests[0]['action'] == 'write'
    assert requests[0]['name'] == 'environment.json'
    assert 'combine({"current_saiserver_container_id": none})' in \
        str(requests[0]['value'])
    writes = [task for task in walk if _is_agent_invocation(task) and
              _agent_request_name(task) == 'write-teardown-environment-clear.json']
    assert len(writes) == 1
    assert str(writes[0].get('when')) == 'ranking_teardown_container_attested | bool'
    completions = [task for task in walk if _is_agent_invocation(task) and
                   _agent_request_name(task) ==
                   'complete-teardown-start-saiserver.json']
    assert len(completions) == 1
    assert walk.index(removes[0]) < walk.index(writes[0]) < \
        walk.index(completions[0])


def test_teardown_restores_only_snapshot_declared_state():
    walk = list(_walk(_load_tasks('teardown.yml')))
    restores = [task for task in walk if _is_agent_invocation(task) and
                _agent_request_name(task) == 'write-restore-files.json']
    assert len(restores) == 1
    requests = [task['ansible.builtin.set_fact']['ranking_teardown_restore_request']
                for task in walk
                if isinstance(task.get('ansible.builtin.set_fact'), dict) and
                'ranking_teardown_restore_request' in
                task['ansible.builtin.set_fact']]
    assert len(requests) == 1
    assert requests[0]['action'] == 'restore_files'
    assert str(requests[0]['originals']) == '{{ ranking_teardown_snapshot.files }}'
    removals = [task['ansible.builtin.file'] for task in walk
                if isinstance(task.get('ansible.builtin.file'), dict) and
                task['ansible.builtin.file'].get('state') == 'absent']
    assert {module['path'] for module in removals} == {'{{ ranking_teardown_ptf_snapshot.staging_path }}',
                                                       '{{ ranking_teardown_ptf_snapshot.staging_path }}/secrets'}
    facts = [task['ansible.builtin.set_fact'] for task in walk
             if isinstance(task.get('ansible.builtin.set_fact'), dict)]
    order = [module for module in facts
             if 'ranking_teardown_service_order' in module]
    assert len(order) == 1
    assert 'ranking_runtime.service_start_order' in str(order[0]['ranking_teardown_service_order'])
    service_includes = [task for task in walk
                        if task.get('ansible.builtin.include_tasks') ==
                        'teardown_service.yml']
    assert len(service_includes) == 1
    assert service_includes[0]['loop'] == '{{ ranking_teardown_service_order }}'
    markers = [str(task['ansible.builtin.set_fact'])
               for task in walk
               if isinstance(task.get('ansible.builtin.set_fact'), dict) and
               'marker' in str(task['ansible.builtin.set_fact'])]
    assert any("'restore:{{ item }}'" in marker for marker in markers)
    assert any("'start:saiserver'" in marker for marker in markers)
    keep_requests = [str(task['ansible.builtin.set_fact'])
                     for task in _walk(_load_tasks('teardown.yml'))
                     if isinstance(task.get('ansible.builtin.set_fact'), dict)]
    assert any("'action': 'keep'" in request for request in keep_requests)
    assert any("'action': 'release'" in request for request in keep_requests)
    releases = [task for task in walk if _is_agent_invocation(task) and
                _agent_request_name(task) in ('release-dut.json', 'release-ptf.json')]
    assert len(releases) == 2
    ptf_release = releases[1]
    assert ptf_release.get('delegate_to') == '{{ ranking_ptf_host }}'
    release_positions = [walk.index(task) for task in releases]
    service_verify = [task for task in walk
                      if task.get('name') == 'Require each original service state to be restored']
    assert len(service_verify) == 1
    assert release_positions[0] > walk.index(service_verify[0])


def test_teardown_service_file_marks_each_reversal():
    walk = list(_walk(_load_tasks('teardown_service.yml')))
    active_gate = "ranking_teardown_snapshot.services[item] == 'active'"
    starts = [task for task in walk if _is_service_stop(task) or
              (_command_argv(task) and _command_argv(task)[0] == 'systemctl' and
               _command_argv(task)[1] == 'start')]
    assert len(starts) == 1
    assert starts[0].get('when') == active_gate
    requests = [task['ansible.builtin.set_fact'] for task in walk
                if isinstance(task.get('ansible.builtin.set_fact'), dict)]
    marks = [module for module in requests if
             'ranking_teardown_service_mark_request' in module]
    completions = [module for module in requests if
                   'ranking_teardown_service_complete_request' in module]
    assert len(marks) == 1 and len(completions) == 1
    assert marks[0]['ranking_teardown_service_mark_request']['marker'] == \
        'stop:{{ item }}'
    assert completions[0]['ranking_teardown_service_complete_request']['marker'] == \
        'stop:{{ item }}'
    for task in walk:
        if _is_agent_invocation(task):
            name = _agent_request_name(task)
            assert name.startswith(('mark-teardown-restart-',
                                    'complete-teardown-restart-'))
            assert task.get('when') == active_gate


def test_status_verifies_the_original_snapshot_and_current_inputs():
    walk = list(_walk(_load_tasks('status.yml')))
    messages = [str(task['ansible.builtin.fail']['msg']) for task in walk
                if 'ansible.builtin.fail' in task]
    for message in ('current DUT image does not match the original snapshot',
                    'local saiserver image does not match the persisted environment',
                    'ranking environment profile does not match the requested inputs',
                    'ranking environment mapping does not match the requested inputs',
                    'ranking environment source does not match the requested inputs'):
        assert message in messages
    snapshot_reads = [task for task in walk if _is_agent_invocation(task) and
                      _agent_request_name(task) == 'read-status-snapshot.json']
    assert len(snapshot_reads) == 1
    facts = [task['ansible.builtin.set_fact'] for task in walk
             if isinstance(task.get('ansible.builtin.set_fact'), dict)]
    assert any('ranking_status_snapshot' in str(module) for module in facts)
    assert not any('to_json' in str(module) for module in facts)
    identity_gates = [task for task in walk if 'ansible.builtin.fail' in task and
                      'original snapshot' in str(task['ansible.builtin.fail']['msg'])]
    assert 'ranking_status_snapshot.identity.image_id' in \
        str(identity_gates[0]['when'])


class TaskFailure(Exception):
    def __init__(self, message, task=None):
        super().__init__(message)
        self.message = message
        self.task = task


def _split_top(expr, separator):
    parts, depth, quote, start, index = [], 0, None, 0, 0
    while index < len(expr):
        char = expr[index]
        if quote:
            if char == quote:
                quote = None
        elif char in '\'"':
            quote = char
        elif char in '([{':
            depth += 1
        elif char in ')]}':
            depth -= 1
        elif depth == 0 and expr.startswith(separator, index):
            parts.append(expr[start:index])
            index += len(separator)
            start = index
            continue
        index += 1
    parts.append(expr[start:])
    return [part.strip() for part in parts]


def _find_top(expr, tokens):
    depth, quote, index = 0, None, 0
    while index < len(expr):
        char = expr[index]
        if quote:
            if char == quote:
                quote = None
        elif char in '\'"':
            quote = char
        elif char in '([{':
            depth += 1
        elif char in ')]}':
            depth -= 1
        elif depth == 0:
            for token in tokens:
                if expr.startswith(token, index):
                    return index
        index += 1
    return -1


_PATH_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\[([^\[\]]+)\]")


class ExpressionEvaluator:
    """Render production expressions with Jinja instead of a partial parser."""

    def __init__(self, variables):
        from jinja2 import ChainableUndefined, Environment
        import importlib.util
        from types import ModuleType
        from unittest.mock import patch
        errors = ModuleType('ansible.errors')
        errors.AnsibleFilterError = ValueError
        spec = importlib.util.spec_from_file_location(
            'ranking_filters', ROLE / 'filter_plugins' / 'ranking_filters.py')
        filters = importlib.util.module_from_spec(spec)
        with patch.dict('sys.modules', {'ansible.errors': errors}):
            spec.loader.exec_module(filters)
        self.variables = variables
        self.environment = Environment(undefined=ChainableUndefined)
        self.environment.globals['lookup'] = lambda plugin, path: Path(path).read_text()
        self.environment.filters.update({
            'bool': bool, 'to_json': json.dumps, 'from_json': json.loads,
            'b64decode': lambda value: base64.b64decode(value).decode('utf-8'),
            'hash': lambda value, algorithm: hashlib.new(algorithm, str(value).encode()).hexdigest(),
            'combine': lambda value, other: dict(value, **other),
            'difference': lambda value, other: [item for item in value if item not in other],
            'union': lambda value, other: list(dict.fromkeys(list(value) + list(other))),
            'dict2items': lambda value: [{'key': key, 'value': item} for key, item in value.items()],
            'regex_replace': lambda value, pattern, replacement: re.sub(pattern, replacement, value),
            'extract': lambda value, mapping: mapping[value],
        })
        self.environment.filters.update(filters.FilterModule().filters())
        self.environment.tests['match'] = lambda value, pattern: re.match(pattern, str(value)) is not None
        self.environment.tests['failed'] = lambda value: bool(value.get('failed', False))

    def render(self, value):
        if isinstance(value, str):
            full = re.fullmatch(r'\{\{\s*(.*?)\s*\}\}', value.strip(), re.DOTALL)
            if full and '{{' not in full.group(1):
                return self.evaluate(full.group(1))
            return self.environment.from_string(value).render(self.variables)
        if isinstance(value, list):
            return [self.render(item) for item in value]
        if isinstance(value, dict):
            return {self.render(key): self.render(item) for key, item in value.items()}
        return value

    def evaluate(self, expression):
        return self.environment.compile_expression(expression, undefined_to_none=False)(self.variables)


class RoleExecutor:
    """A test-only structural simulation of the role task flow."""

    def __init__(self, world, variables, fail_injector=None):
        self.world = world
        self.variables = dict(variables)
        self.fail_injector = fail_injector
        self.agent_calls = []
        world.docker_calls_baseline = len(world.docker.calls)

    def run_file(self, name):
        self.run_tasks(_load_tasks(name))

    def run_tasks(self, tasks):
        for task in tasks:
            self.run_task(task)

    def run_task(self, task):
        if 'ansible.builtin.include_tasks' in task:
            self._run_include(task)
        elif 'block' in task:
            self._run_block(task)
        else:
            loop_items = self._loop_items(task)
            if loop_items is None:
                if self._holds(task, task.get('when')):
                    self._execute(task)
                elif task.get('register'):
                    self.variables[task['register']] = {'skipped': True, 'changed': False}
            else:
                self._run_looped(task, loop_items)

    def _run_include(self, task):
        name = task['ansible.builtin.include_tasks']
        loop_items = self._loop_items(task)
        if loop_items is None:
            if self._holds(task, task.get('when')):
                self.run_file(name)
            return
        for item in loop_items:
            self.variables['item'] = item
            try:
                if self._holds(task, task.get('when')):
                    self.run_file(name)
            finally:
                self.variables.pop('item', None)

    def _run_block(self, task):
        if not self._holds(task, task.get('when')):
            return
        failure = None
        try:
            self.run_tasks(task.get('block') or [])
        except TaskFailure as error:
            rescue = task.get('rescue')
            if not rescue:
                failure = error
            else:
                try:
                    self.run_tasks(rescue)
                except TaskFailure as rescue_error:
                    failure = rescue_error
        finally:
            always = task.get('always')
            if always:
                self.run_tasks(always)
        if failure is not None:
            raise failure

    def _run_looped(self, task, items):
        register = task.get('register')
        results = []
        for item in items:
            self.variables['item'] = item
            try:
                if self._holds(task, task.get('when')):
                    results.append(dict(self._execute(task), item=item))
                else:
                    results.append({'skipped': True, 'item': item})
            finally:
                self.variables.pop('item', None)
        if register:
            self.variables[register] = {
                'results': results,
                'changed': any(result.get('changed') for result in results
                               if isinstance(result, dict)),
            }

    def _loop_items(self, task):
        loop = task.get('loop')
        if loop is None:
            return None
        if isinstance(loop, list):
            return self.evaluator().render(loop)
        value = self.evaluator().render(loop)
        if not isinstance(value, list):
            raise ValueError('loop must resolve to a list: ' + str(loop))
        return value

    def _holds(self, task, condition, overlay=None):
        if condition is None:
            return True
        if isinstance(condition, bool):
            return condition
        if isinstance(condition, list):
            return all(self._holds(task, item, overlay) for item in condition)
        return bool(self.evaluator(overlay).evaluate(condition))

    def evaluator(self, overlay=None):
        variables = dict(self.variables)
        if overlay:
            variables.update(overlay)
        return ExpressionEvaluator(variables)

    def _execute(self, task):
        evaluator = self.evaluator()
        module = next(key for key in MODULES if key in task)
        try:
            rendered = evaluator.render(task[module])
        except (ValueError, TypeError) as error:
            raise TaskFailure(str(error), task)
        params = rendered if isinstance(rendered, dict) else {'argv': rendered}
        delegate = task.get('delegate_to')
        host = delegate if delegate is not None else self.variables['ranking_dut_host']
        host = self.evaluator().render(host)
        register = task.get('register')
        caught = None
        if module == 'ansible.builtin.set_fact':
            result = {'changed': False, 'ansible_facts': params}
            self.variables.update(params)
        elif module == 'ansible.builtin.fail':
            raise TaskFailure(str(params.get('msg', 'task failed')), task)
        else:
            try:
                result = self._dispatch(host, module, params, task)
            except TaskFailure as error:
                caught = error
                result = {'rc': 1, 'stdout': '', 'stderr': error.message,
                          'msg': error.message, 'failed': True}
        if register:
            self.variables[register] = result
        overlay = {register: result} if register else {}
        failed_when = task.get('failed_when')
        if failed_when is not None:
            result['failed'] = self._holds(task, failed_when, overlay)
        elif module == 'ansible.builtin.command' and result.get('rc', 0) != 0:
            result['failed'] = True
        if task.get('until') and not self._holds(task, task['until'], overlay):
            result['failed'] = True
        if result.get('failed') and not task.get('ignore_errors'):
            raise caught or TaskFailure('task failed: ' + str(task.get('name')), task)
        return result

    def _dispatch(self, host, module, params, task):
        if module == 'ansible.builtin.command':
            return self.world.run_command(host, params['argv'], self, task, stdin=params.get('stdin'))
        if module == 'ansible.builtin.slurp':
            return self.world.slurp(host, params['src'])
        if module == 'ansible.builtin.copy':
            return self.world.copy(host, params)
        if module == 'ansible.builtin.service_facts':
            return self.world.service_facts(host)
        if module == 'ansible.builtin.stat':
            return self.world.stat(host, params['path'])
        if module == 'ansible.builtin.fetch':
            return self.world.fetch(host, params)
        if module == 'ansible.builtin.file':
            return self.world.file_module(host, params)
        if module == 'ansible.builtin.wait_for':
            return self.world.wait_for(host, params)
        raise ValueError('unsupported module: ' + module)


class AgentError(Exception):
    pass


ENVIRONMENT_KEYS = {
    'schema_version', 'environment_id', 'resource', 'backend', 'dut_id',
    'dut_image_fingerprint', 'saiserver_image_id', 'saiserver_container_name',
    'current_saiserver_container_id', 'ptf_host_id', 'ptf_container_id',
    'profile_id', 'profile_hash', 'source_identity', 'source_hash', 'mapping_hash',
    'snapshot_path', 'baseline_path', 'peer_resource', 'snapshot_complete',
}
RUN_PHASES = {'prepared', 'running', 'collecting', 'collected', 'failed'}
RUN_TRANSITIONS = {
    'prepared': {'running', 'failed'},
    'running': {'collecting', 'failed'},
    'collecting': {'collected', 'failed'},
    'collected': {'collected'},
    'failed': {'failed', 'collecting', 'collected'},
}


def _digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
        allow_nan=False).encode('utf-8')).hexdigest()


class FakeAgent:
    """A test-only stand-in for tests/ranking/remote_agent.py semantics."""

    def __init__(self, state_root='/var/tmp/ranking-state'):
        self.owners = {}
        self.guards = {}
        self.state = {}
        self.state_root = state_root

    def invoke(self, request):
        action = request['action']
        try:
            result = getattr(self, '_' + action)(request)
        except AgentError as error:
            return '', 1, str(error)
        return json.dumps({'schema_version': 1, 'action': action, 'result': result},
                          sort_keys=True) + '\n', 0, ''

    def _environment_dir(self, resource, environment_id):
        resource_digest = hashlib.sha256(resource.encode('utf-8')).hexdigest()
        return self.state_root + '/' + resource_digest + '/' + environment_id

    def _record(self, handle):
        record = self.owners.get(handle['resource'])
        if record is None:
            raise AgentError('Missing reservation record')
        for key in ('resource', 'environment_id', 'operation_id'):
            if record[key] != handle[key]:
                raise AgentError('Handle does not hold the current operation')
        return record

    def _claim(self, request):
        resource = request['resource']
        if resource in self.owners:
            raise AgentError('Resource already reserved: ' + resource)
        self.owners[resource] = {
            'schema_version': 1, 'resource': resource,
            'environment_id': request['environment_id'],
            'operation_id': request['operation_id'],
            'mutated': False, 'abortable': True,
        }
        return dict(request, created=True)

    def _resume(self, request):
        record = self.owners.get(request['resource'])
        if record is None:
            raise AgentError('Missing reservation record')
        if record['environment_id'] != request['environment_id']:
            raise AgentError('Environment identity mismatch')
        if record['operation_id'] is not None and \
                record['operation_id'] != request['operation_id']:
            raise AgentError('Environment has an active operation')
        record['operation_id'] = request['operation_id']
        record['abortable'] = False
        return dict(request, created=False)

    def _validate(self, request):
        return dict(self._record(request['handle']))

    def _begin_action(self, request):
        handle = request['handle']
        self._record(handle)
        if handle['resource'] in self.guards:
            raise AgentError('Resource has an active or incomplete action')
        guard = dict(resource=handle['resource'], environment_id=handle['environment_id'],
                     operation_id=request['action_id'], created=True)
        self.guards[handle['resource']] = guard
        return dict(guard)

    def _end_action(self, request):
        handle = request['handle']
        if self.guards.get(handle['resource']) != handle:
            raise AgentError('Action guard does not belong to this invocation')
        del self.guards[handle['resource']]
        return {}

    def _keep(self, request):
        record = self._record(request['handle'])
        record['operation_id'] = None
        record['abortable'] = False
        return {}

    def _abort(self, request):
        handle = request['handle']
        record = self._record(handle)
        if not handle['created'] or not record['abortable'] or record['mutated']:
            raise AgentError('Only a new, unmodified reservation can abort')
        del self.owners[handle['resource']]
        self.state.pop(handle['resource'], None)
        return {}

    def _release(self, request):
        handle = request['handle']
        self._record(handle)
        del self.owners[handle['resource']]
        self.state.pop(handle['resource'], None)
        return {}

    def _environment(self, handle, create=False):
        environments = self.state.setdefault(handle['resource'], {})
        environment = environments.get(handle['environment_id'])
        if environment is None and create:
            environment = environments[handle['environment_id']] = {}
        if environment is None:
            raise AgentError('Missing state record: environment')
        return environment

    def _read(self, request):
        handle = request['handle']
        self._record(handle)
        environment = self._environment(handle)
        if request['name'] not in environment:
            raise AgentError('Missing state record: ' + request['name'])
        return environment[request['name']]

    def _write(self, request):
        handle = request['handle']
        name = request['name']
        value = json.loads(json.dumps(request['value']))
        self._record(handle)
        if name == 'snapshot.json':
            if handle['resource'].startswith('dut:'):
                raise AgentError('Snapshot capture requires the snapshot action')
            environment = self._environment(handle, create=True)
            self._check_ptf_snapshot(handle, value)
        else:
            environment = self._environment(handle)
        if name == 'ledger.json':
            self._check_ledger(handle, value, environment)
        elif name == 'baseline.json':
            self._check_baseline(handle, value, environment)
        elif name == 'environment.json':
            self._check_environment(handle, value, environment)
        elif name == 'run-state.json':
            self._check_run_state(handle, value, environment)
        elif name != 'snapshot.json':
            raise AgentError('Unknown state record: ' + name)
        environment[name] = value
        return {}

    def _snapshot(self, request):
        handle = request['handle']
        if not handle['resource'].startswith('dut:'):
            raise AgentError('snapshot action is DUT-only; PTF uses validated write')
        self._record(handle)
        if handle['environment_id'] != request['identity']['environment_id']:
            raise AgentError('Snapshot environment mismatch')
        candidate = {
            'schema_version': 1,
            'identity': json.loads(json.dumps(request['identity'])),
            'services': json.loads(json.dumps(request['services'])),
            'files': {path: {'state': 'absent'} for path in request['paths']},
            'saiserver': json.loads(json.dumps(request['saiserver'])),
        }
        environment = self._environment(handle, create=True)
        original = environment.get('snapshot.json')
        if original is not None:
            if (original['identity'] != candidate['identity'] or
                    original['services'] != candidate['services'] or
                    set(original['files']) != set(request['paths']) or
                    original['saiserver'] != candidate['saiserver']):
                raise AgentError('Snapshot request does not match immutable original')
            return original
        environment['snapshot.json'] = candidate
        return candidate

    def _markers(self, handle, environment):
        if handle['resource'].startswith('ptf:'):
            return {'stage:ptf'}
        snapshot = environment['snapshot.json']
        return ({'stop:' + service for service in snapshot['services']} |
                {'restore:' + path for path in snapshot['files']} | {'start:saiserver'})

    def _check_ledger(self, handle, value, environment):
        if set(value) != {'schema_version', 'environment_id', 'resource',
                          'attempted', 'completed'}:
            raise AgentError('Invalid state fields')
        if value['environment_id'] != handle['environment_id'] or \
                value['resource'] != handle['resource']:
            raise AgentError('State environment identity mismatch')
        if not set(value['completed']).issubset(value['attempted']):
            raise AgentError('Completed marker must have been attempted')
        if not set(value['attempted']).issubset(self._markers(handle, environment)):
            raise AgentError('Unknown or undeclared ledger marker')
        previous = environment.get('ledger.json')
        if previous is not None:
            for key in ('attempted', 'completed'):
                if value[key][:len(previous[key])] != previous[key]:
                    raise AgentError('Ledger updates must append monotonically')

    def _check_baseline(self, handle, value, environment):
        if not handle['resource'].startswith('dut:'):
            raise AgentError('PTF cannot have a DUT baseline')
        snapshot = environment.get('snapshot.json')
        if snapshot is None:
            raise AgentError('Missing state record: snapshot.json')
        keys = {'schema_version', 'environment_id', 'resource',
                'snapshot_identity', 'ports', 'snapshot_sha256'}
        if set(value) not in (keys, keys - {'snapshot_sha256'}):
            raise AgentError('Invalid state fields')
        if value['snapshot_identity'] != snapshot['identity']:
            raise AgentError('Baseline original snapshot proof mismatch')
        if 'snapshot_sha256' not in value:
            value['snapshot_sha256'] = _digest(snapshot)
        if value['snapshot_sha256'] != _digest(snapshot):
            raise AgentError('Baseline original snapshot proof mismatch')
        if not isinstance(value['ports'], dict):
            raise AgentError('Baseline ports must be an object')
        for port, state in value['ports'].items():
            if set(state) != {'admin_state', 'oper_state', 'speed'}:
                raise AgentError('Invalid baseline port fields')

    def _check_environment(self, handle, value, environment):
        if not handle['resource'].startswith('dut:'):
            raise AgentError('PTF cannot have a DUT environment record')
        snapshot = environment.get('snapshot.json')
        if snapshot is None:
            raise AgentError('Missing state record: snapshot.json')
        if set(value) != ENVIRONMENT_KEYS:
            raise AgentError('Invalid state fields')
        directory = self._environment_dir(handle['resource'], handle['environment_id'])
        if value['snapshot_path'] != directory + '/snapshot.json':
            raise AgentError('Snapshot path does not match owned state')
        if value['baseline_path'] != directory + '/baseline.json':
            raise AgentError('Baseline path does not match owned state')
        expected_identity = {
            'environment_id': handle['environment_id'], 'dut_id': value['dut_id'],
            'image_id': value['dut_image_fingerprint'], 'profile_id': value['profile_id'],
            'mapping_hash': value['mapping_hash'],
        }
        if snapshot['identity'] != expected_identity:
            raise AgentError('Environment does not match original snapshot identity')
        if value['saiserver_container_name'] != snapshot['saiserver']['container_name']:
            raise AgentError('Saiserver name does not match original')
        if value['peer_resource'] != 'ptf:{}:{}'.format(
                value['ptf_host_id'], value['ptf_container_id']):
            raise AgentError('PTF metadata resource mismatch')
        previous = environment.get('environment.json')
        if previous is None:
            if value['snapshot_complete']:
                raise AgentError('Initial environment must not attest snapshot completeness')
            return
        mutable = {'current_saiserver_container_id', 'snapshot_complete'}
        for key in previous:
            if key not in mutable and previous[key] != value[key]:
                raise AgentError('Environment identity metadata is immutable')
        if previous['snapshot_complete'] and not value['snapshot_complete']:
            raise AgentError('Snapshot completeness cannot be reset')
        if value['snapshot_complete'] and 'baseline.json' not in environment:
            raise AgentError('Missing state record: baseline.json')

    def _check_ptf_snapshot(self, handle, value):
        if set(value) != {'schema_version', 'environment_id', 'resource',
                          'peer_resource', 'container_id', 'running', 'interfaces',
                          'staging_path', 'staging_state'}:
            raise AgentError('Invalid state fields')
        if value['resource'] != handle['resource']:
            raise AgentError('State resource identity mismatch')
        if value['environment_id'] != handle['environment_id']:
            raise AgentError('State environment identity mismatch')
        if value['container_id'] != handle['resource'].split(':')[2]:
            raise AgentError('PTF container does not match resource')
        if not value['running']:
            raise AgentError('Original PTF container must already be running')
        if value['staging_state'] != 'absent' or \
                handle['environment_id'] not in value['staging_path'].split('/')[1:]:
            raise AgentError('Staging path must be an absent environment-specific stage')

    def _check_run_state(self, handle, value, environment):
        if not handle['resource'].startswith('ptf:'):
            raise AgentError('Run state is a PTF companion record')
        snapshot = environment.get('snapshot.json')
        if snapshot is None:
            raise AgentError('Missing state record: snapshot.json')
        if set(value) != {'schema_version', 'environment_id', 'run_id', 'phase',
                          'process_exited', 'collected', 'outcome_path'}:
            raise AgentError('Invalid state fields')
        expected = snapshot['staging_path'] + '/runs/' + value['run_id'] + '/outcome.json'
        if value['outcome_path'] != expected:
            raise AgentError('Outcome must use the staging run path')
        if value['collected'] and not value['process_exited']:
            raise AgentError('Collection requires process exit')
        if value['phase'] == 'collected' and not value['collected']:
            raise AgentError('Collected phase requires collected result')
        previous = environment.get('run-state.json')
        if previous is not None:
            if previous['run_id'] != value['run_id']:
                if not previous['collected'] or not previous['process_exited']:
                    raise AgentError('Previous run has not exited and been collected')
            elif value['phase'] not in RUN_TRANSITIONS[previous['phase']]:
                raise AgentError('Run progress cannot be reset')
            elif previous['process_exited'] and not value['process_exited']:
                raise AgentError('Run progress cannot be reset')
            elif previous['collected'] and not value['collected']:
                raise AgentError('Run progress cannot be reset')

    def _restore_files(self, request):
        handle = request['handle']
        self._record(handle)
        if not handle['resource'].startswith('dut:'):
            raise AgentError('PTF snapshot declares no file restorations')
        environment = self._environment(handle)
        snapshot = environment.get('snapshot.json')
        if snapshot is None:
            raise AgentError('Missing state record: snapshot.json')
        originals = request['originals']
        if not isinstance(originals, dict):
            raise AgentError('Originals must be an object')
        for path, original in originals.items():
            if path not in snapshot['files'] or snapshot['files'][path] != original:
                raise AgentError('Restore must use declared original file states')
        return {}

    def _mark_attempt(self, request):
        handle = request['handle']
        marker = request['marker']
        self._record(handle)
        environment = self._environment(handle)
        if 'ledger.json' not in environment:
            raise AgentError('Missing state record: ledger.json')
        if marker not in self._markers(handle, environment):
            raise AgentError('Unknown or undeclared attempt marker')
        self._record(handle).update(mutated=True, abortable=False)
        ledger = environment['ledger.json']
        if marker not in ledger['attempted']:
            ledger['attempted'].append(marker)
        return {}

    def _complete_attempt(self, request):
        handle = request['handle']
        marker = request['marker']
        self._record(handle)
        environment = self._environment(handle)
        ledger = environment.get('ledger.json')
        if ledger is None or marker not in ledger['attempted']:
            raise AgentError('Cannot complete a nonattempted marker')
        if marker not in ledger['completed']:
            ledger['completed'].append(marker)
        return {}


class FakeDocker:
    def __init__(self):
        self.images = {}
        self.containers = {}
        self.calls = []
        self._counter = 0

    def _next_id(self):
        self._counter += 1
        return format(self._counter, '064x')

    def seed_image(self, reference, image_id):
        self.images[reference] = {'Id': image_id}

    def seed_container(self, host, name, image_id, running, identifier=None):
        container_id = identifier if identifier is not None else self._next_id()
        self.containers.setdefault(host, {})[name] = {
            'Id': container_id, 'Name': '/' + name, 'Image': image_id,
            'State': {'Running': running}, 'files': {},
        }
        return container_id

    def is_running(self, host, name):
        container = self.containers.get(host, {}).get(name)
        return bool(container and container['State']['Running'])

    def run_command(self, host, argv):
        self.calls.append((host, tuple(argv)))
        containers = self.containers.setdefault(host, {})
        if argv[1:3] == ['image', 'inspect']:
            image = self.images.get(argv[3])
            if image is None:
                return {'rc': 1, 'stdout': '', 'stderr': 'no such image',
                        'changed': False}
            return {'rc': 0, 'stdout': json.dumps([dict(image)]), 'stderr': '',
                    'changed': False}
        if argv[1] == 'inspect':
            container = containers.get(argv[-1])
            if container is None:
                return {'rc': 1, 'stdout': '', 'stderr': 'no such container',
                        'changed': False}
            return {'rc': 0, 'stdout': json.dumps([self.record(container)]),
                    'stderr': '', 'changed': False}
        if argv[1] == 'exec':
            target = argv[2]
            container = next((item for item in containers.values() if item['Id'] == target), None)
            if container is None or not container['State']['Running']:
                return {'rc': 1, 'stdout': '', 'stderr': 'container not running', 'changed': False}
            command = argv[3:]
            if command[:2] == ['test', '-f']:
                return {'rc': 0 if command[2] in container['files'] else 1,
                        'stdout': '', 'stderr': '', 'changed': False}
            if command[0] == 'rm':
                path = command[-1]
                for candidate in list(container['files']):
                    if candidate == path or candidate.startswith(path + '/'):
                        del container['files'][candidate]
            return {'rc': 0, 'stdout': '', 'stderr': '', 'changed': True}
        if argv[1] == 'stop':
            target = argv[-1]
            container = containers.get(target)
            if container is None:
                container = next((item for item in containers.values()
                                  if item['Id'] == target), None)
            if container is None:
                return {'rc': 1, 'stdout': '', 'stderr': 'no such container',
                        'changed': False}
            container['State']['Running'] = False
            return {'rc': 0, 'stdout': container['Id'] + '\n', 'stderr': '',
                    'changed': True}
        if argv[1] == 'rm':
            target = argv[2]
            container = containers.pop(target, None)
            if container is None:
                name = next((candidate for candidate, item in containers.items()
                             if item['Id'] == target), None)
                if name is not None:
                    container = containers.pop(name)
            if container is None:
                return {'rc': 1, 'stdout': '', 'stderr': 'no such container',
                        'changed': False}
            return {'rc': 0, 'stdout': target + '\n', 'stderr': '',
                    'changed': True}
        if argv[1] == 'run':
            name = argv[argv.index('--name') + 1]
            image_id = argv[-1]
            container_id = self._next_id()
            containers[name] = {
                'Id': container_id, 'Name': '/' + name, 'Image': image_id,
                'State': {'Running': True}, 'files': {},
            }
            return {'rc': 0, 'stdout': container_id + '\n', 'stderr': '',
                    'changed': True}
        raise TaskFailure('unsupported simulated docker command: ' + ' '.join(argv))

    @staticmethod
    def record(container):
        return {'Id': container['Id'], 'Name': container['Name'],
                'Image': container['Image'], 'State': dict(container['State'])}


class FakeWorld:
    def __init__(self, dut_host='dut-a', ptf_host='server-a'):
        self.dut_host = dut_host
        self.ptf_host = ptf_host
        self.ptf_container = 'ptf-c'
        self.saiserver_name = 'saiserverv2'
        self.files = {dut_host: {}, ptf_host: {}, 'localhost': {}}
        self.agents = {dut_host: FakeAgent(), ptf_host: FakeAgent()}
        self.docker = FakeDocker()
        self.runner_outputs = True
        self.services = {dut_host: {}, ptf_host: {}}
        self.processes = {dut_host: set(), ptf_host: set()}
        self.systemctl_calls = []
        self.fetches = []
        self.copies = []
        self.file_ops = []
        self.ports = {}
        self.runner_calls = []
        self.directories = set()

    def seed_dut(self, machine_id, services):
        self.files[self.dut_host]['/etc/machine-id'] = (machine_id + '\n', 0o444)
        self.files[self.dut_host]['/etc/sonic/sonic_version.yml'] = (
            'build_version: simulated\n', 0o644)
        for service in services:
            self.services[self.dut_host][service] = 'running'
            self.processes[self.dut_host].add(service)
        self.ports = {
            'Ethernet0': {'admin_state': 'up', 'oper_state': 'up', 'speed': '40000'},
        }

    def seed_ptf(self, machine_id):
        self.files[self.ptf_host]['/etc/machine-id'] = (machine_id + '\n', 0o444)

    def seed_controller_sources(self):
        self.files['localhost']['/source/binding/sai_thrift/__init__.py'] = (
            'prepared = True\n', 0o644)
        self.files['localhost']['/source/prebuilt/attr_map.json'] = ('{}\n', 0o644)
        for path in ('/source/key', '/source/known_hosts',
                     '/source/binding/sai_thrift/sai_adapter.py',
                     '/source/cases/ranking_test/spec_registry.json',
                     '/source/headers/sai.h', '/source/experimental/sai.h',
                     '/source/pipeline/generate_artifacts.py'):
            self.files['localhost'][path] = ('{}', 0o600)
        self.files['localhost']['/opt/ranking/ptf_runner.py'] = (
            'runner = True\n', 0o644)

    def _write(self, host, path, content, mode):
        self.files.setdefault(host, {})[path] = (content, mode)

    def run_command(self, host, argv, executor, task, stdin=None):
        argv = [str(argument) for argument in argv]
        if executor.fail_injector is not None and executor.fail_injector(argv):
            if any(token.endswith('remote_agent.py') or token == 'ranking.remote_agent' for token in argv):
                position = argv.index('--request')
                record = self.files.get(host, {}).get(argv[position + 1])
                if record is not None:
                    request = json.loads(record[0])
                    executor.agent_calls.append(
                        {'host': host, 'action': request['action'],
                         'request': request})
                    return {'rc': 1, 'stdout': '', 'stderr':
                            'injected agent failure', 'changed': False}
            raise TaskFailure('injected command failure: ' + ' '.join(argv), task)
        if any(token.endswith('remote_agent.py') or token == 'ranking.remote_agent' for token in argv):
            position = argv.index('--request')
            return self._run_agent(host, argv[position + 1], executor)
        first = argv[0].rsplit('/', 1)[-1]
        if first == 'docker':
            if argv[1] == 'cp':
                return self._docker_cp(host, argv)
            return self.docker.run_command(host, argv)
        if first == 'systemctl':
            return self._systemctl(host, argv)
        if first == 'pgrep':
            return {'rc': 0 if argv[-1] in self.processes.get(host, set()) else 1,
                    'stdout': '', 'stderr': '', 'changed': False}
        if first == 'show':
            return {'rc': 0, 'stdout': json.dumps(self.ports), 'stderr': '',
                    'changed': False}
        if first == 'ovs-vsctl':
            return {'rc': 0, 'stdout': 'ranking-br\n', 'stderr': '', 'changed': False}
        if first == 'python3' and argv[1] == '-c':
            return {'rc': 0, 'stdout': '{}', 'stderr': '', 'changed': True}
        if first == 'python3' and argv[1].endswith('generate_artifacts.py'):
            outdir = argv[argv.index('--out-dir') + 1]
            for name in ('skeleton.json', 'enum_values.json', 'attr_map.json'):
                self._write(host, outdir + '/' + name, '{}', 0o600)
            return {'rc': 0, 'stdout': '', 'stderr': '', 'changed': True}
        if first == 'python3' and len(argv) > 1 and argv[1].endswith('ptf_runner.py'):
            if '--validate-outcome' in argv:
                from tests.ranking.ptf_runner import parse_outcome
                value = parse_outcome(stdin)
                return {'rc': 0, 'stdout': json.dumps(value), 'stderr': '', 'changed': False}
            if '--recover-outcome' in argv:
                return {'rc': 1, 'stdout': '', 'stderr': 'recovery unconfirmed', 'changed': False}
            self.runner_calls.append((host, tuple(argv)))
            request = json.loads(self.files[host][argv[argv.index('--request') + 1]][0])
            container = self.docker.containers.get(host, {}).get(self.ptf_container)
            if container is not None and self.runner_outputs:
                outcome = dict(phase='ptf', pid=123, group=123, birth='100',
                               argv=request['argv'], timeout_s=request['timeout_s'], rc=0,
                               timed_out=False, process_exited=True, container_id=container['Id'])
                for name, content in (('stdout.log', 'stdout'), ('stderr.log', ''),
                                      ('outcome.json', json.dumps(outcome))):
                    self._write(host, request['run_dir'] + '/' + name, content, 0o600)
                collector = executor.variables['ranking_case'].replace('.', '_') + '.json'
                container['files'][request['run_dir'] + '/' + collector] = '{}'
            return {'rc': 0, 'stdout': '{}\n', 'stderr': '', 'changed': True}
        raise TaskFailure('unsupported simulated command: ' + ' '.join(argv), task)

    def _run_agent(self, host, request_path, executor):
        record = self.files.get(host, {}).get(request_path)
        if record is None:
            raise TaskFailure('missing staged request: ' + request_path)
        request = json.loads(record[0])
        stdout, code, stderr = self.agents[host].invoke(request)
        executor.agent_calls.append(
            {'host': host, 'action': request['action'], 'request': request})
        return {'rc': code, 'stdout': stdout, 'stderr': stderr, 'changed': code == 0}

    def _systemctl(self, host, argv):
        self.systemctl_calls.append((host, tuple(argv)))
        action, service = argv[1], argv[-1]
        if action == 'show':
            state = self.services[host].get(service)
            return {'rc': 0, 'stdout': 'LoadState={}\nActiveState={}\n'.format(
                'loaded' if state else 'not-found',
                'active' if state == 'running' else 'inactive'), 'stderr': '', 'changed': False}
        if action == 'stop':
            self.services[host][service] = 'stopped'
            self.processes[host].discard(service)
            return {'rc': 0, 'stdout': '', 'stderr': '', 'changed': True}
        if action == 'start':
            self.services[host][service] = 'running'
            self.processes[host].add(service)
            return {'rc': 0, 'stdout': '', 'stderr': '', 'changed': True}
        if action == 'is-active':
            state = self.services[host].get(service, 'stopped')
            return {'rc': 0 if state == 'running' else 3, 'stdout': state,
                    'stderr': '', 'changed': False}
        raise TaskFailure('unsupported simulated systemctl: ' + ' '.join(argv))

    def _docker_cp(self, host, argv):
        self.docker.calls.append((host, tuple(argv)))
        source, destination = argv[2], argv[3]
        containers = self.docker.containers.setdefault(host, {})
        if ':' in source:
            name, path = source.split(':', 1)
            container = containers.get(name) or next((item for item in containers.values() if item['Id'] == name), None)
            if container is None or path not in container['files']:
                return {'rc': 1, 'stdout': '', 'stderr': 'no such container file',
                        'changed': False}
            self._write(host, destination, container['files'][path], 0o644)
            return {'rc': 0, 'stdout': '', 'stderr': '', 'changed': True}
        name, path = destination.split(':', 1)
        container = containers.get(name) or next((item for item in containers.values() if item['Id'] == name), None)
        if container is None:
            return {'rc': 1, 'stdout': '', 'stderr': 'no such container',
                    'changed': False}
        if source.endswith('/.'):
            source_root = source[:-2]
            for candidate, (content, _) in self.files.get(host, {}).items():
                if candidate.startswith(source_root + '/'):
                    container['files'][path.rstrip('/') + candidate[len(source_root):]] = content
            return {'rc': 0, 'stdout': '', 'stderr': '', 'changed': True}
        record = self.files.get(host, {}).get(source)
        if record is None:
            return {'rc': 1, 'stdout': '', 'stderr': 'no such file', 'changed': False}
        container['files'][path] = record[0]
        return {'rc': 0, 'stdout': '', 'stderr': '', 'changed': True}

    def slurp(self, host, src):
        record = self.files.get(host, {}).get(src)
        if record is None:
            raise TaskFailure('missing simulated file: ' + src)
        return {'content': base64.b64encode(record[0].encode('utf-8')).decode('ascii'),
                'changed': False, 'failed': False, 'rc': 0}

    def copy(self, host, params):
        destination = params['dest']
        raw_mode = str(params.get('mode', '0644'))
        mode = 0o644 if raw_mode == 'preserve' else int(raw_mode, 8)
        if 'content' in params:
            self._write(host, destination, str(params['content']), mode)
            self.copies.append((host, destination, 'content'))
            return {'changed': True, 'failed': False, 'dest': destination}
        source = str(params.get('src', '')).rstrip('/')
        source_host = host if params.get('remote_src') else 'localhost'
        record = self.files.get(source_host, {}).get(source)
        if record is None and source_host == 'localhost' and Path(source).is_file():
            record = (Path(source).read_text(), mode)
        if record is not None:
            self._write(host, destination, record[0], mode)
            self.copies.append((host, destination, 'src:1'))
            return {'changed': True, 'failed': False, 'dest': destination}
        copied = 0
        for path, (content, _) in sorted(self.files.get(source_host, {}).items()):
            if path.startswith(source + '/'):
                relative = path[len(source) + 1:]
                self._write(host, destination.rstrip('/') + '/' + relative, content,
                            mode)
                copied += 1
        self.copies.append((host, destination, 'src:' + str(copied)))
        return {'changed': copied > 0, 'failed': False, 'dest': destination}

    def service_facts(self, host):
        services = {name: {'state': state}
                    for name, state in self.services[host].items()}
        return {'ansible_facts': {'services': services}, 'changed': False,
                'failed': False}

    def stat(self, host, path):
        exists = path in self.files.get(host, {})
        return {'stat': {'exists': exists, 'isreg': exists and (host, path) not in self.directories},
                'changed': False, 'failed': False}

    def fetch(self, host, params):
        source, destination = params['src'], str(params['dest'])
        record = self.files.get(host, {}).get(source)
        self.fetches.append((host, source, destination))
        if record is None:
            return {'changed': False, 'failed': False, 'msg': 'missing'}
        self._write('localhost', destination, record[0], record[1])
        return {'changed': True, 'failed': False, 'dest': destination}

    def file_module(self, host, params):
        path, state = params['path'], params.get('state')
        self.file_ops.append((host, path, state))
        if state == 'directory':
            self.directories.add((host, path))
            self.files.setdefault(host, {})[path] = ('', 0o700)
        elif state == 'absent':
            for candidate in [item for item in self.files.get(host, {})
                              if item == path or item.startswith(path + '/')]:
                del self.files[host][candidate]
        return {'changed': True, 'failed': False, 'path': path}

    def wait_for(self, host, params):
        if self.docker.is_running(self.dut_host, self.saiserver_name):
            return {'rc': 0, 'changed': False, 'failed': False,
                    'port': params.get('port'), 'host': params.get('host')}
        raise TaskFailure('simulated RPC connectivity check failed', None)


DUT_MACHINE = 'd1' * 16
PTF_MACHINE = 'e' * 32
PTF_CONTAINER_ID = 'f' * 64
SAISERVER_IMAGE_ID = 'sha256:' + 'a' * 64
SERVICES = ['swss', 'syncd', 'bgp', 'lldp']
DUT_RESOURCE = 'dut:' + DUT_MACHINE
PTF_RESOURCE = 'ptf:' + PTF_MACHINE + ':' + PTF_CONTAINER_ID


def build_world():
    world = FakeWorld()
    world.seed_dut(DUT_MACHINE, SERVICES)
    world.seed_ptf(PTF_MACHINE)
    world.seed_controller_sources()
    world.docker.seed_image('saiserver-image-ref', SAISERVER_IMAGE_ID)
    world.docker.seed_container(world.ptf_host, 'ptf-c', SAISERVER_IMAGE_ID, True,
                                PTF_CONTAINER_ID)
    return world


def ranking_variables(action, environment_id='env-a', operation_id='op-a',
                      case=None, run_id=None):
    variables = {
        'ranking_action': action,
        'ranking_action_id': 'action-' + action + '-' + (run_id or 'batch'),
        'ranking_environment_id': environment_id,
        'ranking_operation_id': operation_id,
        'ranking_case': case,
        'ranking_run_id': run_id,
        'ranking_dut_host': 'dut-a',
        'ranking_ptf_host': 'server-a',
        'ranking_artifacts_dir': '/controller/artifacts',
        'ranking_execution': {
            'dut_host': 'dut-a', 'ptf_host': 'server-a',
            'rpc_host': 'dut-a.example.test', 'profile_id': 'launch-a',
            'ptf_argv': ['/usr/bin/ptf'], 'test_params': {}, 'env': {},
            'binding_dir': '/source/binding', 'prebuilt_dir': '/source/prebuilt',
            'dut_files': [],
        },
        'ranking_runtime': {
            'backend': 'physical_fanout', 'dut_id': 'dut-a',
            'ptf_host_id': 'server-a', 'ptf_container': 'ptf-c',
            'saiserver_container': 'saiserverv2', 'saiserver_image':
            'saiserver-image-ref', 'services_to_stop': list(SERVICES),
            'ptf_root': '/var/tmp/ranking-ptf', 'rpc_port': 9092, 'timeout_s': 600,
            'dut_identity_file': '/etc/machine-id',
            'image_identity_files': ['/etc/sonic/sonic_version.yml'],
            'service_start_order': ['syncd', 'swss', 'bgp', 'lldp'],
            'asic_owner_processes': ['syncd'],
            'port_baseline': {'argv': ['show', 'interfaces', 'status'], 'format': 'json', 'timeout_s': 10},
            'case_source': '/source/cases', 'header_dir': '/source/headers',
            'experimental_header_dir': '/source/experimental',
            'adapter_path': '/source/binding/sai_thrift/sai_adapter.py',
            'dut_ssh': {'identity_file': '/source/key', 'known_hosts': '/source/known_hosts', 'user': 'admin'},
            'start_argv': ['/usr/bin/docker', 'run', '--pull=never', '--detach',
                           '--name', '{saiserver_container}', '{saiserver_image_id}'],
            'stop_argv': ['/usr/bin/docker', 'stop', '--time', '90',
                          '{saiserver_container_id}'],
        },
        'ranking_pipeline_dir': '/source/pipeline',
        'ranking_runner_path': '/opt/ranking/ptf_runner.py',
        'ranking_source_hash': 'a' * 64,
        'ranking_mapping_hash': 'b' * 64,
        'ranking_profile_hash': 'c' * 64,
        'ranking_source_identity': {'repo': 'SAI', 'commit': 'd' * 40},
        'ranking_ptf_interfaces': [{'id': 0, 'name': 'eth0'}],
        'ranking_ownership_root': '/var/tmp/ranking-ownership',
        'ranking_state_root': '/var/tmp/ranking-state',
        'ranking_request_base': '/var/tmp/ranking-requests',
        'ranking_request_root': '/var/tmp/ranking-requests/env-a/op-a',
        'ranking_agent_root': '/var/tmp/ranking-requests/env-a/op-a/agent',
        'role_path': str(ROLE),
        'ranking_ownership_acquired': False,
    }
    if action == 'run':
        root = '/var/tmp/ranking-ptf/' + environment_id
        variables['ranking_ptf_request'] = {
            'argv': ['/usr/bin/ptf', '--test-dir', root + '/ptf', case,
                     '--platform', 'eth', '--interface', '0-0@eth0',
                     '--test-params', json.dumps({
                         'thrift_server': 'dut-a.example.test', 'rpc_port': 9092,
                         'config_db_json': root + '/resources/ptf-config-db.json',
                         'port_config_ini': root + '/resources/port_config.ini',
                         'result_output_dir': root + '/runs/' + run_id,
                     }, sort_keys=True)],
            'env': {'PYTHONPATH': root + '/binding:' + root + '/ptf:'},
            'cwd': root,
            'run_dir': root + '/runs/' + run_id,
            'timeout_s': 600,
        }
    return variables


def test_simulated_unauthorized_environment_never_reads_resets_or_collects():
    world = build_world()
    for host, resource in ((world.dut_host, DUT_RESOURCE), (world.ptf_host, PTF_RESOURCE)):
        world.agents[host].invoke({
            'action': 'claim', 'resource': resource, 'environment_id': 'env-a',
            'operation_id': 'op-b',
        })
    variables = ranking_variables('run', case='sairoute.RouteA', run_id='run-a')
    executor = RoleExecutor(world, variables)
    with pytest.raises(TaskFailure) as failure:
        executor.run_file('main.yml')
    assert 'owned by another operation' in failure.value.message
    assert [call['action'] for call in executor.agent_calls] == ['validate', 'validate']
    assert not [call for call in executor.agent_calls
                if call['action'] in ('read', 'write', 'snapshot', 'mark_attempt',
                                      'claim', 'resume', 'complete_attempt')]
    assert world.systemctl_calls == []
    assert not [call for call in world.docker.calls
                if call[1][1] in ('stop', 'start', 'run', 'rm', 'cp')]
    assert world.fetches == []
    assert not [item for item in world.copies if item[2] != 'content' and '/ranking-requests/' not in item[1]]
    assert all(destination.startswith('/var/tmp/ranking-requests/')
               for _, destination, _ in world.copies)
    assert executor.variables['ranking_ownership_acquired'] is False


def test_simulated_setup_half_failure_rolls_back_attempted_markers_once():
    world = build_world()

    def fail_on_syncd_stop(argv):
        return argv[:3] == ['systemctl', 'stop', 'syncd']

    executor = RoleExecutor(world, ranking_variables('setup'),
                            fail_injector=fail_on_syncd_stop)
    with pytest.raises(TaskFailure) as failure:
        executor.run_file('main.yml')
    assert 'ranking setup failed' in failure.value.message
    ledger = world.agents[world.dut_host].state[DUT_RESOURCE]['env-a']['ledger.json']
    assert ledger['attempted'] == ['stop:swss', 'stop:syncd']
    assert ledger['completed'] == []
    starts = [call for call in world.systemctl_calls if call[1][1] == 'start']
    assert sorted(call[1][2] for call in starts) == ['swss', 'syncd']
    assert len(starts) == 2
    assert not [call for call in world.docker.calls if call[1][1] == 'run']
    marks = [call['request']['marker'] for call in executor.agent_calls
             if call['action'] == 'mark_attempt']
    assert marks == ['stop:swss', 'stop:syncd', 'stop:syncd', 'stop:swss']
    for host in (world.dut_host, world.ptf_host):
        assert len(world.agents[host].owners) == 1
    environment = world.agents[world.dut_host].state[DUT_RESOURCE]['env-a'][
        'environment.json']
    assert environment['snapshot_complete'] is True
    assert environment['current_saiserver_container_id'] is None


def _chained_world():
    world = build_world()
    setup = RoleExecutor(world, ranking_variables('setup'))
    setup.run_file('main.yml')
    setup_container_id = world.docker.containers[world.dut_host]['saiserverv2']['Id']
    environment = world.agents[world.dut_host].state[DUT_RESOURCE]['env-a'][
        'environment.json']
    assert environment['current_saiserver_container_id'] == setup_container_id
    world.systemctl_calls = []
    world.fetches = []
    world.file_ops = []
    world.docker_calls_baseline = len(world.docker.calls)
    return world, setup_container_id


def test_simulated_setup_then_run_resets_the_case_container_and_runs_case():
    world, setup_container_id = _chained_world()
    variables = ranking_variables('run', case='sairoute.RouteA', run_id='run-a')
    run = RoleExecutor(world, variables)
    run.run_file('main.yml')

    dut_calls = [call[1] for call in world.docker.calls
                 if call[0] == world.dut_host]
    assert ('/usr/bin/docker', 'stop', '--time', '90', setup_container_id) in \
        dut_calls
    assert ('docker', 'rm', 'saiserverv2') in dut_calls
    assert ('/usr/bin/docker', 'run', '--pull=never', '--detach', '--name',
            'saiserverv2', SAISERVER_IMAGE_ID) in dut_calls
    new_container = world.docker.containers[world.dut_host]['saiserverv2']
    assert new_container['Id'] != setup_container_id
    assert new_container['State']['Running'] is True
    environment = world.agents[world.dut_host].state[DUT_RESOURCE]['env-a'][
        'environment.json']
    assert environment['current_saiserver_container_id'] == new_container['Id']

    assert world.files[world.ptf_host][
        '/var/tmp/ranking-ptf/env-a/runner/ptf_runner.py'][0] == 'runner = True\n'
    staged_request = json.loads(world.files[world.ptf_host][
        '/var/tmp/ranking-ptf/env-a/requests/run-a.json'][0])
    assert staged_request == variables['ranking_ptf_request']
    assert world.runner_calls == [(
        world.ptf_host,
        ('python3', '/var/tmp/ranking-ptf/env-a/runner/ptf_runner.py',
         '--request', '/var/tmp/ranking-ptf/env-a/requests/run-a.json'))]

    assert [call['request']['marker'] for call in run.agent_calls
            if call['action'] == 'mark_attempt'] == ['start:saiserver', 'stage:ptf']
    artifact_fetches = [call for call in world.fetches
                        if call[2] != '/controller/artifacts/role-outcome.json']
    assert sorted(call[2] for call in artifact_fetches) == sorted(
        '/controller/artifacts/env-a/run-a/' + name
        for name in ('outcome.json', 'stdout.log', 'stderr.log', 'sairoute_RouteA.json',
                     'spec_registry.json', 'skeleton.json', 'enum_values.json', 'attr_map.json',
                     'case-id.txt', 'collection-status.json'))
    outcome_fetches = [call for call in world.fetches
                       if call[2] == '/controller/artifacts/role-outcome.json']
    assert len(outcome_fetches) == 1
    record = json.loads(
        world.files['localhost']['/controller/artifacts/role-outcome.json'][0])
    assert record['collected'] and all(record['collected'].values())
    assert record['collected']['outcome.json'] is True
    assert record['collection_errors'] == {}
    assert record['case_rc'] == 0
    assert record['case'] == 'sairoute.RouteA'
    assert json.loads(world.files['localhost'][
        '/controller/artifacts/env-a/run-a/outcome.json'][0])['rc'] == 0
    run_state = world.agents[world.ptf_host].state[PTF_RESOURCE]['env-a'][
        'run-state.json']
    assert run_state['phase'] == 'collected'
    assert run_state['collected'] is True
    assert run_state['process_exited'] is True


def test_simulated_collect_runs_when_the_case_command_fails():
    world, _ = _chained_world()

    def fail_on_runner(argv):
        return argv[0] == 'python3' and len(argv) > 1 and argv[1].endswith('ptf_runner.py')
    run = RoleExecutor(world, ranking_variables('run', case='sairoute.RouteA',
                       run_id='run-a'), fail_injector=fail_on_runner)
    with pytest.raises(TaskFailure):
        run.run_file('main.yml')
    record = _outcome_record(world)
    assert record['collected']['outcome.json'] is False
    assert record['collection_errors']['outcome.json']
    assert record['case_rc'] != 0
    assert record['run_id'] == 'run-a'
    state = world.agents[world.ptf_host].state[PTF_RESOURCE]['env-a']['run-state.json']
    assert state['phase'] == 'failed'
    assert state['collected'] is False
    assert state['process_exited'] is False
    assert any(call['action'] == 'mark_attempt' and call['request']
               ['marker'] == 'stage:ptf' for call in run.agent_calls)


def test_simulated_second_run_requires_previous_run_collected():
    world, _ = _chained_world()

    def fail_on_runner(argv):
        return argv[0] == 'python3' and len(argv) > 1 and \
            argv[1].endswith('ptf_runner.py')

    first = RoleExecutor(world, ranking_variables(
        'run', case='sairoute.RouteA', run_id='run-a'),
        fail_injector=fail_on_runner)
    with pytest.raises(TaskFailure):
        first.run_file('main.yml')
    second = RoleExecutor(world, ranking_variables(
        'run', case='sairoute.RouteA', run_id='run-b'))
    with pytest.raises(TaskFailure) as failure:
        second.run_file('main.yml')
    assert 'previous ranking run has not' in failure.value.message
    starts = [call for call in world.docker.calls
              if len(call[1]) > 1 and call[1][1] == 'run']
    assert len(starts) == 2
    assert world.runner_calls == []
    assert not [path for path in world.files[world.ptf_host]
                if path.endswith('/requests/run-b.json')]
    assert not [path for path in world.files[world.ptf_host]
                if path.endswith('/runs/run-b/outcome.json')]


def test_simulated_setup_completes_with_a_running_saiserver():
    world = build_world()
    executor = RoleExecutor(world, ranking_variables('setup'))
    executor.run_file('main.yml')
    containers = world.docker.containers[world.dut_host]
    assert 'saiserverv2' in containers
    assert containers['saiserverv2']['State']['Running'] is True
    assert containers['saiserverv2']['Image'] == SAISERVER_IMAGE_ID
    environment = world.agents[world.dut_host].state[DUT_RESOURCE]['env-a'][
        'environment.json']
    assert environment['snapshot_complete'] is True
    assert environment['current_saiserver_container_id'] == \
        containers['saiserverv2']['Id']
    ledger = world.agents[world.dut_host].state[DUT_RESOURCE]['env-a']['ledger.json']
    assert ledger['attempted'] == ['stop:' + service for service in SERVICES] + \
        ['start:saiserver']
    assert ledger['completed'] == []
    assert all(world.services[world.dut_host][service] == 'stopped'
               for service in SERVICES)
    assert '/var/tmp/ranking-ptf/env-a/binding/sai_thrift/__init__.py' in \
        world.files[world.ptf_host]
    assert '/var/tmp/ranking-ptf/env-a/binding/sai_thrift/__init__.py' in \
        world.docker.containers[world.ptf_host]['ptf-c']['files']
    ptf_ledger = world.agents[world.ptf_host].state[PTF_RESOURCE]['env-a'][
        'ledger.json']
    assert ptf_ledger['attempted'] == ['stage:ptf']
    assert world.agents[world.dut_host].owners[DUT_RESOURCE]['mutated'] is True
    actions = [call['action'] for call in executor.agent_calls]
    assert actions.count('snapshot') == 1
    assert actions.count('claim') == 2
    assert actions.count('validate') == 2


def _outcome_record(world):
    return json.loads(
        world.files['localhost']['/controller/artifacts/role-outcome.json'][0])


def _kept_world(resume_operation_id='op-b'):
    world, _ = _chained_world()
    keep = RoleExecutor(world, ranking_variables('keep'))
    keep.run_file('main.yml')
    for host, resource in ((world.dut_host, DUT_RESOURCE),
                           (world.ptf_host, PTF_RESOURCE)):
        stdout, code, _ = world.agents[host].invoke({
            'action': 'resume', 'resource': resource, 'environment_id': 'env-a',
            'operation_id': resume_operation_id})
        assert code == 0, stdout
    return world


def _docker_mutations(world):
    baseline = getattr(world, 'docker_calls_baseline', 0)
    return [call for call in world.docker.calls[baseline:]
            if call[1][1] in ('stop', 'start', 'run', 'rm', 'cp')]


def test_simulated_teardown_restores_and_releases_both_resources():
    world, setup_container_id = _chained_world()
    teardown = RoleExecutor(world, ranking_variables('teardown'))
    teardown.run_file('main.yml')
    dut_calls = [call[1] for call in world.docker.calls
                 if call[0] == world.dut_host]
    assert ('/usr/bin/docker', 'stop', '--time', '90', setup_container_id) in \
        dut_calls
    assert ('docker', 'rm', setup_container_id) in dut_calls
    assert 'saiserverv2' not in world.docker.containers[world.dut_host]
    starts = [call for call in world.systemctl_calls if call[1][1] == 'start']
    assert [call[1][2] for call in starts] == ['syncd', 'swss', 'bgp', 'lldp']
    assert all(world.services[world.dut_host][service] == 'running'
               for service in SERVICES)
    assert not [call for call in world.systemctl_calls
                if call[1][1] in ('restart', 'reload')]
    assert _docker_mutations(world) == [
        (world.dut_host, ('/usr/bin/docker', 'stop', '--time', '90',
                          setup_container_id)),
        (world.dut_host, ('docker', 'rm', setup_container_id))]
    assert not [path for path in world.files[world.ptf_host]
                if path.startswith('/var/tmp/ranking-ptf/env-a')]
    actions = [call['action'] for call in teardown.agent_calls]
    assert actions.count('release') == 2
    assert actions.count('restore_files') == 1
    assert not [action for action in actions if action in ('claim', 'resume')]
    markers = [call['request']['marker'] for call in teardown.agent_calls
               if call['action'] == 'mark_attempt']
    assert markers == ['stage:ptf', 'start:saiserver', 'stop:syncd', 'stop:swss', 'stop:bgp', 'stop:lldp']
    completions = [call['request']['marker'] for call in teardown.agent_calls
                   if call['action'] == 'complete_attempt']
    assert completions == ['start:saiserver', 'stop:syncd', 'stop:swss',
                           'stop:bgp', 'stop:lldp', 'stage:ptf']
    for host in (world.dut_host, world.ptf_host):
        assert world.agents[host].owners == {}
        assert world.agents[host].state == {}
    assert _outcome_record(world) == {
        'schema_version': 1, 'environment_id': 'env-a', 'action': 'teardown',
        'restored': True, 'released': [DUT_RESOURCE, PTF_RESOURCE],
        'kept': False, 'uncertain': False}


def test_simulated_teardown_after_a_collected_run_releases_both_resources():
    world, _ = _chained_world()
    run = RoleExecutor(world, ranking_variables('run', case='sairoute.RouteA',
                                                run_id='run-a'))
    run.run_file('main.yml')
    case_container_id = world.docker.containers[world.dut_host]['saiserverv2']['Id']
    teardown = RoleExecutor(world, ranking_variables('teardown'))
    teardown.run_file('main.yml')
    assert ('docker', 'rm', case_container_id) in [
        call[1] for call in world.docker.calls if call[0] == world.dut_host]
    for host in (world.dut_host, world.ptf_host):
        assert world.agents[host].owners == {}
    record = _outcome_record(world)
    assert record['restored'] is True
    assert record['released'] == [DUT_RESOURCE, PTF_RESOURCE]
    assert record['uncertain'] is False


def test_simulated_teardown_refuses_an_uncollected_previous_run():
    world, _ = _chained_world()

    def fail_on_runner(argv):
        return argv[0] == 'python3' and len(argv) > 1 and \
            argv[1].endswith('ptf_runner.py')

    run = RoleExecutor(world, ranking_variables(
        'run', case='sairoute.RouteA', run_id='run-a'), fail_injector=fail_on_runner)
    with pytest.raises(TaskFailure):
        run.run_file('main.yml')
    teardown = RoleExecutor(world, ranking_variables('teardown'))
    with pytest.raises(TaskFailure) as failure:
        teardown.run_file('main.yml')
    assert 'previous ranking run has not' in failure.value.message
    assert _docker_mutations(world) == []
    assert world.systemctl_calls == []
    assert '/var/tmp/ranking-ptf/env-a/runner/ptf_runner.py' in \
        world.files[world.ptf_host]
    for host in (world.dut_host, world.ptf_host):
        assert len(world.agents[host].owners) == 1
    record = _outcome_record(world)
    assert record['restored'] is False
    assert record['released'] == []
    assert record['uncertain'] is True


def test_simulated_keep_retains_both_ends_without_restoration():
    world, _ = _chained_world()
    keep = RoleExecutor(world, ranking_variables('keep'))
    keep.run_file('main.yml')
    assert _docker_mutations(world) == []
    assert world.systemctl_calls == []
    assert all('/ranking-requests/' in call[1] for call in world.file_ops)
    actions = [call['action'] for call in keep.agent_calls]
    assert actions.count('keep') == 2
    assert not [action for action in actions
                if action in ('release', 'restore_files', 'mark_attempt')]
    for host, resource in ((world.dut_host, DUT_RESOURCE),
                           (world.ptf_host, PTF_RESOURCE)):
        assert world.agents[host].owners[resource]['operation_id'] is None
        assert world.agents[host].state[resource]['env-a']
    assert world.agents[world.dut_host].state[DUT_RESOURCE]['env-a'][
        'environment.json']
    assert world.agents[world.ptf_host].state[PTF_RESOURCE]['env-a'][
        'snapshot.json']
    assert '/var/tmp/ranking-ptf/env-a/runner/ptf_runner.py' in \
        world.files[world.ptf_host]
    assert _outcome_record(world) == {
        'schema_version': 1, 'environment_id': 'env-a', 'action': 'keep',
        'restored': False, 'released': [], 'kept': True, 'uncertain': False}


def test_simulated_keep_failure_retains_an_uncertain_outcome():
    world, _ = _chained_world()

    def fail_on_ptf_keep(argv):
        return any(token.endswith('remote_agent.py') or token == 'ranking.remote_agent' for token in argv) and \
            argv[argv.index('--request') + 1].endswith('keep-ptf.json')

    keep = RoleExecutor(world, ranking_variables('keep'),
                        fail_injector=fail_on_ptf_keep)
    with pytest.raises(TaskFailure):
        keep.run_file('main.yml')
    assert world.agents[world.dut_host].owners[DUT_RESOURCE]['operation_id'] is None
    assert world.agents[world.ptf_host].owners[PTF_RESOURCE]['operation_id'] == \
        'op-a'
    record = _outcome_record(world)
    assert record['kept'] is False
    assert record['released'] == []
    assert record['uncertain'] is True


def test_simulated_teardown_refuses_an_unknown_active_operation():
    world, _ = _chained_world()
    teardown = RoleExecutor(world, ranking_variables('teardown',
                                                     operation_id='op-b'))
    with pytest.raises(TaskFailure) as failure:
        teardown.run_file('main.yml')
    assert 'owned by another operation' in failure.value.message
    assert [call['action'] for call in teardown.agent_calls] == \
        ['validate', 'validate']
    assert world.systemctl_calls == []
    assert _docker_mutations(world) == []
    assert world.fetches == []
    for host, resource in ((world.dut_host, DUT_RESOURCE),
                           (world.ptf_host, PTF_RESOURCE)):
        assert world.agents[host].owners[resource]['operation_id'] == 'op-a'


def test_simulated_teardown_refuses_a_wrong_environment_identity():
    world, _ = _chained_world()
    teardown = RoleExecutor(world, ranking_variables('teardown',
                                                     environment_id='env-b'))
    with pytest.raises(TaskFailure) as failure:
        teardown.run_file('main.yml')
    assert 'owned by another operation' in failure.value.message
    assert [call['action'] for call in teardown.agent_calls] == \
        ['validate', 'validate']
    assert _docker_mutations(world) == []
    assert world.systemctl_calls == []


@pytest.mark.parametrize('host', ['dut', 'ptf'])
def test_simulated_teardown_refuses_a_wrong_host_identity(host):
    world, _ = _chained_world()
    target = world.dut_host if host == 'dut' else world.ptf_host
    content, mode = world.files[target]['/etc/machine-id']
    world.files[target]['/etc/machine-id'] = ('f1' * 16 + '\n', mode)
    teardown = RoleExecutor(world, ranking_variables('teardown'))
    with pytest.raises(TaskFailure) as failure:
        teardown.run_file('main.yml')
    assert 'owned by another operation' in failure.value.message
    assert [call['action'] for call in teardown.agent_calls] == \
        ['validate', 'validate']
    assert _docker_mutations(world) == []
    assert world.systemctl_calls == []


def test_simulated_teardown_recovers_a_known_retained_operation():
    world = _kept_world('op-b')
    teardown = RoleExecutor(world, ranking_variables('teardown',
                                                     operation_id='op-b'))
    teardown.run_file('main.yml')
    for host in (world.dut_host, world.ptf_host):
        assert world.agents[host].owners == {}
    record = _outcome_record(world)
    assert record['restored'] is True
    assert record['released'] == [DUT_RESOURCE, PTF_RESOURCE]
    assert record['uncertain'] is False


def test_simulated_teardown_fails_on_a_missing_snapshot_record():
    world, _ = _chained_world()
    del world.agents[world.dut_host].state[DUT_RESOURCE]['env-a']['snapshot.json']
    teardown = RoleExecutor(world, ranking_variables('teardown'))
    with pytest.raises(TaskFailure):
        teardown.run_file('main.yml')
    assert _docker_mutations(world) == []
    assert world.systemctl_calls == []
    for host in (world.dut_host, world.ptf_host):
        assert len(world.agents[host].owners) == 1
    record = _outcome_record(world)
    assert record['restored'] is False
    assert record['released'] == []
    assert record['uncertain'] is True


def test_simulated_teardown_restore_failure_retains_both_ends():
    world, _ = _chained_world()

    def fail_on_restore(argv):
        return any(token.endswith('remote_agent.py') or token == 'ranking.remote_agent' for token in argv) and \
            argv[argv.index('--request') + 1].endswith('write-restore-files.json')

    teardown = RoleExecutor(world, ranking_variables('teardown'),
                            fail_injector=fail_on_restore)
    with pytest.raises(TaskFailure):
        teardown.run_file('main.yml')
    assert world.systemctl_calls == []
    for host in (world.dut_host, world.ptf_host):
        assert len(world.agents[host].owners) == 1
    record = _outcome_record(world)
    assert record['restored'] is False
    assert record['released'] == []
    assert record['uncertain'] is True


def test_simulated_teardown_retries_after_a_failed_restore():
    world, _ = _chained_world()

    def fail_on_restore(argv):
        return any(token.endswith('remote_agent.py') or token == 'ranking.remote_agent' for token in argv) and \
            argv[argv.index('--request') + 1].endswith('write-restore-files.json')

    teardown = RoleExecutor(world, ranking_variables('teardown'),
                            fail_injector=fail_on_restore)
    with pytest.raises(TaskFailure):
        teardown.run_file('main.yml')
    clear_writes = [call for call in teardown.agent_calls
                    if call['action'] == 'write' and
                    call['request']['name'] == 'environment.json']
    assert len(clear_writes) == 1
    assert clear_writes[0]['request']['value']['current_saiserver_container_id'] \
        is None
    retry = RoleExecutor(world, ranking_variables('teardown'))
    retry.run_file('main.yml')
    assert _docker_mutations(world) == []
    for host in (world.dut_host, world.ptf_host):
        assert world.agents[host].owners == {}
    record = _outcome_record(world)
    assert record['restored'] is True
    assert record['released'] == [DUT_RESOURCE, PTF_RESOURCE]
    assert record['uncertain'] is False


def test_simulated_teardown_service_start_failure_retains_both_ends():
    world, _ = _chained_world()

    def fail_on_syncd_start(argv):
        return argv[:3] == ['systemctl', 'start', 'syncd']

    teardown = RoleExecutor(world, ranking_variables('teardown'),
                            fail_injector=fail_on_syncd_start)
    with pytest.raises(TaskFailure):
        teardown.run_file('main.yml')
    assert not [call for call in world.systemctl_calls
                if call[1][1] in ('restart', 'reload')]
    for host in (world.dut_host, world.ptf_host):
        assert len(world.agents[host].owners) == 1
    record = _outcome_record(world)
    assert record['restored'] is False
    assert record['released'] == []
    assert record['uncertain'] is True


@pytest.mark.parametrize('tampered', [
    {'Ethernet0': {'admin_state': 'up', 'oper_state': 'up'}},
    {},
])
def test_simulated_teardown_requires_the_original_port_convergence(tampered):
    world, _ = _chained_world()
    world.ports = tampered
    teardown = RoleExecutor(world, ranking_variables('teardown'))
    with pytest.raises(TaskFailure) as failure:
        teardown.run_file('main.yml')
    assert 'original ranking port baseline was not restored' in \
        failure.value.message
    for host in (world.dut_host, world.ptf_host):
        assert len(world.agents[host].owners) == 1
    record = _outcome_record(world)
    assert record['restored'] is False
    assert record['released'] == []
    assert record['uncertain'] is True


def test_simulated_teardown_requires_the_original_service_states():
    world, _ = _chained_world()
    snapshot = world.agents[world.dut_host].state[DUT_RESOURCE]['env-a'][
        'snapshot.json']
    snapshot['services']['bgp'] = 'absent'
    teardown = RoleExecutor(world, ranking_variables('teardown'))
    with pytest.raises(TaskFailure) as failure:
        teardown.run_file('main.yml')
    assert 'original ranking service state was not restored' in \
        failure.value.message
    for host in (world.dut_host, world.ptf_host):
        assert len(world.agents[host].owners) == 1
    record = _outcome_record(world)
    assert record['restored'] is False
    assert record['released'] == []
    assert record['uncertain'] is True


def test_simulated_teardown_release_failure_marks_the_outcome_uncertain():
    world, _ = _chained_world()

    def fail_on_ptf_release(argv):
        return any(token.endswith('remote_agent.py') or token == 'ranking.remote_agent' for token in argv) and \
            argv[argv.index('--request') + 1].endswith('release-ptf.json')

    teardown = RoleExecutor(world, ranking_variables('teardown'),
                            fail_injector=fail_on_ptf_release)
    with pytest.raises(TaskFailure):
        teardown.run_file('main.yml')
    assert world.agents[world.dut_host].owners == {}
    assert len(world.agents[world.ptf_host].owners) == 1
    record = _outcome_record(world)
    assert record['restored'] is True
    assert record['released'] == [DUT_RESOURCE]
    assert record['uncertain'] is True


def test_simulated_teardown_dut_release_failure_skips_the_ptf_release():
    world, _ = _chained_world()

    def fail_on_dut_release(argv):
        return any(token.endswith('remote_agent.py') or token == 'ranking.remote_agent' for token in argv) and \
            argv[argv.index('--request') + 1].endswith('release-dut.json')

    teardown = RoleExecutor(world, ranking_variables('teardown'),
                            fail_injector=fail_on_dut_release)
    with pytest.raises(TaskFailure):
        teardown.run_file('main.yml')
    releases = [call['request'] for call in teardown.agent_calls
                if call['action'] == 'release']
    assert len(releases) == 1
    assert releases[0]['handle']['resource'] == DUT_RESOURCE
    for host in (world.dut_host, world.ptf_host):
        assert len(world.agents[host].owners) == 1
    record = _outcome_record(world)
    assert record['restored'] is True
    assert record['released'] == []
    assert record['uncertain'] is True


def test_simulated_status_resumes_and_verifies_a_kept_environment():
    world = _kept_world('op-b')
    status = RoleExecutor(world, ranking_variables('status',
                                                   operation_id='op-b'))
    status.run_file('main.yml')
    actions = [call['action'] for call in status.agent_calls]
    assert actions == ['resume', 'resume', 'validate', 'validate', 'begin_action',
                       'begin_action', 'read', 'read', 'read', 'end_action', 'end_action']
    assert _docker_mutations(world) == []
    assert world.systemctl_calls == []
    for host, resource in ((world.dut_host, DUT_RESOURCE),
                           (world.ptf_host, PTF_RESOURCE)):
        assert world.agents[host].owners[resource]['operation_id'] == 'op-b'
    assert _outcome_record(world) == {
        'schema_version': 1, 'environment_id': 'env-a', 'action': 'status',
        'restored': False, 'released': [], 'kept': False, 'uncertain': False}


def test_simulated_concurrent_status_skip_is_refused():
    world = _kept_world('op-b')
    status = RoleExecutor(world, ranking_variables('status',
                                                   operation_id='op-c'))
    with pytest.raises(TaskFailure) as failure:
        status.run_file('main.yml')
    assert 'reservation could not be claimed or resumed' in failure.value.message
    assert [call['action'] for call in status.agent_calls] == ['resume']
    for host, resource in ((world.dut_host, DUT_RESOURCE),
                           (world.ptf_host, PTF_RESOURCE)):
        assert world.agents[host].owners[resource]['operation_id'] == 'op-b'


def test_simulated_status_refuses_a_changed_saiserver_image_tag():
    world = _kept_world('op-b')
    world.docker.seed_image('saiserver-image-ref', 'sha256:' + 'b' * 64)
    status = RoleExecutor(world, ranking_variables('status',
                                                   operation_id='op-b'))
    with pytest.raises(TaskFailure) as failure:
        status.run_file('main.yml')
    assert 'local saiserver image does not match the persisted environment' in \
        failure.value.message
    for host, resource in ((world.dut_host, DUT_RESOURCE),
                           (world.ptf_host, PTF_RESOURCE)):
        assert world.agents[host].owners[resource]['operation_id'] == 'op-b'


def test_simulated_status_refuses_a_changed_dut_image():
    world = _kept_world('op-b')
    world.files[world.dut_host]['/etc/sonic/sonic_version.yml'] = (
        'build_version: changed\n', 0o644)
    status = RoleExecutor(world, ranking_variables('status',
                                                   operation_id='op-b'))
    with pytest.raises(TaskFailure) as failure:
        status.run_file('main.yml')
    assert 'current DUT image does not match the original snapshot' in \
        failure.value.message


@pytest.mark.parametrize('field,value', [
    ('ranking_profile_hash', 'other-profile-hash'),
    ('ranking_mapping_hash', 'other-mapping-hash'),
    ('ranking_source_hash', 'other-source-hash'),
    ('ranking_source_identity', {'repo': 'SAI', 'commit': 'e' * 40}),
])
def test_simulated_status_refuses_mismatched_request_inputs(field, value):
    world = _kept_world('op-b')
    variables = ranking_variables('status', operation_id='op-b')
    variables[field] = value
    status = RoleExecutor(world, variables)
    with pytest.raises(TaskFailure) as failure:
        status.run_file('main.yml')
    assert 'does not match the requested inputs' in failure.value.message
    for host, resource in ((world.dut_host, DUT_RESOURCE),
                           (world.ptf_host, PTF_RESOURCE)):
        assert world.agents[host].owners[resource]['operation_id'] == 'op-b'


def test_setup_omits_the_role_side_baseline_digest():
    walk = list(_walk(_load_tasks('setup.yml')))
    requests = [task['ansible.builtin.set_fact']['ranking_baseline_request']
                for task in walk
                if isinstance(task.get('ansible.builtin.set_fact'), dict) and
                'ranking_baseline_request' in task['ansible.builtin.set_fact']]
    assert len(requests) == 1
    assert 'snapshot_sha256' not in str(requests[0]['value'])


def test_simulated_setup_persists_a_store_derived_baseline_digest():
    world = build_world()
    executor = RoleExecutor(world, ranking_variables('setup'))
    executor.run_file('main.yml')
    environment = world.agents[world.dut_host].state[DUT_RESOURCE]['env-a']
    stored = environment['baseline.json']
    assert set(stored) == {'schema_version', 'environment_id', 'resource',
                           'snapshot_identity', 'ports', 'snapshot_sha256'}
    assert stored['snapshot_sha256'] == _digest(environment['snapshot.json'])
    assert stored['snapshot_identity'] == environment['snapshot.json']['identity']


def test_collect_collected_state_requires_archived_outcome_json():
    tasks = list(_walk(_load_tasks('collect.yml')))
    collected = next(task['ansible.builtin.set_fact']['ranking_run_artifacts_collected']
                     for task in tasks if 'ranking_run_artifacts_collected' in task.get('ansible.builtin.set_fact', {}))
    assert 'ranking_collect_mandatory_names' in collected
    assert 'ranking_collect_flags' in collected
    assert 'ranking_collect_process_exited' in collected
    final = next(task['ansible.builtin.set_fact']['ranking_final_run_request']
                 for task in tasks if 'ranking_final_run_request' in task.get('ansible.builtin.set_fact', {}))
    assert final['value']['collected'] == '{{ ranking_run_artifacts_collected }}'


def test_simulated_unarchived_outcome_keeps_the_run_state_uncollected():
    world, _ = _chained_world()
    world.runner_outputs = False
    run = RoleExecutor(world, ranking_variables('run', case='sairoute.RouteA',
                                                run_id='run-a'))
    with pytest.raises(TaskFailure):
        run.run_file('main.yml')
    run_state = world.agents[world.ptf_host].state[PTF_RESOURCE]['env-a'][
        'run-state.json']
    assert run_state['phase'] != 'collected'
    assert run_state['collected'] is False
    record = json.loads(
        world.files['localhost']['/controller/artifacts/role-outcome.json'][0])
    assert record['collected']['outcome.json'] is False
    assert record['case_rc'] == 0


def test_role_conditions_compare_structures_without_ansible_json():
    for path in TASKS.glob('*.yml'):
        for task in _walk(yaml.safe_load(path.read_text())):
            for condition in (task.get('when'), task.get('failed_when')):
                clauses = condition if isinstance(condition, list) else [condition]
                for clause in clauses:
                    if clause is not None:
                        assert 'to_json' not in str(clause), (path.name, clause)
    assert 'to_json | hash' not in (TASKS / 'status.yml').read_text()


def test_simulated_teardown_tolerates_baseline_port_key_order():
    world = build_world()
    world.ports = {
        'Ethernet0': {'admin_state': 'up', 'oper_state': 'up', 'speed': '40000'},
        'Ethernet4': {'admin_state': 'up', 'oper_state': 'up', 'speed': '40000'},
    }
    setup = RoleExecutor(world, ranking_variables('setup'))
    setup.run_file('main.yml')
    world.ports = dict(reversed(list(world.ports.items())))
    teardown = RoleExecutor(world, ranking_variables('teardown'))
    teardown.run_file('main.yml')
    record = _outcome_record(world)
    assert record['restored'] is True
    assert record['released'] == [DUT_RESOURCE, PTF_RESOURCE]


def test_simulated_setup_records_the_canonical_ptf_peer_identity():
    world = build_world()
    executor = RoleExecutor(world, ranking_variables('setup'))
    executor.run_file('main.yml')
    environment = world.agents[world.dut_host].state[DUT_RESOURCE]['env-a'][
        'environment.json']
    assert environment['ptf_host_id'] == PTF_MACHINE
    assert environment['peer_resource'] == PTF_RESOURCE


def test_simulated_setup_outcome_reports_the_acquired_resources():
    world = build_world()
    executor = RoleExecutor(world, ranking_variables('setup'))
    executor.run_file('main.yml')
    record = _outcome_record(world)
    assert record['resources'] == [
        {'resource': DUT_RESOURCE, 'host': 'dut-a',
         'handle': {'resource': DUT_RESOURCE, 'environment_id': 'env-a',
                    'operation_id': 'op-a', 'created': True}},
        {'resource': PTF_RESOURCE, 'host': 'server-a',
         'handle': {'resource': PTF_RESOURCE, 'environment_id': 'env-a',
                    'operation_id': 'op-a', 'created': True}},
    ]


def test_snapshotless_setup_failure_can_release_unmodified_claims():
    world = build_world()
    world.docker.seed_container(world.dut_host, world.saiserver_name,
                                SAISERVER_IMAGE_ID, True)
    setup = RoleExecutor(world, ranking_variables('setup'))
    with pytest.raises(TaskFailure):
        setup.run_file('main.yml')
    assert world.systemctl_calls and all(call[1][1] == 'show' for call in world.systemctl_calls)
    assert world.agents[world.dut_host].owners[DUT_RESOURCE]['abortable']
    teardown = RoleExecutor(world, ranking_variables('teardown'))
    teardown.run_file('main.yml')
    assert all(not agent.owners for agent in world.agents.values())
    assert world.docker.is_running(world.dut_host, world.saiserver_name)
    assert not any(call['action'] == 'read' for call in teardown.agent_calls)


def test_rollback_refuses_a_container_without_matching_launcher_identity():
    world, setup = _chained_world()
    original = world.docker.containers[world.dut_host][world.saiserver_name]
    owned_id = original['Id']
    foreign_id = world.docker.seed_container(world.dut_host, world.saiserver_name,
                                             SAISERVER_IMAGE_ID, True)
    variables = dict(ranking_variables('setup'), item='start:saiserver')
    variables['ranking_dut_handle'] = {'resource': DUT_RESOURCE,
                                       'environment_id': 'env-a', 'operation_id': 'op-a', 'created': True}
    variables['ranking_saiserver_image_info_json'] = [{'Id': SAISERVER_IMAGE_ID}]
    variables['ranking_saiserver_start'] = {'stdout': owned_id, 'rc': 0}
    rollback = RoleExecutor(world, variables)
    with pytest.raises(TaskFailure, match='owned|identity|launcher'):
        rollback.run_file('rollback_marker.yml')
    container = world.docker.containers[world.dut_host][world.saiserver_name]
    assert container['Id'] == foreign_id
    assert container['State']['Running']


def test_active_recovery_cannot_teardown_a_case_between_reset_and_run_state():
    world, _ = _chained_world()
    requests = []

    class PausingRun(RoleExecutor):
        def _execute(self, task):
            result = super()._execute(task)
            if task.get('name') == 'Record the case saiserver container':
                container_id = world.docker.containers[world.dut_host][world.saiserver_name]['Id']
                variables = ranking_variables('teardown')
                variables['ranking_action_id'] = 'action-concurrent-recovery'
                recovery = RoleExecutor(world, variables)
                before = len(world.docker.calls)
                with pytest.raises(TaskFailure):
                    recovery.run_file('main.yml')
                assert not [call for call in world.docker.calls[before:]
                            if call[1][1] in ('stop', 'rm', 'run')]
                assert world.docker.containers[world.dut_host][world.saiserver_name]['Id'] == container_id
                assert world.docker.is_running(world.dut_host, world.saiserver_name)
                assert all(agent.owners for agent in world.agents.values())
                requests.append(recovery)
            return result
    run = PausingRun(world, ranking_variables('run', case='sairoute.RouteA', run_id='run-a'))
    run.run_file('main.yml')
    assert len(requests) == 1
    assert all(not agent.guards for agent in world.agents.values())
    teardown = RoleExecutor(world, ranking_variables('teardown'))
    teardown.run_file('main.yml')
    assert all(not agent.owners and not agent.guards for agent in world.agents.values())
