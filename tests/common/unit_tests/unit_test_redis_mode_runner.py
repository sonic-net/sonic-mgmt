"""Exercise the real runner hooks with a fake pytest process and no DUTs."""
import os
from pathlib import Path
import re
import shlex
import subprocess

import pytest


FAKE_PYTEST = '''
import json, os, pathlib, sys, xml.etree.ElementTree as ET
action = os.environ['SONIC_REDIS_MODE_ACTION']
if action in ('prepare', 'restore'):
    assert '--skip_sanity' in sys.argv and '--disable_loganalyzer' in sys.argv
with open(os.environ['EVENTS'], 'a') as stream:
    stream.write(action + '\\n')
state = pathlib.Path(os.environ['SONIC_REDIS_MODE_STATE'])
if action == 'prepare' and os.environ.get('NO_STATE') != 'yes':
    state.write_text(json.dumps({'prepared': True}))
root = ET.Element('testsuite')
case = ET.SubElement(root, 'testcase', name=action)
if os.environ.get('SKIP_STAGE') == action:
    ET.SubElement(case, 'skipped')
path = next(value.split('=', 1)[1] for value in reversed(sys.argv) if value.startswith('--junitxml='))
ET.ElementTree(root).write(path)
sys.exit(9 if os.environ.get('FAIL_STAGE') == action else 0)
'''


def run_hook(tmp_path, mode='enforce', fail='', skip='', main_rc=0, signal=False, no_state=False):
    source = Path(__file__).resolve().parents[2] / 'run_tests.sh'
    text = source.read_text()
    functions = []
    for name in ('redis_mode_stage', 'redis_mode_acceptance', 'finish_redis_mode'):
        functions.append(re.search(r'function ' + name + r'\(\)\n\{.*?\n\}', text, re.S)[0])
    start = text.index('REDIS_PROTECTION_MODE=$(python3')
    end = text.index('\nif [[ x"${TEST_METHOD}"', start)
    fake = tmp_path / 'pytest.py'
    fake.write_text(FAKE_PYTEST)
    events = tmp_path / 'events'
    script = tmp_path / 'runner.sh'
    prelude = '\n'.join([
        'PYTEST_EXEC=' + shlex.quote('python3 ' + str(fake)),
        'SCRIPT_PATH=' + shlex.quote(str(source.parent)),
        'LOG_PATH=' + shlex.quote(str(tmp_path / 'logs')),
        'PYTEST_COMMON_OPTS=""', 'TEST_METHOD=group',
        'EXTRA_PARAMETERS=' + shlex.quote('--redis-protection-mode=' + mode if mode else '')])
    finish = 'kill -TERM $$' if signal else 'exit ' + str(main_rc)
    script.write_text(prelude + '\n' + '\n'.join(functions) + '\n' + text[start:end]
                      + '\necho main >> "$EVENTS"\n' + finish + '\n')
    env = dict(os.environ, EVENTS=str(events), FAIL_STAGE=fail, SKIP_STAGE=skip,
               NO_STATE='yes' if no_state else 'no')
    result = subprocess.run(['bash', str(script)], env=env, capture_output=True, text=True, timeout=30)
    return result, events.read_text().splitlines() if events.exists() else []


@pytest.mark.parametrize('mode', ['legacy', 'enforce'])
def test_acceptance_surrounds_suite_and_restore(tmp_path, mode):
    result, events = run_hook(tmp_path, mode)
    assert result.returncode == 0, result.stdout + result.stderr
    assert events == ['prepare', 'before', 'main', 'after', 'restore']


@pytest.mark.parametrize('main_rc', [0, 3])
def test_default_job_does_not_touch_redis(tmp_path, main_rc):
    result, events = run_hook(tmp_path, mode='', main_rc=main_rc)
    assert result.returncode == main_rc
    assert events == ['main']
    assert not (tmp_path / 'logs').exists()


@pytest.mark.parametrize('stage,expected,code', [
    ('prepare', ['prepare', 'restore'], 65),
    ('before', ['prepare', 'before', 'after', 'restore'], 65),
    ('after', ['prepare', 'before', 'main', 'after', 'restore'], 70),
    ('restore', ['prepare', 'before', 'main', 'after', 'restore'], 70),
])
def test_stage_failure_still_attempts_restore(tmp_path, stage, expected, code):
    result, events = run_hook(tmp_path, fail=stage)
    assert result.returncode == code, result.stdout + result.stderr
    assert events == expected


@pytest.mark.parametrize('stage', ['prepare', 'before', 'after', 'restore'])
def test_required_skips_fail_the_job(tmp_path, stage):
    result, events = run_hook(tmp_path, skip=stage)
    assert result.returncode != 0
    assert events[-1] == 'restore'


@pytest.mark.parametrize('signal,expected', [(False, 4), (True, 143)])
def test_suite_failure_or_term_preserves_exit_and_restores(tmp_path, signal, expected):
    result, events = run_hook(tmp_path, main_rc=4, signal=signal)
    assert result.returncode == expected
    assert events[-2:] == ['after', 'restore']


def test_missing_preparation_record_stops_before_suite(tmp_path):
    result, events = run_hook(tmp_path, no_state=True)
    assert result.returncode == 65
    assert events == ['prepare']
