"""Save, activate and restore nonsecret Redis intent around one regression run."""
import base64
import json
import os
from pathlib import Path
import tempfile

INTENT = '/etc/sonic/redis-auth.json'
STARTUP = '/usr/bin/redis_auth_startup.py'
BUILD = '/usr/share/sonic/redis-auth/build-enabled'
POLICY = '/run/redis-auth/local.json'


def checked(dut, argv):
    result = dut.command(argv=argv, module_ignore_errors=True)
    if result['rc']:
        raise RuntimeError('{}: command failed: {}'.format(dut.hostname, ' '.join(argv)))
    return result['stdout'].strip()


def verify_mode(dut, expected):
    actual = checked(dut, [STARTUP, '--check'])
    if actual != expected:
        raise AssertionError('{}: expected Redis mode {}, got {}'.format(dut.hostname, expected, actual))
    published = dut.stat(path=POLICY)['stat']['exists']
    if published != (expected == 'enforce'):
        raise AssertionError('{}: Redis runtime policy disagrees with the requested mode'.format(dut.hostname))


def save_state(path, state):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.redis-mode-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(state, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def prepare(duts, reboot, path, mode, allow_tcp_exceptions=False):
    if mode not in ('legacy', 'enforce'):
        raise ValueError('Expected legacy or enforce')
    if not duts or len({dut.hostname for dut in duts}) != len(duts):
        raise ValueError('Expected a nonempty, distinct DUT inventory')
    if Path(path).exists():
        raise ValueError('Refusing to overwrite an existing Redis restoration record')
    state = {'mode': mode, 'hosts': {}}
    # Check and snapshot every DUT before changing any of them.
    for dut in duts:
        original_mode = checked(dut, [STARTUP, '--check'])
        if original_mode not in ('legacy', 'enforce'):
            raise ValueError('Unknown original Redis mode')
        verify_mode(dut, original_mode)
        info = dut.stat(path=INTENT, follow=False)['stat']
        original, intent = None, {}
        if info['exists']:
            if not info.get('isreg') or info['uid'] != 0 or int(info['mode'], 8) & 0o022:
                raise ValueError('Expected a regular root-controlled Redis intent file')
            original = base64.b64decode(dut.slurp(src=INTENT)['content']).decode('utf-8')
            intent = json.loads(original)
            if not isinstance(intent, dict) or set(intent) - {'mode', 'tcp_exceptions'}:
                raise ValueError('Unexpected Redis intent fields')
        if mode == 'enforce':
            if checked(dut, ['cat', BUILD]) != 'y':
                raise ValueError('Redis protection is not included in this image')
            if intent.get('tcp_exceptions') and not allow_tcp_exceptions:
                raise ValueError('TCP exceptions require an explicitly scoped acceptance run')
            checked(dut, ['python3', '-c',
                          'import sys; sys.path.insert(0, {!r}); import redis_auth_startup as s; '
                          's.check_topology(); s.configured_instances()'.format(str(Path(STARTUP).parent))])
        state['hosts'][dut.hostname] = {
            'original': original, 'original_mode': original_mode,
            'permissions': info.get('mode'), 'uid': info.get('uid'), 'gid': info.get('gid'),
            'intent': dict(intent, mode=mode), 'changed': False, 'restored': False}
    save_state(path, state)
    for dut in duts:
        entry = state['hosts'][dut.hostname]
        # Publish recovery information before the first possible mutation.
        entry['changed'] = True
        save_state(path, state)
        dut.copy(content=json.dumps(entry['intent']) + '\n', dest=INTENT,
                 owner='root', group='root', mode='0600')
        reboot(dut)
        verify_mode(dut, mode)
    state['prepared'] = True
    save_state(path, state)


def restore(duts, reboot, path):
    state = json.loads(Path(path).read_text())
    by_name = {dut.hostname: dut for dut in duts}
    if set(state['hosts']) != set(by_name):
        raise ValueError('Restoration DUTs do not match the saved testbed')
    errors = []
    for name, entry in state['hosts'].items():
        if not entry['changed']:
            continue
        dut = by_name[name]
        try:
            if not entry['restored']:
                if entry['original'] is None:
                    dut.file(path=INTENT, state='absent')
                else:
                    dut.copy(content=entry['original'], dest=INTENT, owner=str(entry['uid']),
                             group=str(entry['gid']), mode=entry['permissions'])
                reboot(dut)
            verify_mode(dut, entry['original_mode'])
            entry['restored'] = True
            save_state(path, state)
        except Exception as error:
            errors.append('{}: {}'.format(name, error))
    if errors:
        raise RuntimeError('Redis restoration failed; retain the testbed and state record: ' + '; '.join(errors))
