"""Exercise mode changes and recovery without using a lab DUT."""
import base64
import json
import pytest

from tests.common.plugins.redis_protection import control


class Dut:
    def __init__(self, name, original=None, events=None):
        self.hostname = name
        self.original = original
        self.content = original
        self.permissions = '0640'
        self.gid = 42
        self.uid = 0
        self.isreg = True
        self.mode = json.loads(original).get('mode', 'legacy') if original else 'legacy'
        self.policy = self.mode == 'enforce'
        self.build = 'y'
        self.supported = True
        self.events = events if events is not None else []
        self.fail_copy = False
        self.fail_reboot = False

    def command(self, argv, **kwargs):
        self.events.append((self.hostname, 'command', tuple(argv)))
        if argv == [control.STARTUP, '--check']:
            return dict(rc=0, stdout=self.mode)
        if argv == ['cat', control.BUILD]:
            return dict(rc=0, stdout=self.build)
        assert argv[:2] == ['python3', '-c']
        return dict(rc=0 if self.supported else 1, stdout='')

    def stat(self, path, **kwargs):
        if path == control.POLICY:
            return {'stat': {'exists': self.policy}}
        assert path == control.INTENT
        return {'stat': dict(exists=self.content is not None, isreg=self.isreg,
                             uid=self.uid, gid=self.gid, mode=self.permissions)}

    def slurp(self, src):
        assert src == control.INTENT, 'Only the nonsecret activation setting may leave the DUT'
        return {'content': base64.b64encode(self.content.encode()).decode()}

    def copy(self, content, dest, owner, group, mode):
        assert dest == control.INTENT
        self.events.append((self.hostname, 'copy'))
        if self.fail_copy:
            raise RuntimeError('copy failed')
        self.content = content
        self.permissions = mode
        self.uid, self.gid = int(owner) if owner != 'root' else 0, int(group) if group != 'root' else 0

    def file(self, path, state):
        assert path == control.INTENT and state == 'absent'
        self.events.append((self.hostname, 'remove'))
        self.content = None

    def reboot(self):
        self.events.append((self.hostname, 'reboot'))
        if self.fail_reboot:
            raise RuntimeError('reboot failed')
        self.mode = json.loads(self.content).get('mode', 'legacy') if self.content else 'legacy'
        self.policy = self.mode == 'enforce'


@pytest.mark.parametrize('mode', ['legacy', 'enforce'])
@pytest.mark.parametrize('original', [None, '{\n "mode": "legacy"\n}\n', '{"mode":"enforce"}\n'])
def test_change_and_exact_restoration(tmp_path, mode, original):
    dut = Dut('dut', original)
    path = tmp_path / 'state.json'
    original_permissions = dut.permissions
    control.prepare([dut], lambda d: d.reboot(), path, mode)
    assert dut.mode == mode
    assert json.loads(path.read_text())['prepared']
    assert path.stat().st_mode & 0o777 == 0o600
    control.restore([dut], lambda d: d.reboot(), path)
    assert dut.content == original
    if original is not None:
        assert (dut.permissions, dut.uid, dut.gid) == (original_permissions, 0, 42)
    assert json.loads(path.read_text())['hosts']['dut']['restored']
    count = dut.events.count(('dut', 'reboot'))
    control.restore([dut], lambda d: d.reboot(), path)
    assert dut.events.count(('dut', 'reboot')) == count


@pytest.mark.parametrize('fault', ['unsupported', 'disabled-build', 'policy-mismatch', 'unsafe-file', 'tcp-exception'])
def test_check_every_dut_before_mutation(tmp_path, fault):
    events = []
    first = Dut('first', events=events)
    second = Dut('second', '{"mode":"legacy"}', events)
    if fault == 'unsupported':
        second.supported = False
    elif fault == 'disabled-build':
        second.build = 'n'
    elif fault == 'policy-mismatch':
        second.policy = True
    elif fault == 'unsafe-file':
        second.permissions = '0666'
    else:
        second.content = '{"mode":"legacy","tcp_exceptions":["redis_bmp"]}'
    path = tmp_path / 'state.json'
    with pytest.raises((ValueError, RuntimeError, AssertionError)):
        control.prepare([first, second], lambda d: d.reboot(), path, 'enforce')
    assert not path.exists()
    assert not any(event[1] in ('copy', 'remove', 'reboot') for event in events)


def test_legacy_does_not_require_supported_enforcement(tmp_path):
    dut = Dut('dut')
    dut.supported = False
    control.prepare([dut], lambda d: d.reboot(), tmp_path / 'state.json', 'legacy')
    assert dut.mode == 'legacy'
    assert not any(event[1] == 'command' and event[2][0] == 'python3' for event in dut.events)


def test_preserve_reviewed_tcp_exceptions(tmp_path):
    original = '{"mode":"legacy","tcp_exceptions":["redis_bmp"]}'
    dut = Dut('dut', original)
    path = tmp_path / 'state.json'
    control.prepare([dut], lambda d: d.reboot(), path, 'enforce', allow_tcp_exceptions=True)
    assert json.loads(dut.content)['tcp_exceptions'] == ['redis_bmp']
    control.restore([dut], lambda d: d.reboot(), path)
    assert dut.content == original


@pytest.mark.parametrize('failure', ['copy', 'reboot', 'mode'])
def test_partial_setup_keeps_recovery_record(tmp_path, failure):
    dut = Dut('dut')
    path = tmp_path / 'state.json'
    dut.fail_copy = failure == 'copy'
    dut.fail_reboot = failure == 'reboot'
    reboot = (lambda d: None) if failure == 'mode' else (lambda d: d.reboot())
    with pytest.raises((RuntimeError, AssertionError)):
        control.prepare([dut], reboot, path, 'enforce')
    assert json.loads(path.read_text())['hosts']['dut']['changed']
    dut.fail_copy = dut.fail_reboot = False
    control.restore([dut], lambda d: d.reboot(), path)
    assert dut.content is None and dut.mode == 'legacy'


def test_restore_continues_other_duts_and_can_be_retried(tmp_path):
    first, second = Dut('first'), Dut('second')
    path = tmp_path / 'state.json'
    control.prepare([first, second], lambda d: d.reboot(), path, 'enforce')
    first.fail_reboot = True
    with pytest.raises(RuntimeError, match='retain the testbed'):
        control.restore([first, second], lambda d: d.reboot(), path)
    saved = json.loads(path.read_text())['hosts']
    assert not saved['first']['restored'] and saved['second']['restored']
    first.fail_reboot = False
    control.restore([first, second], lambda d: d.reboot(), path)
    assert all(entry['restored'] for entry in json.loads(path.read_text())['hosts'].values())


def test_reject_mismatched_restore_inventory_and_existing_record(tmp_path):
    dut = Dut('dut')
    path = tmp_path / 'state.json'
    control.prepare([dut], lambda d: d.reboot(), path, 'enforce')
    with pytest.raises(ValueError, match='existing'):
        control.prepare([dut], lambda d: d.reboot(), path, 'enforce')
    with pytest.raises(ValueError, match='do not match'):
        control.restore([Dut('different')], lambda d: d.reboot(), path)
    assert not json.loads(path.read_text())['hosts']['dut']['restored']


@pytest.mark.parametrize('duts', [[], [Dut('same'), Dut('same')]])
def test_reject_empty_or_duplicate_inventory(tmp_path, duts):
    with pytest.raises(ValueError, match='distinct'):
        control.prepare(duts, lambda d: d.reboot(), tmp_path / 'state.json', 'enforce')
