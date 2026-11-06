import errno
import os
import tarfile
import sys
from pathlib import Path

import pytest


class RecordingHost:
    def __init__(self, target='missing'):
        self.hostname = 'ptf-host'
        self.target = target
        self.commands = []
        self.shells = []
        self.copies = []

    def command(self, argv, module_ignore_errors=False, **kwargs):
        argv = tuple(argv)
        self.commands.append(argv)
        if argv[:5] == ('docker', 'exec', 'saiserverv2', 'python3', '-c'):
            script = argv[5]
            if 'TARGET_PROBE' in script:
                return _result({'missing': 3, 'directory': 0, 'other': 4}[self.target])
            if 'PUBLISH_CASES' in script:
                return _result(0, '{"status":"replaced"}\n' if self.target == 'directory'
                               else '{"status":"synchronized"}\n')
        return _result(0)

    def shell(self, **kwargs):
        self.shells.append(kwargs['cmd'])
        return _result(0)

    def copy(self, **kwargs):
        self.copies.append(kwargs)
        return {'changed': True, 'failed': False, 'dest': kwargs['dest']}


def _result(rc, stdout='', stderr=''):
    return {'rc': rc, 'stdout': stdout, 'stderr': stderr, 'failed': rc != 0}


def _context(tmp_path, host, force=False):
    cases = tmp_path / 'cases'
    ptf = cases / 'ptf'
    resources = ptf / 'resources'
    resources.mkdir(parents=True)
    (ptf / 'case.py').write_text('CASE = True\n')
    (resources / 'port_config.ini').write_text('upstream\n')
    (ptf / 'attr_map.json').write_text('{}\n')
    values = {
        'case_root': cases,
        'force_sync': force,
        'ptfhost': host,
    }
    return type('Context', (), values)()


def _description(tmp_path):
    overlay = tmp_path / 'profile-port-config.ini'
    overlay.write_text('profile\n')
    return {
        'case_sync': {
            'container': 'saiserverv2',
            'target': '/SAI-TEST/ptf',
            'overlays': ({
                'source': overlay,
                'target': 'resources/port_config.ini',
            },),
        },
    }


def test_existing_case_directory_is_successfully_skipped_with_warning(tmp_path):
    from tests.ranking.prepare.case_sync import sync_cases

    host = RecordingHost(target='directory')
    context = _context(tmp_path, host)

    with pytest.warns(pytest.PytestWarning, match='not compared.*force-sync'):
        result = sync_cases(context, _description(tmp_path))

    assert result['status'] == 'skipped'
    assert host.copies == []
    assert host.shells == []


def test_missing_target_is_synchronized_without_output_root(tmp_path):
    from tests.ranking.prepare.case_sync import sync_cases

    host = RecordingHost(target='missing')
    result = sync_cases(_context(tmp_path, host), _description(tmp_path))

    assert result['status'] == 'synchronized'
    assert len(host.copies) == 1
    assert len(host.shells) == 1


def test_force_sync_replaces_existing_target(tmp_path):
    from tests.ranking.prepare.case_sync import sync_cases

    host = RecordingHost(target='directory')
    result = sync_cases(
        _context(tmp_path, host, force=True), _description(tmp_path))

    assert result['status'] == 'replaced'
    assert len(host.copies) == 1
    assert len(host.shells) == 1


def test_non_directory_target_is_rejected(tmp_path):
    from tests.ranking.prepare.case_sync import sync_cases

    with pytest.raises(ValueError, match='not a directory'):
        sync_cases(
            _context(tmp_path, RecordingHost(target='other')),
            _description(tmp_path))


def test_archive_contains_case_tree_and_replaces_overlay(tmp_path):
    from tests.ranking.prepare.case_sync import _create_archive

    context = _context(tmp_path, RecordingHost())
    archive = tmp_path / 'cases.tar'
    overlays = _description(tmp_path)['case_sync']['overlays']

    _create_archive(context.case_root / 'ptf', overlays, archive)

    with tarfile.open(archive) as value:
        assert value.getnames().count('resources/port_config.ini') == 1
        assert value.extractfile('resources/port_config.ini').read() == b'profile\n'
        assert value.extractfile('case.py').read() == b'CASE = True\n'


def test_archive_rejects_symlinked_case_input(tmp_path):
    from tests.ranking.prepare.case_sync import _create_archive

    source = tmp_path / 'ptf'
    source.mkdir()
    outside = tmp_path / 'outside.py'
    outside.write_text('outside\n')
    (source / 'linked.py').symlink_to(outside)

    with pytest.raises(ValueError, match='symlink'):
        _create_archive(source, (), tmp_path / 'cases.tar')


def test_archive_rejects_unsafe_overlay_target(tmp_path):
    from tests.ranking.prepare.case_sync import _create_archive

    source = tmp_path / 'ptf'
    source.mkdir()
    overlay = tmp_path / 'overlay'
    overlay.write_text('data')

    with pytest.raises(ValueError, match='unsafe'):
        _create_archive(source, ({
            'source': overlay,
            'target': '../escape',
        },), tmp_path / 'cases.tar')


def test_publish_rolls_back_when_backup_cleanup_fails(tmp_path, monkeypatch):
    from tests.ranking.prepare.case_sync import PUBLISH_CASES

    target = tmp_path / 'ptf'
    target.mkdir()
    (target / 'version').write_text('old\n')
    source = tmp_path / 'new'
    source.mkdir()
    (source / 'version').write_text('new\n')
    archive = tmp_path / 'cases.tar'
    with tarfile.open(archive, 'w') as value:
        value.add(source / 'version', arcname='version')
    token = 'a' * 32
    real_rmtree = __import__('shutil').rmtree
    attempts = []

    def fail_backup_once(path, *args, **kwargs):
        attempts.append(str(path))
        if str(path).endswith('.backup-' + token) and attempts.count(str(path)) == 1:
            raise OSError('injected backup cleanup failure')
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr('shutil.rmtree', fail_backup_once)
    monkeypatch.setattr(sys, 'argv', [
        'publish', str(archive), str(target), token, '1'])

    with pytest.raises(OSError, match='injected'):
        exec(PUBLISH_CASES, {'__name__': '__main__'})

    assert (target / 'version').read_text() == 'old\n'
    assert not Path(str(target) + '.backup-' + token).exists()
    assert not Path(str(target) + '.prepare-' + token).exists()


def test_publish_replaces_overlayfs_target_when_directory_rename_is_exdev(
        tmp_path, monkeypatch):
    from tests.ranking.prepare.case_sync import PUBLISH_CASES

    target = tmp_path / 'ptf'
    target.mkdir()
    (target / 'version').write_text('old\n')
    source = tmp_path / 'new'
    source.mkdir()
    (source / 'version').write_text('new\n')
    archive = tmp_path / 'cases.tar'
    with tarfile.open(archive, 'w') as value:
        value.add(source / 'version', arcname='version')
    token = 'b' * 32
    backup = Path(str(target) + '.backup-' + token)
    real_rename = os.rename

    def overlayfs_rename(source_path, destination_path, *args, **kwargs):
        if Path(source_path) == target and Path(destination_path) == backup:
            raise OSError(errno.EXDEV, 'injected overlayfs cross-device rename')
        return real_rename(source_path, destination_path, *args, **kwargs)

    monkeypatch.setattr(os, 'rename', overlayfs_rename)
    monkeypatch.setattr(sys, 'argv', [
        'publish', str(archive), str(target), token, '1'])

    exec(PUBLISH_CASES, {'__name__': '__main__'})

    assert (target / 'version').read_text() == 'new\n'
    assert not backup.exists()
    assert not Path(str(target) + '.prepare-' + token).exists()
