# Copyright 2016 Red Hat | Ansible
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import datetime
import io
import json
import os
import os.path
import shutil
import stat
import tarfile

from ansible.module_utils.common.text.converters import to_bytes, to_native, to_text
from ansible_collections.community.docker.plugins.module_utils._six import raise_from

from ansible_collections.community.docker.plugins.module_utils._api.errors import APIError, NotFound


class DockerFileCopyError(Exception):
    pass


class DockerUnexpectedError(DockerFileCopyError):
    pass


class DockerFileNotFound(DockerFileCopyError):
    pass


def _put_archive(client, container, path, data):
    # data can also be file object for streaming. This is because _put uses requests's put().
    # See https://requests.readthedocs.io/en/latest/user/advanced/#streaming-uploads
    url = client._url('/containers/{0}/archive', container)
    res = client._put(url, params={'path': path}, data=data)
    client._raise_for_status(res)
    return res.status_code == 200


def _symlink_tar_creator(b_in_path, file_stat, out_file, user_id, group_id, mode=None, user_name=None):
    if not stat.S_ISLNK(file_stat.st_mode):
        raise DockerUnexpectedError('stat information is not for a symlink')
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode='w|', dereference=False, encoding='utf-8') as tar:
        # Note that without both name (bytes) and arcname (unicode), this either fails for
        # Python 2.7, Python 3.5/3.6, or Python 3.7+. Only when passing both (in this
        # form) it works with Python 2.7, 3.5, 3.6, and 3.7 up to 3.11
        tarinfo = tar.gettarinfo(b_in_path, arcname=to_text(out_file))
        tarinfo.uid = user_id
        tarinfo.uname = ''
        if user_name:
            tarinfo.uname = user_name
        tarinfo.gid = group_id
        tarinfo.gname = ''
        tarinfo.mode &= 0o700
        if mode is not None:
            tarinfo.mode = mode
        if not tarinfo.issym():
            raise DockerUnexpectedError('stat information is not for a symlink')
        tar.addfile(tarinfo)
    return bio.getvalue()


def _symlink_tar_generator(b_in_path, file_stat, out_file, user_id, group_id, mode=None, user_name=None):
    yield _symlink_tar_creator(b_in_path, file_stat, out_file, user_id, group_id, mode, user_name)


def _regular_file_tar_generator(b_in_path, file_stat, out_file, user_id, group_id, mode=None, user_name=None):
    if not stat.S_ISREG(file_stat.st_mode):
        raise DockerUnexpectedError('stat information is not for a regular file')
    tarinfo = tarfile.TarInfo()
    tarinfo.name = os.path.splitdrive(to_text(out_file))[1].replace(os.sep, '/').lstrip('/')
    tarinfo.mode = (file_stat.st_mode & 0o700) if mode is None else mode
    tarinfo.uid = user_id
    tarinfo.gid = group_id
    tarinfo.size = file_stat.st_size
    tarinfo.mtime = file_stat.st_mtime
    tarinfo.type = tarfile.REGTYPE
    tarinfo.linkname = ''
    if user_name:
        tarinfo.uname = user_name

    tarinfo_buf = tarinfo.tobuf()
    total_size = len(tarinfo_buf)
    yield tarinfo_buf

    size = tarinfo.size
    total_size += size
    with open(b_in_path, 'rb') as f:
        while size > 0:
            to_read = min(size, 65536)
            buf = f.read(to_read)
            if not buf:
                break
            size -= len(buf)
            yield buf
    if size:
        # If for some reason the file shrunk, fill up to the announced size with zeros.
        # (If it enlarged, ignore the remainder.)
        yield tarfile.NUL * size

    remainder = tarinfo.size % tarfile.BLOCKSIZE
    if remainder:
        # We need to write a multiple of 512 bytes. Fill up with zeros.
        yield tarfile.NUL * (tarfile.BLOCKSIZE - remainder)
        total_size += tarfile.BLOCKSIZE - remainder

    # End with two zeroed blocks
    yield tarfile.NUL * (2 * tarfile.BLOCKSIZE)
    total_size += 2 * tarfile.BLOCKSIZE

    remainder = total_size % tarfile.RECORDSIZE
    if remainder > 0:
        yield tarfile.NUL * (tarfile.RECORDSIZE - remainder)


def _regular_content_tar_generator(content, out_file, user_id, group_id, mode, user_name=None):
    tarinfo = tarfile.TarInfo()
    tarinfo.name = os.path.splitdrive(to_text(out_file))[1].replace(os.sep, '/').lstrip('/')
    tarinfo.mode = mode
    tarinfo.uid = user_id
    tarinfo.gid = group_id
    tarinfo.size = len(content)
    try:
        tarinfo.mtime = int(datetime.datetime.now().timestamp())
    except AttributeError:
        # Python 2 (or more precisely: Python < 3.3) has no timestamp(). Use the following
        # expression for Python 2:
        tarinfo.mtime = int((datetime.datetime.utcnow() - datetime.datetime(1970, 1, 1)).total_seconds())
    tarinfo.type = tarfile.REGTYPE
    tarinfo.linkname = ''
    if user_name:
        tarinfo.uname = user_name

    tarinfo_buf = tarinfo.tobuf()
    total_size = len(tarinfo_buf)
    yield tarinfo_buf

    total_size += len(content)
    yield content

    remainder = tarinfo.size % tarfile.BLOCKSIZE
    if remainder:
        # We need to write a multiple of 512 bytes. Fill up with zeros.
        yield tarfile.NUL * (tarfile.BLOCKSIZE - remainder)
        total_size += tarfile.BLOCKSIZE - remainder

    # End with two zeroed blocks
    yield tarfile.NUL * (2 * tarfile.BLOCKSIZE)
    total_size += 2 * tarfile.BLOCKSIZE

    remainder = total_size % tarfile.RECORDSIZE
    if remainder > 0:
        yield tarfile.NUL * (tarfile.RECORDSIZE - remainder)


def put_file(client, container, in_path, out_path, user_id, group_id, mode=None, user_name=None, follow_links=False):
    """Transfer a file from local to Docker container."""
    if not os.path.exists(to_bytes(in_path, errors='surrogate_or_strict')):
        raise DockerFileNotFound(
            "file or module does not exist: %s" % to_native(in_path))

    b_in_path = to_bytes(in_path, errors='surrogate_or_strict')

    out_dir, out_file = os.path.split(out_path)

    if follow_links:
        file_stat = os.stat(b_in_path)
    else:
        file_stat = os.lstat(b_in_path)

    if stat.S_ISREG(file_stat.st_mode):
        stream = _regular_file_tar_generator(b_in_path, file_stat, out_file, user_id, group_id, mode=mode, user_name=user_name)
    elif stat.S_ISLNK(file_stat.st_mode):
        stream = _symlink_tar_generator(b_in_path, file_stat, out_file, user_id, group_id, mode=mode, user_name=user_name)
    else:
        raise DockerFileCopyError(
            'File{0} {1} is neither a regular file nor a symlink (stat mode {2}).'.format(
                ' referenced by' if follow_links else '', in_path, oct(file_stat.st_mode)))

    ok = _put_archive(client, container, out_dir, stream)
    if not ok:
        raise DockerUnexpectedError('Unknown error while creating file "{0}" in container "{1}".'.format(out_path, container))


def put_file_content(client, container, content, out_path, user_id, group_id, mode, user_name=None):
    """Transfer a file from local to Docker container."""
    out_dir, out_file = os.path.split(out_path)

    stream = _regular_content_tar_generator(content, out_file, user_id, group_id, mode, user_name=user_name)

    ok = _put_archive(client, container, out_dir, stream)
    if not ok:
        raise DockerUnexpectedError('Unknown error while creating file "{0}" in container "{1}".'.format(out_path, container))


def stat_file(client, container, in_path, follow_links=False, log=None):
    """Fetch information on a file from a Docker container to local.

    Return a tuple ``(path, stat_data, link_target)`` where:

    :path: is the resolved path in case ``follow_links=True``;
    :stat_data: is ``None`` if the file does not exist, or a dictionary with fields
        ``name`` (string), ``size`` (integer), ``mode`` (integer, see https://pkg.go.dev/io/fs#FileMode),
        ``mtime`` (string), and ``linkTarget`` (string);
    :link_target: is ``None`` if the file is not a symlink or when ``follow_links=False``,
        and a string with the symlink target otherwise.
    """
    considered_in_paths = set()

    while True:
        if in_path in considered_in_paths:
            raise DockerFileCopyError('Found infinite symbolic link loop when trying to stating "{0}"'.format(in_path))
        considered_in_paths.add(in_path)

        if log:
            log('FETCH: Stating "%s"' % in_path)

        response = client._head(
            client._url('/containers/{0}/archive', container),
            params={'path': in_path},
        )
        if response.status_code == 404:
            return in_path, None, None
        client._raise_for_status(response)
        header = response.headers.get('x-docker-container-path-stat')
        try:
            stat_data = json.loads(base64.b64decode(header))
        except Exception as exc:
            raise DockerUnexpectedError(
                'When retrieving information for {in_path} from {container}, obtained header {header!r} that cannot be loaded as JSON: {exc}'
                .format(in_path=in_path, container=container, header=header, exc=exc)
            )

        # https://pkg.go.dev/io/fs#FileMode: bit 32 - 5 means ModeSymlink
        if stat_data['mode'] & (1 << (32 - 5)) != 0:
            link_target = stat_data['linkTarget']
            if not follow_links:
                return in_path, stat_data, link_target
            in_path = os.path.join(os.path.split(in_path)[0], link_target)
            continue

        return in_path, stat_data, None


class _RawGeneratorFileobj(io.RawIOBase):
    def __init__(self, stream):
        self._stream = stream
        self._buf = b''

    def readable(self):
        return True

    def _readinto_from_buf(self, b, index, length):
        cpy = min(length - index, len(self._buf))
        if cpy:
            b[index:index + cpy] = self._buf[:cpy]
            self._buf = self._buf[cpy:]
            index += cpy
        return index

    def readinto(self, b):
        index = 0
        length = len(b)

        index = self._readinto_from_buf(b, index, length)
        if index == length:
            return index

        try:
            self._buf += next(self._stream)
        except StopIteration:
            return index

        return self._readinto_from_buf(b, index, length)


def _stream_generator_to_fileobj(stream):
    '''Given a generator that generates chunks of bytes, create a readable buffered stream.'''
    raw = _RawGeneratorFileobj(stream)
    return io.BufferedReader(raw)


def fetch_file_ex(client, container, in_path, process_none, process_regular, process_symlink, process_other, follow_links=False, log=None):
    """Fetch a file (as a tar file entry) from a Docker container to local."""
    considered_in_paths = set()

    while True:
        if in_path in considered_in_paths:
            raise DockerFileCopyError('Found infinite symbolic link loop when trying to fetch "{0}"'.format(in_path))
        considered_in_paths.add(in_path)

        if log:
            log('FETCH: Fetching "%s"' % in_path)
        try:
            stream = client.get_raw_stream(
                '/containers/{0}/archive', container,
                params={'path': in_path},
                headers={'Accept-Encoding': 'identity'},
            )
        except NotFound:
            return process_none(in_path)

        with tarfile.open(fileobj=_stream_generator_to_fileobj(stream), mode='r|') as tar:
            symlink_member = None
            result = None
            found = False
            for member in tar:
                if found:
                    raise DockerUnexpectedError('Received tarfile contains more than one file!')
                found = True
                if member.issym():
                    symlink_member = member
                    continue
                if member.isfile():
                    result = process_regular(in_path, tar, member)
                    continue
                result = process_other(in_path, member)
            if symlink_member:
                if not follow_links:
                    return process_symlink(in_path, symlink_member)
                in_path = os.path.join(os.path.split(in_path)[0], symlink_member.linkname)
                if log:
                    log('FETCH: Following symbolic link to "%s"' % in_path)
                continue
            if found:
                return result
            raise DockerUnexpectedError('Received tarfile is empty!')


def fetch_file(client, container, in_path, out_path, follow_links=False, log=None):
    b_out_path = to_bytes(out_path, errors='surrogate_or_strict')

    def process_none(in_path):
        raise DockerFileNotFound(
            'File {in_path} does not exist in container {container}'
            .format(in_path=in_path, container=container)
        )

    def process_regular(in_path, tar, member):
        if not follow_links and os.path.exists(b_out_path):
            os.unlink(b_out_path)

        in_f = tar.extractfile(member)  # in Python 2, this *cannot* be used in `with`...
        with open(b_out_path, 'wb') as out_f:
            shutil.copyfileobj(in_f, out_f)
        return in_path

    def process_symlink(in_path, member):
        if os.path.exists(b_out_path):
            os.unlink(b_out_path)

        os.symlink(member.linkname, b_out_path)
        return in_path

    def process_other(in_path, member):
        raise DockerFileCopyError('Remote file "%s" is not a regular file or a symbolic link' % in_path)

    return fetch_file_ex(client, container, in_path, process_none, process_regular, process_symlink, process_other, follow_links=follow_links, log=log)


def _execute_command(client, container, command, log=None, check_rc=False):
    if log:
        log('Executing {command} in {container}'.format(command=command, container=container))

    data = {
        'Container': container,
        'User': '',
        'Privileged': False,
        'Tty': False,
        'AttachStdin': False,
        'AttachStdout': True,
        'AttachStderr': True,
        'Cmd': command,
    }

    if 'detachKeys' in client._general_configs:
        data['detachKeys'] = client._general_configs['detachKeys']

    try:
        exec_data = client.post_json_to_json('/containers/{0}/exec', container, data=data)
    except NotFound as e:
        raise_from(
            DockerFileCopyError('Could not find container "{container}"'.format(container=container)),
            e,
        )
    except APIError as e:
        if e.response is not None and e.response.status_code == 409:
            raise_from(
                DockerFileCopyError('Cannot execute command in paused container "{container}"'.format(container=container)),
                e,
            )
        raise
    exec_id = exec_data['Id']

    data = {
        'Tty': False,
        'Detach': False
    }
    stdout, stderr = client.post_json_to_stream('/exec/{0}/start', exec_id, stream=False, demux=True, tty=False)

    result = client.get_json('/exec/{0}/json', exec_id)

    rc = result.get('ExitCode') or 0
    stdout = stdout or b''
    stderr = stderr or b''

    if log:
        log('Exit code {rc}, stdout {stdout!r}, stderr {stderr!r}'.format(rc=rc, stdout=stdout, stderr=stderr))

    if check_rc and rc != 0:
        raise DockerUnexpectedError(
            'Obtained unexpected exit code {rc} when running "{command}" in {container}.\nSTDOUT: {stdout}\nSTDERR: {stderr}'
            .format(command=' '.join(command), container=container, rc=rc, stdout=stdout, stderr=stderr)
        )

    return rc, stdout, stderr


def determine_user_group(client, container, log=None):
    dummy, stdout, stderr = _execute_command(client, container, ['/bin/sh', '-c', 'id -u && id -g'], check_rc=True, log=log)

    stdout_lines = stdout.splitlines()
    if len(stdout_lines) != 2:
        raise DockerUnexpectedError(
            'Expected two-line output to obtain user and group ID for container {container}, but got {lc} lines:\n{stdout}'
            .format(container=container, lc=len(stdout_lines), stdout=stdout)
        )

    user_id, group_id = stdout_lines
    try:
        return int(user_id), int(group_id)
    except ValueError:
        raise DockerUnexpectedError(
            'Expected two-line output with numeric IDs to obtain user and group ID for container {container}, but got "{l1}" and "{l2}" instead'
            .format(container=container, l1=user_id, l2=group_id)
        )
