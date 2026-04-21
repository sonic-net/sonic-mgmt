# Copyright (c) 2019-2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import os
import os.path
import socket as pysocket
import struct

from ansible_collections.community.docker.plugins.module_utils._six import PY2

from ansible_collections.community.docker.plugins.module_utils._api.utils import socket as docker_socket

from ansible_collections.community.docker.plugins.module_utils.socket_helper import (
    make_unblocking,
    shutdown_writing,
    write_to_socket,
)


PARAMIKO_POLL_TIMEOUT = 0.01  # 10 milliseconds


class DockerSocketHandlerBase(object):
    def __init__(self, sock, selectors, log=None):
        make_unblocking(sock)

        self._selectors = selectors
        if log is not None:
            self._log = log
        else:
            self._log = lambda msg: True
        self._paramiko_read_workaround = hasattr(sock, 'send_ready') and 'paramiko' in str(type(sock))

        self._sock = sock
        self._block_done_callback = None
        self._block_buffer = []
        self._eof = False
        self._read_buffer = b''
        self._write_buffer = b''
        self._end_of_writing = False

        self._current_stream = None
        self._current_missing = 0
        self._current_buffer = b''

        self._selector = self._selectors.DefaultSelector()
        self._selector.register(self._sock, self._selectors.EVENT_READ)

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        self._selector.close()

    def set_block_done_callback(self, block_done_callback):
        self._block_done_callback = block_done_callback
        if self._block_done_callback is not None:
            while self._block_buffer:
                elt = self._block_buffer.pop(0)
                self._block_done_callback(*elt)

    def _add_block(self, stream_id, data):
        if self._block_done_callback is not None:
            self._block_done_callback(stream_id, data)
        else:
            self._block_buffer.append((stream_id, data))

    def _read(self):
        if self._eof:
            return
        if hasattr(self._sock, 'recv'):
            try:
                data = self._sock.recv(262144)
            except Exception as e:
                # After calling self._sock.shutdown(), OpenSSL's/urllib3's
                # WrappedSocket seems to eventually raise ZeroReturnError in
                # case of EOF
                if 'OpenSSL.SSL.ZeroReturnError' in str(type(e)):
                    self._eof = True
                    return
                else:
                    raise
        elif not PY2 and isinstance(self._sock, getattr(pysocket, 'SocketIO')):
            data = self._sock.read()
        else:
            data = os.read(self._sock.fileno())
        if data is None:
            # no data available
            return
        self._log('read {0} bytes'.format(len(data)))
        if len(data) == 0:
            # Stream EOF
            self._eof = True
            return
        self._read_buffer += data
        while len(self._read_buffer) > 0:
            if self._current_missing > 0:
                n = min(len(self._read_buffer), self._current_missing)
                self._current_buffer += self._read_buffer[:n]
                self._read_buffer = self._read_buffer[n:]
                self._current_missing -= n
                if self._current_missing == 0:
                    self._add_block(self._current_stream, self._current_buffer)
                    self._current_buffer = b''
            if len(self._read_buffer) < 8:
                break
            self._current_stream, self._current_missing = struct.unpack('>BxxxL', self._read_buffer[:8])
            self._read_buffer = self._read_buffer[8:]
            if self._current_missing < 0:
                # Stream EOF (as reported by docker daemon)
                self._eof = True
                break

    def _handle_end_of_writing(self):
        if self._end_of_writing and len(self._write_buffer) == 0:
            self._end_of_writing = False
            self._log('Shutting socket down for writing')
            shutdown_writing(self._sock, self._log)

    def _write(self):
        if len(self._write_buffer) > 0:
            written = write_to_socket(self._sock, self._write_buffer)
            self._write_buffer = self._write_buffer[written:]
            self._log('wrote {0} bytes, {1} are left'.format(written, len(self._write_buffer)))
            if len(self._write_buffer) > 0:
                self._selector.modify(self._sock, self._selectors.EVENT_READ | self._selectors.EVENT_WRITE)
            else:
                self._selector.modify(self._sock, self._selectors.EVENT_READ)
            self._handle_end_of_writing()

    def select(self, timeout=None, _internal_recursion=False):
        if not _internal_recursion and self._paramiko_read_workaround and len(self._write_buffer) > 0:
            # When the SSH transport is used, Docker SDK for Python internally uses Paramiko, whose
            # Channel object supports select(), but only for reading
            # (https://github.com/paramiko/paramiko/issues/695).
            if self._sock.send_ready():
                self._write()
                return True
            while timeout is None or timeout > PARAMIKO_POLL_TIMEOUT:
                result = self.select(PARAMIKO_POLL_TIMEOUT, _internal_recursion=True)
                if self._sock.send_ready():
                    self._read()
                    result += 1
                if result > 0:
                    return True
                if timeout is not None:
                    timeout -= PARAMIKO_POLL_TIMEOUT
        self._log('select... ({0})'.format(timeout))
        events = self._selector.select(timeout)
        for key, event in events:
            if key.fileobj == self._sock:
                self._log(
                    'select event read:{0} write:{1}'.format(
                        event & self._selectors.EVENT_READ != 0,
                        event & self._selectors.EVENT_WRITE != 0))
                if event & self._selectors.EVENT_READ != 0:
                    self._read()
                if event & self._selectors.EVENT_WRITE != 0:
                    self._write()
        result = len(events)
        if self._paramiko_read_workaround and len(self._write_buffer) > 0:
            if self._sock.send_ready():
                self._write()
                result += 1
        return result > 0

    def is_eof(self):
        return self._eof

    def end_of_writing(self):
        self._end_of_writing = True
        self._handle_end_of_writing()

    def consume(self):
        stdout = []
        stderr = []

        def append_block(stream_id, data):
            if stream_id == docker_socket.STDOUT:
                stdout.append(data)
            elif stream_id == docker_socket.STDERR:
                stderr.append(data)
            else:
                raise ValueError('{0} is not a valid stream ID'.format(stream_id))

        self.end_of_writing()

        self.set_block_done_callback(append_block)
        while not self._eof:
            self.select()
        return b''.join(stdout), b''.join(stderr)

    def write(self, str):
        self._write_buffer += str
        if len(self._write_buffer) == len(str):
            self._write()


class DockerSocketHandlerModule(DockerSocketHandlerBase):
    def __init__(self, sock, module, selectors):
        super(DockerSocketHandlerModule, self).__init__(sock, selectors, module.debug)
