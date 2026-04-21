# Copyright (c) 2019-2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import fcntl
import os
import os.path
import socket as pysocket

from ansible_collections.community.docker.plugins.module_utils._six import PY2


def make_file_unblocking(file):
    fcntl.fcntl(file.fileno(), fcntl.F_SETFL, fcntl.fcntl(file.fileno(), fcntl.F_GETFL) | os.O_NONBLOCK)


def make_file_blocking(file):
    fcntl.fcntl(file.fileno(), fcntl.F_SETFL, fcntl.fcntl(file.fileno(), fcntl.F_GETFL) & ~os.O_NONBLOCK)


def make_unblocking(sock):
    if hasattr(sock, '_sock'):
        sock._sock.setblocking(0)
    elif hasattr(sock, 'setblocking'):
        sock.setblocking(0)
    else:
        make_file_unblocking(sock)


def _empty_writer(msg):
    pass


def shutdown_writing(sock, log=_empty_writer):
    # FIXME: This does **not work with SSLSocket**! Apparently SSLSocket does not allow to send
    #        a close_notify TLS alert without completely shutting down the connection.
    #        Calling sock.shutdown(pysocket.SHUT_WR) simply turns of TLS encryption and from that
    #        point on the raw encrypted data is returned when sock.recv() is called. :-(
    if hasattr(sock, 'shutdown_write'):
        sock.shutdown_write()
    elif hasattr(sock, 'shutdown'):
        try:
            sock.shutdown(pysocket.SHUT_WR)
        except TypeError as e:
            # probably: "TypeError: shutdown() takes 1 positional argument but 2 were given"
            log('Shutting down for writing not possible; trying shutdown instead: {0}'.format(e))
            sock.shutdown()
    elif not PY2 and isinstance(sock, getattr(pysocket, 'SocketIO')):
        sock._sock.shutdown(pysocket.SHUT_WR)
    else:
        log('No idea how to signal end of writing')


def write_to_socket(sock, data):
    if hasattr(sock, '_send_until_done'):
        # WrappedSocket (urllib3/contrib/pyopenssl) does not have `send`, but
        # only `sendall`, which uses `_send_until_done` under the hood.
        return sock._send_until_done(data)
    elif hasattr(sock, 'send'):
        return sock.send(data)
    else:
        return os.write(sock.fileno(), data)
