# Based on local.py (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
# Based on chroot.py (c) 2013, Maykel Moya <mmoya@speedyrails.com>
# (c) 2013, Michael Scherer <misc@zarb.org>
# (c) 2015, Toshio Kuratomi <tkuratomi@ansible.com>
# (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
---
author:
    - Jesse Pretorius (@odyssey4me) <jesse@odyssey4.me>
name: libvirt_qemu
short_description: Run tasks on libvirt/qemu virtual machines
description:
    - Run commands or put/fetch files to libvirt/qemu virtual machines using the qemu agent API.
notes:
    - Currently DOES NOT work with selinux set to enforcing in the VM.
    - Requires the qemu-agent installed in the VM.
    - Requires access to the qemu-ga commands guest-exec, guest-exec-status, guest-file-close, guest-file-open, guest-file-read, guest-file-write.
extends_documentation_fragment:
    - community.libvirt.requirements
version_added: "2.10.0"
options:
  remote_addr:
    description: Virtual machine name.
    default: inventory_hostname
    vars:
      - name: ansible_host
      - name: inventory_hostname
  executable:
    description:
      - Shell to use for execution inside container.
      - Set this to 'cmd' or 'powershell' for Windows VMs.
    default: /bin/sh
    vars:
      - name: ansible_shell_type
  virt_uri:
    description: Libvirt URI to connect to to access the virtual machine.
    default: qemu:///system
    vars:
      - name: ansible_libvirt_uri
"""

import base64
import json
import shlex
import time
import traceback

try:
    import libvirt
    import libvirt_qemu
except ImportError as imp_exc:
    LIBVIRT_IMPORT_ERROR = imp_exc
else:
    LIBVIRT_IMPORT_ERROR = None

from ansible.errors import AnsibleError, AnsibleConnectionFailure, AnsibleFileNotFound
from ansible.module_utils._text import to_bytes, to_native, to_text
from ansible.module_utils.six import raise_from
from ansible.plugins.connection import ConnectionBase, BUFSIZE
from ansible.plugins.shell.powershell import _parse_clixml
from ansible.utils.display import Display
from functools import partial
from os.path import exists

display = Display()


REQUIRED_CAPABILITIES = [
    {'enabled': True, 'name': 'guest-exec', 'success-response': True},
    {'enabled': True, 'name': 'guest-exec-status', 'success-response': True},
    {'enabled': True, 'name': 'guest-file-close', 'success-response': True},
    {'enabled': True, 'name': 'guest-file-open', 'success-response': True},
    {'enabled': True, 'name': 'guest-file-read', 'success-response': True},
    {'enabled': True, 'name': 'guest-file-write', 'success-response': True}
]


class Connection(ConnectionBase):
    ''' Local libvirt qemu based connections '''

    transport = 'community.libvirt.libvirt_qemu'
    # TODO(odyssey4me):
    # Figure out why pipelining does not work and fix it
    has_pipelining = False
    has_tty = False

    def __init__(self, play_context, new_stdin, *args, **kwargs):
        if LIBVIRT_IMPORT_ERROR:
            raise_from(
                AnsibleError('libvirt python bindings must be installed to use this plugin'),
                LIBVIRT_IMPORT_ERROR)

        super(Connection, self).__init__(play_context, new_stdin, *args, **kwargs)

        self._host = self._play_context.remote_addr

        # Windows operates differently from a POSIX connection/shell plugin,
        # we need to set various properties to ensure SSH on Windows continues
        # to work
        # Ensure that any Windows hosts in your inventory have one of the
        # following set, in order to trigger this code:
        # ansible_shell_type: cmd
        # ansible_shell_type: powershell
        if getattr(self._shell, "_IS_WINDOWS", False):
            self.has_native_async = True
            self.always_pipeline_modules = True
            self.module_implementation_preferences = ('.ps1', '.exe', '')
            self.allow_executable = False

    def _connect(self):
        ''' connect to the virtual machine; nothing to do here '''
        super(Connection, self)._connect()
        if not self._connected:

            self._virt_uri = self.get_option('virt_uri')

            self._display.vvv(u"CONNECT TO {0}".format(self._virt_uri), host=self._host)
            try:
                self.conn = libvirt.open(self._virt_uri)
            except libvirt.libvirtError as err:
                raise AnsibleConnectionFailure(to_native(err))

            self._display.vvv(u"FIND DOMAIN {0}".format(self._host), host=self._host)
            try:
                self.domain = self.conn.lookupByName(self._host)
            except libvirt.libvirtError as err:
                raise AnsibleConnectionFailure(to_native(err))

            request_cap = json.dumps({'execute': 'guest-info'})
            response_cap = json.loads(libvirt_qemu.qemuAgentCommand(self.domain, request_cap, 5, 0))
            self.capabilities = response_cap['return']['supported_commands']
            self._display.vvvvv(u"GUEST CAPABILITIES: {0}".format(self.capabilities), host=self._host)
            missing_caps = []
            for cap in REQUIRED_CAPABILITIES:
                if cap not in self.capabilities:
                    missing_caps.append(cap['name'])
            if len(missing_caps) > 0:
                self._display.vvv(u"REQUIRED CAPABILITIES MISSING: {0}".format(missing_caps), host=self._host)
                raise AnsibleConnectionFailure('Domain does not have required capabilities')

            display.vvv(u"ESTABLISH {0} CONNECTION".format(self.transport), host=self._host)
            self._connected = True

    def exec_command(self, cmd, in_data=None, sudoable=True):
        """ execute a command on the virtual machine host """
        super(Connection, self).exec_command(cmd, in_data=in_data, sudoable=sudoable)

        self._display.vvv(u"EXEC {0}".format(cmd), host=self._host)

        cmd_args_list = shlex.split(to_native(cmd, errors='surrogate_or_strict'))

        if getattr(self._shell, "_IS_WINDOWS", False):
            # Become method 'runas' is done in the wrapper that is executed,
            # need to disable sudoable so the bare_run is not waiting for a
            # prompt that will not occur
            sudoable = False

            # Make sure our first command is to set the console encoding to
            # utf-8, this must be done via chcp to get utf-8 (65001)
            cmd = ' '.join(["chcp.com", "65001", self._shell._SHELL_REDIRECT_ALLNULL, self._shell._SHELL_AND, cmd])

            # Generate powershell commands
            cmd_args_list = self._shell._encode_script(cmd, as_list=True, strict_mode=False, preserve_rc=False)

        # TODO(odyssey4me):
        # Implement buffering much like the other connection plugins
        # Implement 'env' for the environment settings
        # Implement 'input-data' for whatever it might be useful for
        request_exec = {
            'execute': 'guest-exec',
            'arguments': {
                'path': cmd_args_list[0],
                'capture-output': True,
                'arg': cmd_args_list[1:]
            }
        }
        request_exec_json = json.dumps(request_exec)

        display.vvv(u"GA send: {0}".format(request_exec_json), host=self._host)

        # TODO(odyssey4me):
        # Add timeout parameter
        result_exec = json.loads(libvirt_qemu.qemuAgentCommand(self.domain, request_exec_json, 5, 0))

        display.vvv(u"GA return: {0}".format(result_exec), host=self._host)

        command_start = time.clock_gettime(time.CLOCK_MONOTONIC)

        request_status = {
            'execute': 'guest-exec-status',
            'arguments': {
                'pid': result_exec['return']['pid']
            }
        }
        request_status_json = json.dumps(request_status)

        display.vvv(u"GA send: {0}".format(request_status_json), host=self._host)

        # TODO(odyssey4me):
        # Work out a better way to wait until the command has exited
        result_status = json.loads(libvirt_qemu.qemuAgentCommand(self.domain, request_status_json, 5, 0))

        display.vvv(u"GA return: {0}".format(result_status), host=self._host)

        while not result_status['return']['exited']:
            # Wait for 5% of the time already elapsed
            sleep_time = (time.clock_gettime(time.CLOCK_MONOTONIC) - command_start) * (5 / 100)
            if sleep_time < 0.0002:
                sleep_time = 0.0002
            elif sleep_time > 1:
                sleep_time = 1
            time.sleep(sleep_time)
            result_status = json.loads(libvirt_qemu.qemuAgentCommand(self.domain, request_status_json, 5, 0))

        display.vvv(u"GA return: {0}".format(result_status), host=self._host)

        if result_status['return'].get('out-data'):
            stdout = base64.b64decode(result_status['return']['out-data'])
        else:
            stdout = b''

        if result_status['return'].get('err-data'):
            stderr = base64.b64decode(result_status['return']['err-data'])
        else:
            stderr = b''

        # Decode xml from windows
        if getattr(self._shell, "_IS_WINDOWS", False) and stdout.startswith(b"#< CLIXML"):
            stdout = _parse_clixml(stdout)

        display.vvv(u"GA stdout: {0}".format(to_text(stdout)), host=self._host)
        display.vvv(u"GA stderr: {0}".format(to_text(stderr)), host=self._host)

        return result_status['return']['exitcode'], stdout, stderr

    def put_file(self, in_path, out_path):
        ''' transfer a file from local to domain '''
        super(Connection, self).put_file(in_path, out_path)
        display.vvv("PUT %s TO %s" % (in_path, out_path), host=self._host)

        if not exists(to_bytes(in_path, errors='surrogate_or_strict')):
            raise AnsibleFileNotFound(
                "file or module does not exist: %s" % in_path)

        request_handle = {
            'execute': 'guest-file-open',
            'arguments': {
                'path': out_path,
                'mode': 'wb+'
            }
        }
        request_handle_json = json.dumps(request_handle)

        display.vvv(u"GA send: {0}".format(request_handle_json), host=self._host)

        result_handle = json.loads(libvirt_qemu.qemuAgentCommand(self.domain, request_handle_json, 5, 0))

        display.vvv(u"GA return: {0}".format(result_handle), host=self._host)

        # TODO(odyssey4me):
        # Handle exception for file/path IOError
        with open(to_bytes(in_path, errors='surrogate_or_strict'), 'rb') as in_file:
            for chunk in iter(partial(in_file.read, BUFSIZE), b''):
                try:
                    request_write = {
                        'execute': 'guest-file-write',
                        'arguments': {
                            'handle': result_handle['return'],
                            'buf-b64': base64.b64encode(chunk).decode()
                        }
                    }
                    request_write_json = json.dumps(request_write)

                    display.vvvvv(u"GA send: {0}".format(request_write_json), host=self._host)

                    result_write = json.loads(libvirt_qemu.qemuAgentCommand(self.domain, request_write_json, 5, 0))

                    display.vvvvv(u"GA return: {0}".format(result_write), host=self._host)

                except Exception:
                    traceback.print_exc()
                    raise AnsibleError("failed to transfer file %s to %s" % (in_path, out_path))

        request_close = {
            'execute': 'guest-file-close',
            'arguments': {
                'handle': result_handle['return']
            }
        }
        request_close_json = json.dumps(request_close)

        display.vvv(u"GA send: {0}".format(request_close_json), host=self._host)

        result_close = json.loads(libvirt_qemu.qemuAgentCommand(self.domain, request_close_json, 5, 0))

        display.vvv(u"GA return: {0}".format(result_close), host=self._host)

    def fetch_file(self, in_path, out_path):
        ''' fetch a file from domain to local '''
        super(Connection, self).fetch_file(in_path, out_path)
        display.vvv("FETCH %s TO %s" % (in_path, out_path), host=self._host)

        request_handle = {
            'execute': 'guest-file-open',
            'arguments': {
                'path': in_path,
                'mode': 'r'
            }
        }
        request_handle_json = json.dumps(request_handle)

        display.vvv(u"GA send: {0}".format(request_handle_json), host=self._host)

        result_handle = json.loads(libvirt_qemu.qemuAgentCommand(self.domain, request_handle_json, 5, 0))

        display.vvv(u"GA return: {0}".format(result_handle), host=self._host)

        request_read = {
            'execute': 'guest-file-read',
            'arguments': {
                'handle': result_handle['return'],
                'count': BUFSIZE
            }
        }
        request_read_json = json.dumps(request_read)

        display.vvv(u"GA send: {0}".format(request_read_json), host=self._host)

        with open(to_bytes(out_path, errors='surrogate_or_strict'), 'wb+') as out_file:
            try:
                result_read = json.loads(libvirt_qemu.qemuAgentCommand(self.domain, request_read_json, 5, 0))
                display.vvvvv(u"GA return: {0}".format(result_read), host=self._host)
                out_file.write(base64.b64decode(result_read['return']['buf-b64']))
                while not result_read['return']['eof']:
                    result_read = json.loads(libvirt_qemu.qemuAgentCommand(self.domain, request_read_json, 5, 0))
                    display.vvvvv(u"GA return: {0}".format(result_read), host=self._host)
                    out_file.write(base64.b64decode(result_read['return']['buf-b64']))

            except Exception:
                traceback.print_exc()
                raise AnsibleError("failed to transfer file %s to %s" % (in_path, out_path))

        request_close = {
            'execute': 'guest-file-close',
            'arguments': {
                'handle': result_handle['return']
            }
        }
        request_close_json = json.dumps(request_close)

        display.vvv(u"GA send: {0}".format(request_close_json), host=self._host)

        result_close = json.loads(libvirt_qemu.qemuAgentCommand(self.domain, request_close_json, 5, 0))

        display.vvv(u"GA return: {0}".format(result_close), host=self._host)

    def close(self):
        ''' terminate the connection; nothing to do here '''
        super(Connection, self).close()
        self._connected = False
