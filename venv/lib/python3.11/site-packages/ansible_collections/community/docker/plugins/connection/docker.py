# Based on the chroot connection plugin by Maykel Moya
#
# (c) 2014, Lorin Hochstein
# (c) 2015, Leendert Brouwer (https://github.com/objectified)
# (c) 2015, Toshio Kuratomi <tkuratomi@ansible.com>
# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
author:
  - Lorin Hochestein (!UNKNOWN)
  - Leendert Brouwer (!UNKNOWN)
name: docker
short_description: Run tasks in docker containers
description:
  - Run commands or put/fetch files to an existing docker container.
  - Uses the Docker CLI to execute commands in the container. If you prefer to directly connect to the Docker daemon, use
    the P(community.docker.docker_api#connection) connection plugin.
options:
  remote_addr:
    description:
      - The name of the container you want to access.
    default: inventory_hostname
    vars:
      - name: inventory_hostname
      - name: ansible_host
      - name: ansible_docker_host
  remote_user:
    description:
      - The user to execute as inside the container.
      - If Docker is too old to allow this (< 1.7), the one set by Docker itself will be used.
    vars:
      - name: ansible_user
      - name: ansible_docker_user
    ini:
      - section: defaults
        key: remote_user
    env:
      - name: ANSIBLE_REMOTE_USER
    cli:
      - name: user
    keyword:
      - name: remote_user
  docker_extra_args:
    description:
      - Extra arguments to pass to the docker command line.
    default: ''
    vars:
      - name: ansible_docker_extra_args
    ini:
      - section: docker_connection
        key: extra_cli_args
  container_timeout:
    default: 10
    description:
      - Controls how long we can wait to access reading output from the container once execution started.
    env:
      - name: ANSIBLE_TIMEOUT
      - name: ANSIBLE_DOCKER_TIMEOUT
        version_added: 2.2.0
    ini:
      - key: timeout
        section: defaults
      - key: timeout
        section: docker_connection
        version_added: 2.2.0
    vars:
      - name: ansible_docker_timeout
        version_added: 2.2.0
    cli:
      - name: timeout
    type: integer
  extra_env:
    description:
      - Provide extra environment variables to set when running commands in the Docker container.
      - This option can currently only be provided as Ansible variables due to limitations of ansible-core's configuration
        manager.
    vars:
      - name: ansible_docker_extra_env
    type: dict
    version_added: 3.12.0
  working_dir:
    description:
      - The directory inside the container to run commands in.
      - Requires Docker CLI version 18.06 or later.
    env:
      - name: ANSIBLE_DOCKER_WORKING_DIR
    ini:
      - key: working_dir
        section: docker_connection
    vars:
      - name: ansible_docker_working_dir
    type: string
    version_added: 3.12.0
  privileged:
    description:
      - Whether commands should be run with extended privileges.
      - B(Note) that this allows command to potentially break out of the container. Use with care!
    env:
      - name: ANSIBLE_DOCKER_PRIVILEGED
    ini:
      - key: privileged
        section: docker_connection
    vars:
      - name: ansible_docker_privileged
    type: boolean
    default: false
    version_added: 3.12.0
"""

import fcntl
import os
import os.path
import subprocess
import re
from shlex import quote as shlex_quote

from ansible.errors import AnsibleError, AnsibleFileNotFound, AnsibleConnectionFailure
from ansible.module_utils.common.process import get_bin_path
from ansible.module_utils.common.text.converters import to_bytes, to_native, to_text
from ansible.plugins.connection import ConnectionBase, BUFSIZE
from ansible.utils.display import Display

from ansible_collections.community.docker.plugins.module_utils.selectors import selectors
from ansible_collections.community.docker.plugins.module_utils.version import LooseVersion

display = Display()


class Connection(ConnectionBase):
    ''' Local docker based connections '''

    transport = 'community.docker.docker'
    has_pipelining = True

    def __init__(self, play_context, new_stdin, *args, **kwargs):
        super(Connection, self).__init__(play_context, new_stdin, *args, **kwargs)

        # Note: docker supports running as non-root in some configurations.
        # (For instance, setting the UNIX socket file to be readable and
        # writable by a specific UNIX group and then putting users into that
        # group).  Therefore we do not check that the user is root when using
        # this connection.  But if the user is getting a permission denied
        # error it probably means that docker on their system is only
        # configured to be connected to by root and they are not running as
        # root.

        self._docker_args = []
        self._container_user_cache = {}
        self._version = None

        # Windows uses Powershell modules
        if getattr(self._shell, "_IS_WINDOWS", False):
            self.module_implementation_preferences = ('.ps1', '.exe', '')

        if 'docker_command' in kwargs:
            self.docker_cmd = kwargs['docker_command']
        else:
            try:
                self.docker_cmd = get_bin_path('docker')
            except ValueError:
                raise AnsibleError("docker command not found in PATH")

    @staticmethod
    def _sanitize_version(version):
        version = re.sub(u'[^0-9a-zA-Z.]', u'', version)
        version = re.sub(u'^v', u'', version)
        return version

    def _old_docker_version(self):
        cmd_args = self._docker_args

        old_version_subcommand = ['version']

        old_docker_cmd = [self.docker_cmd] + cmd_args + old_version_subcommand
        p = subprocess.Popen(old_docker_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cmd_output, err = p.communicate()

        return old_docker_cmd, to_native(cmd_output), err, p.returncode

    def _new_docker_version(self):
        # no result yet, must be newer Docker version
        cmd_args = self._docker_args

        new_version_subcommand = ['version', '--format', "'{{.Server.Version}}'"]

        new_docker_cmd = [self.docker_cmd] + cmd_args + new_version_subcommand
        p = subprocess.Popen(new_docker_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cmd_output, err = p.communicate()
        return new_docker_cmd, to_native(cmd_output), err, p.returncode

    def _get_docker_version(self):

        cmd, cmd_output, err, returncode = self._old_docker_version()
        if returncode == 0:
            for line in to_text(cmd_output, errors='surrogate_or_strict').split(u'\n'):
                if line.startswith(u'Server version:'):  # old docker versions
                    return self._sanitize_version(line.split()[2])

        cmd, cmd_output, err, returncode = self._new_docker_version()
        if returncode:
            raise AnsibleError('Docker version check (%s) failed: %s' % (to_native(cmd), to_native(err)))

        return self._sanitize_version(to_text(cmd_output, errors='surrogate_or_strict'))

    def _get_docker_remote_user(self):
        """ Get the default user configured in the docker container """
        container = self.get_option('remote_addr')
        if container in self._container_user_cache:
            return self._container_user_cache[container]
        p = subprocess.Popen([self.docker_cmd, 'inspect', '--format', '{{.Config.User}}', container],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        out, err = p.communicate()
        out = to_text(out, errors='surrogate_or_strict')

        if p.returncode != 0:
            display.warning(u'unable to retrieve default user from docker container: %s %s' % (out, to_text(err)))
            self._container_user_cache[container] = None
            return None

        # The default exec user is root, unless it was changed in the Dockerfile with USER
        user = out.strip() or u'root'
        self._container_user_cache[container] = user
        return user

    def _build_exec_cmd(self, cmd):
        """ Build the local docker exec command to run cmd on remote_host

            If remote_user is available and is supported by the docker
            version we are using, it will be provided to docker exec.
        """

        local_cmd = [self.docker_cmd]

        if self._docker_args:
            local_cmd += self._docker_args

        local_cmd += [b'exec']

        if self.remote_user is not None:
            local_cmd += [b'-u', self.remote_user]

        if self.get_option('extra_env'):
            for k, v in self.get_option('extra_env').items():
                for val, what in ((k, 'Key'), (v, 'Value')):
                    if not isinstance(val, str):
                        raise AnsibleConnectionFailure(
                            'Non-string {0} found for extra_env option. Ambiguous env options must be '
                            'wrapped in quotes to avoid them being interpreted. {1}: {2!r}'
                            .format(what.lower(), what, val)
                        )
                local_cmd += [b'-e', b'%s=%s' % (to_bytes(k, errors='surrogate_or_strict'), to_bytes(v, errors='surrogate_or_strict'))]

        if self.get_option('working_dir') is not None:
            local_cmd += [b'-w', to_bytes(self.get_option('working_dir'), errors='surrogate_or_strict')]
            if self.docker_version != u'dev' and LooseVersion(self.docker_version) < LooseVersion(u'18.06'):
                # https://github.com/docker/cli/pull/732, first appeared in release 18.06.0
                raise AnsibleConnectionFailure(
                    'Providing the working directory requires Docker CLI version 18.06 or newer. You have Docker CLI version {0}.'
                    .format(self.docker_version)
                )

        if self.get_option('privileged'):
            local_cmd += [b'--privileged']

        # -i is needed to keep stdin open which allows pipelining to work
        local_cmd += [b'-i', self.get_option('remote_addr')] + cmd

        return local_cmd

    def _set_docker_args(self):
        # TODO: this is mostly for backwards compatibility, play_context is used as fallback for older versions
        # docker arguments
        del self._docker_args[:]
        extra_args = self.get_option('docker_extra_args') or getattr(self._play_context, 'docker_extra_args', '')
        if extra_args:
            self._docker_args += extra_args.split(' ')

    def _set_conn_data(self):

        ''' initialize for the connection, cannot do only in init since all data is not ready at that point '''

        self._set_docker_args()

        self.remote_user = self.get_option('remote_user')
        if self.remote_user is None and self._play_context.remote_user is not None:
            self.remote_user = self._play_context.remote_user

        # timeout, use unless default and pc is different, backwards compat
        self.timeout = self.get_option('container_timeout')
        if self.timeout == 10 and self.timeout != self._play_context.timeout:
            self.timeout = self._play_context.timeout

    @property
    def docker_version(self):

        if not self._version:
            self._set_docker_args()

            self._version = self._get_docker_version()
            if self._version == u'dev':
                display.warning(u'Docker version number is "dev". Will assume latest version.')
            if self._version != u'dev' and LooseVersion(self._version) < LooseVersion(u'1.3'):
                raise AnsibleError('docker connection type requires docker 1.3 or higher')
        return self._version

    def _get_actual_user(self):
        if self.remote_user is not None:
            # An explicit user is provided
            if self.docker_version == u'dev' or LooseVersion(self.docker_version) >= LooseVersion(u'1.7'):
                # Support for specifying the exec user was added in docker 1.7
                return self.remote_user
            else:
                self.remote_user = None
                actual_user = self._get_docker_remote_user()
                if actual_user != self.get_option('remote_user'):
                    display.warning(u'docker {0} does not support remote_user, using container default: {1}'
                                    .format(self.docker_version, actual_user or u'?'))
                return actual_user
        elif self._display.verbosity > 2:
            # Since we are not setting the actual_user, look it up so we have it for logging later
            # Only do this if display verbosity is high enough that we'll need the value
            # This saves overhead from calling into docker when we do not need to.
            return self._get_docker_remote_user()
        else:
            return None

    def _connect(self, port=None):
        """ Connect to the container. Nothing to do """
        super(Connection, self)._connect()
        if not self._connected:
            self._set_conn_data()
            actual_user = self._get_actual_user()
            display.vvv(u"ESTABLISH DOCKER CONNECTION FOR USER: {0}".format(
                actual_user or u'?'), host=self.get_option('remote_addr')
            )
            self._connected = True

    def exec_command(self, cmd, in_data=None, sudoable=False):
        """ Run a command on the docker host """

        self._set_conn_data()

        super(Connection, self).exec_command(cmd, in_data=in_data, sudoable=sudoable)

        local_cmd = self._build_exec_cmd([self._play_context.executable, '-c', cmd])

        display.vvv(u"EXEC {0}".format(to_text(local_cmd)), host=self.get_option('remote_addr'))
        display.debug("opening command with Popen()")

        local_cmd = [to_bytes(i, errors='surrogate_or_strict') for i in local_cmd]

        p = subprocess.Popen(
            local_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        display.debug("done running command with Popen()")

        if self.become and self.become.expect_prompt() and sudoable:
            fcntl.fcntl(p.stdout, fcntl.F_SETFL, fcntl.fcntl(p.stdout, fcntl.F_GETFL) | os.O_NONBLOCK)
            fcntl.fcntl(p.stderr, fcntl.F_SETFL, fcntl.fcntl(p.stderr, fcntl.F_GETFL) | os.O_NONBLOCK)
            selector = selectors.DefaultSelector()
            selector.register(p.stdout, selectors.EVENT_READ)
            selector.register(p.stderr, selectors.EVENT_READ)

            become_output = b''
            try:
                while not self.become.check_success(become_output) and not self.become.check_password_prompt(become_output):
                    events = selector.select(self.timeout)
                    if not events:
                        stdout, stderr = p.communicate()
                        raise AnsibleError('timeout waiting for privilege escalation password prompt:\n' + to_native(become_output))

                    chunks = b""
                    for key, event in events:
                        if key.fileobj == p.stdout:
                            chunk = p.stdout.read()
                            if chunk:
                                chunks += chunk
                        elif key.fileobj == p.stderr:
                            chunk = p.stderr.read()
                            if chunk:
                                chunks += chunk

                    if not chunks:
                        stdout, stderr = p.communicate()
                        raise AnsibleError('privilege output closed while waiting for password prompt:\n' + to_native(become_output))
                    become_output += chunks
            finally:
                selector.close()

            if not self.become.check_success(become_output):
                become_pass = self.become.get_option('become_pass', playcontext=self._play_context)
                p.stdin.write(to_bytes(become_pass, errors='surrogate_or_strict') + b'\n')
            fcntl.fcntl(p.stdout, fcntl.F_SETFL, fcntl.fcntl(p.stdout, fcntl.F_GETFL) & ~os.O_NONBLOCK)
            fcntl.fcntl(p.stderr, fcntl.F_SETFL, fcntl.fcntl(p.stderr, fcntl.F_GETFL) & ~os.O_NONBLOCK)

        display.debug("getting output with communicate()")
        stdout, stderr = p.communicate(in_data)
        display.debug("done communicating")

        display.debug("done with docker.exec_command()")
        return (p.returncode, stdout, stderr)

    def _prefix_login_path(self, remote_path):
        ''' Make sure that we put files into a standard path

            If a path is relative, then we need to choose where to put it.
            ssh chooses $HOME but we are not guaranteed that a home dir will
            exist in any given chroot.  So for now we are choosing "/" instead.
            This also happens to be the former default.

            Can revisit using $HOME instead if it is a problem
        '''
        if getattr(self._shell, "_IS_WINDOWS", False):
            import ntpath
            return ntpath.normpath(remote_path)
        else:
            if not remote_path.startswith(os.path.sep):
                remote_path = os.path.join(os.path.sep, remote_path)
            return os.path.normpath(remote_path)

    def put_file(self, in_path, out_path):
        """ Transfer a file from local to docker container """
        self._set_conn_data()
        super(Connection, self).put_file(in_path, out_path)
        display.vvv("PUT %s TO %s" % (in_path, out_path), host=self.get_option('remote_addr'))

        out_path = self._prefix_login_path(out_path)
        if not os.path.exists(to_bytes(in_path, errors='surrogate_or_strict')):
            raise AnsibleFileNotFound(
                "file or module does not exist: %s" % to_native(in_path))

        out_path = shlex_quote(out_path)
        # Older docker does not have native support for copying files into
        # running containers, so we use docker exec to implement this
        # Although docker version 1.8 and later provide support, the
        # owner and group of the files are always set to root
        with open(to_bytes(in_path, errors='surrogate_or_strict'), 'rb') as in_file:
            if not os.fstat(in_file.fileno()).st_size:
                count = ' count=0'
            else:
                count = ''
            args = self._build_exec_cmd([self._play_context.executable, "-c", "dd of=%s bs=%s%s" % (out_path, BUFSIZE, count)])
            args = [to_bytes(i, errors='surrogate_or_strict') for i in args]
            try:
                p = subprocess.Popen(args, stdin=in_file, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except OSError:
                raise AnsibleError("docker connection requires dd command in the container to put files")
            stdout, stderr = p.communicate()

            if p.returncode != 0:
                raise AnsibleError("failed to transfer file %s to %s:\n%s\n%s" %
                                   (to_native(in_path), to_native(out_path), to_native(stdout), to_native(stderr)))

    def fetch_file(self, in_path, out_path):
        """ Fetch a file from container to local. """
        self._set_conn_data()
        super(Connection, self).fetch_file(in_path, out_path)
        display.vvv("FETCH %s TO %s" % (in_path, out_path), host=self.get_option('remote_addr'))

        in_path = self._prefix_login_path(in_path)
        # out_path is the final file path, but docker takes a directory, not a
        # file path
        out_dir = os.path.dirname(out_path)

        args = [self.docker_cmd, "cp", "%s:%s" % (self.get_option('remote_addr'), in_path), out_dir]
        args = [to_bytes(i, errors='surrogate_or_strict') for i in args]

        p = subprocess.Popen(args, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.communicate()

        if getattr(self._shell, "_IS_WINDOWS", False):
            import ntpath
            actual_out_path = ntpath.join(out_dir, ntpath.basename(in_path))
        else:
            actual_out_path = os.path.join(out_dir, os.path.basename(in_path))

        if p.returncode != 0:
            # Older docker does not have native support for fetching files command `cp`
            # If `cp` fails, try to use `dd` instead
            args = self._build_exec_cmd([self._play_context.executable, "-c", "dd if=%s bs=%s" % (in_path, BUFSIZE)])
            args = [to_bytes(i, errors='surrogate_or_strict') for i in args]
            with open(to_bytes(actual_out_path, errors='surrogate_or_strict'), 'wb') as out_file:
                try:
                    p = subprocess.Popen(args, stdin=subprocess.PIPE,
                                         stdout=out_file, stderr=subprocess.PIPE)
                except OSError:
                    raise AnsibleError("docker connection requires dd command in the container to put files")
                stdout, stderr = p.communicate()

                if p.returncode != 0:
                    raise AnsibleError("failed to fetch file %s to %s:\n%s\n%s" % (in_path, out_path, stdout, stderr))

        # Rename if needed
        if actual_out_path != out_path:
            os.rename(to_bytes(actual_out_path, errors='strict'), to_bytes(out_path, errors='strict'))

    def close(self):
        """ Terminate the connection. Nothing to do for Docker"""
        super(Connection, self).close()
        self._connected = False

    def reset(self):
        # Clear container user cache
        self._container_user_cache = {}
