# (c) 2020 Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
    author:
      - Ansible Networking Team (@ansible-network)
    name: libssh
    short_description: Run tasks using libssh for ssh connection
    description:
        - Use the ansible-pylibssh python bindings to connect to targets
        - The python bindings use libssh C library (https://www.libssh.org/) to connect to targets
        - This plugin borrows a lot of settings from the ssh plugin as they both cover the same protocol.
    version_added: 1.1.0
    options:
      remote_addr:
        description:
            - Address of the remote target
        type: string
        default: inventory_hostname
        vars:
            - name: inventory_hostname
            - name: ansible_host
            - name: ansible_ssh_host
            - name: ansible_libssh_host
      remote_user:
        description:
            - User to login/authenticate as
            - Can be set from the CLI via the C(--user) or C(-u) options.
        type: string
        vars:
            - name: ansible_user
            - name: ansible_ssh_user
            - name: ansible_libssh_user
        env:
            - name: ANSIBLE_REMOTE_USER
            - name: ANSIBLE_LIBSSH_REMOTE_USER
        ini:
            - section: defaults
              key: remote_user
            - section: libssh_connection
              key: remote_user
      password:
        description:
          - Secret used to either login the ssh server or as a passphrase for ssh keys that require it
          - Can be set from the CLI via the C(--ask-pass) option.
        type: string
        vars:
            - name: ansible_password
            - name: ansible_ssh_pass
            - name: ansible_ssh_password
            - name: ansible_libssh_pass
            - name: ansible_libssh_password
      password_prompt:
        description:
          - Text to match when using keyboard-interactive authentication to determine if the prompt is
            for the password.
          - Requires ansible-pylibssh version >= 1.0.0
        type: string
        vars:
          - name: ansible_libssh_password_prompt
        version_added: 3.1.0
      private_key_passphrase:
        description:
          - Passphrase used to unlock the private key specified by the C(ansible_private_key_file) attribute.
          - This is required if the private key is encrypted with a passphrase.
        type: string
        vars:
            - name: ansible_private_key_password
            - name: ansible_private_key_passphrase
      host_key_auto_add:
        description: 'TODO: write it'
        env: [{name: ANSIBLE_LIBSSH_HOST_KEY_AUTO_ADD}]
        ini:
          - {key: host_key_auto_add, section: libssh_connection}
        type: boolean
      look_for_keys:
        default: True
        description: 'TODO: write it'
        env: [{name: ANSIBLE_LIBSSH_LOOK_FOR_KEYS}]
        ini:
        - {key: look_for_keys, section: libssh_connection}
        type: boolean
      proxy_command:
        default: ''
        description:
            - Proxy information for running the connection via a jumphost.
            - Also this plugin will scan 'ssh_args', 'ssh_extra_args' and 'ssh_common_args' from the 'ssh' plugin settings for proxy information if set.
        type: string
        env:
          - name: ANSIBLE_LIBSSH_PROXY_COMMAND
        ini:
          - {key: proxy_command, section: libssh_connection}
        vars:
          - name: ansible_paramiko_proxy_command
          - name: ansible_libssh_proxy_command
      pty:
        default: True
        description: 'TODO: write it'
        env:
          - name: ANSIBLE_LIBSSH_PTY
        ini:
          - section: libssh_connection
            key: pty
        type: boolean
      publickey_accepted_algorithms:
        default: ''
        description:
            - List of algorithms to forward to SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES.
        type: str
        env:
          - name: ANSIBLE_LIBSSH_PUBLICKEY_ALGORITHMS
        ini:
          - {key: publickey_algorithms, section: libssh_connection}
        vars:
          - name: ansible_libssh_publickey_algorithms
      hostkeys:
        default: ''
        description: Set the preferred server host key types as a comma-separated list (e.g., ssh-rsa,ssh-dss,ecdh-sha2-nistp256).
        type: str
        env:
          - name: ANSIBLE_LIBSSH_HOSTKEYS
        ini:
          - {key: hostkeys, section: libssh_connection}
        vars:
          - name: ansible_libssh_hostkeys
      key_exchange_algorithms:
        description:
          - Set the key exchange method as a comma-separated list (e.g., "ecdh-sha2-nistp256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1").
          - The list can be prepended by +,-,^ which will append, remove or move to the beginning (prioritizing) of the default list respectively.
            Giving an empty list after + and ^ will cause error.
        type: str
        env:
          - name: ANSIBLE_LIBSSH_KEY_EXCHANGE_ALGORITHMS
        ini:
          - key: key_exchange_algorithms
            section: libssh_connection
        vars:
          - name: ansible_libssh_key_exchange_algorithms
      host_key_checking:
        description: 'Set this to "False" if you want to avoid host key checking by the underlying tools Ansible uses to connect to the host'
        type: boolean
        default: True
        env:
          - name: ANSIBLE_HOST_KEY_CHECKING
          - name: ANSIBLE_SSH_HOST_KEY_CHECKING
          - name: ANSIBLE_LIBSSH_HOST_KEY_CHECKING
        ini:
          - section: defaults
            key: host_key_checking
          - section: libssh_connection
            key: host_key_checking
        vars:
          - name: ansible_host_key_checking
          - name: ansible_ssh_host_key_checking
          - name: ansible_libssh_host_key_checking
      use_persistent_connections:
        description: 'Toggles the use of persistence for connections'
        type: boolean
        default: False
        env:
          - name: ANSIBLE_USE_PERSISTENT_CONNECTIONS
        ini:
          - section: defaults
            key: use_persistent_connections
      ssh_args:
          version_added: 3.2.0
          description:
           - Arguments to pass to all ssh CLI tools.
           - ProxyCommand is the only supported argument.
           - This option is deprecated in favor of I(proxy_command) and will be removed
             in a release after 2026-01-01.
          type: string
          ini:
              - section: 'ssh_connection'
                key: 'ssh_args'
          env:
              - name: ANSIBLE_SSH_ARGS
          vars:
              - name: ansible_ssh_args
          cli:
              - name: ssh_args
      ssh_common_args:
          version_added: 3.2.0
          description:
           - Common extra arguments for all ssh CLI tools.
           - ProxyCommand is the only supported argument.
           - This option is deprecated in favor of I(proxy_command) and will be removed
             in a release after 2026-01-01.
          type: string
          ini:
              - section: 'ssh_connection'
                key: 'ssh_common_args'
          env:
              - name: ANSIBLE_SSH_COMMON_ARGS
          vars:
              - name: ansible_ssh_common_args
          cli:
              - name: ssh_common_args
      ssh_extra_args:
          version_added: 3.2.0
          description:
           - Extra arguments exclusive to the 'ssh' CLI tool.
           - ProxyCommand is the only supported argument.
           - This option is deprecated in favor of I(proxy_command) and will be removed
             in a release after 2026-01-01.
          type: string
          vars:
              - name: ansible_ssh_extra_args
          env:
            - name: ANSIBLE_SSH_EXTRA_ARGS
          ini:
            - key: ssh_extra_args
              section: ssh_connection
          cli:
            - name: ssh_extra_args
      config_file:
        version_added: 5.1.0
        description: Alternate SSH config file location
        type: path
        env:
          - name: ANSIBLE_LIBSSH_CONFIG_FILE
        ini:
          - section: libssh_connection
            key: config_file
        vars:
          - name: ansible_libssh_config_file
# TODO:
#timeout=self._play_context.timeout,
"""
import logging
import os
import re
import socket

from ansible.errors import AnsibleConnectionFailure, AnsibleError, AnsibleFileNotFound
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_bytes, to_native, to_text
from ansible.plugins.connection import ConnectionBase
from ansible.utils.display import Display

from ansible_collections.ansible.netcommon.plugins.plugin_utils.version import Version


display = Display()

try:
    from pylibsshext import __version__ as PYLIBSSH_VERSION
    from pylibsshext.errors import LibsshSCPException, LibsshSessionException
    from pylibsshext.session import Session

    HAS_PYLIBSSH = True
except ImportError:
    HAS_PYLIBSSH = False


AUTHENTICITY_MSG = """
libssh: The authenticity of host '%s' can't be established due to '%s'.
The %s key fingerprint is %s.
Are you sure you want to continue connecting (yes/no)?
"""

# SSH Options Regex
SETTINGS_REGEX = re.compile(r"(\w+)(?:\s*=\s*|\s+)(.+)")


class MyAddPolicy(object):
    """
    Based on AutoAddPolicy in paramiko so we can determine when keys are added

    and also prompt for input.

    Policy for automatically adding the hostname and new host key to the
    local L{HostKeys} object, and saving it.  This is used by L{SSHClient}.
    """

    def __init__(self, connection):
        self.connection = connection
        self._options = connection._options

    def missing_host_key(self, session, hostname, username, key_type, fingerprint, message):
        if all(
            (
                self._options["host_key_checking"],
                not self._options["host_key_auto_add"],
            )
        ):
            if (
                self.connection.get_option("use_persistent_connections")
                or self.connection.force_persistence
            ):
                # don't print the prompt string since the user cannot respond
                # to the question anyway
                raise AnsibleError(
                    AUTHENTICITY_MSG.rsplit("\n", 2)[0] % (hostname, message, key_type, fingerprint)
                )

            inp = to_text(
                display.prompt_until(
                    AUTHENTICITY_MSG % (hostname, message, key_type, fingerprint), private=False
                ),
                errors="surrogate_or_strict",
            )

            self.connection.connection_unlock()
            if inp not in ["yes", "y", ""]:
                raise AnsibleError("host connection rejected by user")

        session.hostkey_auto_add(username)

        # host keys are actually saved in close() function below
        # in order to control ordering.


# keep connection objects on a per host basis to avoid repeated attempts to reconnect
SSH_CONNECTION_CACHE = {}
SFTP_CONNECTION_CACHE = {}


class Connection(ConnectionBase):
    """SSH based connections with Paramiko"""

    transport = "ansible.netcommon.libssh"
    _log_channel = None

    def _cache_key(self):
        return "%s__%s__" % (
            self._play_context.remote_addr,
            self._play_context.remote_user,
        )

    def _connect(self):
        cache_key = self._cache_key()
        if cache_key in SSH_CONNECTION_CACHE:
            self.ssh = SSH_CONNECTION_CACHE[cache_key]
        else:
            self.ssh = SSH_CONNECTION_CACHE[cache_key] = self._connect_uncached()
        return self

    def _set_log_channel(self, name):
        self._log_channel = name

    def _get_proxy_command(self, port=22):
        proxy_command = None
        # Parse ansible_ssh_common_args, specifically looking for ProxyCommand
        ssh_args = [
            self.get_option("ssh_extra_args") or "",
            self.get_option("ssh_common_args") or "",
            self.get_option("ssh_args") or "",
        ]

        if any(ssh_args):
            display.warning(
                "The ssh_*_args options are deprecated and will be removed in a release after 2026-01-01. Please use the proxy_command option instead."
            )
            args = self._split_ssh_args(" ".join(ssh_args))
            for i, arg in enumerate(args):
                if arg.lower() == "proxycommand":
                    # _split_ssh_args split ProxyCommand from the command itself
                    proxy_command = args[i + 1]
                else:
                    # ProxyCommand and the command itself are a single string
                    match = SETTINGS_REGEX.match(arg)
                    if match:
                        if match.group(1).lower() == "proxycommand":
                            proxy_command = match.group(2)

                if proxy_command:
                    break

        proxy_command = proxy_command or self.get_option("proxy_command")

        if proxy_command:
            replacers = {
                "%h": self._play_context.remote_addr,
                "%p": port,
                "%r": self._play_context.remote_user,
            }
            for find, replace in replacers.items():
                proxy_command = proxy_command.replace(find, str(replace))

        return proxy_command

    def _connect_uncached(self):
        """activates the connection object"""

        if not HAS_PYLIBSSH:
            raise AnsibleError(missing_required_lib("ansible-pylibssh"))
        display.vvv(
            "USING PYLIBSSH VERSION %s" % PYLIBSSH_VERSION,
            host=self._play_context.remote_addr,
        )

        ssh_connect_kwargs = {}

        remote_user = self.get_option("remote_user")
        remote_addr = self.get_option("remote_addr")
        port = self._play_context.port or 22
        display.vvv(
            "ESTABLISH LIBSSH CONNECTION FOR USER: %s on PORT %s TO %s"
            % (remote_user, port, remote_addr),
            host=remote_addr,
        )

        self.ssh = Session()

        if display.verbosity > 3:
            self.ssh.set_log_level(logging.DEBUG)

        self.keyfile = os.path.expanduser("~/.ssh/known_hosts")

        proxy_command = self._get_proxy_command(port)

        try:
            private_key = None
            if self._play_context.private_key_file:
                with open(os.path.expanduser(self._play_context.private_key_file)) as fp:
                    b_content = fp.read()
                    private_key = to_bytes(b_content, errors="surrogate_or_strict")

            if proxy_command:
                ssh_connect_kwargs["proxycommand"] = proxy_command

            if self.get_option("config_file"):
                ssh_connect_kwargs["config_file"] = self.get_option("config_file")

            if self.get_option("password_prompt") and (Version(PYLIBSSH_VERSION) < "1.0.0"):
                raise AnsibleError(
                    "Configuring password prompt is not supported in ansible-pylibssh version %s. "
                    "Please upgrade to ansible-pylibssh 1.0.0 or newer." % PYLIBSSH_VERSION
                )

            if self.get_option("publickey_accepted_algorithms"):
                ssh_connect_kwargs["publickey_accepted_algorithms"] = self.get_option(
                    "publickey_accepted_algorithms"
                )

            if self.get_option("hostkeys"):
                ssh_connect_kwargs["hostkeys"] = self.get_option("hostkeys")

            if self.get_option("key_exchange_algorithms"):
                ssh_connect_kwargs["key_exchange_algorithms"] = self.get_option(
                    "key_exchange_algorithms"
                )

            self.ssh.set_missing_host_key_policy(MyAddPolicy(self))

            self.ssh.connect(
                host=remote_addr.lower(),
                user=remote_user,
                look_for_keys=self.get_option("look_for_keys"),
                host_key_checking=self.get_option("host_key_checking"),
                password=self.get_option("password"),
                password_prompt=self.get_option("password_prompt"),
                private_key=private_key,
                private_key_password=self.get_option("private_key_passphrase"),
                timeout=self._play_context.timeout,
                port=port,
                **ssh_connect_kwargs,
            )
        except LibsshSessionException as e:
            msg = "ssh connection failed: " + to_text(e)
            raise AnsibleConnectionFailure(msg)
        except Exception as e:
            raise AnsibleConnectionFailure(to_text(e))

        display.vvv("ssh connection is OK: " + str(self.ssh))
        return self.ssh

    def exec_command(self, cmd, in_data=None, sudoable=True):
        """run a command on the remote host"""

        super(Connection, self).exec_command(cmd, in_data=in_data, sudoable=sudoable)

        if in_data:
            raise AnsibleError(
                "Internal Error: this module does not support optimized module pipelining"
            )

        bufsize = 4096

        try:
            self.chan = self.ssh.new_channel()
        except Exception as e:
            text_e = to_text(e)
            msg = "Failed to open session"
            if text_e:
                msg += ": %s" % text_e
            raise AnsibleConnectionFailure(to_native(msg))

        # sudo usually requires a PTY (cf. requiretty option), therefore
        # we give it one by default (pty=True in ansible.cfg), and we try
        # to initialise from the calling environment when sudoable is enabled
        if self.get_option("pty") and sudoable:
            self.chan.request_shell()

        display.vvv("EXEC %s" % cmd, host=self._play_context.remote_addr)

        cmd = to_bytes(cmd, errors="surrogate_or_strict")

        result = None
        no_prompt_out = b""
        no_prompt_err = b""
        become_output = b""
        out = b""
        err = b""

        try:
            if self.become and self.become.expect_prompt():
                passprompt = False
                become_sucess = False
                self.chan.sendall(cmd)

                while not (become_sucess or passprompt):
                    display.debug("Waiting for Privilege Escalation input")
                    self.chan.poll(timeout=self._play_context.timeout)
                    chunk = self.chan.recv(bufsize)
                    display.debug("chunk is: %s" % chunk)

                    if not chunk:
                        if b"unknown user" in become_output:
                            n_become_user = to_native(
                                self.become.get_option(
                                    "become_user",
                                    playcontext=self._play_context,
                                )
                            )
                            raise AnsibleError("user %s does not exist" % n_become_user)
                        else:
                            break
                            # raise AnsibleError('ssh connection closed waiting for password prompt')
                    become_output += chunk
                    # need to check every line because we might get lectured
                    # and we might get the middle of a line in a chunk
                    for line in become_output.splitlines(True):
                        if self.become.check_success(line):
                            become_sucess = True
                            break
                        if self.become.check_password_prompt(line):
                            passprompt = True
                            break
                if passprompt:
                    if self.become:
                        become_pass = self.become.get_option(
                            "become_pass", playcontext=self._play_context
                        )
                        self.chan.sendall(
                            to_bytes(become_pass, errors="surrogate_or_strict") + b"\n"
                        )
                    else:
                        raise AnsibleError("A password is required but none was supplied")
                else:
                    no_prompt_out += become_output
                    no_prompt_err += become_output
            else:
                result = self.chan.exec_command(to_text(cmd, errors="surrogate_or_strict"))
        except socket.timeout:
            raise AnsibleError("ssh timed out waiting for privilege escalation.\n" + become_output)

        if result:
            rc = result.returncode
            out = result.stdout
            err = result.stderr
        else:
            rc = self.chan.get_channel_exit_status()
        return rc, out, err

    def put_file(self, in_path, out_path, proto="sftp"):
        """transfer a file from local to remote"""

        super(Connection, self).put_file(in_path, out_path)

        display.vvv(
            "PUT %s TO %s" % (in_path, out_path),
            host=self._play_context.remote_addr,
        )

        if not os.path.exists(to_bytes(in_path, errors="surrogate_or_strict")):
            raise AnsibleFileNotFound("file or module does not exist: %s" % in_path)

        if proto == "sftp":
            try:
                self.sftp = self.ssh.sftp()
            except Exception as e:
                raise AnsibleError("failed to open a SFTP connection (%s)" % e)

            try:
                self.sftp.put(
                    to_bytes(in_path, errors="surrogate_or_strict"),
                    to_bytes(out_path, errors="surrogate_or_strict"),
                )
            except IOError:
                raise AnsibleError("failed to transfer file to %s" % out_path)
        elif proto == "scp":
            scp = self.ssh.scp()
            try:
                scp.put(in_path, out_path)
            except LibsshSCPException as exc:
                raise AnsibleError("Error transferring file to %s: %s" % (out_path, to_text(exc)))
        else:
            raise AnsibleError("Don't know how to transfer file over protocol %s" % proto)

    def _connect_sftp(self):
        cache_key = "%s__%s__" % (
            self._play_context.remote_addr,
            self._play_context.remote_user,
        )
        if cache_key in SFTP_CONNECTION_CACHE:
            return SFTP_CONNECTION_CACHE[cache_key]
        else:
            result = SFTP_CONNECTION_CACHE[cache_key] = self._connect().ssh.sftp()
            return result

    def fetch_file(self, in_path, out_path, proto="sftp"):
        """save a remote file to the specified path"""

        super(Connection, self).fetch_file(in_path, out_path)

        display.vvv(
            "FETCH %s TO %s" % (in_path, out_path),
            host=self._play_context.remote_addr,
        )

        if proto == "sftp":
            try:
                self.sftp = self._connect_sftp()
            except Exception as e:
                raise AnsibleError("failed to open a SFTP connection (%s)" % to_native(e))

            try:
                self.sftp.get(
                    to_bytes(in_path, errors="surrogate_or_strict"),
                    to_bytes(out_path, errors="surrogate_or_strict"),
                )
            except IOError:
                raise AnsibleError("failed to transfer file from %s" % in_path)
        elif proto == "scp":
            scp = self.ssh.scp()
            try:
                # this abruptly closes the connection when
                # scp.get fails only when the file is not there
                # it works fine if the file is actually present
                scp.get(in_path, out_path)
            except LibsshSCPException as exc:
                raise AnsibleError("Error transferring file from %s: %s" % (out_path, to_text(exc)))
        else:
            raise AnsibleError("Don't know how to transfer file over protocol %s" % proto)

    def reset(self):
        self.close()
        self._connect()

    def close(self):
        """terminate the connection"""

        cache_key = self._cache_key()
        SSH_CONNECTION_CACHE.pop(cache_key, None)
        SFTP_CONNECTION_CACHE.pop(cache_key, None)

        if hasattr(self, "sftp"):
            if self.sftp is not None:
                self.sftp.close()

        if hasattr(self, "chan"):
            if self.chan is not None:
                self.chan.close()

        self.ssh.close()
        self._connected = False
