# Copyright (c) 2025 Red Hat
# GNU General Public License v3.0+ https://www.gnu.org/licenses/gpl-3.0.txt

from __future__ import annotations

# I had to duplicate (almost?) all of the documentation found in  the
# ansible.plugins.connection.ssh plugin, due to how ansible-doc and ansible-test sanity
# work, they look at the lexical structure of the code. I had initially done:
# 1. load ssh.py DOCUMENTATION string into a yaml object
# 2. modify the yaml object to change defaults / add my options
# 3. set this plugin's DOCUMENTATION to the yaml.dump() of the modified object
# but that doesn't work with how the AST evaluation is done.
# here are the changes from upstream:
# 1. Changed default private_key_file default to ~/.ssh/google_compute_engine
# 2. Make host_key_checking default to False
# 3. Added known_hosts_file option pointing to ~/.ssh/google_compute_known_hosts
# 4. Added missing scp_if_ssh option to fix compatibility issues
DOCUMENTATION = """
  name: iap
  short_description: connect via SSH through Google Cloud's Identity Aware Proxy (IAP)
  description:
    - This connection plugin behaves almost like the stock SSH plugin, but it creates
      a new IAP process per host in the inventory so connections are tunneled through
      it.
  author:
    - Jorge A Gallegos (@thekad)
  notes:
    - This plugin requires you to have configured gcloud authentication prior to using
      it. You can change the active configuration used, but the plugin won't auth
      for you.
    - This plugin is mostly a wrapper to the ``ssh`` CLI utility and the exact behavior
      of the options depends on this tool. This means that the documentation provided
      here is subject to be overridden by the CLI tool itself.
    - Many options default to V(None) here but that only means we do not override the
      SSH tool's defaults and/or configuration. For example, if you specify the port
      in this plugin it will override any C(Port) entry in your C(.ssh/config).
    - The ssh CLI tool uses return code 255 as a 'connection error', this can conflict
      with commands/tools that also return 255 as an error code and will look like an
      'unreachable' condition or 'connection error' to this plugin.
  extends_documentation_fragment:
    - connection_pipelining
  options:
    gcloud_executable:
      description:
        - Path to the gcloud executable, defaults to whatever is found in the PATH
          environment variable.
      type: string
      vars:
        - name: ansible_gcloud_executable
      ini:
        - section: gcloud
          key: executable
    gcloud_configuration:
      description:
        - If set, points to non-standard gcloud configuration.
      type: string
      vars:
        - name: ansible_gcloud_configuration
      ini:
        - section: gcloud
          key: configuration
      env:
        - name: CLOUDSDK_ACTIVE_CONFIG_NAME
    gcloud_project:
      description:
        - The Google Cloud project ID to use for this invocation.
        - If omitted, then the current active project is assumed.
      type: string
      vars:
        - name: ansible_gcloud_project
      ini:
        - section: gcloud
          key: project
      env:
        - name: CLOUDSDK_CORE_PROJECT
    gcloud_account:
      description:
        - Google cloud account to use for invocation.
      type: string
      vars:
        - name: ansible_gcloud_account
      ini:
        - section: gcloud
          key: account
      env:
        - name: CLOUDSDK_CORE_ACCOUNT
    gcloud_zone:
      description:
        - The Google Cloud zone to use for the instance(s).
      type: string
      vars:
        - name: ansible_gcloud_zone
      ini:
        - section: gcloud
          key: zone
      env:
        - name: CLOUDSDK_COMPUTE_ZONE
    gcloud_access_token_file:
      description:
        - A file to read the access token from.
        - The credentials of the active account (if exists) will be ignored.
      type: string
      vars:
        - name: ansible_access_token_file
      ini:
        - section: gcloud
          key: access_token_file
      env:
        - name: CLOUDSDK_AUTH_ACCESS_TOKEN_FILE
    host:
      description: Google Cloud instance name to connect to.
      default: inventory_hostname
      type: string
      vars:
        - name: inventory_hostname
        - name: ansible_host
        - name: ansible_gcloud_host
    known_hosts_file:
      description: Path to the UserKnownHosts file storing SSH fingerprints. Defaults
        to the same file used by `gcloud compute ssh`
      type: string
      default: ~/.ssh/google_compute_known_hosts
      ini:
        - section: ssh_connection
          key: known_hosts_file
      vars:
        - name: ansible_known_hosts_file
        - name: ansible_ssh_known_hosts_file
    host_key_checking:
      description: Determines if SSH should reject or not a connection after checking
        host keys.
      default: false
      type: boolean
      ini:
        - section: defaults
          key: host_key_checking
        - section: ssh_connection
          key: host_key_checking
      env:
        - name: ANSIBLE_HOST_KEY_CHECKING
        - name: ANSIBLE_SSH_HOST_KEY_CHECKING
      vars:
        - name: ansible_host_key_checking
        - name: ansible_ssh_host_key_checking
    password:
      description:
        - Authentication password for the O(remote_user). Can be supplied as CLI option.
      type: string
      vars:
        - name: ansible_password
        - name: ansible_ssh_pass
        - name: ansible_ssh_password
    password_mechanism:
      description: Mechanism to use for handling ssh password prompt
      type: string
      default: ssh_askpass
      choices:
        - ssh_askpass
        - sshpass
        - disable
      env:
        - name: ANSIBLE_SSH_PASSWORD_MECHANISM
      ini:
        - section: ssh_connection
          key: password_mechanism
      vars:
        - name: ansible_ssh_password_mechanism
    sshpass_prompt:
      description:
        - Password prompt that C(sshpass)/C(SSH_ASKPASS) should search for.
        - Supported by sshpass 1.06 and up when O(password_mechanism) set to V(sshpass).
        - Defaults to C(Enter PIN for) when pkcs11_provider is set.
        - Defaults to C(assword) when O(password_mechanism) set to V(ssh_askpass).
      default: ''
      type: string
      ini:
        - section: ssh_connection
          key: 'sshpass_prompt'
      env:
        - name: ANSIBLE_SSHPASS_PROMPT
      vars:
        - name: ansible_sshpass_prompt
    ssh_args:
      description: arguments to pass to all ssh cli tools.
      type: string
      default: '-C -o controlmaster=auto -o controlpersist=60s'
      ini:
        - section: ssh_connection
          key: ssh_args
      env:
        - name: ansible_ssh_args
      vars:
        - name: ansible_ssh_args
    ssh_common_args:
      description: common extra args for all ssh cli tools.
      type: string
      default: ''
      ini:
        - section: ssh_connection
          key: ssh_common_args
      env:
        - name: ANSIBLE_SSH_COMMON_ARGS
      vars:
        - name: ansible_ssh_common_args
      cli:
        - name: ssh_common_args
    ssh_executable:
      description:
        - This defines the location of the SSH binary. It defaults to V(ssh) which will
          use the first SSH binary available in $PATH.
        - This option is usually not required, it might be useful when access to system
          SSH is restricted, or when using SSH wrappers to connect to remote hosts.
      type: string
      default: ssh
      ini:
        - key: ssh_executable
          section: ssh_connection
      env:
        - name: ANSIBLE_SSH_EXECUTABLE
      vars:
        - name: ansible_ssh_executable
    sftp_executable:
      description:
        - This defines the location of the sftp binary. It defaults to V(sftp) which
          will use the first binary available in $PATH.
      type: string
      default: sftp
      ini:
        - key: sftp_executable
          section: ssh_connection
      env:
        - name: ANSIBLE_SFTP_EXECUTABLE
      vars:
        - name: ansible_sftp_executable
    scp_executable:
      description:
        - This defines the location of the scp binary. It defaults to V(scp) which will
          use the first binary available in $PATH.
      type: string
      default: scp
      ini:
        - section: ssh_connection
          key: scp_executable
      env:
        - name: ANSIBLE_SCP_EXECUTABLE
      vars:
        - name: ansible_scp_executable
    scp_extra_args:
      description: Extra exclusive to the C(scp) CLI
      type: string
      default: ''
      ini:
        - section: ssh_connection
          key: scp_extra_args
      env:
        - name: ANSIBLE_SCP_EXTRA_ARGS
      vars:
        - name: ansible_scp_extra_args
      cli:
        - name: scp_extra_args
    scp_if_ssh:
      description:
        - Fallback to SCP (Secure Copy Protocol) when SFTP is not available.
        - When enabled and SFTP fails, Ansible will try to use SCP for file transfers.
      type: bool
      default: smart
      ini:
        - section: ssh_connection
          key: scp_if_ssh
      env:
        - name: ANSIBLE_SCP_IF_SSH
      vars:
        - name: ansible_scp_if_ssh
    sftp_extra_args:
      description: Extra exclusive to the C(sftp) CLI
      type: string
      default: ''
      ini:
        - section: ssh_connection
          key: sftp_extra_args
      vars:
        - name: ansible_sftp_extra_args
      env:
        - name: ANSIBLE_SFTP_EXTRA_ARGS
      cli:
        - name: sftp_extra_args
    ssh_extra_args:
      description: Extra exclusive to the SSH CLI.
      type: string
      default: ''
      vars:
        - name: ansible_ssh_extra_args
      env:
        - name: ANSIBLE_SSH_EXTRA_ARGS
      ini:
        - section: ssh_connection
          key: ssh_extra_args
      cli:
        - name: ssh_extra_args
    reconnection_retries:
      description:
        - Number of attempts to connect.
        - Ansible retries connections only if it gets an SSH error with a return code
          of 255.
        - Any errors with return codes other than 255 indicate an issue with program
          execution.
      type: integer
      default: 0
      env:
        - name: ANSIBLE_SSH_RETRIES
      ini:
        - section: connection
          key: retries
        - section: ssh_connection
          key: retries
      vars:
        - name: ansible_ssh_retries
    port:
      description: Remote port to connect to.
      type: int
      ini:
        - section: defaults
          key: remote_port
      env:
        - name: ANSIBLE_REMOTE_PORT
      vars:
        - name: ansible_port
        - name: ansible_ssh_port
      keyword:
        - name: port
    remote_user:
      description:
        - User name with which to login to the remote server, normally set by the
          remote_user keyword.
        - If no user is supplied, Ansible will let the SSH client binary choose the
          user as it normally.
      type: string
      ini:
        - section: defaults
          key: remote_user
      env:
        - name: ANSIBLE_REMOTE_USER
      vars:
        - name: ansible_user
        - name: ansible_ssh_user
      cli:
        - name: user
      keyword:
        - name: remote_user
    private_key_file:
      description:
        - Path to private key file to use for authentication.
      type: string
      default: '~/.ssh/google_compute_engine'
      ini:
        - section: defaults
          key: private_key_file
        - section: gcloud
          key: private_key_file
      env:
        - name: ANSIBLE_PRIVATE_KEY_FILE
      vars:
        - name: ansible_private_key_file
        - name: ansible_ssh_private_key_file
        - name: ansible_gcloud_private_key_file
      cli:
        - name: private_key_file
          option: '--private-key'
    private_key:
      description:
        - Private key contents in PEM format. Requires the C(SSH_AGENT) configuration
          to be enabled.
      type: string
      env:
        - name: ANSIBLE_PRIVATE_KEY
      vars:
        - name: ansible_private_key
        - name: ansible_ssh_private_key
    private_key_passphrase:
      description:
        - Private key passphrase, dependent on O(private_key).
        - This does NOT have any effect when used with O(private_key_file).
      type: string
      env:
        - name: ANSIBLE_PRIVATE_KEY_PASSPHRASE
      vars:
        - name: ansible_private_key_passphrase
        - name: ansible_ssh_private_key_passphrase
    control_path:
      description:
        - This is the location to save SSH's ControlPath sockets, it uses SSH's variable
          substitution.
        - Be aware that this setting is ignored if C(-o ControlPath) is set in ssh args.
      type: string
      env:
        - name: ANSIBLE_SSH_CONTROL_PATH
      ini:
        - section: ssh_connection
          key: control_path
      vars:
        - name: ansible_control_path
    control_path_dir:
      default: ~/.ansible/cp
      description:
        - This sets the directory to use for ssh control path if the control path
          setting is null.
        - Also, provides the ``%(directory)s`` variable for the control path setting.
      type: string
      env:
        - name: ANSIBLE_SSH_CONTROL_PATH_DIR
      ini:
        - section: ssh_connection
          key: control_path_dir
      vars:
        - name: ansible_control_path_dir
    sftp_batch_mode:
      description:
        - When set to C(True), sftp will be run in batch mode, allowing detection of
          transfer errors.
        - When set to C(False), sftp will not be run in batch mode, preventing detection
          of transfer errors.
      type: bool
      default: true
      env:
        - name: ANSIBLE_SFTP_BATCH_MODE
      ini:
        - section: ssh_connection
          key: sftp_batch_mode
      vars:
        - name: ansible_sftp_batch_mode
    ssh_transfer_method:
      description: Preferred method to use when transferring files over ssh
      type: string
      default: smart
      choices:
        - sftp
        - scp
        - piped
        - smart
      env:
        - name: ANSIBLE_SSH_TRANSFER_METHOD
      ini:
        - section: ssh_connection
          key: transfer_method
      vars:
        - name: ansible_ssh_transfer_method
    use_tty:
      description: add -tt to ssh commands to force tty allocation.
      type: bool
      default: true
      env:
        - name: ANSIBLE_SSH_USETTY
      ini:
        - section: ssh_connection
          key: usetty
      vars:
        - name: ansible_ssh_use_tty
    timeout:
      description:
        - This is the default amount of time we will wait while establishing an SSH
          connection.
        - It also controls how long we can wait to access reading the connection once
          established (select on the socket).
      type: integer
      default: 10
      env:
        - name: ANSIBLE_TIMEOUT
        - name: ANSIBLE_SSH_TIMEOUT
      ini:
        - section: defaults
          key: timeout
        - section: ssh_connection
          key: timeout
      vars:
        - name: ansible_ssh_timeout
      cli:
        - name: timeout
    pkcs11_provider:
      description:
        - PKCS11 SmartCard provider such as opensc, e.g. /usr/local/lib/opensc-pkcs11.so
      type: string
      default: ''
      env:
        - name: ANSIBLE_PKCS11_PROVIDER
      ini:
        - section: ssh_connection
          key: pkcs11_provider
      vars:
        - name: ansible_ssh_pkcs11_provider
    verbosity:
      description:
        - Requested verbosity level for the SSH CLI.
      default: 0
      type: int
      env:
        - name: ANSIBLE_SSH_VERBOSITY
      ini:
        - section: ssh_connection
          key: verbosity
      vars:
        - name: ansible_ssh_verbosity
"""

import os
import re
import pty
import shlex
import select
import shutil
import subprocess
import threading
import time
import tempfile
import typing as T
from os import path as ospath

from ansible.plugins.connection import ssh as sshconn
from ansible import errors
from ansible.utils import display

D = display.Display()
DEFAULT_GCLOUD: T.Optional[str] = shutil.which("gcloud")
DEFAULT_SSH_PORT: int = 22
PORT_REGEX = re.compile(r"\d+")


class IAP:
    host: str
    local_port: int
    remote_port: int
    master_fd: int
    up: bool = False
    process: T.Optional[subprocess.Popen] = None
    thread: T.Optional[threading.Thread] = None
    ready: threading.Event = threading.Event()
    output: T.List[str] = []

    def __init__(
        self,
        gcloud_bin: str,
        host: str,
        remote_port: int,
        project: T.Optional[str],
        account: T.Optional[str],
        zone: T.Optional[str],
        config: T.Optional[str] = None,
        token_file: T.Optional[str] = None,
    ) -> None:

        self.host = host
        self.remote_port = remote_port
        cmd: T.List[str] = [
            gcloud_bin,
            "compute",
            "start-iap-tunnel",
            host,
            str(self.remote_port),
        ]
        if config is not None:
            cmd.extend(
                [
                    "--configuration",
                    shlex.quote(ospath.realpath(ospath.expanduser(config.strip()))),
                ]
            )

        if project is not None:
            cmd.extend(
                [
                    "--project",
                    shlex.quote(project.strip()),
                ]
            )

        if account is not None:
            cmd.extend(
                [
                    "--account",
                    shlex.quote(account.strip()),
                ]
            )

        if zone is not None:
            cmd.extend(
                [
                    "--zone",
                    shlex.quote(zone.strip()),
                ]
            )

        if token_file is not None:
            cmd.extend(
                [
                    "--access-token-file",
                    shlex.quote(token_file.strip()),
                ]
            )

        D.vvv(f"IAP: CMD {' '.join(cmd)}", host=self.host)

        try:
            # start-iap-tunnel prints 2 lines:
            # - Picking local unused port [$PORT].
            # - Testing if tunnel connection works.
            # and only when the terminal is a pty, a 3rd line:
            # - Listening on port [$PORT].
            # The last line only displayed after the tunnel has been tested,
            # that's why we use a PTY for the subprocess
            self.master_fd, slave_fd = pty.openpty()
            self.process = subprocess.Popen(
                cmd, stdout=slave_fd, stderr=slave_fd, text=True, close_fds=True
            )
            os.close(slave_fd)
            self.thread = threading.Thread(target=self._monitor, daemon=True)
            self.thread.start()
            D.vvvvv("started IAP thread", host=self.host)
        except Exception as e:
            self.process = None
            raise Exception from e

    def _monitor(self) -> None:
        """Monitor the thread handling the IAP subprocess until it is 'up'"""

        while self.process is not None and self.process.poll() is None:
            # pylint: disable=disallowed-name
            rlist, _, _ = select.select([self.master_fd], [], [], 0.1)
            if rlist is not None:
                try:
                    output = os.read(self.master_fd, 1024).decode("utf-8")
                    if output:
                        for line in output.splitlines():
                            self.output.append(line)
                            if line.startswith("Listening on port"):
                                m = PORT_REGEX.search(line)
                                if m is not None:
                                    self.local_port = int(m.group())
                                    self.up = True
                                    D.vvv(
                                        f"IAP: LOCAL PORT {self.local_port}",
                                        host=self.host,
                                    )
                except OSError:  # pty is closed
                    break

            if self.up:  # no need to monitor if already up
                break

        if not self.ready.is_set():
            self.ready.set()

        os.close(self.master_fd)

    def terminate(self) -> None:
        """Gracefully terminate the IAP subprocess"""

        D.vvv("IAP: STOPPING TUNNEL", host=self.host)
        if self.process is not None and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)  # wait up to 5 seconds to terminate IAP
            except subprocess.TimeoutExpired:
                self.process.kill()

            D.vvvvv("terminated/killed IAP", host=self.host)

        if self.thread is not None and self.thread.is_alive():
            self.thread.join(timeout=1)  # joining thread back should be quick


class Connection(sshconn.Connection):
    """
    This is pretty much the same as the upstream ssh plugin, just overloads
    the connection handling to start/stop the IAP tunnel with gcloud as appropriate
    """

    iaps: dict[str, IAP] = {}
    lock: threading.Lock = threading.Lock()

    gcloud_executable: T.Optional[str] = None
    ssh_config: str

    transport = "gcloud-iap"  # type: ignore[override]

    def __init__(self, *args: T.Any, **kwargs: T.Any) -> None:

        super(Connection, self).__init__(*args, **kwargs)

        # If the gcloud binary isn't found/configured, bail out immediately
        exec: T.Optional[str] = self.get_option("gcloud_executable")
        if exec is None:
            self.gcloud_executable = DEFAULT_GCLOUD
        else:
            self.gcloud_executable = exec

        if self.gcloud_executable is None:
            raise errors.AnsiblePluginError(
                "Plugin Error: no gcloud binary found in $PATH and "
                "no executable defined in ansible config"
            )

    def _connect(self) -> Connection:
        """Upstream ssh is empty, overload with the stuff starting the IAP tunnel"""

        host: T.Optional[str] = self.get_option("host")
        project: T.Optional[str] = self.get_option("gcloud_project")
        account: T.Optional[str] = self.get_option("gcloud_account")
        zone: T.Optional[str] = self.get_option("gcloud_zone")
        token_file: T.Optional[str] = self.get_option("gcloud_access_token_file")
        config: T.Optional[str] = self.get_option("gcloud_configuration")
        port: T.Optional[int] = self.get_option("port")
        timeout: T.Optional[int] = self.get_option("timeout")

        # this shouldn't happen, but still.
        if host is None:
            raise errors.AnsibleAssertionError("No host defined")

        with self.lock:
            if host not in self.iaps:
                self.iaps[host] = IAP(
                    str(self.gcloud_executable),
                    host=host,
                    remote_port=int(port or DEFAULT_SSH_PORT),
                    project=project,
                    zone=zone,
                    account=account,
                    config=config,
                    token_file=token_file,
                )

        success = self.iaps[host].ready.wait(timeout=timeout)
        is_up: bool = False
        for _ in range(3):  # pylint: disable=disallowed-name
            is_up = self.iaps[host].up
            if success and is_up:
                D.vvv("IAP: TUNNEL IS UP", host=host)
                is_up = True
                break
            else:
                time.sleep(0.5)

        if not is_up:
            D.vvv("IAP: TUNNEL FAILURE", host=host)
            for line in self.iaps[host].output:
                D.vvvvv(line, host=host)
            raise errors.AnsibleRuntimeError("Failure when starting IAP tunnel")

        # override port with the random IAP port
        self.set_option("port", self.iaps[host].local_port)

        # read path to the supplied known hosts file
        ukhf: str = ospath.abspath(
            ospath.expanduser(str(self.get_option("known_hosts_file")))
        )
        # have to trick SSH to connect to localhost instead of the instances
        fd, self.ssh_config = tempfile.mkstemp(
            suffix="ssh_config", prefix="ansible_gcloud", text=True
        )
        with open(fd, "w") as fp:
            fp.write("Host *\n")
            fp.write("  HostName localhost\n")  # trick
            fp.write("  HostKeyAlias {}\n".format(host))  # avoid multiple entries
            fp.write("  UserKnownHostsFile {}\n".format(ukhf))  # as defined in opts

        # prepend our generated ssh config to all ssh_args if not already present
        if self.ssh_config not in str(self.get_option("ssh_args")):
            self.set_option(
                "ssh_args", f"-F {self.ssh_config} " + str(self.get_option("ssh_args"))
            )

        self._connected = True

        return self

    def close(self) -> None:
        """
        Upstream only marks the connection as closed, we have to terminate
        all IAP tunnels as well
        """

        # Terminate IAP
        with self.lock:
            for iap in self.iaps.values():
                iap.terminate()
            self.iaps.clear()

        # remove ssh config
        os.unlink(self.ssh_config)

        self._connected = False
