import imp
import os
import logging

from functools import wraps
from ansible.errors import AnsibleAuthenticationFailure, AnsibleConnectionFailure
from ansible.plugins import connection

logger = logging.getLogger(__name__)

# HACK: workaround to import the SSH connection plugin
_ssh_mod = os.path.join(os.path.dirname(connection.__file__), "ssh.py")
_ssh = imp.load_source("_ssh", _ssh_mod)

# Use same options as the builtin Ansible SSH plugin
DOCUMENTATION = _ssh.DOCUMENTATION
# Add an option `ansible_ssh_altpassword` to represent an alternative password
# to try if `ansible_ssh_password` is invalid
DOCUMENTATION += """
      altpassword:
          description: Alternative authentication password for the C(remote_user). Can be supplied as CLI option.
          vars:
              - name: ansible_altpassword
              - name: ansible_ssh_altpass
              - name: ansible_ssh_altpassword
      altpasswords:
          description: Alternative authentication passwords list for the C(remote_user). Can be supplied as CLI option.
          vars:
              - name: ansible_altpasswords
              - name: ansible_ssh_altpasswords
      hostv6:
          description: IPv6 address
          vars:
              - name: ansible_hostv6
""".lstrip("\n")

# A sample error message that host unreachable:
# 'Failed to connect to the host via ssh: ssh: connect to host 192.168.0.2 port 22: Connection timed out'
CONNECTION_TIMEOUT_ERR_FLAG = "Connection timed out"


def _password_retry(func):
    """
    Decorator to retry ssh/scp/sftp in the case of invalid password

    Will retry for password in (ansible_password, ansible_altpassword, ansible_altpasswords):
    """
    @wraps(func)
    def wrapped(self, *args, **kwargs):

        # If the host have an IPv6 address, try connect IPv4 address first,
        # If IPv4 host unavailable, fall back to use IPv6 address
        try:
            hostv6 = self.get_option("hostv6")
        except KeyError:
            hostv6 = None

        if hostv6:
            try:
                return func(self, *args, **kwargs)
            except AnsibleConnectionFailure as e:
                logger.info("First connection failed: {}".format(str(e)))
                if CONNECTION_TIMEOUT_ERR_FLAG in e.message:
                    self._play_context.remote_addr = hostv6
                    # args sample:
                    # ( [b'sshpass', b'-d18', b'ssh', b'-o', b'ControlMaster=auto', b'-o', b'ControlPersist=120s', b'-o', b'UserKnownHostsFile=/dev/null', b'-o', b'StrictHostKeyChecking=no', b'-o', b'StrictHostKeyChecking=no', b'-o', b'User="admin"', b'-o', b'ConnectTimeout=60', b'-o', b'ControlPath="/home/user/.ansible/cp/376bdcc730"', 'fc00:1234:5678:abcd::2', b'/bin/sh -c \'echo PLATFORM; uname; echo FOUND; command -v \'"\'"\'python3.10\'"\'"\'; command -v \'"\'"\'python3.9\'"\'"\'; command -v \'"\'"\'python3.8\'"\'"\'; command -v \'"\'"\'python3.7\'"\'"\'; command -v \'"\'"\'python3.6\'"\'"\'; command -v \'"\'"\'python3.5\'"\'"\'; command -v \'"\'"\'/usr/bin/python3\'"\'"\'; command -v \'"\'"\'/usr/libexec/platform-python\'"\'"\'; command -v \'"\'"\'python2.7\'"\'"\'; command -v \'"\'"\'/usr/bin/python\'"\'"\'; command -v \'"\'"\'python\'"\'"\'; echo ENDFOUND && sleep 0\''], None) # noqa: E501
                    # args[0] are the parameters of ssh connection
                    ssh_args = args[0]
                    # Change the IPv4 host in the ssh_args to IPv6
                    for idx in range(len(ssh_args)):
                        if type(ssh_args[idx]) == bytes and ssh_args[idx].decode() == self.host:
                            ssh_args[idx] = hostv6
                    self.host = hostv6
                    self.set_option("host", hostv6)
            except BaseException as e:
                # Only catch the connection error, won't block the multi-password functionality
                logger.info("First connection failed: {}".format(str(e)))

            # Reset the sshpass_pipe for the new connections to be created
            self.sshpass_pipe = os.pipe()

        password = self.get_option("password") or self._play_context.password
        conn_passwords = [password]
        altpassword = self.get_option("altpassword")
        if altpassword:
            conn_passwords.append(altpassword)
        altpasswds = self.get_option("altpasswords")
        if altpasswds:
            conn_passwords.extend(altpasswds)

        while conn_passwords:
            conn_password = conn_passwords.pop(0)
            # temporarily replace `password` for this trial
            self.set_option("password", conn_password)
            self._play_context.password = conn_password
            try:
                return func(self, *args, **kwargs)
            except AnsibleAuthenticationFailure:
                # if there is no more altpassword to try, raise
                if not conn_passwords:
                    raise
            finally:
                # reset `password` to its original state
                self.set_option("password", password)
                self._play_context.password = password
            # retry here, need create a new pipe for sshpass
            self.sshpass_pipe = os.pipe()
    return wrapped


class Connection(_ssh.Connection):

    @_password_retry
    def _run(self, *args, **kwargs):
        return super(Connection, self)._run(*args, **kwargs)

    @_password_retry
    def _file_transport_command(self, *args, **kwargs):
        return super(Connection, self)._file_transport_command(*args, **kwargs)
