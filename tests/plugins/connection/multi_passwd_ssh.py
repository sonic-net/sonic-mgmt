import imp
import os

from functools import wraps
from ansible.errors import AnsibleAuthenticationFailure
from ansible.plugins import connection


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
""".lstrip("\n")


def _password_retry(func):
    """
    Decorator to retry ssh/scp/sftp in the case of invalid password

    Will retry for password in (ansible_password, ansible_altpassword):
    """
    @wraps(func)
    def wrapped(self, *args, **kwargs):
        password = self.get_option("password") or self._play_context.password
        conn_passwords = [password]
        altpassword = self.get_option("altpassword")
        if altpassword:
            conn_passwords.append(altpassword)

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
