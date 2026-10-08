import hashlib
try:
    import importlib.util
    import importlib.machinery
    use_importlib = True
except ImportError:
    import imp
    use_importlib = False
import logging
import os

from functools import wraps
from ansible.errors import AnsibleConnectionFailure
from ansible.plugins import connection


logger = logging.getLogger(__name__)


def load_source(modname, filename):
    loader = importlib.machinery.SourceFileLoader(modname, filename)
    spec = importlib.util.spec_from_file_location(modname, filename, loader=loader)
    module = importlib.util.module_from_spec(spec)
    # The module is always executed and not cached in sys.modules.
    # Uncomment the following line to cache the module.
    # sys.modules[module.__name__] = module
    loader.exec_module(module)
    return module


# HACK: workaround to import the SSH connection plugin
_ssh_mod = os.path.join(os.path.dirname(connection.__file__), "ssh.py")
if use_importlib:
    _ssh = load_source("_ssh", _ssh_mod)
else:
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
          description: Alternate management address
          vars:
              - name: ansible_hostv6
      current_password_hash:
          description: The hash of currently used password
""".lstrip("\n")


def _password_retry(func):
    """Try each distinct endpoint/password pair at most once per operation."""
    @wraps(func)
    def wrapped(self, *args, **kwargs):
        # Piped file transfers call exec_command; the outer operation owns retries.
        if getattr(self, "_credential_retry_active", False):
            return func(self, *args, **kwargs)

        candidates = self._get_credential_candidates()
        original_host = (self.host, self.get_option("host"), self._play_context.remote_addr)
        original_password = (self.get_option("password"), self._play_context.password)
        succeeded = False
        self._credential_retry_active = True
        try:
            for offset in range(len(candidates)):
                index = (self._credential_index + offset) % len(candidates)
                host, password = candidates[index]
                self._set_active_host(host)
                self._play_context.password = password
                self.set_option("password", password)
                try:
                    result = func(self, *args, **kwargs)
                except AnsibleConnectionFailure as error:
                    if offset == len(candidates) - 1:
                        raise AnsibleConnectionFailure(
                            "All configured SSH endpoint/credential combinations failed."
                        ) from error
                else:
                    self._credential_index = index
                    digest = hashlib.sha256(password.encode()).hexdigest() if password is not None else None
                    self.set_option("current_password_hash", digest)
                    succeeded = True
                    return result
        finally:
            self._credential_retry_active = False
            self.set_option("password", original_password[0])
            self._play_context.password = original_password[1]
            if not succeeded:
                self.host, host_option, self._play_context.remote_addr = original_host
                self.set_option("host", host_option)

    return wrapped


class Connection(_ssh.Connection):

    def set_options(self, task_keys=None, var_options=None, direct=None):
        previous = getattr(self, "_credential_candidates", None)
        index = getattr(self, "_credential_index", 0)
        super(Connection, self).set_options(task_keys=task_keys, var_options=var_options, direct=direct)
        self._credential_candidates = None
        if self._get_credential_candidates() == previous:
            self._credential_index = index
        self._set_active_host(self._credential_candidates[self._credential_index][0])

    def _set_active_host(self, host):
        self.host = self._play_context.remote_addr = host
        self.set_option("host", host)

    def _get_credential_candidates(self):
        if getattr(self, "_credential_candidates", None) is None:
            self._credential_index = 0
            hosts = [self.get_option("host") or self._play_context.remote_addr]
            alternate = self.get_option("hostv6")
            if alternate and alternate not in hosts:
                hosts.append(alternate)
            passwords = [self.get_option("password") or self._play_context.password]
            for password in [self.get_option("altpassword")] + (self.get_option("altpasswords") or []):
                if password and password not in passwords:
                    passwords.append(password)
            self._credential_candidates = [(host, password) for host in hosts for password in passwords]
        return self._credential_candidates

    # Retry whole operations so Ansible rebuilds commands, pipes and control paths.
    @_password_retry
    def exec_command(self, *args, **kwargs):
        return super(Connection, self).exec_command(*args, **kwargs)

    @_password_retry
    def put_file(self, *args, **kwargs):
        return super(Connection, self).put_file(*args, **kwargs)

    @_password_retry
    def fetch_file(self, *args, **kwargs):
        return super(Connection, self).fetch_file(*args, **kwargs)
