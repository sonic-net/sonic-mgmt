import json

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.connection import Connection, ConnectionError
from ansible.module_utils.network.common.utils import to_list, ComplexList
from ansible.module_utils.six import items

_DEVICE_CONNECTION = None

aos_provider_spec = {
    'host': dict(),
    'port': dict(type='int'),
    'username': dict(fallback=(env_fallback, ['ANSIBLE_NET_USERNAME'])),
    'password': dict(fallback=(env_fallback, ['ANSIBLE_NET_PASSWORD']), no_log=True),
    'ssh_keyfile': dict(fallback=(env_fallback, ['ANSIBLE_NET_SSH_KEYFILE']), type='path'),

    'authorize': dict(fallback=(env_fallback, ['ANSIBLE_NET_AUTHORIZE']), type='bool'),
    'auth_pass': dict(no_log=True, fallback=(env_fallback, ['ANSIBLE_NET_AUTH_PASS'])),

    'use_ssl': dict(default=True, type='bool'),
    'use_proxy': dict(default=True, type='bool'),
    'validate_certs': dict(default=True, type='bool'),
    'timeout': dict(type='int'),

    'transport': dict(default='cli', choices=['cli'])
}
aos_argument_spec = {
    'provider': dict(type='dict', options=aos_provider_spec),
}
aos_top_spec = {
    'host': dict(),
    'port': dict(type='int'),
    'username': dict(),
    'password': dict(no_log=True),
    'ssh_keyfile': dict(type='path'),

    'authorize': dict(fallback=(env_fallback, ['ANSIBLE_NET_AUTHORIZE']), type='bool'),
    'auth_pass': dict(no_log=True),

    'use_ssl': dict(type='bool'),
    'validate_certs': dict(type='bool'),
    'timeout': dict(type='int'),

    'transport': dict(choices=['cli'])
}
aos_argument_spec.update(aos_top_spec)


def get_provider_argspec():
    return aos_provider_spec


def check_args(module, warnings):
    pass


def load_params(module):
    provider = module.params.get('provider') or dict()
    for key, value in items(provider):
        if key in aos_argument_spec:
            if module.params.get(key) is None and value is not None:
                module.params[key] = value


def get_connection(module):
    global _DEVICE_CONNECTION
    if not _DEVICE_CONNECTION:
        load_params(module)
        _DEVICE_CONNECTION = Cli(module)
    return _DEVICE_CONNECTION


class Cli:

    def __init__(self, module):
        self._module = module
        self._device_configs = {}
        self._session_support = None
        self._connection = None

    def supports_sessions(self):
        if self._session_support is None:
            self._session_support = self._get_connection().supports_sessions()
        return self._session_support

    def _get_connection(self):
        if self._connection:
            return self._connection
        self._connection = Connection(self._module._socket_path)

        return self._connection

    def get_config(self, flags=None):
        """Retrieves the current config from the device or cache
        """
        flags = [] if flags is None else flags

        cmd = 'show running-config '
        cmd += ' '.join(flags)
        cmd = cmd.strip()

        try:
            return self._device_configs[cmd]
        except KeyError:
            conn = self._get_connection()
            try:
                out = conn.get_config(flags=flags)
            except ConnectionError as exc:
                self._module.fail_json(msg=to_text(exc, errors='surrogate_then_replace'))

            cfg = to_text(out, errors='surrogate_then_replace').strip()
            self._device_configs[cmd] = cfg
            return cfg

    def run_commands(self, commands, check_rc=True):
        """Run list of commands on remote device and return results
        """
        connection = self._get_connection()
        try:
            response = connection.run_commands(commands=commands, check_rc=check_rc)
        except ConnectionError as exc:
            self._module.fail_json(msg=to_text(exc, errors='surrogate_then_replace'))
        return response

    def load_config(self, commands, commit=False, replace=False):
        """Loads the config commands onto the remote device
        """
        conn = self._get_connection()
        try:
            response = conn.edit_config(commands, commit, replace)
        except ConnectionError as exc:
            message = getattr(exc, 'err', to_text(exc))
            self._module.fail_json(msg="%s" % message, data=to_text(message, errors='surrogate_then_replace'))

        return response

    def get_diff(self, candidate=None, running=None, diff_match='line', diff_ignore_lines=None, path=None, diff_replace='line'):
        conn = self._get_connection()
        try:
            diff = conn.get_diff(candidate=candidate, running=running, diff_match=diff_match, diff_ignore_lines=diff_ignore_lines, path=path,
                                 diff_replace=diff_replace)
        except ConnectionError as exc:
            self._module.fail_json(msg=to_text(exc, errors='surrogate_then_replace'))
        return diff

    def get_capabilities(self):
        """Returns platform info of the remove device
        """
        if hasattr(self._module, '_capabilities'):
            return self._module._capabilities

        connection = self._get_connection()
        try:
            capabilities = connection.get_capabilities()
        except ConnectionError as exc:
            self._module.fail_json(msg=to_text(exc, errors='surrogate_then_replace'))
        self._module._capabilities = json.loads(capabilities)
        return self._module._capabilities


def to_command(module, commands):
    
    default_output = 'text'

    transform = ComplexList(dict(
        command=dict(key=True),
        output=dict(default=default_output),
        prompt=dict(type='list'),
        answer=dict(type='list'),
        sendonly=dict(type='bool', default=False),
        check_all=dict(type='bool', default=False),
    ), module)

    return transform(to_list(commands))


def get_config(module, flags=None):
    flags = None if flags is None else flags

    conn = get_connection(module)
    return conn.get_config(flags)


def run_commands(module, commands, check_rc=True):
    conn = get_connection(module)
    return conn.run_commands(to_command(module, commands), check_rc=check_rc)


def load_config(module, config, commit=False, replace=False):
    conn = get_connection(module)
    return conn.load_config(config, commit, replace)


def get_diff(self, candidate=None, running=None, diff_match='line', diff_ignore_lines=None, path=None, diff_replace='line'):
    conn = self.get_connection()
    return conn.get_diff(candidate=candidate, running=running, diff_match=diff_match, diff_ignore_lines=diff_ignore_lines, path=path, diff_replace=diff_replace)


def get_capabilities(module):
    conn = get_connection(module)
    return conn.get_capabilities()
