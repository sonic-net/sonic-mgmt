#
# (c) 2016 Red Hat Inc.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import sys
import copy

from ansible import constants as C
from ansible.module_utils._text import to_text
from ansible.module_utils.connection import Connection
from ansible.utils.display import Display


from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import load_provider
from ansible_collections.ansible.netcommon.plugins.action.network import ActionModule as ActionNetworkModule


from ansible_collections.f5networks.f5_modules.plugins.module_utils.common import f5_provider_spec

display = Display()


class ActionModule(ActionNetworkModule):

    def run(self, task_vars=None):

        self._config_module = True if self._task.action == 'bigip_imish_config' else False
        socket_path = None
        transport = 'rest'

        if self._play_context.connection == 'network_cli':
            provider = self._task.args.get('provider', {})
            if any(provider.values()):
                display.warning("'provider' is unnecessary when using 'network_cli' and will be ignored")
        elif self._play_context.connection == 'local':
            provider = load_provider(f5_provider_spec, self._task.args)
            # provider = load_provider(f5_provider_spec, self._task.args, module=self._task)

            transport = provider['transport'] or transport

            display.vvvv('connection transport is %s' % transport, self._play_context.remote_addr)

            if transport == 'cli':
                pc = copy.deepcopy(self._play_context)
                pc.connection = 'network_cli'
                pc.network_os = 'bigip'
                pc.remote_addr = provider['server'] or self._play_context.remote_addr
                pc.port = int(provider['server_port'] or self._play_context.port or 22)
                pc.remote_user = provider['user'] or self._play_context.connection_user
                pc.password = provider['password'] or self._play_context.password
                pc.private_key_file = provider.get('ssh_keyfile', None) or self._play_context.private_key_file
                command_timeout = int(provider['timeout'] or C.PERSISTENT_COMMAND_TIMEOUT)

                display.vvv('using connection plugin %s' % pc.connection, pc.remote_addr)
                connection = self._shared_loader_obj.connection_loader.get('persistent', pc, sys.stdin)
                connection.set_options(direct={'persistent_command_timeout': command_timeout})

                socket_path = connection.run()
                display.vvvv('socket_path: %s' % socket_path, pc.remote_addr)
                if not socket_path:
                    return {
                        'failed': True,
                        'msg': 'Unable to open shell. Please see: '
                               'https://docs.ansible.com/ansible/network_debug_troubleshooting.html#unable-to-open-shell'
                    }

                task_vars['ansible_socket'] = socket_path

        if (self._play_context.connection == 'local' and transport == 'cli') or self._play_context.connection == 'network_cli':
            # make sure we are in the right cli context which should be
            # enable mode and not config module
            if socket_path is None:
                socket_path = self._connection.socket_path
            conn = Connection(socket_path)
            out = conn.get_prompt()
            while '(config' in to_text(out, errors='surrogate_then_replace').strip():
                display.vvvv('wrong context, sending exit to device', self._play_context.remote_addr)
                conn.send_command('exit')
                out = conn.get_prompt()

            if self._play_context.connection == 'network_cli':
                p = load_provider(f5_provider_spec, self._task.args)
                p['server'] = task_vars['ansible_host']
                p['user'] = task_vars['ansible_user']
                p['password'] = task_vars['ansible_password']
                task_vars['provider'] = p

        result = super(ActionModule, self).run(task_vars=task_vars)
        return result
