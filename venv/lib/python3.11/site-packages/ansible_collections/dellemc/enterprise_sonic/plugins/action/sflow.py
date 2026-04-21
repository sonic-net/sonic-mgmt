#
# (c) 2020 Red Hat Inc.
#
# (c) 2020 Dell Inc.
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


from ansible_collections.ansible.netcommon.plugins.action.network import ActionModule as ActionNetworkModule

from ansible.utils.display import Display

display = Display()

DOCUMENTATION = """
short_description: Action plugin module for sonic CLI modules
version_added: 1.0.0
"""


class ActionModule(ActionNetworkModule):

    def run(self, task_vars=None):

        module_name = self._task.action.split('.')[-1]
        self._config_module = True if module_name == 'sonic_config' else False

        if self._play_context.connection in ('network_cli', 'httpapi'):
            provider = self._task.args.get('provider', {})
            if any(provider.values()):
                display.warning('provider is unnecessary when using network_cli and will be ignored')
                del self._task.args['provider']

        result = super(ActionModule, self).run(task_vars=task_vars)
        return result
