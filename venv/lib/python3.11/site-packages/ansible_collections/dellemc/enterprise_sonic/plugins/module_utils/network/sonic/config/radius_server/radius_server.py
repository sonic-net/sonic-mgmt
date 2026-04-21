#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_radius_server class
It is in this file where the current configuration (as dict)
is compared to the provided configuration (as dict) and the command set
necessary to bring the current configuration to it's desired end-state is
created
"""
from __future__ import absolute_import, division, print_function
__metaclass__ = type
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.cfg.base import (
    ConfigBase,
)
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible.module_utils.connection import ConnectionError
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    update_states,
    get_diff,
    get_replaced_config,
    normalize_interface_name,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_CONFIG_IF_NO_SUBCONFIG,
    __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF,
    get_new_config,
    get_formatted_config_diff
)

PATCH = 'patch'
DELETE = 'delete'
TEST_KEYS = [
    {'host': {'name': ''}},
]
TEST_KEYS_formatted_diff = [
    {'config': {'__delete_op': __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF}},
    {'host': {'name': '', '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}},
]


class Radius_server(ConfigBase):
    """
    The sonic_radius_server class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'radius_server',
    ]

    def __init__(self, module):
        super(Radius_server, self).__init__(module)

    def get_radius_server_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        radius_server_facts = facts['ansible_network_resources'].get('radius_server')
        if not radius_server_facts:
            return []
        return radius_server_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        existing_radius_server_facts = self.get_radius_server_facts()
        commands, requests = self.set_config(existing_radius_server_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_radius_server_facts = self.get_radius_server_facts()

        result['before'] = existing_radius_server_facts
        if result['changed']:
            result['after'] = changed_radius_server_facts

        new_config = changed_radius_server_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_radius_server_facts,
                                        TEST_KEYS_formatted_diff)
            result['after(generated)'] = new_config

        if self._module._diff:
            result['diff'] = get_formatted_config_diff(existing_radius_server_facts,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_radius_server_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']

        if want and want.get('servers', None) and want['servers'].get('host', None):
            normalize_interface_name(want['servers']['host'], self._module, 'source_interface')

        have = existing_radius_server_facts
        resp = self.set_state(want, have)
        return to_list(resp)

    def set_state(self, want, have):
        """ Select the appropriate function based on the state provided

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        state = self._module.params['state']
        if not want:
            want = {}

        diff = get_diff(want, have, TEST_KEYS)

        if state == 'overridden':
            commands, requests = self._state_overridden(want, have, diff)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have, diff)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have, diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have, diff)
        return commands, requests

    def _state_merged(self, want, have, diff):
        """ The command generator when state is merged

        :param want: the additive configuration as a dictionary
        :param obj_in_have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = []
        command = diff
        requests = self.get_modify_radius_server_requests(command, have)
        if command and len(requests) > 0:
            commands = update_states([command], "merged")
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have, diff):
        """ The command generator when state is deleted

        :param want: the objects from which the configuration should be removed
        :param obj_in_have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        # if want is none, then delete all the radius_serveri except admin
        commands = []
        if not want:
            command = have
        else:
            command = want

        requests = self.get_delete_radius_server_requests(command, have)

        if command and len(requests) > 0:
            commands = update_states([command], "deleted")

        return commands, requests

    def _state_replaced(self, want, have, diff):
        """ The command generator when state is replaced

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :param diff: the difference between want and have
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []
        replaced_config = get_replaced_config(want, have, TEST_KEYS)

        add_commands = []
        if replaced_config:
            del_requests = self.get_delete_radius_server_requests(replaced_config, have)
            requests.extend(del_requests)
            commands.extend(update_states(replaced_config, "deleted"))
            add_commands = want
        else:
            add_commands = diff

        if add_commands:
            add_requests = self.get_modify_radius_server_requests(add_commands, have)
            if len(add_requests) > 0:
                requests.extend(add_requests)
                commands.extend(update_states(add_commands, "replaced"))

        return commands, requests

    def _state_overridden(self, want, have, diff):
        """ The command generator when state is overridden

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :param diff: the difference between want and have
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands = []
        requests = []

        r_diff = get_diff(have, want, TEST_KEYS)
        if have and (diff or r_diff):
            del_requests = self.get_delete_radius_server_requests(have, have)
            requests.extend(del_requests)
            commands.extend(update_states(have, "deleted"))
            have = []

        if not have and want:
            want_commands = want
            want_requests = self.get_modify_radius_server_requests(want_commands, have)

            if len(want_requests) > 0:
                requests.extend(want_requests)
                commands.extend(update_states(want_commands, "overridden"))

        return commands, requests

    def get_radius_global_payload(self, conf):
        payload = {}
        global_cfg = {}

        if conf.get('auth_type', None):
            global_cfg['auth-type'] = conf['auth_type']
        if conf.get('key', None):
            global_cfg['secret-key'] = conf['key']
        if conf.get('timeout', None):
            global_cfg['timeout'] = conf['timeout']

        if global_cfg:
            payload = {'openconfig-system:config': global_cfg}

        return payload

    def get_radius_global_ext_payload(self, conf):
        payload = {}
        global_ext_cfg = {}

        if conf.get('nas_ip', None):
            global_ext_cfg['nas-ip-address'] = conf['nas_ip']
        if conf.get('retransmit', None):
            global_ext_cfg['retransmit-attempts'] = conf['retransmit']
        if conf.get('statistics', None):
            global_ext_cfg['statistics'] = conf['statistics']

        if global_ext_cfg:
            payload = {'openconfig-aaa-radius-ext:config': global_ext_cfg}

        return payload

    def get_radius_server_payload(self, hosts):
        payload = {}
        servers_load = []
        for host in hosts:
            if host.get('name', None):
                host_cfg = {'address': host['name']}
                if host.get('auth_type', None):
                    host_cfg['auth-type'] = host['auth_type']
                if host.get('priority', None):
                    host_cfg['priority'] = host['priority']
                if host.get('vrf', None):
                    host_cfg['vrf'] = host['vrf']
                if host.get('timeout', None):
                    host_cfg['timeout'] = host['timeout']

                radius_port_key_cfg = {}
                if host.get('port', None):
                    radius_port_key_cfg['auth-port'] = host['port']
                if host.get('key', None):
                    radius_port_key_cfg['secret-key'] = host['key']
                if host.get('retransmit', None):
                    radius_port_key_cfg['retransmit-attempts'] = host['retransmit']
                if host.get('source_interface', None):
                    radius_port_key_cfg['openconfig-aaa-radius-ext:source-interface'] = host['source_interface']

                if radius_port_key_cfg:
                    consolidated_load = {'address': host['name']}
                    consolidated_load['config'] = host_cfg
                    consolidated_load['radius'] = {'config': radius_port_key_cfg}
                    servers_load.append(consolidated_load)

        if servers_load:
            payload = {'openconfig-system:servers': {'server': servers_load}}

        return payload

    def get_modify_servers_request(self, command):
        request = None

        hosts = []
        if command.get('servers', None) and command['servers'].get('host', None):
            hosts = command['servers']['host']
        if hosts:
            url = 'data/openconfig-system:system/aaa/server-groups/server-group=RADIUS/servers'
            payload = self.get_radius_server_payload(hosts)
            if payload:
                request = {'path': url, 'method': PATCH, 'data': payload}

        return request

    def get_modify_global_config_request(self, conf):
        request = None

        url = 'data/openconfig-system:system/aaa/server-groups/server-group=RADIUS/config'
        payload = self.get_radius_global_payload(conf)
        if payload:
            request = {'path': url, 'method': PATCH, 'data': payload}

        return request

    def get_modify_global_ext_config_request(self, conf):
        request = None

        url = 'data/openconfig-system:system/aaa/server-groups/server-group=RADIUS/openconfig-aaa-radius-ext:radius/config'
        payload = self.get_radius_global_ext_payload(conf)
        if payload:
            request = {'path': url, 'method': PATCH, 'data': payload}

        return request

    def get_modify_radius_server_requests(self, command, have):
        requests = []
        if not command:
            return requests

        request = self.get_modify_global_config_request(command)
        if request:
            requests.append(request)

        request = self.get_modify_global_ext_config_request(command)
        if request:
            requests.append(request)

        request = self.get_modify_servers_request(command)
        if request:
            requests.append(request)

        return requests

    def get_delete_global_ext_params(self, conf, match):

        requests = []

        url = 'data/openconfig-system:system/aaa/server-groups/server-group=RADIUS/openconfig-aaa-radius-ext:radius/config/'
        if conf.get('nas_ip', None) and match.get('nas_ip', None):
            requests.append({'path': url + 'nas-ip-address', 'method': DELETE})
        if conf.get('retransmit', None) and match.get('retransmit', None):
            requests.append({'path': url + 'retransmit-attempts', 'method': DELETE})
        if conf.get('statistics', None) and match.get('statistics', None):
            requests.append({'path': url + 'statistics', 'method': DELETE})

        return requests

    def get_delete_global_params(self, conf, match):

        requests = []

        url = 'data/openconfig-system:system/aaa/server-groups/server-group=RADIUS/config/'
        if conf.get('auth_type', None) and match.get('auth_type', None) and match['auth_type'] != 'pap':
            requests.append({'path': url + 'auth-type', 'method': DELETE})
        if conf.get('key', None) and match.get('key', None):
            requests.append({'path': url + 'secret-key', 'method': DELETE})
        if conf.get('timeout', None) and match.get('timeout', None) and match['timeout'] != 5:
            requests.append({'path': url + 'timeout', 'method': DELETE})

        return requests

    def get_delete_servers(self, command, have):
        requests = []
        url = 'data/openconfig-system:system/aaa/server-groups/server-group=RADIUS/servers/server='

        mat_hosts = []
        if have.get('servers', None) and have['servers'].get('host', None):
            mat_hosts = have['servers']['host']

        if command.get('servers', None):
            if command['servers'].get('host', None):
                hosts = command['servers']['host']
            else:
                hosts = mat_hosts

        if mat_hosts and hosts:
            for host in hosts:
                if next((m_host for m_host in mat_hosts if m_host['name'] == host['name']), None):
                    requests.append({'path': url + host['name'], 'method': DELETE})

        return requests

    def get_delete_radius_server_requests(self, command, have):
        requests = []
        if not command:
            return requests

        requests.extend(self.get_delete_global_params(command, have))
        requests.extend(self.get_delete_global_ext_params(command, have))
        requests.extend(self.get_delete_servers(command, have))

        return requests
