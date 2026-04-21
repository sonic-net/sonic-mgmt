#
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_mirroring class
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
    remove_empties,
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
    get_normalize_interface_name
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF,
    get_new_config,
    get_formatted_config_diff
)

PATCH = 'patch'
DELETE = 'delete'
URL = 'data/openconfig-mirror-ext:mirror/sessions'
TEST_KEYS = [
    {'span': {'name': ''}},
    {'erspan': {'name': ''}},
]
delete_all = False


def __derive_config_delete_op(key_set, command, exist_conf):
    if delete_all:
        new_conf = {}
        return True, new_conf

    done, new_conf = __DELETE_LEAFS_OR_CONFIG_IF_NO_NON_KEY_LEAF(key_set, command, exist_conf)
    return done, new_conf


TEST_KEYS_generate_config = [
    {'span': {'name': '', '__delete_op': __derive_config_delete_op}},
    {'erspan': {'name': '', '__delete_op': __derive_config_delete_op}}
]


class Mirroring(ConfigBase):
    """
    The sonic_mirroring class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'mirroring',
    ]

    def __init__(self, module):
        super(Mirroring, self).__init__(module)

    def get_mirroring_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset,
                                                         self.gather_network_resources)
        mirroring_facts = facts['ansible_network_resources'].get('mirroring')
        if not mirroring_facts:
            return {}
        return mirroring_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        existing_mirroring_facts = self.get_mirroring_facts()
        commands, requests = self.set_config(existing_mirroring_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_mirroring_facts = self.get_mirroring_facts()

        result['before'] = existing_mirroring_facts
        if result['changed']:
            result['after'] = changed_mirroring_facts

        new_config = changed_mirroring_facts
        old_config = existing_mirroring_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, old_config, TEST_KEYS_generate_config)
            new_config = remove_empties(new_config)
            self.sort_mirrors(new_config)
            result['after(generated)'] = new_config

        if self._module._diff:
            self.sort_mirrors(old_config)
            self.sort_mirrors(new_config)
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)
        return result

    def set_config(self, existing_mirroring_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = remove_empties(self._module.params['config'])
        have = existing_mirroring_facts
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
        state = self._module.params['state']
        new_want = self.preprocess_want(want)
        self.validate_want(new_want)

        commands = []
        requests = []
        if not new_want:
            new_want = {}

        diff = get_diff(new_want, have, TEST_KEYS)
        if state == 'overridden':
            commands, requests = self._state_overridden(new_want, have, diff)
        elif state == 'replaced':
            commands, requests = self._state_replaced(new_want, have, diff)
        elif state == 'deleted':
            commands, requests = self._state_deleted(new_want, have, diff)
        elif state == 'merged':
            commands, requests = self._state_merged(diff)
        return commands, requests

    def _state_merged(self, diff):
        """ The command generator when state is merged

        :param want: the additive configuration as a dictionary
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to merge the specified playbook options into
                  the current configuration
        """
        commands = []
        command = diff
        requests = self.get_modify_mirroring_requests(command)
        if command and len(requests) > 0:
            commands = update_states([command], 'merged')
        else:
            commands = []
        return commands, requests

    def _state_deleted(self, want, have, diff):
        """ The command generator when state is deleted

        :param want: the objects from which the configuration should be removed
        :param have: the current configuration as a dictionary
        :rtype: A list
        :returns: the commands necessary to remove the specified playbook options from the current configuration
        """
        # if want is none, then delete all the mirroring except admin
        commands = []
        global delete_all
        delete_all = False
        if not want:
            command = have
            delete_all = True
        else:
            command = get_diff(want, diff, TEST_KEYS)

        requests = self.get_delete_mirroring_requests(command, delete_all)

        if command and len(requests) > 0:
            commands = update_states([command], 'deleted')

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
            del_requests = self.get_delete_mirroring_requests(replaced_config)
            requests.extend(del_requests)
            commands.extend(update_states(replaced_config, 'deleted'))
            add_commands = want
        else:
            add_commands = diff

        if add_commands:
            add_requests = self.get_modify_mirroring_requests(add_commands)
            if len(add_requests) > 0:
                requests.extend(add_requests)
                commands.extend(update_states(add_commands, 'replaced'))

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
        global delete_all
        delete_all = False
        r_diff = get_diff(have, want, TEST_KEYS)
        if have and (diff or r_diff):
            delete_all = True
            del_requests = self.get_delete_mirroring_requests(have, delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(have, 'deleted'))
            have = []

        if not have and want:
            want_commands = want
            want_requests = self.get_modify_mirroring_requests(want_commands)

            if len(want_requests) > 0:
                requests.extend(want_requests)
                commands.extend(update_states(want_commands, 'overridden'))

        return commands, requests

    def get_modify_span_requests(self, command):
        requests = []

        config = []
        span = command.get('span', [])
        if span:
            for ms in span:
                name = ms.get('name')
                dst_port = ms.get('dst_port')
                source = ms.get('source')
                direction = ms.get('direction')

                conf = {'name': name}
                if dst_port:
                    conf['dst-port'] = dst_port
                if source:
                    conf['src-port'] = source
                if direction:
                    conf['direction'] = direction.upper()

                config.append({'name': name, 'config': conf})

            path = URL
            payload = {'openconfig-mirror-ext:sessions': {'session': config}}
            request = {'path': path, 'method': PATCH, 'data': payload}
            requests.append(request)

        return requests

    def get_modify_erspan_requests(self, command):
        requests = []

        config = []
        erspan = command.get('erspan', [])
        if erspan:
            for ms in erspan:
                name = ms.get('name')
                dst_ip = ms.get('dst_ip')
                src_ip = ms.get('src_ip')
                source = ms.get('source')
                direction = ms.get('direction')
                dscp = ms.get('dscp')
                gre = ms.get('gre')
                ttl = ms.get('ttl')
                queue = ms.get('queue')

                conf = {'name': name}
                if dst_ip:
                    conf['dst-ip'] = dst_ip
                if src_ip:
                    conf['src-ip'] = src_ip
                if source:
                    conf['src-port'] = source
                if direction:
                    conf['direction'] = direction.upper()
                if dscp is not None:
                    conf['dscp'] = dscp
                if gre:
                    conf['gre-type'] = gre
                if ttl is not None:
                    conf['ttl'] = ttl
                if queue is not None:
                    conf['queue'] = queue

                config.append({'name': name, 'config': conf})

            path = URL
            payload = {'openconfig-mirror-ext:sessions': {'session': config}}
            request = {'path': path, 'method': PATCH, 'data': payload}
            requests.append(request)

        return requests

    def get_modify_mirroring_requests(self, command):
        requests = []
        if not command:
            return requests

        span_requests = self.get_modify_span_requests(command)
        if span_requests:
            requests.extend(span_requests)

        erspan_requests = self.get_modify_erspan_requests(command)
        if erspan_requests:
            requests.extend(erspan_requests)

        return requests

    def get_delete_mirroring_requests(self, command, is_delete_all=False):
        requests = []

        if not command:
            return requests

        if is_delete_all:
            requests.append(self.get_delete_mirror_session_request())
            return requests

        span = command.get('span', [])
        erspan = command.get('erspan', [])

        for ms in span:
            name = ms['name']
            if len(ms) == 1:
                requests.append(self.get_delete_mirror_session_request(name))
                continue
            if ms.get('source'):
                requests.append(self.get_delete_mirror_session_request(name, 'src-port'))
            if ms.get('direction'):
                requests.append(self.get_delete_mirror_session_request(name, 'direction'))
            if ms.get('dst_port'):
                requests.append(self.get_delete_mirror_session_request(name, 'dst-port'))

        for ms in erspan:
            name = ms['name']
            if len(ms) == 1:
                requests.append(self.get_delete_mirror_session_request(name))
                continue
            if ms.get('src_ip'):
                requests.append(self.get_delete_mirror_session_request(name, 'src-ip'))
            if ms.get('source'):
                requests.append(self.get_delete_mirror_session_request(name, 'src-port'))
            if ms.get('direction'):
                requests.append(self.get_delete_mirror_session_request(name, 'direction'))
            if ms.get('dscp') is not None:
                requests.append(self.get_delete_mirror_session_request(name, 'dscp'))
            if ms.get('gre'):
                requests.append(self.get_delete_mirror_session_request(name, 'gre-type'))
            if ms.get('ttl') is not None:
                requests.append(self.get_delete_mirror_session_request(name, 'ttl'))
            if ms.get('queue') is not None:
                requests.append(self.get_delete_mirror_session_request(name, 'queue'))
            if ms.get('dst_ip'):
                requests.append(self.get_delete_mirror_session_request(name, 'dst-ip'))

        return requests

    def validate_want(self, want):
        if not want:
            return

        span = want.get('span', [])
        erspan = want.get('erspan', [])

        if span and erspan:
            for ms in span:
                name = ms['name']
                in_erspan = next((ems for ems in erspan if name == ems['name']), None)
                if in_erspan:
                    err_msg = 'Names of SPAN and ERSPAN mirror sessions should not be duplicated.'
                    self._module.fail_json(msg=err_msg, code=400)

    def preprocess_want(self, want):
        if not want:
            return want

        span = want.get('span', [])
        erspan = want.get('erspan', [])
        for ms in span:
            dst_port = ms.get('dst_port')
            if dst_port and dst_port != 'CPU':
                ms['dst_port'] = get_normalize_interface_name(dst_port, self._module)
            source = ms.get('source')
            if source:
                ms['source'] = get_normalize_interface_name(source, self._module)

        for ms in erspan:
            source = ms.get('source')
            if source:
                ms['source'] = get_normalize_interface_name(source, self._module)

        return want

    def sort_mirrors(self, mirror_sessions):
        if not mirror_sessions:
            return

        span = mirror_sessions.get('span', [])
        if span:
            span.sort(key=lambda x: x['name'])

        erspan = mirror_sessions.get('erspan', [])
        if erspan:
            erspan.sort(key=lambda x: x['name'])

    def get_delete_mirror_session_request(self, name=None, attr=None):
        url = URL
        if name:
            url += '/session=%s' % (name)
        if attr:
            url += '/config/%s' % (attr)
        request = {'path': url, 'method': DELETE}
        return request
