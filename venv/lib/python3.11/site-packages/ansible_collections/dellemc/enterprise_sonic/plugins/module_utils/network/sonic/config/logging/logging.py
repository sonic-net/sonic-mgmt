#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic_logging class
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
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.facts.facts import Facts
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    get_diff,
    update_states,
    get_normalize_interface_name,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    __DELETE_CONFIG_IF_NO_SUBCONFIG,
    get_new_config,
    get_formatted_config_diff
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'PATCH'
DELETE = 'DELETE'

DEFAULT_REMOTE_PORT = 514
DEFAULT_LOG_TYPE = 'log'
DEFAULT_PROTOCOL = 'UDP'
DEFAULT_SEVERITY = 'notice'

TEST_KEYS = [
    {
        "remote_servers": {"host": ""}
    }
]
TEST_KEYS_formatted_diff = [
    {
        "remote_servers": {"host": "", '__delete_op': __DELETE_CONFIG_IF_NO_SUBCONFIG}
    }
]


class Logging(ConfigBase):
    """
    The sonic_logging class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'logging',
    ]

    def __init__(self, module):
        super(Logging, self).__init__(module)

    def get_logging_facts(self):
        """ Get the 'facts' (the current configuration)

        :rtype: A dictionary
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        logging_facts = facts['ansible_network_resources'].get('logging')
        if not logging_facts:
            return []
        return logging_facts

    def execute_module(self):
        """ Execute the module

        :rtype: A dictionary
        :returns: The result from module execution
        """
        result = {'changed': False}
        warnings = list()
        commands = list()
        requests = list()

        existing_logging_facts = self.get_logging_facts()

        commands, requests = self.set_config(existing_logging_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_logging_facts = self.get_logging_facts()

        result['before'] = existing_logging_facts
        if result['changed']:
            result['after'] = changed_logging_facts

        new_config = changed_logging_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_config = get_new_config(commands, existing_logging_facts,
                                        TEST_KEYS_formatted_diff)
            result['after(generated)'] = new_config

        if self._module._diff:
            result['diff'] = get_formatted_config_diff(existing_logging_facts,
                                                       new_config,
                                                       self._module._verbosity)
        result['warnings'] = warnings
        return result

    def set_config(self, existing_logging_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a dict from facts)

        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        want = self._module.params['config']
        if want is None:
            want = []

        have = existing_logging_facts
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

        self.preprocess_want(want, state)

        if state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)
        elif state == 'overridden':
            commands, requests = self._state_overridden(want, have)
        elif state == 'replaced':
            commands, requests = self._state_replaced(want, have)

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged

        :param want: the additive configuration as a dictionary
        :param have: the current configuration as a dictionary
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        diff = get_diff(want, have, TEST_KEYS)

        commands = diff
        requests = []
        if commands:
            requests = self.get_merge_requests(commands, have)

        if len(requests) > 0:
            commands = update_states(commands, "merged")
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted

        :param want: the objects from which the configuration should be removed
        :param have: the current configuration as a dictionary
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        # Get a list of requested servers to delete that are not present in the current
        # configuration on the device. This list can be used to filter out these
        # unconfigured servers from the list of "delete" commands to be sent to the switch.
        unconfigured = get_diff(want, have, TEST_KEYS)

        want_none = {'remote_servers': None, 'security_profile': None}
        want_any = get_diff(want, want_none, TEST_KEYS)
        # If want_any is none, then delete all logging configuration.

        delete_all = False
        if not want_any:
            commands = have
            delete_all = True
        else:
            if not unconfigured:
                commands = want_any
            else:
                # Some of the servers requested for deletion are not in the current
                # device configuration. Filter these out of the list to be used for sending
                # "delete" commands to the device.
                commands = get_diff(want_any, unconfigured, TEST_KEYS)

        requests = []
        if commands:
            requests = self.get_delete_requests(commands, delete_all)

        if len(requests) > 0:
            commands = update_states(commands, "deleted")
        else:
            commands = []

        return commands, requests

    def _state_replaced(self, want, have):
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

        replaced_config = self.get_replaced_config(have, want)
        if 'remote_servers' in replaced_config:
            replaced_config['remote_servers'].sort(key=self.get_host)
        if 'remote_servers' in want:
            want['remote_servers'].sort(key=self.get_host)

        if replaced_config and replaced_config != want:
            delete_all = False
            del_requests = self.get_delete_requests(replaced_config, delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(replaced_config, "deleted"))
            replaced_config = []

        if not replaced_config and want:
            add_commands = want
            add_requests = self.get_merge_requests(add_commands, replaced_config)

            if len(add_requests) > 0:
                requests.extend(add_requests)
                commands.extend(update_states(add_commands, "replaced"))

        return commands, requests

    def _state_overridden(self, want, have):
        """ The command generator when state is overridden

        :param want: the desired configuration as a dictionary
        :param have: the current configuration as a dictionary
        :param diff: the difference between want and have
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        if 'remote_servers' in have:
            have['remote_servers'].sort(key=self.get_host)
        if 'remote_servers' in want:
            want['remote_servers'].sort(key=self.get_host)

        commands = []
        requests = []

        want.setdefault('security_profile', None)
        if have and have != want:
            delete_all = True
            del_requests = self.get_delete_requests(have, delete_all)
            requests.extend(del_requests)
            commands.extend(update_states(have, "deleted"))
            have = []

        if not have and want:
            add_commands = want
            add_requests = self.get_merge_requests(add_commands, have)

            if len(add_requests) > 0:
                requests.extend(add_requests)
                commands.extend(update_states(add_commands, "overridden"))

        return commands, requests

    def get_host(self, remote_server):
        return remote_server.get('host')

    def search_config_servers(self, host, servers):

        if servers is not None:
            for server in servers:
                if server['host'] == host:
                    return server
        return []

    def get_replaced_config(self, have, want):

        replaced_config = dict()
        replaced_servers = []

        if have.get('security_profile') and want.get('security_profile'):
            replaced_config['security_profile'] = have['security_profile']

        if 'remote_servers' in have and 'remote_servers' in want:
            for server in want['remote_servers']:
                replaced_server = self.search_config_servers(server['host'], have['remote_servers'])
                if replaced_server:
                    replaced_servers.append(replaced_server)

        replaced_config['remote_servers'] = replaced_servers
        return replaced_config

    def preprocess_want(self, want, state):

        if state == 'merged':
            if 'remote_servers' in want and want['remote_servers'] is not None:
                for server in want['remote_servers']:
                    if 'source_interface' in server and not server['source_interface']:
                        server.pop('source_interface', None)
                    else:
                        server['source_interface'] = \
                            get_normalize_interface_name(server['source_interface'], self._module)
                    if 'remote_port' in server and not server['remote_port']:
                        server.pop('remote_port', None)
                    if 'protocol' in server and not server['protocol']:
                        server.pop('protocol', None)
                    if 'message_type' in server and not server['message_type']:
                        server.pop('message_type', None)
                    if 'severity' in server and not server['severity']:
                        server.pop('severity', None)
                    if 'vrf' in server and not server['vrf']:
                        server.pop('vrf', None)

            if 'remote_servers' in want and want['remote_servers'] is None:
                want.pop('remote_servers')

            if 'security_profile' in want and want['security_profile'] is None:
                want.pop('security_profile')

        if state == 'replaced' or state == 'overridden':
            if 'remote_servers' in want and want['remote_servers'] is not None:
                for server in want['remote_servers']:
                    if 'source_interface' in server and not server['source_interface']:
                        server.pop('source_interface', None)
                    else:
                        server['source_interface'] = \
                            get_normalize_interface_name(server['source_interface'], self._module)
                    if 'remote_port' in server and not server['remote_port']:
                        server['remote_port'] = DEFAULT_REMOTE_PORT
                    if 'message_type' in server and not server['message_type']:
                        server['message_type'] = DEFAULT_LOG_TYPE
                    if 'protocol' in server and not server['protocol']:
                        server['protocol'] = DEFAULT_PROTOCOL
                    if 'severity' in server and not server['severity']:
                        server['severity'] = DEFAULT_SEVERITY

            if 'remote_servers' in want and want['remote_servers'] is None:
                want.pop('remote_servers')

            if 'security_profile' in want and want['security_profile'] is None:
                want.pop('security_profile')

    def get_merge_requests(self, configs, have):

        requests = []

        servers_config = configs.get('remote_servers', None)
        if servers_config:
            servers_request = self.get_create_servers_requests(servers_config, have)
            if servers_request:
                requests.extend(servers_request)

        if 'security_profile' in configs and configs['security_profile'] is not None:
            payload = {'openconfig-system-ext:security-profile': configs['security_profile']}
            url = 'data/openconfig-system:system/openconfig-system-ext:syslog/config/security-profile'
            requests.append({'path': url, 'method': PATCH, 'data': payload})

        return requests

    def get_delete_requests(self, configs, delete_all):

        requests = []

        servers_config = configs.get('remote_servers', None)
        if servers_config:
            servers_request = []
            if delete_all:
                servers_request = self.get_delete_all_servers_requests()
            else:
                servers_request = self.get_delete_servers_requests(servers_config)

            if servers_request:
                requests.extend(servers_request)

        if configs.get('security_profile'):
            url = 'data/openconfig-system:system/openconfig-system-ext:syslog/config/security-profile'
            requests.append({'path': url, 'method': DELETE})

        return requests

    def get_create_servers_requests(self, configs, have):

        requests = []

        # Create URL and payload
        method = PATCH
        url = 'data/openconfig-system:system/logging/remote-servers'
        server_configs = []
        for config in configs:
            req_config = dict()
            req_config['host'] = config['host']
            if 'source_interface' in config:
                req_config['source-interface'] = config['source_interface']
            if 'message_type' in config:
                req_config['message-type'] = config['message_type']
            if 'severity' in config and config.get("severity") is not None:
                req_config['severity'] = (config.get("severity", "").upper()).replace("INFO", "INFORMATIONAL")
            if 'remote_port' in config:
                req_config['remote-port'] = config['remote_port']
            if 'protocol' in config:
                req_config['protocol'] = config['protocol']
            if 'vrf' in config:
                req_config['vrf-name'] = config['vrf']

            server_host = config['host']
            server_config = {"host": server_host, "config": req_config}
            server_configs.append(server_config)

        payload = {"openconfig-system:remote-servers": {"remote-server": server_configs}}
        request = {"path": url, "method": method, "data": payload}
        requests.append(request)

        return requests

    def get_delete_servers_requests(self, configs):

        requests = []

        # Create URL and payload
        method = DELETE
        for config in configs:
            server_host = config['host']
            url = 'data/openconfig-system:system/logging/remote-servers/remote-server={0}'.format(server_host)
            if not (config.get("vrf") or config.get("source_interface") or config.get("message_type") or
                    config.get("remote_port") or config.get("protocol") or config.get("severity")):
                request = {"path": url, "method": method}
                requests.append(request)
            else:
                if config.get('source_interface'):
                    request = {"path": "{}/config/openconfig-system-ext:source-interface".format(url), "method": method}
                    requests.append(request)
                if config.get("message_type"):
                    request = {"path": "{}/config/openconfig-system-ext:message-type".format(url), "method": method}
                    requests.append(request)
                if config.get("vrf"):
                    request = {"path": "{}/config/openconfig-system-ext:vrf-name".format(url), "method": method}
                    requests.append(request)
                if config.get("remote_port"):
                    request = {"path": "{}/config/remote-port".format(url), "method": method}
                    requests.append(request)
                if config.get("protocol"):
                    request = {"path": "{}/config/openconfig-system-ext:protocol".format(url), "method": method}
                    requests.append(request)
                if config.get("severity"):
                    request = {"path": "{}/config/openconfig-system-ext:severity".format(url), "method": method}
                    requests.append(request)
        return requests

    def get_delete_all_servers_requests(self):

        requests = []

        # Create URL and payload
        method = DELETE
        url = 'data/openconfig-system:system/logging/remote-servers'
        request = {"path": url, "method": method}
        requests.append(request)

        return requests
