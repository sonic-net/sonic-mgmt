from __future__ import absolute_import, division, print_function
__metaclass__ = type

from copy import deepcopy
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
    update_states,
    get_diff,
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.formatted_diff_utils import (
    get_new_config,
    get_formatted_config_diff,
    __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF
)
from ansible.module_utils.connection import ConnectionError

PATCH = 'patch'
DELETE = 'delete'

TEST_KEYS = [
    {'config': {'name': ''}}
]

TEST_KEYS_overridden_diff = [
    {'config': {'name': '', '__delete_op': __DELETE_LEAFS_THEN_CONFIG_IF_NO_NON_KEY_LEAF}}
]

OSPF_INT_ATTRIBUTES = {
    'bfd': {
        'enable': '/enable-bfd',
        'bfd_profile': '/enable-bfd/config/bfd-profile'
    },
    'network': '/config/network-type',
    'area_id': '/config/area-id',
    'cost': '/config/metric',
    'dead_interval': '/config/dead-interval',
    'hello_interval': '/config/hello-interval',
    'mtu_ignore': '/config/mtu-ignore',
    'priority': '/config/priority',
    'retransmit_interval': '/config/retransmission-interval',
    'transmit_delay': '/config/transmit-delay',
    'passive': '/config/passive',
    'advertise': '/config/advertise'

}


class Ospfv3_interfaces(ConfigBase):
    """
    The sonic_ospfv3_interfaces class
    """

    gather_subset = [
        '!all',
        '!min',
    ]

    gather_network_resources = [
        'ospfv3_interfaces',
    ]

    def __init__(self, module):

        super(Ospfv3_interfaces, self).__init__(module)

    def get_ospfv3_interfaces_facts(self):
        """ Get the 'facts' (the current configuration)
        :rtype: A list
        :returns: The current configuration as a dictionary
        """
        facts, _warnings = Facts(self._module).get_facts(self.gather_subset, self.gather_network_resources)
        ospfv3_interfaces_facts = facts['ansible_network_resources'].get('ospfv3_interfaces')
        if not ospfv3_interfaces_facts:
            return []
        return ospfv3_interfaces_facts

    def execute_module(self):
        result = {'changed': False}
        warnings = list()
        commands = list()

        existing_ospfv3_interfaces_facts = self.get_ospfv3_interfaces_facts()
        commands, requests = self.set_config(existing_ospfv3_interfaces_facts)
        if commands and len(requests) > 0:
            if not self._module.check_mode:
                try:
                    edit_config(self._module, to_request(self._module, requests))
                except ConnectionError as exc:
                    self._module.fail_json(msg=str(exc), code=exc.code)
            result['changed'] = True
        result['commands'] = commands

        changed_ospfv3_interfaces_facts = self.get_ospfv3_interfaces_facts()

        result['before'] = existing_ospfv3_interfaces_facts
        if result['changed']:
            result['after'] = changed_ospfv3_interfaces_facts

        new_config = changed_ospfv3_interfaces_facts
        old_config = existing_ospfv3_interfaces_facts
        if self._module.check_mode:
            result.pop('after', None)
            new_commands = deepcopy(commands)
            new_config = get_new_config(new_commands, old_config, TEST_KEYS)
            new_config = self.new_cfg(new_config)
            new_config.sort(key=lambda x: x['name'])
            result['after(generated)'] = remove_empties_from_list(new_config)

        if self._module._diff:
            result['diff'] = get_formatted_config_diff(old_config, new_config, self._module._verbosity)

        result['warnings'] = warnings
        return result

    def set_config(self, existing_ospfv3_interfaces_facts):
        """ Collect the configuration from the args passed to the module,
            collect the current configuration (as a list from facts)
            :rtype: A list
            :returns: the commands necessary to migrate the current configuration
            to the desired configuration
        """
        want = self._module.params['config']
        have = existing_ospfv3_interfaces_facts
        new_want = deepcopy(want)
        new_have = deepcopy(have)
        new_want = remove_empties_from_list(want)
        new_have = remove_empties_from_list(have)
        new_want.sort(key=lambda x: x['name'])
        new_have.sort(key=lambda x: x['name'])
        resp = self.set_state(new_want, new_have)
        return to_list(resp)

    def set_state(self, want, have):
        """ Select the appropriate function based on the state provided
        :param want: the desired configuration as a list
        :param have: the current configuration as a list
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, requests = [], []
        state = self._module.params['state']

        if state == 'overridden' or state == 'replaced':
            commands, requests = self._state_replaced_or_overridden(want, have)
        elif state == 'deleted':
            commands, requests = self._state_deleted(want, have)
        elif state == 'merged':
            commands, requests = self._state_merged(want, have)

        return commands, requests

    def _state_replaced_or_overridden(self, want, have):
        """ The command generator when state is replaced or overridden
        :rtype: A list
        :returns: the commands necessary to migrate the current configuration
                  to the desired configuration
        """
        commands, requests = [], []
        add_config, del_config = self._get_replaced_overridden_config(want, have)
        if del_config:
            del_commands, del_requests = self.get_delete_ospf_interfaces_commands_requests(del_config, have, False)
            if len(del_requests) > 0:
                commands.extend(update_states(del_commands, 'deleted'))
                requests.extend(del_requests)

        if add_config:
            mod_requests = self.get_create_ospf_interfaces_requests(add_config, [])
            if len(mod_requests) > 0:
                commands.extend(update_states(add_config, self._module.params['state']))
                requests.extend(mod_requests)

        return commands, requests

    def _state_merged(self, want, have):
        """ The command generator when state is merged
        :rtype: A list
        :returns: the commands necessary to merge the provided into
                  the current configuration
        """
        commands = get_diff(want, have)
        requests = self.get_create_ospf_interfaces_requests(commands, have)

        if commands and len(requests) > 0:
            commands = update_states(commands, 'merged')
        else:
            commands = []

        return commands, requests

    def _state_deleted(self, want, have):
        """ The command generator when state is deleted
        :rtype: A list
        :returns: the commands necessary to remove the current configuration
                  of the provided objects
        """
        commands, requests = [], []
        is_delete_all = False

        if not want:
            commands = have
            is_delete_all = True
        else:
            commands = want

        del_commands, requests = self.get_delete_ospf_interfaces_commands_requests(commands, have, is_delete_all)

        if del_commands and len(requests) > 0:
            commands = update_states(del_commands, 'deleted')
        else:
            commands = []

        return commands, requests

    def _get_replaced_overridden_config(self, want, have):
        add_config, del_config = [], []
        state = self._module.params['state']
        for conf in want:
            intf_name = conf.get('name')
            have_conf = next((cfg for cfg in have if cfg['name'] == intf_name), None)
            if not have_conf:
                add_config.append(conf)
            else:
                add_cfg, del_cfg = {}, {}
                for attr in OSPF_INT_ATTRIBUTES:
                    if attr in conf:
                        if attr not in have_conf:
                            add_cfg[attr] = conf[attr]
                        else:
                            if attr == 'bfd':
                                for bfd_attr in ['enable', 'bfd_profile']:
                                    if bfd_attr in conf[attr]:
                                        if bfd_attr not in have_conf[attr]:
                                            add_cfg.setdefault(attr, {})[bfd_attr] = conf[attr][bfd_attr]
                                        elif conf[attr][bfd_attr] != have_conf[attr][bfd_attr]:
                                            add_cfg.setdefault(attr, {})[bfd_attr] = conf[attr][bfd_attr]
                                    elif bfd_attr in have_conf[attr]:
                                        del_cfg.setdefault(attr, {})[bfd_attr] = have_conf[attr][bfd_attr]
                            elif attr == 'network':
                                if conf[attr] != have_conf[attr]:
                                    add_cfg[attr] = conf[attr]
                            elif attr == 'area':
                                if (attr in conf and attr not in have_conf):
                                    add_cfg[attr] = conf[attr]
                                elif (attr in conf and attr in have_conf and conf[attr] != have_conf[attr]):
                                    del_cfg = have_conf[attr]
                                    add_cfg[attr] = conf[attr]
                            else:
                                if (attr in conf and attr not in have_conf):
                                    add_cfg[attr] = conf[attr]
                                elif (attr in conf and attr in have_conf and conf[attr] != have_conf[attr]):
                                    add_cfg[attr] = conf[attr]
                    elif attr in have_conf:
                        del_cfg[attr] = have_conf[attr]
                if add_cfg:
                    add_cfg['name'] = intf_name
                    add_config.append(add_cfg)
                if del_cfg:
                    del_cfg['name'] = intf_name
                    del_config.append(del_cfg)

        if state == 'overridden':
            for conf in have:
                intf_name = conf.get('name')
                want_conf = next((cfg for cfg in want if cfg['name'] == intf_name), None)
                if not want_conf:
                    del_config.append({'name': intf_name})
        return add_config, del_config

    def get_create_ospf_interfaces_requests(self, commands, have):
        requests = []
        bfd_dict = {}
        if not commands:
            return requests

        for cmd in commands:
            payload = {}
            bfd_dict = {}
            name = cmd.get('name')
            match = next((item for item in have if item['name'] == cmd['name']), None)
            intf_name, sub_intf = self.get_ospf_if_and_subif(name)
            ospf_path = self.get_ospf_uri(intf_name, sub_intf)
            ospf_attr_configs = {}
            # default_address_attr_dict = {}
            network_type = ""
            area_id = cmd.get('area_id')
            have_area_id = None
            if match is not None:
                have_area_id = match.get('area_id')
            if area_id and have_area_id and have_area_id != area_id:
                path = ospf_path + OSPF_INT_ATTRIBUTES['area_id']
                requests.append({'path': path, 'method': DELETE})
            self.update_dict(cmd, ospf_attr_configs, 'area_id', 'area-id')
            self.update_dict(cmd, ospf_attr_configs, 'cost', 'metric')
            self.update_dict(cmd, ospf_attr_configs, 'dead_interval', 'dead-interval')
            self.update_dict(cmd, ospf_attr_configs, 'hello_interval', 'hello-interval')
            self.update_dict(cmd, ospf_attr_configs, 'mtu_ignore', 'mtu-ignore')
            self.update_dict(cmd, ospf_attr_configs, 'priority', 'priority')
            self.update_dict(cmd, ospf_attr_configs, 'retransmit_interval', 'retransmission-interval')
            self.update_dict(cmd, ospf_attr_configs, 'transmit_delay', 'transmit-delay')
            self.update_dict(cmd, ospf_attr_configs, 'passive', 'passive')
            self.update_dict(cmd, ospf_attr_configs, 'advertise', 'advertise')

            if 'bfd' in cmd:
                attr = 'bfd'
                self.update_dict(cmd[attr], bfd_dict, 'enable', 'enabled')
                self.update_dict(cmd[attr], bfd_dict, 'bfd_profile', 'bfd-profile')
            # network_type = cmd.get('network')
            if 'network' in cmd:
                network_type = cmd.get('network')
                network_type = network_type.upper() + '_NETWORK'
                # self.update_dict(cmd, ospf_attr_configs, 'network_type', 'network-type')
                ospf_attr_configs['network-type'] = network_type
            if ospf_attr_configs:
                payload = {
                    'openconfig-ospfv3-ext:ospfv3': {
                        'config': ospf_attr_configs
                    }
                }
                requests.append({'path': ospf_path, 'method': PATCH, 'data': payload})
            if bfd_dict:
                payload = {
                    'openconfig-ospfv3-ext:ospfv3': {
                        'enable-bfd': {'config': bfd_dict}
                    }
                }
                requests.append({'path': ospf_path, 'method': PATCH, 'data': payload})
        return requests

    def get_delete_ospf_interfaces_commands_requests(self, commands, have, is_delete_all):
        commands_del, requests = [], []
        if not commands:
            return commands_del, requests

        for cmd in commands:
            del_cmd = {}
            name = cmd.get('name')
            intf_name, sub_intf = self.get_ospf_if_and_subif(name)
            ospf_path = self.get_ospf_uri(intf_name, sub_intf)
            match_have = next((cfg for cfg in have if cfg['name'] == name), None)
            if match_have:
                if is_delete_all or len(cmd) == 1:
                    commands_del.append(match_have)
                    requests.append({'path': ospf_path, 'method': DELETE})
                    continue
                for attr in cmd:
                    if attr == 'name':
                        continue
                    if attr == 'bfd':
                        if 'enable' in cmd.get(attr, {}) and 'enable' in match_have.get(attr, {}):
                            path = ospf_path + OSPF_INT_ATTRIBUTES['bfd']['enable']
                            requests.append({'path': path, 'method': DELETE})
                            del_cmd.setdefault(attr, {})['enable'] = match_have[attr]['enable']
                            if 'bfd_profile' in match_have.get(attr, {}):
                                del_cmd[attr]['bfd_profile'] = match_have[attr]['bfd_profile']
                        elif 'bfd_profile' in cmd.get(attr, {}) and 'bfd_profile' in match_have.get(attr, {}):
                            path = ospf_path + OSPF_INT_ATTRIBUTES['bfd']['bfd_profile']
                            requests.append({'path': path, 'method': DELETE})
                            del_cmd.setdefault(attr, {})['bfd_profile'] = match_have[attr]['bfd_profile']
                    elif attr == 'network' and match_have.get(attr, {}):
                        path = ospf_path + OSPF_INT_ATTRIBUTES['network']
                        requests.append({'path': path, 'method': DELETE})
                        del_cmd[attr] = match_have[attr]
                    else:
                        match_ospf_attrs = match_have.get(attr, [])
                        ospf_attrs = cmd.get(attr)
                        if match_ospf_attrs and ospf_attrs:
                            path = ospf_path + OSPF_INT_ATTRIBUTES[attr]
                            requests.append({'path': path, 'method': DELETE})
                            del_cmd[attr] = match_ospf_attrs

                if del_cmd:
                    del_cmd['name'] = name
                    commands_del.append(del_cmd)
        return commands_del, requests

    def get_ospf_uri(self, intf_name, sub_intf=0):
        ospf_uri = self.get_ospf_intf_uri(intf_name, sub_intf)
        ospf_uri += '/openconfig-if-ip:ipv6/openconfig-ospfv3-ext:ospfv3'
        return ospf_uri

    def get_ospf_intf_uri(self, intf_name, sub_intf=0):
        intf_name = intf_name.replace('/', '%2f')
        ospf_intf_uri = '/data/openconfig-interfaces:interfaces/interface={}'.format(intf_name)
        if intf_name.startswith('Vlan'):
            ospf_intf_uri += '/openconfig-vlan:routed-vlan'
        else:
            ospf_intf_uri += '/subinterfaces/subinterface={}'.format(sub_intf)
        return ospf_intf_uri

    def get_ospf_if_and_subif(self, intf_name):
        return intf_name.split('.') if '.' in intf_name else (intf_name, 0)

    def update_dict(self, src, dest, src_key, dest_key, value=False):
        if not value:
            if src.get(src_key) is not None:
                dest[dest_key] = src[src_key]
        elif src:
            dest.update(value)

    def check_config(self , conf, have_conf, key, add_key, del_key, add_config, del_config):
        if not have_conf and conf.get(key):
            add_config.append(conf.get(add_key))
        elif have_conf != conf.get(key) and conf.get(key):
            del_config.append(have_conf.get(del_key))
            add_config.append(conf.get(add_key))
        elif have_conf and not conf.get(key):
            del_config.append(have_conf.get(del_key))

    def new_cfg(self, new_config):
        new_list = []
        for d in new_config:
            if len(d) == 1 and 'name' in d:
                pass
            else:
                new_list.append(d)
        return new_list
