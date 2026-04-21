from __future__ import absolute_import, division, print_function
__metaclass__ = type


from copy import deepcopy

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ospfv3_interfaces.ospfv3_interfaces import Ospfv3_interfacesArgs

from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties_from_list
)
from ansible.module_utils.connection import ConnectionError


class Ospfv3_interfacesFacts(object):
    """ The sonic ospfv3_interfaces fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Ospfv3_interfacesArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for ospfv3_interfaces
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        all_ospfv3_interface_configs = {}
        if not data:
            all_ospfv3_interface_configs = self.get_ospfv3_interfaces()

        for ospfv3_interface_config in all_ospfv3_interface_configs:
            if ospfv3_interface_config:
                objs.append(ospfv3_interface_config)

        ansible_facts['ansible_network_resources'].pop('ospfv3_interfaces', None)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['ospfv3_interfaces'] = remove_empties_from_list(params['config'])

        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def get_ospfv3_interfaces(self):
        """Get all OSPFv3 interfaces available in chassis"""
        request = [{"path": "data/openconfig-interfaces:interfaces", "method": "GET"}]

        try:
            response = edit_config(self._module, to_request(self._module, request))
        except ConnectionError as exc:
            self._module.fail_json(msg=str(exc), code=exc.code)
        ospf_configs = []

        if "openconfig-interfaces:interfaces" in response[0][1]:
            interfaces = response[0][1].get("openconfig-interfaces:interfaces", {})
            if interfaces.get('interface'):
                interfaces = interfaces['interface']
            for interface in interfaces:
                intf_name = interface.get('name')
                if intf_name == "eth0":
                    continue
                ospf_config = {}
                if interface.get('openconfig-vlan:routed-vlan'):
                    ospf = interface.get('openconfig-vlan:routed-vlan', {})
                else:
                    ospf = interface.get('subinterfaces', {}).get('subinterface', [{}])[0]
                if ospf:
                    ipv6 = ospf.get('openconfig-if-ip:ipv6', {})
                    if ipv6:
                        ospf_int = ipv6.get('openconfig-ospfv3-ext:ospfv3', {})
                        if ospf_int:
                            config = ospf_int.get('config', {})
                            if config:
                                self.update_dict(ospf_config, 'area_id', config.get('area-id'))
                                self.update_dict(ospf_config, 'cost', config.get('metric'))
                                self.update_dict(ospf_config, 'hello_interval', config.get('hello-interval'))
                                self.update_dict(ospf_config, 'dead_interval', config.get('dead-interval'))
                                self.update_dict(ospf_config, 'mtu_ignore', config.get('mtu-ignore'))
                                self.update_dict(ospf_config, 'priority', config.get('priority'))
                                self.update_dict(ospf_config, 'retransmit_interval', config.get('retransmission-interval'))
                                self.update_dict(ospf_config, 'transmit_delay', config.get('transmit-delay'))
                                self.update_dict(ospf_config, 'passive', config.get('passive'))
                                self.update_dict(ospf_config, 'advertise', config.get('advertise'))
                                if 'network-type' in config:
                                    network = "broadcast" if 'BROADCAST' in config['network-type'] else "point_to_point"
                                    ospf_config['network'] = network
                            if 'enable-bfd' in ospf_int:
                                bfd = ospf_int.get('enable-bfd')
                                cfg = bfd.get('config')
                                if cfg:
                                    bfd_cfg = {}
                                    self.update_dict(bfd_cfg, 'enable', cfg.get('enabled'))
                                    self.update_dict(bfd_cfg, 'bfd_profile', cfg.get('bfd-profile'))
                                    self.update_dict(ospf_config, 'bfd', bfd_cfg)
                if ospf_config:
                    ospf_config['name'] = intf_name
                    ospf_configs.append(ospf_config)

        return ospf_configs

    def update_dict(self, dict, key, value, parent_key=None):
        if value not in [None, {}, []]:
            if parent_key:
                dict.setdefault(parent_key, {})[key] = value
            else:
                dict[key] = value
