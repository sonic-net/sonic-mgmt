from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
# Copyright (c) 2018-2019 Red Hat, Inc.
# Copyright (c) 2020 Infoblox, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
    name: nios_inventory
    author:
      - Will Tome (@willtome)
    short_description: Infoblox inventory plugin
    version_added: "1.0.0"
    description:
        - This plugin allows you to query the Infoblox Grid for host records and
          use the response data to populate the inventory file.
    options:
        host:
            description:
              - Specifies the DNS host name or address for connecting to the remote
                instance of NIOS WAPI over REST.
              - Value can also be specified using C(INFOBLOX_HOST) environment
                variable.
            type: string
            required: True
            env:
                - name: INFOBLOX_HOST
        username:
            description:
              - Configures the username to use to authenticate the connection to
                the remote instance of NIOS.
              - Value can also be specified using C(INFOBLOX_USERNAME) environment
                variable.
            type: string
            required: True
            env:
                - name: INFOBLOX_USERNAME
        password:
            description:
              - Specifies the password to use to authenticate the connection to
                the remote instance of NIOS.
              - Value can also be specified using C(INFOBLOX_PASSWORD) environment
                variable.
            type: string
            env:
                - name: INFOBLOX_PASSWORD
        extattrs:
            description:
              - Allows you to filter the returned host record based on the
                extensible attributes assigned to them.
            default: {}
            type: dict
        hostfilter:
            description:
              - Accepts a key/value pair and uses it to filter the
                host records to be returned.
            default: {}
            type: dict
    requirements:
        - python >= 3.4
        - infoblox-client
'''

EXAMPLES = r'''
plugin: infoblox.nios_modules.nios_inventory
host: blox.example.com
username: admin
'''


from ansible.plugins.inventory import BaseInventoryPlugin
from ..module_utils.api import WapiInventory
from ..module_utils.api import normalize_extattrs, flatten_extattrs
from ansible.module_utils.six import iteritems
from ansible.errors import AnsibleError


class InventoryModule(BaseInventoryPlugin):
    NAME = 'nios_inventory'

    def parse(self, inventory, loader, path, cache=True):  # Plugin interface (2)
        super(InventoryModule, self).parse(inventory, loader, path)
        self._read_config_data(path)

        provider = {'host': self.get_option('host'),
                    'username': self.get_option('username'),
                    'password': self.get_option('password')}

        wapi = WapiInventory(provider)

        host_filter = self.get_option('hostfilter')
        extattrs = normalize_extattrs(self.get_option('extattrs'))
        return_fields = ['name', 'view', 'extattrs', 'ipv4addrs']

        hosts = wapi.get_object('record:host', host_filter, extattrs=extattrs, return_fields=return_fields) or []

        if not hosts:
            raise AnsibleError("host record is not present")

        for host in hosts:
            group_name = self.inventory.add_group(host['view'])
            host_name = self.inventory.add_host(host['name'])
            self.inventory.add_child(group_name, host_name)

            self.inventory.set_variable(host_name, 'view', host['view'])
            self.inventory.set_variable(host_name, 'ipv4addrs', [item['ipv4addr'] for item in host['ipv4addrs']])

            for key, value in iteritems(flatten_extattrs(host['extattrs'])):
                self.inventory.set_variable(host_name, key, value)
