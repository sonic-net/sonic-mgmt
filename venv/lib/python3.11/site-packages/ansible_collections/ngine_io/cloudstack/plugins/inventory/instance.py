# -*- coding: utf-8 -*-
#
# Copyright (c) 2020, Rafael del valle <rafael@privaz.io>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r'''
    name: instance
    short_description: Apache CloudStack instance inventory source
    author: Rafael del Valle (@rvalle)
    version_added: 2.1.0
    description:
        - Get inventory hosts from Apache CloudStack
        - Allows filtering and grouping inventory hosts.
        - |
            Uses an YAML configuration file ending with either I(cloudstack-instances.yml) or I(cloudstack-instances.yaml)
            to set parameter values (also see examples).
    options:
        plugin:
            description: Token that ensures this is a source file for the 'instance' plugin.
            type: string
            required: True
            choices: [ ngine_io.cloudstack.instance ]
        hostname:
            description: |
                Field to match the hostname. Note v4_main_ip corresponds to the primary ipv4address of the first nic
                adapter of the instance.
            type: string
            default: v4_default_ip
            choices:
                - v4_default_ip
                - hostname
        filter_by_zone:
            description: Only return instances in the provided zone.
            type: string
        filter_by_domain:
            description: Only return instances in the provided domain.
            type: string
        filter_by_project:
            description: Only return instances in the provided project.
            type: string
        filter_by_vpc:
            description: Only return instances in the provided VPC.
            type: string
    extends_documentation_fragment:
        - constructed
        - ngine_io.cloudstack.cloudstack
        - ngine_io.cloudstack.cloudstack_environment
'''

# TODO: plugin should work as 'cloudstack' only
EXAMPLES = '''
# inventory_cloudstack.yml file in YAML format
# Example command line: ansible-inventory --list -i cloudstack-instances.yml
plugin: ngine_io.cloudstack.instance

# Use the default ip as ansible_host
hostname: v4_default_ip

# Return only instances related to the VPC vpc1 and in the zone EU
filter_by_vpc: vpc1
filter_by_zone: EU

# Group instances with a disk_offering as storage
# Create a group dmz for instances connected to the dmz network
groups:
  storage: disk_offering is defined
  dmz: "'dmz' in networks"

# Group the instances by network, with net_network1 as name of the groups
# Group the instanes by custom tag sla, groups like sla_value for tag sla
keyed_groups:
  - prefix: net
    key: networks
  - prefix: sla
    key: tags.sla


'''

# The J2 Template takes 'instance' object as returned from ACS and returns 'instance' object as returned by
# This inventory plugin.
# The data structure of this inventory has been designed according to the following criteria:
# - do not duplicate/compete with Ansible instance facts
# - do not duplicate/compete with Cloudstack facts modules
# - hide internal ACS structures and identifiers
# - if possible use similar naming to previous inventory script
# - prefer non-existing attributes over null values
# - populate the data required to group and filter instances
INVENTORY_NORMALIZATION_J2 = '''
---
instance:

  name: {{ instance.name }}
  hostname: {{ instance.hostname or instance.name | lower }}
  v4_default_ip: {{ instance.nic[0].ipaddress }}

  zone: {{ instance.zonename }}
  domain: {{ instance.domain | lower }}
  account: {{ instance.account }}
  username: {{ instance.username }}
  {% if instance.group %}
  group: {{ instance.group }}
  {% endif %}

  {% if instance.tags %}
  tags:
  {% for tag in instance.tags %}
    {{ tag.key }}: {{ tag.value }}
  {% endfor %}
  {% endif %}

  template: {{ instance.templatename }}
  service_offering: {{ instance.serviceofferingname }}
  {% if instance.diskofferingname is defined %}
  disk_offering: {{ instance.diskofferingname }}
  {% endif %}
  {% if instance.affinitygroup %}
  affinity_groups:
    {% for ag in instance.affinitygroup %}
    - {{ ag.name }}
    {% endfor %}
  {% endif %}
  networks:
    {% for nic in instance.nic %}
    - {{ nic.networkname }}
    {% endfor %}

  ha_enabled: {{ instance.haenable }}
  password_enabled: {{ instance.passwordenabled }}

  hypervisor: {{ instance.hypervisor | lower }}
  cpu_speed: {{ instance.cpuspeed }}
  cpu_number: {{ instance.cpunumber }}
  memory: {{ instance.memory }}
  dynamically_scalable: {{ instance.isdynamicallyscalable }}

  state: {{ instance.state }}
  cpu_usage: {{ instance.cpuused }}
  created: {{ instance.created }}
'''

import yaml
from ansible.module_utils.basic import missing_required_lib
from ansible.plugins.inventory import (AnsibleError, BaseInventoryPlugin,
                                       Constructable)
from jinja2 import Template

from ..module_utils.cloudstack import HAS_LIB_CS

try:
    from cs import CloudStack
except ImportError:
    pass


class InventoryModule(BaseInventoryPlugin, Constructable):

    NAME = 'ngine_io.cloudstack.instance'

    def __init__(self):
        super().__init__()
        if not HAS_LIB_CS:
            raise AnsibleError(missing_required_lib('cs'))
        self._cs = None
        self._normalization_template = Template(INVENTORY_NORMALIZATION_J2)

    def init_cs(self):

        # The configuration logic matches modules specification
        api_config = {
            'endpoint': self.get_option('api_url'),
            'key': self.get_option('api_key'),
            'secret': self.get_option('api_secret'),
            'timeout': self.get_option('api_timeout'),
            'method': self.get_option('api_http_method'),
            'verify': self.get_option('api_verify_ssl_cert')
        }

        self._cs = CloudStack(**api_config)

    @property
    def cs(self):
        return self._cs

    def query_api(self, command, **args):
        res = getattr(self.cs, command)(**args)

        if 'errortext' in res:
            raise AnsibleError(res['errortext'])

        return res

    def verify_file(self, path):
        """return true/false if this is possibly a valid file for this plugin to consume"""
        valid = False
        if super(InventoryModule, self).verify_file(path):
            # base class verifies that file exists and is readable by current user
            if path.endswith(('cloudstack-instances.yaml', 'cloudstack-instances.yml')):
                valid = True
        return valid

    def add_filter(self, args, filter_option, query, arg):
        # is there a value to filter by? we will search with it
        search = self.get_option('filter_by_' + filter_option)
        if search:
            found = False
            # we return all items related to the query involved in the filtering
            result = self.query_api(query, listItems=True)
            for item in result[filter_option]:
                # if we find the searched value as either an id or a name
                if search in [item['id'], item['name']]:
                    # we add the corresponding filter as query argument
                    args[arg] = item['id']
                    found = True
            if not found:
                raise AnsibleError(
                    "Could not apply filter_by_{fo}. No {fo} with id or name {s} found".format(
                        fo=filter_option, s=search
                    )
                )

        return args

    def get_filters(self):
        # Filtering as supported by ACS goes here
        args = {
            'fetch_list': True
        }

        self.add_filter(args, 'domain', 'listDomains', 'domainid')
        self.add_filter(args, 'project', 'listProjects', 'projectid')
        self.add_filter(args, 'zone', 'listZones', 'zoneid')
        self.add_filter(args, 'vpc', 'listVPCs', 'vpcid')

        return args

    def normalize_instance_data(self, instance):
        inventory_instance_str = self._normalization_template.render(instance=instance)
        inventory_instance = yaml.load(inventory_instance_str, Loader=yaml.FullLoader)
        return inventory_instance['instance']

    def parse(self, inventory, loader, path, cache=False):

        # call base method to ensure properties are available for use with other helper methods
        super(InventoryModule, self).parse(inventory, loader, path, cache)

        # This is the inventory Config
        self._read_config_data(path)

        # We Initialize the query_api
        self.init_cs()

        # All Hosts from
        self.inventory.add_group('cloudstack')

        # The ansible_host preference
        hostname_preference = self.get_option('hostname')

        # Retrieve the filtered list of instances
        instances = self.query_api('listVirtualMachines', **self.get_filters())

        for instance in instances:

            # we normalize the instance data using the embedded J2 template
            instance = self.normalize_instance_data(instance)

            inventory_name = instance['name']
            self.inventory.add_host(inventory_name, group='cloudstack')

            for attribute, value in instance.items():
                # Add all available attributes
                self.inventory.set_variable(inventory_name, attribute, value)

            # set hostname preference
            self.inventory.set_variable(inventory_name, 'ansible_host', instance[hostname_preference])

            # Use constructed if applicable
            strict = self.get_option('strict')

            # Composed variables
            self._set_composite_vars(self.get_option('compose'), instance, inventory_name, strict=strict)

            # Complex groups based on jinja2 conditionals, hosts that meet the conditional are added to group
            self._add_host_to_composed_groups(self.get_option('groups'), instance, inventory_name, strict=strict)

            # Create groups based on variable values and add the corresponding hosts to it
            self._add_host_to_keyed_groups(self.get_option('keyed_groups'), instance, inventory_name, strict=strict)
