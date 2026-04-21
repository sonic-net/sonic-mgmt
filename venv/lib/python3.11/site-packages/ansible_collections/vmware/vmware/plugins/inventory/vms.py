# Copyright: (c) 2024, Ansible Cloud Team
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
name: vms
short_description: Create an inventory containing VMware VMs
author:
    - Ansible Cloud Team (@ansible-collections)
description:
    - Create a dynamic inventory of VMware VMs from a vCenter or ESXi environment.
    - Uses any file which ends with vms.yml, vms.yaml, vmware_vms.yml, or vmware_vms.yaml as a YAML configuration file.

extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options
    - vmware.vmware.plugin_base_options
    - ansible.builtin.inventory_cache
    - ansible.builtin.constructed

requirements:
    - vSphere Automation SDK (when gather_tags is True)

options:
    properties:
        default: [
            'name', 'config.cpuHotAddEnabled', 'config.cpuHotRemoveEnabled',
            'config.instanceUuid', 'config.hardware.numCPU', 'config.template',
            'config.name', 'config.uuid', 'guest.hostName', 'guest.ipAddress',
            'guest.guestId', 'guest.guestState', 'runtime.maxMemoryUsage',
            'customValue', 'summary.runtime.powerState', 'config.guestId'
        ]
    keyed_groups:
        default: [
            {key: 'config.guestId', separator: ''},
            {key: 'summary.runtime.powerState', separator: ''},
        ]
    gather_compute_objects:
        description:
            - If true, gather the cluster and ESXi host identifiers for this VM. This will add the cluster
              and esxi_host properties to the VM object.
            - If these properties are not available for some reason, the values will be empty strings.
            - If false, these properties will not be added to the VM object.
            - Looking up these values can add time to the inventory process.
        default: false
        type: bool
"""

EXAMPLES = r"""
# Below are examples of inventory configuration files that can be used with this plugin.
# To test these and see the resulting inventory, save the snippet in a file named hosts.vmware_vms.yml and run:
# ansible-inventory -i hosts.vmware_vms.yml --list


# Simple configuration with in-file authentication parameters
---
plugin: vmware.vmware.vms
hostname: 10.65.223.31
username: administrator@vsphere.local
password: Esxi@123$%
validate_certs: false
...

# More complex configuration. Authentication parameters are assumed to be set as environment variables.
---
plugin: vmware.vmware.vms
# Create groups based on host paths
group_by_paths: true
# Create a group with VMs that support CPU hot add using the cpuHotAddEnabled property,
# and groups based on VMware tools
properties: ["name", "config", "guest"]
groups:
  cpu_hot_add_enabled: config.cpuHotAddEnabled
keyed_groups:
  - key: guest.toolsStatus
    separator: ""
  - key: guest.toolsRunningStatus
    separator: ""
# Only gather VMs found in certain vSphere folder paths
search_paths:
  - /DC1/vm/production
  - /DC1/vm/hq/production
  - /DC3
# Filter out VMs using jinja patterns. For example, filter out powered off VMs
filter_expressions:
  - 'summary.runtime.powerState == "poweredOff"'

# Set custom inventory hostnames based on attributes
# If more than one host has the same name, only the first host is shown in the inventory and a warning is thrown.
# If strict is true, this warning is considered a fatal error.
hostnames:
  - "'VM - ' + name + ' - ' + guest.ipAddress"
  - "'VM - ' + name + ' - ' + config.instanceUuid"
# Use compose to set variables for the hosts that we find
compose:
  ansible_user: "'root'"
  ansible_connection: "'ssh'"
  # assuming path is something like /MyDC/vms/myfolder
  datacenter: "(path | split('/'))[1]"
...

# Use Tags and Tag Categories to create groups
# Given the example tags below:
#
#   tags:
#     urn:vmomi:InventoryServiceTag:70f87e82-6ac6-42bc-878c-817d7b2a4520:GLOBAL: db
#     urn:vmomi:InventoryServiceTag:bb10e90b-263f-4248-be06-086df1100d6b:GLOBAL: tofu-managed
#     urn:vmomi:InventoryServiceTag:70f87e82-6ac6-42bc-878c-111111111111:GLOBAL: web
#   tags_by_category:
#     app_type:
#       - urn:vmomi:InventoryServiceTag:70f87e82-6ac6-42bc-878c-817d7b2a4520:GLOBAL: db
#       - urn:vmomi:InventoryServiceTag:70f87e82-6ac6-42bc-878c-111111111111:GLOBAL: web
#     tofu:
#       - urn:vmomi:InventoryServiceTag:bb10e90b-263f-4248-be06-086df1100d6b:GLOBAL: tofu-managed
---
plugin: vmware.vmware.vms
gather_tags: true
keyed_groups:
  # create groups based on tag names/values, like db, web, and tofu-managed
  - key: tags.values()
    prefix: ""
    separator: ""

  # create groups based on app types, like db and web
  - key: tags_by_category.app_type | map('dict2items') | flatten | map(attribute='value')
    prefix: "vmware_tag_app_type_category_"
    separator: ""

  # create groups based on categories, like app_type or tofu
  - key: tags_by_category.keys()
    prefix: "vmware_tag_category_name_"
    separator: ""
...

# gather and group hosts by compute resource information.
---
plugin: vmware.vmware.vms

# creates properties for cluster and ESXi host identifiers on the VM object, like
# cluster: {name: "Cluster1", moid: "1234567890"}
# esxi_host: {name: "esxi-host-1", moid: "1234567890"}
gather_compute_objects: true

# create groups based on cluster and ESXi host name.
keyed_groups:
  - key: 'cluster["name"]'
    prefix: "cluster"
    separator: "_"
  - key: 'esxi_host["name"]'
    prefix: "esxi_host"
    separator: "_"

# filter out VMs that are not running in one or more of clusters.
filter_expressions:
  - 'cluster["name"] in ["Cluster1", "Cluster2"]'
...


# customizing hostnames based on VM's FQDN. The second hostnames template acts as a fallback mechanism.
---
plugin: vmware.vmware.vms
hostnames:
  - 'config.name+"."+guest.ipStack.0.dnsConfig.domainName'
  - 'config.name'
properties:
  - 'config.name'
  - 'config.guestId'
  - 'guest.hostName'
  - 'guest.ipAddress'
  - 'guest.guestFamily'
  - 'guest.ipStack'
...

# Select a specific IP address for use by ansible when multiple NICs are present on the VM
---
plugin: vmware.vmware.vms
compose:
  # Set the IP address used by ansible to one that starts by 10.42. or 10.43.
  ansible_host: >-
    guest.net
    | selectattr('ipAddress')
    | map(attribute='ipAddress')
    | flatten
    | select('match', '^10.42.*|^10.43.*')
    | list
    | first
properties:
  - guest.net
...

# Group hosts using Jinja2 conditionals
---
plugin: vmware.vmware.vms
properties:
  - 'config.datastoreUrl'
groups:
  slow_storage: "'Nas01' in config.datastoreUrl[0].name"
  fast_storage: "'SSD' in config.datastoreUrl[0].name"
...
"""

try:
    from pyVmomi import vim
except ImportError:
    # Already handled in base class
    pass

from ansible_collections.vmware.vmware.plugins.inventory_utils._base import (
    VmwareInventoryHost,
    VmwareInventoryBase
)


class VmInventoryHost(VmwareInventoryHost):
    def __init__(self):
        super().__init__()
        self._guest_ip = None
        self._cluster = None
        self._esxi_host = None

    @property
    def guest_ip(self):
        if self._guest_ip:
            return self._guest_ip

        try:
            self._guest_ip = self.properties['guest']['ipAddress']
        except KeyError:
            self._guest_ip = ""

        return self._guest_ip

    @property
    def cluster(self):
        if self._cluster is None:
            try:
                _cluster = self.object.summary.runtime.host.parent
                self._cluster = dict(
                    name=_cluster.name,
                    moid=_cluster._GetMoId()
                )
            except AttributeError:
                self._cluster = dict(name='', moid='')

        return self._cluster

    @property
    def esxi_host(self):
        if self._esxi_host is None:
            try:
                _esxi_host = self.object.summary.runtime.host
                self._esxi_host = dict(
                    name=_esxi_host.name,
                    moid=_esxi_host._GetMoId()
                )
            except AttributeError:
                self._esxi_host = dict(name='', moid='')

        return self._esxi_host

    def get_tags(self, rest_client):
        return rest_client.get_tags_by_vm_moid(self.object._GetMoId())


class InventoryModule(VmwareInventoryBase):

    NAME = "vmware.vmware.vms"

    def verify_file(self, path):
        """
        Checks the plugin configuration file format and name, and returns True
        if everything is valid.
        Args:
            path: Path to the configuration YAML file
        Returns:
            True if everything is correct, else False
        """
        if super(InventoryModule, self).verify_file(path):
            return path.endswith(
                (
                    "vms.yml",
                    "vms.yaml",
                    "vmware_vms.yaml",
                    "vmware_vms.yml"
                )
            )
        return False

    def parse_properties_param(self):
        """
        The properties option can be a variety of inputs from the user and we need to
        manipulate it into a list of properties that can be used later.
        Returns:
          A list of property names that should be returned in the inventory. An empty
          list means all properties should be collected
        """
        properties_param = self.get_option("properties")
        if not isinstance(properties_param, list):
            properties_param = [properties_param]

        if "all" in properties_param:
            return []

        if "name" not in properties_param:
            properties_param.append("name")

        # needed by keyed_groups default value
        if "config.guestId" not in properties_param:
            properties_param.append("config.guestId")

        # needed by keyed_groups default value
        if "summary.runtime.powerState" not in properties_param:
            properties_param.append("summary.runtime.powerState")

        # needed by esxi_host and cluster properties value
        if self.get_option("gather_compute_objects"):
            properties_param.append("summary.runtime.host")

        return properties_param

    def populate_from_cache(self, cache_data):
        """
        Populate inventory data from cache
        """
        hostvars = {}
        for inventory_hostname, vm_properties in cache_data.items():
            vm = VmInventoryHost.create_from_cache(
                inventory_hostname=inventory_hostname,
                properties=vm_properties
            )
            self.add_host_object_from_vcenter_to_inventory(vm, hostvars)

    def populate_from_vcenter(self):
        """
        Populate inventory data from vCenter
        """
        hostvars = {}
        properties_to_gather = self.parse_properties_param()
        self.initialize_pyvmomi_client()
        if self.get_option("gather_tags"):
            self.initialize_rest_client()

        for vm_object in self.get_objects_by_type(vim_type=[vim.VirtualMachine]):
            vm = VmInventoryHost.create_from_object(
                vmware_object=vm_object,
                properties_to_gather=properties_to_gather,
                pyvmomi_client=self.pyvmomi_client
            )

            if self.get_option("gather_tags"):
                self.add_tags_to_object_properties(vm)

            if self.get_option("gather_compute_objects"):
                vm.properties['cluster'] = vm.cluster
                vm.properties['esxi_host'] = vm.esxi_host

            self.set_inventory_hostname(vm)
            self.add_host_object_from_vcenter_to_inventory(new_host=vm, hostvars=hostvars)

        return hostvars

    def set_default_ansible_host_var(self, vmware_host_object):
        """
            Sets the default ansible_host var. This is usually an IP that is dependent on the object type.
            This is a default because the user can override this via compose
            Args:
              vmware_host_object: EsxiInventoryHost, The host object that should be used
        """
        self.inventory.set_variable(
            vmware_host_object.inventory_hostname, "ansible_host",
            vmware_host_object.guest_ip
        )
