# -*- coding: utf-8 -*-

# Copyright: (c) 2016, Charles Paul <cpaul@ansible.com>
# Copyright: (c) 2018, Ansible Project
# Copyright: (c) 2019, Abhijeet Kasurde <akasurde@redhat.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class ModuleDocFragment(object):
    # This document fragment serves as a partial base for all vmware plugins. It should be used in addition to the base fragment, vmware.vmware.base_options
    # since that contains the actual argument descriptions and defaults. This just defines the environment variables since plugins have something
    # like the module spec where that is usually done.
    DOCUMENTATION = r'''
options:
  hostname:
    env:
      - name: VMWARE_HOST
  username:
    env:
      - name: VMWARE_USER
  password:
    env:
      - name: VMWARE_PASSWORD
  validate_certs:
    env:
      - name: VMWARE_VALIDATE_CERTS
  port:
    env:
      - name: VMWARE_PORT
  proxy_host:
    env:
      - name: VMWARE_PROXY_HOST
  proxy_port:
    env:
      - name: VMWARE_PROXY_PORT
  gather_tags:
    description:
      - If true, gather any tags attached to the associated VMs
      - Requires 'vSphere Automation SDK' library to be installed on the Ansible controller machine.
    default: false
    type: bool
  hostnames:
    description:
      - A list of templates evaluated in order to compose inventory_hostname.
      - Each value in the list should be a jinja template. You can see the examples section for more details.
      - Templates that result in an empty string or None value are ignored and the next template is evaluated.
      - You can use hostvars such as properties specified in O(properties) as variables in the template.
    type: list
    elements: string
    default: ['name']
  properties:
    description:
      - Specify a list of VMware schema properties associated with the host to collect and return as hostvars.
      - Each value in the list can be a path to a specific property in a VMware object or a path to a collection of properties.
      - Please make sure that if you use a property in another parameter that it is included in this option.
      - Some properties are always returned, such as name, customValue, and summary.runtime.powerState
      - Use V(all) to return all properties available for the VMware object.
    type: list
    elements: string
    default: [
      'name', 'customValue', 'summary.runtime.powerState'
    ]
  flatten_nested_properties:
    description:
      - If true, flatten any nested properties into their dot notation names.
      - For example 'summary["runtime"]["powerState"]' would become "summary.runtime.powerState"
    type: bool
    default: false
  keyed_groups:
    description:
      - Use the values of the VMware object properties or other hostvars to create and populate groups.
    type: list
    default: []
  search_paths:
    description:
      - Specify a list of paths that should be searched recursively for VMware objects.
      - This effectively allows you to only include objects in certain datacenters, clusters, or folders. The path must
        be a valid vSphere inventory or folder path. Valid paths depend on the object type (vm, network, host, datastore).
      - >-
        Filtering is done before the initial object gathering query. If you have a large number of VMware objects, specifying
        a subset of paths to search can help speed up the inventory plugin.
      - The default value is an empty list, which means all paths (i.e. all datacenters) will be searched.
    type: list
    elements: str
    default: []
  group_by_paths:
    description:
      - If true, groups will be created based on the VMware object's paths.
      - >-
        Paths will be sanitized to match Ansible group name standards.
        For example, any slashes or dashes in the paths will be replaced by underscores in the group names.
      - A group is created for each step down in the path, with the group from the step above containing subsequent groups.
      - For example, a path /DC-01/vms/Cluster will create groups 'DC_01' which contains group 'DC_01_vms' which contains group 'DC_01_vms_Cluster'
    default: false
    type: bool
  group_by_paths_prefix:
    description:
      - If O(group_by_paths) is true, set this variable if you want to add a prefix to any groups created based on paths.
      - By default, no prefix is added to the group names.
    default: ''
    type: str
  sanitize_property_names:
    description:
      - If true, sanitize VMware object property names so they can safely be referenced within Ansible playbooks.
      - This option also transforms property names to snake case. For example, powerState would become power_state.
    type: bool
    default: false
  filter_expressions:
    description:
      - A list of jinja expressions to filter out hosts from the final inventory.
      - If any of the expressions evaluate to True, the host will not be included in the inventory.
      - This filtering is done after the host information has been collected from vSphere. It does not affect
        the speed of the inventory plugin. For faster collection time, refer to the O(search_paths) option.
    type: list
    elements: list
    default: []
    aliases: ['filters']
  rename_reserved_variables:
    description:
      - If true, the plugin will rename the reserved variables to avoid potential conflicts with ansible-core and resolve warnings.
        Variables will be prefixed with 'vmware_inventory_'.
      - Some variables have names that were maintained for backwards compatibility with older versions of the plugins, but are
        now reserved by ansible-core and cause warnings.
      - "Affected host variables include: name, and tags."
    default: false
    type: bool
'''
