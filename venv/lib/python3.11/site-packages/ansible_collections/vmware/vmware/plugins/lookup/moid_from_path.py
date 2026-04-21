# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later
from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
name: moid_from_path
short_description: Look up MoID for vSphere objects based on the inventory path
description:
    - Returns Managed Object Reference (MoID) of the vSphere object contained in the specified path.
    - Multiple objects can be returned if the path ends in slash, indicating that the path is a
      container and its contents should be queried.
author:
    - Ansible Cloud Team (@ansible-collections)

options:
    _terms:
        description:
            - vSPhere inventory path to the object(s) to look up.
            - Inventory paths are unique for objects in vSphere. The format should be '/<datacenter>/<folder type>/....', where
              folder type is one of vm, host, network, or datastore.
            - If the path ends in a slash, the path is treated as a container and objects inside of the container are returned.
            - If the path ends in a slash, the return value will be a string of comma separated MoIDs. You can return a list
              with `wantlist=true`
        required: True

    type:
        description:
            - Limits the types of objects to include in the search results. If this not supplied and the inventory
              path is a container, all types of objects in the container will be included.
            - This is only used when the search path ends in a slash (/).
        choices: [all, cluster, datacenter, datastore, folder, host, network, resource_pool, vm]
        type: str
        required: false
        default: all

extends_documentation_fragment:
    - vmware.vmware.lookup_base_options
    - vmware.vmware.base_options
"""


EXAMPLES = r"""
#
#
# The examples below assume you have a datacenter named 'my_dc' and a cluster named 'my_cluster'.
# Replace these values as needed for your environment.
#
#

#
# Authentication / Connection Arguments
#
# You can explicitly set the connection arguments in each lookup. This may be clearer for some use cases
- name: Pass In Connection Arguments Explicitly
  ansible.builtin.debug:
    msg: >-
      {{ lookup('vmware.vmware.moid_from_path', '/my_dc/host/my_cluster',
      vcenter_hostname="vcenter.test",
      vcenter_username="administrator@vsphere.local",
      vcenter_password="1234") }}

# Alternatively, you can add the connection arguments to a dictionary variable, and then pass that variable to the
# lookup plugins. This makes the individual lookup plugin calls simpler
- name: Example Playbook
  hosts: all
  vars:
    connection_args:
      vcenter_hostname: "vcenter.test"
      vcenter_username: "administrator@vsphere.local"
      vcenter_password: "1234"
  tasks:
    # Add more tasks or lookups as needed, referencing the same connection_args variable
    - name: Lookup MoID of the object
      ansible.builtin.debug:
        msg: "{{ lookup('vmware.vmware.moid_from_path', '/my_dc/host/my_cluster', **connection_args) }}"

# Finally, you can also leverage the environment variables associated with each connection arg, and avoid passing
# extra args to the lookup plugins. The environment variables must be exposed on the Ansible controller. You cannot
# set them in the playbook
- name: Use a lookup plugin with VMWARE_* environment variables set
  ansible.builtin.debug:
    msg: "{{ lookup('vmware.vmware.moid_from_path', '/my_dc/host/my_cluster') }}"

#
# Search Path Examples
#
# There are four key folder types, which contain a subset of vSphere types
#    host - ESXi, clusters, resource pools, folders
#    network - network, folders
#    datastore - datastores, folders
#    vm - VMs, folders
# Folder paths should be /<datacenter name>/<folder type>/.....
- name: Lookup Datacenter 'my_dc'
  ansible.builtin.debug:
    msg: "{{ lookup('vmware.vmware.moid_from_path', '/my_dc') }}"

- name: Lookup All Datacenters
  ansible.builtin.debug:
    msg: "{{ lookup('vmware.vmware.moid_from_path', '/') }}"

- name: Lookup Cluster Named 'my_cluster' in Datacenter 'my_dc'
  ansible.builtin.debug:
    msg: "{{ lookup('vmware.vmware.moid_from_path', '/my_dc/host/my_cluster') }}"

- name: Lookup All Clusters In Datacenter 'my_dc'
  ansible.builtin.debug:
    msg: "{{ lookup('vmware.vmware.moid_from_path', '/my_dc/host/', type='cluster') }}"

- name: Lookup VM Named 'my_vm' in Datacenter 'my_dc', folder 'production'
  ansible.builtin.debug:
    msg: "{{ lookup('vmware.vmware.moid_from_path', '/my_dc/vm/production/my_vm') }}"

- name: Lookup All VMs in Datacenter 'my_dc', folder 'production'
  ansible.builtin.debug:
    msg: "{{ lookup('vmware.vmware.moid_from_path', '/my_dc/vm/production/', type='vm') }}"

- name: Lookup Datastore Named 'my_ds' in Datacenter 'my_dc'
  ansible.builtin.debug:
    msg: "{{ lookup('vmware.vmware.moid_from_path', '/my_dc/datastore/my_ds') }}"

- name: Lookup Network Named 'my_net' in Datacenter 'my_dc'
  ansible.builtin.debug:
    msg: "{{ lookup('vmware.vmware.moid_from_path', '/my_dc/network/my_net') }}"

- name: Lookup All Resource Pools in Datacenter 'my_dc', cluster 'my_cluser' (this is not recursive!)
  ansible.builtin.debug:
    msg: "{{ lookup('vmware.vmware.moid_from_path', '/my_dc/host/my_cluster/', type='resource_pool', wantlist=true) }}"

- name: Lookup All ESXi Hosts in Datacenter 'my_dc', cluster 'my_cluser' (this is not recursive!)
  ansible.builtin.debug:
    msg: "{{ lookup('vmware.vmware.moid_from_path', '/my_dc/host/my_cluster/', type='host', wantlist=true) }}"

#
# Usage in Playbooks
#
#
# The lookup plugin can be used to simplify your playbook. Here is an example of how you might use it.
#
# Without the lookup, this takes two modules which both run on the remote host. This can slow down execution
# and adds extra steps to the playbook:
- name: Retrieve details about a cluster named 'my_cluster'
  vmware.vmware_rest.vcenter_cluster_info:
    names:
      - my_cluster
  register: my_cluster_info

- name: Create a VM
  vmware.vmware_rest.vcenter_vm:
    placement:
      cluster: "{{ my_cluster_info.value[0].cluster }}"
    name: test_vm1
    guest_OS: RHEL_7_64
    hardware_version: VMX_11
    memory:
      size_MiB: 1024
    disks:
      - type: SATA
        new_vmdk:
          name: first_disk
          capacity: 3200

# With the lookup, playbooks are shorter, quicker, and more intuitive:
- name: Create a VM
  vmware.vmware_rest.vcenter_vm:
    placement:
      cluster: "{{ lookup('vmware.vmware.moid_from_path', '/my_dc/host/my_cluster') }}"
    name: test_vm1
    guest_OS: RHEL_7_64
    hardware_version: VMX_11
    memory:
      size_MiB: 1024
    disks:
      - type: SATA
        new_vmdk:
          name: first_disk
          capacity: 3200
"""

RETURN = r"""
_raw:
    description: MoID of the vSphere cluster object
    type: str
    sample: domain-c1007
"""

from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display
from ansible.errors import AnsibleError, AnsibleParserError
from ansible.module_utils.common.text.converters import to_native
from ansible_collections.vmware.vmware.plugins.module_utils.clients.pyvmomi import PyvmomiClient
import ansible_collections.vmware.vmware.plugins.module_utils._folder_paths as vsphere_folder_paths
try:
    from pyVmomi import vim
except ImportError:
    pass


display = Display()


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):

        # First of all populate options,
        # this will already take into account env vars and ini config
        self.set_options(var_options=variables, direct=kwargs)
        self.initialize_pyvmomi_client()

        ret = set()
        for object_path in terms:
            self._validate_path(object_path)
            self._get_moids_from_path(object_path=object_path, moids=ret)

        return list(ret)

    @property
    def supported_types(self):
        return {
            "cluster": [vim.ClusterComputeResource],
            "datacenter": [vim.Datacenter],
            "datastore": [vim.Datastore],
            "folder": [vim.Folder],
            "host": [vim.HostSystem],
            "network": [vim.Network],
            "resource_pool": [vim.ResourcePool],
            "vm": [vim.VirtualMachine],
            "all": []  # an empty list will cause vsphere to include all object types
        }

    @property
    def lookup_type(self):
        try:
            return self.supported_types[self.get_option('type')]
        except KeyError:
            raise AnsibleError(
                "Unsupported vSphere type, %s. Must be one of %s" %
                (self.get_option('type'), self.supported_types.keys())
            )

    def _validate_path(self, object_path):
        """
        Validates the path format, making sure that the user provided a fully formed path with a supported
        folder type.
        """
        if not object_path:
            raise AnsibleParserError("Either an empty object path, or no path, was provided.")

        _object_path = object_path.strip('/')
        split_path = _object_path.split('/')
        # if path is one level deep (or less), we will only ever find datacenters or folders.
        if len(split_path) <= 1 and self.get_option('type') not in ('all', 'datacenter', 'folder'):
            raise AnsibleParserError(
                "Path is too short to find any objects of type %s. Paths should be '/<datacenter>/<type>/...'"
                % (self.get_option('type'))
            )

        # if path is more than one level deep, the seconds level of the path needs to be
        # one of the known folder types
        if len(split_path) > 1 and split_path[1] not in vsphere_folder_paths.FOLDER_TYPES:
            raise AnsibleParserError(
                "Path %s is not on one of the four folder types, %s. Paths should be '/<datacenter>/<type>/...'"
                % (object_path, list(vsphere_folder_paths.FOLDER_TYPES))
            )

    def _get_moids_from_path(self, object_path, moids):
        """
        Get one or more object moids from the path. Add the moids to the moids parameter
        Params:
            object_path: str, The vsphere inventory path that should be used
            moids: set, The set of moids that the results should be added to
        """
        found_obj = self.pyvmomi_client.si.content.searchIndex.FindByInventoryPath(object_path)
        if found_obj is None:
            if self.get_option('fail_on_missing'):
                raise AnsibleError("Unable to find object at path %s" % object_path)
            else:
                return

        if object_path.endswith('/'):
            container = self.pyvmomi_client.si.content.viewManager.CreateContainerView(
                container=found_obj,
                type=self.lookup_type,
                recursive=False
            )
            for child_obj in container.view:
                moids.add(child_obj._GetMoId())
        else:
            moids.add(found_obj._GetMoId())

    def initialize_pyvmomi_client(self):
        """
        Create an instance of the pyvmomi client based on the user's input (auth) parameters
        """
        try:
            self.pyvmomi_client = PyvmomiClient(
                hostname=self.get_option("hostname"),
                username=self.get_option("username"),
                password=self.get_option("password"),
                port=self.get_option("port"),
                validate_certs=self.get_option("validate_certs"),
                proxy_host=self.get_option("proxy_host"),
                proxy_port=self.get_option("proxy_port")
            )
        except Exception as e:
            raise AnsibleParserError(message=to_native(e))
