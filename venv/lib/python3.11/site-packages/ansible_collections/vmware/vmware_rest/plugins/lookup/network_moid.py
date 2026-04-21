# Copyright: (c) 2021, Alina Buzachis <@alinabuzachis>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
name: network_moid
short_description: Look up MoID for vSphere network objects using vCenter REST API
description:
  - Returns Managed Object Reference (MoID) of the vSphere network object contained in the specified path.
  - >-
    This lookup cannot distinguish between multiple networks with the same name defined in multiple switches
    as that is not supported by the vSphere REST API; network names must be unique within a given datacenter/folder path.
author:
  - Alina Buzachis (@alinabuzachis)
version_added: 2.1.0
requirements:
  - vSphere 7.0.3 or greater
  - python >= 3.6
  - aiohttp
notes:
  - This plugin requires the cloud.common collection, which will not be installed automatically as a dependency.
extends_documentation_fragment:
  - vmware.vmware_rest.moid
"""


EXAMPLES = r"""
#
#
# The examples below assume you have a datacenter named 'my_dc' and a network named 'my_network'.
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
      {{ lookup('vmware.vmware_rest.network_moid', '/my_dc/network/my_network',
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
        msg: "{{ lookup('vmware.vmware_rest.network_moid', '/my_dc/network/my_network', **connection_args) }}"

# Finally, you can also leverage the environment variables associated with each connection arg, and avoid passing
# extra args to the lookup plugins
- name: Use a lookup plugin with VMWARE_* environment variables set
  ansible.builtin.debug:
    msg: "{{ lookup('vmware.vmware_rest.network_moid', '/my_dc/network/my_network') }}"

#
# Network Search Path Examples
#
# Networks are located under the 'network' folder in a datacenter.
# The basic path for a datastore should look like '/<datacenter-name>/network/<network-name>'
- name: Lookup Network Named 'my_network' in Datacenter 'my_dc'
  ansible.builtin.debug:
    msg: "{{ lookup('vmware.vmware_rest.network_moid', '/my_dc/network/my_network') }}"

# If the network is in a user created 'network' type folder, the path shoud just include the
# datacenter and folder name.
- name: Lookup Network Named 'my_network' in Datacenter 'my_dc' in a Network folder 'production'
  ansible.builtin.debug:
    msg: "{{ lookup('vmware.vmware_rest.network_moid', '/my_dc/production/my_network') }}"


#
# Usage in Playbooks
#
#
# The lookup plugin can be used to simplify your playbook. Here is an example of how you might use it.
#
# Without the lookup, this takes two modules which both run on the remote host. This can slow down execution
# and adds extra steps to the playbook:
- name: Retrieve details about the network named 'my_network'
  vmware.vmware_rest.vcenter_network_info:
    names:
      - my_network
  register: my_network_info

- name: Create a VM
  vmware.vmware_rest.vcenter_vm:
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
    nics:
      - backing:
          type: STANDARD_PORTGROUP
          network: "{{ my_network_info.value[0].network }}"

# With the lookup, playbooks are shorter, quicker, and more intuitive:
- name: Create a VM
  vmware.vmware_rest.vcenter_vm:
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
    nics:
      - backing:
          type: STANDARD_PORTGROUP
          network: "{{ lookup('vmware.vmware_rest.network_moid', '/my_dc/network/my_network') }}"
"""


RETURN = r"""
_raw:
    description: MoID of the vSphere network object
    type: str
    sample: network-1017
"""


from ansible.errors import AnsiblePluginError

try:
    from ansible_collections.cloud.common.plugins.plugin_utils.turbo.lookup import (
        TurboLookupBase as LookupBase,
    )
except ImportError:
    raise AnsiblePluginError(
        message="This plugin requires the cloud.common collection."
    )

from ansible_collections.vmware.vmware_rest.plugins.plugin_utils.lookup import Lookup


class LookupModule(LookupBase):
    async def _run(self, terms, variables, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        self.set_option("object_type", "network")
        result = await Lookup.entry_point(terms, self._options)
        return [result]

    run = _run if not hasattr(LookupBase, "run_on_daemon") else LookupBase.run_on_daemon
