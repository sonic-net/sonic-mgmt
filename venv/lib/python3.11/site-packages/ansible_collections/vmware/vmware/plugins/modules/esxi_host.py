#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: esxi_host
short_description: Manage VMware ESXi host status in vCenter
description:
    - Manage VMware ESXi host status in vCenter, including cluster or folder membership.
    - The host must be in maintenance mode to remove it or update its placement.
    - This module does not manage the connection status of hosts in vCenter. That functionality
      is in vmware.vmware.esxi_connection
    - The host must be in maintenance mode if it is already registered with vCenter but should
      be moved to a new cluster or folder.

author:
    - Ansible Cloud Team (@ansible-collections)

seealso:
    - module: vmware.vmware.esxi_connection

options:
    cluster:
        description:
            - The name of the cluster to be managed.
            - One of O(cluster) or O(folder) is required when O(state) is V(present).
            - Since ESXi names are unique in a datacenter, this option is not used when O(state) is V(absent).
        type: str
        required: false
        aliases: [cluster_name]
    datacenter:
        description:
            - The name of the datacenter.
        type: str
        required: true
        aliases: [datacenter_name]
    folder:
        description:
            - Name of the folder under which host to add.
            - One of O(cluster) or O(folder) is required when O(state) is V(present)
            - Since ESXi names are unique in a datacenter, this option is not used when O(state) is V(absent).
        type: str
    folder_paths_are_absolute:
        description:
            - If true, any folder path parameters are treated as absolute paths.
            - If false, modules will try to intelligently determine if the path is absolute
              or relative.
            - This option is useful when your environment has a complex folder structure. By default,
              modules will try to intelligently determine if the path is absolute or relative.
              They may mistakenly prepend the datacenter name or other folder names, and this option
              can be used to avoid this.
        type: bool
        required: false
        default: false
    esxi_host_name:
        description:
            - ESXi hostname to manage.
        required: true
        type: str
    esxi_username:
        description:
            - The username to use when authenticating to the ESXi host.
            - Required when O(state) is V(present).
        type: str
    esxi_password:
        description:
            - The password to use when authenticating to the ESXi host.
            - Required when O(state) is V(present).
        type: str
    esxi_port:
        description:
            - The port on which the ESXi host's SSL certificate can be seen.
            - This is used when fetching the SSL thumbprint, and is not used if
              O(ssl_thumbprint) is provided.
        type: int
        default: 443
    state:
        description:
            - If set to V(present), make sure the host is registered in vCenter in the desired folder or cluster.
            - If set to V(absent), remove the host from vCenter if it exists.
            - If set to V(absent), the host must either be disconnected or be in maintenance mode before it can be
              removed.
        default: present
        choices: ['present', 'absent']
        type: str
    ssl_thumbprint:
        description:
            - Specify the host system's SSL certificate thumbprint.
            - You can run the following command on the host to get the thumbprint -
              'openssl x509 -in /etc/vmware/ssl/rui.crt -fingerprint -sha1 -noout'
            - If this is not set, the module will attempt to fetch the thumbprint from the host itself.
              This essentially skips the host certificate verification, since whatever host is presented will be trusted.
            - This option is only used when state is present.
            - If O(proxy_host) is set, the proxy is used when fetching the SSL thumbprint.
        type: str
    force_add:
        description:
            - Forces the ESXi host to be added to the vCenter server, even if it is already being managed by another server.
            - The host must be in maintenance mode even if this option is enabled.
        type: bool
        default: False

extends_documentation_fragment:
    - vmware.vmware.base_options
'''

EXAMPLES = r'''
- name: Make Sure Host Is In A Cluster
  vmware.vmware.esxi_host:
    datacenter: DC01
    cluster: MyCluster
    esxi_host_name: 1.1.1.1
    esxi_username: root
    esxi_password: mypassword!
    state: present


- name: Make Sure Host Is In A Folder (Standalone Host)
  vmware.vmware.esxi_host:
    datacenter: DC01
    folder: my/host/folder   # or DC01/host/my/host/folder
    esxi_host_name: 1.1.1.1
    esxi_username: root
    esxi_password: mypassword!
    state: present


- name: Remove Host From Cluster
  vmware.vmware.esxi_host:
    datacenter: DC01
    esxi_host_name: 1.1.1.1
    state: absent
'''

RETURN = r'''
host:
    description:
        - Identifying information about the host
        - If the state is absent and the host does not exist, only the name is returned
    returned: On success
    type: dict
    sample: {
        "host": {
            "moid": "host-111111",
            "name": "10.10.10.10"
        },
    }
result:
    description:
        - Information about the vCenter task, if something changed
    returned: On change
    type: dict
    sample: {
        "result": {
            "completion_time": "2024-07-29T15:27:37.041577+00:00",
            "entity_name": "test-5fb1_my_esxi_host",
            "error": null,
            "state": "success"
        }
    }
'''

import ssl
import socket
import hashlib

try:
    from pyVmomi import vim, vmodl
except ImportError:
    pass

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_native

from ansible_collections.vmware.vmware.plugins.module_utils._module_pyvmomi_base import (
    ModulePyvmomiBase
)
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import (
    base_argument_spec
)
from ansible_collections.vmware.vmware.plugins.module_utils._vsphere_tasks import (
    TaskError,
    RunningTaskMonitor
)
from ansible_collections.vmware.vmware.plugins.module_utils._folder_paths import (
    format_folder_path_as_host_fq_path
)


class VmwareHost(ModulePyvmomiBase):
    def __init__(self, module):
        super().__init__(module)
        self.datacenter = self.get_datacenter_by_name_or_moid(self.params.get('datacenter'), fail_on_missing=True)
        self.cluster = None
        self.folder = None
        if self.params['cluster']:
            self.cluster = self.get_cluster_by_name_or_moid(self.params.get('cluster'), fail_on_missing=True, datacenter=self.datacenter)
        elif self.params['folder']:
            if (
                self.params.get('folder_paths_are_absolute') or
                self.params['folder'].startswith(self.params['datacenter']) or
                self.params['folder'].startswith('/' + self.params['datacenter'])
            ):
                path = self.params['folder']
            else:
                path = format_folder_path_as_host_fq_path(self.params['folder'], self.params['datacenter'])
            self.folder = self.get_folder_by_absolute_path(folder_path=path, fail_on_missing=True)

        self.host = self.get_esxi_host_by_name_or_moid(identifier=self.params['esxi_host_name'])

    def __host_parent_type_is_folder(self):
        """
            Checks if the host is in a cluster or folder. Returns true if its in a folder.
            Technically, the parent of a host in a folder is a ComputeResource. Clusters are
            also a type of ComputeResource, so we need to check for the cluster type specifically.
        """
        if isinstance(self.host.parent, vim.ClusterComputeResource):
            # the parent is a cluster
            return False
        else:
            return True

    def __run_and_wait_for_task(self, task, error_msg):
        """
            Helper method to run and wait for an arbitrary vCenter task
        """
        try:
            _, task_result = RunningTaskMonitor(task).wait_for_completion()   # pylint: disable=disallowed-name
        except (vmodl.RuntimeFault)as vmodl_fault:
            self.module.fail_json(msg=to_native(vmodl_fault.msg))
        except TaskError as task_e:
            self.module.fail_json(msg="ESXi task failed to complete due to: %s" % to_native(task_e))
        except Exception as generic_exc:
            self.module.fail_json(msg="%s due to exception %s" % (error_msg, to_native(generic_exc)))

        return task_result

    def create_host_connect_spec(self):
        """
            Function to create a host connection spec based on user params
            Returns:
                host connection specification
        """
        # Get the thumbprint of the SSL certificate
        ssl_thumbprint = self.params['ssl_thumbprint']
        if not ssl_thumbprint:
            ssl_thumbprint = self.get_host_ssl_thumbprint()

        host_connect_spec = vim.host.ConnectSpec()
        host_connect_spec.sslThumbprint = ssl_thumbprint
        host_connect_spec.hostName = self.params['esxi_host_name']
        host_connect_spec.userName = self.params['esxi_username']
        host_connect_spec.password = self.params['esxi_password']
        host_connect_spec.force = self.params['force_add']
        return host_connect_spec

    def validate_host_state(func):   # pylint: disable=no-self-argument
        """
            Decorator function to perform a state check on a host before moving or removing it. Both of
            these changes require that the host is in maintenance mode, or in some state other than connected.
        """
        def wrapper(self):
            try:
                if not self.host.runtime.inMaintenanceMode and self.host.runtime.connectionState == 'connected':
                    self.module.fail_json(msg='Host is not in valid state to be moved or removed. It must either be in maintenance mode or disconnected.')
            except AttributeError:
                pass
            func(self)
        return wrapper

    def add_host(self):
        host_connect_spec = self.create_host_connect_spec()
        _kwargs = {'spec': host_connect_spec, 'license': None}
        if self.folder:
            task = self.folder.AddStandaloneHost(**_kwargs, addConnected=True, compResSpec=None)
        else:
            task = self.cluster.AddHost_Task(**_kwargs, asConnected=True, resourcePool=None)

        task_result = self.__run_and_wait_for_task(
            task=task,
            error_msg="Failed to add host %s" % self.params['esxi_host_name']
        )
        self.host = task_result['result']
        del task_result['result']

        return task_result

    @validate_host_state
    def remove_host(self):
        if self.__host_parent_type_is_folder():
            task = self.host.parent.Destroy_Task()
        else:
            task = self.host.Destroy_Task()
        return self.__run_and_wait_for_task(
            task=task,
            error_msg="Failed to remove host %s" % self.params['esxi_host_name']
        )

    @validate_host_state
    def move_host(self):
        """
            Move the host to a new folder or cluster
        """
        if self.folder:
            if self.__host_parent_type_is_folder():
                task = self.folder.MoveIntoFolder_Task([self.host.parent])
            else:
                task = self.folder.MoveIntoFolder_Task([self.host])
        else:
            task = self.cluster.MoveHostInto_Task(host=self.host, resourcePool=None)

        return self.__run_and_wait_for_task(
            task=task,
            error_msg="Failed to move host %s" % self.params['esxi_host_name']
        )

    def host_needs_to_be_moved(self):
        """
            Returns true if the host is in the wrong cluster or folder, when compared to the inputs
            the user provided.
            Note that a standalone host (one in a folder) has a ComputeResource as a parent, and the
            parent of that is the folder.
            Returns:
                True if host needs to be moved
        """
        if self.cluster:
            if self.host.parent._GetMoId() == self.cluster._GetMoId():
                return False

        if self.folder:
            if self.host.parent.parent._GetMoId() == self.folder._GetMoId():
                return False

        return True

    def get_host_ssl_thumbprint(self):
        """
            Connect to the UI provided by the host and parse the SSL thumbprint
            from it
            Returns:
                str, the thumbprint presented by the host
        """
        host_fqdn = self.params['esxi_host_name']
        host_port = self.params['esxi_port']
        if self.params['proxy_host']:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((self.params['proxy_host'], self.params['proxy_port']))
            command = "CONNECT %s:%d HTTP/1.0\r\n\r\n" % (host_fqdn, host_port)
            sock.send(command.encode())
            buf = sock.recv(8192).decode()
            if buf.split()[1] != '200':
                self.module.fail_json(msg="Failed to connect to the proxy")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            der_cert_bin = ctx.wrap_socket(sock, server_hostname=host_fqdn).getpeercert(True)
            sock.close()
        else:
            try:
                pem = ssl.get_server_certificate((host_fqdn, host_port))
            except Exception:
                self.module.fail_json(msg=f"Cannot connect to host to fetch thumbprint: {host_fqdn}")
            der_cert_bin = ssl.PEM_cert_to_DER_cert(pem)

        if der_cert_bin:
            string = str(hashlib.sha1(der_cert_bin).hexdigest())
            return ':'.join(a + b for a, b in zip(string[::2], string[1::2]))
        else:
            self.module.fail_json(msg=f"Unable to fetch SSL thumbprint for host: {host_fqdn}")


def main():
    module = AnsibleModule(
        argument_spec={
            **base_argument_spec(), **dict(
                cluster=dict(type='str', required=False, aliases=['cluster_name']),
                datacenter=dict(type='str', required=True, aliases=['datacenter_name']),
                folder=dict(type='str', required=False),
                folder_paths_are_absolute=dict(type='bool', required=False, default=False),
                state=dict(type='str', default='present', choices=['absent', 'present']),

                esxi_host_name=dict(type='str', required=True),
                esxi_username=dict(type='str', required=False),
                esxi_password=dict(type='str', required=False, no_log=True),
                esxi_port=dict(type='int', default=443),
                ssl_thumbprint=dict(type='str', required=False),
                force_add=dict(type='bool', default=False),
            )
        },
        supports_check_mode=True,
        required_if=[
            ('state', 'present', ('cluster', 'folder'), True),
            ('state', 'present', ('esxi_username', 'esxi_password'), True),
        ],
        mutually_exclusive=[
            ('cluster', 'folder')
        ]
    )

    result = dict(changed=False, host=dict(name=module.params['esxi_host_name']))

    vmware_host = VmwareHost(module)

    if module.params['state'] == 'present':
        if not vmware_host.host:
            result['changed'] = True
            result['result'] = vmware_host.add_host()
        elif vmware_host.host_needs_to_be_moved():
            result['changed'] = True
            result['result'] = vmware_host.move_host()
        result['host']['moid'] = vmware_host.host._GetMoId()

    elif module.params['state'] == 'absent':
        if vmware_host.host:
            result['changed'] = True
            result['host']['moid'] = vmware_host.host._GetMoId()
            result['result'] = vmware_host.remove_host()

    module.exit_json(**result)


if __name__ == '__main__':
    main()
