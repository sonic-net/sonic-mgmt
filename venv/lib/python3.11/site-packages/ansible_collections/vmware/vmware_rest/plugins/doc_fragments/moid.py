# Copyright: (c) 2021, Alina Buzachis <@alinabuzachis>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    # Parameters for the Lookup Managed Object Reference (MoID) plugins
    DOCUMENTATION = r"""
    notes:
        - >-
            Lookup plugins are run on the ansible controller and are used to lookup information from an external
            resource. See https://docs.ansible.com/ansible/latest/plugins/lookup.html#lookup-plugins
        - >-
            This collection's plugins allow you to quickly gather VMWare resource identifiers and either store or
            use them, instead of requiring multiple modules and tasks to do the same thing.
            See the examples section for a comparison.

    deprecated:
        removed_in: 5.0.0
        why: >-
          This plugin will not work with ansible-core 2.19 and above. Refer to
          L(the migration documentation,https://github.com/ansible-collections/vmware.vmware/tree/main/docs/lookup_plugin_migration.md)
          for migration examples.
        alternative: Use M(vmware.vmware.moid_from_path) instead.

    options:
        _terms:
            description:
                - The absolute folder path to the object you would like to lookup.
                - Folder paths always start with the datacenter name, and then the object type (host, vm, network, datastore).
                - >-
                    If the object is in a sub folder, the sub folder path should be added after the object type
                    (for example /my_dc/vm/some/sub_folder/vm_name_to_lookup).
                - Enter the object or folder names as seen in the VCenter GUI. Do not escape spaces or special characters.
            required: True
            type: string
        vcenter_hostname:
            description:
                - The hostname or IP address of the vSphere vCenter.
            env:
                - name: VMWARE_HOST
            required: True
            type: string
        vcenter_password:
            description:
                - The vSphere vCenter password.
            env:
                - name: VMWARE_PASSWORD
            required: True
            type: string
        vcenter_rest_log_file:
            description:
                - You can use this optional parameter to set the location of a log file.
                - This file will be used to record the HTTP REST interactions.
                - The file will be stored on the host that runs the module.
            env:
                - name: VMWARE_REST_LOG_FILE
            type: string
        vcenter_username:
            description:
                - The vSphere vCenter username.
            env:
                - name: VMWARE_USER
            required: True
            type: string
        vcenter_validate_certs:
            description:
                - Allows connection when SSL certificates are not valid. Set to V(false) when
                  certificates are not trusted.
            default: true
            env:
                - name: VMWARE_VALIDATE_CERTS
            type: boolean
        object_type:
            description:
                - Should not be set by the user, it is set internally when using a specific lookup plugin.
                - Describes the type of object to lookup. Example, cluster, datacenter, datastore, etc.
            default: 'cluster'
            type: str
            required: False
"""
