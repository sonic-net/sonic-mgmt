# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note: This utility is considered private, and can only be referenced from inside the vmware.vmware collection.
#       It may be made public at a later date

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.errors import RequiredIfError


FOLDER_TYPES = ('vm', 'host', 'network', 'datastore')


def prepend_datacenter_and_folder_type(folder_path=None, datacenter_name=None, folder_type=None):
    """
    Formats a folder path so it is absolute, meaning it includes the datacenter name and
    type (vm, host, etc) at the start of the path. If path already starts with
    the datacenter name, nothing is added.
    Eg: rest/of/path -> datacenter name/type/rest/of/path
    """
    if not folder_path:
        folder_path = ''

    folder_path = folder_path.strip('/')

    if not datacenter_name:
        folder_parts = folder_path.split('/')
        if len(folder_parts) > 1 and folder_parts[1] in FOLDER_TYPES:
            # this fits the format of a fully qualified path and even though datacenter name was passed in,
            # we can attempt to treat it as a fq path and the user will just get an error later on
            return folder_path

        # the path is too vague to complete without the datacenter name
        raise RequiredIfError("Datacenter is a required parameter when using a relative folder path, %s" % folder_path)

    if folder_path.startswith(datacenter_name):
        return folder_path

    if folder_type not in FOLDER_TYPES:
        raise ValueError("folder_type %s not in acceptable " % folder_type +
                         "folder type values %s" % ', '.join(FOLDER_TYPES))

    return '/'.join([datacenter_name, folder_type, folder_path]).rstrip('/')


def format_folder_path_as_vm_fq_path(folder_path, datacenter_name):
    """
    Formats a VM folder path so it is absolute, meaning it prepends
    'datacenter name/vm/' to the path if needed. If path already starts with
    the datacenter name, nothing is added.
    Eg: rest/of/path -> datacenter name/vm/rest/of/path
    """
    return prepend_datacenter_and_folder_type(folder_path, datacenter_name, folder_type='vm')


def format_folder_path_as_host_fq_path(folder_path, datacenter_name):
    """
    Formats a host folder path so it is absolute, meaning it prepends
    'datacenter name/vm/' to the path if needed. If path already starts with
    the datacenter name, nothing is added.
    Eg: rest/of/path -> datacenter name/host/rest/of/path
    """
    return prepend_datacenter_and_folder_type(folder_path, datacenter_name, folder_type='host')


def format_folder_path_as_network_fq_path(folder_path, datacenter_name):
    """
    Formats a network folder path so it is absolute, meaning it prepends
    'datacenter name/network/' to the path if needed. If path already starts with
    the datacenter name, nothing is added.
    Eg: rest/of/path -> datacenter name/network/rest/of/path
    """
    return prepend_datacenter_and_folder_type(folder_path, datacenter_name, folder_type='network')


def format_folder_path_as_datastore_fq_path(folder_path, datacenter_name):
    """
    Formats a datastore folder path so it is absolute, meaning it prepends
    'datacenter name/datastore/' to the path if needed. If path already starts with
    the datacenter name, nothing is added.
    Eg: rest/of/path -> datacenter name/datastore/rest/of/path
    """
    return prepend_datacenter_and_folder_type(folder_path, datacenter_name, folder_type='datastore')


def get_folder_path_of_vsphere_object(vsphere_obj):
    """
    Find the path of an object in vsphere.
    Args:
        vsphere_obj: VMware content object

    Returns: Folder of object if exists, else None

    """
    folder_path = []

    # Start with the immediate parent, accounting for different parent types
    # - The default for most objects is 'parent'
    # - VMs in VApps have 'parentVApp'
    parent = getattr(vsphere_obj, 'parent', None) or getattr(vsphere_obj, 'parentVApp', None)

    while parent:
        if parent.name == 'Datacenters':
            break

        folder_path.append(parent.name)

        # Get the next parent in the hierarchy, accounting for different parent types
        # - Regular folders have 'parent'
        # - VApps can have 'parentFolder' (top-level VApp) or 'parent' (nested VApp)
        parent = getattr(parent, 'parentFolder', None) or getattr(parent, 'parent', None)

    folder_path.reverse()
    out = '/'.join(folder_path)
    if not out.startswith('/'):
        out = '/' + out
    return out
