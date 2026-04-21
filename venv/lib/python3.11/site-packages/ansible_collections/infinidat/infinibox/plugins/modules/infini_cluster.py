#!/usr/bin/python
# -*- coding: utf-8 -*-

# pylint: disable=invalid-name,use-dict-literal,too-many-branches,too-many-locals,line-too-long,wrong-import-position

""" A module for managing Infinibox clusters """

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: infini_cluster
version_added: '2.9.0'
short_description: Create, Delete and Modify Host Cluster on Infinibox
description:
    - This module creates, deletes or modifies host clusters on Infinibox.
author: David Ohlemacher (@ohlemacher)
options:
  name:
    description:
      - Cluster Name
    required: true
    type: str
  state:
    description:
      - Creates/Modifies Cluster when present, removes when absent, or provides
        details of a cluster when stat.
    required: false
    type: str
    default: present
    choices: [ "stat", "present", "absent" ]
  cluster_hosts:
    description: A list of hosts to add to a cluster when state is present.
    required: false
    type: list
    elements: dict
extends_documentation_fragment:
    - infinibox
'''

EXAMPLES = r'''
- name: Create new cluster
  infini_cluster:
    name: foo_cluster
    user: admin
    password: secret
    system: ibox001
'''

# RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

try:
    from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
        HAS_INFINISDK,
        api_wrapper,
        infinibox_argument_spec,
        get_system,
        get_cluster,
        unixMillisecondsToDate,
        merge_two_dicts,
    )
except ModuleNotFoundError:
    from infinibox import (  # Used when hacking
        HAS_INFINISDK,
        api_wrapper,
        infinibox_argument_spec,
        get_system,
        get_cluster,
        unixMillisecondsToDate,
        merge_two_dicts,
    )


@api_wrapper
def get_host_by_name(system, host_name):
    """Find a host by the name specified in the module"""
    host = None

    for a_host in system.hosts.to_list():
        a_host_name = a_host.get_name()
        if a_host_name == host_name:
            host = a_host
            break
    return host


@api_wrapper
def create_cluster(module, system):
    """ Create a cluster """
    changed = False
    if not module.check_mode:
        cluster = system.host_clusters.create(name=module.params['name'])
        cluster_hosts = module.params['cluster_hosts']
        if cluster_hosts:
            for cluster_host in cluster_hosts:
                if cluster_host['host_cluster_state'] == 'present':
                    host = get_host_by_name(system, cluster_host['host_name'])
                    cluster.add_host(host)
                    changed = True
    return changed


@api_wrapper
def update_cluster(module, system, cluster):
    """ Update a cluster """
    changed = False

    # e.g. of one host dict found in the module.params['cluster_hosts'] list:
    #    {host_name: <'some_name'>, host_cluster_state: <'present' or 'absent'>}
    module_cluster_hosts = module.params['cluster_hosts']
    current_cluster_hosts_names = [host.get_name() for host in cluster.get_field('hosts')]
    if module_cluster_hosts:
        for module_cluster_host in module_cluster_hosts:
            module_cluster_host_name = module_cluster_host['host_name']
            # Need to add host to cluster?
            if module_cluster_host_name not in current_cluster_hosts_names:
                if module_cluster_host['host_cluster_state'] == 'present':
                    host = get_host_by_name(system, module_cluster_host_name)
                    if not host:
                        msg = f'Cannot find host {module_cluster_host_name} to add to cluster {cluster.get_name()}'
                        module.fail_json(msg=msg)
                    cluster.add_host(host)
                    changed = True
            # Need to remove host from cluster?
            elif module_cluster_host_name in current_cluster_hosts_names:
                if module_cluster_host['host_cluster_state'] == 'absent':
                    host = get_host_by_name(system, module_cluster_host_name)
                    if not host:
                        msg = f'Cannot find host {module_cluster_host_name} to add to cluster {cluster.get_name()}'
                        module.fail_json(msg=msg)
                    cluster.remove_host(host)
                    changed = True
    return changed


@api_wrapper
def delete_cluster(module, cluster):
    """ Delete a cluster """
    if not cluster:
        msg = f"Cluster {cluster.get_name()} not found"
        module.fail_json(msg=msg)
    changed = True
    if not module.check_mode:
        cluster.delete()
    return changed


def get_cluster_fields(cluster):
    """ Find fields for cluster """
    fields = cluster.get_fields(from_cache=True, raw_value=True)
    created_at, created_at_timezone = unixMillisecondsToDate(fields.get('created_at', None))
    field_dict = dict(
        hosts=[],
        id=cluster.id,
        created_at=created_at,
        created_at_timezone=created_at_timezone,
    )
    hosts = cluster.get_hosts()
    for host in hosts:
        host_dict = {
            'host_id': host.id,
            'host_name': host.get_name(),
        }
        field_dict['hosts'].append(host_dict)
    return field_dict


def handle_stat(module):
    """ Handle stat state """
    system = get_system(module)
    cluster = get_cluster(module, system)
    cluster_name = module.params["name"]
    if not cluster:
        module.fail_json(msg=f'Cluster {cluster_name} not found')
    field_dict = get_cluster_fields(cluster)
    result = dict(
        changed=False,
        msg='Cluster stat found'
    )
    result = merge_two_dicts(result, field_dict)
    module.exit_json(**result)


def handle_present(module):
    """ Handle present state """
    system = get_system(module)
    cluster = get_cluster(module, system)
    cluster_name = module.params["name"]
    if not cluster:
        changed = create_cluster(module, system)
        msg = f'Cluster {cluster_name} created'
        module.exit_json(changed=changed, msg=msg)
    else:
        changed = update_cluster(module, system, cluster)
        if changed:
            msg = f'Cluster {cluster_name} updated'
        else:
            msg = f'Cluster {cluster_name} required no changes'
        module.exit_json(changed=changed, msg=msg)


def handle_absent(module):
    """ Handle absent state """
    system = get_system(module)
    cluster = get_cluster(module, system)
    cluster_name = module.params["name"]
    if not cluster:
        changed = False
        msg = f"Cluster {cluster_name} already absent"
    else:
        changed = delete_cluster(module, cluster)
        msg = f"Cluster {cluster_name} removed"
    module.exit_json(changed=changed, msg=msg)


def execute_state(module):
    """ Handle states """
    state = module.params['state']
    try:
        if state == 'stat':
            handle_stat(module)
        elif state == 'present':
            handle_present(module)
        elif state == 'absent':
            handle_absent(module)
        else:
            module.fail_json(msg=f'Internal handler error. Invalid state: {state}')
    finally:
        system = get_system(module)
        system.logout()


def check_options(module):
    """ Check module parameters for logic errors """
    state = module.params['state']
    if state == 'present':
        cluster_hosts = module.params['cluster_hosts']
        if cluster_hosts:
            for host in cluster_hosts:
                try:
                    # Check host has required keys
                    valid_keys = ['host_name', 'host_cluster_state']
                    for valid_key in valid_keys:
                        # _ = host[valid_key]
                        if valid_key not in host.keys():
                            raise KeyError
                    # Check host has no unknown keys
                    if len(host.keys()) != len(valid_keys):
                        raise KeyError
                except KeyError:
                    msg = 'With state present, all cluster_hosts ' \
                        + 'require host_name and host_cluster_state key:values ' \
                        + 'and no others'
                    module.fail_json(msg=msg)


def main():
    """ Main """
    argument_spec = infinibox_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True),
            state=dict(default='present', choices=['stat', 'present', 'absent']),
            cluster_hosts=dict(required=False, type="list", elements="dict"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_INFINISDK:
        module.fail_json(msg=missing_required_lib('infinisdk'))

    check_options(module)
    execute_state(module)


if __name__ == '__main__':
    main()
