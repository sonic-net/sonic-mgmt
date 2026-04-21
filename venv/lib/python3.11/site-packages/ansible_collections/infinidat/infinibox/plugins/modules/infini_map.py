#!/usr/bin/python
# -*- coding: utf-8 -*-

# pylint: disable=invalid-name,use-dict-literal,line-too-long,wrong-import-position

"""This module creates, deletes or modifies mappings on Infinibox."""

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: infini_map
version_added: 2.9.0
short_description: Create and Delete mapping of a volume to a host or cluster on Infinibox
description:
    - This module creates or deletes mappings of volumes to hosts or clusters
      on Infinibox.
    - For Linux hosts, after calling this module, the playbook should execute "rescan-scsi-bus.sh" on the host when creating mappings.
    - When removing mappings "rescan-scsi-bus.sh --remove" should be called.
    - For Windows hosts, consider using "'rescan' | diskpart" or "Update-HostStorageCache".
author: David Ohlemacher (@ohlemacher)
options:
  host:
    description:
      - Host Name
    type: str
    required: false
  cluster:
    description:
      - Cluster Name
    type: str
    required: false
  state:
    description:
      - Creates mapping when present or removes when absent, or provides
        details of a mapping when stat.
    required: false
    default: present
    choices: [ "stat", "present", "absent" ]
    type: str
  volume:
    description:
      - Volume name to map to the host.
    type: str
    required: true
  lun:
    description:
      - Volume lun.
    type: int
extends_documentation_fragment:
    - infinibox
'''

EXAMPLES = r'''
- name: Map a volume to an existing host
  infini_map:
    host: foo.example.com
    volume: bar
    state: present  # Default
    user: admin
    password: secret
    system: ibox001

- name: Map a volume to an existing cluster
  infini_map:
    cluster: test-cluster
    volume: bar
    state: present  # Default
    user: admin
    password: secret
    system: ibox001

- name: Unmap volume bar from host foo.example.com
  infini_map:
    host: foo.example.com
    volume: bar
    state: absent
    system: ibox01
    user: admin
    password: secret

- name: Stat mapping of volume bar to host foo.example.com
  infini_map:
    host: foo.example.com
    volume: bar
    state: stat
    system: ibox01
    user: admin
    password: secret
'''

# RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
    HAS_INFINISDK,
    api_wrapper,
    get_cluster,
    get_host,
    get_system,
    get_volume,
    infinibox_argument_spec,
    merge_two_dicts
)

try:
    from infinisdk.core.exceptions import APICommandFailed
except ImportError:
    pass  # Handled by HAS_INFINISDK from module_utils


def vol_is_mapped_to_host(volume, host):
    """ Return a bool showing if a vol is mapped to a host """
    host_luns = host.get_luns()
    for lun in host_luns:
        if lun.volume == volume:
            return True
    return False


def vol_is_mapped_to_cluster(volume, cluster):
    """ Return a bool showing if a vol is mapped to a cluster """
    cluster_luns = cluster.get_luns()
    for lun in cluster_luns:
        if lun.volume == volume:
            return True
    return False


def find_host_lun_use(module, host, volume):
    """ Return a dict showing if a host lun matches a volume. """
    check_result = {'lun_used': False, 'lun_volume_matches': False}
    desired_lun = module.params['lun']

    if desired_lun:
        for host_lun in host.get_luns():
            if desired_lun == host_lun.lun:
                if host_lun.volume == volume:
                    check_result = {'lun_used': True, 'lun_volume_matches': True}
                else:
                    check_result = {'lun_used': True, 'lun_volume_matches': False}

    return check_result


def find_cluster_lun_use(module, cluster, volume):
    """ Return a dict showing if a cluster lun matches a volume. """
    check_result = {'lun_used': False, 'lun_volume_matches': False}
    desired_lun = module.params['lun']

    if desired_lun:
        for cluster_lun in cluster.get_luns():
            if desired_lun == cluster_lun:
                if cluster.volume == volume:
                    check_result = {'lun_used': True, 'lun_volume_matches': True}
                else:
                    check_result = {'lun_used': True, 'lun_volume_matches': False}

    return check_result


def find_host_lun(host, volume):
    """ Find a hosts lun """
    found_lun = None
    luns = host.get_luns()

    for lun in luns:
        if lun.volume == volume:
            found_lun = lun.lun
    return found_lun


def find_cluster_lun(cluster, volume):
    """ Find a cluster's LUN """
    found_lun = None
    luns = cluster.get_luns()

    for lun in luns:
        if lun.volume == volume:
            found_lun = lun.lun
    return found_lun


@api_wrapper
def create_mapping(module, system):
    """ Create mapping of volume to host or cluster. If already mapped, exit_json with changed False. """

    host = get_host(module, system)
    cluster = get_cluster(module, system)

    if host:
        changed = create_mapping_to_host(module, system)
    elif cluster:
        changed = create_mapping_to_cluster(module, system)
    else:
        msg = "A programming error has occurred in create_mapping()"
        module.fail_json(msg=msg)

    # if changed:
    #     with sh.contrib.sudo:
    #         print("rescanning")
    #         rescan_scsi()

    return changed


@api_wrapper
def create_mapping_to_cluster(module, system):
    """ Create mapping of volume to cluster. If already mapped, exit_json with changed False. """
    changed = False

    cluster = get_cluster(module, system)
    volume = get_volume(module, system)
    volume_name = module.params['volume']
    cluster_name = module.params['cluster']
    lun_name = module.params['lun']

    lun_use = find_cluster_lun_use(module, cluster, volume)
    if lun_use['lun_used']:
        msg = f"Cannot create mapping of volume '{volume_name}' to cluster '{cluster_name}' using lun '{lun_name}'. Lun in use."
        module.fail_json(msg=msg)

    try:
        desired_lun = module.params['lun']
        if not module.check_mode:
            cluster.map_volume(volume, lun=desired_lun)
        changed = True
    except APICommandFailed as err:
        if "is already mapped" not in str(err):
            msg = f"Cannot map volume '{volume_name}' to cluster '{cluster_name}': {str(err)}. Already mapped."
            module.fail_json(msg=msg)

    return changed


@api_wrapper
def create_mapping_to_host(module, system):
    """ Create mapping of volume to host. If already mapped, exit_json with changed False. """
    changed = False

    host = system.hosts.get(name=module.params['host'])
    volume = get_volume(module, system)
    volume_name = module.params['volume']
    host_name = module.params['host']
    lun_name = module.params['lun']

    lun_use = find_host_lun_use(module, host, volume)
    if lun_use['lun_used']:
        msg = f"Cannot create mapping of volume '{volume_name}' to host '{host_name}' using lun '{lun_name}'. Lun in use."
        module.fail_json(msg=msg)

    try:
        desired_lun = module.params['lun']
        if not module.check_mode:
            host.map_volume(volume, lun=desired_lun)
        changed = True
    except APICommandFailed as err:
        if "is already mapped" not in str(err):
            msg = f"Cannot map volume '{host_name}' to host '{host_name}': {str(err)}. Already mapped."
            module.fail_json(msg=msg)

    return changed


@api_wrapper
def update_mapping_to_host(module, system):
    """ Update a mapping to a host """
    host = get_host(module, system)
    volume = get_volume(module, system)
    volume_name = module.params['volume']
    host_name = module.params['host']
    desired_lun = module.params['lun']

    if not vol_is_mapped_to_host(volume, host):
        msg = f"Volume '{volume_name}' is not mapped to host '{host_name}'"
        module.fail_json(msg=msg)

    if desired_lun:
        found_lun = find_host_lun(host, volume)
        if found_lun != desired_lun:
            msg = f"Cannot change the lun from '{found_lun}' to '{desired_lun}' for existing mapping of volume '{volume_name}' to host '{host_name}'"
            module.fail_json(msg=msg)

    changed = False
    return changed


@api_wrapper
def update_mapping_to_cluster(module, system):
    """ Update a mapping to a cluster """
    cluster = get_cluster(module, system)
    volume = get_volume(module, system)
    desired_lun = module.params['lun']
    volume_name = module.params['volume']
    cluster_name = module.params['cluster']

    if not vol_is_mapped_to_cluster(volume, cluster):
        msg = f"Volume {volume_name} is not mapped to cluster {cluster_name}"
        module.fail_json(msg=msg)

    if desired_lun:
        found_lun = find_cluster_lun(cluster, volume)
        if found_lun != desired_lun:
            msg = f"Cannot change the lun from '{found_lun}' to '{desired_lun}' for existing mapping of volume '{volume_name}' to cluster '{cluster_name}'"
            module.fail_json(msg=msg)

    changed = False
    return changed


@api_wrapper
def delete_mapping(module, system):
    """ Delete a mapping """
    host = get_host(module, system)
    cluster = get_cluster(module, system)
    if host:
        changed = delete_mapping_to_host(module, system)
    elif cluster:
        changed = delete_mapping_to_cluster(module, system)
    else:
        msg = "A programming error has occurred in delete_mapping()"
        module.fail_json(msg=msg)

    # if changed:
    #     with sh.contrib.sudo:
    #         print("rescanning --remove")
    #         rescan_scsi_remove()

    return changed


@api_wrapper
def delete_mapping_to_host(module, system):
    """
    Remove mapping of volume from host. If the either the volume or host
    do not exist, then there should be no mapping to unmap. If unmapping
    generates a key error with 'has no logical units' in its message, then
    the volume is not mapped.  Either case, return changed=False.
    """
    changed = False
    msg = ""

    if not module.check_mode:
        volume = get_volume(module, system)
        host = get_host(module, system)
        volume_name = module.params['volume']
        host_name = module.params['host']

        if volume and host:
            try:
                existing_lun = find_host_lun(host, volume)
                host.unmap_volume(volume)
                changed = True
                msg = f"Volume '{volume_name}' was unmapped from host '{host_name}' freeing lun '{existing_lun}'"
            except KeyError as err:
                if 'has no logical units' not in str(err):
                    module.fail_json(f"Cannot unmap volume '{volume_name}' from host '{host_name}': {str(err)}")
                else:
                    msg = f"Volume '{volume_name}' was not mapped to host '{host_name}' and so unmapping was not executed"
        else:
            msg = f"Either volume '{volume_name}' or host '{host_name}' does not exist. Unmapping was not executed"
    else:  # check_mode
        changed = True

    module.exit_json(msg=msg, changed=changed)


@api_wrapper
def delete_mapping_to_cluster(module, system):
    """
    Remove mapping of volume from cluster. If the either the volume or cluster
    do not exist, then there should be no mapping to unmap. If unmapping
    generates a key error with 'has no logical units' in its message, then
    the volume is not mapped.  Either case, return changed=False.
    """
    changed = False
    msg = ""

    if not module.check_mode:
        volume = get_volume(module, system)
        cluster = get_cluster(module, system)
        volume_name = module.params['volume']
        cluster_name = module.params['cluster']

        if volume and cluster:
            try:
                existing_lun = find_cluster_lun(cluster, volume)
                cluster.unmap_volume(volume)
                changed = True
                msg = f"Volume '{volume_name}' was unmapped from cluster '{cluster_name}' freeing lun '{existing_lun}'"
            except KeyError as err:
                if 'has no logical units' not in str(err):
                    msg = f"Cannot unmap volume '{volume_name}' from cluster '{cluster_name}': {str(err)}"
                    module.fail_json(msg=msg)
                else:
                    msg = f"Volume '{volume_name}' was not mapped to cluster '{cluster_name}' and so unmapping was not executed"
        else:
            msg = f"Either volume '{volume_name}' or cluster '{cluster_name}' does not exist. Unmapping was not executed"
    else:  # check_mode
        changed = True

    module.exit_json(msg=msg, changed=changed)


def get_mapping_fields(volume, host_or_cluster):
    """ Get mapping fields """
    luns = host_or_cluster.get_luns()
    for lun in luns:
        if volume.get_name() == lun.volume.get_name():
            field_dict = dict(
                id=lun.id,
            )
            return field_dict
    return dict()


def handle_stat(module):
    """ Return mapping stat """
    system = get_system(module)
    volume = get_volume(module, system)
    host = get_host(module, system)
    cluster = get_cluster(module, system)
    volume_name = module.params['volume']

    host_name = module.params['host']
    cluster_name = module.params['cluster']

    if not volume:
        module.fail_json(msg=f"Volume '{volume_name}' not found")

    if not host and not cluster:
        msg = f"Neither host '{host_name}' nor cluster '{cluster_name}' found"
        module.fail_json(msg=msg)

    if (not host or not vol_is_mapped_to_host(volume, host)) \
            and (not cluster or not vol_is_mapped_to_cluster(volume, cluster)):
        if host_name:
            msg = f"Volume '{volume_name}' is not mapped to host '{host_name}'"
        elif cluster_name:
            msg = f"Volume '{volume_name}' is not mapped to cluster '{cluster_name}'"
        module.fail_json(msg=msg)

    if host and host_name:
        found_lun = find_host_lun(host, volume)
        field_dict = get_mapping_fields(volume, host)
        if found_lun is not None:
            msg = f"Volume '{volume_name}' is mapped to host '{host_name}' using lun '{found_lun}'"
            result = dict(
                changed=False,
                volume_lun=found_lun,
                msg=msg,
            )
        else:
            msg = f"Volume '{volume_name}' is not mapped to host '{host_name}'"
            module.fail_json(msg=msg)
    elif cluster and cluster_name:
        found_lun = find_cluster_lun(cluster, volume)
        field_dict = get_mapping_fields(volume, cluster)
        if found_lun is not None:
            msg = f"Volume '{volume_name}' is mapped to cluster '{cluster_name}' using lun '{found_lun}'"
            result = dict(
                changed=False,
                volume_lun=found_lun,
                msg=msg,
            )
        else:
            msg = f"Volume '{volume_name}' is not mapped to cluster '{cluster_name}'"
            module.fail_json(msg=msg)
    else:
        msg = 'A programming error has occurred in handle_stat()'
        module.fail_json(msg=msg)
    result = merge_two_dicts(result, field_dict)
    module.exit_json(**result)


def handle_present(module):
    """ Create or update mapping """
    system = get_system(module)
    volume = get_volume(module, system)
    host = get_host(module, system)
    cluster = get_cluster(module, system)
    volume_name = module.params['volume']
    host_name = module.params['host']
    cluster_name = module.params['cluster']
    if not volume:
        module.fail_json(changed=False, msg=f"Volume '{volume_name}' not found")
    if not host and not cluster:
        if not host_name:
            host_name = "not specified"
        if not cluster_name:
            cluster_name = "not specified"
        module.fail_json(changed=False, msg=f"Neither host '{host_name}' nor cluster '{cluster_name}' found")
    if host:
        if not vol_is_mapped_to_host(volume, host):
            changed = create_mapping(module, system)
            msg = f"Volume '{volume_name}' map to host '{host_name}' created"
        else:
            changed = update_mapping_to_host(module, system)
            existing_lun = find_host_lun(host, volume)
            msg = f"Volume '{volume_name}' map to host '{host_name}' already exists using lun '{existing_lun}'"
    elif cluster:
        if not vol_is_mapped_to_cluster(volume, cluster):
            changed = create_mapping(module, system)
            msg = f"Volume '{volume_name}' map to cluster '{cluster_name}' created"
        else:
            changed = update_mapping_to_cluster(module, system)
            existing_lun = find_cluster_lun(cluster, volume)
            msg = f"Volume '{volume_name}' map to cluster '{cluster_name}' already exists using lun '{existing_lun}'"

    result = dict(
        changed=changed,
        msg=msg,
    )
    module.exit_json(**result)


def handle_absent(module):
    """ Remove mapping """
    system = get_system(module)
    volume = get_volume(module, system)
    host = get_host(module, system)
    cluster = get_cluster(module, system)
    volume_name = module.params['volume']
    host_name = module.params['host']
    cluster_name = module.params['cluster']
    if not volume or (not host and not cluster):
        module.exit_json(changed=False, msg=f'Mapping of volume {volume_name} to host {host_name} or cluster {cluster_name} already absent')
    else:
        changed = delete_mapping(module, system)
        module.exit_json(changed=changed, msg="Mapping removed")


def execute_state(module):
    """Determine which state function to execute and do so"""
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


def check_parameters(module):
    """Verify module options are sane"""
    host_name = module.params['host']
    cluster_name = module.params['cluster']
    if host_name and cluster_name:
        msg = "infini_map requires a host or a cluster but not both to be provided"
        module.fail_json(msg=msg)

    if not host_name and not cluster_name:
        msg = "infini_map requires a host or a cluster to be provided"
        module.fail_json(msg=msg)


def main():
    """ Main """
    argument_spec = infinibox_argument_spec()
    argument_spec.update(
        dict(
            host=dict(required=False, default=None),
            cluster=dict(required=False, default=None),
            state=dict(default='present', choices=['stat', 'present', 'absent']),
            volume=dict(required=True),
            lun=dict(type="int"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_INFINISDK:
        module.fail_json(msg=missing_required_lib('infinisdk'))

    check_parameters(module)
    execute_state(module)


if __name__ == '__main__':
    main()
