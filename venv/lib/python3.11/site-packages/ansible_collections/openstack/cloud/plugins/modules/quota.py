#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016 Pason System Corporation
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = '''
---
module: quota
short_description: Manage OpenStack Quotas
author: OpenStack Ansible SIG
description:
    - Manage OpenStack Quotas. Quotas can be created,
      updated or deleted using this module. A quota will be updated
      if matches an existing project and is present.
options:
    backup_gigabytes:
        description: Maximum size of backups in GB's.
        type: int
    backups:
        description: Maximum number of backups allowed.
        type: int
    cores:
        description: Maximum number of CPU's per project.
        type: int
    fixed_ips:
        description:
          - Number of fixed IP's to allow.
          - Available until Nova API version 2.35.
        type: int
    floating_ips:
        description: Number of floating IP's to allow.
        aliases: [compute_floating_ips, floatingip, network_floating_ips]
        type: int
    gigabytes:
        description: Maximum volume storage allowed for project.
        type: int
    groups:
        description: Number of groups that are allowed for the project
        type: int
    health_monitors:
        description: Maximum number of health monitors that can be created.
        type: int
    injected_file_content_bytes:
        description:
          - Maximum file size in bytes.
          - Available until Nova API version 2.56.
        type: int
        aliases: [injected_file_size]
    injected_files:
        description:
          - Number of injected files to allow.
          - Available until Nova API version 2.56.
        type: int
    injected_file_path_bytes:
        description:
          - Maximum path size.
          - Available until Nova API version 2.56.
        type: int
        aliases: [injected_path_size]
    instances:
        description: Maximum number of instances allowed.
        type: int
    key_pairs:
        description: Number of key pairs to allow.
        type: int
    l7_policies:
        description: The maximum amount of L7 policies you can create.
        type: int
    listeners:
        description: The maximum number of listeners you can create.
        type: int
    load_balancers:
        description: The maximum amount of load balancers you can create
        type: int
        aliases: [loadbalancer]
    metadata_items:
       description: Number of metadata items allowed per instance.
       type: int
    members:
       description: Number of members allowed for loadbalancer.
       type: int
    name:
        description: Name of the OpenStack Project to manage.
        required: true
        type: str
    networks:
        description: Number of networks to allow.
        type: int
        aliases: [network]
    per_volume_gigabytes:
        description: Maximum size in GB's of individual volumes.
        type: int
    pools:
        description: The maximum number of pools you can create
        type: int
        aliases: [pool]
    ports:
        description: Number of Network ports to allow, this needs to be greater
                     than the instances limit.
        type: int
        aliases: [port]
    ram:
        description: Maximum amount of ram in MB to allow.
        type: int
    rbac_policies:
        description: Number of policies to allow.
        type: int
        aliases: [rbac_policy]
    routers:
        description: Number of routers to allow.
        type: int
        aliases: [router]
    security_group_rules:
        description: Number of rules per security group to allow.
        type: int
        aliases: [security_group_rule]
    security_groups:
        description: Number of security groups to allow.
        type: int
        aliases: [security_group]
    server_group_members:
        description: Number of server group members to allow.
        type: int
    server_groups:
        description: Number of server groups to allow.
        type: int
    snapshots:
        description: Number of snapshots to allow.
        type: int
    state:
        description: A value of C(present) sets the quota and a value of
                     C(absent) resets the quota to defaults.
        default: present
        type: str
        choices: [absent, present]
    subnets:
        description: Number of subnets to allow.
        type: int
        aliases: [subnet]
    subnet_pools:
        description: Number of subnet pools to allow.
        type: int
        aliases: [subnetpool]
    volumes:
        description: Number of volumes to allow.
        type: int
extends_documentation_fragment:
- openstack.cloud.openstack
'''

EXAMPLES = '''
- name: Fetch current project quota
  openstack.cloud.quota:
    cloud: mycloud
    name: demoproject

- name: Reset project quota back to defaults
  openstack.cloud.quota:
    cloud: mycloud
    name: demoproject
    state: absent

- name: Change number of cores and volumes
  openstack.cloud.quota:
    cloud: mycloud
    name: demoproject
    cores: 100
    volumes: 20

- name: Update quota again
  openstack.cloud.quota:
    cloud: mycloud
    name: demo_project
    floating_ips: 5
    networks: 50
    ports: 300
    rbac_policies: 5
    routers: 5
    subnets: 5
    subnet_pools: 5
    security_group_rules: 5
    security_groups: 5
    backup_gigabytes: 500
    backups: 5
    gigabytes: 500
    groups: 1
    pools: 5
    per_volume_gigabytes: 10
    snapshots: 5
    volumes: 5
    cores: 5
    instances: 5
    key_pairs: 5
    metadata_items: 5
    ram: 5
    server_groups: 5
    server_group_members: 5

'''

RETURN = '''
quotas:
    description: Dictionary describing the project quota.
    returned: Regardless if changes where made or not
    type: dict
    contains:
        compute:
            description: Compute service quotas
            type: dict
            contains:
                cores:
                    description: Maximum number of CPU's per project.
                    type: int
                injected_file_content_bytes:
                    description: Maximum file size in bytes.
                    type: int
                injected_files:
                    description: Number of injected files to allow.
                    type: int
                injected_file_path_bytes:
                    description: Maximum path size.
                    type: int
                instances:
                    description: Maximum number of instances allowed.
                    type: int
                key_pairs:
                    description: Number of key pairs to allow.
                    type: int
                metadata_items:
                   description: Number of metadata items allowed per instance.
                   type: int
                ram:
                    description: Maximum amount of ram in MB to allow.
                    type: int
                server_group_members:
                    description: Number of server group members to allow.
                    type: int
                server_groups:
                    description: Number of server groups to allow.
                    type: int
        load_balancer:
            description: Load_balancer service quotas
            type: dict
            contains:
                health_monitors:
                    description: Maximum number of health monitors that can be
                      created.
                    type: int
                l7_policies:
                    description: The maximum amount of L7 policies you can
                       create.
                    type: int
                listeners:
                    description: The maximum number of listeners you can create
                    type: int
                load_balancers:
                    description: The maximum amount of load balancers one can
                                 create
                    type: int
                members:
                    description: The maximum amount of members for
                      loadbalancer.
                    type: int
                pools:
                    description: The maximum amount of pools one can create.
                    type: int

        network:
            description: Network service quotas
            type: dict
            contains:
                floating_ips:
                    description: Number of floating IP's to allow.
                    type: int
                networks:
                    description: Number of networks to allow.
                    type: int
                ports:
                    description: Number of Network ports to allow, this needs
                        to be greater than the instances limit.
                    type: int
                rbac_policies:
                    description: Number of policies to allow.
                    type: int
                routers:
                    description: Number of routers to allow.
                    type: int
                security_group_rules:
                    description: Number of rules per security group to allow.
                    type: int
                security_groups:
                    description: Number of security groups to allow.
                    type: int
                subnet_pools:
                    description: Number of subnet pools to allow.
                    type: int
                subnets:
                    description: Number of subnets to allow.
                    type: int
        volume:
            description: Block storage service quotas
            type: dict
            contains:
                backup_gigabytes:
                    description: Maximum size of backups in GB's.
                    type: int
                backups:
                    description: Maximum number of backups allowed.
                    type: int
                gigabytes:
                    description: Maximum volume storage allowed for project.
                    type: int
                groups:
                    description: Number of groups that are allowed for the
                                 project
                    type: int
                per_volume_gigabytes:
                    description: Maximum size in GB's of individual volumes.
                    type: int
                snapshots:
                    description: Number of snapshots to allow.
                    type: int
                volumes:
                    description: Number of volumes to allow.
                    type: int
    sample:
        quotas:
            compute:
                cores: 150,
                fixed_ips: -1,
                floating_ips: 10,
                injected_file_content_bytes: 10240,
                injected_file_path_bytes: 255,
                injected_files: 5,
                instances: 100,
                key_pairs: 100,
                metadata_items: 128,
                networks: -1,
                ram: 153600,
                security_group_rules: -1,
                security_groups: -1,
                server_group_members: 10,
                server_groups: 10,
            network:
                floating_ips: 50,
                networks: 10,
                ports: 160,
                rbac_policies: 10,
                routers: 10,
                security_group_rules: 100,
                security_groups: 10,
                subnet_pools: -1,
                subnets: 10,
            volume:
                backup_gigabytes: 1000,
                backups: 10,
                gigabytes: 1000,
                groups: 10,
                per_volume_gigabytes: -1,
                snapshots: 10,
                volumes: 10,
            load_balancer:
                health_monitors: 10,
                load_balancers: 10,
                l7_policies: 10,
                listeners: 10,
                pools: 5,
                members: 5,
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule
from collections import defaultdict


class QuotaModule(OpenStackModule):
    # TODO: Add missing network quota options 'check_limit'
    #       to argument_spec, DOCUMENTATION and RETURN docstrings
    argument_spec = dict(
        backup_gigabytes=dict(type='int'),
        backups=dict(type='int'),
        cores=dict(type='int'),
        fixed_ips=dict(type='int'),
        floating_ips=dict(
            type='int', aliases=['floatingip', 'compute_floating_ips',
                                 'network_floating_ips']),
        gigabytes=dict(type='int'),
        groups=dict(type='int'),
        health_monitors=dict(type='int'),
        injected_file_content_bytes=dict(type='int',
                                         aliases=['injected_file_size']),
        injected_file_path_bytes=dict(type='int',
                                      aliases=['injected_path_size']),
        injected_files=dict(type='int'),
        instances=dict(type='int'),
        key_pairs=dict(type='int', no_log=False),
        l7_policies=dict(type='int'),
        listeners=dict(type='int'),
        load_balancers=dict(type='int', aliases=['loadbalancer']),
        metadata_items=dict(type='int'),
        members=dict(type='int'),
        name=dict(required=True),
        networks=dict(type='int', aliases=['network']),
        per_volume_gigabytes=dict(type='int'),
        pools=dict(type='int', aliases=['pool']),
        ports=dict(type='int', aliases=['port']),
        ram=dict(type='int'),
        rbac_policies=dict(type='int', aliases=['rbac_policy']),
        routers=dict(type='int', aliases=['router']),
        security_group_rules=dict(type='int', aliases=['security_group_rule']),
        security_groups=dict(type='int', aliases=['security_group']),
        server_group_members=dict(type='int'),
        server_groups=dict(type='int'),
        snapshots=dict(type='int'),
        state=dict(default='present', choices=['absent', 'present']),
        subnet_pools=dict(type='int', aliases=['subnetpool']),
        subnets=dict(type='int', aliases=['subnet']),
        volumes=dict(type='int'),
    )

    module_kwargs = dict(
        supports_check_mode=True
    )

    # Some attributes in quota resources don't exist in the api anymore, e.g.
    # compute quotas that were simply network proxies, and pre-Octavia network
    # quotas. This map allows marking them to be skipped.
    exclusion_map = {
        'compute': {
            # 'fixed_ips',  # Available until Nova API version 2.35
            'floating_ips',  # Available until Nova API version 2.35
            'name',
            'networks',  # Available until Nova API version 2.35
            'security_group_rules',  # Available until Nova API version 2.35
            'security_groups',  # Available until Nova API version 2.35
            # 'injected_file_content_bytes',  # Available until
            # 'injected_file_path_bytes',     # Nova API
            # 'injected_files',               # version 2.56
        },
        'load_balancer': {'name'},
        'network': {
            'name',
            'l7_policies',
            'load_balancers',
            'loadbalancer',
            'health_monitors',
            'pools',
            'listeners',
        },
        'volume': {'name'},
    }

    def _get_quotas(self, project):
        quota = {}
        if self.conn.has_service('block-storage'):
            quota['volume'] = self.conn.block_storage.get_quota_set(project.id)
        else:
            self.warn('Block storage service aka volume service is not'
                      ' supported by your cloud. Ignoring volume quotas.')

        if self.conn.has_service('load-balancer'):
            quota['load_balancer'] = self.conn.load_balancer.get_quota(
                project.id)
        else:
            self.warn('Loadbalancer service is not supported by your'
                      ' cloud. Ignoring loadbalancer quotas.')

        if self.conn.has_service('network'):
            quota['network'] = self.conn.network.get_quota(project.id)
        else:
            self.warn('Network service is not supported by your cloud.'
                      ' Ignoring network quotas.')
        quota['compute'] = self.conn.compute.get_quota_set(project.id)

        return quota

    def _build_update(self, quotas):
        changes = defaultdict(dict)

        for quota_type in quotas.keys():
            exclusions = self.exclusion_map[quota_type]
            for attr in quotas[quota_type].keys():
                if attr in exclusions:
                    continue
                if (attr in self.params and self.params[attr] is not None
                        and quotas[quota_type][attr] != self.params[attr]):
                    changes[quota_type][attr] = self.params[attr]

        return changes

    def _system_state_change(self, project_quota_output):
        """
        Determine if changes are required to the current project quota.

        This is done by comparing the current project_quota_output against
        the desired quota settings set on the module params.
        """

        if self.params['state'] == 'absent':
            return True

        return bool(self._build_update(project_quota_output))

    def run(self):
        project = self.conn.identity.find_project(
            self.params['name'], ignore_missing=False)

        # Get current quota values
        quotas = self._get_quotas(project)
        changed = False

        if self.ansible.check_mode:
            self.exit_json(changed=self._system_state_change(quotas))

        if self.params['state'] == 'absent':
            # If a quota state is set to absent we should assume there will be
            # changes. The default quota values are not accessible so we can
            # not determine if no changes will occur or not.
            changed = True
            self.conn.compute.revert_quota_set(project)
            if 'network' in quotas:
                self.conn.network.delete_quota(project.id)
            if 'volume' in quotas:
                self.conn.block_storage.revert_quota_set(project)
            if 'load_balancer' in quotas:
                self.conn.load_balancer.delete_quota(project.id)

            # Necessary since we can't tell what the default quotas are
            quotas = self._get_quotas(project)

        elif self.params['state'] == 'present':
            changes = self._build_update(quotas)

            if changes:
                if 'volume' in changes:
                    quotas['volume'] = self.conn.block_storage.update_quota_set(
                        project.id, **changes['volume'])
                if 'compute' in changes:
                    quotas['compute'] = self.conn.compute.update_quota_set(
                        project.id, **changes['compute'])
                if 'network' in changes:
                    quotas['network'] = self.conn.network.update_quota(
                        project.id, **changes['network'])
                if 'load_balancer' in changes:
                    quotas['load_balancer'] = \
                        self.conn.load_balancer.update_quota(
                        project.id, **changes['load_balancer'])
                changed = True

        quotas = {k: v.to_dict(computed=False) for k, v in quotas.items()}
        self.exit_json(changed=changed, quotas=quotas)


def main():
    module = QuotaModule()
    module()


if __name__ == '__main__':
    main()
