#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2018 Catalyst IT Ltd.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: coe_cluster
short_description: Manage COE cluster in OpenStack Cloud
author: OpenStack Ansible SIG
description:
  - Add or remove a COE (Container Orchestration Engine) cluster
    via OpenStack's Magnum aka Container Infrastructure Management API.
options:
  cluster_template_id:
    description:
      - The template ID of cluster template.
      - Required if I(state) is C(present).
    type: str
  discovery_url:
    description:
      - URL used for cluster node discovery.
    type: str
  flavor_id:
    description:
      - The flavor of the minion node for this cluster template.
    type: str
  is_floating_ip_enabled:
    description:
      - Indicates whether created cluster should have a floating ip.
      - Whether enable or not using the floating IP of cloud provider. Some
        cloud providers used floating IP, some used public IP, thus Magnum
        provide this option for specifying the choice of using floating IP.
      - If not set, the value of I(is_floating_ip_enabled) of the cluster template
        specified with I(cluster_template_id) will be used.
      - When I(is_floating_ip_enabled) is set to C(true), then
        I(external_network_id) in cluster template must be defined.
    type: bool
    aliases: ['floating_ip_enabled']
  keypair:
    description:
      - Name of the keypair to use.
    type: str
  labels:
    description:
      - One or more key/value pairs.
    type: raw
  master_count:
    description:
      - The number of master nodes for this cluster.
      - Magnum's default value for I(master_count) is 1.
    type: int
  master_flavor_id:
    description:
      - The flavor of the master node for this cluster template.
    type: str
  name:
    description:
      - Name that has to be given to the cluster template.
    required: true
    type: str
  node_count:
    description:
      - The number of nodes for this cluster.
      - Magnum's default value for I(node_count) is 1.
    type: int
  state:
    description:
      - Indicate desired state of the resource.
    choices: [present, absent]
    default: present
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

RETURN = r'''
cluster:
  description: Dictionary describing the cluster.
  returned: On success when I(state) is C(present).
  type: dict
  contains:
    api_address:
      description: The endpoint URL of COE API exposed to end-users.
      type: str
      sample: https://172.24.4.30:6443
    cluster_template_id:
      description: The UUID of the cluster template.
      type: str
      sample: '7b1418c8-cea8-48fc-995d-52b66af9a9aa'
    coe_version:
      description: Version info of chosen COE in bay/cluster for helping
                   client in picking the right version of client.
      type: str
      sample: v1.11.1
    create_timeout:
      description: Timeout for creating the cluster in minutes.
                   Default to 60 if not set.
      type: int
      sample: 60
    created_at:
      description: The date and time in UTC at which the cluster is created.
      type: str
      sample: "2018-08-16T10:29:45+00:00"
    discovery_url:
      description: The custom discovery url for node discovery. This is used
                   by the COE to discover the servers that have been created
                   to host the containers. The actual discovery mechanism
                   varies with the COE. In some cases, the service fills in
                   the server info in the discovery service. In other cases,
                   if the discovery_url is not specified, the service will
                   use the public discovery service at
                   U(https://discovery.etcd.io). In this case, the service
                   will generate a unique url here for each bay and store the
                   info for the servers.
      type: str
      sample: https://discovery.etcd.io/a42ee38e7113f31f4d6324f24367aae5
    fixed_network:
      description: The name or ID of the network to provide connectivity to the
                   internal network for the bay/cluster.
      type: str
    fixed_subnet:
      description: The fixed subnet to use when allocating network addresses
                   for nodes in bay/cluster.
      type: str
    flavor_id:
      description: The flavor name or ID to use when booting the node servers.
                   Defaults to m1.small.
      type: str
    id:
      description: Unique UUID for this cluster.
      type: str
      sample: '86246a4d-a16c-4a58-9e96ad7719fe0f9d'
    is_floating_ip_enabled:
      description: Indicates whether created clusters should have a
                   floating ip or not.
      type: bool
      sample: true
    is_master_lb_enabled:
      description: Indicates whether created clusters should have a load
                   balancer for master nodes or not.
      type: bool
      sample: true
    keypair:
      description: Name of the keypair to use.
      type: str
      sample: mykey
    labels:
      description: One or more key/value pairs.
      type: dict
      sample: {'key1': 'value1', 'key2': 'value2'}
    master_addresses:
      description: A list of floating IPs of all master nodes.
      type: list
      sample: ['172.24.4.5']
    master_count:
      description: The number of servers that will serve as master for the
                   bay/cluster. Set to more than 1 master to enable High
                   Availability. If the option master-lb-enabled is specified
                   in the baymodel/cluster template, the master servers will
                   be placed in a load balancer pool. Defaults to 1.
      type: int
      sample: 1
    master_flavor_id:
      description: The flavor of the master node for this baymodel/cluster
                   template.
      type: str
      sample: c1.c1r1
    name:
      description: Name that has to be given to the cluster.
      type: str
      sample: k8scluster
    node_addresses:
      description: A list of floating IPs of all servers that serve as nodes.
      type: list
      sample: ['172.24.4.8']
    node_count:
      description: The number of master nodes for this cluster.
      type: int
      sample: 1
    stack_id:
      description: The reference UUID of orchestration stack from Heat
                   orchestration service.
      type: str
      sample: '07767ec6-85f5-44cb-bd63-242a8e7f0d9d'
    status:
      description: Status of the cluster from the heat stack.
      type: str
      sample: 'CREATE_COMLETE'
    status_reason:
      description: Status reason of the cluster from the heat stack
      type: str
      sample: 'Stack CREATE completed successfully'
    updated_at:
      description: The date and time in UTC at which the cluster was updated.
      type: str
      sample: '2018-08-16T10:39:25+00:00'
    uuid:
      description: Unique UUID for this cluster.
      type: str
      sample: '86246a4d-a16c-4a58-9e96ad7719fe0f9d'
'''

EXAMPLES = r'''
- name: Create a new Kubernetes cluster
  openstack.cloud.coe_cluster:
    cloud: devstack
    cluster_template_id: k8s-ha
    keypair: mykey
    master_count: 3
    name: k8s
    node_count: 5
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class COEClusterModule(OpenStackModule):
    argument_spec = dict(
        cluster_template_id=dict(),
        discovery_url=dict(),
        flavor_id=dict(),
        is_floating_ip_enabled=dict(type='bool',
                                    aliases=['floating_ip_enabled']),
        keypair=dict(no_log=False),  # := noqa no-log-needed
        labels=dict(type='raw'),
        master_count=dict(type='int'),
        master_flavor_id=dict(),
        name=dict(required=True),
        node_count=dict(type='int'),
        state=dict(default='present', choices=['absent', 'present']),
    )
    module_kwargs = dict(
        required_if=[
            ('state', 'present', ('cluster_template_id',))
        ],
        supports_check_mode=True,
    )

    def run(self):
        state = self.params['state']

        cluster = self._find()

        if self.ansible.check_mode:
            self.exit_json(changed=self._will_change(state, cluster))

        if state == 'present' and not cluster:
            # Create cluster
            cluster = self._create()
            self.exit_json(changed=True,
                           cluster=cluster.to_dict(computed=False))

        elif state == 'present' and cluster:
            # Update cluster
            update = self._build_update(cluster)
            if update:
                cluster = self._update(cluster, update)

            self.exit_json(changed=bool(update),
                           cluster=cluster.to_dict(computed=False))

        elif state == 'absent' and cluster:
            # Delete cluster
            self._delete(cluster)
            self.exit_json(changed=True)

        elif state == 'absent' and not cluster:
            # Do nothing
            self.exit_json(changed=False)

    def _build_update(self, cluster):
        update = {}

        # TODO: Implement support for updates.
        non_updateable_keys = [k for k in ['cluster_template_id',
                                           'discovery_url', 'flavor_id',
                                           'is_floating_ip_enabled', 'keypair',
                                           'master_count', 'master_flavor_id',
                                           'name', 'node_count']
                               if self.params[k] is not None
                               and self.params[k] != cluster[k]]

        labels = self.params['labels']
        if labels is not None:
            if isinstance(labels, str):
                labels = dict([tuple(kv.split(":"))
                               for kv in labels.split(",")])
            if labels != cluster['labels']:
                non_updateable_keys.append('labels')

        if non_updateable_keys:
            self.fail_json(msg='Cannot update parameters {0}'
                               .format(non_updateable_keys))

        attributes = dict((k, self.params[k])
                          for k in []
                          if self.params[k] is not None
                          and self.params[k] != cluster[k])

        if attributes:
            update['attributes'] = attributes

        return update

    def _create(self):
        # TODO: Complement *_id parameters with find_* functions to allow
        #       specifying names in addition to IDs.
        kwargs = dict((k, self.params[k])
                      for k in ['cluster_template_id', 'discovery_url',
                                'flavor_id', 'is_floating_ip_enabled',
                                'keypair', 'master_count', 'master_flavor_id',
                                'name', 'node_count']
                      if self.params[k] is not None)

        labels = self.params['labels']
        if labels is not None:
            if isinstance(labels, str):
                labels = dict([tuple(kv.split(":"))
                               for kv in labels.split(",")])
            kwargs['labels'] = labels

        kwargs['create_timeout'] = self.params['timeout']

        cluster = self.conn.container_infrastructure_management.\
            create_cluster(**kwargs)

        if not self.params['wait']:
            # openstacksdk's create_cluster() returns a cluster's id only
            # but we cannot use self.conn.container_infrastructure_management.\
            # get_cluster(cluster_id) because it might return None as long as
            # the cluster is being set up.
            return cluster

        if self.params['wait']:
            cluster = self.sdk.resource.wait_for_status(
                self.conn.container_infrastructure_management, cluster,
                status='active',
                failures=['error'],
                wait=self.params['timeout'])

        return cluster

    def _delete(self, cluster):
        self.conn.container_infrastructure_management.\
            delete_cluster(cluster['id'])

        if self.params['wait']:
            self.sdk.resource.wait_for_delete(
                self.conn.container_infrastructure_management, cluster,
                interval=None, wait=self.params['timeout'])

    def _find(self):
        name = self.params['name']
        filters = {}

        cluster_template_id = self.params['cluster_template_id']
        if cluster_template_id is not None:
            filters['cluster_template_id'] = cluster_template_id

        return self.conn.get_coe_cluster(name_or_id=name, filters=filters)

    def _update(self, cluster, update):
        attributes = update.get('attributes')
        if attributes:
            # TODO: Implement support for updates.
            # cluster = self.conn.container_infrastructure_management.\
            # update_cluster(...)
            pass

        return cluster

    def _will_change(self, state, cluster):
        if state == 'present' and not cluster:
            return True
        elif state == 'present' and cluster:
            return bool(self._build_update(cluster))
        elif state == 'absent' and cluster:
            return True
        else:
            # state == 'absent' and not cluster:
            return False


def main():
    module = COEClusterModule()
    module()


if __name__ == "__main__":
    main()
