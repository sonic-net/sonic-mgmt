#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2021 IBM CORPORATION
# Author(s): Rohit kumar <rohit.kumar6@ibm.com>
#            Shilpi Jain <shilpi.jain1@ibm.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_manage_migration
short_description: This module manages volume migration between clusters on IBM Storage Virtualize family systems
description:
  - Ansible interface to manage the migration commands.
version_added: "1.6.0"
options:
  type_of_migration:
    description:
    - Specifies the type of migration whether it is migration across pools or migration across clusters
    choices: [across_pools, across_clusters]
    default: across_clusters
    type: str
    version_added: '1.11.0'
  new_pool:
    description:
    - Specifies the pool on which the volume has to be migrated.
    - Valid only when I(type_of_migration=across_pools).
    type: str
    version_added: '1.11.0'
  source_volume:
    description:
    - Specifies the name of the existing source volume to be used in migration.
    - Required when I(state=initiate) or I(state=cleanup) or I(type_of_migration=across_pools).
    type: str
  target_volume:
    description:
    - Specifies the name of the volume to be created on the target system.
    - Required when I(state=initiate).
    type: str
  clustername:
    description:
    - The hostname or management IP of the Storage Virtualize system.
    type: str
    required: true
  remote_cluster:
    description:
    - Specifies the name of the remote cluster.
    - Required when I(state=initiate).
    type: str
  domain:
    description:
    - Domain for the Storage Virtualize system.
    - Valid when hostname is used for the parameter I(clustername).
    type: str
  username:
    description:
    - REST API username for the Storage Virtualize system.
    - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user on the local system.
    type: str
  remote_username:
    description:
    - REST API username for the partner Storage Virtualize system.
    - The parameters I(remote_username) and I(remote_password) are required if not using I(remote_token) to authenticate a user on the partner system.
    - Valid when C(state=initiate).
    type: str
  password:
    description:
    - REST API password for the Storage Virtualize system.
    - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user on the local system.
    type: str
  remote_password:
    description:
    - REST API password for the partner Storage Virtualize system.
    - The parameters I(remote_username) and I(remote_password) are required if not using I(remote_token) to authenticate a user on the partner system.
    - Valid when I(state=initiate).
    type: str
  relationship_name:
    description:
    - Name of the migration relationship. Required when I(state=initiate) or I(state=switch).
    type: str
  state:
    description:
    - Specifies the different states of the migration process when I(type_of_migration=across_clusters).
    - C(initiate), creates a volume on remote cluster; optionally used to replicate hosts, and to create and start a migration relationship.
    - C(switch), switches the migration relationship direction allowing write access on the target volume.
    - C(cleanup), deletes the source volume and migration relationship after a 'switch'.
    choices: [initiate, switch, cleanup]
    type: str
  token:
    description:
    - The authentication token to verify a user on the Storage Virtualize system.
    - To generate a token, use the ibm_svc_auth module.
    type: str
  remote_token:
    description:
    - The authentication token to verify a user on the partner Storage Virtualize system.
    - To generate a token, use the ibm_svc_auth module.
      Valid when I(state=initiate).
    type: str
  remote_pool:
    description:
    - Specifies the pool on which the volume on Partner Storage Virtualize system should get created.
    - Required when I(state=initiate).
    type: str
  validate_certs:
    description:
    - Validates certification.
    default: false
    type: bool
  remote_validate_certs:
    description:
    - Validates certification for partner Storage Virtualize system.
    - Valid when I(state=initiate).
    default: false
    type: bool
  replicate_hosts:
    description:
    - Replicates the hosts mapped to a source volume on the source system, to the target system, and maps the hosts to the target volume. The
      user can use ibm_svc_host and ibm_svc_vol_map modules to create and map hosts to the target volume for an
      existing migration relationship.
    - Valid when I(state=initiate).
    default: false
    type: bool
  log_path:
    description:
    - Path of debug log file.
    type: str
author:
    - Rohit Kumar(@rohitk-github)
    - Shilpi Jain(@Shilpi-J)
notes:
    - This module supports C(check_mode).
    - This module supports both volume migration across pools and volume migration across clusters.
    - In case, user does not specify type_of_migration, the module shall proceed with migration across clusters by default.
    - In case of I(type_of_migration=across_pools), the only parameters allowed are I(new_pool) and I(source_volume) along with cluster credentials.
'''

EXAMPLES = '''
- name: Create a target volume
        Create a relationship
        Replicate hosts from source volume to target volume
        Start a relationship
  ibm.storage_virtualize.ibm_svc_manage_migration:
    source_volume: "src_vol"
    target_volume: "target_vol"
    clustername: "{{ source_cluster }}"
    remote_cluster: "{{ remote_cluster }}"
    token: "{{ source_cluster_token }}"
    state: initiate
    replicate_hosts: true
    remote_token: "{{ partner_cluster_token }}"
    relationship_name: "migrate_vol"
    log_path: /tmp/ansible.log
    remote_pool: "{{ remote_pool }}"
- name: Switch replication direction
  ibm.storage_virtualize.ibm_svc_manage_migration:
    relationship_name: "migrate_vol"
    clustername: "{{ source_cluster }}"
    token: "{{ source_cluster_token }}"
    state: switch
    log_path: /tmp/ansible.log
- name: Delete source volume and migration relationship
  ibm.storage_virtualize.ibm_svc_manage_migration:
    clustername: "{{ source_cluster }}"
    state: cleanup
    source_volume: "src_vol"
    token: "{{ source_cluster_token }}"
    log_path: /tmp/ansible.log
- name: Migration an existing vol from pool0 to pool1
  ibm.storage_virtualize.ibm_svc_manage_migration:
    clustername: "{{ source_cluster }}"
    token: "{{ source_cluster_token }}"
    log_path: /tmp/ansible.log
    type_of_migration: across_pools
    source_volume: vol1
    new_pool: pool1
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger
from ansible.module_utils._text import to_native


class IBMSVCMigrate(object):
    def __init__(self):
        argument_spec = svc_argument_spec()

        argument_spec.update(
            dict(
                type_of_migration=dict(type='str', required=False, default='across_clusters',
                                       choices=['across_clusters', 'across_pools']),
                new_pool=dict(type='str', required=False),
                source_volume=dict(type='str', required=False),
                target_volume=dict(type='str', required=False),
                state=dict(type='str',
                           choices=['initiate', 'switch', 'cleanup']),
                remote_pool=dict(type='str', required=False),
                replicate_hosts=dict(type='bool', default=False),
                relationship_name=dict(type='str', required=False),
                remote_cluster=dict(type='str', required=False),
                remote_token=dict(type='str', required=False, no_log=True),
                remote_validate_certs=dict(type='bool', default=False),
                remote_username=dict(type='str', required=False),
                remote_password=dict(type='str', required=False, no_log=True)
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)
        self.existing_rel_data = ""
        self.source_vdisk_data = ""
        self.hosts_iscsi_flag = False

        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        # Required when migration across clusters
        self.state = self.module.params['state']

        # Required when migration across pools
        self.new_pool = self.module.params['new_pool']

        # Optional
        self.type_of_migration = self.module.params['type_of_migration']
        self.source_volume = self.module.params['source_volume']
        self.remote_pool = self.module.params['remote_pool']
        self.target_volume = self.module.params['target_volume']
        self.relationship_name = self.module.params['relationship_name']
        self.remote_username = self.module.params['remote_username']
        self.replicate_hosts = self.module.params['replicate_hosts']
        self.remote_password = self.module.params['remote_password']
        self.remote_token = self.module.params['remote_token']
        self.remote_cluster = self.module.params['remote_cluster']
        self.remote_validate_certs = self.module.params['remote_validate_certs']

        self.restapi = IBMSVCRestApi(
            module=self.module,
            clustername=self.module.params['clustername'],
            domain=self.module.params['domain'],
            username=self.module.params['username'],
            password=self.module.params['password'],
            validate_certs=self.module.params['validate_certs'],
            log_path=log_path,
            token=self.module.params['token']
        )

    def get_existing_vdisk(self):
        self.log("Entering function get_existing_vdisk")
        cmd = 'lsvdisk'
        cmdargs = {}
        cmdopts = {'bytes': True}
        cmdargs = [self.source_volume]
        remote_vdisk_data = ""
        existing_vdisk_data = self.restapi.svc_obj_info(cmd, cmdopts, cmdargs)
        if self.target_volume:
            cmdargs = [self.target_volume]
            remote_restapi = self.construct_remote_rest()
            remote_vdisk_data = remote_restapi.svc_obj_info(cmd, cmdopts, cmdargs)
        return existing_vdisk_data, remote_vdisk_data

    def basic_checks(self):
        self.log("Entering function basic_checks()")
        valid_params = {}
        valid_params['initiate'] = ['source_volume', 'remote_cluster', 'target_volume', 'replicate_hosts',
                                    'remote_username', 'remote_password', 'relationship_name',
                                    'remote_token', 'remote_pool', 'remote_validate_certs']
        valid_params['switch'] = ['relationship_name']
        valid_params['cleanup'] = ['source_volume']
        param_list = set(valid_params['initiate'] + valid_params['switch'] + valid_params['cleanup'])

        # Check for missing mandatory parameter
        for param in valid_params[self.state]:
            param_value = getattr(self, param)
            if not param_value:
                if self.state == "initiate":
                    if param == 'remote_validate_certs' or param == 'replicate_hosts':
                        continue
                    if (param == 'remote_username' or param == 'remote_password'):
                        if not self.remote_username or not self.remote_password:
                            if self.remote_token:
                                continue
                            else:
                                self.module.fail_json(msg="You must pass in either pre-acquired remote_token or "
                                                          "remote_username/remote_password to generate new token.")
                    elif param == 'remote_token':
                        if (self.remote_username and self.remote_password):
                            if not self.remote_token:
                                continue
                self.module.fail_json(msg="Missing mandatory parameter [%s]." % param)

        # Check for invalid parameters
        for param in param_list:
            if self.state == 'initiate':
                if getattr(self, param):
                    if param not in valid_params['initiate']:
                        self.module.fail_json(msg="Invalid parameter [%s] for state 'initiate'" % param)
            if self.state == 'switch':
                if getattr(self, param):
                    if param not in valid_params['switch']:
                        self.module.fail_json(msg="Invalid parameter [%s] for state 'switch'" % param)
            elif self.state == 'cleanup':
                if getattr(self, param):
                    if param not in valid_params['cleanup']:
                        self.module.fail_json(msg="Invalid parameter [%s] for state 'cleanup'" % param)

    def get_source_hosts(self):
        self.log("Entering function get_source_hosts")
        cmd = 'lsvdiskhostmap'
        cmdargs = {}
        cmdopts = {}
        cmdargs = [self.source_volume]
        sourcevolume_hosts = self.restapi.svc_obj_info(cmd, cmdopts, cmdargs)
        return sourcevolume_hosts

    def replicate_source_hosts(self, hosts_data):
        self.log("Entering function replicate_source_hosts()")
        merged_result = []
        hosts_wwpn = {}
        hosts_iscsi = {}
        host_list = []

        if self.module.check_mode:
            self.changed = True
            return

        self.log("creating vdiskhostmaps on target system")

        if isinstance(hosts_data, list):
            for d in hosts_data:
                merged_result.append(d)
        elif hosts_data:
            merged_result = [hosts_data]

        for host in merged_result:
            host_list.append(host['host_name'])

        for host in host_list:
            host_wwpn_list = []
            host_iscsi_list = []
            self.log("for host %s", host)
            data = self.restapi.svc_obj_info(cmd='lshost', cmdopts=None, cmdargs=[host])
            nodes_data = data['nodes']
            for node in nodes_data:
                if 'WWPN' in node.keys():
                    host_wwpn_list.append(node['WWPN'])
                    hosts_wwpn[host] = host_wwpn_list
                elif 'iscsi_name' in node.keys():
                    host_iscsi_list.append(node['iscsi_name'])
                    hosts_iscsi[host] = host_iscsi_list
        if hosts_wwpn or hosts_iscsi:
            self.create_remote_hosts(hosts_wwpn, hosts_iscsi)

    def create_remote_hosts(self, hosts_wwpn, hosts_iscsi):
        self.log("Entering function create_remote_hosts()")

        if self.module.check_mode:
            self.changed = True
            return
        # Make command
        remote_hosts_list = []
        source_host_list = []
        remote_hosts_list = self.return_remote_hosts()
        if hosts_iscsi:
            for host, iscsi_vals in hosts_iscsi.items():
                source_host_list.append(host)
        if hosts_wwpn:
            for host, wwpn_vals in hosts_wwpn.items():
                source_host_list.append(host)

        cmd = 'mkhost'
        for host, wwpn in hosts_wwpn.items():
            if host not in remote_hosts_list:
                cmdopts = {'name': host, 'force': True}
                wwpn = ':'.join([str(elem) for elem in wwpn])
                cmdopts['fcwwpn'] = wwpn
                remote_restapi = self.construct_remote_rest()
                remote_restapi.svc_run_command(cmd, cmdopts, cmdargs=None)

        for host, iscsi in hosts_iscsi.items():
            if host not in remote_hosts_list:
                cmdopts = {'name': host, 'force': True}
                iscsi = ','.join([str(elem) for elem in iscsi])
                cmdopts['iscsiname'] = iscsi
                remote_restapi = self.construct_remote_rest()
                remote_restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        if source_host_list:
            self.map_host_vol_remote(source_host_list)

    def map_host_vol_remote(self, host_list):
        remote_restapi = self.construct_remote_rest()
        if self.module.check_mode:
            self.changed = True
            return
        for host in host_list:
            # Run command
            cmd = 'mkvdiskhostmap'
            cmdopts = {'force': True}
            cmdopts['host'] = host

            cmdargs = [self.target_volume]
            result = remote_restapi.svc_run_command(cmd, cmdopts, cmdargs)
            self.log("create vdiskhostmap result %s", result)

            if 'message' in result:
                self.changed = True
                self.log("create vdiskhostmap result message %s", result['message'])
            else:
                self.module.fail_json(msg="Failed to create vdiskhostmap.")

    def vdisk_create(self, data):
        if not self.remote_pool:
            self.module.fail_json(msg="You must pass in "
                                      "remote_pool to the module.")

        if self.module.check_mode:
            self.changed = True
            return
        self.log("creating vdisk '%s'", self.source_volume)
        size = int(data[0]['capacity'])
        # Make command
        cmd = 'mkvolume'
        cmdopts = {}
        if self.remote_pool:
            cmdopts['pool'] = self.remote_pool
        cmdopts['name'] = self.target_volume
        cmdopts['size'] = size
        cmdopts['unit'] = "b"
        self.log("creating vdisk command %s opts %s", cmd, cmdopts)
        # Run command
        remote_restapi = self.construct_remote_rest()
        result = remote_restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.log("create vdisk result %s", result)

        if 'message' in result:
            self.changed = True
            self.log("create vdisk result message %s", result['message'])
        else:
            self.module.fail_json(msg="Failed to create volume [%s]" % self.source_volume)

    def verify_remote_volume_mapping(self):
        self.log("Entering function verify_remote_volume_mapping")
        cmd = 'lsvdiskhostmap'
        cmdargs = {}
        cmdopts = {}
        cmdargs = [self.target_volume]
        remote_hostmap_data = ""
        remote_restapi = self.construct_remote_rest()
        remote_hostmap_data = remote_restapi.svc_obj_info(cmd, cmdopts, cmdargs)
        if remote_hostmap_data:
            self.module.fail_json(msg="The target volume has hostmappings, Migration relationship cannot be created.")

    def return_remote_hosts(self):
        self.log("Entering function return_remote_hosts")
        cmd = 'lshost'
        remote_hosts = []
        cmdopts = {}
        cmdargs = None
        remote_hosts_data = []
        remote_restapi = self.construct_remote_rest()
        remote_hosts_data = remote_restapi.svc_obj_info(cmd, cmdopts, cmdargs)
        self.log(len(remote_hosts_data))
        for host in remote_hosts_data:
            remote_hosts.append(host['name'])
        return remote_hosts

    def verify_target(self):
        self.log("Entering function verify_target()")
        source_data, target_data = self.get_existing_vdisk()
        if source_data:
            if source_data[0]['RC_name']:
                self.module.fail_json(msg="Source Volume [%s] is already in a relationship." % self.source_volume)
        if target_data:
            if target_data[0]['RC_name']:
                self.module.fail_json(msg="Target Volume [%s] is already in a relationship." % self.target_volume)
            if target_data[0]['mdisk_grp_name'] != self.remote_pool:
                self.module.fail_json(msg="Target Volume [%s] exists on a different pool." % self.target_volume)
        if not source_data:
            self.module.fail_json(msg="Source Volume [%s] does not exist." % self.source_volume)
        elif source_data and target_data:
            source_size = int(source_data[0]['capacity'])
            remote_size = int(target_data[0]['capacity'])
            if source_size != remote_size:
                self.module.fail_json(msg="Remote Volume size is different than that of source volume.")
            else:
                self.log("Target volume already exists, verifying volume mappings now..")
                self.verify_remote_volume_mapping()
        elif source_data and not target_data:
            self.vdisk_create(source_data)
            self.log("Target volume successfully created")
            self.changed = True

    def discover_partner_system(self):
        cmd = 'lspartnership'
        cmdopts = {}
        cmdargs = [self.remote_cluster]
        partnership_data = self.restapi.svc_obj_info(cmd, cmdopts, cmdargs)
        if partnership_data:
            system_location = partnership_data['location']
            if system_location == 'local':
                self.module.fail_json(msg="The relationship could not be created as migration relationships are only allowed to be created to a remote system.")
            self.partnership_exists = True
            remote_socket = partnership_data['console_IP']
            return remote_socket.split(':')[0]
        else:
            msg = "The partnership with remote cluster [%s] does not exist." % self.remote_cluster
            self.module.fail_json(msg=msg)

    def construct_remote_rest(self):
        remote_ip = self.discover_partner_system()
        self.remote_restapi = IBMSVCRestApi(
            module=self.module,
            domain='',
            clustername=remote_ip,
            username=self.module.params['remote_username'],
            password=self.module.params['remote_password'],
            validate_certs=self.module.params['remote_validate_certs'],
            log_path=self.module.params['log_path'],
            token=self.module.params['remote_token']
        )
        return self.remote_restapi

    def create_relationship(self):
        if self.module.check_mode:
            self.changed = True
            return
        self.log("Creating remote copy '%s'", self.relationship_name)

        # Make command
        cmd = 'mkrcrelationship'
        cmdopts = {}
        if self.remote_cluster:
            cmdopts['cluster'] = self.remote_cluster
        if self.source_volume:
            cmdopts['master'] = self.source_volume
            cmdopts['aux'] = self.target_volume
            cmdopts['name'] = self.relationship_name
            cmdopts['migration'] = True

        # Run command
        self.log("Command %s opts %s", cmd, cmdopts)
        if not self.existing_rel_data:
            result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
            self.log("create remote copy result %s", result)

            if 'message' in result:
                self.changed = True
                self.log("Succeeded to create remote copy result message %s", result['message'])
            else:
                msg = "Failed to create migration relationship [%s]" % self.relationship_name
                self.module.fail_json(msg=msg)

    def source_vol_relationship(self, volume):
        """
        Check if the source volume is associated to any migration relationship.
        Returns:
            None if no matching instances
        """

        source_vdisk_data, target_vdisk_data = self.get_existing_vdisk()
        if not source_vdisk_data:
            msg = "Source volume [%s] does not exist" % self.source_volume
            self.module.exit_json(msg=msg)
        self.log('Trying to get the remote copy relationship')
        relationship_name = source_vdisk_data[0]['RC_name']
        if not relationship_name:
            self.module.fail_json(msg="Volume [%s] cannot be deleted. No Migration relationship is configured with the volume." % self.source_volume)
        existing_rel_data = self.restapi.svc_obj_info(cmd='lsrcrelationship', cmdopts=None, cmdargs=[relationship_name])
        if existing_rel_data['copy_type'] != 'migration':
            self.module.fail_json(msg="Volume [%s] cannot be deleted. No Migration relationship is configured with the volume." % self.source_volume)

    def existing_rc(self):
        """
        Find the relationships such as Metro Mirror, Global Mirror relationships visible to the system.

        Returns:
            None if no matching instances or a list including all the matching
            instances
        """
        self.log('Trying to get the remote copy relationship %s', self.relationship_name)
        self.existing_rel_data = self.restapi.svc_obj_info(cmd='lsrcrelationship', cmdopts=None, cmdargs=[self.relationship_name])
        return self.existing_rel_data

    def verify_existing_rel(self, rel_data):
        if self.existing_rel_data:
            master_volume, aux_volume = rel_data['master_vdisk_name'], rel_data['aux_vdisk_name']
            primary, remotecluster, rel_type = rel_data['primary'], rel_data['aux_cluster_name'], rel_data['copy_type']
            if rel_type != 'migration':
                self.module.fail_json(msg="Remote Copy relationship [%s] already exists and is not a migration relationship" % self.relationship_name)
            if self.source_volume != master_volume:
                self.module.fail_json(msg="Migration relationship [%s] already exists with a different source volume" % self.relationship_name)
            if self.target_volume != aux_volume:
                self.module.fail_json(msg="Migration relationship [%s] already exists with a different target volume" % self.relationship_name)
            if primary != 'master':
                self.module.fail_json(msg="Migration relationship [%s] replication direction is incorrect" % self.relationship_name)
            if remotecluster != self.remote_cluster:
                self.module.fail_json(msg="Migration relationship [%s] is configured with a different partner system" % self.relationship_name)

    def start_relationship(self):
        """Start the migration relationship copy process."""
        cmdopts = {}
        if self.module.check_mode:
            self.changed = True
            return
        result = self.restapi.svc_run_command(cmd='startrcrelationship', cmdopts=cmdopts, cmdargs=[self.relationship_name])

        if result == '':
            self.changed = True
            self.log("succeeded to start the remote copy %s", self.relationship_name)
        elif 'message' in result:
            self.changed = True
            self.log("start the rcrelationship %s with result message %s", self.relationship_name, result['message'])
        else:
            msg = "Failed to start the rcrelationship [%s]" % self.relationship_name
            self.module.fail_json(msg=msg)

    def switch(self):
        """Switch the replication direction."""
        cmdopts = {}
        cmdopts['primary'] = 'aux'
        if self.existing_rel_data:
            rel_type = self.existing_rel_data['copy_type']
            if rel_type != 'migration':
                self.module.fail_json(msg="Remote Copy relationship [%s] is not a migration relationship." % self.relationship_name)
        if self.module.check_mode:
            self.changed = True
            return
        result = self.restapi.svc_run_command(cmd='switchrcrelationship', cmdopts=cmdopts, cmdargs=[self.relationship_name])
        self.log("switch the rcrelationship %s with result %s", self.relationship_name, result)
        if result == '':
            self.changed = True
            self.log("succeeded to switch the remote copy %s", self.relationship_name)
        elif 'message' in result:
            self.changed = True
            self.log("switch the rcrelationship %s with result message %s", self.relationship_name, result['message'])
        else:
            msg = "Failed to switch the rcrelationship [%s]" % self.relationship_name
            self.module.fail_json(msg=msg)

    def delete(self):
        """Use the rmvolume command to delete the source volume and the existing migration relationship."""
        if self.module.check_mode:
            self.changed = True
            return
        cmd = 'rmvolume'
        cmdopts = {}
        cmdopts['removehostmappings'] = True
        cmdargs = [self.source_volume]
        if self.module.check_mode:
            self.changed = True
            return
        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        # Any error will have been raised in svc_run_command
        # Command does not output anything when successful.
        if result == '':
            self.changed = True
            self.log("succeeded to delete the source volume %s and associated host mappings and migration relationship", self.source_volume)
            self.changed = True
        elif 'message' in result:
            self.changed = True
            self.log("delete the source volume %s with result message %s",
                     self.source_volume, result['message'])
        else:
            self.module.fail_json(
                msg="Failed to delete the volume [%s]" % self.source_volume)

    def basic_checks_migrate_vdisk(self):
        self.log("Entering function basic_checks_migrate_vdisk()")
        invalid_params = {}

        # Check for missing parameters
        missing = [item[0] for item in [('new_pool', self.new_pool), ('source_volume', self.source_volume)] if not item[1]]
        if missing:
            self.module.fail_json(
                msg='Missing mandatory parameter: [{0}] for migration across pools'.format(', '.join(missing))
            )

        invalid_params['across_pools'] = ['state', 'relationship_name', 'remote_cluster', 'remote_username',
                                          'remote_password', 'remote_token', 'remote_pool', 'remote_validate_certs',
                                          'replicate_hosts']
        param_list = set(invalid_params['across_pools'])

        # Check for invalid parameters
        for param in param_list:
            if self.type_of_migration == 'across_pools':
                if getattr(self, param):
                    if param in invalid_params['across_pools']:
                        self.module.fail_json(msg="Invalid parameter [%s] for volume migration 'across_pools'" % param)

    def migrate_pools(self):
        self.basic_checks_migrate_vdisk()

        if self.module.check_mode:
            self.changed = True
            return

        source_data, target_data = self.get_existing_vdisk()
        if not source_data:
            msg = "Source volume [%s] does not exist" % self.source_volume
            self.module.fail_json(msg=msg)
        elif source_data[0]['mdisk_grp_name'] != self.new_pool:
            cmd = 'migratevdisk'
            cmdopts = {}
            cmdopts['mdiskgrp'] = self.new_pool
            cmdopts['vdisk'] = self.source_volume
            self.log("Command %s opts %s", cmd, cmdopts)
            result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)

            if result == '':
                self.changed = True
            else:
                self.module.fail_json(msg="Failed to migrate volume in different pool.")
        else:
            msg = "No modifications done. New pool [%s] is same" % self.new_pool
            self.module.exit_json(msg=msg, changed=False)

    def apply(self):
        changed = False
        msg = None
        if self.type_of_migration == 'across_pools':
            self.migrate_pools()
            msg = "Source Volume migrated successfully to new pool [%s]." % self.new_pool
            changed = True
        else:
            self.basic_checks()
            if self.state == 'initiate' or self.state == 'switch':
                existing_rc_data = self.existing_rc()
                if not existing_rc_data:
                    if self.state == 'initiate':
                        self.verify_target()
                        self.create_relationship()
                        if self.replicate_hosts:
                            hosts_data = self.get_source_hosts()
                            self.replicate_source_hosts(hosts_data)
                        self.start_relationship()
                        changed = True
                        msg = "Migration Relationship [%s] has been started." % self.relationship_name
                    elif self.state == 'switch':
                        msg = "Relationship [%s] does not exist." % self.relationship_name
                        changed = False
                        self.module.fail_json(msg=msg)
                elif self.state == 'initiate':
                    self.verify_existing_rel(existing_rc_data)
                    self.start_relationship()
                    msg = "Migration Relationship [%s] has been started." % self.relationship_name
                    changed = True
                elif self.state == 'switch':
                    self.switch()
                    msg = "Migration Relationship [%s] successfully switched." % self.relationship_name
                    changed = True
            elif self.state == 'cleanup':
                self.source_vol_relationship(self.source_volume)
                self.delete()
                msg = "Source Volume [%s] deleted successfully." % self.source_volume
                changed = True
        if self.module.check_mode:
            msg = "skipping changes due to check mode."
        self.module.exit_json(msg=msg, changed=changed)


def main():
    v = IBMSVCMigrate()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
