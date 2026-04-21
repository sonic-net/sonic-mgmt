#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_cluster
short_description: Manages VSP One SDS Block and Cloud system clusters.
description:
  - This module allows adding storage node to the cluster, and removing storage node from the cluster.
  - For examples, go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/sdsb_cluster.yml)
version_added: "4.1.0"
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: none
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.sdsb_connection_info
notes:
  - Replace node operation steps for GCP platform
    1) The node should be on block state before replacement.
    2) Create configuration file using hv_sds_block_cluster module with state as download_config_file and
      export_file_type as replace_storage_node and id of the existing node.
    3) Run the terraform file generated using the above step to replace the node (it will remove the existing node from GCP).
    4) Create configuration file using hv_sds_block_cluster module with state as download_config_file and
      export_file_type as replace_storage_node with recover_single_node as true.
    5) Run the terraform file generated using the above step to add the new node to GCP (it will add the new node to GCP).
    6) Add the new node to the cluster using hv_sds_block_cluster module with state as replace_storage_node and
      node_id as the id of the existing node.
  - Replace node operation steps for AWS platform
    1) The node should be on block state before replacement.
    2) Create configuration file using hv_sds_block_cluster module with state as download_config_file and
      export_file_type as replace_storage_node and id of the existing node.
    3) Transfer the configuration file to the S3 location specified in vm_configuration_file_s3_uri.
    4) Add the new node to the cluster using hv_sds_block_cluster module with state as replace_storage_node,
      node_id as the id of the existing node and machine_image_id as the AMI id
  - Replace node operation steps for Azure platform
    1) The node should be on block state before replacement.
    2) Add the new node to the cluster using hv_sds_block_cluster module with state as replace_storage_node,
      node_id as the id of the existing node and machine_image_id as the VM image id.
  - Replace node operation steps for on-premise platform
    1) The node should be on block state before replacement.
    2) add the new node to the cluster using hv_sds_block_cluster module with state as replace_storage_node,
      node_id as the id of the existing node.
options:
  state:
    description: The desired state of the storage cluster.
    type: str
    required: false
    choices: ['present', 'add_storage_node', 'remove_storage_node', 'download_config_file',
              'stop_removing_storage_node', 'replace_storage_node', 'system_requirement_file_present',
              'stop_storage_cluster']
    default: "present"
  spec:
    description: Specification for the storage node to be added to or removed from the cluster.
    type: dict
    required: false
    suboptions:
      configuration_file:
        description: The configuration definition file to be transferred to the storage cluster.
          if this field is specified, storage_nodes field will be ignored if present.
        type: str
        required: false
      config_file_location:
        description: The directory where the cluster configuration file is downloaded. This is a
          required field when the state field is C(download_config_file).
        type: str
        required: false
      export_file_type:
        description: Specifies the type of the configuration file to be output for download. This is a valid field
          when the state field is C(download_config_file).
        type: str
        required: false
        choices: ['normal', 'add_storage_nodes', 'add_drives', 'replace_storage_node']
        default: 'normal'
      should_recover_single_node:
        description: Whether to recover a single node. This is a valid field when the state field is C(download_config_file)
          and export_file_type is C(replace_storage_node) for GCP platform.
        type: bool
        required: false
      machine_image_id:
        description: The ID of the machine image be used for storage node addition or storage node replacement.
        type: str
        required: false
      system_requirement_file:
        description: The path of system requirements file, that describes system requirements to be updated. This field is
          valid and mandatory when the state field is C(system_requirement_file_present).
        type: str
        required: false
      template_s3_url:
        description: URL (https) of Amazon S3 where the VM configuration file is to be stored at the time of each
          maintenance operation. This option is a mandatory parameter for the cloud model for AWS when the state field is
          C(download_config_file) and refresh is true. This parameter is ignored if it is specified for other platforms.
        type: str
        required: false
      vm_configuration_file_s3_uri:
        description: URI (starting with "s3") of Amazon S3 where the VMConfigurationFile.yml VM configuration file is stored.
          If the bucket name contains a period (.), the URI cannot be specified.
          This option is a mandatory parameter for the cloud model for AWS when the state field is C(add_storage_node).
          This parameter is ignored if it is specified for other platforms.
        type: str
        required: false
      no_of_drives:
        description: The number of drives to be installed per storage node after adding the drives. The specified number
          of drives applies to all storage nodes. This is a required field when the export_file_type is C(add_drives).
        type: int
        required: false
      refresh:
        description: Whether to create the cluster configuration file. This is a valid field
          when the state field is C(download_config_file).
        type: bool
        required: false
        default: false
      controller_id:
        description: The ID of the storage controller node for which capacity balancing setting will be
          changded to value specified by attribute is_capacity_balancing_enabled.
        type: str
        required: false
      is_capacity_balancing_enabled:
        description: Enables or disables capacity balancing. If this is true, capacity balancing applies.
          If this is false, capacity balancing does not apply. If controller_id is not specified it will be
          applied to the cluster, otherwise it will be applied to the controller node.
        type: bool
        required: false
      node_id:
        description: The ID of the storage node that will be removed or replaced. This field is valid
          when the state field is C(remove_storage_node) and C(replace_storage_node).
        type: str
        required: false
      node_name:
        description: The name of the storage node that will be removed. This field is valid
          when the state field is C(remove_storage_node).
        type: str
        required: false
      setup_user_password:
        description: Setup user password.
        type: str
        required: false
      force:
        description: This is a valid field when the state field is C(stop_storage_cluster). Specifies whether to perform the operation forcibly.
          When true is specified, the operation is performed forcibly.
          Specify `true` for this parameter only when instructed to do so in a document or by customer support.
          When true is specified for reboot or config_parameter_setting_mode, true cannot be specified here.
        type: bool
        required: false
        default: false
      reboot:
        description: This is a valid field when the state field is C(stop_storage_cluster). Specifies whether to restart the storage cluster.
          Specify false to stop it, or true to restart it. When true is specified for force, true cannot be specified.
        type: bool
        required: false
        default: false
      config_parameter_setting_mode:
        description: This is a valid field when the state field is C(stop_storage_cluster). Specifies whether to start the storage cluster in
          the configuration parameter setting mode after shutdown. If true is specified, the storage node cluster will start in the configuration
          parameter setting mode. When true is specified for force, true cannot be specified.
          Specify `true` for this parameter only when instructed to do so in a document or by customer support.
        type: bool
        required: false
        default: false
      storage_nodes:
        description: List of storage node objects.
        type: list
        elements: dict
        required: false
        suboptions:
          host_name:
            description: Name of the storage node. Used as the host name of the storage node.
            type: str
            required: true
          fault_domain_name:
            description: Name of the fault domain to which the storage node belongs.
            type: str
            required: true
          is_cluster_master_role:
            description: Whether the node is a master node in the cluster.
            type: bool
            required: false
            default: false
          number_of_fc_target_port:
            description: Number of FC target ports.
            type: int
            required: false
            default: 0
          control_network:
            description: Information about the control network.
            type: dict
            required: true
            suboptions:
              control_network_ip:
                description: IP address (IPv4) of the storage node for the control network.
                type: str
                required: true
              control_network_subnet:
                description: IPv4 subnet of the control network.
                type: str
                required: false
                default: "255.255.255.0"
              control_network_mtu_size:
                description: MTU size of the control network.
                type: int
                required: false
                default: 1500
          internode_network:
            description: Information about the control network.
            type: dict
            required: true
            suboptions:
              internode_network_ip:
                description: IP address (IPv4) of the storage node for the inter node network.
                type: str
                required: true
              internode_network_subnet:
                description: IPv4 subnet of the inter node network.
                type: str
                required: false
                default: "255.255.255.0"
              internode_network_mtu_size:
                description: MTU size of the inter node network.
                type: int
                required: false
                default: 9000
          control_internode_network:
            description: Information about the control and inter node networks.
            type: dict
            required: false
            suboptions:
              control_internode_network_route_destinations:
                description: Destination networks to be set in the routing table of the control port or internode port.
                  Up to four network addresses or ip addresses can be provided.
                type: list
                elements: str
                required: false
                default: ["default"]
              control_internode_network_route_gateways:
                description: Gateways (IPv4) to be set in the routing table of the control port or internode port.
                  If not provided, gateway information from the other node of the cluster will be used.
                type: list
                elements: str
                required: false
              control_internode_network_route_interfaces:
                description: Interface name to be set in the routing table of the control port or internode port.
                type: list
                elements: str
                required: false
                default: ["control"]
          compute_networks:
            description: Information about the control network.
            type: list
            elements: dict
            required: true
            suboptions:
              compute_port_protocol:
                description: Protocol of the compute port.
                type: str
                required: false
                choices: [ "iSCSI", "NVMe/TCP"]
                default: "iSCSI"
              compute_network_ip:
                description: IP address (IPv4) of the storage node for the compute network.
                type: str
                required: true
              compute_network_subnet:
                description: IPv4 subnet of the compute network.
                type: str
                required: false
                default: "255.255.255.0"
              compute_network_gateway:
                description: Default IPv4 gateway for the compute network. If not provided,
                  gateway information from the other compute node of the cluster will be used.
                type: str
                required: false
              is_compute_network_ipv6_mode:
                description: Whether the compute network uses IPv6 mode.
                type: bool
                required: false
                default: false
              compute_network_ipv6_globals:
                description: IPv6 global addresses for the compute network.
                type: list
                elements: str
                required: false
              compute_network_ipv6_subnet_prefix:
                description: IPv6 subnet prefix for the compute network.
                type: str
                required: false
              compute_network_ipv6_gateway:
                description: Default IPv6 gateway for the compute network.
                type: str
                required: false
              compute_network_mtu_size:
                description: MTU size of the compute network.
                type: int
                required: false
                default: 9000
"""

EXAMPLES = """
- name: Add storage node to the cluster with the configuration file
  hitachivantara.vspone_block.sds_block.hv_sds_block_cluster:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
      state: "add_storage_node"
      spec:
        configuration_file: "/tmp/download2/SystemConfigurationFile.csv"
        setup_user_password: "CHANGE_ME_SET_YOUR_PASSWORD"

- name: Add storage node to the cluster using ansible variables
  hitachivantara.vspone_block.sds_block.hv_sds_block_cluster:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
      state: "add_storage_node"
      spec:
        setup_user_password: "CHANGE_ME_SET_YOUR_PASSWORD"
        storage_nodes:
          - host_name: "SDSB-NODE6"
            fault_domain_name: "SC01-PD01-FD01"
            is_cluster_master_role: false
            control_network:
              control_network_ip: "10.76.34.106"
            internode_network:
              internode_network_ip: "192.168.210.106"
            control_internode_network:
              control_internode_network_route_destinations:
                - "default"
              control_internode_network_route_gateways:
                - "10.76.34.1"
              control_internode_network_route_interfaces:
                - "control"
            compute_networks:
              - compute_network_ip: "10.76.27.106"
                compute_network_gateway: "10.76.27.1"

- name: Remove storage node from the cluster by storage node ID
  hitachivantara.vspone_block.sds_block.hv_sds_block_cluster:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
      state: "remove_storage_node"
      spec:
        node_id: "8deb71e9-cdba-4002-94bc-c2f6f7a1bee7"

- name: Remove storage node from the cluster by storage node name
  hitachivantara.vspone_block.sds_block.hv_sds_block_cluster:
    connection_info:
      address: storage1.company.com
      username: "admin"
      password: "secret"
      state: "remove_storage_node"
      spec:
        node_name: "vssbesxi1"
"""

RETURN = """
storage_nodes:
  description: A success or failure message for the task.
  returned: always
  type: dict
  contains:
    clusters:
      description: A success or failure message for the task.
      type: str
      sample: "Successfully downloaded SystemConfigurationFile.csv in the directory /tmp/1752598196036657707"
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.reconciler.sdsb_cluster import (
    SDSBClusterReconciler,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.hv_log import (
    Log,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.sdsb_utils import (
    SDSBClusterArguments,
    SDSBParametersManager,
)
from ansible_collections.hitachivantara.vspone_block.plugins.module_utils.common.ansible_common import (
    validate_ansible_product_registration,
)


class SDSBClusterManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBClusterArguments().cluster()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=False,
        )
        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_cluster_spec()
        self.state = parameter_manager.get_state()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Cluster Configuration Operation ===")
        clusters = None
        registration_message = validate_ansible_product_registration()
        try:
            sdsb_reconciler = SDSBClusterReconciler(self.connection_info, self.state)
            clusters = sdsb_reconciler.reconcile_cluster(self.spec)
        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Cluster Configuration Operation ===")
            self.module.fail_json(msg=str(e))
        data = {
            "changed": self.connection_info.changed,
            "messages": clusters,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of SDSB Cluster Configuration Operation ===")
        self.module.exit_json(**data)


def main():
    obj_store = SDSBClusterManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
