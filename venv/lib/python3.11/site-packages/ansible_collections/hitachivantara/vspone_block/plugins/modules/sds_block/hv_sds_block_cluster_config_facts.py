#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, [ Hitachi Vantara ]
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: hv_sds_block_cluster_config_facts
short_description: Retrieves cluster configuration information.
description:
  - This module retrieves information about SDS Block cluster configuration.
  - It provides details about a cluster configuration such as storage nodes, fault domains and other details.
  - For examples go to URL
    U(https://github.com/hitachi-vantara/vspone-block-ansible/blob/main/playbooks/sds_block_direct/hv_sds_block_cluster_config_facts.yml)
version_added: '4.1.0'
author:
  - Hitachi Vantara LTD (@hitachi-vantara)
requirements:
  - python >= 3.9
attributes:
  check_mode:
    description: Determines if the module should run in check mode.
    support: full
extends_documentation_fragment:
  - hitachivantara.vspone_block.common.sdsb_connection_info
"""

EXAMPLES = """
- name: Retrieve information about configuration of SDS block clusters
  hitachivantara.vspone_block.sds_block.hv_sds_block_cluster_config_facts:
    connection_info:
      address: sdsb.company.com
      username: "admin"
      password: "password"
"""

RETURN = """
ansible_facts:
  description: >
    Dictionary containing the discovered properties of the SDS block storage clusters.
  returned: always
  type: dict
  contains:
    clusters:
      description: A list of clusters.
      type: list
      elements: dict
      contains:
        cluster:
          description: Information about the cluster.
          type: list
          elements: dict
          contains:
            cluster_ip_v4_address:
              description: Cluster's IP v4 address.
              type: str
              sample: "10.76.34.110"
            cluster_name:
              description: Name of the cluster.
              type: str
              sample: "SC01"
            dns_server_1:
              description: First DNS server's IP address.
              type: str
              sample: "10.76.46.10"
            dns_server_2:
              description: Second DNS server's IP address.
              type: str
              sample: ""
            ntp_server_1:
              description: First NTP server's IP address.
              type: str
              sample: "10.76.46.1"
            ntp_server_2:
              description: Second NTP server's IP address.
              type: str
              sample: ""
            time_zone:
              description: Timezone of the cluster.
              type: str
              sample: "UTC"
        fault_domains:
          description: Fault domains in the cluster.
          type: list
          elements: dict
          contains:
            fault_domain_name:
              description: Fault domain name.
              type: str
              sample: "SC01-PD01-FD01"
        fc_port_setting:
          description: FC port settings.
          type: list
          elements: dict
          contains:
            speed:
              description: Speed of the port.
              type: str
              sample: "Auto"
            topology:
              description: Topology of the port.
              type: str
              sample: "Point-to-Point"
        general:
          description: General information about the cluster.
          type: list
          elements: dict
          contains:
            cvs_version:
              description: Software version of the cluster.
              type: str
              sample: "01.17.00.40"
        nodes:
          description: Information about the storage nodes in the cluster.
          type: list
          elements: dict
          contains:
            cluster_master_role:
              description: Whether the node is cluster master.
              type: str
              sample: "clustermaster"
            compute_network_gateway_1:
              description: IP v4 address of the compute network gateway for the storage node.
              type: str
              sample: "10.76.27.1"
            compute_network_ip_1:
              description: IP v4 address of the compute network for the storage node.
              type: str
              sample: "10.76.27.1"
            compute_network_ip_v6_mode_1:
              description: Whether IP v6 address is enabled on the compute network.
              type: str
              sample: "Disable"
            compute_network_ipv6_gateway_1:
              description: IP v6 address of the compute network gateway for the storage node.
              type: str
              sample: ""
            compute_network_ipv6_global_1_1:
              description: IP v6 global information of the compute network for the storage node.
              type: str
              sample: ""
            compute_network_ipv6_subnet_prefix_1:
              description: IP v6 subnet prefix information of the compute network for the storage node.
              type: str
              sample: ""
            compute_network_mtu_size_1:
              description: MTU size of the compute network.
              type: int
              sample: 9000
            compute_network_subnet_1:
              description: IP v4 address subnet mask of the compute network for the storage node.
              type: str
              sample: "255.255.255.0"
            compute_port_protocol_1:
              description: Protocol of the compute port.
              type: str
              sample: "iSCSI"
            control_internode_network_route_destination_1:
              description: Route destination for the control and inter node networks.
              type: str
              sample: "default"
            control_internode_network_route_gateway_1:
              description: Gateway for the control and inter node networks.
              type: str
              sample: "10.76.34.1"
            control_internode_network_route_interface_1:
              description: Interface information for the control and inter node networks.
              type: str
              sample: "control"
            control_network_ip:
              description: IP v4 address of the control network for the storage node.
              type: str
              sample: "10.76.34.101"
            control_network_mtu_size:
              description: MTU size of the compute network.
              type: int
              sample: 1500
            control_network_subnet:
              description: IP v4 address subnet mask of the control network for the storage node.
              type: str
              sample: "255.255.255.0"
            fault_domain_name:
              description: Fault domain name where this storage node belongs to.
              type: str
              sample: "SC01-PD01-FD01"
            host_name:
              description: Hostname of the storage node.
              type: str
              sample: "SDSB-NODE1"
            internode_network_ip:
              description: IP v4 address of the inter node network for the storage node.
              type: str
              sample: "10.76.34.101"
            internode_network_mtu_size:
              description: MTU size of the inter node network.
              type: int
              sample: 9000
            internode_network_subnet:
              description: IP v4 address subnet mask of the inter node network for the storage node.
              type: str
              sample: "255.255.255.0"
            number_of_fc_target_port:
              description: Number of FC target ports.
              type: int
              sample: 0
        protection_domains:
          description: Protection domains in the cluster.
          type: list
          elements: dict
          contains:
            async_processing_resource_usage_rate:
              description: Information about the async processing resource usage rate.
              type: str
              sample: "VeryHigh"
            protection_domain_name:
              description: Protection domain name.
              type: str
              sample: "SC01-PD01"
            redundant_policy:
              description: Redundant policy information.
              type: str
              sample: "HitachiPolyphaseErasureCoding"
            redundant_type:
              description: Redundant type information.
              type: str
              sample: "4D+1P"
            storage_pool_name:
              description: Name of the storage pool.
              type: str
              sample: "SP01"
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


class SDSBClusterFactsManager:
    def __init__(self):
        self.logger = Log()
        self.argument_spec = SDSBClusterArguments().cluster_facts()
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True,
        )
        parameter_manager = SDSBParametersManager(self.module.params)
        self.connection_info = parameter_manager.get_connection_info()
        self.spec = parameter_manager.get_cluster_fact_spec()

    def apply(self):
        self.logger.writeInfo("=== Start of SDSB Cluster Configuratiorn Facts ===")
        storage_nodes = None
        registration_message = validate_ansible_product_registration()
        try:
            sdsb_reconciler = SDSBClusterReconciler(self.connection_info)
            clusters = sdsb_reconciler.get_clusters(self.spec)
        except Exception as e:
            self.logger.writeException(e)
            self.logger.writeInfo("=== End of SDSB Cluster Configuratiorn Facts ===")
            self.module.fail_json(msg=str(e))
        data = {
            "clusters": clusters,
        }
        if registration_message:
            data["user_consent_required"] = registration_message
        self.logger.writeInfo(f"{data}")
        self.logger.writeInfo("=== End of SDSB Cluster Configuratiorn Facts ===")
        self.module.exit_json(changed=False, ansible_facts=data)


def main():
    obj_store = SDSBClusterFactsManager()
    obj_store.apply()


if __name__ == "__main__":
    main()
