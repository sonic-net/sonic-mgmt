#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2022, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Abhishek Maheshwari, Madhan Sankaranarayanan"
DOCUMENTATION = r"""
---
module: sda_fabric_virtual_networks_workflow_manager
short_description: Configure fabric VLANs, Virtual Networks,
  and Anycast Gateways in Cisco Catalyst Center.
description:
  - Create, update, or delete layer2 Fabric VLAN(s)
    for SDA operations in Cisco Catalyst Center.
  - Create, update, or delete layer3 Virtual Network(s)
    for SDA operations in Cisco Catalyst Center.
  - Create, update, or delete Anycast Gateway(s) for
    SDA operations in Cisco Catalyst Center.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Abhishek Maheshwari (@abmahesh) Madhan Sankaranarayanan
  (@madhansansel)
options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst
      Center config after applying the playbook config.
    type: bool
    default: false
  state:
    description: The state of Cisco Catalyst Center
      after module completion.
    type: str
    choices: [merged, deleted]
    default: merged
  sda_fabric_vlan_limit:
    description: Sets the maximum number of fabric VLANs
      that can be created or updated at a time via the
      SDA API, aligning with GUI constraints. The default
      is 20, as the GUI allows creating up to 20 fabric
      VLANs at a time.
    type: int
    default: 20
  sda_fabric_gateway_limit:
    description: Sets the maximum number of anycast
      gateways that can be created or updated at a time
      via the SDA API, aligning with GUI constraints.
      The default is 20, as the GUI allows creating
      up to 20 anycast gateways at a time.
    type: int
    default: 20
  config:
    description: A list containing detailed configurations
      for creating, updating, or deleting fabric sites/zones
      in a Software-Defined Access (SDA) environment.
      It also includes specifications for updating the
      authentication profile template for these sites.
      Each element in the list represents a specific
      operation to be performed on the SDA infrastructure,
      such as the addition, modification, or removal
      of fabric sites/zones, and modifications to authentication
      profiles.
    type: list
    elements: dict
    required: true
    suboptions:
      fabric_vlan:
        description: A list of VLAN configurations for
          fabric sites in SDA environment. Each VLAN
          entry includes information about its name,
          ID, traffic type, and wireless capabilities.
        type: list
        elements: dict
        suboptions:
          vlan_name:
            description: Name of the VLAN of the layer2
              virtual network. Must contain only alphanumeric
              characters, underscores, and hyphens.
              Updating this field is not allowed.
            type: str
            required: true
          vlan_id:
            description: ID for the layer2 VLAN network.
              Allowed VLAN range is 2-4093 except for
              reserved VLANs 1002-1005, and 2046. If
              deploying on a fabric zone, this vlan_id
              must match the vlan_id of the corresponding
              layer2 virtual network on the fabric site.
              And updation of this field is not allowed.
            type: int
            required: true
          fabric_site_locations:
            description: A list of fabric site locations
              where this VLAN is deployed, including
              site hierarchy and fabric type details.
            type: list
            elements: dict
            suboptions:
              site_name_hierarchy:
                description: This name uniquely identifies
                  the site for operations such as creating/updating/deleting
                  any fabric VLAN. This parameter is
                  required, and updates to this field
                  is not allowed.
                type: str
                required: true
              fabric_type:
                description: Specifies the type of site
                  to be managed within the SDA environment.
                  The acceptable values are 'fabric_site'
                  and 'fabric_zone'. The default value
                  is 'fabric_site', indicating the configuration
                  of a broader network area, whereas
                  'fabric_zone' typically refers to
                  a more specific segment within the
                  site.
                type: str
                required: true
          traffic_type:
            description: The type of traffic handled
              by the VLAN (e.g., DATA, VOICE). By default,
              it is set to "DATA".
            type: str
            required: true
          fabric_enabled_wireless:
            description: Indicates whether the fabric
              VLAN is enabled for wireless in the fabric
              environment. By default, it is set to
              False.
            type: bool
          wireless_flooding_enable:
            description: Controls wireless flooding behavior for
              the fabric VLAN, which determines how BUM traffic
              (Broadcast, Unknown unicast, and Multicast) from
              wireless clients is handled within the fabric network.
              When enabled, BUM traffic from wireless clients is
              flooded across the fabric to ensure proper connectivity
              and service discovery. When disabled, BUM traffic
              flooding is suppressed, which can improve network
              efficiency but may impact certain network services
              that rely on broadcast or multicast communication.
              If there is an associated layer 3 virtual network,
              wireless flooding will default to false and can only
              be set to true when fabric-enabled wireless is also
              enabled. If there is no associated layer 3 virtual
              network, wireless flooding will match the
              fabric-enabled wireless setting.
            type: bool
            default: false
          resource_guard_enable:
            description: A security feature control for fabric VLANs
              that enables or disables Resource Guard functionality.
              Resource Guard is a security mechanism that provides
              protection against unauthorized access to network resources
              by implementing additional security controls and access
              restrictions at the VLAN level within the fabric network.
              When enabled, it enhances the security posture of the
              fabric VLAN by enforcing stricter access policies and
              monitoring capabilities.
            type: bool
            default: false
          flooding_address_assignment:
            description: Controls the source configuration for flooding
              addresses used in layer 2 flooding within the fabric VLAN.
              This parameter determines whether the layer 2 virtual network
              uses a 'SHARED' flooding address from the parent fabric or a
              'CUSTOM' address specific to this virtual network. Two
              options are available - "SHARED" means that the layer 2
              virtual network will inherit the flooding address from
              the parent fabric configuration, ensuring consistency
              across the fabric. "CUSTOM" allows the layer 2 virtual
              network to use a different flooding address for specific
              use cases or network segmentation requirements. When set
              to "CUSTOM", you must also provide a valid flooding_address
              parameter.
            type: str
            choices: ["SHARED", "CUSTOM"]
            default: "SHARED"
          flooding_address:
            description: Specifies a custom multicast IP address for layer 2
              flooding operations within the fabric VLAN. This parameter defines
              the multicast address used when the fabric needs to flood traffic
              to all ports in the VLAN for unknown unicast, broadcast, or
              multicast frames. The IP address must be in the 239.0.0.0/8
              multicast range (239.0.0.1 through 239.255.255.255) to ensure
              proper multicast behavior and compliance with RFC standards.
              This property is applicable only when the flooding_address_assignment
              is set to "CUSTOM". If flooding_address_assignment is "SHARED",
              this parameter will be ignored as the flooding address is inherited
              from the parent fabric configuration. The address should be unique
              within your network topology to avoid multicast conflicts and
              ensure proper traffic isolation between different VLANs or fabric
              segments.
            type: str
            required: false
          associated_layer3_virtual_network:
            description: Name of the layer3 virtual
              network associated with the layer2 fabric
              VLAN. This field is provided to support
              requests related to virtual network anchoring.
              The layer3 virtual network must have already
              been added to the fabric before association.
              This field must either be present in all
              payload elements or none. And updation
              of this field is not allowed.
            type: str
      virtual_networks:
        description: A list of virtual networks (VNs)
          configured within the SDA fabric. Each virtual
          network includes details such as its name,
          associated fabric sites, and optionally, an
          anchored site.
        type: list
        elements: dict
        suboptions:
          vn_name:
            description: The virtual network must be
              added to the site before creating an anycast
              gateway with it. Updating this field is
              not allowed. It consist of only letters,
              numbers, and underscores, and must be
              between 1-16 characters in length.
            type: str
            required: true
          fabric_site_locations:
            description: A list of fabric site locations
              where this this Layer3 virtual network
              is to be assigned to, including site hierarchy
              and fabric type details. If this parameter
              is given make sure to provide the site_name
              and fabric_type as well as the required
              parameter to extend the virtual networks
              across given fabric sites.
            type: list
            elements: dict
            suboptions:
              site_name_hierarchy:
                description: This name uniquely identifies
                  the site for operations such as creating/updating/deleting
                  any layer3 virtual network.
                type: str
              fabric_type:
                description: Specifies the type of site
                  to be managed within the SDA environment.
                  The acceptable values are 'fabric_site'
                  and 'fabric_zone'. The default value
                  is 'fabric_site', indicating the configuration
                  of a broader network area, whereas
                  'fabric_zone' typically refers to
                  a more specific segment within the
                  site.
                type: str
                default: "fabric_site"
          anchored_site_name:
            description: Specifies the name of the fabric
              site where the virtual network is anchored.
              When this parameter is provided, ensure
              that the 'fabric_site_locations' contains
              the same 'site_name', and that only one
              fabric site location is specified. If
              all parameters are provided, the Layer3
              virtual network is created and extended
              across multiple fabric sites. However,
              the operation will fail due to conflicting
              'anchored_site_name' settings, and the
              module will return a failure response.
              For a Virtual Network anchored at a site,
              at least one Control Plane (CP) and External
              Border must be present.
            type: str
      anycast_gateways:
        description: A list of anycast gateways in the
          SDA fabric, each with details about its associated
          virtual network, IP pool, VLAN configuration,
          and other advanced network settings.
        type: list
        elements: dict
        suboptions:
          vn_name:
            description: The name of the Layer3 virtual
              network. It must consist only of letters,
              numbers, and underscores, with a length
              between 1 and 16 characters. This field
              cannot be updated after creation.
            type: str
            required: true
          fabric_site_location:
            description: A list of fabric site locations
              where this Layer3 virtual network will
              be assigned, including details about the
              site hierarchy and fabric type. If this
              parameter is provided, ensure that both
              site_name and fabric_type are specified
              for each entry. This is required to extend
              the virtual networks across the specified
              fabric sites.
            type: dict
            required: true
            suboptions:
              site_name_hierarchy:
                description: The hierarchical name of
                  the site where the anycast gateway
                  is deployed.
                type: str
              fabric_type:
                description: Specifies the type of site
                  to be managed within the SDA environment.
                  The acceptable values are 'fabric_site'
                  and 'fabric_zone'. The default value
                  is 'fabric_site', indicating the configuration
                  of a broader network area, whereas
                  'fabric_zone' typically refers to
                  a more specific segment within the
                  site.
                type: str
                default: "fabric_site"
          ip_pool_name:
            description: Name of the IP pool associated
              with the anycast gateway. The IP pool
              must already exist in the Cisco Catalyst
              Center, if it does not exist, it can be
              created or reserved using the 'network_settings_workflow_manager'
              module. Updating this field is not allowed.
            type: str
            required: true
          tcp_mss_adjustment:
            description: The value used to adjust the
              TCP Maximum Segment Size (MSS). The value
              should be in the range (500, 1441).
            type: int
          vlan_name:
            description: Name of the VLAN for the anycast
              gateway. This field is optional if the
              parameter auto_generate_vlan_name is set
              to True. Updating this field is not allowed.
            type: str
          vlan_id:
            description: ID of the VLAN for the anycast
              gateway. The allowed VLAN range is 2-4093,
              except for reserved VLANs 1002-1005, 2046,
              and 4094. If deploying an anycast gateway
              on a fabric zone, this 'vlan_id' must
              match the 'vlan_id' of the corresponding
              anycast gateway on the fabric site. This
              field is optional if the parameter 'auto_generate_vlan_name'
              is set to true. Updating this field is
              not allowed.
            type: int
          traffic_type:
            description: The type of traffic handled
              by the VLAN (e.g., DATA, VOICE). By defaut,
              it is set to "DATA". Updating the "traffic_type"
              in the anycast gateway is not allowed
              if "is_critical_pool" is set to true.
            type: str
          pool_type:
            description: The pool type of the anycast
              gateway. This field is required and applicable
              only to INFRA_VN. One of the following
              values must be selected (EXTENDED_NODE,
              FABRIC_AP). Updating this field is not
              allowed.
          security_group_name:
            description: The name of the security group
              associated with the anycast gateway. It
              is not applicable to INFRA_VN.
            type: str
          is_critical_pool:
            description: Specifies whether this pool
              is marked as critical for the network.
              If set to true, 'auto_generate_vlan_name'
              must also be true. By default, this field
              is set to false. This field is not applicable
              to INFRA_VN. Updating this field is not
              allowed.
            type: bool
            default: false
          layer2_flooding_enabled:
            description: Indicates whether Layer 2 flooding
              is enabled in the network. By default,
              it is set to false. It is not applicable
              to INFRA_VN.
            type: bool
            default: false
          flooding_address_assignment:
            description: Controls the source configuration for flooding
                addresses used in layer 2 flooding within the anycast gateway.
                This parameter determines whether the virtual network uses
                a 'SHARED' flooding address from the parent fabric or a
                'CUSTOM' address specific to this virtual network. Two
                options are available - "SHARED" means that the layer 2
                virtual network will inherit the flooding address from
                the parent fabric configuration, ensuring consistency
                across the fabric. "CUSTOM" allows the layer 2 virtual
                network to use a different flooding address for specific
                use cases or network segmentation requirements. When set
                to "CUSTOM", you must also provide a valid flooding_address
                parameter. This field is not applicable to INFRA_VN.
            type: str
            choices: ["SHARED", "CUSTOM"]
            default: "SHARED"
          flooding_address:
            description: Specifies a custom multicast IP address for layer 2
              flooding operations within the anycast gateway. This parameter defines
              the multicast address used when the fabric needs to flood traffic
              to all ports in the VLAN for unknown unicast, broadcast, or
              multicast frames. The IP address must be in the 239.0.0.0/8
              multicast range (239.0.0.1 through 239.255.255.255) to ensure
              proper multicast behavior and compliance with RFC standards.
              This property is applicable only when the flooding_address_assignment
              is set to "CUSTOM". If flooding_address_assignment is "SHARED",
              this parameter will be ignored as the flooding address is inherited
              from the parent fabric configuration. The address should be unique
              within your network topology to avoid multicast conflicts and
              ensure proper traffic isolation between different VLANs or fabric
              segments. This field is not applicable to INFRA_VN.
            type: str
            required: false
          fabric_enabled_wireless:
            description: Specifies whether the anycast
              gateway is enabled for wireless in the
              fabric. By default, this field is set
              to false. This field is not applicable
              to INFRA_VN.
            type: bool
            default: false
          wireless_flooding_enable:
            description: Controls wireless flooding behavior for
              the anycast gateway, which determines how BUM traffic
              (Broadcast, Unknown unicast, and Multicast) from
              wireless clients is handled within the fabric network.
              When enabled, BUM traffic from wireless clients is
              flooded across the fabric to ensure proper connectivity
              and service discovery. When disabled, BUM traffic
              flooding is suppressed, which can improve network
              efficiency but may impact certain network services
              that rely on broadcast or multicast communication.
              If there is an associated layer 3 virtual network,
              wireless flooding will default to false and can only
              be set to true when fabric-enabled wireless is also
              enabled. If there is no associated layer 3 virtual
              network, wireless flooding will match the
              fabric-enabled wireless setting.
            type: bool
          resource_guard_enable:
            description: A security feature control for anycast gateways
              that enables or disables Resource Guard functionality.
              Resource Guard is a security mechanism that provides
              protection against unauthorized access to network resources
              by implementing additional security controls and access
              restrictions at the VLAN level within the fabric network.
              When enabled, it enhances the security posture of the
              anycast gateway by enforcing stricter access policies and
              monitoring capabilities.
              This field is not applicable to INFRA_VN.
            type: bool
            default: false
          ip_directed_broadcast:
            description: Indicates whether IP directed
              broadcasts are allowed. By default, it
              is set to false. This field is not applicable
              to INFRA_VN, layer2_flooding_enabled should
              be enabled for turning on ip directed
              broadcasts.
            type: bool
            default: false
          intra_subnet_routing_enabled:
            description: Specifies whether routing is
              enabled within the subnet. By default,
              this field is set to false. This field
              is not applicable to INFRA_VN. Updating
              this field is not allowed.
            type: bool
            default: false
          multiple_ip_to_mac_addresses:
            description: Indicates whether multiple
              IPs can be associated with a single MAC
              address. By default, it is set to false.
              This field is not applicable to INFRA_VN.
            type: bool
            default: false
          supplicant_based_extended_node_onboarding:
            description: Specifies whether supplicant-based
              onboarding for extended nodes is enabled.
              By default, this field is set to false.
              This field is applicable only to INFRA_VN
              requests and must not be null when 'pool_type'
              is EXTENDED_NODE.
            type: bool
            default: false
          group_policy_enforcement_enabled:
            description: Indicates whether group policy
              enforcement is enabled in the fabric.
              By default, it is set to false.
            type: bool
            default: false
          auto_generate_vlan_name:
            description: Specifies whether the VLAN
              name should be auto-generated. If 'is_critical_pool'
              is set to true, then this field must also
              be set to true. If 'auto_generate_vlan_name'
              is set to true, then 'vlan_name' and 'vlan_id'
              will be autogenerated by Catalyst Center,
              even if 'vlan_name' or 'vlan_id' is provided
              in the playbook.
            type: bool
requirements:
  - dnacentersdk >= 2.9.2
  - python >= 3.9
notes:
  - To ensure the module operates correctly for scaled
    sets,
    which involve creating,
    updating,
    or deleting
    Layer2 fabric VLANs and Layer3 virtual networks,
    as well as configuring anycast gateways,
    valid input
    in the playbook is required. If any failures are
    encountered,
    the module will halt execution without
    proceeding to further operations.
  - To delete the Fabric VLAN on the fabric site,
    if
    any fabric zones exist within that site,
    the Fabric
    VLAN must be deleted from the fabric zones first.
    Only after all Fabric VLANs are deleted from the
    fabric zones will the parent fabric site with VLAN
    be available for deletion.
  - For Layer 3 virtual networks,
    all Anycast Gateways
    associated with the given virtual network must be
    deleted first before the deletion operation for
    the virtual network is enabled.
  - All newly created Layer3 Virtual Networks must either
    be assigned to one or more Fabric Sites,
    or they
    all must not be assigned to any Fabric Sites.
  - To create or update a fabric VLAN according to the
    module design,
    the vlan_id parameter must be provided
    as a required input. Although in the GUI it's an
    optional parameter but to uniquely identify the
    VLAN,
    vlan is required along with the fabric site
    location.
  - If the playbook specifies fabric sites while deleting
    a virtual network,
    the module will operate at a
    lower level by removing only the fabric sites from
    the virtual network without deleting the virtual
    network itself. However,
    if only the virtual network
    name is provided,
    the module will first remove all
    associated fabric sites before proceeding with the
    deletion of the virtual network.
  - SDK Method used are
    ccc_virtual_network.sda.get_site
    ccc_virtual_network.sda.get_fabric_sites ccc_virtual_network.sda.get_fabric_zones
    ccc_virtual_network.sda.get_layer2_virtual_networks
    ccc_virtual_network.sda.add_layer2_virtual_networks
    ccc_virtual_network.sda.update_layer2_virtual_networks
    ccc_virtual_network.sda.delete_layer2_virtual_network_by_id
    ccc_virtual_network.sda.get_layer3_virtual_networks
    ccc_virtual_network.sda.add_layer3_virtual_networks
    ccc_virtual_network.sda.update_layer3_virtual_networks
    ccc_virtual_network.sda.delete_layer3_virtual_network_by_id
    ccc_virtual_network.sda.get_reserve_ip_subpool ccc_virtual_network.sda.get_anycast_gateways
    ccc_virtual_network.sda.add_anycast_gateways ccc_virtual_network.sda.update_anycast_gateways
    ccc_virtual_network.sda.delete_anycast_gateway_by_id
  - New parameters added in the module are
    wireless_flooding_enable, resource_guard_enable,
    flooding_address_assignment, flooding_address
    as part of fabric_vlan and anycast_gateways creation/updation
    will start supporting from Catalsyt Center
    with version 3.1.3.0 onwards.
"""
EXAMPLES = r"""
---
- name: Create Layer2 Fabric VLAN for SDA in Cisco Catalyst
    Center.
  cisco.dnac.sda_fabric_virtual_networks_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - fabric_vlan:
          - vlan_name: "vlan_test1"
            fabric_site_locations:
              - site_name_hierarchy: "Global/India"
                fabric_type: "fabric_site"
              - site_name_hierarchy: "Global/India/Chennai"
                fabric_type: "fabric_zone"
            vlan_id: 1333
            traffic_type: "DATA"
            fabric_enabled_wireless: false
          - vlan_name: "vlan_test2"
            fabric_site_locations:
              - site_name_hierarchy: "Global/USA"
                fabric_type: "fabric_site"
            vlan_id: 1334
            traffic_type: "VOICE"
            fabric_enabled_wireless: false

- name: Create Layer2 Fabric VLAN with wireless flooding, resource guard, and custom
    L2 flooding address for SDA in Cisco Catalyst Center.
  cisco.dnac.sda_fabric_virtual_networks_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - fabric_vlan:
          - vlan_name: "vlan_added_params"
            fabric_site_locations:
              - site_name_hierarchy: "Global/India/Bangalore"
                fabric_type: "fabric_site"
            vlan_id: 1933
            traffic_type: "VOICE"
            fabric_enabled_wireless: true
            wireless_flooding_enable: true
            resource_guard_enable: true
            flooding_address_assignment: CUSTOM
            flooding_address: 239.0.0.1

- name: Update Layer 2 Voice VLAN in Bangalore site to use shared flooding address assignment.
  cisco.dnac.sda_fabric_virtual_networks_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - fabric_vlan:
          - vlan_name: "vlan_added_params"
            fabric_site_locations:
              - site_name_hierarchy: "Global/India/Bangalore"
                fabric_type: "fabric_site"
            vlan_id: 1933
            traffic_type: "VOICE"
            fabric_enabled_wireless: true
            resource_guard_enable: true
            flooding_address_assignment: SHARED# Inherit flooding address from the fabric

- name: Update Layer 2 Fabric VLAN for SDA in Cisco
    Catalyst Center.
  cisco.dnac.sda_fabric_virtual_networks_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - fabric_vlan:
          - vlan_name: "vlan_test1"
            fabric_site_locations:
              - site_name_hierarchy: "Global/India"
                fabric_type: "fabric_site"
              - site_name_hierarchy: "Global/India/Chennai"
                fabric_type: "fabric_zone"
            vlan_id: 1333
            traffic_type: "VOICE"
            fabric_enabled_wireless: true

- name: Deleting Layer 2 Fabric VLAN from the Cisco
    Catalyst Center.
  cisco.dnac.sda_fabric_virtual_networks_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: deleted
    config:
      - fabric_vlan:
          - vlan_name: "vlan_test1"
            fabric_site_locations:
              - site_name_hierarchy: "Global/India/Chennai"
                fabric_type: "fabric_zone"
            vlan_id: 1333

- name: Create layer3 Virtual Network and anchored the
    site to the VN as well.
  cisco.dnac.sda_fabric_virtual_networks_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - virtual_networks:
          - vn_name: "vn_with_anchor"
            fabric_site_locations:
              - site_name_hierarchy: "Global/India"
                fabric_type: "fabric_site"
            anchored_site_name: "Global/India"

- name: Create layer3 Virtual Network and extend it
    to multiple fabric sites.
  cisco.dnac.sda_fabric_virtual_networks_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - virtual_networks:
          - vn_name: "vn_test"
            fabric_site_locations:
              - site_name_hierarchy: "Global/India"
                fabric_type: "fabric_site"
              - site_name_hierarchy: "Global/USA"
                fabric_type: "fabric_site"

- name: Update layer3 Virtual Network in the Cisco Catalyst
    Center.
  cisco.dnac.sda_fabric_virtual_networks_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - virtual_networks:
          - vn_name: "vn_test"
            fabric_site_locations:
              - site_name_hierarchy: "Global/India"
                fabric_type: "fabric_site"
              - site_name_hierarchy: "Global/USA"
                fabric_type: "fabric_site"
              - site_name_hierarchy: "Global/China"
                fabric_type: "fabric_site"

- name: Removing the fabric sites only from the given
    Virtual Network in the Cisco Catalyst Center.
  cisco.dnac.sda_fabric_virtual_networks_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: deleted
    config:
      - virtual_networks:
          - vn_name: "vn_test"
            fabric_site_locations:
              - site_name_hierarchy: "Global/India"
                fabric_type: "fabric_site"
              - site_name_hierarchy: "Global/USA"
                fabric_type: "fabric_site"

- name: Deleting Virtual Network from the Cisco Catalyst
    Center and removing fabric sites if any.
  cisco.dnac.sda_fabric_virtual_networks_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: deleted
    config:
      - virtual_networks:
          - vn_name: "vlan_test1"

- name: Create the Anycast gateway(s) for SDA in Catalsyt
    Center.
  cisco.dnac.sda_fabric_virtual_networks_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - anycast_gateways:
          - vn_name: "VN_Anycast"
            fabric_site_location:
              site_name_hierarchy: "Global/India"
              fabric_type: "fabric_site"
            ip_pool_name: "IP_Pool_1"
            tcp_mss_adjustment: 580
            traffic_type: "DATA"
            is_critical_pool: false
            auto_generate_vlan_name: true

- name: Create Anycast gateway in SDA fabric with new parameters
    (wireless flooding, resource guard, custom flooding address)
    in Cisco Catalyst Center
  cisco.dnac.sda_fabric_virtual_networks_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - anycast_gateways:
          - vn_name: VN_Test
            fabric_site_location:
              site_name_hierarchy: Global/India
              fabric_type: fabric_site
            ip_pool_name: AB_Pool
            tcp_mss_adjustment: 701
            traffic_type: DATA
            is_critical_pool: false
            layer2_flooding_enabled: true
            fabric_enabled_wireless: true
            wireless_flooding_enable: true
            resource_guard_enable: false
            ip_directed_broadcast: false
            intra_subnet_routing_enabled: false
            multiple_ip_to_mac_addresses: false
            supplicant_based_extended_node_onboarding: false
            group_policy_enforcement_enabled: true
            flooding_address_assignment: CUSTOM
            flooding_address: 239.0.0.1
            auto_generate_vlan_name: true

- name: Update Anycast gateway with shared flooding address
    and resource guard enabled in Cisco Catalyst Center.
  cisco.dnac.sda_fabric_virtual_networks_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - anycast_gateways:
          - vn_name: VN_Test
            fabric_site_location:
              site_name_hierarchy: Global/India
              fabric_type: fabric_site
            ip_pool_name: AB_Pool
            flooding_address_assignment: SHARED
            resource_guard_enable: true

- name: Update the Anycast gateway(s) for SDA in Catalsyt
    Center.
  cisco.dnac.sda_fabric_virtual_networks_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: merged
    config:
      - anycast_gateways:
          - vn_name: "VN_India"
            fabric_site_location:
              site_name_hierarchy: "Global/India"
              fabric_type: "fabric_site"
            ip_pool_name: "Reserve_Ip_Abhi_pool"
            tcp_mss_adjustment: 590
            traffic_type: "DATA"
            is_critical_pool: false
            layer2_flooding_enabled: false
            multiple_ip_to_mac_addresses: false

- name: Deleting Anycast Gateway from the Cisco Catalyst
    Center.
  cisco.dnac.sda_fabric_virtual_networks_workflow_manager:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: false
    state: deleted
    config:
      - anycast_gateways:
          - vn_name: "vlan_test1"
            fabric_site_location:
              site_name_hierarchy: "Global/India"
              fabric_type: "fabric_site"
            ip_pool_name: "IP_Pool_1"
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)
import copy
import re


class VirtualNetwork(DnacBase):
    """Class containing member attributes for fabric sites and zones workflow manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.deleted_anycast_gateways, self.absent_anycast_gateways = [], []
        self.removed_vn_sites = []
        self.created_fabric_vlans = []
        self.updated_fabric_vlans = []
        self.no_update_fabric_vlans = []

        self.created_virtual_networks = []
        self.updated_virtual_networks = []
        self.no_update_virtual_networks = []

        self.created_anycast_gateways = []
        self.updated_anycast_gateways = []
        self.no_update_anycast_gateways = []

        self.deleted_fabric_vlans = []
        self.absent_fabric_vlans = []

        self.deleted_virtual_networks = []
        self.absent_virtual_networks = []

        self.deleted_anycast_gateways = []
        self.absent_anycast_gateways = []

    def validate_input(self):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.
        Parameters:
            self: The instance of the class containing the 'config' attribute to be validated.
        Returns:
            The method returns an instance of the class with updated attributes:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation (either 'success' or 'failed').
                - self.validated_config: If successful, a validated version of the 'config' parameter.
        Example:
            To use this method, create an instance of the class and call 'validate_input' on it.
            If the validation succeeds, 'self.status' will be 'success' and 'self.validated_config'
            will contain the validated configuration. If it fails, 'self.status' will be 'failed', and
            'self.msg' will describe the validation issues.
        """

        temp_spec = {
            "fabric_vlan": {
                "type": "list",
                "elements": "dict",
                "vlan_name": {"type": "str"},
                "vlan_id": {"type": "int"},
                "traffic_type": {"type": "str"},
                "fabric_enabled_wireless": {"type": "bool"},
                "associated_layer3_virtual_network": {"type": "str"},
                "fabric_site_locations": {
                    "type": "list",
                    "elements": "dict",
                    "site_name_hierarchy": {"type": "str"},
                    "fabric_type": {"type": "str"},
                },
                "wireless_flooding_enable": {"type": "bool", "default": False},
                "resource_guard_enable": {"type": "bool"},
                "flooding_address_assignment": {"type": "str"},
                "flooding_address": {"type": "str"},
            },
            "virtual_networks": {
                "type": "list",
                "elements": "dict",
                "vn_name": {"type": "str"},
                "anchored_site_name": {"type": "str"},
                "fabric_site_locations": {
                    "type": "list",
                    "elements": "dict",
                    "site_name_hierarchy": {"type": "str"},
                    "fabric_type": {"type": "str"},
                },
            },
            "anycast_gateways": {
                "type": "list",
                "elements": "dict",
                "vn_name": {"type": "str"},
                "fabric_site_location": {
                    "type": "dict",
                    "site_name_hierarchy": {"type": "str"},
                    "fabric_type": {"type": "str"},
                },
                "ip_pool_name": {"type": "str"},
                "tcp_mss_adjustment": {"type": "int"},
                "vlan_name": {"type": "str"},
                "vlan_id": {"type": "int"},
                "traffic_type": {"type": "str"},
                "pool_type": {"type": "str"},
                "security_group_name": {"type": "str"},
                "is_critical_pool": {"type": "bool"},
                "layer2_flooding_enabled": {"type": "bool"},
                "flooding_address_assignment": {"type": "str"},
                "flooding_address": {"type": "str"},
                "fabric_enabled_wireless": {"type": "bool"},
                "wireless_flooding_enable": {"type": "bool"},
                "resource_guard_enable": {"type": "bool"},
                "ip_directed_broadcast": {"type": "bool"},
                "intra_subnet_routing_enabled": {"type": "bool"},
                "multiple_ip_to_mac_addresses": {"type": "bool"},
                "supplicant_based_extended_node_onboarding": {"type": "bool"},
                "group_policy_enforcement_enabled": {"type": "bool"},
                "auto_generate_vlan_name": {"type": "bool"},
            },
        }

        # Validate device params
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)

        if invalid_params:
            self.msg = "The playbook contains invalid parameters: {0}".format(
                invalid_params
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook configuration parameters using 'validate_input': {0}".format(
            str(valid_temp)
        )
        self.log(self.msg, "INFO")
        self.status = "success"

        return self

    def fetch_site_id_from_fabric_id(self, fabric_id, site_name):
        """
        Fetches the site id corresponding to a given fabric ID in Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            fabric_id (str): The ID of the fabric for which the site id needs to be retrieved.
            site_name (str): Name of the fabric site for which the site id needs to be retrieved.
        Description:
            - Attempts to fetch the site id from the fabric site using the provided fabric ID.
            - If the fabric site lookup fails, it checks if the ID belongs to a fabric zone.
            - Logs messages at different stages for debugging and error handling.
            - Uses `execute_get_request` to retrieve fabric site and fabric zone details.
            - If an error occurs, it logs the error message and sets the operation result accordingly.
        Returns:
            str or None: The retrieved site id if found, otherwise None.
        """

        site_id = None
        self.log(
            "Starting retrieval of site id from fabric site: '{0}'.".format(site_name),
            "DEBUG",
        )

        try:
            params = {"id": fabric_id}
            self.log(
                "Calling 'get_fabric_sites' API with params: {0}".format(params),
                "DEBUG",
            )
            response = self.execute_get_request("sda", "get_fabric_sites", params)

            if not response or not response.get("response"):
                self.log = (
                    "Failed to retrieve site details for fabric site '{0}' from fabric sites. "
                    "Checking if it belongs to a fabric zone.".format(site_name),
                    "INFO",
                )
                try:
                    self.log(
                        "Calling 'get_fabric_zones' API with params: {0}".format(
                            params
                        ),
                        "DEBUG",
                    )
                    response = self.execute_get_request(
                        "sda", "get_fabric_zones", params
                    )
                    if not response or not response.get("response"):
                        self.log = (
                            "Failed to retrieve site details for fabric zone '{0}' having fabric id {1}.".format(
                                site_name, fabric_id
                            ),
                            "INFO",
                        )
                except Exception as e:
                    self.msg = """Error while fetching the site id from fabric zone '{0}' present in
                            Cisco Catalyst Center: {1}""".format(
                        site_name, str(e)
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

            response = response.get("response")
            if not response:
                self.log = (
                    "Failed to retrieve site details for fabric zone '{0}' having fabric id {1}.".format(
                        site_name, fabric_id
                    ),
                    "INFO",
                )
                return site_id

            site_id = response[0].get("siteId")
            self.log(
                "Successfully retrieved site id '{0}' for given fabric site '{1}'.".format(
                    site_id, site_name
                ),
                "DEBUG",
            )

        except Exception as e:
            self.msg = """Error while fetching the site id with given fabric site '{0}' having fabric id '{1}' present in
                    Cisco Catalyst Center: {2}""".format(
                site_name, fabric_id, str(e)
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        return site_id

    def get_fabric_site_id(self, site_name, site_id):
        """
        Retrieves the fabric site id for a given site in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site_name (str): The name of the site whose fabric ID is being retrieved.
            site_id (str): The unique identifier of the site in Cisco Catalyst Center.
        Returns:
            str or None: The fabric site id if the site is a fabric site, or `None` if it is not found.
        Description:
            This function interacts with the Cisco Catalyst Center API to check if a site is part of the fabric network.
            It uses the site id to query the `get_fabric_sites` API, and if the site exists within the fabric, its fabric
            site id is returned. If the site is not part of the fabric or an error occurs, the function logs an appropriate
            message and returns `None`.
            In case of an exception during the API call, the function logs the error, updates the status to "failed", and
            triggers a check for return status.
        """

        fabric_site_id = None
        self.log(
            "Starting retrieval of fabric site id for site '{0}' with ID '{1}'.".format(
                site_name, site_id
            ),
            "DEBUG",
        )

        try:
            response = self.dnac._exec(
                family="sda",
                function="get_fabric_sites",
                op_modifies=False,
                params={"site_id": site_id},
            )
            response = response.get("response")
            self.log(
                "Received API response from 'get_fabric_sites' for the site '{0}': {1}".format(
                    site_name, str(response)
                ),
                "DEBUG",
            )

            if not response:
                self.log(
                    "Given site '{0}' is not a fabric site in Cisco Catalyst Center.".format(
                        site_name
                    ),
                    "INFO",
                )
                return fabric_site_id

            fabric_site_id = response[0].get("id")
            self.log(
                "Successfully retrieved fabric site id '{0}' for site '{1}'.".format(
                    fabric_site_id, site_name
                ),
                "DEBUG",
            )
        except Exception as e:
            self.msg = """Error while getting the details of Site with given name '{0}' present in
                    Cisco Catalyst Center: {1}""".format(
                site_name, str(e)
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        return fabric_site_id

    def get_fabric_zone_id(self, site_name, site_id):
        """
        Retrieves the fabric zone ID for a given site in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site_name (str): The name of the site whose fabric zone ID is being retrieved.
            site_id (str): The unique identifier of the site in Cisco Catalyst Center.
        Returns:
            str or None: The fabric zone ID if the site is a fabric zone, or `None` if it is not found.
        Description:
            This function queries Cisco Catalyst Center's API to determine whether a site is part of a fabric zone.
            It sends a request to the `get_fabric_zones` API using the provided site id. If the site is part of a fabric
            zone, the corresponding zone ID is returned. If the site is not a fabric zone or no response is received,
            the function logs an informational message and returns `None`.
            If an error occurs during the API call, the function logs the error, sets the status to "failed", and performs
            error handling through `check_return_status`.
        """

        fabric_zone_id = None
        self.log(
            "Starting retrieval of fabric zone ID for site '{0}' with ID '{1}'.".format(
                site_name, site_id
            ),
            "DEBUG",
        )

        try:
            response = self.dnac._exec(
                family="sda",
                function="get_fabric_zones",
                op_modifies=False,
                params={"site_id": site_id},
            )
            self.log(
                "Received API response from 'get_fabric_zones' for the site '{0}': {1}".format(
                    site_name, str(response)
                ),
                "DEBUG",
            )
            if not response:
                self.log(
                    "Given site '{0}' is not a fabric zone in Cisco Catalyst Center.".format(
                        site_name
                    ),
                    "INFO",
                )
                return fabric_zone_id

            response = response.get("response")
            if not response:
                self.log(
                    "Given site '{0}' is not a fabric zone in Cisco Catalyst Center.".format(
                        site_name
                    ),
                    "INFO",
                )
                return fabric_zone_id

            fabric_zone_id = response[0].get("id")
            self.log(
                "Successfully retrieved fabric zone ID '{0}' for site '{1}'.".format(
                    fabric_zone_id, site_name
                ),
                "DEBUG",
            )

        except Exception as e:
            self.msg = """Error while getting the details of fabric zone '{0}' present in
                    Cisco Catalyst Center: {1}""".format(
                site_name, str(e)
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        return fabric_zone_id

    def is_valid_vn_name(self, vn_name):
        """
        Validates the format of a layer3 Virtual Network name for SDA (Software-Defined Access) operations.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            vn_name (str): The virtual network name to validate.
        Returns:
            bool: Returns true if the given Virtual Network name validates against the regex otherwise return false.
        Description:
            This function checks whether the provided virtual network name follows a specific pattern using a regular
            expression. The VN name must consist of only letters, numbers, and underscores, and must be between 1-16
            characters in length. If the VN name is valid, it logs an informational message and returns the instance.
            If invalid, the function sets the status to "failed", logs a warning, and stores the error message in the
            result dictionary.
        """

        self.log(
            "Starting validation for virtual network name '{0}'.".format(vn_name),
            "DEBUG",
        )
        # Regex pattern for virtual network name having only letters numbers and underscores with 1-16 character long.
        pattern = r"^[a-zA-Z0-9_]{1,16}$"
        if re.match(pattern, vn_name):
            return True

        return False

    def is_valid_fabric_vlan_name(self, vlan_name):
        """
        Validates the format of a fabric VLAN name for SDA (Software-Defined Access) operations.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            vlan_name (str): The fabric VLAN name to validate.
        Returns:
            bool: Returns true if the given fabric VLAN name validates against the regex otherwise return false.
        Description:
            This function checks whether the provided fabric VLAN name follows a specific pattern using a regular
            expression. The VLAN name must consist of alphanumeric characters, underscores, and hyphens, and be
            between 1-32 characters in length. If the VLAN name is valid, it logs an informational message and
            returns the instance. If the VLAN name is invalid, the function sets the status to "failed", logs a
            warning, and stores the error message in the result dictionary.
        """

        self.log(
            "Starting validation for fabric VLAN name '{0}'.".format(vlan_name), "DEBUG"
        )
        # Regex pattern for fabric vlan name having alphanumeric characters, underscores and hyphens with 1-32 character long.
        vlan_name_pattern = r"^[a-zA-Z0-9_-]{1,32}$"
        if re.match(vlan_name_pattern, vlan_name):
            return True

        return False

    def validate_fabric_type(self, fabric_type):
        """
        Validates the fabric type provided for SDA (Software-Defined Access) operations.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            fabric_type (str): The fabric type to validate. It must be either "fabric_site" or "fabric_zone".
        Returns:
            self (object): Returns the instance of the class. If an invalid fabric type is provided, it updates the status to
            "failed", logs an error message, and adds the failure response to the result dictionary.
        Description:
            This function checks if the given `fabric_type` is one of the allowed values: "fabric_site" or "fabric_zone".
            If the `fabric_type` is valid, the function does nothing and simply returns the class instance. If the
            `fabric_type` is invalid, it sets the status to "failed", logs an error, and updates the result dictionary
            with an appropriate error message.
        """

        self.log(
            "Starting validation for fabric type '{0}'.".format(fabric_type), "DEBUG"
        )
        if fabric_type not in ["fabric_site", "fabric_zone"]:
            self.msg = (
                "Invalid fabric_type '{0}' parameter given in the playbook. Please provide one of the following "
                "fabric types: ['fabric_site', 'fabric_zone']."
            ).format(fabric_type)
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def collect_fabric_vlan_ids(self, vlan_name, vlan_id):
        """
        Collects fabric VLAN IDs for a given VLAN in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            vlan_name (str): The name of the VLAN whose fabric VLAN IDs are to be collected.
            vlan_id (str): The unique identifier of the VLAN in Cisco Catalyst Center.
        Returns:
            list: A list of VLAN IDs associated with the given VLAN. Returns an empty list if no VLANs are found or if
            an error occurs.
        Description:
            This function interacts with the Cisco Catalyst Center API to retrieve fabric VLAN IDs for a specified VLAN.
            It queries the `get_layer2_virtual_networks` API using the provided VLAN ID. If VLAN data is found, it collects
            the corresponding VLAN IDs into a list and returns them. If the VLAN is not present or an error occurs during
            the API call, the function logs an appropriate message, updates the status to "failed" if necessary, and returns
            an empty list.
        """

        vlan_ids = []
        try:
            self.log(
                "Starting to collect fabric VLAN IDs for VLAN '{0}' with ID '{1}'.".format(
                    vlan_name, vlan_id
                ),
                "DEBUG",
            )
            response = self.dnac._exec(
                family="sda",
                function="get_layer2_virtual_networks",
                op_modifies=False,
                params={"vlan_id": vlan_id},
            )
            response = response.get("response")
            self.log(
                "Received API response from 'get_layer2_virtual_networks' for the VLAN '{0}': {1}".format(
                    vlan_name, str(response)
                ),
                "DEBUG",
            )

            if not response:
                self.log(
                    "Given layer2 fabric VLAN '{0}' is not present in Cisco Catalyst Center.".format(
                        vlan_name
                    ),
                    "INFO",
                )
                return vlan_ids

            for vlan_vn in response:
                vlan_id_value = vlan_vn.get("id")
                vlan_ids.append(vlan_id_value)
                self.log(
                    "Collected VLAN ID '{0}' for VLAN '{1}'.".format(
                        vlan_id_value, vlan_name
                    ),
                    "DEBUG",
                )

            self.log(
                "Finished collecting fabric VLAN IDs for VLAN '{0}'. Collected IDs: {1}".format(
                    vlan_name, vlan_ids
                ),
                "DEBUG",
            )

        except Exception as e:
            self.msg = (
                "Error while getting the details for layer2 fabric VLAN '{0}' present in "
                "Cisco Catalyst Center: {1}"
            ).format(vlan_name, str(e))
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        return vlan_ids

    def get_fabric_vlan_details(self, vlan_name, vlan_id, fabric_id):
        """
        Retrieves the details of a fabric VLAN from the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            vlan_name (str): The name of the VLAN whose details are to be retrieved.
            vlan_id (str): The unique identifier of the VLAN in Cisco Catalyst Center.
            fabric_id (str): The unique identifier of the fabric in which the VLAN resides.
        Returns:
            dict or None: A dictionary containing the details of the VLAN if found. Returns `None` if the VLAN does not
            exist or an error occurs during the API call.
        Description:
            This function queries Cisco Catalyst Center's API to fetch details about a specified fabric VLAN using the
            provided `vlan_id` and `fabric_id`. If the VLAN is not found or an exception occurs, the function logs an
            appropriate message, sets the status to "failed" if needed, and returns `None`.
        """

        try:
            self.log(
                "Fetching details for VLAN '{0}' with ID '{1}' in fabric '{2}'.".format(
                    vlan_name, vlan_id, fabric_id
                ),
                "DEBUG",
            )
            response = self.dnac._exec(
                family="sda",
                function="get_layer2_virtual_networks",
                op_modifies=False,
                params={"vlan_id": vlan_id, "fabric_id": fabric_id},
            )
            response = response.get("response")
            self.log(
                "Received API response from 'get_layer2_virtual_networks' for VLAN '{0}': {1}".format(
                    vlan_name, str(response)
                ),
                "DEBUG",
            )

            if not response:
                self.log(
                    "Given layer2 VLAN '{0}' is not present in Cisco Catalyst Center.".format(
                        vlan_name
                    ),
                    "INFO",
                )
                return None

            self.log(
                "Returning details for VLAN '{0}': {1}".format(vlan_name, response[0]),
                "DEBUG",
            )

        except Exception as e:
            self.msg = (
                "Error while getting the details for layer2 VLAN '{0}' present in "
                "Cisco Catalyst Center: {1}"
            ).format(vlan_name, str(e))
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        return response[0]

    def validate_traffic_type(self, traffic_type):
        """
        Validates the traffic type provided for SDA (Software-Defined Access) operations.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            traffic_type (str): The traffic type to validate. Allowed values are "DATA" or "VOICE".
        Returns:
            self (object): Returns the instance of class. If invalid traffic type is provided, function sets the
            status to "failed", logs an error message, and adds the failure response to the result dictionary.
        Description:
            This function checks if the provided `traffic_type` is one of the allowed values: "DATA" or "VOICE".
            If valid, it logs a success message and returns the class instance. If the `traffic_type` is invalid,
            the function sets the status to "failed", logs an error message, and updates the result dictionary
            with the error information.
        """

        allowed_types = ["DATA", "VOICE"]

        if traffic_type not in allowed_types:
            self.msg = (
                "Invalid traffic_type '{0}' given in the playbook. Allowed values are: {1}."
            ).format(traffic_type, allowed_types)
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        self.log(
            "Parameter traffic_type '{0}' given in the playbook validated successfully.".format(
                traffic_type
            ),
            "INFO",
        )

        return self

    def create_payload_for_fabric_vlan(self, vlan, fabric_id_list):
        """
        Creates a list of payloads for configuring fabric VLANs in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            vlan (dict): A dictionary containing VLAN details, including:
                - vlan_name (str): The name of the VLAN.
                - vlan_id (int): The identifier of the VLAN.
                - traffic_type (str): The type of traffic, either "DATA" or "VOICE". Defaults to "DATA".
                - fabric_enabled_wireless (bool): Whether fabric-enabled wireless is enabled for the VLAN.
                - associated_layer3_virtual_network (str): The associated Layer 3 virtual network name.
                - wireless_flooding_enable (bool, optional): Whether wireless flooding is enabled.
                - resource_guard_enable (bool, optional): Whether resource guard is enabled.
                - flooding_address_assignment (str, optional): How the flooding address is assigned
                  ("SHARED" or "CUSTOM").
                - flooding_address (str, optional): The custom flooding address, if assignment is "CUSTOM".
            fabric_id_list (list): A list of fabric IDs where the VLAN configuration will be applied.
        Returns:
            list: A list of dictionaries, each containing the payload required to create or configure the VLAN
            on each fabric in the `fabric_id_list`.
        Description:
            This function generates a payload for configuring a fabric VLAN in Cisco Catalyst Center.
            For each fabric ID in the `fabric_id_list`, it creates a deep copy of the base payload, adds the fabric ID,
            and appends the result to the payload list. The function returns the list of payloads, one for each fabric ID.
        """

        self.log(
            "Creating fabric VLAN payloads for VLAN '{vlan_name}' across {count} fabric(s)".format(
                vlan_name=vlan.get("vlan_name"), count=len(fabric_id_list)
            ),
            "DEBUG",
        )
        create_vlan_payload_list = []
        traffic_type = vlan.get("traffic_type", "DATA").upper()
        # Validate the given traffic type for Vlan/VN/Anycast configuration.
        self.validate_traffic_type(traffic_type)

        vlan_payload = {
            "vlanName": vlan.get("vlan_name"),
            "vlanId": vlan.get("vlan_id"),
            "trafficType": traffic_type,
            "isFabricEnabledWireless": vlan.get("fabric_enabled_wireless", False),
            "associatedLayer3VirtualNetworkName": vlan.get(
                "associated_layer3_virtual_network"
            ),
        }

        if self.compare_dnac_versions(self.get_ccc_version(), "3.1.3.0") >= 0:
            self.log(
                "Using new payload structure for fabric VLAN creation in Cisco Catalyst Center.",
                "DEBUG",
            )
            vlan_payload["isWirelessFloodingEnabled"] = vlan.get(
                "wireless_flooding_enable", False
            )
            vlan_payload["isResourceGuardEnabled"] = vlan.get(
                "resource_guard_enable", False
            )
            vlan_payload["layer2FloodingAddressAssignment"] = vlan.get(
                "flooding_address_assignment", "SHARED"
            )
            if vlan_payload["layer2FloodingAddressAssignment"] == "CUSTOM":
                vlan_payload["layer2FloodingAddress"] = vlan.get(
                    "flooding_address", None
                )

        self.log(
            "Creating payloads for VLAN '{0}' with ID '{1}' across fabric IDs: {2}".format(
                vlan_payload["vlanName"], vlan_payload["vlanId"], fabric_id_list
            ),
            "DEBUG",
        )

        for fabric_id in fabric_id_list:
            deep_payload_dict = copy.deepcopy(vlan_payload)
            deep_payload_dict["fabricId"] = fabric_id
            create_vlan_payload_list.append(deep_payload_dict)
            del deep_payload_dict

        self.log(
            "Successfully created {count} payloads for VLAN '{vlan_name}'.".format(
                count=len(create_vlan_payload_list), vlan_name=vlan.get("vlan_name")
            ),
            "DEBUG",
        )

        return create_vlan_payload_list

    def create_fabric_vlan(self, vlan_payloads):
        """
        Creates fabric VLAN(s) in Cisco Catalyst Center using the provided payload.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            vlan_payloads (dict): The payload containing the details for the VLAN(s) to be created.
        Returns:
            self (object): Returns the instance of the class. If the creation process fails at any point, the instance's
                status is set to "failed" and the failure response is added to the result dictionary.
        Description:
            This function interacts with the Cisco Catalyst Center API to create one or more fabric VLANs. It sends a
            request to the `add_layer2_virtual_networks` API with the provided payload. If the task completes successfully,
            an message is logged. If the task fails, the function logs the reason for failure, updating the
            class status accordingly.
        """

        req_limit = self.params.get("sda_fabric_vlan_limit", 20)
        self.log(
            "API request batch size set to '{0}' for fabric VLAN creation.".format(
                req_limit
            ),
            "DEBUG",
        )

        for i in range(0, len(vlan_payloads), req_limit):
            fabric_vlan_payload = vlan_payloads[i : i + req_limit]
            fabric_vlan_details = self.created_fabric_vlans[i : i + req_limit]

            try:
                payload = {"payload": fabric_vlan_payload}
                task_name = "add_layer2_virtual_networks"
                task_id = self.get_taskid_post_api_call("sda", task_name, payload)

                if not task_id:
                    self.msg = "Failed to retrieve task ID for task '{0}'. Payload: '{1}'".format(
                        task_name, payload
                    )
                    self.msg = (
                        "Unable to retrieve the task_id for the task '{0}'.".format(
                            task_name
                        )
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                success_msg = "Layer2 Fabric VLAN(s) '{0}' created successfully in the Cisco Catalyst Center.".format(
                    fabric_vlan_details
                )
                self.log(success_msg, "DEBUG")
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()

            except Exception as e:
                self.msg = (
                    "An exception occured while creating the layer2 VLAN(s) '{0}' in the Cisco Catalyst "
                    "Center: {1}"
                ).format(self.fabric_vlan_details, str(e))
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

        return self

    def fabric_vlan_needs_update(self, desired_vlan_config, current_vlan_config):
        """
        Determines if a fabric VLAN needs to be updated based on the provided configuration.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            desired_vlan_config (dict): A dictionary containing the desired VLAN configuration, which may include:
                - traffic_type (str): The type of traffic for the VLAN (e.g., "DATA", "VOICE").
                - fabric_enabled_wireless (bool): Indicates if fabric-enabled wireless is enabled.
                - wireless_flooding_enable (bool): Indicates if wireless flooding is enabled.
                - resource_guard_enable (bool): Indicates if resource guard is enabled.
                - flooding_address_assignment (str): The assignment method for the flooding address
                  ('SHARED' or 'CUSTOM').
                - flooding_address (str): The custom flooding IP address.
            current_vlan_config (dict): A dictionary representing the current VLAN configuration from Catalyst Center.
        Returns:
            bool: Returns `True` if the VLAN needs to be updated and `False` otherwise.
        Description:
            This function compares the desired VLAN configuration provided in the `desired_vlan_config` dictionary
            with the current configuration stored in `current_vlan_config`. If either parameter requires an update,
            function returns `true`. If both parameters match the current configuration, it returns `false`.
        """

        self.log(
            "Comparing desired VLAN config '{desired}' with current config '{current}' to determine if an"
            " update is needed.".format(
                desired=desired_vlan_config.get("vlan_name"),
                current=current_vlan_config.get("vlanName"),
            ),
            "DEBUG",
        )
        desired_traffic_type = desired_vlan_config.get("traffic_type")
        current_traffic_type = current_vlan_config.get("trafficType")

        if desired_traffic_type and desired_traffic_type.upper() != current_traffic_type:
            self.log(
                "Traffic type needs update: desired='{0}', current='{1}'".format(
                    desired_traffic_type, current_traffic_type
                ),
                "DEBUG",
            )
            return True

        desired_enabled_wireless = desired_vlan_config.get("fabric_enabled_wireless")
        current_enabled_wireless = current_vlan_config.get("isFabricEnabledWireless")

        if (
            desired_enabled_wireless is not None
            and desired_enabled_wireless != current_enabled_wireless
        ):
            self.log(
                "Fabric Enable Wireless needs to be updated in the Cisco Catalyst Center.",
                "INFO",
            )
            return True

        if (
            desired_enabled_wireless is not None
            and desired_enabled_wireless != current_enabled_wireless
        ):
            self.log(
                "Fabric-enabled wireless setting needs update: desired='{0}', current='{1}'".format(
                    desired_enabled_wireless, current_enabled_wireless
                ),
                "DEBUG",
            )
            return True

        if self.compare_dnac_versions(self.get_ccc_version(), "3.1.3.0") >= 0:
            self.log(
                "Using new payload structure for fabric VLAN configuration in Cisco Catalyst Center.",
                "DEBUG",
            )
            wireless_flooding_enable = desired_vlan_config.get("wireless_flooding_enable")
            if (
                wireless_flooding_enable is not None
                and wireless_flooding_enable != current_vlan_config.get(
                    "isWirelessFloodingEnabled"
                )
            ):
                self.log(
                    "Wireless flooding setting needs update: desired='{0}', current='{1}'".format(
                        wireless_flooding_enable,
                        current_vlan_config.get("isWirelessFloodingEnabled"),
                    ),
                    "DEBUG",
                )
                return True

            resource_guard_enable = desired_vlan_config.get("resource_guard_enable")
            if (
                resource_guard_enable is not None
                and resource_guard_enable != current_vlan_config.get(
                    "isResourceGuardEnabled"
                )
            ):
                self.log(
                    "Resource guard setting needs update: desired='{0}', current='{1}'".format(
                        resource_guard_enable,
                        current_vlan_config.get("isResourceGuardEnabled"),
                    ),
                    "DEBUG",
                )
                return True

            flooding_address_assignment = desired_vlan_config.get(
                "flooding_address_assignment"
            )
            if flooding_address_assignment and flooding_address_assignment != current_vlan_config.get(
                "layer2FloodingAddressAssignment"
            ):
                self.log(
                    "Flooding address assignment needs update: desired='{0}', current='{1}'".format(
                        flooding_address_assignment,
                        current_vlan_config.get("layer2FloodingAddressAssignment"),
                    ),
                    "DEBUG",
                )
                return True

            flooding_address = desired_vlan_config.get("flooding_address")
            address_assignment = flooding_address_assignment or current_vlan_config.get(
                "layer2FloodingAddressAssignment"
            )
            if (
                flooding_address and address_assignment == "CUSTOM"
                and flooding_address != current_vlan_config.get("layer2FloodingAddress")
            ):
                self.log(
                    "Flooding address needs update: desired='{0}', current='{1}'".format(
                        flooding_address,
                        current_vlan_config.get("layer2FloodingAddress"),
                    ),
                    "DEBUG",
                )
                return True

        self.log("No updates required for the fabric VLAN configuration.", "DEBUG")

        return False

    def update_payload_fabric_vlan(
        self, new_vlan_config, current_vlan_config, fabric_id
    ):
        """
        Constructs an update payload for a fabric VLAN based on the provided configuration.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            new_vlan_config (dict): A dictionary containing the new VLAN configuration.
            current_vlan_config (dict): A dictionary representing the current VLAN configuration in Cisco Catalyst Center.
            fabric_id (str): The unique identifier of the fabric to which the VLAN belongs.
        Returns:
            dict: A dictionary containing the payload needed to update the fabric VLAN configuration, including the
                relevant identifiers and configuration details.
        Description:
            This function constructs a payload for updating a fabric VLAN in Cisco Catalyst Center. The resulting payload
            is structured to include the VLAN ID, fabric ID, traffic type, wireless enablement status, and associated
            Layer3 virtual network name and used to submit an update request to the Cisco Catalyst Center API.
        """
        self.log(
            "Constructing update payload for VLAN '{vlan_name}' on fabric '{fabric_id}'.".format(
                vlan_name=new_vlan_config.get("vlan_name"), fabric_id=fabric_id
            ),
            "DEBUG",
        )
        traffic_type = new_vlan_config.get("traffic_type")
        if traffic_type:
            traffic_type = traffic_type.upper()
            # Validate the given traffic type for Vlan/VN/Anycast configuration.
            self.validate_traffic_type(traffic_type)
        else:
            self.log(
                "Parameter 'traffic_type' is not given in the playbook so taking it from current vlan config.",
                "INFO",
            )
            traffic_type = current_vlan_config.get("trafficType")

        wireless_enabled = new_vlan_config.get("fabric_enabled_wireless")
        if wireless_enabled is None:
            wireless_enabled = current_vlan_config.get("isFabricEnabledWireless")

        vlan_update_payload = {
            "id": current_vlan_config.get("id"),
            "fabricId": fabric_id,
            "vlanName": new_vlan_config.get("vlan_name"),
            "vlanId": new_vlan_config.get("vlan_id"),
            "trafficType": traffic_type,
            "isFabricEnabledWireless": wireless_enabled,
            "associatedLayer3VirtualNetworkName": current_vlan_config.get(
                "associatedLayer3VirtualNetworkName"
            ),
        }

        if vlan_update_payload.get("associatedLayer3VirtualNetworkName"):
            vlan_update_payload["isWirelessFloodingEnabled"] = False
            self.log(
                "Associated Layer3 Virtual Network is set, disabling wireless flooding for VLAN '{0}'.".format(
                    vlan_update_payload["vlanName"]
                ),
                "DEBUG",
            )

        if self.compare_dnac_versions(self.get_ccc_version(), "3.1.3.0") >= 0:
            self.log(
                "Using new payload structure for fabric VLAN update in Cisco Catalyst Center.",
                "DEBUG",
            )
            wireless_flooding_enable = new_vlan_config.get("wireless_flooding_enable")
            if wireless_flooding_enable is None:
                self.log(
                    "Parameter 'wireless_flooding_enable' not provided; using current value from Catalyst Center.",
                    "DEBUG",
                )
                wireless_flooding_enable = current_vlan_config.get(
                    "isWirelessFloodingEnabled"
                )

            resource_guard_enable = new_vlan_config.get("resource_guard_enable")
            if resource_guard_enable is None:
                self.log(
                    "Parameter 'resource_guard_enable' not provided; using current value from Catalyst Center.",
                    "DEBUG",
                )
                resource_guard_enable = current_vlan_config.get("isResourceGuardEnabled")

            flooding_address_assignment = new_vlan_config.get(
                "flooding_address_assignment"
            )
            if flooding_address_assignment is None:
                self.log(
                    "Parameter 'flooding_address_assignment' not provided; using current value from Catalyst Center.",
                    "DEBUG",
                )
                flooding_address_assignment = current_vlan_config.get(
                    "layer2FloodingAddressAssignment"
                )

            vlan_update_payload["isResourceGuardEnabled"] = resource_guard_enable
            vlan_update_payload["layer2FloodingAddressAssignment"] = flooding_address_assignment

            if flooding_address_assignment == "CUSTOM":
                self.log(
                    "Using 'CUSTOM' flooding address assignment for the VLAN update payload.",
                    "DEBUG",
                )
                flooding_address = new_vlan_config.get("flooding_address")
                if flooding_address is None:
                    self.log(
                        "Parameter 'flooding_address' not provided; using current value from Catalyst Center.",
                        "DEBUG",
                    )
                    flooding_address = current_vlan_config.get("layer2FloodingAddress")
                vlan_update_payload["layer2FloodingAddress"] = flooding_address

            if vlan_update_payload["associatedLayer3VirtualNetworkName"]:
                fabric_enable_wireless = new_vlan_config.get("fabric_enabled_wireless")
                self.log(
                    "Evaluating wireless flooding settings - wireless_enabled: {0}, "
                    "fabric_enable_wireless: {1}".format(
                        wireless_enabled, fabric_enable_wireless
                    ),
                    "DEBUG"
                )
                if wireless_enabled and wireless_enabled is True:
                    vlan_update_payload["isWirelessFloodingEnabled"] = wireless_flooding_enable
                elif fabric_enable_wireless and fabric_enable_wireless is False:
                    vlan_update_payload["isWirelessFloodingEnabled"] = False

                self.log(
                    "Constructed update payload for fabric VLAN with associated Layer3 VN: {0}".format(
                        vlan_update_payload
                    ),
                    "DEBUG",
                )

                return vlan_update_payload

            vlan_update_payload["isWirelessFloodingEnabled"] = vlan_update_payload["isFabricEnabledWireless"]

        self.log(
            "Constructed update payload for fabric VLAN: {0}".format(
                vlan_update_payload
            ),
            "DEBUG",
        )

        return vlan_update_payload

    def update_fabric_vlan(self, update_vlan_payload):
        """
        Updates the fabric VLAN(s) in Cisco Catalyst Center using the provided payload.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            update_vlan_payload (dict): A dictionary containing the details required to update the fabric VLAN(s).
        Returns:
            self (object): Returns the instance of the class. If the update process fails at any point, the instance's
                status is set to "failed" and the failure response is added to the result dictionary.
        Description:
            This function interacts with the Cisco Catalyst Center API to update one or more fabric VLANs. It sends
            request to the `update_layer2_virtual_networks` API with the provided payload. If the task completes
            successfully, an informational message is logged. If the task fails, the function logs the reason for
            failure, updating the class status accordingly.
            In case of exceptions during the process, the function captures the error, logs an appropriate message,
            and sets the status to "failed".
        """

        req_limit = self.params.get("sda_fabric_vlan_limit", 20)
        self.log(
            "API request batch size set to '{0}' for fabric VLAN updation.".format(
                req_limit
            ),
            "DEBUG",
        )

        for i in range(0, len(update_vlan_payload), req_limit):
            vlan_payload = update_vlan_payload[i : i + req_limit]
            fabric_vlan_details = self.created_fabric_vlans[i : i + req_limit]

            try:
                payload = {"payload": vlan_payload}
                task_name = "update_layer2_virtual_networks"
                task_id = self.get_taskid_post_api_call("sda", task_name, payload)

                if not task_id:
                    self.msg = (
                        "Unable to retrieve the task_id for the task '{0}'.".format(
                            task_name
                        )
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                success_msg = "Layer2 Fabric VLAN(s) '{0}' updated successfully in the Cisco Catalyst Center.".format(
                    fabric_vlan_details
                )
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()

            except Exception as e:
                self.msg = (
                    "An exception occured while updating the layer2 fabric VLAN(s) '{0}' in the Cisco Catalyst "
                    "Center: {1}"
                ).format(fabric_vlan_details, str(e))
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

        return self

    def delete_layer2_fabric_vlan(self, vlan_vn_id, vlan_name_with_id_and_site):
        """
        Deletes a Layer2 fabric VLAN in Cisco Catalyst Center based on the provided VLAN ID.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            vlan_vn_id (str): The unique identifier of the Fabric VLAN to be deleted.
            vlan_name_with_id_and_site (str): Uniquely identify the name of vlan with it's VLAN id and
                to the site(s) it is assoicated with
        Returns:
            self (object): Returns the instance of the class. If the deletion process fails at any point, the
                instance's status is set to "failed" and the failure response is added to result dictionary.
        Description:
            This function interacts with the Cisco Catalyst Center API to delete a specified Layer 2 fabric VLAN.
            If the task completes successfully, an informational message is logged and VLAN name is appended to
            the list of deleted VLANs. If the task fails, the function logs the reason for failure, updating the
            class status accordingly.
            In case of exceptions during the process, the function captures the error, logs an appropriate message,
            and sets the status to "failed".
        """

        try:
            payload = {"id": vlan_vn_id}
            task_name = "delete_layer2_virtual_network_by_id"
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "Fabric VLAN '{0}' deleted successfully from the Cisco Catalyst Center.".format(
                vlan_name_with_id_and_site
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
            self.deleted_fabric_vlans.append(vlan_name_with_id_and_site)

        except Exception as e:
            self.msg = "Exception occurred while deleting the fabric Vlan '{0}' due to: {1}".format(
                vlan_name_with_id_and_site, str(e)
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def is_virtual_network_exist(self, vn_name):
        """
        Checks if a specified Layer3 Virtual Network exists in the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            vn_name (str): The name of the Virtual Network to check for existence.
        Returns:
            bool: Returns True if the virtual network exists, False if it does not.
        Description:
            This function interacts with the Cisco Catalyst Center API to determine the existence of a
            specified Layer3 Virtual Network by querying the `get_layer3_virtual_networks` endpoint.
            If the function successfully retrieves a response, it will return True, indicating the
            virtual network exists.
        """

        try:
            response = self.dnac._exec(
                family="sda",
                function="get_layer3_virtual_networks",
                op_modifies=False,
                params={
                    "virtual_network_name": vn_name,
                },
            )
            response = response.get("response")
            self.log(
                "Received API response from 'get_layer3_virtual_networks' for vn '{0}': {1}".format(
                    vn_name, str(response)
                ),
                "DEBUG",
            )

            if not response:
                self.log(
                    "Given layer3 Virtual Network '{0}' is not present in Cisco Catalyst Center.".format(
                        vn_name
                    ),
                    "INFO",
                )
                return False

        except Exception as e:
            self.msg = (
                "Error while getting the details for layer3 virtual network '{0}' present in "
                "Cisco Catalyst Center: {1}"
            ).format(vn_name, str(e))
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        return True

    def get_fabric_ids(self, fabric_locations):
        """
        Retrieves a list of fabric IDs based on the specified fabric locations.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            fabric_locations (list): A list of dictionaries, each containing information about fabric locations.
                including "site_name_hierarchy" and "fabric_type". The "fabric_type" can either be "fabric_site" or
                "fabric_zone".
        Returns:
            list: A list of fabric IDs corresponding to the specified fabric locations. If a fabric ID cannot
                be retrieved for a location, a warning is logged, and the function continues to the next location.
        Description:
            This function processes a list of fabric locations to extract fabric IDs. For each location, it
            validates the fabric type and retrieves the corresponding site id. Depending on the fabric type, it
            calls either `get_fabric_site_id` or `get_fabric_zone_id` to obtain the fabric ID.
            If the site is not recognized as a fabric site or zone, a warning message is logged, and that
            location is skipped. The resulting list of fabric IDs is returned.
        """

        fabric_id_list = []

        for fabric in fabric_locations:
            site_name = fabric.get("site_name_hierarchy")
            fabric_type = fabric.get("fabric_type", "fabric_site")
            # Validate the correct fabric_type given in the playbook
            self.validate_fabric_type(fabric_type).check_return_status()
            self.log("Fabric type '{0}' is valid.".format(fabric_type), "INFO")
            site_exists, site_id = self.get_site_id(site_name)

            if fabric_type == "fabric_site":
                fabric_id = self.get_fabric_site_id(site_name, site_id)
            else:
                fabric_id = self.get_fabric_zone_id(site_name, site_id)

            if not fabric_id:
                self.log(
                    "Unable to retrieve the Fabric ID for site '{0}' as it is not a recognized fabric "
                    "site/zone.".format(site_name),
                    "WARNING",
                )
                continue
            self.log(
                "Site: '{0}' - Fabric ID: '{1}'".format(site_name, fabric_id), "DEBUG"
            )
            fabric_id_list.append(fabric_id)

        return fabric_id_list

    def create_vn_payload(self, vn_detail):
        """
        Constructs a payload for a Virtual Network based on the provided details.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            vn_detail (dict): A dictionary containing the details required to create the virtual network.
        Returns:
            dict: A dictionary representing the virtual network payload. This includes -
                - "virtualNetworkName": The name of the virtual network.
                - "fabricIds" (optional): A list of fabric IDs associated with the fabric locations, if applicable.
                - "anchoredSiteId" (optional): The ID of the anchored site, if it exists.
        Description:
            This function generates a payload necessary for creating a virtual network in the Cisco Catalyst Center.
            Additionally, if an anchored site name is provided, the function attempts to retrieve the associated
            site id. If the site id is found, it fetches the corresponding fabric ID for the anchored site.
            The constructed payload, containing the virtual network name and optionally the fabric IDs and anchored
            site id, is then returned for further use.
        """

        fabric_locations = vn_detail.get("fabric_site_locations")
        vn_name = vn_detail.get("vn_name")
        self.log("Creating payload for Virtual Network '{0}'.".format(vn_name), "DEBUG")
        vn_payload = {
            "virtualNetworkName": vn_name,
        }

        if fabric_locations:
            self.log(
                "Retrieving fabric IDs for locations: {0}".format(fabric_locations),
                "DEBUG",
            )
            fabric_ids = self.get_fabric_ids(fabric_locations)

            if fabric_ids:
                vn_payload["fabricIds"] = fabric_ids
                self.log("Fabric IDs retrieved: {0}".format(fabric_ids), "DEBUG")
            else:
                self.log("No fabric IDs found for the provided locations.", "WARNING")

        site_name = vn_detail.get("anchored_site_name")
        if site_name:
            self.log("Checking for anchored site '{0}'.".format(site_name), "DEBUG")
            site_exists, site_id = self.get_site_id(site_name)

            if not site_exists:
                msg = "Given Anchor site '{0}' not  present in Cisco Catalyst Center.".format(
                    site_name
                )
                self.log(msg, "ERROR")
                return vn_payload
            try:
                self.log(
                    "Anchored site id found for '{0}': {1}".format(site_name, site_id),
                    "DEBUG",
                )
                anchor_fabric_id = self.get_fabric_site_id(site_name, site_id)
            except Exception as e:
                anchor_fabric_id = self.get_fabric_zone_id(site_name, site_id)
                self.log(
                    "Fabric zone ID retrieved for anchored site '{0}': {1}".format(
                        site_name, anchor_fabric_id
                    ),
                    "DEBUG",
                )

            if anchor_fabric_id:
                vn_payload["anchoredSiteId"] = anchor_fabric_id
                self.log(
                    "Anchored fabric ID added to payload: {0}".format(anchor_fabric_id),
                    "DEBUG",
                )

        self.log("Payload created successfully: {0}".format(vn_payload), "INFO")

        return vn_payload

    def get_vn_details_from_ccc(self, vn_name):
        """
        Retrieves details of a specified Layer3 Virtual Network from the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            vn_name (str): The name of the Layer3 Virtual Network whose details are to be fetched.
        Returns:
            dict or None: A dictionary containing the details of the specified virtual network if found;
                        otherwise, returns None.
        Description:
            This function queries the Cisco Catalyst Center API to obtain information about a Layer3
            Virtual Network identified by the provided name.
            If the response does not contain any data, it logs an informational message indicating that the
            specified virtual network is not present.
            The function returns the details of the virtual network as a dictionary, or None if the network
            does not exist or if an error occurs during the retrieval process.
        """

        try:
            response = self.dnac._exec(
                family="sda",
                function="get_layer3_virtual_networks",
                op_modifies=False,
                params={
                    "virtual_network_name": vn_name,
                },
            )
            response = response.get("response")
            self.log(
                "Received API response from 'get_layer3_virtual_networks' for the vn '{0}': {1}".format(
                    vn_name, str(response)
                ),
                "DEBUG",
            )

            if not response:
                self.log(
                    "Given layer3 virtual network '{0}' is not present in Cisco Catalyst Center.".format(
                        vn_name
                    ),
                    "INFO",
                )
                return None

        except Exception as e:
            self.msg = (
                "Error while getting the details for layer3 virtual network '{0}' present in "
                "Cisco Catalyst Center: {1}"
            ).format(vn_name, str(e))
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()
            self.log(
                "Details retrieved successfully for Layer3 virtual network '{0}': {1}".format(
                    vn_name, response[0]
                ),
                "INFO",
            )

        return response[0]

    def create_vn_and_assign_to_fabric_site(self, item):
        """
        Creates a Layer3 Virtual Network (VN) and assigns it to a specified fabric site in the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            item (dict): A dictionary containing details required for creating and assigning the virtual network.
        Returns:
            self (object): The current instance of the class, updated with operation results.
        Description:
            This method constructs the payload for creating a Layer3 Virtual Network and anchoring it to a fabric site.
            It triggers the appropriate Cisco Catalyst Center API call to create the virtual network and monitor the
            operation's status. Upon success, a confirmation message is logged with details of the created virtual network.
        """

        try:
            vn_name = item.get("virtualNetworkName")
            self.log(
                "Starting Layer3 Virtual Network creation: '{0}'".format(vn_name),
                "DEBUG",
            )
            anchored_vn_payload = []
            payload_dict = {
                "virtualNetworkName": vn_name,
                "fabricIds": [item.get("anchoredSiteId")],
            }
            anchored_vn_payload.append(payload_dict)
            payload = {"payload": anchored_vn_payload}
            self.log(
                "Constructed payload for VN creation: {0}".format(payload), "DEBUG"
            )
            task_name = "add_layer3_virtual_networks"
            self.log(
                "Triggering '{0}' API call with payload.".format(task_name), "DEBUG"
            )
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)

            if not task_id:
                self.msg = (
                    "Failed to retrieve task ID for '{0}'. VN creation aborted.".format(
                        task_name
                    )
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            self.log(
                "Received task ID: {0}. Monitoring task status.".format(task_id),
                "DEBUG",
            )
            success_msg = "Layer3 Virtual Network '{0}' created successfully in the Cisco Catalyst Center.".format(
                vn_name
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        except Exception as e:
            self.msg = (
                "An exception occured while creating and anchoring the layer3 Virtual Network(s) '{0}' in the Cisco Catalyst "
                "Center: {1}"
            ).format(vn_name, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def update_vn_anchored_to_fabric_site(self, item):
        """
        Updates a layer3 Virtual Network (VN) and anchors it to a specified fabric site in the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            item (dict): A dictionary containing details required for updating and anchoring the virtual network.
        Returns:
            self (object): The current instance of the class, updated with operation results.
        Description:
            This method retrieves the details of an existing layer3 Virtual Network from the Cisco Catalyst Center
            and updates its configuration to anchor it to a specified fabric site. The method constructs the
            required payload and triggers the appropriate API call to perform the update. It then monitors the
            operation's task status and logs the result.
            If the task ID for the operation cannot be retrieved or an exception occurs during the process,
            the operation is marked as failed, and an error message is logged. Upon successful completion, a
            confirmation message is logged with details of the updated virtual network.
        """

        try:
            vn_name = item.get("virtualNetworkName")
            self.log(
                "Starting update process for Layer3 Virtual Network: '{0}'.".format(
                    vn_name
                ),
                "DEBUG",
            )
            self.log(
                "Fetching VN details from Cisco Catalyst Center for: '{0}'.".format(
                    vn_name
                ),
                "DEBUG",
            )
            vn_in_ccc = self.get_vn_details_from_ccc(vn_name)
            anchored_vn_payload = []
            payload_dict = {
                "id": vn_in_ccc.get("id"),
                "virtualNetworkName": vn_name,
                "anchoredSiteId": item.get("anchoredSiteId"),
                "fabricIds": [item.get("anchoredSiteId")],
            }
            anchored_vn_payload.append(payload_dict)
            payload = {"payload": anchored_vn_payload}
            self.log("Constructed payload for VN update: {0}".format(payload), "DEBUG")
            task_name = "update_layer3_virtual_networks"
            self.log(
                "Triggering '{0}' API call with payload.".format(task_name), "DEBUG"
            )
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            self.log(
                "Received task ID: {0}. Monitoring task status.".format(task_id),
                "DEBUG",
            )
            success_msg = "Layer3 Virtual Network(s) '{0}' updated and anchored successfully in the Cisco Catalyst Center.".format(
                vn_name
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        except Exception as e:
            self.msg = (
                "An exception occured while creating and anchoring the layer3 Virtual Network(s) '{0}' in the Cisco Catalyst "
                "Center: {1}"
            ).format(vn_name, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def extend_vn_to_fabric_sites(self, item):
        """
        Extends a Layer3 Virtual Network (VN) to additional fabric sites in the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            item (dict): A dictionary containing details required for extending the virtual network to new fabric sites.
        Returns:
            self (object): The current instance of the class, updated with operation results.
        Description:
            This method retrieves the details of an existing layer3 Virtual Network from the Cisco Catalyst Center
            and updates its configuration to extend the network to additional fabric sites. The method constructs
            the required payload and triggers the appropriate API call to perform the extension. It then monitors
            the operation's task status and logs the result.
            If the task ID for the operation cannot be retrieved or an exception occurs during the process,
            the operation is marked as failed, and an error message is logged. Upon successful completion, a
            confirmation message is logged with details of the extended virtual network.
        """

        try:
            vn_name = item.get("virtualNetworkName")
            self.log(
                "Starting extension of Layer3 Virtual Network: '{0}'.".format(vn_name),
                "DEBUG",
            )
            self.log(
                "Fetching VN details from Cisco Catalyst Center for: '{0}'.".format(
                    vn_name
                ),
                "DEBUG",
            )
            vn_in_ccc = self.get_vn_details_from_ccc(vn_name)
            self.log("Removing the anchored site id from the fabricIds list.", "DEBUG")
            extend_vn_payload = []
            payload_dict = {
                "id": vn_in_ccc.get("id"),
                "virtualNetworkName": vn_name,
                "fabricIds": item.get("fabricIds"),
                "anchoredSiteId": item.get("anchoredSiteId"),
            }
            extend_vn_payload.append(payload_dict)
            payload = {"payload": extend_vn_payload}
            self.log(
                "Constructed payload for VN extension: {0}".format(payload), "DEBUG"
            )
            task_name = "update_layer3_virtual_networks"
            self.log(
                "Triggering '{0}' API call with payload.".format(task_name), "DEBUG"
            )
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)

            if not task_id:
                self.msg = "Failed to retrieve task ID for '{0}'. VN extension aborted.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            self.log(
                "Received task ID: {0}. Monitoring task status.".format(task_id),
                "DEBUG",
            )
            success_msg = "Layer3 Virtual Network(s) '{0}' extended successfully in the Cisco Catalyst Center.".format(
                vn_name
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        except Exception as e:
            self.msg = (
                "An exception occured while extending the layer3 Virtual Network(s) '{0}' in the Cisco Catalyst "
                "Center: {1}"
            ).format(vn_name, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def create_virtual_networks(self, add_vn_payloads):
        """
        Creates Layer3 Virtual Networks in the Cisco Catalyst Center using the provided payload.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            add_vn_payloads (dict): A dictionary containing the details required to create
                                            the Layer3 Virtual Networks.
        Returns:
            self (object): The instance of the class with updated status and result attributes reflecting
                        the outcome of the virtual network creation operation.
        Description:
            This function sends a request to the Cisco Catalyst Center API to create Layer3 virtual
            networks based on the information provided in the `add_vn_payloads`.
            If successful, it logs an informational message indicating the creation of the virtual networks.
            If the creation fails, it logs the failure reason if available; otherwise it logs generic failure message.
            In the case of any exceptions during the process, it logs the error and updates the status to "failed."
        """

        try:
            self.log(
                "Checking if the virtual network needs to be anchored to fabric site...",
                "DEBUG",
            )

            for item in add_vn_payloads:
                vn_name = item.get("virtualNetworkName")
                anchored_site_id = item.get("anchoredSiteId")
                if anchored_site_id:
                    self.log(
                        "Given virtual network '{0}' is supposed to be anchored the anchored VN.".format(
                            vn_name
                        ),
                        "INFO",
                    )
                    self.create_vn_and_assign_to_fabric_site(item).check_return_status()
                    self.log(
                        "Given virtual network '{0}' created successfully and assigned to site as well.",
                        "DEBUG",
                    )
                    self.log(
                        "Now virtual network '{0}' is ready for anchored to a fabric site.",
                        "DEBUG",
                    )
                    self.update_vn_anchored_to_fabric_site(item).check_return_status()
                    self.log(
                        "Virtual Network '{0}' marked as anchored successfully.".format(
                            vn_name
                        ),
                        "DEBUG",
                    )
                    if len(item.get("fabricIds")) > 1:
                        self.log(
                            "Virtual Network '{0}' needs to be extended to additional fabric sites.".format(
                                vn_name
                            ),
                            "INFO",
                        )
                        self.extend_vn_to_fabric_sites(item)

                    self.log(
                        "Remove the virtual network '{0}' details from the creation payload as it is already created.".format(
                            vn_name
                        ),
                        "DEBUG",
                    )
                    add_vn_payloads.remove(item)
                    self.log(
                        "Successfully removed '{0}' from add_vn_payloads.".format(
                            vn_name
                        ),
                        "DEBUG",
                    )

            if not add_vn_payloads:
                self.log(
                    "There are no more virtual networks to be created in the Cisco Catalyst Center.",
                    "INFO",
                )
                return self

            self.log(
                "Proceeding with creation of remaining Virtual Networks in Cisco Catalyst Center.",
                "INFO",
            )
            payload = {"payload": add_vn_payloads}
            self.log(
                "Constructed payload for VN creation: {0}".format(payload), "DEBUG"
            )
            task_name = "add_layer3_virtual_networks"
            self.log(
                "Triggering '{0}' API call with payload.".format(task_name), "DEBUG"
            )
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)

            if not task_id:
                self.msg = (
                    "Failed to retrieve task ID for '{0}'. VN creation aborted.".format(
                        task_name
                    )
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            self.log(
                "Received task ID: {0}. Monitoring task status.".format(task_id),
                "DEBUG",
            )
            success_msg = "Layer3 Virtual Network(s) '{0}' created successfully in the Cisco Catalyst Center.".format(
                self.created_virtual_networks
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        except Exception as e:
            self.msg = (
                "An exception occured while creating the layer3 Virtual Network(s) '{0}' in the Cisco Catalyst "
                "Center: {1}"
            ).format(self.created_virtual_networks, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def is_vn_needs_update(self, vn_details, vn_in_ccc):
        """
        Determines if a Virtual Network requires an update based on its details and current state in
        the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            vn_details (dict): A dictionary containing details about the virtual network, including:
                - vn_name (str): The name of the virtual network.
                - fabric_site_locations (list): A list of fabric site locations associated with the virtual network.
                - anchored_site_name (str): The name of the anchored site.
            vn_in_ccc (dict): A dictionary representing the current state of the virtual network in the Cisco
                            Catalyst Center, which includes:
                - fabricIds (list): A list of fabric IDs currently associated with the virtual network.
                - anchoredSiteId (str): The ID of the anchored site currently associated with the virtual network.
        Returns:
            bool: Returns `True` if the virtual network needs an update; otherwise, returns `False`.
        Description:
            This function checks if a virtual network needs to be updated by comparing its provided details
            with the existing configuration in the Cisco Catalyst Center.
            If all checks are passed without indicating an update, the function returns `False`.
        """

        vn_name = vn_details.get("vn_name")
        fabric_ids_in_ccc = vn_in_ccc.get("fabricIds")
        fabric_locations = vn_details.get("fabric_site_locations")

        if fabric_locations is None:
            self.log(
                "There are no fabric site details given in the playbook for the vn '{0}'.".format(
                    vn_name
                ),
                "INFO",
            )
            return False

        if not fabric_locations and fabric_ids_in_ccc:
            self.log(
                "Fabric locations not provided, but fabric IDs found for VN '{0}'.".format(
                    vn_name
                ),
                "INFO",
            )
            return True

        fabric_site_ids = self.get_fabric_ids(fabric_locations)
        if not fabric_site_ids:
            self.log(
                "Unable to get fabric site ids for the vn '{0}'.".format(vn_name),
                "INFO",
            )
            return False

        if not fabric_ids_in_ccc:
            self.log(
                "No fabric sites available in Cisco Catalyst Center for the VN '{0}'.".format(
                    vn_name
                ),
                "INFO",
            )
            return True

        for fabric_id in fabric_site_ids:
            if fabric_id not in fabric_ids_in_ccc:
                self.log(
                    "Fabric ID '{0}' from VN '{1}' is not present in Cisco Catalyst Center".format(
                        fabric_id, vn_name
                    ),
                    "INFO",
                )
                return True

        anchor_site = vn_details.get("anchored_site_name")
        if (
            anchor_site == ""
            and vn_in_ccc.get("anchoredSiteId") is not None
            and anchor_site != vn_in_ccc.get("anchoredSiteId")
        ):
            self.log(
                "Need to remove the anchor site for the VN '{0}' from Cisco Catalyst Center.".format(
                    vn_name
                ),
                "INFO",
            )
            return True

        if anchor_site:
            site_exists, site_id = self.get_site_id(anchor_site)

            if not site_exists:
                msg = "Given Anchor site '{0}' not  present in Cisco Catalyst Center.".format(
                    anchor_site
                )
                self.log(msg, "ERROR")
                return False
            try:
                anchor_fabric_id = self.get_fabric_site_id(anchor_site, site_id)
            except Exception as e:
                anchor_fabric_id = self.get_fabric_zone_id(anchor_site, site_id)

            if anchor_fabric_id and anchor_fabric_id != vn_in_ccc.get("anchoredSiteId"):
                anchor_site_id = vn_in_ccc.get("anchoredSiteId")
                self.log(
                    "Anchored site id has changed for VN '{0}': old {1}, new {2}.".format(
                        vn_name, anchor_site_id, anchor_fabric_id
                    ),
                    "INFO",
                )
                return True

        return False

    def update_payload_vn(self, vn_details, vn_in_ccc):
        """
        Constructs an update payload for a virtual network based on the provided details and its current
        configuration in the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            vn_details (dict): A dictionary containing details about VN to be updated, including:
                - vn_name (str): The name of the virtual network.
                - fabric_site_locations (list): A list of fabric site locations associated with virtual network.
                - anchored_site_name (str): The name of the anchored site.
            vn_in_ccc (dict): A dictionary representing the current state of the virtual network in the
                            Cisco Catalyst Center, which includes:
                - id (str): The identifier of the existing virtual network.
                - anchoredSiteId (str): The ID of anchored site currently associated with the virtual network.
        Returns:
            dict: A dictionary representing the payload for updating the virtual network.
        Description:
            This function constructs a payload for updating a virtual network by gathering relevant details
            from the provided `vn_details` and the current configuration in `vn_in_ccc`.
            The function returns the constructed update payload for the virtual network, which includes all
            necessary identifiers and configurations needed for the update operation.
        """

        vn_name = vn_details.get("vn_name")
        update_vn_payload = {"id": vn_in_ccc.get("id"), "virtualNetworkName": vn_name}
        fabric_locations = vn_details.get("fabric_site_locations")
        fabric_ids_in_ccc = vn_in_ccc.get("fabricIds", [])
        fabric_site_ids = self.get_fabric_ids(fabric_locations)

        for fabric_id in fabric_site_ids:
            if fabric_id not in fabric_ids_in_ccc:
                self.log(
                    "Given fabric site id {0} not present for the vn {1} so extending the given "
                    "fabric site in the Cisco Catalyst Center.".format(
                        fabric_id, vn_name
                    ),
                    "DEBUG",
                )
                fabric_ids_in_ccc.append(fabric_id)

            update_vn_payload["fabricIds"] = fabric_ids_in_ccc

        anchor_site = vn_details.get("anchored_site_name")
        if anchor_site == "":
            self.log(
                "Need to remove the anchorSiteId for the VN {0}.".format(vn_name),
                "DEBUG",
            )
            update_vn_payload["anchoredSiteId"] = ""
            return update_vn_payload

        if not anchor_site:
            current_anchored_site_id = vn_in_ccc.get("anchoredSiteId")

            if current_anchored_site_id:
                update_vn_payload["anchoredSiteId"] = current_anchored_site_id
            else:
                self.log(
                    "No anchored site provided for VN '{0}', and no current anchored site id "
                    "available.".format(vn_name),
                    "INFO",
                )

            return update_vn_payload

        site_exists, site_id = self.get_site_id(anchor_site)
        if not site_exists:
            self.log(
                "Anchor site '{0}' not found. Cannot update payload for VN '{1}'.".format(
                    anchor_site, vn_name
                ),
                "ERROR",
            )
            return update_vn_payload

        try:
            anchor_fabric_id = self.get_fabric_site_id(anchor_site, site_id)
        except Exception as e:
            anchor_fabric_id = self.get_fabric_zone_id(anchor_site, site_id)

        update_vn_payload["anchoredSiteId"] = anchor_fabric_id

        return update_vn_payload

    def update_virtual_networks(self, update_vn_payloads):
        """
        Updates Layer3 Virtual Networks in the Cisco Catalyst Center using the provided payload.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            update_vn_payloads (dict): A dictionary containing the payload for updating
                                                Layer3 Virtual Networks.
        Returns:
            self (object): The instance of the class, allowing for method chaining.
        Description:
            This function sends a request to the Cisco Catalyst Center to update Layer3 Virtual
            Networks using the provided payload.
            The function returns the instance of the class, allowing for further method calls on the
            same instance.
        """

        payload = {"payload": update_vn_payloads}
        task_name = "update_layer3_virtual_networks"

        try:
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "Layer3 Virtual Network(s) '{0}' updated successfully in the Cisco Catalyst Center.".format(
                self.updated_virtual_networks
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        except Exception as e:
            self.msg = (
                "An exception occured while updating the layer3 Virtual Network(s) '{0}' in "
                "the Cisco Catalyst Center: {1}"
            ).format(self.updated_virtual_networks, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def delete_layer3_virtual_network(self, vn_name, vn_id):
        """
        Deletes a Layer3 Virtual Network from the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            vn_name (str): The name of the virtual network to be deleted.
            vn_id (str): The identifier of the virtual network to be deleted.
        Returns:
            self (object): The instance of the class, allowing for method chaining.
        Description:
            This function sends a request to delete a Layer3 Virtual Network specified by the
            given virtual network ID. It executes the API call to the Cisco Catalyst Center
            and logs the response received.
            The function returns the instance of the class, enabling further method calls on the
            same instance.
        """

        payload = {"id": vn_id}
        task_name = "delete_layer3_virtual_network_by_id"

        try:
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "Layer3 Virtual Network '{0}' deleted successfully from the Cisco Catalyst Center.".format(
                vn_name
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
            self.deleted_virtual_networks.append(vn_name)

        except Exception as e:
            self.msg = "Exception occurred while deleting the layer3 Virtual Network '{0}' due to: {1}".format(
                vn_name, str(e)
            )
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        return self

    def is_ip_pool_exist(self, ip_pool_name, site_id):
        """
        Checks if a specified IP pool exists in the Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            ip_pool_name (str): The name of the IP pool to check for existence.
            site_id (str): The identifier of the site where the IP pool is located.
        Returns:
            bool: True if the IP pool exists, False otherwise.
        Description:
            This function sends a request to the Cisco Catalyst Center to retrieve information
            about a specific reserved IP subpool based on the provided IP pool name and site id.
            The primary purpose of this function is to facilitate validation of IP pool existence
            for network configurations or management tasks.
        """

        try:
            response = self.dnac._exec(
                family="network_settings",
                function="get_reserve_ip_subpool",
                op_modifies=True,
                params={"site_id": site_id, "group_name": ip_pool_name},
            )
            response = response.get("response")
            self.log(
                "Received API response from 'get_reserve_ip_subpool' for the IP Pool '{0}': {1}".format(
                    ip_pool_name, str(response)
                ),
                "DEBUG",
            )

            if not response:
                self.log(
                    "There is no reserve ip pool '{0}' present in the Cisco Catalyst Center system.".format(
                        ip_pool_name
                    ),
                    "INFO",
                )
                return False

            self.log(
                "IP Pool '{0}' exists in the Cisco Catalyst Center.".format(
                    ip_pool_name
                ),
                "INFO",
            )

        except Exception as e:
            self.msg = (
                "Error while getting the details for reserve IP Pool with name '{0}' present in "
                "Cisco Catalyst Center: {1}"
            ).format(ip_pool_name, str(e))
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        return True

    def get_anycast_gateway_details(self, vn_name, ip_pool_name, fabric_id):
        """
        Retrieves details of an Anycast Gateway for a specified virtual network and IP pool.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            vn_name (str): The name of the virtual network associated with the Anycast Gateway.
            ip_pool_name (str): The name of the IP pool for which the Anycast Gateway details are requested.
            fabric_id (str): The identifier of the fabric within which the IP pool is located.
        Returns:
            dict or None: Returns a dictionary containing the Anycast Gateway details if found,
                        or None if no details are available.
        Description:
            This function sends a request to the Cisco Catalyst Center to fetch the details
            of an Anycast Gateway related to the specified virtual network and IP pool.
            The function primarily serves to facilitate the management and configuration of
            Anycast Gateways in network environments, aiding in tasks related to IP addressing
            and routing.
        """

        try:
            response = self.dnac._exec(
                family="sda",
                function="get_anycast_gateways",
                op_modifies=False,
                params={
                    "fabric_id": fabric_id,
                    "ip_pool_name": ip_pool_name,
                    "virtual_network_name": vn_name,
                },
            )
            response = response.get("response")
            self.log(
                "Received API response from 'get_anycast_gateways' for the IP Pool '{0}': {1}".format(
                    ip_pool_name, str(response)
                ),
                "DEBUG",
            )
            if not response:
                unique_anycast = vn_name + "_" + ip_pool_name
                self.log(
                    "Gateway '{0}' is not present in the Cisco Catalyst Center.".format(
                        unique_anycast
                    ),
                    "INFO",
                )
                return None

            self.log(
                "Returning Anycast Gateway details for IP Pool '{0}': {1}".format(
                    ip_pool_name, str(response[0])
                ),
                "INFO",
            )

        except Exception as e:
            self.msg = (
                "Error while getting the details for reserve IP Pool with name '{0}' for the virtual network '{1}' present in "
                "Cisco Catalyst Center: {2}"
            ).format(ip_pool_name, vn_name, str(e))
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        return response[0]

    def validate_gateway_payload(self, anycast):
        """
        Validates the payload parameters for configuring an Anycast Gateway.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            anycast (dict): A dictionary containing configuration parameters for the Anycast Gateway.
        Returns:
            self (object): The instance of the class, which allows for method chaining or further handling
                based on the validation outcome.
        Description:
            This function checks the validity of several parameters specified in the provided
            `anycast` dictionary for configuring an Anycast Gateway.
            - It validates the `pool_type` to ensure it is either "EXTENDED_NODE" or "FABRIC_AP".
            If not valid, it logs an error message and sets the status to "failed".
            - The `tcp_mss_adjustment` is validated to be within the range of 500 to 1440.
            - The `traffic_type` is validated through a separate method `validate_traffic_type()`.
            - The `vlan_id` is checked to be within the range of 2 to 4094, excluding the reserved
                VLAN IDs 1002-1005 and 2046. An error message is logged, and the status is set to
                "failed" if the `vlan_id` is invalid.
            - The `flooding_address_assignment` is validated to be either "SHARED" or "CUSTOM".
            If all parameters are valid, a success message is logged indicating successful validation
            of the Anycast Gateway configuration parameters.
        """

        pool_type = anycast.get("pool_type")
        if pool_type and pool_type not in ["EXTENDED_NODE", "FABRIC_AP"]:
            self.msg = (
                "Invalid pool_type '{0}' parameter given in the playbook. Please provide one of the following "
                "pool_type ['EXTENDED_NODE', 'FABRIC_AP']."
            ).format(pool_type)
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        tcp_mss_adjustment = anycast.get("tcp_mss_adjustment")
        if tcp_mss_adjustment and tcp_mss_adjustment not in range(500, 1441):
            self.msg = (
                "Invalid tcp_mss_adjustment '{0}' given in the playbook. Allowed tcp_mss_adjustment range is (500,1440)."
            ).format(tcp_mss_adjustment)
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        traffic_type = anycast.get("traffic_type")
        if traffic_type:
            # Validate the given traffic type for Vlan/VN/Anycast configuration.
            self.validate_traffic_type(traffic_type.upper())

        vlan_id = anycast.get("vlan_id")
        if (
            vlan_id
            and vlan_id not in range(2, 4094)
            or vlan_id in [1002, 1003, 1004, 1005, 2046]
        ):
            self.msg = (
                "Invalid vlan_id '{0}' given in the playbook. Allowed VLAN range is (2,4094) except for "
                "reserved VLANs 1002-1005, and 2046."
            ).format(vlan_id)
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        if self.compare_dnac_versions(self.get_ccc_version(), "3.1.3.0") >= 0:
            self.log(
                "CCC version is 3.1.3 or above, validating additional parameters for Anycast Gateway.",
                "DEBUG",
            )
            flooding_address_assignment = anycast.get("flooding_address_assignment")
            if flooding_address_assignment and flooding_address_assignment not in [
                "SHARED",
                "CUSTOM",
            ]:
                self.msg = (
                    "Invalid flooding_address_assignment '{0}' given in the playbook. Allowed values are "
                    "'SHARED' or 'CUSTOM'."
                ).format(flooding_address_assignment)
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

        self.log(
            "Given parameters '{0}' for the configuration of anycast gateway validated successfully.".format(
                str(anycast)
            ),
            "INFO",
        )

        return self

    def get_anycast_gateway_mapping(self, vn_name):
        """
        Retrieves a mapping of Anycast Gateway configuration parameters from their common names
        to their respective API field names.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            vn_name (str): The name of the layer3 Virtual Network to check whether it's INFRA_VN or not
                and seperate the payload for the API for respective VN.
        Returns:
            dict: A dictionary where the keys are common parameter names used in configuration
                and the values are the corresponding field names used in the Anycast Gateway API.
        Description:
            This function creates and returns a mapping of various configuration parameters
            associated with Anycast Gateways. The mapping translates common, user-friendly names
            into the specific field names expected by the API.
        """

        gateway_mapping = {
            "tcp_mss_adjustment": "tcpMssAdjustment",
            "vlan_name": "vlanName",
            "vlan_id": "vlanId",
            "traffic_type": "trafficType",
            "pool_type": "poolType",
            "security_group_name": "securityGroupName",
            "is_critical_pool": "isCriticalPool",
            "layer2_flooding_enabled": "isLayer2FloodingEnabled",
            "fabric_enabled_wireless": "isWirelessPool",
            "ip_directed_broadcast": "isIpDirectedBroadcast",
            "intra_subnet_routing_enabled": "isIntraSubnetRoutingEnabled",
            "multiple_ip_to_mac_addresses": "isMultipleIpToMacAddresses",
            "supplicant_based_extended_node_onboarding": "isSupplicantBasedExtendedNodeOnboarding",
            "group_policy_enforcement_enabled": "isGroupBasedPolicyEnforcementEnabled",
            "flooding_address_assignment": "layer2FloodingAddressAssignment",
            "flooding_address": "layer2FloodingAddress",
            "wireless_flooding_enable": "isWirelessFloodingEnabled",
            "resource_guard_enable": "isResourceGuardEnabled"
        }

        if vn_name == "INFRA_VN":
            params_to_remove = [
                "is_critical_pool",
                "layer2_flooding_enabled",
                "fabric_enabled_wireless",
                "security_group_name",
                "ip_directed_broadcast",
                "intra_subnet_routing_enabled",
                "multiple_ip_to_mac_addresses",
                "flooding_address_assignment",
                "wireless_flooding_enable",
                "resource_guard_enable"
            ]

            for item in params_to_remove:
                gateway_mapping.pop(item, None)
                self.log(
                    "Removing parameter '{0}' from gateway mapping for INFRA_VN.".format(
                        item
                    ),
                    "DEBUG",
                )
        elif self.compare_dnac_versions(self.get_ccc_version(), "3.1.3.0") < 0:
            self.log(
                "CCC version is below 3.1.3, removing certain parameters from gateway mapping.",
                "DEBUG",
            )
            params_to_remove = [
                "flooding_address",
                "flooding_address_assignment",
                "wireless_flooding_enable",
                "resource_guard_enable"
            ]

            for item in params_to_remove:
                gateway_mapping.pop(item, None)
                self.log(
                    "Removing parameter '{0}' from gateway mapping for versions below 3.1.3.".format(
                        item
                    ),
                    "DEBUG",
                )

        self.log(
            "Final gateway mapping for '{0}': {1}".format(vn_name, gateway_mapping),
            "INFO",
        )

        return gateway_mapping

    def create_anycast_payload(self, anycast, fabric_id):
        """
        Constructs the payload for creating an Anycast Gateway configuration.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            anycast (dict): A dictionary containing Anycast Gateway configuration details.
            fabric_id (str): The identifier for the fabric associated with the Anycast Gateway.
        Returns:
            dict: A dictionary representing the Anycast Gateway payload, structured with the necessary
                parameters for API submission. This includes:
                - fabricId: The ID of the fabric.
                - virtualNetworkName: The name of the virtual network.
                - ipPoolName: The name of the IP pool.
                - trafficType: The type of traffic.
                - Additional parameters mapped from the Anycast configuration, with defaults set as needed.
        Description:
            This function creates a payload for the Anycast Gateway API based on the provided configuration
            details. It retrieves a mapping of parameters needed for the Anycast configuration and populates
            the payload with values from the `anycast` dictionary.
            This structured payload then be sent to the API to create/update Anycast Gateway configuration.
        """

        vn_name = anycast.get("vn_name")
        anycast_payload = {
            "fabricId": fabric_id,
            "virtualNetworkName": vn_name,
            "ipPoolName": anycast.get("ip_pool_name"),
            "trafficType": anycast.get("traffic_type", "DATA"),
        }
        anycast_mapping = self.get_anycast_gateway_mapping(vn_name)
        self.log(
            "Initial payload structure created: {0}".format(anycast_payload), "DEBUG"
        )

        if vn_name == "INFRA_VN":
            infra_enable_list = [
                "supplicant_based_extended_node_onboarding",
                "group_policy_enforcement_enabled",
            ]

            for key, value in anycast_mapping.items():
                playbook_param = anycast.get(key)
                if key == "pool_type":
                    anycast_payload[value] = anycast.get(key, "EXTENDED_NODE")
                    self.log(
                        "Setting pool_type in payload: '{0}'.".format(
                            anycast_payload[value]
                        ),
                        "DEBUG",
                    )
                    continue

                if playbook_param is not None:
                    anycast_payload[value] = playbook_param
                    self.log(
                        "Adding parameter '{0}' with value '{1}' to payload.".format(
                            key, playbook_param
                        ),
                        "DEBUG",
                    )
                elif playbook_param is None and key in infra_enable_list:
                    anycast_payload[value] = False
                    self.log(
                        "Setting '{0}' to False in payload for INFRA_VN.".format(key),
                        "DEBUG",
                    )
        else:
            params_enable_list = [
                "is_critical_pool",
                "layer2_flooding_enabled",
                "fabric_enabled_wireless",
                "ip_directed_broadcast",
                "intra_subnet_routing_enabled",
                "multiple_ip_to_mac_addresses",
            ]
            for key, value in anycast_mapping.items():
                playbook_param = anycast.get(key)

                if playbook_param is not None:
                    anycast_payload[value] = playbook_param
                    self.log(
                        "Adding parameter '{0}' with value '{1}' to payload.".format(
                            key, playbook_param
                        ),
                        "DEBUG",
                    )
                elif playbook_param is None and key in params_enable_list:
                    anycast_payload[value] = False
                    self.log("Setting '{0}' to False in payload.".format(key), "DEBUG")

            if self.compare_dnac_versions(self.get_ccc_version(), "3.1.3.0") >= 0:
                self.log(
                    "CCC version is 3.1.3 or above, checking additional parameters for Anycast Gateway.",
                    "DEBUG",
                )
                flooding_address_assignment = anycast_payload.get(
                    "layer2FloodingAddressAssignment"
                )
                flooding_address = anycast.get("flooding_address")
                if flooding_address and flooding_address_assignment == "CUSTOM":
                    anycast_payload["layer2FloodingAddress"] = flooding_address
                    self.log(
                        "Adding custom flooding address '{0}' to payload.".format(
                            flooding_address
                        ),
                        "DEBUG",
                    )

        if (
            anycast.get("auto_generate_vlan_name") is True
            or anycast_payload.get("isCriticalPool") is True
        ):
            anycast_payload.pop("vlanName", None)
            anycast_payload.pop("vlanId", None)
            anycast_payload["autoGenerateVlanName"] = True
            self.log(
                "Auto-generating VLAN name and removing vlanName and vlanId from payload.",
                "DEBUG",
            )
        else:
            vlan_id = anycast_payload.get("vlanId")
            if (
                vlan_id
                and vlan_id not in range(2, 4094)
                or vlan_id in [1002, 1003, 1004, 1005, 2046]
            ):
                self.msg = (
                    "Invalid vlan_id '{0}' given in the playbook. Allowed VLAN range is (2,4094) except for "
                    "reserved VLANs 1002-1005, and 2046."
                ).format(vlan_id)
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

        self.log("Final Anycast payload created: {0}".format(anycast_payload), "INFO")

        return anycast_payload

    def is_gateway_needs_update(self, anycast, anycast_details_in_ccc):
        """
        Checks if the Anycast Gateway configuration needs to be updated based on provided parameters.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            anycast (dict): A dictionary containing the current configuration parameters for the Anycast Gateway.
            anycast_details_in_ccc (dict): A dictionary containing the current Anycast Gateway configuration details
                                            from the Cisco Catalyst Center (CCC) to compare against.
        Returns:
            bool: True if any of the relevant parameters differ between the provided `anycast` configuration and the
                corresponding parameters in `anycast_details_in_ccc`, indicating that an update is needed.
                Returns False if no differences are found.
        Description:
            This function compares specific configuration parameters of an Anycast Gateway between the provided
            configuration (`anycast`) and the existing configuration in the Cisco Catalyst Center.
            If any differences are detected, it logs an informational message and returns True. If no discrepancies
            are found, the function returns False, indicating that the current configuration is up to date.
        """

        update_param_to_check = [
            "tcp_mss_adjustment",
            "traffic_type",
            "security_group_name",
            "layer2_flooding_enabled",
            "fabric_enabled_wireless",
            "ip_directed_broadcast",
            "multiple_ip_to_mac_addresses",
            "supplicant_based_extended_node_onboarding",
            "group_policy_enforcement_enabled",
        ]

        if self.compare_dnac_versions(self.get_ccc_version(), "3.1.3.0") >= 0:
            self.log(
                "CCC version is 3.1.3 or above, adding additional parameters for Anycast Gateway update checks.",
                "DEBUG",
            )
            update_param_to_check.append("flooding_address_assignment")
            update_param_to_check.append("flooding_address")
            update_param_to_check.append("wireless_flooding_enable")
            update_param_to_check.append("resource_guard_enable")

        vn_name = anycast.get("vn_name")
        anycast_mapping = self.get_anycast_gateway_mapping(vn_name)
        self.log(
            "Checking if Anycast Gateway needs update for VN: '{0}'.".format(vn_name),
            "INFO",
        )

        if vn_name == "INFRA_VN":
            params_to_remove = [
                "security_group_name",
                "layer2_flooding_enabled",
                "fabric_enabled_wireless",
                "ip_directed_broadcast",
                "multiple_ip_to_mac_addresses",
                "flooding_address_assignment",
                "flooding_address",
                "wireless_flooding_enable",
                "resource_guard_enable",
            ]
            for param in params_to_remove:
                if param in update_param_to_check:
                    update_param_to_check.remove(param)
                    self.log(
                        "Removing parameter '{0}' from update check for INFRA_VN.".format(
                            param
                        ),
                        "DEBUG",
                    )
        else:
            update_param_to_check.remove("supplicant_based_extended_node_onboarding")
            update_param_to_check.remove("group_policy_enforcement_enabled")
            self.log(
                "Removed parameters for non-INFRA_VN: 'supplicant_based_extended_node_onboarding' and "
                "'group_policy_enforcement_enabled'.",
                "DEBUG",
            )
            if self.compare_dnac_versions(self.get_ccc_version(), "3.1.3.0") >= 0:
                self.log(
                    "CCC version is 3.1.3 or above, checking additional parameters for non-INFRA_VN.",
                    "DEBUG",
                )
                flooding_address = anycast.get("flooding_address")
                address_in_ccc = anycast_details_in_ccc.get("layer2FloodingAddress")
                update_param_to_check.remove("flooding_address")
                if flooding_address and anycast_details_in_ccc.get(
                    "layer2FloodingAddressAssignment"
                ) == "CUSTOM" and flooding_address != address_in_ccc:
                    self.log(
                        "Given flooding address '{0}' does not match the one in CCC '{1}'; gateway needs update.".format(
                            flooding_address, address_in_ccc
                        ),
                        "INFO",
                    )
                    return True

        if (
            anycast.get("traffic_type")
            and anycast_details_in_ccc.get("isCriticalPool") is True
        ):
            self.log(
                "Removing 'traffic_type' from update checks as 'is_critical_pool' is true.",
                "DEBUG",
            )
            update_param_to_check.remove("traffic_type")

        for param in update_param_to_check:
            if anycast.get(param) is not None:
                key_in_ccc = anycast_mapping.get(param)
                if anycast.get(param) != anycast_details_in_ccc.get(key_in_ccc):
                    msg = (
                        "Given parameter '{0}' does not match; gateway needs update."
                    ).format(param)
                    self.log(msg, "INFO")
                    return True

        self.log(
            "No discrepancies found; Anycast Gateway configuration is up to date.",
            "INFO",
        )

        return False

    def get_anycast_gateway_update_payload(self, anycast, anycast_details_in_ccc):
        """
        Constructs the payload necessary to update the Anycast Gateway configuration in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            anycast (dict): A dictionary containing the new configuration parameters for the Anycast Gateway.
            anycast_details_in_ccc (dict): A dictionary containing the current Anycast Gateway configuration details from CCC.
        Returns:
            dict: A dictionary containing the payload needed to update the Anycast Gateway configuration.
        Description:
            This function constructs an update payload for the Anycast Gateway by combining existing values from
            `anycast_details_in_ccc` with any new values specified in the `anycast` dictionary. If a parameter exists in
            `anycast`, it is prioritized over the existing value. If a parameter does not exist in `anycast`, the function
            retains the current value from `anycast_details_in_ccc`.
            The resulting payload can be used for updating the Anycast Gateway configuration in the Cisco Catalyst Center.
        """

        vn_name = anycast_details_in_ccc.get("virtualNetworkName")
        self.log(
            "Constructing update payload for Anycast Gateway in VN: '{0}'.".format(
                vn_name
            ),
            "INFO",
        )
        anycast_payload = {
            "id": anycast_details_in_ccc.get("id"),
            "fabricId": anycast_details_in_ccc.get("fabricId"),
            "virtualNetworkName": vn_name,
            "ipPoolName": anycast_details_in_ccc.get("ipPoolName"),
            "vlanName": anycast_details_in_ccc.get("vlanName"),
            "vlanId": anycast_details_in_ccc.get("vlanId"),
            "isCriticalPool": anycast_details_in_ccc.get("isCriticalPool"),
            "poolType": anycast_details_in_ccc.get("poolType"),
            "isIntraSubnetRoutingEnabled": anycast_details_in_ccc.get(
                "isIntraSubnetRoutingEnabled"
            ),
        }
        params_in_playbook = [
            "tcp_mss_adjustment",
            "traffic_type",
            "security_group_name",
            "layer2_flooding_enabled",
            "fabric_enabled_wireless",
            "ip_directed_broadcast",
            "multiple_ip_to_mac_addresses",
            "supplicant_based_extended_node_onboarding",
            "group_policy_enforcement_enabled",
        ]

        anycast_mapping = self.get_anycast_gateway_mapping(vn_name)

        if vn_name == "INFRA_VN":
            params_to_remove = [
                "security_group_name",
                "layer2_flooding_enabled",
                "fabric_enabled_wireless",
                "ip_directed_broadcast",
                "multiple_ip_to_mac_addresses",
            ]

            for param in params_to_remove:
                if param in params_in_playbook:
                    params_in_playbook.remove(param)
                    self.log(
                        "Removing parameter '{0}' from payload construction for INFRA_VN.".format(
                            param
                        ),
                        "DEBUG",
                    )

            anycast_payload.pop("isCriticalPool", None)
            anycast_payload.pop("isIntraSubnetRoutingEnabled", None)
            self.log(
                "Removed 'isCriticalPool' and 'isIntraSubnetRoutingEnabled' for INFRA_VN.",
                "DEBUG",
            )
        else:
            params_in_playbook.remove("supplicant_based_extended_node_onboarding")
            params_in_playbook.remove("group_policy_enforcement_enabled")
            anycast_payload.pop("poolType", None)
            self.log(
                "Removed parameters for non-INFRA_VN: 'supplicant_based_extended_node_onboarding' and "
                "'group_policy_enforcement_enabled'.",
                "DEBUG",
            )

        if (
            anycast.get("traffic_type")
            and anycast_details_in_ccc.get("isCriticalPool") is True
        ):
            params_in_playbook.remove("traffic_type")
            anycast_payload["trafficType"] = anycast_details_in_ccc.get("trafficType")
            self.log(
                "Retaining 'traffic_type' from existing configuration due to 'is_critical_pool' being true.",
                "DEBUG",
            )

        for param in params_in_playbook:
            key = anycast_mapping.get(param)
            if anycast.get(param) is not None:
                anycast_payload[key] = anycast.get(param)
                self.log(
                    "Setting '{0}' to '{1}' in the payload.".format(
                        key, anycast.get(param)
                    ),
                    "DEBUG",
                )
            else:
                anycast_payload[key] = anycast_details_in_ccc.get(key)
                self.log(
                    "Using existing value for '{0}': '{1}'.".format(
                        key, anycast_details_in_ccc.get(key)
                    ),
                    "DEBUG",
                )

        if vn_name != "INFRA_VN" and self.compare_dnac_versions(
            self.get_ccc_version(), "3.1.3.0"
        ) >= 0:
            self.log(
                "Catalyst version {0} supports new Anycast Gateway parameters; processing them."
                .format(self.get_ccc_version()),
                "DEBUG",
            )
            self.log(
                "Processing additional parameters for non-INFRA_VN Anycast Gateway.",
                "DEBUG",
            )
            flooding_address_assignment = anycast.get("flooding_address_assignment")
            anycast_payload["layer2FloodingAddressAssignment"] = (
                flooding_address_assignment
                or anycast_details_in_ccc.get("layer2FloodingAddressAssignment", "SHARED")
            )

            flooding_address = anycast.get("flooding_address")
            if flooding_address_assignment == "CUSTOM":
                anycast_payload["layer2FloodingAddress"] = flooding_address or anycast_details_in_ccc.get(
                    "layer2FloodingAddress"
                )

            wireless_flooding_enable = anycast.get("wireless_flooding_enable")
            fabric_enabled_wireless = anycast_payload.get("isWirelessPool") or anycast_details_in_ccc.get(
                "isWirelessPool"
            )
            if fabric_enabled_wireless and fabric_enabled_wireless is True:
                anycast_payload["isWirelessFloodingEnabled"] = (
                    wireless_flooding_enable
                    if wireless_flooding_enable is not None
                    else anycast_details_in_ccc.get("isWirelessFloodingEnabled", False)
                )

            resource_guard_enable = anycast.get("resource_guard_enable")
            if resource_guard_enable is not None:
                anycast_payload["isResourceGuardEnabled"] = resource_guard_enable
            else:
                anycast_payload["isResourceGuardEnabled"] = anycast_details_in_ccc.get(
                    "isResourceGuardEnabled", False
                )

        self.log(
            "Constructed payload for Anycast Gateway update: {0}".format(
                anycast_payload
            ),
            "INFO",
        )

        return anycast_payload

    def add_anycast_gateways_in_system(self, add_anycast_payloads):
        """
        Adds Anycast Gateways to the Cisco Catalyst Center using the provided payload.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            add_anycast_payloads (dict): A dictionary containing the necessary details for
                adding Anycast Gateways.
        Returns:
            self (object): The instance of the class, allowing for method chaining. The status of the operation
                can be checked via the `status` attribute.
        Description:
            This function interacts with the Cisco DNA Center API to add Anycast Gateways. It sends the provided
            payload to the API and processes the response.
            In case of an exception during the API call, the function captures the exception and logs the error.
            The method returns the instance itself, allowing for further interactions with the object.
        """

        self.log("Starting the process to add Anycast Gateways.", "INFO")
        req_limit = self.params.get("sda_fabric_gateway_limit", 20)
        self.log(
            "API request batch size set to '{0}' for anycast gateway(s) creation.".format(
                req_limit
            ),
            "DEBUG",
        )
        for i in range(0, len(add_anycast_payloads), req_limit):
            batch_number = (i // req_limit) + 1
            gateway_payload = add_anycast_payloads[i : i + req_limit]
            batch_gateways_added = self.created_anycast_gateways[i : i + req_limit]
            payload = {"payload": gateway_payload}
            task_name = "add_anycast_gateways"
            self.log(
                "Processing batch {0}: Constructing API payload for '{1}' task: "
                "{2}".format(batch_number, task_name, payload),
                "INFO",
            )

            try:
                task_id = self.get_taskid_post_api_call("sda", task_name, payload)

                if not task_id:
                    self.msg = (
                        "Batch {0}: Failed to retrieve task ID for '{1}'.".format(
                            batch_number, task_name
                        )
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                success_msg = "Batch {0}: Successfully added Anycast Gateways '{1}' in Cisco Catalyst Center.".format(
                    batch_number, batch_gateways_added
                )
                self.log(
                    "Batch {0}: Received Task ID '{1}'. Checking task status.".format(
                        batch_number, task_id
                    ),
                    "INFO",
                )
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()
                self.log(
                    "Batch {0}: Completed Anycast Gateway addition.".format(
                        batch_number
                    ),
                    "INFO",
                )

            except Exception as e:
                self.msg = (
                    "Batch {0}: Exception occurred while adding Anycast Gateways '{1}': {2}"
                ).format(batch_number, batch_gateways_added, str(e))
                self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def update_anycast_gateways_in_system(self, update_anycast_payloads):
        """
        Updates Anycast Gateways in the Cisco Catalyst Center using the provided payload.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            update_anycast_payloads (dict): A dictionary containing the necessary details for updating
                Anycast Gateways.
        Returns:
            self (object): The instance of the class, allowing for method chaining. The status of the operation
                can be checked via the `status` attribute.
        Description:
            This function interacts with the Cisco DNA Center API to update Anycast Gateways. It sends the provided
            payload to the API and processes the response.
            In case of an exception during the API call, the function captures the exception and logs the error.
            The method returns the instance itself, allowing for further interactions with the object.
        """

        self.log("Starting the process to update Anycast Gateways.", "INFO")
        req_limit = self.params.get("sda_fabric_gateway_limit", 20)
        self.log(
            "API request batch size set to '{0}' for anycast gateway(s) creation.".format(
                req_limit
            ),
            "DEBUG",
        )
        for i in range(0, len(update_anycast_payloads), req_limit):
            batch_number = (i // req_limit) + 1
            gateway_payload = update_anycast_payloads[i : i + req_limit]
            batch_gateways_updated = self.updated_anycast_gateways[i : i + req_limit]
            payload = {"payload": gateway_payload}
            task_name = "update_anycast_gateways"

            try:
                self.log(
                    "Processing batch {0}: Constructing API payload for '{1}' task: "
                    "{2}".format(batch_number, task_name, payload),
                    "DEBUG",
                )
                task_id = self.get_taskid_post_api_call("sda", task_name, payload)

                if not task_id:
                    self.msg = (
                        "Batch {0}: Failed to retrieve task ID for '{1}'.".format(
                            batch_number, task_name
                        )
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                success_msg = "Batch {0}: Successfully updated Anycast Gateways '{1}' in Cisco Catalyst Center.".format(
                    batch_number, batch_gateways_updated
                )
                self.log(
                    "Batch {0}: Received Task ID '{1}'. Checking task status.".format(
                        batch_number, task_id
                    ),
                    "INFO",
                )
                self.get_task_status_from_tasks_by_id(
                    task_id, task_name, success_msg
                ).check_return_status()
                self.log(
                    "Batch {0}: Completed Anycast Gateway updation.".format(
                        batch_number
                    ),
                    "INFO",
                )

            except Exception as e:
                self.msg = (
                    "Batch {0}: Exception occurred while updating Anycast Gateways '{1}': {2}"
                ).format(batch_number, batch_gateways_updated, str(e))
                self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def delete_anycast_gateway(self, gateway_id, unique_anycast):
        """
        Deletes an Anycast Gateway in the Cisco Catalyst Center based on the provided gateway ID.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            gateway_id (str): The unique identifier of the Anycast Gateway to be deleted.
            unique_anycast (str): A descriptive name or identifier for the Anycast Gateway, used for logging.
        Returns:
            self (object): The instance of the class, allowing for method chaining. The status of the operation
                can be checked via the `status` attribute.
        Description:
            This function sends a request to the Cisco DNA Center API to delete the specified Anycast Gateway
            using its ID. It processes the API response and checks for the presence of a task ID to confirm that
            the deletion request was received.
            If the deletion is successful, it logs a success message and appends the deleted gateway's name to the
            `deleted_anycast_gateways` list. If there is an error during the deletion process or an exception occurs, it
            captures the error, logs an appropriate message, and updates the status.
            The method returns the instance itself, allowing for further interactions with the object.
        """

        self.log(
            "Initiating deletion of Anycast Gateway '{0}'.".format(unique_anycast),
            "INFO",
        )
        payload = {"id": gateway_id}
        task_name = "delete_anycast_gateway_by_id"

        try:
            self.log(
                "Constructing API call payload for task '{0}': {1}".format(
                    task_name, payload
                ),
                "DEBUG",
            )
            task_id = self.get_taskid_post_api_call("sda", task_name, payload)

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "Anycast Gateway '{0}' deleted successfully from the Cisco Catalyst Center.".format(
                unique_anycast
            )
            self.log(
                "Task ID '{0}' received. Checking task status...".format(task_id),
                "INFO",
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
            self.deleted_anycast_gateways.append(unique_anycast)
            self.log(
                "Completed deletion process for Anycast Gateway '{0}'.".format(
                    unique_anycast
                ),
                "INFO",
            )

        except Exception as e:
            self.msg = "Exception occurred while deleting the Anycast Gateway '{0}' due to: {1}".format(
                unique_anycast, str(e)
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def get_want_fabric_vlan_details(self, fabric_vlan_details):
        """
        Retrieves and validates fabric VLAN details required for Cisco Catalyst Center operations.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            fabric_vlan_details (list): A list of dictionaries containing VLAN details. Each dictionary should include
                the keys 'vlan_name', 'vlan_id', and 'fabric_site_locations'.
        Returns:
            list: A list of validated fabric VLAN information. If a VLAN fails validation, the function sets the
                operation result as 'failed' and returns the instance of the class.
        Description:
            This function iterates through the provided `fabric_vlan_details` to validate and collect necessary fabric
            VLAN information.
            If any validation fails, the function logs the reason and updates the class status to "failed", returning the
            instance. On successful validation, the VLAN information is added to the result list.
        """

        fabric_vlan_info = []

        for vlan in fabric_vlan_details:
            missing_required_param = []
            vlan_name = vlan.get("vlan_name")
            fabric_site_locations = vlan.get("fabric_site_locations")
            vlan_id = vlan.get("vlan_id")
            required_param = ["vlan_name", "vlan_id", "fabric_site_locations"]

            for param in required_param:
                value = vlan.get(param)
                if not value:
                    self.log(
                        "Adding the missing param '{0}' required for fabric Vlan operations".format(
                            value
                        ),
                        "DEBUG",
                    )
                    missing_required_param.append(param)

            if vlan_id not in range(2, 4094) or vlan_id in [
                1002,
                1003,
                1004,
                1005,
                2046,
            ]:
                self.msg = (
                    "Invalid vlan_id '{0}' given in the playbook. Allowed VLAN range is (2,4094) except for "
                    "reserved VLANs 1002-1005, and 2046."
                ).format(vlan_id)
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()
                return self

            if missing_required_param:
                self.msg = (
                    "Required parameter(s) '{0}' are missing and they must be given in the playbook in order to  "
                    "perform any layer2 fabric vlan operation in Cisco Catalyst Center."
                ).format(missing_required_param)
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            flooding_address_assignment = vlan.get("flooding_address_assignment")
            if flooding_address_assignment and flooding_address_assignment not in ["SHARED", "CUSTOM"]:
                self.msg = (
                    "Invalid flooding_address_assignment '{0}' given in the playbook. Allowed values are "
                    "'SHARED' or 'CUSTOM'."
                ).format(flooding_address_assignment)
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            # Validate the Fabric Vlan name against the regex
            is_valid_vlan_name = self.is_valid_fabric_vlan_name(vlan_name)

            if is_valid_vlan_name:
                self.log(
                    "Given fabric VLAN name '{0}' is valid for the sda operation.".format(
                        vlan_name
                    ),
                    "INFO",
                )
            else:
                self.msg = (
                    "Given Fabric VLAN name '{0}' in the input playbook is not valid. Fabric VLAN name "
                    "should be 1-32 characters long and contains only alphanumeric characters, underscores and hyphens."
                ).format(vlan_name)
                self.set_operation_result(
                    "failed", False, self.msg, "WARNING"
                ).check_return_status()

            for fabric in fabric_site_locations:
                site_name = fabric.get("site_name_hierarchy")
                fabric_type = fabric.get("fabric_type")

                if not site_name or not fabric_type:
                    self.msg = (
                        "Required parameter 'site_name' and 'fabric_type 'must be given in the playbook in order to "
                        "perform any operation on fabric vlan '{0}'."
                    ).format(vlan_name)
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                # Validate the correct fabric_type given in the playbook
                self.validate_fabric_type(fabric_type).check_return_status()
                self.log("Fabric type '{0}' is valid.".format(fabric_type), "INFO")
            fabric_vlan_info.append(vlan)

        return fabric_vlan_info

    def get_want_virtual_network_details(self, vn_details):
        """
        Retrieves and validates Virtual Network (VN) details required for Cisco Catalyst Center operations.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            vn_details (list): A list of dictionaries, where each dictionary contains details about a virtual network.
        Returns:
            list: A list of validated virtual network information. If a virtual network fails validation, the function
                sets the operation result as 'failed' and returns the instance of the class.
        Description:
            This function processes and validates virtual network (VN) details provided in the `vn_details` list.
            - Ensures that the required parameter 'vn_name' is present in each virtual network's dictionary.
            - Validates that the `vn_name` conforms to naming conventions (1-16 characters long, containing only letters,
            numbers, and underscores).
            If the `vn_name` is missing or invalid, an appropriate error message is logged, and the function updates the
            class's operation result to 'failed'. On successful validation, the virtual network information is added to
            the result list and returned for further operations.
        """

        vn_info = []

        for vn in vn_details:
            vn_name = vn.get("vn_name")

            if not vn_name:
                self.msg = (
                    "Required parameter 'vn_name' must be given in the playbook in order to perform any virtual "
                    "networks operation including creation/updation/deletion in Cisco Catalyst Center."
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            # Validate the VN name against the regex
            is_valid_name = self.is_valid_vn_name(vn_name)

            if is_valid_name:
                self.log(
                    "Given virtual network name '{0}' is valid for the SDA operation.".format(
                        vn_name
                    ),
                    "INFO",
                )
            else:
                self.msg = (
                    "Given Virtual Network name '{0}' in the input playbook is not valid. Virtual Network "
                    "name should be 1-16 characters long and contain only letters numbers and underscores."
                ).format(vn_name)
                self.set_operation_result(
                    "failed", False, self.msg, "WARNING"
                ).check_return_status()

            vn_info.append(vn)

        return vn_info

    def get_want_anycast_gateway_details(self, anycast_gateway_details):
        """
        Retrieves and validates anycast gateway details required for Cisco Catalyst Center operations.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            anycast_gateway_details (list): A list of dictionaries containing details of anycast gateways.
        Returns:
            list: A list of validated anycast gateway information. If validation fails for any entry, the function logs
                the error, updates the class status to 'failed', and returns the instance of the class.
        Description:
            This function processes and validates the provided `anycast_gateway_details` list to ensure all necessary
            information is available and valid. The validation steps include:
            - Checking that the required parameters ('vn_name', 'fabric_site_location', and 'ip_pool_name') are present
            in each anycast gateway's details. If any are missing, an error is logged and the operation is marked as
            failed.
            - Ensuring the given virtual network (`vn_name`) exists in Cisco Catalyst Center. If not, an error is raised
            unless the operation is for deletion.
            - Validating that the 'fabric_site_location' contains a valid 'site_name_hierarchy'. If not present or invalid,
            an error is logged.
            - Verifying that the IP pool (`ip_pool_name`) exists and is reserved for the specified site. If the pool does
            not exist, an error is logged and the operation is marked as failed.
            If all validations pass, the anycast gateway information is added to the result list and returned for further
            processing.
        """

        anycast_info = []
        state = self.params.get("state")

        for anycast in anycast_gateway_details:
            required_param = ["vn_name", "fabric_site_location", "ip_pool_name"]
            vn_name = anycast.get("vn_name")
            ip_pool_name = anycast.get("ip_pool_name")
            missing_required_item = []

            for item in required_param:
                if not anycast.get(item):
                    missing_required_item.append(item)

            if missing_required_item:
                self.msg = (
                    "Required parameter '{0}' must be given in the playbook in order to perform any anycast "
                    "networks operation including creation/updation/deletion in Cisco Catalyst Center."
                ).format(missing_required_item)
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            is_vn_exist = self.is_virtual_network_exist(vn_name)

            if not is_vn_exist:
                self.msg = (
                    "Given layer3 Virtual Network '{0}' does not exist in the Cisco Catalyst Center. "
                    "Please create the L3 Virtual network first in order to configure anycast gateway."
                ).format(vn_name)
                if state == "deleted":
                    continue

                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            site_name = anycast.get("fabric_site_location").get("site_name_hierarchy")
            if not site_name:
                self.msg = (
                    "Parameter 'site_name' must be provided in the playbook in order to configure "
                    "anycast gateway in the Catalyst Center."
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            site_exists, site_id = self.get_site_id(site_name)
            if not site_exists:
                self.msg = (
                    "Given site '{0}' does not exist in the Catalyst Center.".format(
                        site_name
                    )
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            is_pool_exist = self.is_ip_pool_exist(ip_pool_name, site_id)
            if state == "deleted" and not is_pool_exist:
                self.log(
                    "The reserved IP pool '{0}' has already been deleted from the fabric site '{1}'.".format(
                        ip_pool_name, site_name
                    ),
                    "INFO",
                )
                continue

            if not is_pool_exist:
                self.log(
                    "Checking if the given VN '{0}' is an anchored VN, as anchored VNs can use the "
                    "same poolreserved on the anchored site.".format(vn_name),
                    "DEBUG",
                )
                vn_details_in_ccc = self.get_vn_details_from_ccc(vn_name)
                anchored_fabric_id = vn_details_in_ccc.get("anchoredSiteId")
                if not anchored_fabric_id:
                    self.msg = (
                        "The virtual network '{0}' is not anchored to any site for the reserved IP pool '{1}' in "
                        "Cisco Catalyst Center. Please ensure the virtual network is properly configured with site anchoring.".format(
                            vn_name, ip_pool_name
                        )
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                self.log(
                    "Fetching the site id from the fabric site/zone from Catalyst Center.",
                    "DEBUG",
                )
                fabric_anchored_site_id = self.fetch_site_id_from_fabric_id(
                    anchored_fabric_id, site_name
                )

                if fabric_anchored_site_id and self.is_ip_pool_exist(
                    ip_pool_name, fabric_anchored_site_id
                ):
                    self.log(
                        "Given ip pool '{0}' shared to extended fabric site '{1}'".format(
                            ip_pool_name, site_name
                        ),
                        "INFO",
                    )
                    anycast_info.append(anycast)
                    continue

                self.msg = (
                    "Given reserve ip pool '{0}' does not exist and reserve to the given site '{1}'. "
                    "Please create and reserve the given IP pool using the network_settings_workflow_manager"
                    " module for the configuration of Anycast gateways in the Catalyst Center."
                ).format(ip_pool_name, site_name)
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            anycast_info.append(anycast)

        return anycast_info

    def get_want(self, config):
        """
        Collects and validates the desired state of fabric VLANs, virtual networks,
        and Anycast gateways based on the provided configuration.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A configuration dictionary containing details about fabric VLANs,
                        virtual networks, and Anycast gateways.
        Returns:
            self (object): The instance of the class with the updated `want` attribute containing the validated desired state
                of fabric Vlan, Virtual Network and Anycast Gateways.
        Description:
            This function processes the given configuration to gather and validate details about:
            - Fabric VLANs: It collects information on VLANs, ensuring required parameters are present
            and that the VLAN IDs are within valid ranges.
            - Virtual Networks: It checks for the existence of specified virtual networks, ensuring
            their names are provided and valid.
            - Anycast Gateways: It collects details about Anycast gateways, checking that necessary
            parameters are present and that referenced virtual networks and IP pools exist.
            If any required parameters are missing or invalid, the function logs an error message
            and updates the status accordingly. On successful collection of all parameters, it logs
            the desired state and sets the status to success.
        """

        want = {}
        self.log(
            "Starting the process of gathering the desired state from the configuration.",
            "INFO",
        )

        fabric_vlan_details = config.get("fabric_vlan")
        if fabric_vlan_details:
            vlan_details = self.get_want_fabric_vlan_details(fabric_vlan_details)

            if vlan_details:
                want["fabric_vlan_info"] = vlan_details

        vn_details = config.get("virtual_networks")
        if vn_details:
            vn_info_details = self.get_want_virtual_network_details(vn_details)

            if vn_info_details:
                want["vn_info"] = vn_info_details

        anycast_gateway_details = config.get("anycast_gateways")
        if anycast_gateway_details:
            anycast_info_details = self.get_want_anycast_gateway_details(
                anycast_gateway_details
            )

            if anycast_info_details:
                want["anycast_info"] = anycast_info_details

        self.want = want
        self.msg = "Successfully collected all parameters for the desired state."
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        return self

    def get_have(self, config):
        """
        Collects and stores the current state of fabric VLANs, Layer3 virtual networks, and Anycast
        gateway IDs based on the provided configuration.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A configuration dictionary containing details about fabric VLANs,
                        virtual networks, and Anycast gateways.
        Returns:
            self (object): The instance of the class with the updated `have` attribute containing the current
                state of fabric Vlan, Virtual Network and Anycast Gateways.
        Description:
            This function processes the given configuration to gather details about:
            - Fabric VLANs: It retrieves VLAN IDs based on the names provided.
            - Layer3 Virtual Networks: It checks for the existence of specified virtual networks.
            - Anycast Gateways: It collects IDs of Anycast gateways based on their associated
            virtual networks and IP pool names.
            For each of these components, the function logs success messages for each
            successfully collected item. The collected data is stored in the `have`
            attribute of the instance.
        """

        have = {"fabric_vlan_ids": [], "l3_vn_name": [], "anycast_gateway_ids": []}

        fabric_vlan_details = config.get("fabric_vlan")
        if fabric_vlan_details:
            self.log("Starting to collect fabric VLAN details.", "INFO")
            for vlan in fabric_vlan_details:
                vlan_name = vlan.get("vlan_name")
                vlan_id = vlan.get("vlan_id")
                self.log(
                    "Collecting VLAN IDs for VLAN '{0}' with ID '{1}'.".format(
                        vlan_name, vlan_id
                    ),
                    "DEBUG",
                )
                fabric_vlan_ids = self.collect_fabric_vlan_ids(vlan_name, vlan_id)

                if fabric_vlan_ids:
                    self.log(
                        "Successfully collect the vlan details for the vlan '{0}'.".format(
                            vlan_name
                        ),
                        "DEBUG",
                    )
                    have["fabric_vlan_ids"].extend(fabric_vlan_ids)
                else:
                    self.log(
                        "No VLAN details found for '{0}'.".format(vlan_name), "DEBUG"
                    )

        virtual_networks = config.get("virtual_networks")
        if virtual_networks:
            self.log("Starting to collect Layer3 Virtual Network details.", "INFO")
            for vn in virtual_networks:
                vn_name = vn.get("vn_name")
                self.log(
                    "Checking existence for Virtual Network '{0}'.".format(vn_name),
                    "DEBUG",
                )
                is_vn_exist = self.is_virtual_network_exist(vn_name)

                if is_vn_exist:
                    self.log(
                        "Successfully collect the layer3 VN details for the VN '{0}'.".format(
                            vn_name
                        ),
                        "DEBUG",
                    )
                    have["l3_vn_name"].append(vn_name)
                else:
                    self.log(
                        "Virtual Network '{0}' does not exist.".format(vn_name), "DEBUG"
                    )

        anycast_gateways = config.get("anycast_gateways")
        if anycast_gateways:
            self.log("Starting to collect Anycast Gateway details.", "INFO")
            for anycast in anycast_gateways:
                vn_name = anycast.get("vn_name")
                ip_pool_name = anycast.get("ip_pool_name")
                site_name = anycast.get("fabric_site_location").get(
                    "site_name_hierarchy"
                )
                self.log(
                    "Collecting Anycast Gateway details for VN '{0}', IP Pool '{1}', Site '{2}'.".format(
                        vn_name, ip_pool_name, site_name
                    ),
                    "DEBUG",
                )
                site_exists, site_id = self.get_site_id(site_name)
                if not site_exists:
                    self.msg = "Given site '{0}' does not exist in the Catalyst Center.".format(
                        site_name
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                fabric_type = anycast.get("fabric_site_location").get("fabric_type")
                # Validate the fabric_type given in the playbook
                self.log("Validating fabric type '{0}'.".format(fabric_type), "DEBUG")
                self.validate_fabric_type(fabric_type).check_return_status()
                self.log("Fabric type '{0}' is valid.".format(fabric_type), "INFO")

                if fabric_type == "fabric_site":
                    fabric_id = self.get_fabric_site_id(site_name, site_id)
                else:
                    fabric_id = self.get_fabric_zone_id(site_name, site_id)

                self.log(
                    "Collected fabric ID '{0}' for site '{1}'.".format(
                        fabric_id, site_name
                    ),
                    "DEBUG",
                )
                # Collect the gateway id with combination of vn_name, ip_pool_name and fabric id
                gateway_details = self.get_anycast_gateway_details(
                    vn_name, ip_pool_name, fabric_id
                )
                if gateway_details:
                    gateway_id = gateway_details.get("id")
                    self.log(
                        "Successfully collect the anycast gateway details for the IP pool '{0}'.".format(
                            ip_pool_name
                        ),
                        "DEBUG",
                    )
                    have["anycast_gateway_ids"].append(gateway_id)
                else:
                    self.log(
                        "No Anycast Gateway found for IP Pool '{0}' in VN '{1}'.".format(
                            ip_pool_name, vn_name
                        ),
                        "DEBUG",
                    )

        self.have = have
        self.log("Current State (have): {0}".format(str(have)), "INFO")

        return self

    def get_task_tree_failure_reasons(self, task_id):
        """
        Returns the task tree response of the task ID.
        Args:
            task_id (string) - The unique identifier of the task for which you want to retrieve details.
        Returns:
            error_msg (str) - Returns the task tree error message of the task ID.
        """

        response = self.dnac._exec(
            family="task", function="get_task_tree", params={"task_id": task_id}
        )
        self.log(
            "Retrieving task tree details by the API 'get_task_tree' using task ID: {0}, Response: {1}".format(
                task_id, response
            ),
            "DEBUG",
        )
        error_msg = ""
        if response and isinstance(response, dict):
            result = response.get("response")
            error_messages = []
            for item in result:
                if item.get("isError") is True:
                    failure_reason = item.get("failureReason")
                    if "Batch Operation" in failure_reason:
                        continue

                    error_messages.append(failure_reason)

            if error_messages:
                error_msg = ". ".join(error_messages)

        return error_msg

    def update_fabric_vlan_vn_anycast_gateway_messages(self):
        """
        Updates and logs messages based on the status of fabric VLANs, virtual networks,
        and Anycast gateways.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): Returns the current instance of the class with updated `result`
                        and `msg` attributes.
        Description:
            This method aggregates status messages related to the creation, update, or
            deletion of fabric VLANs, Layer 3 virtual networks, and Anycast gateways.
            The messages include success and failure notifications for:
            - Fabric VLANs: created, updated, or deleted
            - Layer3 Virtual Networks: created, updated, or deleted
            - Anycast Gateways: added, updated, or deleted
            The method also updates the `result["response"]` attribute with the concatenated status messages.
        """

        self.result["changed"] = False
        result_msg_list = []

        if self.created_fabric_vlans:
            create_fabric_vlan = "Layer2 Fabric VLAN(s) '{0}' created successfully in the Cisco Catalyst Center.".format(
                self.created_fabric_vlans
            )
            result_msg_list.append(create_fabric_vlan)

        if self.updated_fabric_vlans:
            update_fabric_vlan = "Layer2 Fabric VLAN(s) '{0}' updated successfully in the Cisco Catalyst Center.".format(
                self.updated_fabric_vlans
            )
            result_msg_list.append(update_fabric_vlan)

        if self.no_update_fabric_vlans:
            no_update_fabric_vlans = "Given Fabric VLAN(s) '{0}' does not need any update in Cisco Catalyst Center.".format(
                self.no_update_fabric_vlans
            )
            result_msg_list.append(no_update_fabric_vlans)

        if self.created_virtual_networks:
            create_vn_msg = "Layer3 Virtual Network(s) '{0}' created successfully in the Cisco Catalyst Center.".format(
                self.created_virtual_networks
            )
            result_msg_list.append(create_vn_msg)

        if self.updated_virtual_networks:
            update_vn_msg = "Layer3 Virtual Network(s) '{0}' updated successfully in the Cisco Catalyst Center.".format(
                self.updated_virtual_networks
            )
            result_msg_list.append(update_vn_msg)

        if self.no_update_virtual_networks:
            no_update_vns_msg = "Given Virtual Network(s) '{0}' does not need any update in Cisco Catalyst Center.".format(
                self.no_update_virtual_networks
            )
            result_msg_list.append(no_update_vns_msg)

        if self.created_anycast_gateways:
            create_anycast_msg = "Anycast Gateway(s) '{0}' added successfully in the Cisco Catalyst Center.".format(
                self.created_anycast_gateways
            )
            result_msg_list.append(create_anycast_msg)

        if self.updated_anycast_gateways:
            update_anycast_msg = "Anycast Gateway(s) '{0}' updated successfully in the Cisco Catalyst Center.".format(
                self.updated_anycast_gateways
            )
            result_msg_list.append(update_anycast_msg)

        if self.no_update_anycast_gateways:
            no_update_anycast_gateways_msg = (
                "Given Anycast Gateway(s) '{0}' does not need any update in the Cisco Catalyst Center."
            ).format(self.no_update_anycast_gateways)
            result_msg_list.append(no_update_anycast_gateways_msg)

        if self.deleted_fabric_vlans:
            delete_vlan_msg = "Fabric VLAN(s) '{0}' deleted successfully from the Cisco Catalyst Center.".format(
                self.deleted_fabric_vlans
            )
            result_msg_list.append(delete_vlan_msg)

        if self.absent_fabric_vlans:
            absent_vlan_msg = "Unable to delete Fabric VLAN(s) '{0}' as they are not present in Cisco Catalyst Center.".format(
                self.absent_fabric_vlans
            )
            result_msg_list.append(absent_vlan_msg)

        if self.deleted_virtual_networks:
            delete_vn_msg = "Layer3 Virtual Network(s) '{0}' deleted successfully from the Cisco Catalyst Center.".format(
                self.deleted_virtual_networks
            )
            result_msg_list.append(delete_vn_msg)

        if self.absent_virtual_networks:
            absent_virtual_networks_msg = (
                "Unable to delete Layer3 Virtual Network(s) '{0}' as they are not present in Cisco Catalyst Center."
            ).format(self.absent_virtual_networks)
            result_msg_list.append(absent_virtual_networks_msg)

        if self.deleted_anycast_gateways:
            delete_anycast_msg = "Anycast Gateway(s) '{0}' deleted successfully from the Cisco Catalyst Center.".format(
                self.deleted_anycast_gateways
            )
            result_msg_list.append(delete_anycast_msg)

        if self.removed_vn_sites:
            vn_sites_msg = "Fabric site(s) removed from Virtual Network(s) '{0}'  successfully from the Cisco Catalyst Center.".format(
                self.removed_vn_sites
            )
            result_msg_list.append(vn_sites_msg)

        if self.absent_anycast_gateways:
            absent_anycast_gateways_msg = (
                "Unable to delete Anycast Gateway(s) '{0}' as they are not present in Cisco Catalyst Center."
            ).format(self.absent_anycast_gateways)
            result_msg_list.append(absent_anycast_gateways_msg)

        if (
            self.created_fabric_vlans
            or self.updated_fabric_vlans
            or self.deleted_fabric_vlans
            or self.created_virtual_networks
            or self.updated_virtual_networks
            or self.deleted_virtual_networks
            or self.created_anycast_gateways
            or self.updated_anycast_gateways
            or self.deleted_anycast_gateways
            or self.removed_vn_sites
        ):
            self.result["changed"] = True

        self.msg = " ".join(result_msg_list)
        self.set_operation_result("success", self.result["changed"], self.msg, "INFO")

        return self

    def process_fabric_vlans(self, fabric_vlan_details):
        """
        Processes and manages fabric VLANs in Cisco Catalyst Center by creating or updating VLAN configurations.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            fabric_vlan_details (list): A list of dictionaries containing fabric VLAN details, where each dictionary
                includes 'vlan_name', 'vlan_id', and 'fabric_site_locations'.
        Returns:
            self (object): Returns the instance of the class after processing the fabric VLANs. If VLAN creation or
                updates are performed, the function updates the class state accordingly.
        Description:
            This function processes a list of fabric VLAN details and performs necessary operations to create or update
            fabric VLANs in Cisco Catalyst Center.
            - It sends the collected payloads to create new fabric VLANs and update existing ones, ensuring the
            operation is completed successfully.
            The function manages and logs the status of each operation, including creating or updating the VLANs.
        """

        collected_add_vlan_payload, collected_update_vlan_payload = [], []

        for vlan in fabric_vlan_details:
            vlan_name = vlan.get("vlan_name")
            vlan_id = vlan.get("vlan_id")
            fabric_locations = vlan.get("fabric_site_locations")
            fabric_id_list, site_name_list = [], []
            self.log(
                "Processing VLAN '{0}' with ID '{1}'.".format(vlan_name, vlan_id),
                "INFO",
            )

            for fabric in fabric_locations:
                site_name = fabric.get("site_name_hierarchy")
                fabric_type = fabric.get("fabric_type")
                site_exists, site_id = self.get_site_id(site_name)
                if not site_exists:
                    self.msg = "Given site '{0}' does not exist in the Catalyst Center.".format(
                        site_name
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                self.log(
                    "Checking fabric type for site '{0}'.".format(site_name), "DEBUG"
                )
                if fabric_type == "fabric_site":
                    fabric_id = self.get_fabric_site_id(site_name, site_id)
                else:
                    fabric_id = self.get_fabric_zone_id(site_name, site_id)

                if not fabric_id:
                    self.msg = (
                        "Given site '{0}' is not the fabric site/zone. Please make it fabric site/zone "
                        "first to perform any layer2 fabric vlan operation in Cisco Catalyst Center."
                    ).format(site_name)
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                fabric_vlan_in_ccc = self.get_fabric_vlan_details(
                    vlan_name, vlan_id, fabric_id
                )
                if fabric_vlan_in_ccc:

                    if fabric_type == "fabric_site":
                        vlan_name_in_ccc = fabric_vlan_in_ccc.get("vlanName")
                        vlan_name_with_id_and_site = (
                            "{0} having vlan id: {1} and site: {2}".format(
                                vlan_name_in_ccc, vlan_id, site_name
                            )
                        )
                        # Check fabric VLAN needs update or not only for fabric site
                        if self.fabric_vlan_needs_update(vlan, fabric_vlan_in_ccc):
                            self.updated_fabric_vlans.append(vlan_name_with_id_and_site)
                            collected_update_vlan_payload.append(
                                self.update_payload_fabric_vlan(
                                    vlan, fabric_vlan_in_ccc, fabric_id
                                )
                            )
                            self.log(
                                "VLAN '{0}' needs to be updated.".format(vlan_name),
                                "INFO",
                            )
                        else:
                            self.no_update_fabric_vlans.append(
                                vlan_name_with_id_and_site
                            )
                            self.log(
                                "Given L2 Vlan '{0}' does not need any update".format(
                                    vlan_name_with_id_and_site
                                ),
                                "INFO",
                            )
                else:
                    self.log(
                        "Fabric ID '{0}' added for VLAN '{1}' for site {2}.".format(
                            fabric_id, vlan_name, site_name
                        ),
                        "DEBUG",
                    )
                    fabric_id_list.append(fabric_id)
                    site_name_list.append(site_name)

            if fabric_id_list:
                sites = ", ".join(site_name_list)
                vlan_name_with_id_and_site = (
                    "{0} having vlan id: {1} and site: {2}".format(
                        vlan_name, vlan_id, sites
                    )
                )
                self.log(
                    "Creating new VLAN '{0}' with fabric IDs: {1}.".format(
                        vlan_name, fabric_id_list
                    ),
                    "INFO",
                )
                self.created_fabric_vlans.append(vlan_name_with_id_and_site)
                collected_add_vlan_payload.extend(
                    self.create_payload_for_fabric_vlan(vlan, fabric_id_list)
                )

        if collected_add_vlan_payload:
            self.create_fabric_vlan(collected_add_vlan_payload).check_return_status()
            self.log("Successfully created fabric VLANs.", "INFO")

        if collected_update_vlan_payload:
            self.update_fabric_vlan(collected_update_vlan_payload)
            self.log("Successfully updated fabric VLANs.", "INFO")

        return self

    def process_virtual_networks(self, virtual_networks):
        """
        Processes Virtual Networks in Cisco Catalyst Center by creating or updating network configurations.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            virtual_networks (list): A list of dictionaries where each dictionary contains details of a virtual
              network.
        Returns:
            self (object): Returns the instance of the class after processing the virtual networks. The function updates
                the class state with the results of the operations (created, updated, or no action needed).
        Description:
            This function processes a list of virtual networks and performs necessary operations to either create or update
            the configurations in Cisco Catalyst Center. The steps are as follows:
            - Iterates over the `virtual_networks` list, extracting each VN's name (`vn_name`).
            - Checks if the given virtual network already exists in the Cisco Catalyst Center:
                - If it exists, the function retrieves the current VN configuration and checks whether an update is required.
                If so, it adds the update payload to the collection. If no update is necessary, it logs a message indicating
                no action is needed.
                - If the virtual network does not exist, the function prepares a payload for creating the virtual network
                and adds it to the creation payload collection.
            - After collecting the payloads, the function proceeds to:
                - Create any new virtual networks that were not found in the existing configuration.
                - Update any virtual networks that require changes.
            - The function logs the outcome for each virtual network and ensures that the operation status is reflected
            accordingly.
            In the event of errors or failures during the process, the function logs the issue and updates the operation
            result accordingly.
        """

        add_vn_payloads, update_vn_payloads = [], []
        for vn_details in virtual_networks:
            vn_name = vn_details.get("vn_name")
            vn_payload = {"virtualNetworkName": vn_name}
            self.log("Processing Virtual Network '{0}'.".format(vn_name), "INFO")

            if self.have.get("l3_vn_name") and vn_name in self.have.get("l3_vn_name"):
                # Given VN already present in Cisco Catalyst Center, check vn needs update or not.
                vn_in_ccc = self.get_vn_details_from_ccc(vn_name)
                vn_needs_update = self.is_vn_needs_update(vn_details, vn_in_ccc)
                if vn_needs_update:
                    self.updated_virtual_networks.append(vn_name)
                    update_vn_payloads.append(
                        self.update_payload_vn(vn_details, vn_in_ccc)
                    )
                    self.log(
                        "Virtual Network '{0}' needs to be updated.".format(vn_name),
                        "INFO",
                    )
                else:
                    # Given Virtual network doesnot need any update
                    self.no_update_virtual_networks.append(vn_name)
                    self.msg = (
                        "Given Virtual network '{0}' does not need any update".format(
                            vn_name
                        )
                    )
                    self.log(self.msg, "INFO")
                    self.result["response"] = self.msg
            else:
                self.created_virtual_networks.append(vn_name)
                vn_payload = self.create_vn_payload(vn_details)
                add_vn_payloads.append(vn_payload)
                self.log(
                    "Virtual Network '{0}' is new and will be created.".format(vn_name),
                    "INFO",
                )

        if add_vn_payloads:
            self.create_virtual_networks(add_vn_payloads).check_return_status()
            self.log("Successfully created virtual networks.", "INFO")

        if update_vn_payloads:
            self.update_virtual_networks(update_vn_payloads)
            self.log("Successfully updated virtual networks.", "INFO")

        return self

    def process_anycast_gateways(self, anycast_gateways):
        """
        Processes anycast gateways in Cisco Catalyst Center by creating or updating gateway configurations.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            anycast_gateways (list): A list of dictionaries where each dictionary contains details of an anycast gateway.
        Returns:
            self (object): Returns the instance of the class after processing the anycast gateways. The function updates
                the class state with the results of the operations (created, updated, or no action needed).
        Description:
            This function processes a list of anycast gateways and performs necessary operations to either create or update
            the configurations in Cisco Catalyst Center.
            - After collecting the payloads, the function proceeds to:
                - Add any new anycast gateways that were not found in the existing configuration.
                - Update any gateways that require changes.
            - The function logs the outcome for each anycast gateway and ensures that the operation status is reflected
            accordingly.
            In case of errors or failures during the process, the function logs the issue and updates the operation
            result as necessary.
        """

        add_anycast_payloads, update_anycast_payloads = [], []
        for anycast in anycast_gateways:
            vn_name = anycast.get("vn_name")
            ip_pool_name = anycast.get("ip_pool_name")
            site_name = anycast.get("fabric_site_location").get("site_name_hierarchy")
            site_exists, site_id = self.get_site_id(site_name)
            if not site_exists:
                self.msg = (
                    "Given site '{0}' does not exist in the Catalyst Center.".format(
                        site_name
                    )
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            fabric_type = anycast.get("fabric_site_location").get("fabric_type")

            if fabric_type == "fabric_site":
                fabric_id = self.get_fabric_site_id(site_name, site_id)
            else:
                fabric_id = self.get_fabric_zone_id(site_name, site_id)

            # Collect the gateway id with combination of vn_name, ip_pool_name and fabric id
            unique_anycast = vn_name + "_" + ip_pool_name + "_" + site_name
            anycast_details_in_ccc = self.get_anycast_gateway_details(
                vn_name, ip_pool_name, fabric_id
            )
            self.validate_gateway_payload(anycast).check_return_status()
            self.log("Processing anycast gateway: {0}".format(unique_anycast), "INFO")

            if anycast_details_in_ccc:
                # Already present in the Cisco Catalyst Center and check for update needed or not.
                gateway_needs_update = self.is_gateway_needs_update(
                    anycast, anycast_details_in_ccc
                )
                if gateway_needs_update:
                    self.updated_anycast_gateways.append(unique_anycast)
                    gateway_update_payload = self.get_anycast_gateway_update_payload(
                        anycast, anycast_details_in_ccc
                    )
                    update_anycast_payloads.append(gateway_update_payload)
                    self.log(
                        "Updated anycast gateway: {0}".format(unique_anycast), "INFO"
                    )
                else:
                    self.no_update_anycast_gateways.append(unique_anycast)
                    self.msg = "Given Anycast gateway '{0}' does not need any update in the Cisco Catalyst Center".format(
                        unique_anycast
                    )
                    self.log(self.msg, "INFO")
                    self.result["response"] = self.msg
            else:
                # Given Anycast gateways details not present in the system needs to create it
                self.created_anycast_gateways.append(unique_anycast)
                gateway_payload = self.create_anycast_payload(anycast, fabric_id)
                add_anycast_payloads.append(gateway_payload)
                self.log("Created anycast gateway: {0}".format(unique_anycast), "INFO")

        if add_anycast_payloads:
            self.add_anycast_gateways_in_system(
                add_anycast_payloads
            ).check_return_status()
            self.log(
                "Added anycast gateways: {0}".format(
                    ", ".join(self.created_anycast_gateways)
                ),
                "INFO",
            )

        if update_anycast_payloads:
            self.update_anycast_gateways_in_system(update_anycast_payloads)
            self.log(
                "Updated anycast gateways: {0}".format(
                    ", ".join(self.updated_anycast_gateways)
                ),
                "INFO",
            )

        return self

    def delete_fabric_vlan(self, fabric_vlan_details):
        """
        Deletes specified fabric VLANs from Cisco Catalyst Center based on the provided details.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            fabric_vlan_details (list): A list of dictionaries, where each dictionary contains details of a fabric VLAN
                to be deleted.
        Returns:
            self (object): Returns the instance of the class after attempting to delete the specified fabric VLANs.
                The instance maintains updated states of deleted or absent VLANs.
        Description:
            This function processes a list of fabric VLANs to be deleted from Cisco Catalyst Center. The function follows
            these steps for each VLAN:
            - If the VLAN exists, the function retrieves its ID and calls the appropriate method to delete the VLAN from
            Cisco Catalyst Center, checking the return status of the operation.
            - After processing all VLANs, the function logs a success message if any VLANs were successfully deleted.
            The function maintains lists to track deleted VLANs and absent VLANs, which can be useful for logging or
            further processing. In case of any errors or failures during the deletion process, appropriate messages
            are logged.
        """

        fabric_site_dict = {}

        for vlan in fabric_vlan_details:
            vlan_name = vlan.get("vlan_name")
            vlan_id = vlan.get("vlan_id")
            fabric_locations = vlan.get("fabric_site_locations")

            for fabric in fabric_locations:
                site_name = fabric.get("site_name_hierarchy")
                fabric_type = fabric.get("fabric_type")
                vlan_name_with_id_and_site = (
                    "{0} having vlan id: {1} and site: {2}".format(
                        vlan_name, vlan_id, site_name
                    )
                )
                site_exists, site_id = self.get_site_id(site_name)
                if not site_exists:
                    self.msg = "Given site '{0}' does not exist in the Catalyst Center.".format(
                        site_name
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                if fabric_type == "fabric_site":
                    fabric_id = self.get_fabric_site_id(site_name, site_id)
                else:
                    fabric_id = self.get_fabric_zone_id(site_name, site_id)

                if not fabric_id:
                    msg = (
                        "Given site '{0}' is not associated to given layer2 vlan '{1}' so cannot delete the "
                        "layer2 vlan from Cisco Catalyst Center."
                    ).format(site_name, vlan_name)
                    self.log(msg, "ERROR")
                    self.absent_fabric_vlans.append(vlan_name_with_id_and_site)
                    continue

                fabric_vlan_in_ccc = self.get_fabric_vlan_details(
                    vlan_name, vlan_id, fabric_id
                )
                if not fabric_vlan_in_ccc:
                    self.log(
                        "Given fabric vlan '{0}' is not present in Cisco Catalyst Center.".format(
                            vlan_name
                        ),
                        "WARNING",
                    )
                    self.absent_fabric_vlans.append(vlan_name_with_id_and_site)
                    continue

                fabric_vlan_id = fabric_vlan_in_ccc.get("id")
                if fabric_type == "fabric_site":
                    name_id_site_key = "{0}${1}${2}".format(
                        vlan_name, vlan_id, site_name
                    )
                    fabric_site_dict[name_id_site_key] = fabric_vlan_id
                else:
                    self.delete_layer2_fabric_vlan(
                        fabric_vlan_id, vlan_name_with_id_and_site
                    ).check_return_status()
                    self.log(
                        "Successfully deleted fabric VLAN '{0}' from Cisco Catalyst Center.".format(
                            vlan_name_with_id_and_site
                        ),
                        "INFO",
                    )

        for name_id_key, fabric_vlan_id in fabric_site_dict.items():
            vlan_name, vlan_id, site_name = name_id_key.split("$")
            vlan_name_with_id_and_site = "{0} having vlan id: {1} and site: {2}".format(
                vlan_name, vlan_id, site_name
            )
            self.delete_layer2_fabric_vlan(
                fabric_vlan_id, vlan_name_with_id_and_site
            ).check_return_status()
            self.log(
                "Successfully deleted fabric VLAN '{0}' from Cisco Catalyst Center.".format(
                    vlan_name_with_id_and_site
                ),
                "INFO",
            )

        if self.deleted_fabric_vlans:
            self.log(
                "Given VLAN(s) '{0}' deleted successfully from the Cisco Catalyst Center".format(
                    self.deleted_fabric_vlans
                ),
                "INFO",
            )

        return self

    def delete_virtual_network(self, virtual_network_details):
        """
        Deletes specified Virtual Networks from Cisco Catalyst Center based on the provided details.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            virtual_network_details (list): A list of dictionaries, where each dictionary contains details of a virtual
                network to be deleted.
        Returns:
            self (object): Returns the instance of the class after attempting to delete the specified virtual networks.
                The instance maintains updated states of deleted or absent virtual networks.
        Description:
            This function processes a list of virtual networks to be deleted from Cisco Catalyst Center. The function
            performs the following steps for each network:
            - Iterates over the `virtual_network_details` list to extract the `vn_name`.
            - Checks if the virtual network name exists in the `self.have` dictionary, indicating that it is currently
            present in Cisco Catalyst Center.
            - If the network exists, the function retrieves its ID using the `get_vn_details_from_ccc` method and then
            calls the method to delete the Layer3 virtual network, checking the return status of the operation.
            - If the virtual network is not found in the current configurations, the function logs an informational message
            and adds the network name to the list of absent virtual networks.
            - After processing all networks, the function logs a success message if any networks were successfully deleted.

            The function effectively tracks the success of the delete operations and logs appropriate messages for any
            networks that could not be found in the Cisco Catalyst Center, ensuring a clear audit trail of actions taken.
        """

        for vn in virtual_network_details:
            vn_name = vn.get("vn_name")
            # If site details are given in the input then we should operate on site only not delete the vn
            fabric_locations = vn.get("fabric_site_locations")
            vn_in_ccc = self.get_vn_details_from_ccc(vn_name)
            if not vn_in_ccc:
                self.log(
                    "Given Virtual network '{0}' is not present in Cisco Catalyst Center.".format(
                        vn_name
                    ),
                    "INFO",
                )
                self.absent_virtual_networks.append(vn_name)
                continue

            if fabric_locations:
                removed_vn_site_list = []
                self.log(
                    "Retrieving fabric IDs for locations: {0}".format(fabric_locations),
                    "DEBUG",
                )
                fabric_ids = self.get_fabric_ids(fabric_locations)
                if not fabric_ids:
                    self.absent_virtual_networks.append(vn_name + " with fabric sites: " + str(fabric_locations))
                    self.log(
                        "No fabric IDs found for the provided locations so cannot remove any site.",
                        "WARNING",
                    )
                    continue

                fabric_ids_in_ccc = vn_in_ccc.get("fabricIds")
                if not fabric_ids_in_ccc:
                    self.absent_virtual_networks.append(vn_name + " with fabric sites: " + str(fabric_locations))
                    self.log(
                        "No fabric IDs found in the Catalyst Center for the VN {0} against "
                        "the fabric_ids: {1}".format(vn_name, fabric_ids),
                        "WARNING",
                    )
                    continue

                anchor_site = vn_in_ccc.get("anchoredSiteId")
                if anchor_site:
                    # We cannot remove the anchored site id if subscriber sites are there
                    if fabric_ids[0] == anchor_site and len(fabric_ids) == 1:
                        if len(vn_in_ccc.get("fabricIds")) > 1:
                            self.msg = (
                                "Given Anchored VN '{0}' contains the subscriber sites, so in order to delete the main site, "
                                "please remove the subscriber sites."
                            ).format(vn_name)
                            self.fail_and_exit(self.msg)

                        removed_vn_site_list.append(fabric_ids[0])
                        self.log(
                            "Only anchored site associated with the virtual network {0} so removing it as well.".format(
                                vn_name
                            ),
                            "INFO",
                        )
                        vn_in_ccc["anchoredSiteId"] = ""
                        vn_in_ccc["fabricIds"] = [anchor_site]
                        self.update_virtual_networks([vn_in_ccc]).check_return_status()
                        self.delete_layer3_virtual_network(vn_name, vn_in_ccc.get("id"))
                        if self.status == "failed" and "task tree" in self.msg:
                            task_id = self.msg.split(":")[1].split(".")[0].lstrip()
                            failure_reason = self.get_task_tree_failure_reasons(task_id)
                            self.msg = "Unable to delele the virtual network {0} because of: {1}".format(
                                vn_name, failure_reason
                            )
                            self.log(self.msg, "WARNING")
                            self.fail_and_exit(self.msg)
                        continue

                    for fabric_id in fabric_ids:
                        if fabric_id != anchor_site and fabric_id in fabric_ids_in_ccc:
                            self.log(
                                "Removing fabric id '{0}' from the virtual network {1} update payload".format(
                                    fabric_id, vn_name
                                ),
                                "DEBUG",
                            )
                            fabric_ids_in_ccc.remove(fabric_id)
                            removed_vn_site_list.append(fabric_id)

                    vn_in_ccc["fabricIds"] = fabric_ids_in_ccc

                    self.update_virtual_networks([vn_in_ccc]).check_return_status()
                    self.log(
                        "Given fabric site(s) '{0}' removed successfully from the virtual network {1}".format(
                            fabric_locations, vn_name
                        ),
                        "INFO",
                    )
                    self.removed_vn_sites.append(
                        vn_name + ": " + str(removed_vn_site_list)
                    )
                    continue

                self.log(
                    "Handling the check of removing the subsciber site(s) extending the vn {0}".format(
                        vn_name
                    ),
                    "DEBUG",
                )
                self.log(
                    "Checking given fabric id is present in Cisco Catalyst Center and if present then remove from the payload.",
                    "DEBUG",
                )
                for fabric_id in fabric_ids:
                    if fabric_id in fabric_ids_in_ccc:
                        self.log(
                            "Removing fabric id '{0}' from the virtual network {1} update payload".format(
                                fabric_id, vn_name
                            ),
                            "DEBUG",
                        )
                        removed_vn_site_list.append(fabric_id)
                        fabric_ids_in_ccc.remove(fabric_id)

                self.removed_vn_sites.append(
                    vn_name + ": " + str(removed_vn_site_list)
                )
                vn_in_ccc["fabricIds"] = fabric_ids_in_ccc
                # Call the update API to remove the fabric sites from the given virtual network
                self.update_virtual_networks([vn_in_ccc]).check_return_status()
                self.log(
                    "Given fabric site(s) '{0}' removed successfully from the virtual network {1}".format(
                        fabric_locations, vn_name
                    ),
                    "INFO",
                )
                continue

            if vn_name in ["DEFAULT_VN", "INFRA_VN"]:
                self.log(
                    "Given VN '{0}' are not applicable for deletion as it comes with system.".format(
                        vn_name
                    ),
                    "WARNING",
                )
                continue

            if self.have.get("l3_vn_name") and vn_name in self.have.get("l3_vn_name"):
                vn_in_ccc = self.get_vn_details_from_ccc(vn_name)
                vn_id = vn_in_ccc.get("id")
                anchored_fabric_id = vn_in_ccc.get("anchoredSiteId")

                if anchored_fabric_id and len(vn_in_ccc.get("fabricIds")) > 1:
                    update_vn_payload = {
                        "id": vn_in_ccc.get("id"),
                        "virtualNetworkName": vn_name,
                        "anchoredSiteId": anchored_fabric_id,
                        "fabricIds": [anchored_fabric_id],
                    }
                    self.log(
                        "Virtual Network '{0}' is anchored and extended to multiple fabric sites. "
                        "Initiating removal of extended fabric sites.".format(vn_name),
                        "INFO",
                    )
                    self.update_virtual_networks(
                        [update_vn_payload]
                    ).check_return_status()
                    self.log(
                        "Successfully removed the extended fabric sites for the virtual network {0}.".format(
                            vn_name
                        ),
                        "INFO",
                    )
                    self.log(
                        "Successfully removed extended fabric sites for Virtual Network '{0}'. "
                        "Now it is only anchored to its primary fabric site.".format(
                            vn_name
                        ),
                        "INFO",
                    )

                self.delete_layer3_virtual_network(vn_name, vn_id)
                if self.status == "failed" and "task tree" in self.msg:
                    task_id = self.msg.split(":")[1].split(".")[0].lstrip()
                    failure_reason = self.get_task_tree_failure_reasons(task_id)
                    self.msg = "Unable to delele the virtual network {0} because of: {1}".format(
                        vn_name, failure_reason
                    )
                    self.log(self.msg, "WARNING")
                    self.fail_and_exit(self.msg)

                self.log(
                    "Successfully deleted virtual network '{0}' from Cisco Catalyst Center.".format(
                        vn_name
                    ),
                    "INFO",
                )

        if self.deleted_virtual_networks:
            self.log(
                "Given Virtual Network(s) '{0}' deleted successfully from the Cisco Catalyst Center".format(
                    self.deleted_virtual_networks
                ),
                "INFO",
            )

        return self

    def delete_anycast_gateway_from_ccc(self, anycast_gateways):
        """
        Deletes specified anycast gateways from Cisco Catalyst Center based on the provided details.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            anycast_gateways (list): A list of dictionaries, where each dictionary contains details of an
                anycast gateway to be deleted.
        Returns:
            self (object): Returns the instance of the class after attempting to delete the specified anycast gateways.
                The instance maintains updated states of deleted or absent anycast gateways.
        Description:
            This function processes a list of anycast gateways to be deleted from the Cisco Catalyst Center. For each
            anycast gateway specified in `anycast_gateways`, the function performs the following steps:
            - Extracts the `vn_name`, `ip_pool_name`, and `site_name` from each dictionary.
            - Checks for the existence of the site and retrieves its ID using `get_site_id`.
            - Determines the fabric ID based on the `fabric_type` (either fabric site or fabric zone).
            - Retrieves the existing anycast gateway details from the Cisco Catalyst Center.
            - If the anycast gateway is not found, it logs an informational message and adds the unique identifier to the
            list of absent anycast gateways.
            - Finally, after processing all gateways, it logs a success message if any gateways were successfully deleted.

            This function effectively manages the deletion of anycast gateways and maintains logs for both successful
            deletions and any gateways that could not be found, ensuring clarity and traceability of actions taken within
            the Cisco Catalyst Center.
        """
        self.log("Starting the process to delete anycast gateways from Cisco Catalyst Center.", "INFO")
        anchored_gateway_dict = {}

        for anycast in anycast_gateways:
            vn_name = anycast.get("vn_name")
            ip_pool_name = anycast.get("ip_pool_name")
            site_name = anycast.get("fabric_site_location").get("site_name_hierarchy")
            site_exists, site_id = self.get_site_id(site_name)
            if not site_exists:
                self.msg = (
                    "Given site '{0}' does not exist in the Catalyst Center.".format(
                        site_name
                    )
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            fabric_type = anycast.get("fabric_site_location").get("fabric_type")
            self.log(
                f"Processing Anycast Gateway: VN='{vn_name}', IP Pool='{ip_pool_name}', "
                f"Site='{site_name}', Fabric Type='{fabric_type}'.",
                "DEBUG",
            )

            if fabric_type == "fabric_site":
                fabric_id = self.get_fabric_site_id(site_name, site_id)
            else:
                fabric_id = self.get_fabric_zone_id(site_name, site_id)

            # Collect the gateway id with combination of vn_name, ip_pool_name and fabric id
            unique_anycast = vn_name + "_" + ip_pool_name + "_" + site_name
            if not fabric_id:
                self.absent_anycast_gateways.append(unique_anycast)
                self.log(
                    f"Anycast Gateway '{unique_anycast}' is not associated with a valid Fabric ID in the Catalyst Center. "
                    f"Fabric Type: '{fabric_type}', Site: '{site_name}'. Skipping deletion.",
                    "INFO",
                )
                continue

            self.log(
                f"Checking if IP Pool '{ip_pool_name}' exists in site '{site_name}' (Fabric Type: {fabric_type}).",
                "DEBUG",
            )
            is_pool_exist = self.is_ip_pool_exist(ip_pool_name, site_id)
            self.log(
                "Checking if given ip pool '{0}' already deleted from the Cisco Catalyst Center "
                "to depict the idempotency behaviour.".format(ip_pool_name),
                "DEBUG",
            )
            if not is_pool_exist:
                self.log(
                    "IP pool '{0}' is not present in Cisco Catalyst Center.".format(
                        ip_pool_name
                    ),
                    "INFO",
                )
                self.absent_anycast_gateways.append(unique_anycast)
                continue

            anycast_details_in_ccc = self.get_anycast_gateway_details(
                vn_name, ip_pool_name, fabric_id
            )

            if not anycast_details_in_ccc:
                self.absent_anycast_gateways.append(unique_anycast)
                self.log(
                    "Given Anycast gateway '{0}' is not present in Cisco Catalyst Center.".format(
                        unique_anycast
                    ),
                    "INFO",
                )
                continue

            gateway_id = anycast_details_in_ccc.get("id")
            self.log(
                "Checking if Anycast Gateway '{0}' is associated with an anchored VN."
                "If it is, sites extending the anchored VN will be deleted first, then the gateway "
                "itself.".format(unique_anycast),
                "DEBUG",
            )
            vn_in_ccc = self.get_vn_details_from_ccc(vn_name)
            anchored_fabric_id = vn_in_ccc.get("anchoredSiteId")

            if anchored_fabric_id and anchored_fabric_id == fabric_id:
                self.log(
                    "Anycast Gateway '{0}' is extending the anchored VN '{1}'. "
                    "It will be deleted at the end.".format(unique_anycast, vn_name),
                    "INFO",
                )
                anchored_gateway_dict[unique_anycast] = gateway_id
                continue

            self.delete_anycast_gateway(
                gateway_id, unique_anycast
            ).check_return_status()

        if anchored_gateway_dict:
            self.log(
                "Anycast Gateway(s) associated with an anchored VN are available for deletion.",
                "DEBUG",
            )

            for gateway_name, gateway_id in anchored_gateway_dict.items():
                self.log(
                    "Deleting Anycast Gateway '{0}' associated with the anchored VN's main site.".format(
                        gateway_name
                    ),
                    "INFO",
                )
                self.delete_anycast_gateway(
                    gateway_id, gateway_name
                ).check_return_status()

        if self.deleted_anycast_gateways:
            self.log(
                "Given Anycast Gateway(s) '{0}' deleted successfully from the Cisco Catalyst Center.".format(
                    self.deleted_anycast_gateways
                ),
                "INFO",
            )

        return self

    def verify_fabric_vlan(self, fabric_vlan_details):
        """
        Verifies the presence of specified fabric VLANs in Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            fabric_vlan_details (list): A list of dictionaries, where each dictionary contains details of
                a fabric VLAN to be verified.
        Returns:
            self (object): Returns the instance of the class after verifying the fabric VLANs, along with logging
                the results of the verification process.
        Description:
            This function serves to ensure that fabric VLAN configurations are accurately represented in the Cisco
            Catalyst Center, providing essential feedback for operational integrity and consistency.
        """

        verify_vlan_list, missed_vlan_list = [], []
        for vlan in fabric_vlan_details:
            vlan_name = vlan.get("vlan_name")
            vlan_id = vlan.get("vlan_id")
            fabric_locations = vlan.get("fabric_site_locations")
            for fabric in fabric_locations:
                site_name = fabric.get("site_name_hierarchy")
                fabric_type = fabric.get("fabric_type")
                site_exists, site_id = self.get_site_id(site_name)
                if not site_exists:
                    self.msg = "Given site '{0}' does not exist in the Catalyst Center.".format(
                        site_name
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                if fabric_type == "fabric_site":
                    fabric_id = self.get_fabric_site_id(site_name, site_id)
                else:
                    fabric_id = self.get_fabric_zone_id(site_name, site_id)

                fabric_vlan_in_ccc = self.get_fabric_vlan_details(
                    vlan_name, vlan_id, fabric_id
                )
                if fabric_vlan_in_ccc:
                    verify_vlan_list.append(vlan_name)
                else:
                    missed_vlan_list.append(vlan_name)

        if not missed_vlan_list:
            msg = (
                "Requested fabric Vlan(s) '{0}' have been successfully added/updated to the Cisco Catalyst Center "
                "and their addition/updation has been verified."
            ).format(verify_vlan_list)
        else:
            msg = (
                "Playbook's input does not match with Cisco Catalyst Center, indicating that the fabric Vlan(s) '{0}' "
                " addition/updation task may not have executed successfully."
            ).format(missed_vlan_list)

        self.log(msg, "INFO")

        return self

    def verify_virtual_network(self, virtual_networks):
        """
        Verifies the presence of specified Layer3 virtual networks in Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            virtual_networks (list): A list of dictionaries, where each dictionary contains details of a layer3
                virtual network to be verified.
        Returns:
            self (object): Returns the instance of the class after verifying the Layer3 virtual networks, along
                with logging the results of the verification process.
        Description:
            This function serves to ensure that Layer3 virtual network configurations are accurately represented
            in the Cisco Catalyst Center, providing essential feedback for operational integrity and consistency.
        """

        verify_vn_list, missed_vn_list = [], []

        for vn_details in virtual_networks:
            vn_name = vn_details.get("vn_name")

            if self.have.get("l3_vn_name") and vn_name in self.have.get("l3_vn_name"):
                verify_vn_list.append(vn_name)
            else:
                missed_vn_list.append(vn_name)

        if not missed_vn_list:
            msg = (
                "Requested layer3 Virtual Network(s) '{0}' have been successfully added/updated to the Cisco Catalyst Center "
                "and their addition/updation has been verified."
            ).format(verify_vn_list)
        else:
            msg = (
                "Playbook's input does not match with Cisco Catalyst Center, indicating that the fabric Vlan(s) '{0}' "
                " addition/updation task may not have executed successfully."
            ).format(missed_vn_list)

        self.log(msg, "INFO")

        return self

    def verify_anycast_gateway(self, anycast_gateways):
        """
        Verifies the presence of specified Anycast gateways in Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            anycast_gateways (list): A list of dictionaries, where each dictionary contains details of an Anycast
                gateway to be verified.
        Returns:
            self (object): Returns the instance of the class after verifying the Anycast gateways, along with
                logging the results of the verification process.
        Description:
            This function serves to ensure that Anycast gateway configurations are accurately represented in the
            Cisco Catalyst Center, providing essential feedback for operational integrity and consistency.
        """

        verify_anycast_list, missed_anycast_list = [], []
        for anycast in anycast_gateways:
            vn_name = anycast.get("vn_name")
            ip_pool_name = anycast.get("ip_pool_name")
            site_name = anycast.get("fabric_site_location").get("site_name_hierarchy")
            site_exists, site_id = self.get_site_id(site_name)
            if not site_exists:
                self.msg = (
                    "Given site '{0}' does not exist in the Catalyst Center.".format(
                        site_name
                    )
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            fabric_type = anycast.get("fabric_site_location").get("fabric_type")

            if fabric_type == "fabric_site":
                fabric_id = self.get_fabric_site_id(site_name, site_id)
            else:
                fabric_id = self.get_fabric_zone_id(site_name, site_id)

            # Collect the gateway id with combination of vn_name, ip_pool_name and fabric id
            unique_anycast = vn_name + "_" + ip_pool_name + "_" + site_name
            anycast_details_in_ccc = self.get_anycast_gateway_details(
                vn_name, ip_pool_name, fabric_id
            )

            if anycast_details_in_ccc:
                verify_anycast_list.append(unique_anycast)
            else:
                missed_anycast_list.append(unique_anycast)

        if not missed_anycast_list:
            msg = (
                "Requested Anycast Gateway(s) '{0}' have been successfully added/updated to the Cisco Catalyst Center "
                "and their addition/updation has been verified."
            ).format(verify_anycast_list)
        else:
            msg = (
                "Playbook's input does not match with Cisco Catalyst Center, indicating that the Anycast Gateway(s) '{0}' "
                " addition/updation task may not have executed successfully."
            ).format(missed_anycast_list)

        self.log(msg, "INFO")

        return self

    def verify_vlan_deletion(self, fabric_vlan_details):
        """
        Verifies the deletion of specified VLANs from the Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            fabric_vlan_details (list): A list of dictionaries, where each dictionary contains details of
                a fabric VLAN to be verified for deletion.
        Returns:
            self (object): Returns the instance of the class after verifying the deletion of the fabric VLANs,
                along with logging the results of the verification process.
        Description:
            This function serves to ensure that VLAN deletion operations are accurately reflected in the Cisco
            Catalyst Center, providing essential feedback for operational integrity and consistency.
        """

        verify_vlan_list, missed_vlan_list = [], []
        for vlan in fabric_vlan_details:
            vlan_name = vlan.get("vlan_name")
            vlan_id = vlan.get("vlan_id")
            fabric_locations = vlan.get("fabric_site_locations")

            for fabric in fabric_locations:
                site_name = fabric.get("site_name_hierarchy")
                fabric_type = fabric.get("fabric_type")
                site_exists, site_id = self.get_site_id(site_name)
                if not site_exists:
                    self.msg = "Given site '{0}' does not exist in the Catalyst Center.".format(
                        site_name
                    )
                    self.set_operation_result(
                        "failed", False, self.msg, "ERROR"
                    ).check_return_status()

                if fabric_type == "fabric_site":
                    fabric_id = self.get_fabric_site_id(site_name, site_id)
                else:
                    fabric_id = self.get_fabric_zone_id(site_name, site_id)

                fabric_vlan_in_ccc = self.get_fabric_vlan_details(
                    vlan_name, vlan_id, fabric_id
                )
                if not fabric_vlan_in_ccc:
                    verify_vlan_list.append(vlan_name)
                else:
                    missed_vlan_list.append(vlan_name)

        if verify_vlan_list:
            msg = (
                "Requested fabric Vlan(s) '{0}' have been successfully deleted from the Cisco Catalyst "
                "Center and their deletion has been verified."
            ).format(verify_vlan_list)
        else:
            msg = (
                "Playbook's input does not match with Cisco Catalyst Center, indicating that fabric Vlan(s)"
                " '{0}' deletion task may not have executed successfully."
            ).format(missed_vlan_list)

        self.log(msg, "INFO")

        return self

    def verify_virtual_network_deletion(self, virtual_network_details):
        """
        Verifies the deletion of specified Layer 3 Virtual Networks from the Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for managing resources in the Cisco Catalyst Center.
            virtual_network_details (list): A list of dictionaries, where each dictionary contains details of
                a Layer 3 Virtual Network to be verified for deletion.
        Returns:
            self (object): Returns the instance of the class after verifying the deletion of the Layer3
                Virtual Networks, along with logging the results of the verification process.
        Description:
            This function serves to ensure that Layer 3 Virtual Network deletion operations are accurately
            reflected in the Cisco Catalyst Center, providing essential feedback for operational integrity and
            consistency.
        """

        verify_vn_list, missed_vn_list = [], []
        for vn in virtual_network_details:
            vn_name = vn.get("vn_name")

            if self.have.get("l3_vn_name") and vn_name in self.have.get("l3_vn_name"):
                missed_vn_list.append(vn_name)
            else:
                verify_vn_list.append(vn_name)

        if verify_vn_list:
            self.status = "success"
            msg = (
                "Requested layer3 Virtual Network(s) '{0}' have been successfully deleted from the Cisco "
                "Catalyst Center and their deletion has been verified."
            ).format(verify_vn_list)
        else:
            msg = (
                "Playbook's input does not match with Cisco Catalyst Center, indicating that layer3 Virtual"
                "  Network(s) '{0}' deletion task may not have executed successfully."
            ).format(missed_vn_list)

        self.log(msg, "INFO")

        return self

    def verify_anycast_gateways_deletion(self, anycast_gateways):
        """
        Verifies the deletion of specified Anycast Gateways from the Cisco Catalyst Center.

        Args:
            self (object): An instance of a class used for managing resources in the Cisco Catalyst Center.
            anycast_gateways (list): A list of dictionaries, where each dictionary contains details of
                an Anycast Gateway to be verified for deletion.
        Returns:
            self (object): Returns the instance of the class after verifying the deletion of the Anycast
                Gateways, along with logging the results of the verification process.
        Description:
            This function serves to ensure that Anycast Gateway deletion operations are accurately reflected
            in the Cisco Catalyst Center, providing essential feedback for operational integrity and
            consistency.
        """

        verify_anycast_list, missed_anycast_list = [], []
        for anycast in anycast_gateways:
            vn_name = anycast.get("vn_name")
            ip_pool_name = anycast.get("ip_pool_name")
            site_name = anycast.get("fabric_site_location").get("site_name_hierarchy")
            site_exists, site_id = self.get_site_id(site_name)
            if not site_exists:
                self.msg = (
                    "Given site '{0}' does not exist in the Catalyst Center.".format(
                        site_name
                    )
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            fabric_type = anycast.get("fabric_site_location").get("fabric_type")

            if fabric_type == "fabric_site":
                fabric_id = self.get_fabric_site_id(site_name, site_id)
            else:
                fabric_id = self.get_fabric_zone_id(site_name, site_id)

            # Collect the gateway id with combination of vn_name, ip_pool_name and fabric id
            unique_anycast = vn_name + "_" + ip_pool_name + "_" + site_name
            anycast_details_in_ccc = self.get_anycast_gateway_details(
                vn_name, ip_pool_name, fabric_id
            )

            if not anycast_details_in_ccc:
                verify_anycast_list.append(unique_anycast)
                continue
            missed_anycast_list.append(unique_anycast)

        if verify_anycast_list:
            self.status = "success"
            msg = (
                "Requested Anycast Gateway(s) '{0}' have been successfully deleted from the Cisco "
                "Catalyst Center and their deletion has been verified."
            ).format(verify_anycast_list)
        else:
            msg = (
                "Playbook's input does not match with Cisco Catalyst Center, indicating that Anycast "
                " Gateway(s) '{0}' deletion task may not have executed successfully."
            ).format(missed_anycast_list)

        self.log(msg, "INFO")

        return self

    def get_diff_merged(self, config):
        """
        Creates or updates fabric VLANs, virtual networks, and Anycast gateways in the Cisco Catalyst Center
        based on the provided configuration.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing the configuration details for fabric VLANs, virtual networks,
                        and Anycast gateways. The structure includes:
                - 'fabric_vlan': List of dictionaries with details about fabric VLANs.
                - 'virtual_networks': List of dictionaries with details about virtual networks.
                - 'anycast_gateways': List of dictionaries with details about Anycast gateways.
        Returns:
            self (object): Returns the current instance of the class with updated attributes for created,
                        updated, and no-update status of VLANs, virtual networks, and Anycast gateways.
        Description:
            This method processes the configuration to perform the following tasks:
            - Create or update fabric VLANs based on the provided details. It checks for existing VLANs and
            determines if updates are necessary. Newly created VLANs are collected for later processing.
            - Create or update Layer 3 virtual networks. It checks for existing networks and evaluates if
            updates are required, collecting information on both newly created and updated networks.
            - Create or update Anycast gateways. The method checks if Anycast gateways already exist, evaluates
            whether they need updating, and collects payloads for creation or updates as necessary.
        """

        # Create/Update fabric Vlan in Cisco Catalyst Center
        fabric_vlan_details = config.get("fabric_vlan")
        if fabric_vlan_details:
            self.process_fabric_vlans(fabric_vlan_details).check_return_status()

        # Create/Update virtual network in Cisco Catalyst Center
        virtual_networks = config.get("virtual_networks")
        if virtual_networks:
            self.process_virtual_networks(virtual_networks).check_return_status()

        # Create/Update Anycast gateway in Cisco Catalyst Center with fabric id, ip pool and vn name
        anycast_gateways = config.get("anycast_gateways")
        if anycast_gateways:
            self.process_anycast_gateways(anycast_gateways).check_return_status()

        self.log("Completed the creation/updation process for specified items.", "INFO")

        return self

    def get_diff_deleted(self, config):
        """
        Deletes specified layer2 fabric VLANs, layer3 virtual networks, and Anycast gateways from the Cisco Catalyst
        Center based on the provided configuration.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): A dictionary containing configuration details for deleting fabric VLANs, virtual networks,
                        and Anycast gateways. The structure includes:
                - 'fabric_vlan': List of dictionaries with details about fabric VLANs to delete.
                - 'virtual_networks': List of dictionaries with details about virtual networks to delete.
                - 'anycast_gateways': List of dictionaries with details about Anycast gateways to delete.
        Returns:
            self (object): Returns the current instance of the class after attempting to delete the specified items.
        Description:
            This method processes the provided configuration to perform the following deletion tasks:
            - For each specified layer2 fabric VLAN, it checks if the VLAN is associated with the given fabric site or zone.
            If so, it deletes the VLAN from the Cisco Catalyst Center. If the VLAN does not exist, it logs a warning and
            adds the VLAN name to the `absent_fabric_vlans` list.
            - For each specified layer3 virtual network, it checks if the network exists in the Cisco Catalyst Center. If
            present, it deletes the virtual network. If not, it logs an informational message and adds the network name
            to the `absent_virtual_networks` list.
            - For each specified Anycast gateway, it retrieves the corresponding gateway ID and deletes the gateway if it exists.
            If the gateway is not found, it logs an informational message and adds the unique identifier of the gateway to
            the `absent_anycast_gateways` list.
        """

        # Verify the deletion of layer2 Fabric Vlan from the Cisco Catalyst Center
        fabric_vlan_details = config.get("fabric_vlan")
        if fabric_vlan_details:
            self.delete_fabric_vlan(fabric_vlan_details)
        else:
            self.log("No fabric VLANs to delete.", "DEBUG")

        # Need ID of the anycast gateway to delete the anycast gateway
        anycast_gateways = config.get("anycast_gateways")
        if anycast_gateways:
            self.delete_anycast_gateway_from_ccc(anycast_gateways)
        else:
            self.log("No Anycast gateways to delete.", "INFO")

        # Delete layer3 Virtual network from the Cisco Catalyst Center
        virtual_network_details = config.get("virtual_networks")
        if virtual_network_details:
            self.delete_virtual_network(virtual_network_details)
        else:
            self.log("No Virtual Networks to delete.", "DEBUG")

        self.log("Completed the deletion process for specified items.", "INFO")

        return self

    def verify_diff_merged(self, config):
        """
        Verify the addition/update status of fabric Vlan, layer3 Virtual Networks and
        Anycast Gateway(s) in teh Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration details to be verified.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method verifies whether the specified configurations have been successfully added/updated
            in Cisco Catalyst Center as desired.
        """

        self.get_have(config)
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        # Verify the creation/updation of fabric Vlan in the Cisco Catalyst Center
        fabric_vlan_details = config.get("fabric_vlan")
        if fabric_vlan_details:
            self.verify_fabric_vlan(fabric_vlan_details)
        else:
            self.log("No fabric VLAN details provided for verification.", "DEBUG")

        # Verify the creation/updation of layer3 Virtual Network in the Cisco Catalyst Center
        virtual_networks = config.get("virtual_networks")
        if virtual_networks:
            self.verify_virtual_network(virtual_networks)
        else:
            self.log(
                "No layer3 Virtual Network details provided for verification.", "DEBUG"
            )

        # Verify the creation/updation of Anycast gateway in the Cisco Catalyst Center with fabric id, ip pool and vn name
        anycast_gateways = config.get("anycast_gateways")
        if anycast_gateways:
            self.verify_anycast_gateway(anycast_gateways)
        else:
            self.log("No Anycast Gateway details provided for verification.", "DEBUG")

        return self

    def verify_diff_deleted(self, config):
        """
        Verify the deletion status of fabric sites/zones fromt the Cisco Catalyst Center.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration details to be verified.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks the deletion status of a configuration in Cisco Catalyst Center.
            It validates whether the specified fabric Vlan(s), layer3 Virtual Network(s) or
            Anycast Gateway(s) deleted from Cisco Catalyst Center and verified it.
        """

        self.get_have(config)
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        # Verify the deletion of layer2 Fabric Vlan from the Cisco Catalyst Center
        fabric_vlan_details = config.get("fabric_vlan")
        if fabric_vlan_details:
            self.verify_vlan_deletion(fabric_vlan_details)
        else:
            self.log("No fabric VLAN details provided for verification.", "DEBUG")

        # Verify the deletion of layer3 Virtual Network from the Cisco Catalyst Center
        virtual_network_details = config.get("virtual_networks")
        if virtual_network_details:
            self.verify_virtual_network_deletion(virtual_network_details)
        else:
            self.log(
                "No layer3 Virtual Network details provided for verification.", "DEBUG"
            )

        # Verify the deletion of Anycast gateway from the Cisco Catalyst Center
        anycast_gateways = config.get("anycast_gateways")
        if anycast_gateways:
            self.verify_anycast_gateways_deletion(anycast_gateways)
        else:
            self.log("No Anycast Gateway details provided for verification.", "DEBUG")

        return self


def main():
    """main entry point for module execution"""

    element_spec = {
        "dnac_host": {"required": True, "type": "str"},
        "dnac_port": {"type": "str", "default": "443"},
        "dnac_username": {"type": "str", "default": "admin", "aliases": ["user"]},
        "dnac_password": {"type": "str", "no_log": True},
        "dnac_verify": {"type": "bool", "default": "True"},
        "dnac_version": {"type": "str", "default": "2.2.3.3"},
        "dnac_debug": {"type": "bool", "default": False},
        "dnac_log_level": {"type": "str", "default": "WARNING"},
        "dnac_log_file_path": {"type": "str", "default": "dnac.log"},
        "dnac_log_append": {"type": "bool", "default": True},
        "dnac_log": {"type": "bool", "default": False},
        "validate_response_schema": {"type": "bool", "default": True},
        "config_verify": {"type": "bool", "default": False},
        "sda_fabric_vlan_limit": {"type": "int", "default": 20},
        "sda_fabric_gateway_limit": {"type": "int", "default": 20},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"required": True, "type": "list", "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged", "deleted"]},
    }

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)

    # Initialize the Virtual Network object
    ccc_virtual_network = VirtualNetwork(module)
    if (
        ccc_virtual_network.compare_dnac_versions(
            ccc_virtual_network.get_ccc_version(), "2.3.7.6"
        )
        < 0
    ):
        ccc_virtual_network.msg = (
            "The specified version '{0}' does not support the SDA fabric devices feature. Supported versions start "
            "  from '2.3.7.6' onwards. Version '2.3.7.6' introduces APIs for creating, updating and deleting the "
            "Fabric VLAN, Virtual Networks and Anycast Gateways.".format(
                ccc_virtual_network.get_ccc_version()
            )
        )
        ccc_virtual_network.set_operation_result(
            "failed", False, ccc_virtual_network.msg, "ERROR"
        ).check_return_status()

    state = ccc_virtual_network.params.get("state")

    # Validate the provided state
    if state not in ccc_virtual_network.supported_states:
        ccc_virtual_network.status = "invalid"
        ccc_virtual_network.msg = "State {0} is invalid".format(state)
        ccc_virtual_network.check_return_status()

    # Validate input parameters
    ccc_virtual_network.validate_input().check_return_status()
    config_verify = ccc_virtual_network.params.get("config_verify")

    # Process each configuration
    for config in ccc_virtual_network.validated_config:
        ccc_virtual_network.reset_values()
        ccc_virtual_network.get_want(config).check_return_status()
        ccc_virtual_network.get_have(config).check_return_status()
        ccc_virtual_network.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_virtual_network.verify_diff_state_apply[state](
                config
            ).check_return_status()

    # Invoke the API to check status and log the output of each fabric VLAN, virtual network, and
    # anycast gateways update on the console.
    ccc_virtual_network.update_fabric_vlan_vn_anycast_gateway_messages().check_return_status()

    # Exit the module with the results
    module.exit_json(**ccc_virtual_network.result)


if __name__ == "__main__":
    main()
