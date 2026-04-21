Ansible Network Collection for Enterprise SONiC Distribution by Dell Technologies
=================================================================================

This collection includes Ansible core modules, network resource modules, and plugins needed to provision and manage Dell EMC PowerSwitch platforms running Enterprise SONiC Distribution by Dell Technologies. Sample playbooks and documentation are also included to show how the collection can be used.

Supported connections
---------------------
The SONiC Ansible collection supports network_cli and httpapi connections.

Plugins
--------
**CLICONF plugin**

Name | Description
--- | ---
[network_cli](https://github.com/ansible-collections/dellemc.enterprise_sonic)|Use Ansible CLICONF to run commands on Enterprise SONiC

**HTTPAPI plugin**

Name | Description
--- | ---
[httpapi](https://github.com/ansible-collections/dellemc.enterprise_sonic)|Use Ansible HTTPAPI to run commands on Enterprise SONiC

Collection core modules
------------------------
Name | Description | Connection type
--- | --- | ---
[**sonic_command**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_command/)|Run commands through the Management Framework CLI|network_cli
[**sonic_config**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_config)|Manage configuration through the Management Framework CLI|network_cli
[**sonic_api**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_api)|Perform REST operations through the Management Framework REST API|httpapi
[**sonic_api**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_facts)|Collect "facts" (configuration) in argspec format for selected modules|httpapi

Collection network resource modules
-----------------------------------
Listed are the SONiC Ansible network resource modules which need ***httpapi*** as the connection type. Supported operations are ***merged***, ***deleted***, ***replaced*** and ***overridden***.

Name | Description
--- | ---
[**sonic_aaa**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_aaa)| Manage AAA and its parameters
[**sonic_acl_interfaces**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_acl_interfaces)| Manage access control list (ACL) to interface binding
[**sonic_ars**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_ars)| Manage adaptive routing and switching (ARS) configuration on SONiC
[**sonic_bfd**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_bfd)| Manage BFD configuration
[**sonic_bgp**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_bgp)| Manage global BGP and its parameters
[**sonic_bgp_af**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_bgp_af)| Manage global BGP address-family and its parameters
[**sonic_bgp_as_paths**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_bgp_as_paths)| Manage BGP autonomous system path (or as-path-list) and its parameters
[**sonic_bgp_communities**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_bgp_communities)| Manage BGP community and its parameters
[**sonic_bgp_ext_communities**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_bgp_ext_communities)| Manage BGP extended community-list and its parameters
[**sonic_bgp_neighbors**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_bgp_neighbors)| Manage a BGP neighbor and its parameters
[**sonic_bgp_neighbors_af**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_bgp_neighbors_af)| Manage the BGP neighbor address-family and its parameters
[**sonic_br_l2pt**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_br_l2pt)| Manage L2PT configurations on SONiC
[**sonic_copp**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_copp)| Manage CoPP configuration
[**sonic_dcbx**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_dcbx)| Manage DCBx configurations on SONiC
[**sonic_dhcp_relay**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_dhcp_relay)| Manage DHCP and DHCPv6 relay configurations
[**sonic_dhcp_snooping**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_dhcp_snooping)| Manage DHCP Snooping
[**sonic_drop_counter**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_drop_counter)| Manage drop counter configuration on SONiC
[**sonic_ecmp_load_share**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_ecmp_load_share)| IP ECMP load share mode configuration handling for SONiC
[**sonic_evpn_esi_multihome**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_evpn_esi_multihome)| Manage EVPN ESI multihoming configuration on SONiC
[**sonic_fbs_classifiers**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_fbs_classifiers)| Manage flow based services (FBS) classifiers configuration on SONiC
[**sonic_fbs_groups**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_fbs_groups)| Manage flow based services (FBS) groups configuration on SONiC
[**sonic_fbs_policies**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_fbs_policies)| Manage flow based services (FBS) policies configuration on SONiC
[**sonic_fips**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_fips)| Manage FIPS configurations
[**sonic_image_management**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_image_management)| Manage installation of Enterprise SONiC image, software patch and firmware updater.
[**sonic_interfaces**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_interfaces)| Configure Interface attributes
[**sonic_ip_neighbor**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_ip_neighbor)| Manage IP neighbor global configuration
[**sonic_ip_neighbor_interfaces**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_ip_neighbor_interfaces)| Manage interface-specific IP neighbor configurations on SONiC
[**sonic_ipv6_router_advertisement**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_ipv6_router_advertisement)| Manage interface-specific IPv6 Router Advertisement configurations on SONiC
[**sonic_l2_acls**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_l2_acls)| Manage Layer 2 access control lists (ACL) configurations
[**sonic_l2_interfaces**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_l2_interfaces)| Configure interface-to-VLAN association
[**sonic_l3_acls**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_l3_acls)| Manage Layer 3 access control lists (ACL) configurations
[**sonic_l3_interfaces**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_l3_interfaces)| Configure the IPv4 and IPv6 parameters on Interfaces
[**sonic_lag_interfaces**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_lag_interfaces)| Manage link aggregation group (LAG) interface parameters
[**sonic_ldap**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_ldap)| Configure global LDAP server settings
[**sonic_lldp_global**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_lldp_global)| Manage Global LLDP configurations
[**sonic_lldp_interfaces**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_lldp_interfaces)| Manage interface LLDP configurations
[**sonic_logging**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_logging)| Manage logging configuration
[**sonic_login_lockout**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_login_lockout)| Manage Global Login Lockout configuration
[**sonic_lst**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_lst)| Manage link state tracking (LST) configuration on SONiC
[**sonic_mac**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_mac)| Manage MAC configuration
[**sonic_mclag**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_mclag)| Manage multi chassis link aggregation groups domain (MCLAG) and its parameters
[**sonic_mgmt_servers**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_mgmt_servers)| Manage management servers configuration
[**sonic_mirroring**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_mirroring)| Manage port mirroring configuration on SONiC
[**sonic_network_policy**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_network_policy)| Manage network policy configuration on SONiC
[**sonic_ntp**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_ntp)| Manage NTP configuration
[**sonic_ospf_area**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_ospf_area)| Configure OSPF area setting
[**sonic_ospfv2**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_ospfv2)| Configure global OSPFv2 protocol settings
[**sonic_ospfv2_interfaces**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_ospfv2_interfaces)| Configure OSPFv2 interface mode protocol settings
[**sonic_ospfv3**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_ospfv3)| Configure global OSPFv3 protocol settings on SONiC
[**sonic_ospfv3_area**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_ospfv3_area)| Configure OSPFv3 area settings on SONiC
[**sonic_ospfv3_interfaces**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_ospfv3_interfaces)| Configure OSPFv3 interface mode protocol settings on SONiC
[**sonic_pim_global**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_pim_global)| Manage global PIM configuration
[**sonic_pim_interfaces**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_pim_interfaces)| Manage interface-specific PIM configurations
[**sonic_pki**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_pki)| Manages PKI attributes
[**sonic_pms**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_pms)| Configure interface mode port security settings on SONiC
[**sonic_poe**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_poe)| Manage Power over Ethernet PoE configuration
[**sonic_port_breakout**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_port_breakout)| Configure port breakout settings on physical interfaces
[**sonic_port_group**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_port_group)| Manage port group configuration
[**sonic_prefix_lists**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_prefix_lists)| Manage prefix list configuration
[**sonic_ptp_default_ds**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_ptp_default_ds)| Manage global PTP configurations on SONiC
[**sonic_ptp_port_ds**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_ptp_port_ds)| Manage port specific PTP configurations on SONiC
[**sonic_qos_buffer**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_qos_buffer)| Manage QoS buffer configuration
[**sonic_qos_interfaces**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_qos_interfaces)| Manage QoS interfaces configuration
[**sonic_qos_maps**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_qos_maps)| Manage QoS maps configuration
[**sonic_qos_pfc**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_qos_pfc)| Manage QoS PFC configuration    
[**sonic_qos_scheduler**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_qos_scheduler)| Manage QoS scheduler configuration
[**sonic_qos_wred**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_qos_wred)| Manage QoS WRED profiles configuration
[**sonic_radius_server**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_radius_server)| Manage RADIUS server and its parameters
[**sonic_roce**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_roce)| Manage RoCE QoS configuration
[**sonic_route_maps**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_route_maps)| Manage route map configuration
[**sonic_sflow**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_sflow)| Manage sflow configuration settings
[**sonic_ssh**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_ssh)| Manage SSH configuration settings
[**sonic_ssh_server**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_ssh_server)| Manage SSH server configurations on SONiC
[**sonic_static_routes**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_static_routes)| Manage static routes configuration
[**sonic_stp**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_stp)| Manage STP configuration
[**sonic_system**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_system)| Configure system parameters
[**sonic_tacacs_server**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_tacacs_server)| Manage TACACS server and its parameters
[**sonic_users**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_users)| Manage users and its parameters
[**sonic_vlan_mapping**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_vlan_mapping)| Configure vlan mappings
[**sonic_vlans**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_vlans)| Manage VLAN and its parameters
[**sonic_vrfs**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_vrfs)| Manage VRFs and associate VRFs to interfaces
[**sonic_vrrp**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_vrrp)| Manage VRRP protocol configuration settings
[**sonic_vxlans**](https://galaxy.ansible.com/ui/repo/published/dellemc/enterprise_sonic/content/module/sonic_vxlans)| Manage VxLAN EVPN and its parameters

Sample use case playbooks
-------------------------
The playbooks directory includes this sample playbook that shows end-to-end use cases.

Name | Description
--- | ---
[**BGP Layer 3 fabric**](https://github.com/ansible-collections/dellemc.enterprise_sonic/tree/master/playbooks/bgp_l3_fabric)|Example playbook to build a Layer 3 leaf-spine fabric

Version compatibility
----------------------
* Recommended Ansible version 2.17 or higher (This is required for enterprise_sonic collection version >= 3.2.0).
* Enterprise SONiC Distribution by Dell Technologies version 3.1 or higher
* Recommended Python 3.10 or higher (This is required for enterprise_sonic collection version >= 3.2.0.).
* Dell Enterprise SONiC images for releases 3.1 - 3.5: Use Ansible Enterprise SONiC collection version 1.1.0 or later 1.m.n versions (from the 1.x branch of this repo)
* Dell Enterprise SONiC images for release 4.0 and later 4.x.y releases before 4.4.0: Use Ansible Enterprise SONiC collection version 2.0.0 or later 2.m.n releases (from the "2.x" branch of this repo).
* Dell Enterprise SONiC images for release 4.4.0 and later 4.x.y releases: Use Ansible Enterprise SONiC collection version 3.0.0 or later 3.m.n releases (from the "main" branch of this repo).


> **NOTE**: Community SONiC versions that include the Management Framework container should work as well, however, this collection has not been tested nor validated 
        with community versions and is not supported.

Installation of Ansible 2.11+
-----------------------------
##### Dependencies for Ansible Enterprise SONiC collection

      pip3 install paramiko>=2.7
      pip3 install jinja2>=2.8
      pip3 install ansible-core

Installation of Ansible 2.10+
-----------------------------
##### Dependencies for Ansible Enterprise SONiC collection

      pip3 install paramiko>=2.7
      pip3 install jinja2>=2.8
      pip3 install ansible-base
      
      
Installation of Ansible 2.9
---------------------------
##### Dependencies for Ansible Enterprise SONiC collection

      pip3 install paramiko>=2.7
      pip3 install jinja2>=2.8
      pip3 install ansible
      
##### Setting Environment Variables

To use the Enterprise SONiC collection in Ansible 2.9, it is required to add one of the two available environment variables.

Option 1: Add the environment variable while running the playbook.


      ANSIBLE_NETWORK_GROUP_MODULES=sonic ansible-playbook sample_playbook.yaml -i inventory.ini
      
      
Option 2: Add the environment variable in user profile.


      ANSIBLE_NETWORK_GROUP_MODULES=sonic
      

Installation of Enterprise SONiC collection from Ansible Galaxy
---------------------------------------------------------------

Install the latest version of the Enterprise SONiC collection from Ansible Galaxy.

      ansible-galaxy collection install dellemc.enterprise_sonic

To install a specific version, specify a version range identifier. For example, to install the most recent version that is greater than or equal to 1.0.0 and less than 2.0.0.

      ansible-galaxy collection install 'dellemc.enterprise_sonic:>=1.0.0,<2.0.0'


Sample playbooks
-----------------
**VLAN configuration using CLICONF**

***sonic_network_cli.yaml***

    ---

    - name: SONiC Management Framework CLI configuration examples
      hosts: sonic_switches
      gather_facts: no
      connection: network_cli
      tasks:
        - name: Add VLAN entry
          dellemc.enterprise_sonic.sonic_config:
            commands: ['interface Vlan 700','exit']
            save: yes
          register: config_op
        - name: Test SONiC single command
          dellemc.enterprise_sonic.sonic_command:
            commands: 'show vlan'
          register: cmd_op

**VLAN configuration using HTTPAPI**

***sonic_httpapi.yaml***

    ---

    - name: SONiC Management Framework REST API examples
      hosts: sonic_switches
      gather_facts: no
      connection: httpapi
      tasks:
        - name: Perform PUT operation to add a VLAN network instance
          dellemc.enterprise_sonic.sonic_api:
            url: data/openconfig-network-instance:network-instances/network-instance=Vlan100
            method: "PUT"
            body: {"openconfig-network-instance:network-instance": [{"name": "Vlan100","config": {"name": "Vlan100"}}]}
            status_code: 204
        - name: Perform GET operation to view VLAN network instance
          dellemc.enterprise_sonic.sonic_api:
            url: data/openconfig-network-instance:network-instances/network-instance=Vlan100
            method: "GET"
            status_code: 200
          register: api_op

**Configuration using network resource modules**

***sonic_resource_modules.yaml***

    ---

    - name: VLANs, Layer 2 and Layer 3 interfaces configuration using Enterprise SONiC resource modules
      hosts: sonic_switches
      gather_facts: no
      connection: httpapi
      tasks:
       - name: Configure VLANs
         dellemc.enterprise_sonic.sonic_vlans:
            config:
             - vlan_id: 701
             - vlan_id: 702
             - vlan_id: 703
             - vlan_id: 704
            state: merged
         register: sonic_vlans_output
       - name: Configure Layer 2 interfaces
         dellemc.enterprise_sonic.sonic_l2_interfaces:
            config:
            - name: Eth1/2
              access:
                vlan: 701
              trunk:
                allowed_vlans:
                  - vlan: 702
                  - vlan: 703
            state: merged
         register: sonic_l2_interfaces_output
       - name: Configure Layer 3 interfaces
         dellemc.enterprise_sonic.sonic_l3_interfaces:
           config:
            - name: Eth1/3
              ipv4:
                - address: 8.1.1.1/16
              ipv6:
                - address: 3333::1/16
           state: merged
         register: sonic_l3_interfaces_output

***host_vars/sonic_sw1.yaml***

    hostname: sonic_sw1

    # Common parameters for connection type httpapi or network_cli:
    ansible_user: xxxx
    ansible_password: xxxx
    ansible_network_os: dellemc.enterprise_sonic.sonic

    # Additional parameters for connection type httpapi:
    ansible_httpapi_use_ssl: true
    ansible_httpapi_validate_certs: false

***inventory.ini***

    [sonic_sw1]
    sonic_sw1 ansible_host=100.104.28.119

    [sonic_sw2]
    sonic_sw2 ansible_host=100.104.28.120

    [sonic_switches:children]
    sonic_sw1
    sonic_sw2

Releasing, Versioning and Deprecation
-------------------------------------

This collection follows [Semantic Versioning](https://semver.org/). More details on versioning can be found [in the Ansible docs](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections.html#collection-versions).

We plan to regularly release new minor or bugfix versions once new features or bugfixes have been implemented.

Enterprise SONiC Ansible Modules deprecation cycle is aligned with [Ansible](https://docs.ansible.com/ansible/latest/dev_guide/module_lifecycle.html).

Source control branches on Github:
  - Released code versions are located on "release" branches with names of the form "M.x", where "M" specifies the "major" release version for releases residing on the branch.
  - Unreleased and pre-release code versions are located on sub-branches of the "main" branch. This is a development branch, and is not intended for use in production environments.

Code of Conduct
---------------

This repository adheres to the [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

Communication
-------------

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others.
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

(c) 2020-2021 Dell Inc. or its subsidiaries. All Rights Reserved.
