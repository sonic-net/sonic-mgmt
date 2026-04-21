# Cisco NX-OS Collection
[![Codecov](https://codecov.io/gh/ansible-collections/cisco.nxos/branch/main/graph/badge.svg)](https://codecov.io/gh/ansible-collections/cisco.nxos)
[![CI](https://github.com/ansible-collections/cisco.nxos/actions/workflows/tests.yml/badge.svg?branch=main&event=schedule)](https://github.com/ansible-collections/cisco.nxos/actions/workflows/tests.yml)

The Ansible Cisco NX-OS collection includes a variety of Ansible content to help automate the management of Cisco NX-OS network appliances.

The Cisco NX-OS connection plugins combined with Cisco NX-OS resource modules aligns the Cisco NX-OS experience with the other core networking platforms supported by Ansible.

The modules with full support for Cisco MDS are tested against NX-OS 8.4(1) and 9.4(3a) on MDS Switches. The modules should work for all releases above 8.4(1)

## Support

As Red Hat Ansible Certified Content, this collection is entitled to support through the Ansible Automation Platform (AAP) using the **Create issue** button on the top right corner. If a support case cannot be opened with Red Hat and the collection has been obtained either from Galaxy or GitHub, there may community help available on the [Ansible Forum](https://forum.ansible.com/).

Additionally, you can join us on [#network:ansible.com](https://matrix.to/#/#network:ansible.com) room or the [Ansible Forum Network Working Group](https://forum.ansible.com/g/network-wg).

For more information you can check the communication section below.

## Communication

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others.
  * [Posts tagged with 'network'](https://forum.ansible.com/tag/network): subscribe to participate in collection-related conversations.
  * [Ansible Network Automation Working Group](https://forum.ansible.com/g/network-wg): by joining the team you will automatically get subscribed to the posts tagged with [network](https://forum.ansible.com/tags/network).
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

<!--start requires_ansible-->
## Ansible version compatibility

This collection has been tested against the following Ansible versions: **>=2.16.0**.

Plugins and modules within a collection may be tested with only specific Ansible versions.
A collection may contain metadata that identifies these versions.
PEP440 is the schema used to describe the versions of Ansible.
<!--end requires_ansible-->

### Supported connections
The Cisco NX-OS collection supports ``network_cli``  and ``httpapi`` connections. A detailed platform guide can be found [here](https://github.com/ansible-collections/cisco.nxos/blob/main/platform_guide.rst).

## Included content
<!--start collection content-->
### Cliconf plugins
Name | Description
--- | ---
[cisco.nxos.nxos](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_cliconf.rst)|Use NX-OS cliconf to run commands on Cisco NX-OS platform

### Httpapi plugins
Name | Description
--- | ---
[cisco.nxos.nxos](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_httpapi.rst)|Use NX-API to run commands on Cisco NX-OS platform

### Netconf plugins
Name | Description
--- | ---
[cisco.nxos.nxos](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_netconf.rst)|Use nxos netconf plugin to run netconf commands on Cisco NX-OS platform.

### Modules
Name | Description
--- | ---
[cisco.nxos.nxos_aaa_server](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_aaa_server_module.rst)|Manages AAA server global configuration.
[cisco.nxos.nxos_aaa_server_host](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_aaa_server_host_module.rst)|Manages AAA server host-specific configuration.
[cisco.nxos.nxos_acl_interfaces](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_acl_interfaces_module.rst)|ACL interfaces resource module
[cisco.nxos.nxos_acls](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_acls_module.rst)|ACLs resource module
[cisco.nxos.nxos_banner](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_banner_module.rst)|Manage multiline banners on Cisco NXOS devices
[cisco.nxos.nxos_bfd_global](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_bfd_global_module.rst)|Bidirectional Forwarding Detection (BFD) global-level configuration
[cisco.nxos.nxos_bfd_interfaces](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_bfd_interfaces_module.rst)|BFD interfaces resource module
[cisco.nxos.nxos_bgp_address_family](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_bgp_address_family_module.rst)|BGP Address Family resource module.
[cisco.nxos.nxos_bgp_global](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_bgp_global_module.rst)|BGP Global resource module.
[cisco.nxos.nxos_bgp_neighbor_address_family](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_bgp_neighbor_address_family_module.rst)|BGP Neighbor Address Family resource module.
[cisco.nxos.nxos_bgp_templates](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_bgp_templates_module.rst)|BGP Templates resource module.
[cisco.nxos.nxos_command](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_command_module.rst)|Run arbitrary command on Cisco NXOS devices
[cisco.nxos.nxos_config](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_config_module.rst)|Manage Cisco NXOS configuration sections
[cisco.nxos.nxos_devicealias](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_devicealias_module.rst)|Configuration of device alias for Cisco NXOS MDS Switches.
[cisco.nxos.nxos_evpn_global](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_evpn_global_module.rst)|Handles the EVPN control plane for VXLAN.
[cisco.nxos.nxos_evpn_vni](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_evpn_vni_module.rst)|Manages Cisco EVPN VXLAN Network Identifier (VNI).
[cisco.nxos.nxos_facts](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_facts_module.rst)|Gets facts about NX-OS switches
[cisco.nxos.nxos_fc_interfaces](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_fc_interfaces_module.rst)|Fc Interfaces resource module
[cisco.nxos.nxos_feature](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_feature_module.rst)|Manage features in NX-OS switches.
[cisco.nxos.nxos_file_copy](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_file_copy_module.rst)|Copy a file to a remote NXOS device.
[cisco.nxos.nxos_gir](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_gir_module.rst)|Trigger a graceful removal or insertion (GIR) of the switch.
[cisco.nxos.nxos_gir_profile_management](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_gir_profile_management_module.rst)|Create a maintenance-mode or normal-mode profile for GIR.
[cisco.nxos.nxos_hostname](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_hostname_module.rst)|Hostname resource module.
[cisco.nxos.nxos_hsrp](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_hsrp_module.rst)|(deprecated, removed after 2028-06-01) Manages HSRP configuration on NX-OS switches.
[cisco.nxos.nxos_hsrp_interfaces](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_hsrp_interfaces_module.rst)|HSRP interfaces resource module
[cisco.nxos.nxos_igmp](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_igmp_module.rst)|Manages IGMP global configuration.
[cisco.nxos.nxos_igmp_interface](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_igmp_interface_module.rst)|Manages IGMP interface configuration.
[cisco.nxos.nxos_igmp_snooping](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_igmp_snooping_module.rst)|Manages IGMP snooping global configuration.
[cisco.nxos.nxos_install_os](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_install_os_module.rst)|Set boot options like boot, kickstart image and issu.
[cisco.nxos.nxos_interfaces](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_interfaces_module.rst)|Interfaces resource module
[cisco.nxos.nxos_l2_interfaces](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_l2_interfaces_module.rst)|L2 interfaces resource module
[cisco.nxos.nxos_l3_interfaces](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_l3_interfaces_module.rst)|L3 interfaces resource module
[cisco.nxos.nxos_lacp](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_lacp_module.rst)|LACP resource module
[cisco.nxos.nxos_lacp_interfaces](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_lacp_interfaces_module.rst)|LACP interfaces resource module
[cisco.nxos.nxos_lag_interfaces](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_lag_interfaces_module.rst)|LAG interfaces resource module
[cisco.nxos.nxos_lldp_global](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_lldp_global_module.rst)|LLDP resource module
[cisco.nxos.nxos_lldp_interfaces](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_lldp_interfaces_module.rst)|LLDP interfaces resource module
[cisco.nxos.nxos_logging_global](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_logging_global_module.rst)|Logging resource module.
[cisco.nxos.nxos_ntp_global](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_ntp_global_module.rst)|NTP Global resource module.
[cisco.nxos.nxos_nxapi](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_nxapi_module.rst)|Manage NXAPI configuration on an NXOS device.
[cisco.nxos.nxos_ospf_interfaces](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_ospf_interfaces_module.rst)|OSPF Interfaces Resource Module.
[cisco.nxos.nxos_ospfv2](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_ospfv2_module.rst)|OSPFv2 resource module
[cisco.nxos.nxos_ospfv3](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_ospfv3_module.rst)|OSPFv3 resource module
[cisco.nxos.nxos_overlay_global](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_overlay_global_module.rst)|Configures anycast gateway MAC of the switch.
[cisco.nxos.nxos_pim](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_pim_module.rst)|Manages configuration of a PIM instance.
[cisco.nxos.nxos_pim_interface](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_pim_interface_module.rst)|Manages PIM interface configuration.
[cisco.nxos.nxos_pim_rp_address](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_pim_rp_address_module.rst)|Manages configuration of an PIM static RP address instance.
[cisco.nxos.nxos_ping](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_ping_module.rst)|Tests reachability using ping from Nexus switch.
[cisco.nxos.nxos_prefix_lists](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_prefix_lists_module.rst)|Prefix-Lists resource module.
[cisco.nxos.nxos_reboot](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_reboot_module.rst)|Reboot a network device.
[cisco.nxos.nxos_rollback](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_rollback_module.rst)|Set a checkpoint or rollback to a checkpoint.
[cisco.nxos.nxos_route_maps](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_route_maps_module.rst)|Route Maps resource module.
[cisco.nxos.nxos_rpm](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_rpm_module.rst)|Install patch or feature rpms on Cisco NX-OS devices.
[cisco.nxos.nxos_snapshot](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_snapshot_module.rst)|Manage snapshots of the running states of selected features.
[cisco.nxos.nxos_snmp_server](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_snmp_server_module.rst)|SNMP Server resource module.
[cisco.nxos.nxos_static_routes](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_static_routes_module.rst)|Static routes resource module
[cisco.nxos.nxos_system](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_system_module.rst)|Manage the system attributes on Cisco NXOS devices
[cisco.nxos.nxos_telemetry](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_telemetry_module.rst)|TELEMETRY resource module
[cisco.nxos.nxos_udld](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_udld_module.rst)|Manages UDLD global configuration params.
[cisco.nxos.nxos_udld_interface](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_udld_interface_module.rst)|Manages UDLD interface configuration params.
[cisco.nxos.nxos_user](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_user_module.rst)|Manage the collection of local users on Nexus devices
[cisco.nxos.nxos_vlans](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_vlans_module.rst)|VLANs resource module
[cisco.nxos.nxos_vpc](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_vpc_module.rst)|Manages global VPC configuration
[cisco.nxos.nxos_vpc_interface](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_vpc_interface_module.rst)|Manages interface VPC configuration
[cisco.nxos.nxos_vrf](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_vrf_module.rst)|(deprecated, removed after 2026-07-25) Manages global VRF configuration.
[cisco.nxos.nxos_vrf_address_family](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_vrf_address_family_module.rst)|Resource module to configure VRF address family definitions.
[cisco.nxos.nxos_vrf_af](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_vrf_af_module.rst)|Manages VRF AF.
[cisco.nxos.nxos_vrf_global](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_vrf_global_module.rst)|Resource module to configure VRF definitions.
[cisco.nxos.nxos_vrf_interface](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_vrf_interface_module.rst)|(deprecated, removed after 2028-06-01) Manages interface specific VRF configuration.
[cisco.nxos.nxos_vrf_interfaces](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_vrf_interfaces_module.rst)|Resource module to configure VRF interfaces.
[cisco.nxos.nxos_vrrp](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_vrrp_module.rst)|Manages VRRP configuration on NX-OS switches.
[cisco.nxos.nxos_vsan](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_vsan_module.rst)|Configuration of vsan for Cisco NXOS MDS Switches.
[cisco.nxos.nxos_vtp_domain](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_vtp_domain_module.rst)|Manages VTP domain configuration.
[cisco.nxos.nxos_vtp_password](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_vtp_password_module.rst)|Manages VTP password configuration.
[cisco.nxos.nxos_vtp_version](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_vtp_version_module.rst)|Manages VTP version configuration.
[cisco.nxos.nxos_vxlan_vtep](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_vxlan_vtep_module.rst)|Manages VXLAN Network Virtualization Endpoint (NVE).
[cisco.nxos.nxos_vxlan_vtep_vni](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_vxlan_vtep_vni_module.rst)|Creates a Virtual Network Identifier member (VNI)
[cisco.nxos.nxos_zone_zoneset](https://github.com/ansible-collections/cisco.nxos/blob/main/docs/cisco.nxos.nxos_zone_zoneset_module.rst)|Configuration of zone/zoneset for Cisco NXOS MDS Switches.

<!--end collection content-->

Click the ``Content`` button to see the list of content included in this collection.

## Installing this collection

You can install the Cisco NX-OS collection with the Ansible Galaxy CLI:

    ansible-galaxy collection install cisco.nxos

You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: cisco.nxos
```
## Using this collection


This collection includes [network resource modules](https://docs.ansible.com/ansible/latest/network/user_guide/network_resource_modules.html).

### Using modules from the Cisco NX-OS collection in your playbooks

You can call modules by their Fully Qualified Collection Namespace (FQCN), such as `cisco.nxos.nxos_l2_interfaces`.
The following example task replaces configuration changes in the existing configuration on a Cisco NX-OS network device, using the FQCN:

```yaml
---
  - name: Replace device configuration of specified L2 interfaces with provided configuration.
    cisco.nxos.nxos_l2_interfaces:
      config:
        - name: Ethernet1/1
          trunk:
            native_vlan: 20
            trunk_vlans: 5-10, 15
      state: replaced

```

**NOTE**: For Ansible 2.9, you may not see deprecation warnings when you run your playbooks with this collection. Use this documentation to track when a module is deprecated.


### See Also:

* [Cisco NX-OS Platform Options](https://docs.ansible.com/ansible/latest/network/user_guide/platform_nxos.html)
* [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection

Ongoing development efforts and contributions to this collection are solely focused on enhancements to current resource modules, additional resource modules and enhancements to connection plugins.

We welcome community contributions to this collection. If you find problems, please open an issue or create a PR against the [Cisco NX-OS collection repository](https://github.com/ansible-collections/cisco.nxos).  See [Contributing to Ansible-maintained collections](https://docs.ansible.com/ansible/devel/community/contributing_maintained_collections.html#contributing-maintained-collections) for complete details.

You can also join us on:

- IRC - the ``#ansible-network`` [libera.chat](https://libera.chat/) channel
- Slack - https://ansiblenetwork.slack.com

See the [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html) for details on contributing to Ansible.

### Code of Conduct
This collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.


## Release notes

Release notes are available [here](https://github.com/ansible-collections/cisco.nxos/blob/main/CHANGELOG.rst).

## Roadmap

<!-- Optional. Include the roadmap for this collection, and the proposed release/versioning strategy so users can anticipate the upgrade/update cycle. -->

## More information

- [Ansible network resources](https://docs.ansible.com/ansible/latest/network/getting_started/network_resources.html)
- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## Licensing

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
