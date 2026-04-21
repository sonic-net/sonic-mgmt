![Fortinet logo|](https://upload.wikimedia.org/wikipedia/commons/thumb/6/62/Fortinet_logo.svg/320px-Fortinet_logo.svg.png)

# fortinet.fortios - Configuring FortiGate

## Description

The collection includes modules that allow users to configure FortiOS and FortiGate, specifically for managing firewall features.
Please refer to [Documentation](https://ansible-galaxy-fortios-docs.readthedocs.io/en/latest/index.html) for more information.

## Requirements

- Ansible 2.15.0 or above
- Python 3.9 or above

## Installation
This collection is distributed via [ansible-galaxy](https://galaxy.ansible.com/).

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```
ansible-galaxy collection install fortinet.fortios
```

You can also include it in a requirements.yml file and install it with ansible-galaxy collection install -r requirements.yml, using the format:


```yaml
collections:
  - name: fortinet.fortios
```

Note that if you install any collections from Ansible Galaxy, they will not be upgraded automatically when you upgrade the Ansible package.
To upgrade the collection to the latest available version, run the following command:

```
ansible-galaxy collection install fortinet.fortios --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax to install version 2.3.7:

```
ansible-galaxy collection install fortinet.fortios:==2.3.9
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

## Use Cases

The FortiOS collection supports both username/password and access token authentication, with access tokens being the recommended method for enhanced security. For more infirmation about generating an access_token, please refer to [Generate access_token](https://ansible-galaxy-fortios-docs.readthedocs.io/en/latest/faq.html#what-s-access-token).

Follow the example here [Examples](https://ansible-galaxy-fortios-docs.readthedocs.io/en/latest/playbook.html) to configure the hosts file and write your first playbook.

Change the FortiGate host name:
```yaml
tasks:
  - name: Change hostname
    fortios_system_global:
      vdom:  "{{ vdom }}"
        system_global:
          hostname: 'YOUR_OWN_VALUE'
```

Run the playbook:
```bash
ansible-playbook change_hostname.yml
```

## Testing

Testing is conducted by the Fortinet team. The new version will be released once the entire collection passes both unit and sanity tests.

## Support

Please open a Github issue if your have any questions [Report issues](https://github.com/fortinet-ansible-dev/ansible-galaxy-fortios-collection/issues)

## Release Notes and Roadmap

Refer to the release notes here [Release Notes](https://ansible-galaxy-fortios-docs.readthedocs.io/en/latest/release.html)
The FortiOS Ansible collection is scheduled to be updated every two months.

## Related Information

For more information, please refer to [Documentation](https://ansible-galaxy-fortios-docs.readthedocs.io/en/latest/index.html)

## Modules
The collection incluses the following modules:


* `fortios_alertemail_setting` Configure alert email settings in Fortinet's FortiOS and FortiGate.
* `fortios_antivirus_exempt_list` Configure a list of hashes to be exempt from AV scanning in Fortinet's FortiOS and FortiGate.
* `fortios_antivirus_heuristic` Configure global heuristic options in Fortinet's FortiOS and FortiGate.
* `fortios_antivirus_mms_checksum` Configure MMS content checksum list in Fortinet's FortiOS and FortiGate.
* `fortios_antivirus_notification` Configure AntiVirus notification lists in Fortinet's FortiOS and FortiGate.
* `fortios_antivirus_profile` Configure AntiVirus profiles in Fortinet's FortiOS and FortiGate.
* `fortios_antivirus_quarantine` Configure quarantine options in Fortinet's FortiOS and FortiGate.
* `fortios_antivirus_settings` Configure AntiVirus settings in Fortinet's FortiOS and FortiGate.
* `fortios_application_custom` Configure custom application signatures in Fortinet's FortiOS and FortiGate.
* `fortios_application_group` Configure firewall application groups in Fortinet's FortiOS and FortiGate.
* `fortios_application_list` Configure application control lists in Fortinet's FortiOS and FortiGate.
* `fortios_application_name` Configure application signatures in Fortinet's FortiOS and FortiGate.
* `fortios_application_rule_settings` Configure application rule settings in Fortinet's FortiOS and FortiGate.
* `fortios_authentication_rule` Configure Authentication Rules in Fortinet's FortiOS and FortiGate.
* `fortios_authentication_scheme` Configure Authentication Schemes in Fortinet's FortiOS and FortiGate.
* `fortios_authentication_setting` Configure authentication setting in Fortinet's FortiOS and FortiGate.
* `fortios_automation_setting` Automation setting configuration in Fortinet's FortiOS and FortiGate.
* `fortios_casb_attribute_match` Configure CASB attribute match rule in Fortinet's FortiOS and FortiGate.
* `fortios_casb_profile` Configure CASB profile in Fortinet's FortiOS and FortiGate.
* `fortios_casb_saas_application` Configure CASB SaaS application in Fortinet's FortiOS and FortiGate.
* `fortios_casb_user_activity` Configure CASB user activity in Fortinet's FortiOS and FortiGate.
* `fortios_certificate_ca` CA certificate in Fortinet's FortiOS and FortiGate.
* `fortios_certificate_crl` Certificate Revocation List as a PEM file in Fortinet's FortiOS and FortiGate.
* `fortios_certificate_hsm_local` Local certificates whose keys are stored on HSM in Fortinet's FortiOS and FortiGate.
* `fortios_certificate_local` Local keys and certificates in Fortinet's FortiOS and FortiGate.
* `fortios_certificate_remote` Remote certificate as a PEM file in Fortinet's FortiOS and FortiGate.
* `fortios_cifs_domain_controller` Define known domain controller servers in Fortinet's FortiOS and FortiGate.
* `fortios_cifs_profile` Configure CIFS profile in Fortinet's FortiOS and FortiGate.
* `fortios_configuration_fact` Retrieve Facts of FortiOS Configurable Objects.
* `fortios_credential_store_domain_controller` Define known domain controller servers in Fortinet's FortiOS and FortiGate.
* `fortios_diameter_filter_profile` Configure Diameter filter profiles in Fortinet's FortiOS and FortiGate.
* `fortios_dlp_data_type` Configure predefined data type used by DLP blocking in Fortinet's FortiOS and FortiGate.
* `fortios_dlp_dictionary` Configure dictionaries used by DLP blocking in Fortinet's FortiOS and FortiGate.
* `fortios_dlp_exact_data_match` Configure exact-data-match template used by DLP scan in Fortinet's FortiOS and FortiGate.
* `fortios_dlp_filepattern` Configure file patterns used by DLP blocking in Fortinet's FortiOS and FortiGate.
* `fortios_dlp_fp_doc_source` Create a DLP fingerprint database by allowing the FortiGate to access a file server containing files from which to create fingerprints in Fortinet's FortiOS and FortiGate.
* `fortios_dlp_fp_sensitivity` Create self-explanatory DLP sensitivity levels to be used when setting sensitivity under config fp-doc-source in Fortinet's FortiOS and FortiGate.
* `fortios_dlp_label` Configure labels used by DLP blocking in Fortinet's FortiOS and FortiGate.
* `fortios_dlp_profile` Configure DLP profiles in Fortinet's FortiOS and FortiGate.
* `fortios_dlp_sensitivity` Create self-explanatory DLP sensitivity levels to be used when setting sensitivity under config fp-doc-source in Fortinet's FortiOS and FortiGate.
* `fortios_dlp_sensor` Configure sensors used by DLP blocking in Fortinet's FortiOS and FortiGate.
* `fortios_dlp_settings` Configure settings for DLP in Fortinet's FortiOS and FortiGate.
* `fortios_dnsfilter_domain_filter` Configure DNS domain filters in Fortinet's FortiOS and FortiGate.
* `fortios_dnsfilter_profile` Configure DNS domain filter profile in Fortinet's FortiOS and FortiGate.
* `fortios_dpdk_cpus` Configure CPUs enabled to run engines in each DPDK stage in Fortinet's FortiOS and FortiGate.
* `fortios_dpdk_global` Configure global DPDK options in Fortinet's FortiOS and FortiGate.
* `fortios_emailfilter_block_allow_list` Configure anti-spam block/allow list in Fortinet's FortiOS and FortiGate.
* `fortios_emailfilter_bwl` Configure anti-spam black/white list in Fortinet's FortiOS and FortiGate.
* `fortios_emailfilter_bword` Configure AntiSpam banned word list in Fortinet's FortiOS and FortiGate.
* `fortios_emailfilter_dnsbl` Configure AntiSpam DNSBL/ORBL in Fortinet's FortiOS and FortiGate.
* `fortios_emailfilter_fortishield` Configure FortiGuard - AntiSpam in Fortinet's FortiOS and FortiGate.
* `fortios_emailfilter_iptrust` Configure AntiSpam IP trust in Fortinet's FortiOS and FortiGate.
* `fortios_emailfilter_mheader` Configure AntiSpam MIME header in Fortinet's FortiOS and FortiGate.
* `fortios_emailfilter_options` Configure AntiSpam options in Fortinet's FortiOS and FortiGate.
* `fortios_emailfilter_profile` Configure Email Filter profiles in Fortinet's FortiOS and FortiGate.
* `fortios_endpoint_control_client` Configure endpoint control client lists in Fortinet's FortiOS and FortiGate.
* `fortios_endpoint_control_fctems_override` Configure FortiClient Enterprise Management Server (EMS) entries in Fortinet's FortiOS and FortiGate.
* `fortios_endpoint_control_fctems` Configure FortiClient Enterprise Management Server (EMS) entries in Fortinet's FortiOS and FortiGate.
* `fortios_endpoint_control_forticlient_ems` Configure FortiClient Enterprise Management Server (EMS) entries in Fortinet's FortiOS and FortiGate.
* `fortios_endpoint_control_forticlient_registration_sync` Configure FortiClient registration synchronization settings in Fortinet's FortiOS and FortiGate.
* `fortios_endpoint_control_profile` Configure FortiClient endpoint control profiles in Fortinet's FortiOS and FortiGate.
* `fortios_endpoint_control_registered_forticlient` Registered FortiClient list in Fortinet's FortiOS and FortiGate.
* `fortios_endpoint_control_settings` Configure endpoint control settings in Fortinet's FortiOS and FortiGate.
* `fortios_export_config_playbook` Convert the returned facts into a playbook.
* `fortios_extender_controller_dataplan` FortiExtender dataplan configuration in Fortinet's FortiOS and FortiGate.
* `fortios_extender_controller_extender_profile` FortiExtender extender profile configuration in Fortinet's FortiOS and FortiGate.
* `fortios_extender_controller_extender` Extender controller configuration in Fortinet's FortiOS and FortiGate.
* `fortios_extender_extender_info` Display FortiExtender struct information in Fortinet's FortiOS and FortiGate.
* `fortios_extender_lte_carrier_by_mcc_mnc` Display FortiExtender modem carrier based on MCC and MNC in Fortinet's FortiOS and FortiGate.
* `fortios_extender_lte_carrier_list` Display FortiExtender modem carrier list in Fortinet's FortiOS and FortiGate.
* `fortios_extender_modem_status` Display detailed FortiExtender modem status in Fortinet's FortiOS and FortiGate.
* `fortios_extender_sys_info` Display detailed FortiExtender system information in Fortinet's FortiOS and FortiGate.
* `fortios_extension_controller_dataplan` FortiExtender dataplan configuration in Fortinet's FortiOS and FortiGate.
* `fortios_extension_controller_extender_profile` FortiExtender extender profile configuration in Fortinet's FortiOS and FortiGate.
* `fortios_extension_controller_extender_vap` FortiExtender wifi vap configuration in Fortinet's FortiOS and FortiGate.
* `fortios_extension_controller_extender` Extender controller configuration in Fortinet's FortiOS and FortiGate.
* `fortios_extension_controller_fortigate_profile` FortiGate connector profile configuration in Fortinet's FortiOS and FortiGate.
* `fortios_extension_controller_fortigate` FortiGate controller configuration in Fortinet's FortiOS and FortiGate.
* `fortios_file_filter_profile` Configure file-filter profiles in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_access_proxy6` Configure IPv6 access proxy in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_access_proxy_ssh_client_cert` Configure Access Proxy SSH client certificate in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_access_proxy_virtual_host` Configure Access Proxy virtual hosts in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_access_proxy` Configure IPv4 access proxy in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_acl6` Configure IPv6 access control list in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_acl` Configure IPv4 access control list in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_address6_template` Configure IPv6 address templates in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_address6` Configure IPv6 firewall addresses in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_address` Configure IPv4 addresses in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_addrgrp6` Configure IPv6 address groups in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_addrgrp` Configure IPv4 address groups in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_auth_portal` Configure firewall authentication portals in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_carrier_endpoint_bwl` Carrier end point black/white list tables in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_central_snat_map` Configure IPv4 and IPv6 central SNAT policies in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_city` Define city table in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_consolidated_policy` Configure consolidated IPv4/IPv6 policies in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_country` Define country table in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_decrypted_traffic_mirror` Configure decrypted traffic mirror in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_dnstranslation` Configure DNS translation in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_dos_policy6` Configure IPv6 DoS policies in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_dos_policy` Configure IPv4 DoS policies in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_global` Global firewall settings in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_gtp` Configure GTP in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_identity_based_route` Configure identity based routing in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_interface_policy6` Configure IPv6 interface policies in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_interface_policy` Configure IPv4 interface policies in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_internet_service_addition` Configure Internet Services Addition in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_internet_service_append` Configure additional port mappings for Internet Services in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_internet_service_botnet` Show Internet Service botnet in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_internet_service_custom_group` Configure custom Internet Service group in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_internet_service_custom` Configure custom Internet Services in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_internet_service_definition` Configure Internet Service definition in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_internet_service_extension` Configure Internet Services Extension in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_internet_service_fortiguard` Configure FortiGuard Internet Services in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_internet_service_group` Configure group of Internet Service in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_internet_service_ipbl_reason` IP block list reason in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_internet_service_ipbl_vendor` IP block list vendor in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_internet_service_list` Internet Service list in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_internet_service_name` Define internet service names in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_internet_service_owner` Internet Service owner in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_internet_service_reputation` Show Internet Service reputation in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_internet_service_sld` Internet Service Second Level Domain in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_internet_service` Show Internet Service application in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_ip_translation` Configure firewall IP-translation in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_ipmacbinding_setting` Configure IP to MAC binding settings in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_ipmacbinding_table` Configure IP to MAC address pairs in the IP/MAC binding table in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_ippool6` Configure IPv6 IP pools in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_ippool` Configure IPv4 IP pools in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_iprope_list` List in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_ipv6_eh_filter` Configure IPv6 extension header filter in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_ldb_monitor` Configure server load balancing health monitors in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_local_in_policy6` Configure user defined IPv6 local-in policies in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_local_in_policy` Configure user defined IPv4 local-in policies in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_mms_profile` Configure MMS profiles in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_multicast_address6` Configure IPv6 multicast address in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_multicast_address` Configure multicast addresses in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_multicast_policy6` Configure IPv6 multicast NAT policies in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_multicast_policy` Configure multicast NAT policies in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_network_service_dynamic` Configure Dynamic Network Services in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_on_demand_sniffer` Configure on-demand packet sniffer in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_pfcp` Configure PFCP in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_policy46` Configure IPv4 to IPv6 policies in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_policy64` Configure IPv6 to IPv4 policies in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_policy6` Configure IPv6 policies in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_policy` Configure IPv4/IPv6 policies in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_profile_group` Configure profile groups in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_profile_protocol_options` Configure protocol options in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_proute` List policy routing in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_proxy_address` Configure web proxy address in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_proxy_addrgrp` Configure web proxy address group in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_proxy_policy` Configure proxy policies in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_region` Define region table in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_schedule_group` Schedule group configuration in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_schedule_onetime` Onetime schedule configuration in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_schedule_recurring` Recurring schedule configuration in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_security_policy` Configure NGFW IPv4/IPv6 application policies in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_service_category` Configure service categories in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_service_custom` Configure custom services in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_service_group` Configure service groups in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_shaper_per_ip_shaper` Configure per-IP traffic shaper in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_shaper_traffic_shaper` Configure shared traffic shaper in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_shaping_policy` Configure shaping policies in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_shaping_profile` Configure shaping profiles in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_sniffer` Configure sniffer in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_ssh_host_key` SSH proxy host public keys in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_ssh_local_ca` SSH proxy local CA in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_ssh_local_key` SSH proxy local keys in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_ssh_setting` SSH proxy settings in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_ssl_server` Configure SSL servers in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_ssl_setting` SSL proxy settings in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_ssl_ssh_profile` Configure SSL/SSH protocol options in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_traffic_class` Configure names for shaping classes in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_ttl_policy` Configure TTL policies in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_vendor_mac` Show vendor and the MAC address they have in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_vip46` Configure IPv4 to IPv6 virtual IPs in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_vip64` Configure IPv6 to IPv4 virtual IPs in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_vip6` Configure virtual IP for IPv6 in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_vip` Configure virtual IP for IPv4 in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_vipgrp46` Configure IPv4 to IPv6 virtual IP groups in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_vipgrp64` Configure IPv6 to IPv4 virtual IP groups in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_vipgrp6` Configure IPv6 virtual IP groups in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_vipgrp` Configure IPv4 virtual IP groups in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_wildcard_fqdn_custom` Config global/VDOM Wildcard FQDN address in Fortinet's FortiOS and FortiGate.
* `fortios_firewall_wildcard_fqdn_group` Config global Wildcard FQDN address groups in Fortinet's FortiOS and FortiGate.
* `fortios_ftp_proxy_explicit` Configure explicit FTP proxy settings in Fortinet's FortiOS and FortiGate.
* `fortios_gtp_apn_shaper` Global per-APN shaper in Fortinet's FortiOS and FortiGate.
* `fortios_gtp_apn` Configure APN for GTP in Fortinet's FortiOS and FortiGate.
* `fortios_gtp_apngrp` Configure APN groups for GTP in Fortinet's FortiOS and FortiGate.
* `fortios_gtp_ie_allow_list` IE allow list in Fortinet's FortiOS and FortiGate.
* `fortios_gtp_ie_white_list` IE white list in Fortinet's FortiOS and FortiGate.
* `fortios_gtp_message_filter_v0v1` Message filter for GTPv0/v1 messages in Fortinet's FortiOS and FortiGate.
* `fortios_gtp_message_filter_v2` Message filter for GTPv2 messages in Fortinet's FortiOS and FortiGate.
* `fortios_gtp_rat_timeout_profile` RAT timeout profil in Fortinet's FortiOS and FortiGate.
* `fortios_gtp_tunnel_limit` GTP tunnel limiter in Fortinet's FortiOS and FortiGate.
* `fortios_hardware_nic` Display NIC information in Fortinet's FortiOS and FortiGate.
* `fortios_hardware_npu_np6_dce` Show NP6 non-zero subengine drop counters in Fortinet's FortiOS and FortiGate.
* `fortios_hardware_npu_np6_session_stats` Show NP6 session offloading statistics counters in Fortinet's FortiOS and FortiGate.
* `fortios_hardware_npu_np6_sse_stats` Show NP6 hardware session statistics counters in Fortinet's FortiOS and FortiGate.
* `fortios_icap_profile` Configure ICAP profiles in Fortinet's FortiOS and FortiGate.
* `fortios_icap_server_group` Configure an ICAP server group consisting of multiple forward servers. Supports failover and load balancing in Fortinet's FortiOS and FortiGate.
* `fortios_icap_server` Configure ICAP servers in Fortinet's FortiOS and FortiGate.
* `fortios_ips_custom` Configure IPS custom signature in Fortinet's FortiOS and FortiGate.
* `fortios_ips_decoder` Configure IPS decoder in Fortinet's FortiOS and FortiGate.
* `fortios_ips_global` Configure IPS global parameter in Fortinet's FortiOS and FortiGate.
* `fortios_ips_rule_settings` Configure IPS rule setting in Fortinet's FortiOS and FortiGate.
* `fortios_ips_rule` Configure IPS rules in Fortinet's FortiOS and FortiGate.
* `fortios_ips_sensor` Configure IPS sensor in Fortinet's FortiOS and FortiGate.
* `fortios_ips_settings` Configure IPS VDOM parameter in Fortinet's FortiOS and FortiGate.
* `fortios_ips_view_map` Configure IPS view-map in Fortinet's FortiOS and FortiGate.
* `fortios_log_custom_field` Configure custom log fields in Fortinet's FortiOS and FortiGate.
* `fortios_log_disk_filter` Configure filters for local disk logging. Use these filters to determine the log messages to record according to severity and type in Fortinet's FortiOS and FortiGate.
* `fortios_log_disk_setting` Settings for local disk logging in Fortinet's FortiOS and FortiGate.
* `fortios_log_eventfilter` Configure log event filters in Fortinet's FortiOS and FortiGate.
* `fortios_log_fact` Retrieve Log Data of Fortios Log Objects.
* `fortios_log_fortianalyzer2_filter` Filters for FortiAnalyzer in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortianalyzer2_override_filter` Override filters for FortiAnalyzer in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortianalyzer2_override_setting` Override FortiAnalyzer settings in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortianalyzer2_setting` Global FortiAnalyzer settings in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortianalyzer3_filter` Filters for FortiAnalyzer in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortianalyzer3_override_filter` Override filters for FortiAnalyzer in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortianalyzer3_override_setting` Override FortiAnalyzer settings in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortianalyzer3_setting` Global FortiAnalyzer settings in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortianalyzer_cloud_filter` Filters for FortiAnalyzer Cloud in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortianalyzer_cloud_override_filter` Override filters for FortiAnalyzer Cloud in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortianalyzer_cloud_override_setting` Override FortiAnalyzer Cloud settings in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortianalyzer_cloud_setting` Global FortiAnalyzer Cloud settings in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortianalyzer_filter` Filters for FortiAnalyzer in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortianalyzer_override_filter` Override filters for FortiAnalyzer in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortianalyzer_override_setting` Override FortiAnalyzer settings in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortianalyzer_setting` Global FortiAnalyzer settings in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortiguard_filter` Filters for FortiCloud in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortiguard_override_filter` Override filters for FortiCloud in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortiguard_override_setting` Override global FortiCloud logging settings for this VDOM in Fortinet's FortiOS and FortiGate.
* `fortios_log_fortiguard_setting` Configure logging to FortiCloud in Fortinet's FortiOS and FortiGate.
* `fortios_log_gui_display` Configure how log messages are displayed on the GUI in Fortinet's FortiOS and FortiGate.
* `fortios_log_memory_filter` Filters for memory buffer in Fortinet's FortiOS and FortiGate.
* `fortios_log_memory_global_setting` Global settings for memory logging in Fortinet's FortiOS and FortiGate.
* `fortios_log_memory_setting` Settings for memory buffer in Fortinet's FortiOS and FortiGate.
* `fortios_log_null_device_filter` Filters for null device logging in Fortinet's FortiOS and FortiGate.
* `fortios_log_null_device_setting` Settings for null device logging in Fortinet's FortiOS and FortiGate.
* `fortios_log_setting` Configure general log settings in Fortinet's FortiOS and FortiGate.
* `fortios_log_syslogd2_filter` Filters for remote system server in Fortinet's FortiOS and FortiGate.
* `fortios_log_syslogd2_override_filter` Override filters for remote system server in Fortinet's FortiOS and FortiGate.
* `fortios_log_syslogd2_override_setting` Override settings for remote syslog server in Fortinet's FortiOS and FortiGate.
* `fortios_log_syslogd2_setting` Global settings for remote syslog server in Fortinet's FortiOS and FortiGate.
* `fortios_log_syslogd3_filter` Filters for remote system server in Fortinet's FortiOS and FortiGate.
* `fortios_log_syslogd3_override_filter` Override filters for remote system server in Fortinet's FortiOS and FortiGate.
* `fortios_log_syslogd3_override_setting` Override settings for remote syslog server in Fortinet's FortiOS and FortiGate.
* `fortios_log_syslogd3_setting` Global settings for remote syslog server in Fortinet's FortiOS and FortiGate.
* `fortios_log_syslogd4_filter` Filters for remote system server in Fortinet's FortiOS and FortiGate.
* `fortios_log_syslogd4_override_filter` Override filters for remote system server in Fortinet's FortiOS and FortiGate.
* `fortios_log_syslogd4_override_setting` Override settings for remote syslog server in Fortinet's FortiOS and FortiGate.
* `fortios_log_syslogd4_setting` Global settings for remote syslog server in Fortinet's FortiOS and FortiGate.
* `fortios_log_syslogd_filter` Filters for remote system server in Fortinet's FortiOS and FortiGate.
* `fortios_log_syslogd_override_filter` Override filters for remote system server in Fortinet's FortiOS and FortiGate.
* `fortios_log_syslogd_override_setting` Override settings for remote syslog server in Fortinet's FortiOS and FortiGate.
* `fortios_log_syslogd_setting` Global settings for remote syslog server in Fortinet's FortiOS and FortiGate.
* `fortios_log_tacacsplusaccounting2_filter` Settings for TACACS+ accounting events filter in Fortinet's FortiOS and FortiGate.
* `fortios_log_tacacsplusaccounting2_setting` Settings for TACACS+ accounting in Fortinet's FortiOS and FortiGate.
* `fortios_log_tacacsplusaccounting3_filter` Settings for TACACS+ accounting events filter in Fortinet's FortiOS and FortiGate.
* `fortios_log_tacacsplusaccounting3_setting` Settings for TACACS+ accounting in Fortinet's FortiOS and FortiGate.
* `fortios_log_tacacsplusaccounting_filter` Settings for TACACS+ accounting events filter in Fortinet's FortiOS and FortiGate.
* `fortios_log_tacacsplusaccounting_setting` Settings for TACACS+ accounting in Fortinet's FortiOS and FortiGate.
* `fortios_log_threat_weight` Configure threat weight settings in Fortinet's FortiOS and FortiGate.
* `fortios_log_webtrends_filter` Filters for WebTrends in Fortinet's FortiOS and FortiGate.
* `fortios_log_webtrends_setting` Settings for WebTrends in Fortinet's FortiOS and FortiGate.
* `fortios_monitor_fact` Retrieve Facts of FortiOS Monitor Objects.
* `fortios_monitor` Ansible Module for FortiOS Monitor API.
* `fortios_monitoring_np6_ipsec_engine` Configure NP6 IPsec engine status monitoring in Fortinet's FortiOS and FortiGate.
* `fortios_monitoring_npu_hpe` Configure npu-hpe status monitoring in Fortinet's FortiOS and FortiGate.
* `fortios_nsxt_service_chain` Configure NSX-T service chain in Fortinet's FortiOS and FortiGate.
* `fortios_nsxt_setting` Configure NSX-T setting in Fortinet's FortiOS and FortiGate.
* `fortios_pfcp_message_filter` Message filter for PFCP messages in Fortinet's FortiOS and FortiGate.
* `fortios_report_chart` Report chart widget configuration in Fortinet's FortiOS and FortiGate.
* `fortios_report_dataset` Report dataset configuration in Fortinet's FortiOS and FortiGate.
* `fortios_report_layout` Report layout configuration in Fortinet's FortiOS and FortiGate.
* `fortios_report_setting` Report setting configuration in Fortinet's FortiOS and FortiGate.
* `fortios_report_style` Report style configuration in Fortinet's FortiOS and FortiGate.
* `fortios_report_theme` Report themes configuratio in Fortinet's FortiOS and FortiGate.
* `fortios_router_access_list6` Configure IPv6 access lists in Fortinet's FortiOS and FortiGate.
* `fortios_router_access_list` Configure access lists in Fortinet's FortiOS and FortiGate.
* `fortios_router_aspath_list` Configure Autonomous System (AS) path lists in Fortinet's FortiOS and FortiGate.
* `fortios_router_auth_path` Configure authentication based routing in Fortinet's FortiOS and FortiGate.
* `fortios_router_bfd6` Configure IPv6 BFD in Fortinet's FortiOS and FortiGate.
* `fortios_router_bfd` Configure BFD in Fortinet's FortiOS and FortiGate.
* `fortios_router_bgp` Configure BGP in Fortinet's FortiOS and FortiGate.
* `fortios_router_community_list` Configure community lists in Fortinet's FortiOS and FortiGate.
* `fortios_router_extcommunity_list` Configure extended community lists in Fortinet's FortiOS and FortiGate.
* `fortios_router_isis` Configure IS-IS in Fortinet's FortiOS and FortiGate.
* `fortios_router_key_chain` Configure key-chain in Fortinet's FortiOS and FortiGate.
* `fortios_router_multicast6` Configure IPv6 multicast in Fortinet's FortiOS and FortiGate.
* `fortios_router_multicast_flow` Configure multicast-flow in Fortinet's FortiOS and FortiGate.
* `fortios_router_multicast` Configure router multicast in Fortinet's FortiOS and FortiGate.
* `fortios_router_ospf6` Configure IPv6 OSPF in Fortinet's FortiOS and FortiGate.
* `fortios_router_ospf` Configure OSPF in Fortinet's FortiOS and FortiGate.
* `fortios_router_policy6` Configure IPv6 routing policies in Fortinet's FortiOS and FortiGate.
* `fortios_router_policy` Configure IPv4 routing policies in Fortinet's FortiOS and FortiGate.
* `fortios_router_prefix_list6` Configure IPv6 prefix lists in Fortinet's FortiOS and FortiGate.
* `fortios_router_prefix_list` Configure IPv4 prefix lists in Fortinet's FortiOS and FortiGate.
* `fortios_router_rip` Configure RIP in Fortinet's FortiOS and FortiGate.
* `fortios_router_ripng` Configure RIPng in Fortinet's FortiOS and FortiGate.
* `fortios_router_route_map` Configure route maps in Fortinet's FortiOS and FortiGate.
* `fortios_router_setting` Configure router settings in Fortinet's FortiOS and FortiGate.
* `fortios_router_static6` Configure IPv6 static routing tables in Fortinet's FortiOS and FortiGate.
* `fortios_router_static` Configure IPv4 static routing tables in Fortinet's FortiOS and FortiGate.
* `fortios_sctp_filter_profile` Configure SCTP filter profiles in Fortinet's FortiOS and FortiGate.
* `fortios_spamfilter_bwl` Configure anti-spam black/white list in Fortinet's FortiOS and FortiGate.
* `fortios_spamfilter_bword` Configure AntiSpam banned word list in Fortinet's FortiOS and FortiGate.
* `fortios_spamfilter_dnsbl` Configure AntiSpam DNSBL/ORBL in Fortinet's FortiOS and FortiGate.
* `fortios_spamfilter_fortishield` Configure FortiGuard - AntiSpam in Fortinet's FortiOS and FortiGate.
* `fortios_spamfilter_iptrust` Configure AntiSpam IP trust in Fortinet's FortiOS and FortiGate.
* `fortios_spamfilter_mheader` Configure AntiSpam MIME header in Fortinet's FortiOS and FortiGate.
* `fortios_spamfilter_options` Configure AntiSpam options in Fortinet's FortiOS and FortiGate.
* `fortios_spamfilter_profile` Configure AntiSpam profiles in Fortinet's FortiOS and FortiGate.
* `fortios_ssh_filter_profile` Configure SSH filter profile in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_802_1x_settings` Configure global 802.1X settings in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_acl_group` Configure ACL groups to be applied on managed FortiSwitch ports in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_acl_ingress` Configure ingress ACL policies to be applied on managed FortiSwitch ports in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_auto_config_custom` Policies which can override the 'default' for specific ISL/ICL/FortiLink interface in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_auto_config_default` Policies which are applied automatically to all ISL/ICL/FortiLink interfaces in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_auto_config_policy` Policy definitions which can define the behavior on auto configured interfaces in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_custom_command` Configure the FortiGate switch controller to send custom commands to managed FortiSwitch devices in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_dynamic_port_policy` Configure Dynamic port policy to be applied on the managed FortiSwitch ports through DPP device in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_flow_tracking` Configure FortiSwitch flow tracking and export via ipfix/netflow in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_fortilink_settings` Configure integrated FortiLink settings for FortiSwitch in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_global` Configure FortiSwitch global settings in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_igmp_snooping` Configure FortiSwitch IGMP snooping global settings in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_initial_config_template` Configure template for auto-generated VLANs in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_initial_config_vlans` Configure initial template for auto-generated VLAN interfaces in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_ip_source_guard_log` Configure FortiSwitch ip source guard log in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_lldp_profile` Configure FortiSwitch LLDP profiles in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_lldp_settings` Configure FortiSwitch LLDP settings in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_location` Configure FortiSwitch location services in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_mac_policy` Configure MAC policy to be applied on the managed FortiSwitch devices through NAC device in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_mac_sync_settings` Configure global MAC synchronization settings in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_managed_switch` Configure FortiSwitch devices that are managed by this FortiGate in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_nac_device` Configure/list NAC devices learned on the managed FortiSwitch ports which matches NAC policy in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_nac_settings` Configure integrated NAC settings for FortiSwitch in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_network_monitor_settings` Configure network monitor settings in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_poe` List PoE end-points status in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_port_policy` Configure port policy to be applied on the managed FortiSwitch ports through NAC device in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_ptp_interface_policy` PTP interface-policy configuration in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_ptp_policy` PTP policy configuration in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_ptp_profile` Global PTP profile in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_ptp_settings` Global PTP settings in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_qos_dot1p_map` Configure FortiSwitch QoS 802.1p in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_qos_ip_dscp_map` Configure FortiSwitch QoS IP precedence/DSCP in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_qos_qos_policy` Configure FortiSwitch QoS policy in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_qos_queue_policy` Configure FortiSwitch QoS egress queue policy in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_quarantine` Configure FortiSwitch quarantine support in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_remote_log` Configure logging by FortiSwitch device to a remote syslog server in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_security_policy_802_1x` Configure 802.1x MAC Authentication Bypass (MAB) policies in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_security_policy_captive_portal` Names of VLANs that use captive portal authentication in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_security_policy_local_access` Configure allowaccess list for mgmt and internal interfaces on managed FortiSwitch units in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_sflow` Configure FortiSwitch sFlow in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_snmp_community` Configure FortiSwitch SNMP v1/v2c communities globally in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_snmp_sysinfo` Configure FortiSwitch SNMP system information globally in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_snmp_trap_threshold` Configure FortiSwitch SNMP trap threshold values globally in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_snmp_user` Configure FortiSwitch SNMP v3 users globally in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_storm_control_policy` Configure FortiSwitch storm control policy to be applied on managed-switch ports in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_storm_control` Configure FortiSwitch storm control in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_stp_instance` Configure FortiSwitch multiple spanning tree protocol (MSTP) instances in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_stp_settings` Configure FortiSwitch spanning tree protocol (STP) in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_switch_group` Configure FortiSwitch switch groups in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_switch_interface_tag` Configure switch object tags in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_switch_log` Configure FortiSwitch logging (logs are transferred to and inserted into FortiGate event log) in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_switch_profile` Configure FortiSwitch switch profile in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_system` Configure system-wide switch controller settings in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_traffic_policy` Configure FortiSwitch traffic policy in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_traffic_sniffer` Configure FortiSwitch RSPAN/ERSPAN traffic sniffing parameters in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_virtual_port_pool` Configure virtual pool in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_vlan_policy` Configure VLAN policy to be applied on the managed FortiSwitch ports through dynamic-port-policy in Fortinet's FortiOS and FortiGate.
* `fortios_switch_controller_vlan` Configure VLANs for switch controller in Fortinet's FortiOS and FortiGate.
* `fortios_system_3g_modem_custom` 3G MODEM custom in Fortinet's FortiOS and FortiGate.
* `fortios_system_accprofile` Configure access profiles for system administrators in Fortinet's FortiOS and FortiGate.
* `fortios_system_acme` Configure ACME client in Fortinet's FortiOS and FortiGate.
* `fortios_system_admin` Configure admin users in Fortinet's FortiOS and FortiGate.
* `fortios_system_affinity_interrupt` Configure interrupt affinity in Fortinet's FortiOS and FortiGate.
* `fortios_system_affinity_packet_redistribution` Configure packet redistribution in Fortinet's FortiOS and FortiGate.
* `fortios_system_alarm` Configure alarm in Fortinet's FortiOS and FortiGate.
* `fortios_system_alias` Configure alias command in Fortinet's FortiOS and FortiGate.
* `fortios_system_api_user` Configure API users in Fortinet's FortiOS and FortiGate.
* `fortios_system_arp_table` Configure ARP table in Fortinet's FortiOS and FortiGate.
* `fortios_system_auto_install` Configure USB auto installation in Fortinet's FortiOS and FortiGate.
* `fortios_system_auto_script` Configure auto script in Fortinet's FortiOS and FortiGate.
* `fortios_system_automation_action` Action for automation stitches in Fortinet's FortiOS and FortiGate.
* `fortios_system_automation_condition` Condition for automation stitches in Fortinet's FortiOS and FortiGate.
* `fortios_system_automation_destination` Automation destinations in Fortinet's FortiOS and FortiGate.
* `fortios_system_automation_stitch` Automation stitches in Fortinet's FortiOS and FortiGate.
* `fortios_system_automation_trigger` Trigger for automation stitches in Fortinet's FortiOS and FortiGate.
* `fortios_system_autoupdate_push_update` Configure push updates in Fortinet's FortiOS and FortiGate.
* `fortios_system_autoupdate_schedule` Configure update schedule in Fortinet's FortiOS and FortiGate.
* `fortios_system_autoupdate_tunneling` Configure web proxy tunneling for the FDN in Fortinet's FortiOS and FortiGate.
* `fortios_system_central_management` Configure central management in Fortinet's FortiOS and FortiGate.
* `fortios_system_cloud_service` Configure system cloud service in Fortinet's FortiOS and FortiGate.
* `fortios_system_cluster_sync` Configure FortiGate Session Life Support Protocol (FGSP) session synchronization in Fortinet's FortiOS and FortiGate.
* `fortios_system_console` Configure console in Fortinet's FortiOS and FortiGate.
* `fortios_system_csf` Add this FortiGate to a Security Fabric or set up a new Security Fabric on this FortiGate in Fortinet's FortiOS and FortiGate.
* `fortios_system_custom_language` Configure custom languages in Fortinet's FortiOS and FortiGate.
* `fortios_system_ddns` Configure DDNS in Fortinet's FortiOS and FortiGate.
* `fortios_system_dedicated_mgmt` Configure dedicated management in Fortinet's FortiOS and FortiGate.
* `fortios_system_device_upgrade_exemptions` Configure device upgrade exemptions. Device will stop receiving upgrade notifications on the GUI in Fortinet's FortiOS and FortiGate.
* `fortios_system_device_upgrade` Independent upgrades for managed devices in Fortinet's FortiOS and FortiGate.
* `fortios_system_dhcp6_server` Configure DHCPv6 servers in Fortinet's FortiOS and FortiGate.
* `fortios_system_dhcp_server` Configure DHCP servers in Fortinet's FortiOS and FortiGate.
* `fortios_system_dns64` Configure DNS64 in Fortinet's FortiOS and FortiGate.
* `fortios_system_dns_database` Configure DNS databases in Fortinet's FortiOS and FortiGate.
* `fortios_system_dns_server` Configure DNS servers in Fortinet's FortiOS and FortiGate.
* `fortios_system_dns` Configure DNS in Fortinet's FortiOS and FortiGate.
* `fortios_system_dscp_based_priority` Configure DSCP based priority table in Fortinet's FortiOS and FortiGate.
* `fortios_system_email_server` Configure the email server used by the FortiGate various things. For example, for sending email messages to users to support user authentication features in Fortinet's FortiOS and FortiGate.
* `fortios_system_evpn` Configure EVPN instance in Fortinet's FortiOS and FortiGate.
* `fortios_system_external_resource` Configure external resource in Fortinet's FortiOS and FortiGate.
* `fortios_system_fabric_vpn` Setup for self orchestrated fabric auto discovery VPN in Fortinet's FortiOS and FortiGate.
* `fortios_system_federated_upgrade` Coordinate federated upgrades within the Security Fabric in Fortinet's FortiOS and FortiGate.
* `fortios_system_fips_cc` Configure FIPS-CC mode in Fortinet's FortiOS and FortiGate.
* `fortios_system_fm` Configure FM in Fortinet's FortiOS and FortiGate.
* `fortios_system_fortiai` Configure FortiAI in Fortinet's FortiOS and FortiGate.
* `fortios_system_fortidata` Configure FortiData in Fortinet's FortiOS and FortiGate.
* `fortios_system_fortiguard` Configure FortiGuard services in Fortinet's FortiOS and FortiGate.
* `fortios_system_fortimanager` Configure FortiManager in Fortinet's FortiOS and FortiGate.
* `fortios_system_fortindr` Configure FortiNDR in Fortinet's FortiOS and FortiGate.
* `fortios_system_fortisandbox` Configure FortiSandbox in Fortinet's FortiOS and FortiGate.
* `fortios_system_fsso_polling` Configure Fortinet Single Sign On (FSSO) server in Fortinet's FortiOS and FortiGate.
* `fortios_system_ftm_push` Configure FortiToken Mobile push services in Fortinet's FortiOS and FortiGate.
* `fortios_system_geneve` Configure GENEVE devices in Fortinet's FortiOS and FortiGate.
* `fortios_system_geoip_country` Define geoip country name-ID table in Fortinet's FortiOS and FortiGate.
* `fortios_system_geoip_override` Configure geographical location mapping for IP address(es) to override mappings from FortiGuard in Fortinet's FortiOS and FortiGate.
* `fortios_system_gi_gk` Configure Gi Firewall Gatekeeper in Fortinet's FortiOS and FortiGate.
* `fortios_system_global` Configure global attributes in Fortinet's FortiOS and FortiGate.
* `fortios_system_gre_tunnel` Configure GRE tunnel in Fortinet's FortiOS and FortiGate.
* `fortios_system_ha_monitor` Configure HA monitor in Fortinet's FortiOS and FortiGate.
* `fortios_system_ha` Configure HA in Fortinet's FortiOS and FortiGate.
* `fortios_system_health_check_fortiguard` SD-WAN status checking or health checking. Identify a server predefine by FortiGuard and determine how SD-WAN verifies that FGT can communicate with it in Fortinet's FortiOS and FortiGate.
* `fortios_system_ike` Configure IKE global attributes in Fortinet's FortiOS and FortiGate.
* `fortios_system_interface` Configure interfaces in Fortinet's FortiOS and FortiGate.
* `fortios_system_ipam` Configure IP address management services in Fortinet's FortiOS and FortiGate.
* `fortios_system_ipip_tunnel` Configure IP in IP Tunneling in Fortinet's FortiOS and FortiGate.
* `fortios_system_ips_urlfilter_dns6` Configure IPS URL filter IPv6 DNS servers in Fortinet's FortiOS and FortiGate.
* `fortios_system_ips_urlfilter_dns` Configure IPS URL filter DNS servers in Fortinet's FortiOS and FortiGate.
* `fortios_system_ips` Configure IPS system settings in Fortinet's FortiOS and FortiGate.
* `fortios_system_ipsec_aggregate` Configure an aggregate of IPsec tunnels in Fortinet's FortiOS and FortiGate.
* `fortios_system_ipv6_neighbor_cache` Configure IPv6 neighbor cache table in Fortinet's FortiOS and FortiGate.
* `fortios_system_ipv6_tunnel` Configure IPv6/IPv4 in IPv6 tunnel in Fortinet's FortiOS and FortiGate.
* `fortios_system_isf_queue_profile` Create a queue profile of switch in Fortinet's FortiOS and FortiGate.
* `fortios_system_link_monitor` Configure Link Health Monitor in Fortinet's FortiOS and FortiGate.
* `fortios_system_lldp_network_policy` Configure LLDP network policy in Fortinet's FortiOS and FortiGate.
* `fortios_system_lte_modem` Configure USB LTE/WIMAX devices in Fortinet's FortiOS and FortiGate.
* `fortios_system_mac_address_table` Configure MAC address tables in Fortinet's FortiOS and FortiGate.
* `fortios_system_management_tunnel` Management tunnel configuration in Fortinet's FortiOS and FortiGate.
* `fortios_system_mem_mgr` Configure memory manager in Fortinet's FortiOS and FortiGate.
* `fortios_system_mobile_tunnel` Configure Mobile tunnels, an implementation of Network Mobility (NEMO) extensions for Mobile IPv4 RFC5177 in Fortinet's FortiOS and FortiGate.
* `fortios_system_modem` Configure MODEM in Fortinet's FortiOS and FortiGate.
* `fortios_system_nat64` Configure NAT64 in Fortinet's FortiOS and FortiGate.
* `fortios_system_nd_proxy` Configure IPv6 neighbor discovery proxy (RFC4389) in Fortinet's FortiOS and FortiGate.
* `fortios_system_netflow` Configure NetFlow in Fortinet's FortiOS and FortiGate.
* `fortios_system_network_visibility` Configure network visibility settings in Fortinet's FortiOS and FortiGate.
* `fortios_system_ngfw_settings` Configure IPS NGFW policy-mode VDOM settings in Fortinet's FortiOS and FortiGate.
* `fortios_system_np6` Configure NP6 attributes in Fortinet's FortiOS and FortiGate.
* `fortios_system_npu_vlink` Configure NPU VDOM link in Fortinet's FortiOS and FortiGate.
* `fortios_system_npu` Configure NPU attributes in Fortinet's FortiOS and FortiGate.
* `fortios_system_ntp` Configure system NTP information in Fortinet's FortiOS and FortiGate.
* `fortios_system_object_tagging` Configure object tagging in Fortinet's FortiOS and FortiGate.
* `fortios_system_password_policy_guest_admin` Configure the password policy for guest administrators in Fortinet's FortiOS and FortiGate.
* `fortios_system_password_policy` Configure password policy for locally defined administrator passwords and IPsec VPN pre-shared keys in Fortinet's FortiOS and FortiGate.
* `fortios_system_pcp_server` Configure PCP server information in Fortinet's FortiOS and FortiGate.
* `fortios_system_performance_top` Display information about the top CPU processes in Fortinet's FortiOS and FortiGate.
* `fortios_system_physical_switch` Configure physical switches in Fortinet's FortiOS and FortiGate.
* `fortios_system_pppoe_interface` Configure the PPPoE interfaces in Fortinet's FortiOS and FortiGate.
* `fortios_system_probe_response` Configure system probe response in Fortinet's FortiOS and FortiGate.
* `fortios_system_proxy_arp` Configure proxy-ARP in Fortinet's FortiOS and FortiGate.
* `fortios_system_ptp` Configure system PTP information in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_admin` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_alertmail` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_auth` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_automation` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_device_detection_portal` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_ec` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_fortiguard_wf` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_ftp` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_group` Configure replacement message groups in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_http` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_icap` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_image` Configure replacement message images in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_mail` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_mm1` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_mm3` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_mm4` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_mm7` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_mms` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_nac_quar` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_nntp` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_spam` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_sslvpn` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_traffic_quota` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_utm` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_replacemsg_webproxy` Replacement messages in Fortinet's FortiOS and FortiGate.
* `fortios_system_resource_limits` Configure resource limits in Fortinet's FortiOS and FortiGate.
* `fortios_system_saml` Global settings for SAML authentication in Fortinet's FortiOS and FortiGate.
* `fortios_system_sdn_connector` Configure connection to SDN Connector in Fortinet's FortiOS and FortiGate.
* `fortios_system_sdn_proxy` Configure SDN proxy in Fortinet's FortiOS and FortiGate.
* `fortios_system_sdn_vpn` Configure public cloud VPN service in Fortinet's FortiOS and FortiGate.
* `fortios_system_sdwan` Configure redundant Internet connections with multiple outbound links and health-check profiles in Fortinet's FortiOS and FortiGate.
* `fortios_system_security_rating_controls` Settings for individual Security Rating controls in Fortinet's FortiOS and FortiGate.
* `fortios_system_security_rating_settings` Settings for Security Rating in Fortinet's FortiOS and FortiGate.
* `fortios_system_session_helper` Configure session helper in Fortinet's FortiOS and FortiGate.
* `fortios_system_session_ttl` Configure global session TTL timers for this FortiGate in Fortinet's FortiOS and FortiGate.
* `fortios_system_settings` Configure VDOM settings in Fortinet's FortiOS and FortiGate.
* `fortios_system_sflow` Configure sFlow in Fortinet's FortiOS and FortiGate.
* `fortios_system_sit_tunnel` Configure IPv6 tunnel over IPv4 in Fortinet's FortiOS and FortiGate.
* `fortios_system_smc_ntp` Configure SMC NTP information in Fortinet's FortiOS and FortiGate.
* `fortios_system_sms_server` Configure SMS server for sending SMS messages to support user authentication in Fortinet's FortiOS and FortiGate.
* `fortios_system_snmp_community` SNMP community configuration in Fortinet's FortiOS and FortiGate.
* `fortios_system_snmp_mib_view` SNMP Access Control MIB View configuration in Fortinet's FortiOS and FortiGate.
* `fortios_system_snmp_rmon_stat` SNMP Remote Network Monitoring (RMON) Ethernet statistics configuration in Fortinet's FortiOS and FortiGate.
* `fortios_system_snmp_sysinfo` SNMP system info configuration in Fortinet's FortiOS and FortiGate.
* `fortios_system_snmp_user` SNMP user configuration in Fortinet's FortiOS and FortiGate.
* `fortios_system_speed_test_schedule` Speed test schedule for each interface in Fortinet's FortiOS and FortiGate.
* `fortios_system_speed_test_server` Configure speed test server list in Fortinet's FortiOS and FortiGate.
* `fortios_system_speed_test_setting` Configure speed test setting in Fortinet's FortiOS and FortiGate.
* `fortios_system_ssh_config` Configure SSH config in Fortinet's FortiOS and FortiGate.
* `fortios_system_sso_admin` Configure SSO admin users in Fortinet's FortiOS and FortiGate.
* `fortios_system_sso_forticloud_admin` Configure FortiCloud SSO admin users in Fortinet's FortiOS and FortiGate.
* `fortios_system_sso_fortigate_cloud_admin` Configure FortiCloud SSO admin users in Fortinet's FortiOS and FortiGate.
* `fortios_system_standalone_cluster` Configure FortiGate Session Life Support Protocol (FGSP) cluster attributes in Fortinet's FortiOS and FortiGate.
* `fortios_system_storage` Configure logical storage in Fortinet's FortiOS and FortiGate.
* `fortios_system_stp` Configure Spanning Tree Protocol (STP) in Fortinet's FortiOS and FortiGate.
* `fortios_system_switch_interface` Configure software switch interfaces by grouping physical and WiFi interfaces in Fortinet's FortiOS and FortiGate.
* `fortios_system_tos_based_priority` Configure Type of Service (ToS) based priority table to set network traffic priorities in Fortinet's FortiOS and FortiGate.
* `fortios_system_vdom_dns` Configure DNS servers for a non-management VDOM in Fortinet's FortiOS and FortiGate.
* `fortios_system_vdom_exception` Global configuration objects that can be configured independently across different ha peers for all VDOMs or for the defined VDOM scope in Fortinet's FortiOS and FortiGate.
* `fortios_system_vdom_link` Configure VDOM links in Fortinet's FortiOS and FortiGate.
* `fortios_system_vdom_netflow` Configure NetFlow per VDOM in Fortinet's FortiOS and FortiGate.
* `fortios_system_vdom_property` Configure VDOM property in Fortinet's FortiOS and FortiGate.
* `fortios_system_vdom_radius_server` Configure a RADIUS server to use as a RADIUS Single Sign On (RSSO) server for this VDOM in Fortinet's FortiOS and FortiGate.
* `fortios_system_vdom_sflow` Configure sFlow per VDOM to add or change the IP address and UDP port that FortiGate sFlow agents in this VDOM use to send sFlow datagrams to an sFlow collector in Fortinet's FortiOS and FortiGate.
* `fortios_system_vdom` Configure virtual domain in Fortinet's FortiOS and FortiGate.
* `fortios_system_virtual_switch` Configure virtual hardware switch interfaces in Fortinet's FortiOS and FortiGate.
* `fortios_system_virtual_wan_link` Configure redundant internet connections using SD-WAN (formerly virtual WAN link) in Fortinet's FortiOS and FortiGate.
* `fortios_system_virtual_wire_pair` Configure virtual wire pairs in Fortinet's FortiOS and FortiGate.
* `fortios_system_vne_interface` Configure virtual network enabler tunnels in Fortinet's FortiOS and FortiGate.
* `fortios_system_vne_tunnel` Configure virtual network enabler tunnel in Fortinet's FortiOS and FortiGate.
* `fortios_system_vxlan` Configure VXLAN devices in Fortinet's FortiOS and FortiGate.
* `fortios_system_wccp` Configure WCCP in Fortinet's FortiOS and FortiGate.
* `fortios_system_zone` Configure zones to group two or more interfaces. When a zone is created you can configure policies for the zone instead of individual interfaces in the zone in Fortinet's FortiOS and FortiGate.
* `fortios_telemetry_controller_agent_profile` Configure FortiTelemetry agent profiles in Fortinet's FortiOS and FortiGate.
* `fortios_telemetry_controller_agent` Configure FortiTelemetry agents managed by a FortiGate unit in Fortinet's FortiOS and FortiGate.
* `fortios_telemetry_controller_application_predefine` Configure FortiTelemetry predefined applications in Fortinet's FortiOS and FortiGate.
* `fortios_telemetry_controller_global` Configure FortiTelemetry global settings in Fortinet's FortiOS and FortiGate.
* `fortios_telemetry_controller_profile` Configure FortiTelemetry profiles in Fortinet's FortiOS and FortiGate.
* `fortios_user_adgrp` Configure FSSO groups in Fortinet's FortiOS and FortiGate.
* `fortios_user_certificate` Configure certificate users in Fortinet's FortiOS and FortiGate.
* `fortios_user_device_access_list` Configure device access control lists in Fortinet's FortiOS and FortiGate.
* `fortios_user_device_category` Configure device categories in Fortinet's FortiOS and FortiGate.
* `fortios_user_device_group` Configure device groups in Fortinet's FortiOS and FortiGate.
* `fortios_user_device` Configure devices in Fortinet's FortiOS and FortiGate.
* `fortios_user_domain_controller` Configure domain controller entries in Fortinet's FortiOS and FortiGate.
* `fortios_user_exchange` Configure MS Exchange server entries in Fortinet's FortiOS and FortiGate.
* `fortios_user_external_identity_provider` Configure external identity provider in Fortinet's FortiOS and FortiGate.
* `fortios_user_fortitoken` Configure FortiToken in Fortinet's FortiOS and FortiGate.
* `fortios_user_fsso_polling` Configure FSSO active directory servers for polling mode in Fortinet's FortiOS and FortiGate.
* `fortios_user_fsso` Configure Fortinet Single Sign On (FSSO) agents in Fortinet's FortiOS and FortiGate.
* `fortios_user_group` Configure user groups in Fortinet's FortiOS and FortiGate.
* `fortios_user_krb_keytab` Configure Kerberos keytab entries in Fortinet's FortiOS and FortiGate.
* `fortios_user_ldap` Configure LDAP server entries in Fortinet's FortiOS and FortiGate.
* `fortios_user_local` Configure local users in Fortinet's FortiOS and FortiGate.
* `fortios_user_nac_policy` Configure NAC policy matching pattern to identify matching NAC devices in Fortinet's FortiOS and FortiGate.
* `fortios_user_password_policy` Configure user password policy in Fortinet's FortiOS and FortiGate.
* `fortios_user_peer` Configure peer users in Fortinet's FortiOS and FortiGate.
* `fortios_user_peergrp` Configure peer groups in Fortinet's FortiOS and FortiGate.
* `fortios_user_pop3` POP3 server entry configuration in Fortinet's FortiOS and FortiGate.
* `fortios_user_quarantine` Configure quarantine support in Fortinet's FortiOS and FortiGate.
* `fortios_user_radius` Configure RADIUS server entries in Fortinet's FortiOS and FortiGate.
* `fortios_user_saml` SAML server entry configuration in Fortinet's FortiOS and FortiGate.
* `fortios_user_scim` Configure SCIM client entries in Fortinet's FortiOS and FortiGate.
* `fortios_user_security_exempt_list` Configure security exemption list in Fortinet's FortiOS and FortiGate.
* `fortios_user_setting` Configure user authentication setting in Fortinet's FortiOS and FortiGate.
* `fortios_user_tacacsplus` Configure TACACS+ server entries in Fortinet's FortiOS and FortiGate.
* `fortios_videofilter_keyword` Configure video filter keywords in Fortinet's FortiOS and FortiGate.
* `fortios_videofilter_profile` Configure VideoFilter profile in Fortinet's FortiOS and FortiGate.
* `fortios_videofilter_youtube_channel_filter` Configure YouTube channel filter in Fortinet's FortiOS and FortiGate.
* `fortios_videofilter_youtube_key` Configure YouTube API keys in Fortinet's FortiOS and FortiGate.
* `fortios_virtual_patch_profile` Configure virtual-patch profile in Fortinet's FortiOS and FortiGate.
* `fortios_voip_profile` Configure VoIP profiles in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_certificate_ca` CA certificate in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_certificate_crl` Certificate Revocation List as a PEM file in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_certificate_hsm_local` Local certificates whose keys are stored on HSM in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_certificate_local` Local keys and certificates in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_certificate_ocsp_server` OCSP server configuration in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_certificate_remote` Remote certificate as a PEM file in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_certificate_setting` VPN certificate setting in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_ike_gateway` List gateways in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_ipsec_concentrator` Concentrator configuration in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_ipsec_fec` Configure Forward Error Correction (FEC) mapping profiles in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_ipsec_forticlient` Configure FortiClient policy realm in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_ipsec_manualkey_interface` Configure IPsec manual keys in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_ipsec_manualkey` Configure IPsec manual keys in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_ipsec_phase1_interface` Configure VPN remote gateway in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_ipsec_phase1` Configure VPN remote gateway in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_ipsec_phase2_interface` Configure VPN autokey tunnel in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_ipsec_phase2` Configure VPN autokey tunnel in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_kmip_server` KMIP server entry configuration in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_l2tp` Configure L2TP in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_ocvpn` Configure Overlay Controller VPN settings in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_pptp` Configure PPTP in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_qkd` Configure Quantum Key Distribution server in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_ssl_client` Client in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_ssl_settings` Configure Agentless VPN in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_ssl_web_host_check_software` SSL-VPN host check software in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_ssl_web_portal` Portal in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_ssl_web_realm` Realm in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_ssl_web_user_bookmark` Configure Agentless VPN user bookmark in Fortinet's FortiOS and FortiGate.
* `fortios_vpn_ssl_web_user_group_bookmark` Configure Agentless VPN user group bookmark in Fortinet's FortiOS and FortiGate.
* `fortios_waf_main_class` Hidden table for datasource in Fortinet's FortiOS and FortiGate.
* `fortios_waf_profile` Configure Web application firewall configuration in Fortinet's FortiOS and FortiGate.
* `fortios_waf_signature` Hidden table for datasource in Fortinet's FortiOS and FortiGate.
* `fortios_waf_sub_class` Hidden table for datasource in Fortinet's FortiOS and FortiGate.
* `fortios_wanopt_auth_group` Configure WAN optimization authentication groups in Fortinet's FortiOS and FortiGate.
* `fortios_wanopt_cache_service` Designate cache-service for wan-optimization and webcache in Fortinet's FortiOS and FortiGate.
* `fortios_wanopt_content_delivery_network_rule` Configure WAN optimization content delivery network rules in Fortinet's FortiOS and FortiGate.
* `fortios_wanopt_peer` Configure WAN optimization peers in Fortinet's FortiOS and FortiGate.
* `fortios_wanopt_profile` Configure WAN optimization profiles in Fortinet's FortiOS and FortiGate.
* `fortios_wanopt_remote_storage` Configure a remote cache device as Web cache storage in Fortinet's FortiOS and FortiGate.
* `fortios_wanopt_settings` Configure WAN optimization settings in Fortinet's FortiOS and FortiGate.
* `fortios_wanopt_webcache` Configure global Web cache settings in Fortinet's FortiOS and FortiGate.
* `fortios_web_proxy_debug_url` Configure debug URL addresses in Fortinet's FortiOS and FortiGate.
* `fortios_web_proxy_explicit` Configure explicit Web proxy settings in Fortinet's FortiOS and FortiGate.
* `fortios_web_proxy_fast_fallback` Proxy destination connection fast-fallback in Fortinet's FortiOS and FortiGate.
* `fortios_web_proxy_forward_server_group` Configure a forward server group consisting or multiple forward servers. Supports failover and load balancing in Fortinet's FortiOS and FortiGate.
* `fortios_web_proxy_forward_server` Configure forward-server addresses in Fortinet's FortiOS and FortiGate.
* `fortios_web_proxy_global` Configure Web proxy global settings in Fortinet's FortiOS and FortiGate.
* `fortios_web_proxy_isolator_server` Configure forward-server addresses in Fortinet's FortiOS and FortiGate.
* `fortios_web_proxy_profile` Configure web proxy profiles in Fortinet's FortiOS and FortiGate.
* `fortios_web_proxy_url_match` Exempt URLs from web proxy forwarding, caching and fast-fallback in Fortinet's FortiOS and FortiGate.
* `fortios_web_proxy_wisp` Configure Websense Integrated Services Protocol (WISP) servers in Fortinet's FortiOS and FortiGate.
* `fortios_webfilter_content_header` Configure content types used by Web filter in Fortinet's FortiOS and FortiGate.
* `fortios_webfilter_content` Configure Web filter banned word table in Fortinet's FortiOS and FortiGate.
* `fortios_webfilter_fortiguard` Configure FortiGuard Web Filter service in Fortinet's FortiOS and FortiGate.
* `fortios_webfilter_ftgd_local_cat` Configure FortiGuard Web Filter local categories in Fortinet's FortiOS and FortiGate.
* `fortios_webfilter_ftgd_local_rating` Configure local FortiGuard Web Filter local ratings in Fortinet's FortiOS and FortiGate.
* `fortios_webfilter_ftgd_local_risk` Configure FortiGuard Web Filter local risk score in Fortinet's FortiOS and FortiGate.
* `fortios_webfilter_ftgd_risk_level` Configure FortiGuard Web Filter risk level in Fortinet's FortiOS and FortiGate.
* `fortios_webfilter_ips_urlfilter_cache_setting` Configure IPS URL filter cache settings in Fortinet's FortiOS and FortiGate.
* `fortios_webfilter_ips_urlfilter_setting6` Configure IPS URL filter settings for IPv6 in Fortinet's FortiOS and FortiGate.
* `fortios_webfilter_ips_urlfilter_setting` Configure IPS URL filter settings in Fortinet's FortiOS and FortiGate.
* `fortios_webfilter_override` Configure FortiGuard Web Filter administrative overrides in Fortinet's FortiOS and FortiGate.
* `fortios_webfilter_profile` Configure Web filter profiles in Fortinet's FortiOS and FortiGate.
* `fortios_webfilter_search_engine` Configure web filter search engines in Fortinet's FortiOS and FortiGate.
* `fortios_webfilter_status` Display rating info in Fortinet's FortiOS and FortiGate.
* `fortios_webfilter_urlfilter` Configure URL filter lists in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_access_control_list` Configure WiFi bridge access control list in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_address` Configure the client with its MAC address in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_addrgrp` Configure the MAC address group in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_ap_status` Configure access point status (rogue | accepted | suppressed) in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_apcfg_profile` Configure AP local configuration profiles in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_arrp_profile` Configure WiFi Automatic Radio Resource Provisioning (ARRP) profiles in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_ble_profile` Configure Bluetooth Low Energy profile in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_bonjour_profile` Configure Bonjour profiles. Bonjour is Apple's zero configuration networking protocol. Bonjour profiles allow APs and FortiAPs to connnect to networks using Bonjour in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_client_info` Wireless controller client-info in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_global` Configure wireless controller global settings in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_hotspot20_anqp_3gpp_cellular` Configure 3GPP public land mobile network (PLMN) in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_hotspot20_anqp_ip_address_type` Configure IP address type availability in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_hotspot20_anqp_nai_realm` Configure network access identifier (NAI) realm in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_hotspot20_anqp_network_auth_type` Configure network authentication type in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_hotspot20_anqp_roaming_consortium` Configure roaming consortium in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_hotspot20_anqp_venue_name` Configure venue name duple in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_hotspot20_anqp_venue_url` Configure venue URL in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_hotspot20_h2qp_advice_of_charge` Configure advice of charge in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_hotspot20_h2qp_conn_capability` Configure connection capability in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_hotspot20_h2qp_operator_name` Configure operator friendly name in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_hotspot20_h2qp_osu_provider_nai` Configure online sign up (OSU) provider NAI list in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_hotspot20_h2qp_osu_provider` Configure online sign up (OSU) provider list in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_hotspot20_h2qp_terms_and_conditions` Configure terms and conditions in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_hotspot20_h2qp_wan_metric` Configure WAN metrics in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_hotspot20_hs_profile` Configure hotspot profile in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_hotspot20_icon` Configure OSU provider icon in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_hotspot20_qos_map` Configure QoS map set in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_inter_controller` Configure inter wireless controller operation in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_log` Configure wireless controller event log filters in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_mpsk_profile` Configure MPSK profile in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_nac_profile` Configure WiFi network access control (NAC) profiles in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_qos_profile` Configure WiFi quality of service (QoS) profiles in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_region` Configure FortiAP regions (for floor plans and maps) in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_rf_analysis` Wireless controller rf-analysis in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_setting` VDOM wireless controller configuration in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_snmp` Configure SNMP in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_spectral_info` Wireless controller spectrum analysis in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_ssid_policy` Configure WiFi SSID policies in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_status` Wireless controller status in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_syslog_profile` Configure Wireless Termination Points (WTP) system log server profile in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_timers` Configure CAPWAP timers in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_utm_profile` Configure UTM (Unified Threat Management) profile in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_vap_group` Configure virtual Access Point (VAP) groups in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_vap_status` Wireless controller VAP-status in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_vap` Configure Virtual Access Points (VAPs) in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_wag_profile` Configure wireless access gateway (WAG) profiles used for tunnels on AP in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_wids_profile` Configure wireless intrusion detection system (WIDS) profiles in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_wtp_group` Configure WTP groups in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_wtp_profile` Configure WTP profiles or FortiAP profiles that define radio settings for manageable FortiAP platforms in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_wtp_status` Wireless controller WTP-status in Fortinet's FortiOS and FortiGate.
* `fortios_wireless_controller_wtp` Configure Wireless Termination Points (WTPs), that is, FortiAPs or APs to be managed by FortiGate in Fortinet's FortiOS and FortiGate.
* `fortios_ztna_reverse_connector` Configure ZTNA Reverse-Connector in Fortinet's FortiOS and FortiGate.
* `fortios_ztna_traffic_forward_proxy_reverse_service` Configure ZTNA traffic forward proxy reverse service in Fortinet's FortiOS and FortiGate.
* `fortios_ztna_traffic_forward_proxy` Configure ZTNA traffic forward proxy in Fortinet's FortiOS and FortiGate.
* `fortios_ztna_web_portal_bookmark` Configure ztna web-portal bookmark in Fortinet's FortiOS and FortiGate.
* `fortios_ztna_web_portal` Configure ztna web-portal in Fortinet's FortiOS and FortiGate.
* `fortios_ztna_web_proxy` Configure ZTNA web-proxy in Fortinet's FortiOS and FortiGate.

## License Information

FortiOS Ansible Collection follows [GNU General Public License v3.0](./LICENSE).