# cisco.ucs Collection Development Notes

### Current Development Status

These object specific modules cover a very small set of UCS Manager managed objects. For UCS objects that do not
have a specific module below use `ucs_managed_objects`. This module accepts either JSON or YAML
when used as a task in a playbook. Review `playbooks/ucs_managed_objects` playbook for examples.

| Configuration Category | Configuration Task | Module Name |
| ---------------------- | ------------------ | ----------- |
| Objects        | | |
|                        | Any UCS Object | cisco.ucs.ucs_managed_objects |
| Query                  | | |
|                        | Query Classes or DNs | cisco.ucs.ucs_query |
|                        | VLAN Find | cisco.ucs.ucs_vlan_find
| Organizations          | | |
|                        | Organizations | cisco.ucs.ucs_org |
| Servers                | | |
|                        | Graphics Card Policy | cisco.ucs.ucs_graphics_card_policy |
|                        | Scrub Policy | cisco.ucs.ucs_scrub_policy |
|                        | Serial Over Lan Policy | cisco.ucs.ucs_serial_over_lan_policy |
|                        | Service Profile Template | cisco.ucs.ucs_service_profile_template |
|                        | Service Profile from Template | cisco.ucs.ucs_service_profile_from_template |
|                        | UUID Suffix Pool | cisco.ucs.ucs_uuid_pool |
| LAN                    | | |
|                        | IP Addresses for KVM Access | cisco.ucs.ucs_ip_pool |
|                        | LAN Connectivity Policy | cisco.ucs.ucs_lan_connectivity |
|                        | MAC Address Pools | cisco.ucs.ucs_mac_pool |
|                        | System QOS | cisco.ucs.ucs_system_qos |
|                        | vNIC Template | cisco.ucs.ucs_vnic_template |
|                        | VLANs | cisco.ucs.ucs_vlans |
| SAN                    | | |
|                        | SAN Connectivity Policy | cisco.ucs.ucs_san_connectivity |
|                        | vHBA Template | cisco.ucs.ucs_vhba_template |
|                        | VSANs | cisco.ucs.ucs_vsans |
|                        | WWN Pool | cisco.ucs.ucs_wwn_pool |
| Storage                | | |
|                        | Disk Group Policy | cisco.ucs.ucs_disk_group_policy |
|                        | Storage Profile | cisco.ucs.ucs_storage_profile |
| Admin                  | | |
|                        | DNS Server | cisco.ucs.ucs_dns_server |
|                        | NTP Server | cisco.ucs.ucs_ntp_server |
|                        | Time Zone | cisco.ucs.ucs_timezone |

### Ansible Development Notes

Modules in development follow processes documented at http://docs.ansible.com/ansible/latest/dev_guide/developing_modules_general.html.  The modules support ansible-doc and should eventually have integration tests.

When developing modules in this repository, here are a few helpful commands to sanity check the code and documentation (replace module_name with your module (e.g., intersight_objects)).  Ansible modules won't generally be pylint or pycodestyle (PEP8) clean without disabling several of the checks:
  ```
  pylint --disable=invalid-name,no-member,too-many-nested-blocks,redefined-variable-type,too-many-statements,too-many-branches,broad-except,line-too-long,missing-docstring,wrong-import-position,too-many-locals,import-error <module_name>.py
  
  pycodestyle --max-line-length 160 --config /dev/null --ignore E402 <module_name>.py
  
  ansible-doc <module_name>
  ```

# Community:

* We are on Slack (https://ciscoucs.slack.com/) - Slack requires registration, but the ucspython team is open invitation to
  anyone.  Click [here](https://ucspython.herokuapp.com) to register 
