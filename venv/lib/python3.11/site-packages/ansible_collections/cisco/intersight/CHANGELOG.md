# cisco.intersight Ansible Collection Changelog

## Version 2.12.0
- Repost collection with UUID pool support added to server profile module.

## Version 2.11.0
- UUID pool support added to server profile module.

## Version 2.10.0
- Fixes #204 with support for api_response when resource_path contains a Moid.

## Version 2.9.0
- Adds support for switch control, ssh, memory, link aggregation, ldap, flow control, server pool, and certificate management policies.

## Version 2.8.0
- Fixes incorrect updates for Port, Storage, LAN, and SAN Connectivity Policies.
- Adds support for Device Connector, Drive Security, and Memory Policies.

## Version 2.7.0
- Added SAN Connectivity and FC Zone/QoS/Network/Adapter Policies, vHBA Template, and indirect node count support.

## Version 2.6.0
- Added support for VLAN ranges

## Version 2.5.0
- New iSCSI Policy and support cryptography >= 45.0 for v3 API keys

## Version 2.4.0
- New Port Policy

## Version 2.3.0
- New Policy (Storage, Link Control, KVM, IPMI, Firmware, Ethernet Adapter/Network Control/Network Group), Pool (IQN, WWxN), and Template modules

## Version 2.2.0
- New Policy (VLAN, Thermal, Syslog, SNMP, Power, Network Conn., Multicast) and Pool (UUID, MAC, IP) modules

## Version 2.1.0
- Bump minor version to support semantic versioning for new features in server_profile

## Version 2.0.21
- Info example playbook added and removed playbooks dir from collection

## Version 2.0.20
- Replace 2.0.19 release and remove unneeded directory

## Version 2.0.19
- New collection to add support for LDAP, Network Connectivity, SD Card, SMTP, SSH Policies to intersight_server_profile

## Version 2.0.18
- Add support for LDAP, Network Connectivity, SD Card, SMTP, SSH Policies to intersight_server_profile

## Version 2.0.17
- Fixes #135 to support JSON Patch of existing resources with example port_policy_json_patch.yml playbook

## Version 2.0.16
- Fixes #133 to add support for Power Policies in Server Profiles

## Version 2.0.15
- Add CI workflow and workaround for ansible-test sanity failures

## Version 2.0.14
- Fixes #127 to avoid changes to existing users in local user policies

## Version 2.0.12
- Update README to follow the Ansible Certified Collections template

## Version 2.0.11
- Fix issue #125 to avoid exceptions when local user policy does not exist

## Version 2.0.10
- Fix issue #119 to avoid incorrect resources used on deletes or updates

## Version 2.0.9
- Fix issue #114 to support $count query param

## Version 2.0.8
- Fix issue #111 to allow User Policy updates

## Version 2.0.7
- Fix issue #101 to support IMM Server Policies.
- Update deploy_server_profiles playbook to support Unassign

## Version 2.0.6
- Updated Ansible Core requirement to >=2.14.0
- ansible-lint fixes for production profile

## Version 2.0.4
- Fix issue #99 to support NVMe boot devices in intersight_boot_order_policy

## Version 2.0.1

- Updated README with requirement for Python 3.6 or newer
- Added CHANGELOG.md
- Added tests/config.yml

## Version 2.0.0

- Initial version for Ansible Automation Platform
