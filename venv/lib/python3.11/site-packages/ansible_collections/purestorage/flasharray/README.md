<a href="https://github.com/Pure-Storage-Ansible/FlashArray-Collection/releases/latest"><img src="https://img.shields.io/github/v/tag/Pure-Storage-Ansible/FlashArray-Collection?label=release">
<a href="COPYING.GPLv3"><img src="https://img.shields.io/badge/license-GPL%20v3.0-brightgreen.svg"></a>
<img src="https://cla-assistant.io/readme/badge/Pure-Storage-Ansible/FlashArray-Collection">
<img src="https://github.com/Pure-Storage-Ansible/FLashArray-Collection/workflows/Pure%20Storage%20Ansible%20CI/badge.svg">
<a href="https://github.com/psf/black"><img src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>

# Pure Storage FlashArray Collection

## Description

The Pure Storage FlashArray collection consists of the latest versions of the FlashArray modules and also includes support for Cloud Block Store

## Requirements

- Ansible 2.15 or later
- Pure Storage FlashArray system running Purity 6.1.0 or later
    - some modules require higher versions of Purity
- Some modules require specific Purity versions
- distro
- py-pure-client >= 1.75.0
- python >= 3.9
- netaddr >= 1.2.0
- requests
- pycountry
- packaging
- pyz
- urllib3

## Installation

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```
ansible-galaxy collection install purestorage.flasharray
```

You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```
collections:
  - name: purestorage.flasharray
```

Note that if you install the collection from Ansible Galaxy, it will not be upgraded automatically when you upgrade the Ansible package. 

To upgrade the collection to the latest available version, run the following command:

```
ansible-galaxy collection install purestorage.flasharray --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax to install version 1.0.0:

```
ansible-galaxy collection install purestorage.flasharray:==1.0.0
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

## Use Cases

This collection can be used to perform any task that you would normally perform using the command-line or GUI on a FlashArray. This also includes using the collection in larger playbooks to perform actions with storage-related components, such as:
* Infrastructure Drift Control
* Database Cloning
* Disaster Recovery

## Contributing

There are many ways in which you can participate in the project, for example:

* Submit bugs and feature requests, and help us verify as they are checked in
* Review source code changes
* Review the documentation and make pull requests for anything from typos to new content
* If you are interested in fixing issues and contributing directly to the code base, please see the details below:
    1. Fork this project into your account if you are a first-time contributor.
    2. Create a branch based on the latest `master` branch, commit your changes on this branch.
    3. You may merge the Pull Request in once you have the sign-off of two other developers, or if you do not have permission to do that, you may request the second reviewer to merge it for you.
 
## Support

Only the latest release of this collection is supported.

As Red Hat Ansible Certified Content, this collection is entitled to support through the Ansible Automation Platform (AAP) using the **Create issue** button on the top right corner. If a support case cannot be opened with Red Hat and the collection has been obtained either from Galaxy or GitHub, you can raise a GitHub Issue directly with the developers [here](https://github.com/Pure-Storage-Ansible/FlashArray-Collection/issues) or get community help available on the [Ansible Forum](https://forum.ansible.com/).

If you are a Pure Storage customer, you may log a support call with the Pure Storage Support team ([support\@purestorage.com](mailto:support@purestorage.com?subject=FlashArray-Ansible-Collection))

## Release Notes

Release notes for this collection can be found [here](https://github.com/Pure-Storage-Ansible/FlashArray-Collection/releases)

## Related Information
### Known Issues
* **purefa_info** - Volume tags information is only provided for the ``default`` namespace. Tags created in other namespaces are not visible to the current APIs. This is to be addressed in a future release of Purity//FA. 

### Idempotency

All modules are idempotent with the exception of modules that change or set passwords. Due to security requirements exisitng passwords can be validated against and therefore will always be modified, even if there is no change.

### Available Modules

- purefa_ad - manage FlashArray Active Directoy accounts
- purefa_admin - Configure Pure Storage FlashArray Global Admin settings
- purefa_alert - manage email alert settings on the FlashArray
- purefa_apiclient - manage FlashArray API clients
- purefa_arrayname - manage the name of the FlashArray
- pureaf_audits - get FlashArray audit events
- purefa_banner - manage the CLI and GUI login banner of the FlashArray
- purefa_cbsexpand - manage CBS FlashArray capacity expansion
- purefa_certs - manage FlashArray SSL certificates
- purefa_connect - manage FlashArrays connecting for replication purposes
- purefa_console - manage Console Lock setting for the FlashArray
- purefa_default_protection - manage FlashArray default protections
- purefa_directory - manage FlashArray managed file system directories
- purefa_dirsnap - manage FlashArray managed file system directory snapshots
- purefa_dns - manage the DNS settings of the FlashArray
- purefa_ds - manage the Directory Services of the FlashArray
- purefa_dsrole - manage the Directory Service Roles of the FlashArray
- purefa_endpoint - manage VMware protocol-endpoints on the FlashArray
- purefa_eradication - manage eradication timer for deleted items
- purefa_eula - sign, or resign, FlashArray EULA
- purefa_export - manage FlashArrray managed file system exports
- purefa_file - copy file between managed directories
- purefa_fleet - manage FlashArray Fusion fleets and members
- purefa_fs - manage FlashArray managed file systems
- purefa_hardware - manage component identification LEDs
- purefa_hg - manage hostgroups on the FlashArray
- purefa_host - manage hosts on the FlashArray
- purefa_info - get information regarding the configuration of the Flasharray
- purefa_inventory - get hardware inventory information from a FlashArray
- purefa_logging - get audit and session logs from a FlashArray
- purefa_maintenance - manage FlashArray maintenance windows
- purefa_messages - list FlashArray alert messages
- purefa_network - manage the physical and virtual network settings on the FlashArray
- purefa_ntp - manage the NTP settings on the FlashArray
- purefa_offload - manage the offload targets for a FlashArray
- purefa_pg - manage protection groups on the FlashArray
- purefa_pgsched - manage protection group snapshot and replication schedules on the FlashArray
- purefa_pgsnap - manage protection group snapshots (local and remote) on the FlashArray
- purefa_phonehome - manage the phonehome setting for the FlashArray
- purefa_pod - manage ActiveCluster pods in FlashArrays
- purefa_pod_replica - manage ActiveDR pod replica links in FlashArrays
- purefa_policy - manage FlashArray NFS, SMB and snapshot policies
- purefa_proxy - manage the phonehome HTTPS proxy setting for the FlashArray
- purefa_ra - manage the Remote Assist setting for the FlashArray
- purefa_realm - manage the FlashArray realms
- purefa_saml - manage FlashArray SAML2 service and identity providers
- purefa_sessions - get FlashArray sessions log
- purefa_smis - manage SMI-S settings on the FlashArray
- purefa_smtp - manage SMTP settings on the FlashArray
- purefa_snap - manage local snapshots on the FlashArray
- purefa_snmp - manage SNMP Manager settings on the FlashArray
- purefa_snmp_agent - manage SNMP Agent settings on the FlashArray
- purefa_sso - set Single Sign-On from Pure1 Manage state
- purefa_subnet - manage network subnets on the FlashArray
- purefa_syslog - manage the Syslog settings on the FlashArray
- purefa_syslog_settings - manage the global syslog server settings on the FlashArray
- purefa_token - manage FlashArray user API tokens
- purefa_timeout - manage the GUI idle timeout on the FlashArray
- purefa_user - manage local user accounts on the FlashArray
- purefa_vg - manage volume groups on the FlashArray
- purefa_vlan - manage VLAN interfaces on the FlashArray
- purefa_vnc - manage VNC for installed applications on the FlashArray
- purefa_volume - manage volumes on the FlashArray
- purefa_volume_tags - manage volume tags on the FlashArray
- purefa_workload - manage Fusion workloads in a Fleet

## License Information

[BSD-2-Clause](https://directory.fsf.org/wiki?title=License:FreeBSD)

[GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.en.html)

## Author

This collection was created in 2019 by [Simon Dodsley](@sdodsley) for, and on behalf of, the [Pure Storage Ansible Team](pure-ansible-team@purestorage.com)
