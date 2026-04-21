<a href="https://github.com/Pure-Storage-Ansible/FlashBlade-Collection/releases/latest"><img src="https://img.shields.io/github/v/tag/Pure-Storage-Ansible/FlashBlade-Collection?label=release">
<a href="COPYING.GPLv3"><img src="https://img.shields.io/badge/license-GPL%20v3.0-brightgreen.svg"></a>
<img src="https://cla-assistant.io/readme/badge/Pure-Storage-Ansible/FlashBlade-Collection">
<img src="https://github.com/Pure-Storage-Ansible/FLashBlade-Collection/workflows/Pure%20Storage%20Ansible%20CI/badge.svg">
<a href="https://github.com/psf/black"><img src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>
    
# Pure Storage FlashBlade Collection

## Description

The Pure Storage FlashBlade collection consists of the latest versions of the FlashBlade modules.

## Requirements

- Ansible 2.15 or later
- Pure Storage FlashBlade system running Purity//FB 3.3.3 or later
- py-pure-client >=v1.67.2
- python >=3.9
- netaddr
- datetime
- pytz
- distro
- pycountry
- urllib3

## Installation

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```
ansible-galaxy collection install purestorage.flashblade
```

You can also include it in a `requirements.yml` file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```
collections:
  - name: purestorage.flashblade
```

Note that if you install the collection from Ansible Galaxy, it will not be upgraded automatically when you upgrade the Ansible package. 

To upgrade the collection to the latest available version, run the following command:

```
ansible-galaxy collection install purestorage.flashblade --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax to install version 1.0.0:

```
ansible-galaxy collection install purestorage.flashblade:==1.0.0
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

## Use Cases

This collection can be used to perform any task that you would normally perform using the command-line or GUI on a FlashBlade. This also includes using the collection in larger playbooks to perform actions with storage-related components, such as:
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

For support please raise a GitHub Issue on this repository.

If you are a Pure Storage customer, you may log a support call with the Pure Storage Support team ([support\@purestorage.com](mailto:support@purestorage.com?subject=FlashBlade-Ansible-Collection))

If you have a Red Hat Ansible support contract, as this is a Certified collection, you may log a support call with Red Hat directly.
  
## Release Notes

Release notes for this collection can be found [here](https://github.com/Pure-Storage-Ansible/FlashBlade-Collection/releases)

## Related Information
### Idempotency

All modules are idempotent with the exception of modules that change or set passwords. Due to security requirements exisitng passwords can be validated against and therefore will always be modified, even if there is no change.

### Available Modules

- purefb_ad - manage Active Directory account on FlashBlade
- purefb_alert - manage alert email settings on a FlashBlade
- purefb_apiclient - manage API clients for FlashBlade
- purefb_banner - manage FlashBlade login banner
- purefb_bladename - manage FlashBlade name
- purefb_bucket - manage S3 buckets on a FlashBlade
- purefb_bucket_access - manage S3 bucket access policies on a FlashBlade
- purefb_bucket_replica - manage bucket replica links on a FlashBlade
- purefb_certgrp - manage FlashBlade certificate groups
- purefb_certs - manage FlashBlade SSL certificates
- purefb_connect - manage connections between FlashBlades
- purefb_dns - manage DNS settings on a FlashBlade
- purefb_ds - manage Directory Services settings on a FlashBlade
- purefb_dsrole - manage Directory Service Roles on a FlashBlade
- purefb_eula - manage EULA on FlashBlade
- purefb_fleet - manage Fusion fleet members
- purefb_fs - manage filesystems on a FlashBlade
- purefb_fs_replica - manage filesystem replica links on a FlashBlade
- purefb_groupquota - manage individual group quotas on FlashBlade filesystems
- purefb_hardware - manage hardware LED identifiers and hardware connectors
- purefb_info - get information about the configuration of a FlashBlade
- purefb_inventory - get information about the hardware inventory of a FlashBlade
- purefb_keytabs - manage FlashBlade Kerberos keytabs
- purefb_kmip - manage FlashBlade KMIP servers
- purefb_lag - manage FlashBlade Link Aggregation Groups
- purefb_lifecycle - manage FlashBlade Bucket Lifecycle Rules
- purefb_messages - list FlashBlade alert messages
- purefb_network - manage the network settings for a FlashBlade
- purefb_ntp - manage the NTP settings for a FlashBlade
- purefb_phonehome - manage the phone home settings for a FlashBlade
- purefb_pingtrace - perform FlashBlade network diagnostics
- purefb_policy - manage the filesystem snapshot policies for a FlashBlade
- purefb_proxy - manage the phone home HTTP proxy settings for a FlashBlade
- purefb_ra - manage the Remote Assist connections on a FlashBlade
- purefb_remote_cred - manage the Object Store Remote Credentials on a FlashBlade
- purefb_s3acc - manage the object store accounts on a FlashBlade
- purefb_s3user - manage the object atore users on a FlashBlade
- purefb_saml - manage FlashBlade SAML2 service and identity providers
- purefb_server - manage FlashBlade servers
- purefb_smtp - manage SMTP settings on a FlashBlade
- purefb_snap - manage filesystem snapshots on a FlashBlade
- purefb_snmp_agent - modify the FlashBlade SNMP Agent
- purefb_snmp_mgr - manage SNMP Managers on a FlashBlade
- purefb_subnet - manage network subnets on a FlashBlade
- purefb_syslog - manage FlashBlade syslog server configuration
- purefb_target - manage remote S3-capable targets for a FlashBlade
- purefb_timeout - manage FlashBlade GUI timeout
- purefb_user - manage local *pureuser* account password on a FlashBlade
- purefb_userpolicy - manage FlashBlade Object Store User Access Policies
- purefb_userquota - manage individual user quotas on FlashBlade filesystems
- purefb_virtualhost - manage FlashBlade Object Store Virtual Hosts

## License Information

[BSD-2-Clause](https://directory.fsf.org/wiki?title=License:FreeBSD)

[GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.en.html)

## Author

This collection was created in 2019 by [Simon Dodsley](@sdodsley) for, and on behalf of, the [Pure Storage Ansible Team](pure-ansible-team@purestorage.com)
