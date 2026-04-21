# ansible-aci

## Description

The `ansible-aci` project provides an Ansible collection for managing and automating your Cisco Application Centric Infrastructure (ACI) environment. It consists of a set of modules and roles for performing tasks related to ACI.

See the [cisco.aci collection index](https://galaxy.ansible.com/ui/repo/published/cisco/aci/content/) for a full list of modules and plugins.

## Requirements

- Ansible v2.16 or newer
- Python v3.11 or newer

Follow the [Installing Ansible](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html) guide for detailed instructions.

## Installation

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```sh
ansible-galaxy collection install cisco.aci
```

You can also include this collection in a `requirements.yml` file and install it with:

```sh
ansible-galaxy collection install -r requirements.yml
```

Using the following `requirements.yml` format:

```yaml
collections:
  - name: cisco.aci
```

Note that if you install any collections from Ansible Galaxy, they will not be upgraded automatically when you upgrade the Ansible package.
To upgrade the collection to the latest available version, run the following command:

```sh
ansible-galaxy collection install cisco.aci --upgrade
```

You can also install a specific version of the collection. For example, to install version 1.0.0, use the following syntax:

```sh
ansible-galaxy collection install cisco.aci:==1.0.0
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

### Latest Build

Follow these instructions to get the latest collection.

#### First Approach - Build From Source Code

Clone the ansible-aci repository.

```sh
git clone https://github.com/CiscoDevNet/ansible-aci.git
```

Go to the ansible-aci directory

```sh
cd ansible-aci
```

Pull the latest master on your aci

```sh
git pull origin master
```

Build and Install a collection from source

```sh
ansible-galaxy collection build --force
ansible-galaxy collection install cisco-aci-* --force
```

#### Second Approach - Download From Latest CI Build

Go to [ansible-aci Actions](https://github.com/CiscoDevNet/ansible-aci/actions/workflows/ansible-test.yml?query=branch%3Amaster) and select the latest CI build.

Under Artifacts download collection suffixed with the latest version of Ansible (eg. `collection-stable-2.17`) and unzip it using Terminal or Console.

*Note: The collection file is a zip file containing a tar.gz file. We recommend using CLI because some GUI-based unarchiver might unarchive both nested archives in one go.*

Install the unarchived tar.gz file

```sh
ansible-galaxy collection install cisco-aci-1.0.0.tar.gz —-force
```

## Use Cases

Once the collection is installed, you can use it in a playbook by specifying the full namespace path to the module, plugin and/or role.

### Adding a new EPG

```yml
- hosts: aci
  gather_facts: no

  tasks:
  - name: Add a new EPG
    cisco.aci.aci_epg:
      hostname: apic
      username: admin
      password: SomeSecretPassword
      tenant: production
      ap: intranet
      epg: web_epg
      description: Web Intranet EPG
      bd: prod_bd
    delegate_to: localhost
```

## Optimizing Playbooks

There are two main methods to optimize the execution of ACI modules in your playbooks.

1. Using the ACI HTTPAPI plugin
1. Using the `suppress_` options

To find out more about optimizing playbook execution, please refer to the [Optimizing Playbooks](docs/optimizing.md) documentation.

## Testing

Integration tests for each module in the `cisco.aci` collection are executed on the following ACI versions:

- 4.2
- 5.2
- 6.0

## Contributing

Ongoing development efforts and contributions to this collection are tracked as issues in this repository.

We welcome community contributions to this collection. If you find problems, need an enhancement or need a new module, please open an issue or create a PR against the [Cisco ACI collection repository](https://github.com/CiscoDevNet/ansible-aci/issues).

## Support

This collection supports any ACI version within the Last Day of Support (LDOS) date.

Certain modules and options in the collection are only available from specific versions of ACI. The versions that a module or option supports are documented in the individual module documentation.

To find EOL announcements for ACI versions, refer to the [End-of-Life and End-of-Sale Notices](https://www.cisco.com/c/en/us/products/cloud-systems-management/application-policy-infrastructure-controller-apic/eos-eol-notice-listing.html) page.

## Release Notes

See the [Changelog](https://github.com/CiscoDevNet/ansible-aci/blob/master/CHANGELOG.rst) for full release notes.

## Related Information

For further information and guides, refer to the following:

- [Cisco ACI DevNet Documentation](https://developer.cisco.com/docs/aci/ansible/#cisco-aci-ansible-modules)
- [Automating ACI using Ansible](https://developer.cisco.com/docs/nexus-as-code/aci-with-ansible/#automating-aci-using-ansible)
- [ACI Programmability Learning Lab](https://developer.cisco.com/learning/tracks/aci-programmability/)

## License Information

This collection is licensed under the [GNU General Public License v3.0](https://github.com/CiscoDevNet/ansible-aci/blob/master/LICENSE)
