# ansible-mso

## Description

The `ansible-mso` project provides an Ansible collection for managing and automating your Cisco ACI Multi-Site or Nexus Dashboard Orchestrator environments.
It consists of a set of modules and roles for performing tasks related to ACI Multi-Site.

See the [cisco.mso collection index](https://galaxy.ansible.com/ui/repo/published/cisco/mso/content/) for a full list of modules and plugins.

*Note: The Nexus Dashboard (ND) HTTPAPI connection plugin should be used when Cisco ACI Multi-Site is installed on Nexus Dashboard (v3.2+) or when using this collection with Nexus Dashboard Orchestrator (v3.6+).*

## Requirements

- Ansible v2.16 or newer
- Python v3.11 or newer

Follow the [Installing Ansible](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html) guide for detailed instructions.

## Installation

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```sh
ansible-galaxy collection install cisco.mso
```

You can also include this collection in a requirements.yml file and install it with:

```sh
ansible-galaxy collection install -r requirements.yml
```

Using the following `requirements.yml` format:

```yaml
collections:
  - name: cisco.mso
```

Note that if you install any collections from Ansible Galaxy, they will not be upgraded automatically when you upgrade the Ansible package.
To upgrade the collection to the latest available version, run the following command:

```sh
ansible-galaxy collection install cisco.mso --upgrade
```

You can also install a specific version of the collection. For example, to install version 1.0.0, use the following syntax:

```sh
ansible-galaxy collection install cisco.mso:==1.0.0
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

### Installation with Nexus Dashboard

Install the Nexus Dashboard (ND) collection when Cisco ACI Multi-Site is installed on Nexus Dashboard (v3.2+) or when using this collection with Nexus Dashboard Orchestrator (v3.6+)

```sh
ansible-galaxy collection install cisco.nd
```

### Latest Build

Follow these instructions to get the latest collection.

#### First Approach - Build From Source Code

Clone the `ansible-mso` repository.

```sh
git clone https://github.com/CiscoDevNet/ansible-mso.git
```

Go to the `ansible-mso` directory

```sh
cd ansible-mso
```

Pull the latest master on your mso

```sh
git pull origin master
```

Build and Install a collection from source

```sh
ansible-galaxy collection build --force
ansible-galaxy collection install cisco-mso-* --force
```

#### Second Approach - Download From Latest CI Build

Go to [ansible-mso Actions](https://github.com/CiscoDevNet/ansible-mso/actions/workflows/ansible-test.yml?query=branch%3Amaster) and select the latest CI build.

Under Artifacts download collection suffixed with the latest version of Ansible (eg. `collection-stable-2.17`) and unzip it using Terminal or Console.

*Note: The collection file is a zip file containing a tar.gz file. We recommend using CLI because some GUI-based unarchiver might unarchive both nested archives in one go.*

Install the unarchived tar.gz file

```sh
ansible-galaxy collection install cisco-mso-1.0.0.tar.gz —-force
```

## Use Cases

Once the collection is installed, you can use it in a playbook by specifying the full namespace path to the module, plugin and/or role.

### Adding a new site EPG

```yaml
- hosts: mso
  gather_facts: no

  tasks:
  - name: Add a new site EPG
    cisco.mso.mso_schema_site_anp_epg:
      host: mso_host
      username: admin
      password: SomeSecretPassword
      schema: Schema1
      site: Site1
      template: Template1
      anp: ANP1
      epg: EPG1
      state: present
```

## MSO HTTPAPI Plugin

You can use the MSO HTTPAPI connection plugin by setting the following variables in your inventory file (cisco.mso collection v1.2+).

```yaml
ansible_connection=ansible.netcommon.httpapi
ansible_network_os=cisco.mso.mso
```

The HTTPAPI connection plugin will also allow you to specify additional parameters as variable and omit them from the task itself. Module parameters will override global variables.

```yaml
ansible_host=10.0.0.1
ansible_user=admin
ansible_ssh_pass="MySuperPassword"
ansible_httpapi_validate_certs=False
ansible_httpapi_use_ssl=True
ansible_httpapi_use_proxy=True
```

You should use the Nexus Dashboard (ND) collection plugin, which is available in the [cisco.nd](https://galaxy.ansible.com/cisco/nd) collection, when Cisco ACI Multi-Site is installed on Nexus Dashboard (v3.2+) or when using this collection with Nexus Dashboard Orchestrator (v3.6+) by changing the following variables.

```yaml
ansible_connection=ansible.netcommon.httpapi
ansible_network_os=cisco.nd.nd
ansible_httpapi_use_ssl=True
```

## Testing

Integration tests for each module in the `cisco.mso` collection are executed on the following Nexus Dashboard Orchestrator versions:

- 3.7
- 4.1
- 4.2
- 4.3

## Contributing

Ongoing development efforts and contributions to this collection are tracked as issues in this repository.

We welcome community contributions to this collection. If you find problems, need an enhancement or need a new module, please open an issue or create a PR against the [Cisco MSO collection repository](https://github.com/CiscoDevNet/ansible-mso/issues).

## Support

This collection supports any MSO/NDO version within the Last Day of Support (LDOS) date.

Certain modules and options in the collection are only available from specific versions of MSO/NDO. The versions that a module or option supports are documented in the individual module documentation.

To find EOL announcements for MSO/NDO versions, refer to the [End-of-Life and End-of-Sale Notices](https://www.cisco.com/c/en/us/products/cloud-systems-management/multi-site-orchestrator/eos-eol-notice-listing.html) page.

## Release Notes

See the [Changelog](https://github.com/CiscoDevNet/ansible-mso/blob/master/CHANGELOG.rst) for full release notes.

## Related Information

For further information, refer to the following:

- [Automating Cisco MSO with Ansible Learning Lab](https://developer.cisco.com/learning/labs/mso-ansible_part1-intro/setup-an-ansible-and-mso-environment/)
- [Nexus Dashboard Orchestrator Overview](https://www.cisco.com/c/en/us/products/collateral/cloud-systems-management/multi-site-orchestrator/nb-06-mso-so-cte-en.html)
- [Nexus Dashboard Orchestrator Support Documentation](https://www.cisco.com/c/en/us/support/cloud-systems-management/multi-site-orchestrator/series.html)
- [Nexus Dashboard Orchestrator API Release Notes](https://developer.cisco.com/docs/search/?q=Nexus+Dashboard+Orchestrator)

## License Information

This collection is licensed under the [GNU General Public License v3.0](https://github.com/CiscoDevNet/ansible-mso/blob/master/LICENSE)
