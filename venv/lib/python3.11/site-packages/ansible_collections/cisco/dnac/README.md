# Ansible Collection - cisco.dnac

## Ansible Modules for DNA Center

The dnacenter-ansible project provides an Ansible collection for managing and automating your Cisco DNA Center environment. It consists of a set of modules and roles for performing tasks related to DNA Center.

This collection has been tested and supports Cisco DNA Center 2.3.7.6.

*Note: This collection is not compatible with versions of Ansible before v2.8.*

Other versions of this collection have support for previous Cisco DNA Center versions. The recommended versions are listed below on the [Compatibility matrix](https://github.com/cisco-en-programmability/dnacenter-ansible#compatibility-matrix).

## Compatibility matrix
The following table shows the supported versions.

| Cisco DNA Center version | Ansible "cisco.dnac" version | Python "dnacentersdk" version |
|--------------------------|------------------------------|-------------------------------|
| 2.3.5.3                  | 6.13.3                       |  2.6.11                       |
| 2.3.7.6                  | 6.25.0                       |  2.8.3                        |
| 2.3.7.7                  | 6.30.2                       |  2.8.6                        |
| 2.3.7.9                  | 6.33.2                       |  2.8.6                        |
| 3.1.3.0                  | ^6.36.0                      |  ^2.10.1                      |

If your Ansible collection is older please consider updating it first.

*Notes*:


1. The "Python 'dnacentersdk' version" column has the minimum recommended version used when testing the Ansible collection. This means you could use later versions of the Python "dnacentersdk" than those listed.
2. The "Cisco DNA Center version" column has the value of the `dnac_version` you should use for the Ansible collection.

## Installing according to Compatibility Matrix

For example, for Cisco DNA Center 2.2.2.3, it is recommended to use Ansible "cisco.dnac" v3.3.1 and Python "dnacentersdk" v2.3.3.

To get the Python DNA Center SDK v2.3.3 in a fresh development environment:
```
sudo pip install dnacentersdk==2.3.3
```

To get the Ansible collection v3.3.1 in a fresh development environment:
```
ansible-galaxy collection install cisco.dnac:3.3.1
```

## Requirements
- Ansible >= 2.15
- [Python DNA Center SDK](https://github.com/cisco-en-programmability/dnacentersdk) v2.7.0 or newer
- Python >= 3.9, as the DNA Center SDK doesn't support Python version 2.x

## Install
Ansible must be installed ([Install guide](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html))
```
sudo pip install ansible
```

Python DNA Center SDK must be installed
```
sudo pip install dnacentersdk
```

Install the collection ([Galaxy link](https://galaxy.ansible.com/cisco/dnac))
```
ansible-galaxy collection install cisco.dnac
```
## Using this collection

There are three ways to use it:
- [Using environment variables](#using-environment-variables)
- [Using vars_files](#using-vars_files)

### Using environment variables
First, export the environment variables where you specify your DNA Center credentials as ansible variables:
```
export DNAC_HOST=<A.B.C.D>
export DNAC_PORT=443 # optional, defaults to 443
export DNAC_USERNAME=<username>
export DNAC_PASSWORD=<password>
export DNAC_VERSION=2.3.7.6 # optional, defaults to 2.3.7.6. See the Compatibility matrix
export DNAC_VERIFY=False # optional, defaults to True
export DNAC_DEBUG=False # optional, defaults to False
```

Create a `hosts` ([example](https://github.com/cisco-en-programmability/dnacenter-ansible/blob/main/playbooks/hosts)) file that uses `[dnac_servers]` with your Cisco DNA Center Settings:
```
[dnac_servers]
dnac_server
```

Then, create a playbook `myplaybook.yml` ([example](https://github.com/cisco-en-programmability/dnacenter-ansible/blob/main/playbooks/tag.yml)) referencing the variables in your credentials.yml file and specifying the full namespace path to the module, plugin and/or role:
```
- hosts: dnac_servers
  gather_facts: false
  tasks:
  - name: Create tag with name "MyNewTag"
    cisco.dnac.tag:
      state: present
      description: My Tag
      name: MyNewTag
    register: result
```

Execute the playbook:
```
ansible-playbook -i hosts myplaybook.yml
```

### Using vars_files

First, define a `credentials.yml` ([example](https://github.com/cisco-en-programmability/dnacenter-ansible/blob/main/playbooks/credentials.template)) file where you specify your DNA Center credentials as Ansible variables:
```
---
dnac_host: <A.B.C.D>
dnac_port: 443  # optional, defaults to 443
dnac_username: <username>
dnac_password: <password>
dnac_version: 2.3.7.6  # optional, defaults to 2.3.7.6. See the Compatibility matrix
dnac_verify: False  # optional, defaults to True
dnac_debug: False  # optional, defaults to False
```

Create a `hosts` ([example](https://github.com/cisco-en-programmability/dnacenter-ansible/blob/main/playbooks/hosts)) file that uses `[dnac_servers]` with your Cisco DNA Center Settings:
```
[dnac_servers]
dnac_server
```

Then, create a playbook `myplaybook.yml` ([example](https://github.com/cisco-en-programmability/dnacenter-ansible/blob/main/playbooks/tag.yml)) referencing the variables in your credentials.yml file and specifying the full namespace path to the module, plugin and/or role:
```
- hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: false
  tasks:
  - name: Create tag with name "MyNewTag"
    cisco.dnac.tag:
      dnac_host: "{{dnac_host}}"
      dnac_username: "{{dnac_username}}"
      dnac_password: "{{dnac_password}}"
      dnac_verify: "{{dnac_verify}}"
      state: present
      description: My Tag
      name: MyNewTag
    register: result
```

Execute the playbook:
```
ansible-playbook -i hosts myplaybook.yml
```
In the `playbooks` [directory](https://github.com/cisco-en-programmability/dnacenter-ansible/blob/main/playbooks) you can find more examples and use cases.


## Update
Getting the latest/nightly collection build

Clone the dnacenter-ansible repository.
```
git clone https://github.com/cisco-en-programmability/dnacenter-ansible.git
```

Go to the dnacenter-ansible directory
```
cd dnacenter-ansible
```

Pull the latest master from the repo
```
git pull origin master
```

Build and install a collection from source
```
ansible-galaxy collection build --force
ansible-galaxy collection install cisco-dnac-* --force
```

### See Also:

* [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Attention macOS users

If you're using macOS you may receive this error when running your playbook:

```
objc[34120]: +[__NSCFConstantString initialize] may have been in progress in another thread when fork() was called.
objc[34120]: +[__NSCFConstantString initialize] may have been in progress in another thread when fork() was called. We cannot safely call it or ignore it in the fork() child process. Crashing instead. Set a breakpoint on objc_initializeAfterForkError to debug.
ERROR! A worker was found in a dead state
```

If that's the case try setting this environment variable:
```
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
```

## Contributing to this collection

Ongoing development efforts and contributions to this collection are tracked as issues in this repository.

We welcome community contributions to this collection. If you find problems, need an enhancement or need a new module, please open an issue or create a PR against the [Cisco DNA Center Ansible collection repository](https://github.com/cisco-en-programmability/dnacenter-ansible/issues).

## Code of Conduct
This collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.

## Releasing, Versioning and Deprecation

This collection follows [Semantic Versioning](https://semver.org/). More details on versioning can be found [in the Ansible docs](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections.html#collection-versions).

New minor and major releases as well as deprecations will follow new releases and deprecations of the Cisco DNA Center product, its REST API and the corresponding Python SDK, which this project relies on.
