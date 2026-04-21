![Collection integration](https://github.com/ngine-io/ansible-collection-cloudstack/workflows/Collection%20integration/badge.svg)
 [![Codecov](https://img.shields.io/codecov/c/github/ngine-io/ansible-collection-cloudstack)](https://codecov.io/gh/ngine-io/ansible-collection-cloudstack)
[![License](https://img.shields.io/badge/license-GPL%20v3.0-brightgreen.svg)](LICENSE)

# Ansible Collection for Apache CloudStack Clouds

This collection provides a series of Ansible modules and plugins for interacting with the [Apache CloudStack](https://cloudstack.apache.org) Cloud.

## Requirements

- ansible version >= 2.9

## Installation

To install the collection hosted in Galaxy:

```bash
ansible-galaxy collection install ngine_io.cloudstack
```

To upgrade to the latest version of the collection:

```bash
ansible-galaxy collection install ngine_io.cloudstack --force
```

## Usage

### Playbooks

To use a module from Apache CloudStack collection, please reference the full namespace, collection name, and modules name that you want to use:

```yaml
---
- name: Using Apache CloudStack collection
  hosts: localhost
  tasks:
    - ngine_io.cloudstack.cs_instance:
      ...
```

Or you can add full namepsace and collecton name in the `collections` element:

```yaml
---
- name: Using Apache CloudStack collection
  hosts: localhost
  collections:
    - ngine_io.cloudstack
  tasks:
    - cs_instance:
      ...
```

### Roles

For existing Ansible roles, please also reference the full namespace, collection name, and modules name which used in tasks instead of just modules name.

### Plugins

To use a plugin, please reference the full namespace, collection name, and plugin name that you want to use:

```yaml
plugin: ngine_io.cloudstack.cloudstack
```

## Contributing

There are many ways in which you can participate in the project, for example:

- Submit bugs and feature requests, and help us verify as they are checked in
- Review source code changes
- Review the documentation and make pull requests for anything from typos to new content
- If you are interested in fixing issues and contributing directly to the code base, please see the [CONTRIBUTING](CONTRIBUTING.md) document.

## Run tests

Activate env setup of ansible core:

```
git clone git@github.com:ansible/ansible.git
cd ansible
source hacking/env-setup
```

Clone the repo:

```
git clone git@github.com:ngine-io/ansible-collection-cloudstack.git
cd ansible-collection-cloudstack
```

Run tests in docker with cloudstack simulator:
```
# All tests (note the trailing slash in `cloud/cs/`)
ansible-test integration --docker --color --diff -v cloud/cs/

# One test e.g. cs_instance (note no trailing slash in `cloud/cs/cs_instance`)
ansible-test integration --docker --color --diff -v cloud/cs/cs_instance

# Run tests for code you changed
ansible-test integration --docker --color --diff -v --changed cloud/cs/
```

## License

GNU General Public License v3.0

See [COPYING](COPYING) to see the full text.
