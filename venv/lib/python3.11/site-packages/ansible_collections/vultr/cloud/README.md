[![Collection integration](https://github.com/vultr/ansible-collection-vultr/actions/workflows/integration.yml/badge.svg?branch=main)](https://github.com/vultr/ansible-collection-vultr/actions/workflows/integration.yml) [![Codecov](https://img.shields.io/codecov/c/github/vultr/ansible-collection-vultr)](https://codecov.io/gh/vultr/ansible-collection-vultr) [![License](https://img.shields.io/badge/license-GPL%20v3.0-brightgreen.svg)](LICENSE)

# Ansible Collection for Vultr Cloud

This repository contains the `vultr.cloud` Ansible Collection . The collection will be part of the Ansible package and provides a series of Ansible modules and plugins for interacting with the [Vultr](https://www.vultr.com) Cloud. You can find the documentation for this collection on the [Ansible docs site](https://docs.ansible.com/ansible/latest/collections/vultr/cloud/).

---
**NOTE**

`vultr.cloud` is the successor of deprecated `ngine_io.vultr` collection which used the sunsetted Vultr v1 API.

---

## Ansible Version Compatibility

Tested with Ansible Core versions >= 2.14.

## Release Notes

Release notes are available in our [changelog](https://github.com/vultr/ansible-collection-vultr/blob/main/CHANGELOG.rst).

## Using this Collection

This collection will be shipped with the Ansible package >=6.0.0. If you have it installed, no more action is required.

If you have a minimal installation (only Ansible Core installed) or you want to use the latest version of the collection along with the whole Ansible package, you need to install the collection from [Ansible Galaxy](https://galaxy.ansible.com/ui/repo/published/vultr/cloud/) manually with the `ansible-galaxy` command-line tool:

    ansible-galaxy collection install vultr.cloud

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml` using the format:

```yaml
collections:
  - name: vultr.cloud
```

Note that if you install the collection manually, it will not be upgraded automatically when you upgrade the Ansible package. To upgrade the collection to the latest available version, run the following command:

```bash
ansible-galaxy collection install vultr.cloud --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax where `X.Y.Z` can be any [available version](https://galaxy.ansible.com/vultr/cloud):

```bash
ansible-galaxy collection install vultr.cloud:==X.Y.Z
```

See [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing

There are many ways in which you can participate in the project, for example:

- Submit bugs and feature requests, and help us verify as they are checked in
- Review source code changes
- Review the documentation and make pull requests for anything from typos to new content
- If you are interested in fixing issues and contributing directly to the code base, please see the [CONTRIBUTING](CONTRIBUTING.md) document.


## Run Tests

See [Testing collections](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections_testing.html) to learn how to test a collection.

### Clone the Source

```
git clone git@github.com:vultr/ansible-collection-vultr.git
cd ansible-collection-vultr
```

### Create a Virtual Environent

```
python3 -m venv .venv
source .venv/bin/activate
```

### Install Ansible

```bash
pip install ansible
```

### Setup your Vultr API Key

```bash
cp tests/integration/cloud-config-vultr.ini.origin tests/integration/cloud-config-vultr.ini
edit tests/integration/cloud-config-vultr.ini
```

### Runs Tests in Docker

All vultr tests:

```bash
ansible-test integration --docker --diff -v cloud/vultr/
```

Specific vultr test e.g. ssh_key_info:

```bash
ansible-test integration --docker --diff -v cloud/vultr/ssh_key_info
```

## Releasing

See the [Releasing Guidelines](https://docs.ansible.com/ansible/devel/community/collection_contributors/collection_releasing.html#releasing) to learn how to release this collection.

## Code of Conduct

We follow the Ansible Code of Conduct in all our interactions within this project.

If you encounter abusive behavior violating the Ansible Code of Conduct, please refer to the policy violations section of the Code of Conduct for information on how to raise a complaint.

## License

GNU General Public License v3.0

See [COPYING](COPYING) to see the full text.
