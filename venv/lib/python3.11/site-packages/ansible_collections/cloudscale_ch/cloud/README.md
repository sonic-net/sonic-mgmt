
![Collection Integration tests](https://github.com/cloudscale-ch/ansible-collection-cloudscale/workflows/Collection%20Integration%20tests/badge.svg)
[![Codecov](https://img.shields.io/codecov/c/github/cloudscale-ch/ansible-collection-cloudscale)](https://codecov.io/gh/cloudscale-ch/ansible-collection-cloudscale)
[![License](https://img.shields.io/badge/license-GPL%20v3.0-brightgreen.svg)](LICENSE)

# Ansible Collection for cloudscale.ch Cloud

This collection provides a series of Ansible modules and plugins for interacting with the [cloudscale.ch](https://www.cloudscale.ch) Cloud.

## Installation

To install the collection hosted in Galaxy:

```bash
ansible-galaxy collection install cloudscale_ch.cloud
```

To upgrade to the latest version of the collection:

```bash
ansible-galaxy collection install cloudscale_ch.cloud --force
```

## Usage

### Playbooks

To use a module from the cloudscale.ch collection, please reference the full namespace, collection name, and modules name that you want to use:

```yaml
---
- name: Using cloudscale.ch collection
  hosts: localhost
  tasks:
    - cloudscale_ch.cloud.server:
        name: web1
        image: debian-10
        flavor: flex-2
        ssh_keys:
          - ssh-rsa XXXXXXXXXX...XXXX ansible@cloudscale
        server_groups: web-group
        zone: lpg1
        api_token: ...
```

Or you can add the full namespace and collection name in the `collections` element:

```yaml
---
- name: Using cloudscale.ch collection
  hosts: localhost
  collections:
    - cloudscale_ch.cloud
  tasks:
    - server:
        name: web1
        image: debian-10
        flavor: flex-2
        ssh_keys:
          - ssh-rsa XXXXXXXXXX...XXXX ansible@cloudscale
        server_groups: web-group
        zone: lpg1
        api_token: ...
```

### Roles

For existing Ansible roles, please also reference the full namespace, collection name, and modules name that are used in tasks instead of just modules name.

### Plugins

To use a plugin, please reference the full namespace, collection name, and plugins name that you want to use:

```yaml
plugin: cloudscale_ch.cloud.<myplugin>
```

## Contributing

There are many ways in which you can participate in the project, for example:

- Submit bugs and feature requests, and help us verify them as they are checked in
- Review source code changes
- Review the documentation and make pull requests for anything from typos to new content
- If you are interested in fixing issues and contributing directly to the code base, please see the [CONTRIBUTING](CONTRIBUTING.md) document.

## Releasing

### Prepare a new release

The changelog is managed using the `antsibull` tool. You can install
it using `pip install antsibull`

1. Update version in galaxy.yml
2. Update changelog using antsibull
```
antsibull-changelog release
```
3. Commit changelog and new version
```
git commit -m "Release version X.Y.Z" galaxy.yml CHANGELOG.rst changelogs/
```
4. Tag the release. Preferably create a GPG signed tag if you have a GPG
key. Version tags should be prefixed with "v" (otherwise the
integration tests won't run automatically).
```
git tag -s -m "Version X.Y.Z" vX.Y.Z
```
5. Push the release and tag
```
git push origin master vX.Y.Z
```

### Release to Ansible Galaxy

After the release is tagged and pushed to Github a release to Ansible
Galaxy can be created using the release feature in Github:

1. **Wait for integration tests to succeed. They should automatically
run on new tags.** Only release if they succeed. Otherwise delete the
tag and fix the issue.
2. Create a release on Github by going to the release overview and
   selecting "Draft a new release".

## License

GNU General Public License v3.0

See [COPYING](COPYING) to see the full text.
