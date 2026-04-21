# Chocolatey Ansible Collection

|                   Build Status                   |
| :----------------------------------------------: |
| [![Build Status][pipeline-badge]][pipeline-link] |

## Description

The `chocolatey.chocolatey` Ansible Collection includes the modules required to configure Chocolatey, as well as manage packages on Windows using Chocolatey.
It contains the following modules:

| Name                          | Description                               |
|-------------------------------|-------------------------------------------|
|`win_chocolatey`               | Manage packages using chocolatey          |
|`win_chocolatey_config`        | Manage Chocolatey config settings         |
|`win_chocolatey_facts`         | Create a facts collection for Chocolatey  |
|`win_chocolatey_feature`       | Manage Chocolatey features                |
|`win_chocolatey_source`        | Manage Chocolatey sources                 |

## Requirements

- `ansible-core` >= 2.15, 2.16, 2.17
- `python` >= 3.8

### Python Dependencies

- `pywinrm`

## Installation

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```sh
ansible-galaxy collection install chocolatey.chocolatey
```

You can also include it in a requirements.yml file and install it with ansible-galaxy collection install -r requirements.yml, using the format:

```yaml
collections:
  - name: chocolatey.chocolatey
```

Note that if you install any collections from Ansible Galaxy, they will not be upgraded automatically when you upgrade the Ansible package.
To upgrade the collection to the latest available version, run the following command:

```sh
ansible-galaxy collection install chocolatey.chocolatey --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax to install version 1.0.0:

```sh
ansible-galaxy collection install chocolatey.chocolatey:==1.0.0
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

### Use Cases

Some example usages of the modules in this collection are below.

Upgrade all packages with Chocolatey:

```yaml
- name: Upgrade installed packages
  win_chocolatey:
    name: all
    state: latest
```

Install version 6.6 of `notepadplusplus`:

```yaml
- name: Install notepadplusplus version 6.6
  win_chocolatey:
    name: notepadplusplus
    version: '6.6'
```

Set the Chocolatey cache location:

```yaml
- name: Set the cache location
  win_chocolatey_config:
    name: cacheLocation
    state: present
    value: C:\Temp
```

Use Background Mode for Self-Service (Business Feature):

```yaml
- name: Use background mode for self-service
  win_chocolatey_feature:
    name: useBackgroundService
    state: enabled
```

Remove the Community Package Repository (as you have an internal repository; recommended):

```yaml
- name: Disable Community Repo
  win_chocolatey_source:
    name: chocolatey
    state: absent
```

## Testing

This collection is tested against `ansible-core` versions >= **2.15, 2.16, 2.17**.

Testing is primarily conducted on Ubuntu runners in Azure Pipelines at the latest OS version, with the collection being targeted at a Windows 10 Enterprise 21H2 client machine, using `ansible-test` to run the tests included in the collection.

## Contributing

If you want to develop new content for this collection or improve what's already here, the easiest way to work on the collection is to clone it into one of the configured [`COLLECTIONS_PATHS`](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths), and work on it there.

### Testing with `ansible-test`

The `tests` directory contains configuration for running integration tests using [`ansible-test`](https://docs.ansible.com/ansible/latest/dev_guide/testing_integration.html).

You can run the collection's test suites with the commands:

```code
ansible-test windows-integration --docker -v --color
```

## Support

Presently only the latest version of the collection is supported.

If you need to report an issue with the collection, please [file an issue on Github](https://github.com/chocolatey/chocolatey-ansible/issues/new).

## Release Notes

[Release Notes on Github](https://github.com/chocolatey/chocolatey-ansible/releases)

## Related Information

- [Chocolatey For Business Ansible Environment](https://docs.chocolatey.org/en-us/c4b-environments/ansible)

## License Information

GPL v3.0 License

See [LICENSE](LICENSE) to see full text.

<!-- Link Targets -->

[pipeline-link]: https://dev.azure.com/ChocolateyCI/Chocolatey-Ansible/_build/latest?definitionId=2&branchName=master
[pipeline-badge]: https://dev.azure.com/ChocolateyCI/Chocolatey-Ansible/_apis/build/status/Chocolatey%20Collection%20CI?branchName=master
