# google.cloud.gcloud

This role installs the gcloud command-line tool on a linux system.

## Requirements

### Debian

None

### Ubuntu

None

### CentOS

-   epel (if using archive installation)

## Role Variables

All variables which can be overridden are stored in defaults/main.yml file as well as in table below.

| Variable                       | Required | Default                                                                                | Comments                                                   |
| ------------------------------ | -------- | -------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `gcloud_install_type`          | No       | `package`                                                                              | Type of install `package` or `archive`                     |
| `gcloud_apt_url`               | No       | `http://packages.cloud.google.com/apt`                                                 | URL of the APT Repository                                  |
| `gcloud_apt_key`               | No       | `https://packages.cloud.google.com/apt/doc/apt-key.gpg`                                | GPG Key for the APT Repository                             |
| `gcloud_apt_repo`              | No       | `cloud-sdk-{{ ansible_distribution_release }}`                                         | Name of the APT Repository                                 |
| `gcloud_yum_baseurl`           | No       | `https://packages.cloud.google.com/yum/repos/cloud-sdk-el7-x86_64`                     | URL of the YUM Repository                                  |
| `gcloud_yum_key`               | No       | `https://packages.cloud.google.com/yum/doc/yum-key.gpg`                                | GPG Key for the YUM Repository                             |
| `gcloud_version`               | No       | `268.0.0`                                                                              | Version of google-cloud-sdk to install                     |
| `gcloud_archive_name`          | No       | `google-cloud-sdk-{{ gcloud_version }}-linux-{{ ansible_architecture }}.tar.gz`        | Full length name of gcloud archive                         |
| `gcloud_archive_url`           | No       | `https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/{{ gcloud_archive_name }}` | URL to download the gcloud archive                         |
| `gcloud_archive_path`          | No       | `/usr/lib`                                                                             | Where should we unpack the archive                         |
| `gcloud_library_path`          | No       | `{{ gcloud_archive_path }}/google-cloud-sdk`                                           | Path of the library after archive unpack                   |
| `gcloud_install_script`        | No       | `false`                                                                                | Boolean: Execute install.sh from archive                   |
| `gcloud_usage_reporting`       | No       | `false`                                                                                | Boolean: Disable anonymous usage reporting.                |
| `gcloud_profile_path`          | No       | `false`                                                                                | Profile to update with PATH and completion.                |
| `gcloud_command_completion`    | No       | `false`                                                                                | Boolean: Add a line for command completion in the profile  |
| `gcloud_update_path`           | No       | `false`                                                                                | Boolean: Add a line for path updating in the profile       |
| `gcloud_override_components`   | No       | `[]`                                                                                   | Override the components that would be installed by default |
| `gcloud_additional_components` | No       | `[]`                                                                                   | Additional components to installed                         |

## Example Playbook

```yaml
- hosts: servers
  roles:
     - role: google.cloud.gcloud
```

## License

MIT

## Author Information

[ericsysmin](https://ericsysmin.com)
