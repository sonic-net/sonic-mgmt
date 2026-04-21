# Ansible role - Alloy

[![License](https://img.shields.io/github/license/grafana/grafana-ansible-collection)](LICENSE)

This Ansible role to install and configure [Alloy](https://grafana.com/docs/alloy/latest/), which can be used to collect traces, metrics, and logs.
This role is tailored for operating systems such as **RedHat**, **Rocky Linux**, **AlmaLinux**, **Ubuntu**, **Debian**, **macOS**, and **openSUSE**.

## Table of Content

- [Requirements](#requirements)
- [Role Variables](#role-variables)
- [Playbook](#playbook)

## Requirements

- Ansible 2.13+
- `ansible.utils` collection is required. Additionally, you must install the `netaddr` Python library on the host where you are running Ansible (not on the target remote host) if is not present.
- `community.general` collection is required for macOS support
- **macOS**: Homebrew must be installed

## Role Variables

| Variable Name         | Description                                                          | Default Value                                                       |
|-----------------------|----------------------------------------------------------------------|---------------------------------------------------------------------|
| `alloy_version`             | The version of Alloy to download and deploy. Supported standard version "1.4.2" format or "latest". | `latest` |
| `alloy_uninstall`           | If set to `true` will perfom uninstall instead of deployment. | `false` |
| `alloy_expose_port`         | By default, this is set to false. It supports only simple firewalld configurations. If set to true, a firewalld rule is added to expose the TCP alloy port. The Port is automatically extracted from the environment variable `alloy_env_file_vars` in CUSTOM_ARGS when --server.http.listen-addr=0.0.0.0:12345 is defined. If set to false, configuration is skipped. If the firewalld.service is not active, all firewalld tasks are skipped. | `false` |
| `alloy_user_groups`         | Appends the alloy user to specific groups. | `[]` |
| `alloy_github_api_url`      | The default Github API URL to check for the latest version available. | `"https://api.github.com/repos/grafana/alloy/releases/latest"` |
| `alloy_download_url_rpm`    | The default download URL for the Alloy rpm package from GitHub. | `"https://github.com/grafana/alloy/releases/download/v{{ aloy_version }}/alloy-{{ aloy_version }}-1.{{ __alloy_arch }}.rpm"` |
| `alloy_download_url_deb`    | The default download URL for the Alloy deb package from GitHub. | `"https://github.com/grafana/alloy/releases/download/v{{ aloy_version }}/alloy-{{ aloy_version }}-1.{{ __alloy_arch }}.deb"` |
| `alloy_readiness_check_use_https` | This boolean variable determines whether the readiness check for the Alloy server should use HTTPS or HTTP when validating the `/-/ready` endpoint. This variable does not enable TLS on the Alloy server itself.  | `false` |
| `alloy_readiness_check_use_proxy` | This boolean variable determines whether the readiness check for the Alloy server should use a proxy when validating the `/-/ready` endpoint.  If false, it will not use a proxy, even if one is defined in an environment variable on the target hosts.  | `true` |
| `alloy_env_file_vars`       | You can use environment variables to control the run-time behavior of Grafana Alloy. | `{}` |
| `alloy_systemd_override`    | Systemd unit drop-in file used to override or extend the default configuration of a systemd unit. | `{}` |
| `alloy_config`              | This is the configuration that sets up Alloy. Refer to the [configuration blocks](https://grafana.com/docs/alloy/latest/reference/config-blocks/) and [components](https://grafana.com/docs/alloy/latest/reference/components/) documentation for more details. Since the purpose of using Alloy varies, no default configuration is provided. ⚠️ **You must provide either `alloy_config` for single config or set `alloy_env_file_vars.CONFIG_FILE` for multi-config setup**. Note that if you use `alloy_env_file_vars.CONFIG_FILE`, the content of `alloy_config` will not be templated. It is expected that you manage the multi-config content using pre_tasks or with your own role. | `{}` |

## Dependencies

No Dependencies

## Playbook

```yaml
- name: Manage alloy service
  hosts: all
  become: true
  vars:
    # alloy_config: |
    #   Your Config Content
  roles:
    - role: grafana.grafana.alloy
```

- Playbook execution example
```shell
# Deploy Alloy
ansible-playbook function_alloy_play.yml

# Uninstall Alloy
ansible-playbook function_alloy_play.yml -e "alloy_uninstall=true"
```

## License

See [LICENSE](https://github.com/grafana/grafana-ansible-collection/blob/main/LICENSE)

## Author Information

-   [Ishan Jain](https://github.com/ishanjainn)
-   [VoidQuark](https://github.com/voidquark)
