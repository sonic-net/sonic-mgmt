<p><img src="https://grafana.com/blog/assets/img/blog/timeshift/grafana_release_icon.png" alt="grafana logo" title="grafana" align="right" height="60" /></p>

# Ansible Role: grafana.grafana.grafana

[![License](https://img.shields.io/badge/license-MIT%20License-brightgreen.svg)](https://opensource.org/licenses/MIT)

Provision and manage [Grafana](https://github.com/grafana/grafana) - platform for analytics and monitoring

## Requirements

- Ansible >= 2.9 (It might work on previous versions, but we cannot guarantee it)
- libselinux-python on deployer host (only when deployer machine has SELinux)
- Grafana >= 5.1 (for older Grafana versions use this role in version 0.10.1 or earlier)
- jmespath on deployer machine. If you are using Ansible from a Python virtualenv, install *jmespath* to the same virtualenv via pip.

## Role Variables

All variables which can be overridden are stored in [defaults/main.yml](defaults/main.yml) file as well as in table below.

| Name           | Default Value | Description                        |
| -------------- | ------------- | -----------------------------------|
| `grafana_use_provisioning` | true | Use Grafana provisioning capability when possible (**grafana_version=latest will assume >= 5.0**). |
| `grafana_provisioning_synced` | false | Ensure no previously provisioned dashboards are kept if not referenced anymore. |
| `grafana_version` | latest | Grafana package version |
| `grafana_manage_repo` | true | Manage package repository (or don't) |
| `grafana_yum_repo` | https://rpm.grafana.com | Yum repository URL |
| `grafana_yum_key` | https://rpm.grafana.com/gpg.key | Yum repository gpg key |
| `grafana_rhsm_subscription` | | rhsm subscription name (redhat subscription-manager) |
| `grafana_rhsm_repo` | | rhsm repository name (redhat subscription-manager) |
| `grafana_apt_release_channel` | stable | Apt release chanel (stable or beta) |
| `grafana_apt_arch` | {{ 'arm64' if ansible_facts['architecture'] == 'aarch64' else 'amd64' }} | Apt architecture | 
| `grafana_apt_repo` | deb [arch={{ grafana_apt_arch }} signed-by=/usr/share/keyrings/grafana.asc] https://apt.grafana.com/ {{ grafana_apt_release_channel }} main | Apt repository string |
| `grafana_apt_key` | https://apt.grafana.com/gpg.key | Apt repository gpg key |
| `grafana_ini.instance_name` | {{ ansible_facts['fqdn'] \| default(ansible_host) \| default(inventory_hostname) }} | Grafana instance name |
| `grafana_ini.paths.logs` | /var/log/grafana | Path to logs directory |
| `grafana_ini.paths.data` | /var/lib/grafana | Path to database directory |
| `grafana_ini.server.http_addr` | 0.0.0.0 | Address on which Grafana listens |
| `grafana_ini.server.http_port` | 3000 | port on which Grafana listens |
| `grafana_cap_net_bind_service` | false | Enables the use of ports below 1024 without root privileges by leveraging the 'capabilities' of the linux kernel. read: http://man7.org/linux/man-pages/man7/capabilities.7.html |
| `grafana_ini.server.root_url` | "http://{{ grafana_ini.server.http_addr }}:{{ grafana_ini.server.http_port }}" | Full URL used to access Grafana from a web browser |
| `grafana_api_url` | "{{ grafana_url }}" | URL used for API calls in provisioning if different from public URL. See [this issue](https://github.com/cloudalchemy/ansible-grafana/issues/70). |
| `grafana_ini.server.domain` | "{{ ansible_facts['fqdn'] \| default(ansible_host) \| default('localhost') }}" | setting is only used in as a part of the `root_url` option. Useful when using GitHub or Google OAuth |
| `grafana_ini.server` | { protocol: http, enforce_domain: false, socket: "", cert_key: "", cert_file: "", enable_gzip: false, static_root_path: public, router_logging: false } | [server](http://docs.grafana.org/installation/configuration/#server) configuration section |
| `grafana_ini.security` | { admin_user: admin, admin_password: "" } | [security](http://docs.grafana.org/installation/configuration/#security) configuration section |
| `grafana_ini.database` | { type: sqlite3 } | [database](http://docs.grafana.org/installation/configuration/#database) configuration section |
| `grafana_ini.users` | { allow_sign_up: false, auto_assign_org_role: Viewer, default_theme: dark } | [users](http://docs.grafana.org/installation/configuration/#users) configuration section |
| `grafana_ini.auth` | {} | [authorization](http://docs.grafana.org/installation/configuration/#auth) configuration section |
| `grafana_ldap` | {} | [ldap](http://docs.grafana.org/installation/ldap/) configuration section. group_mappings are expanded, see defaults for example |
| `grafana_dashboards` | [] | List of dashboards which should be imported |
| `grafana_dashboards_dir` | "dashboards" | Path to a local directory containing dashboards files in `json` format |
| `grafana_datasources` | [] | List of datasources which should be configured |
| `grafana_environment` | {} | Optional Environment param for Grafana installation, useful ie for setting http_proxy |
| `grafana_plugins` | [] |  List of Grafana plugins which should be installed |
| `grafana_alert_notifications` | [] | List of alert notification channels to be created, updated, or deleted |

Data source example:

```yaml
grafana_datasources:
  - name: prometheus
    type: prometheus
    access: proxy
    url: 'http://{{ prometheus_web_listen_address }}'
    basicAuth: false
```

Dashboard example:

```yaml
grafana_dashboards:
  - dashboard_id: 111
    revision_id: 1
    datasource: prometheus
```

Alert notification channel example:

**NOTE**: setting the variable `grafana_alert_notifications` will only come into
effect when `grafana_use_provisioning` is `true`. That means the new
provisioning system using config files, which is available starting from Grafana
v5.0, needs to be in use.

```yaml
grafana_alert_notifications:
  notifiers:
    - name: Channel 1
      type: email
      uid: channel1
      is_default: false
      send_reminder: false
      settings:
        addresses: "example@example.com"
        autoResolve: true
  delete_notifiers:
    - name: Channel 2
      uid: channel2
```

## Supported CPU Architectures

Historically packages were taken from different channels according to CPU architecture. Specifically, armv6/armv7 and aarch64/arm64 packages were via [unofficial packages distributed by fg2it](https://github.com/fg2it/grafana-on-raspberry). Now that Grafana publishes official ARM builds, all packages are taken from the official [Debian/Ubuntu](http://docs.grafana.org/installation/debian/#installing-on-debian-ubuntu) or [RPM](http://docs.grafana.org/installation/rpm/) packages.

## Example

### Playbook

Fill in the admin password field with your choice, the Grafana web page won't ask to change it at the first login.

```yaml
- hosts: all
  roles:
    - role: grafana.grafana.grafana
      vars:
        grafana_ini:
          security:
            admin_user: admin
            admin_password: enter_your_secure_password
```


## Local Testing

The preferred way of locally testing the role is to use Docker and [molecule](https://github.com/ansible-community/molecule). You will have to install Docker on your system.

For more information about molecule go to their [docs](http://molecule.readthedocs.io/en/latest/).

## License

This project is licensed under MIT License. See [LICENSE](/LICENSE) for more details.

## Credits
This role was migrated from [cloudalchemy.grafana](https://github.com/cloudalchemy/ansible-grafana).
