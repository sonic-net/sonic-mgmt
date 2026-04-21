|![](https://upload.wikimedia.org/wikipedia/commons/thumb/1/17/Warning.svg/156px-Warning.svg.png) | This Ansible role is now in maintenance mode only. We recommend using the Grafana Alloy Role for future deployments and updates.
|---|---|

# Ansible Role for Grafana Agent

Ansible Role to deploy Grafana Agent on Linux hosts. Using this Role, Grafana Agent can be deployed on RedHat, Ubuntu, Debian, CentOS
and Fedora linux distributions.

## Requirements

Please ensure that `curl` is intalled on Ansible controller.

To use this role, You need a YAML file having the Grafana Agent configuration.

## Role Variables

All variables which can be overridden are stored in [./defaults/main.yaml](./defaults/main.yaml) file as well as in table below.

| Variable | Default | Description |
| :------ | :------ | :--------- |
| `grafana_agent_version` | `latest` | version of the agent to install |
| `grafana_agent_base_download_url` | `https://github.com/{{ _grafana_agent_github_org }}/{{ _grafana_agent_github_repo }}/releases/download` | base download url. Github or mirror to download from |
| `grafana_agent_install_dir` | `/opt/grafana-agent/bin` | directory to install the binary to |
| `grafana_agent_binary` | `grafana-agent` | name to use for the binary |
| `grafana_agent_config_dir` | `/etc/grafana-agent` | directory to store the configuration files in |
| `grafana_agent_config_filename` | `config.yaml` | name of the configuration file for the agent |
| `grafana_agent_env_file` | `service.env` | name of the environment file loaded by the system unit file |
| `grafana_agent_service_extra` | "" | dictionary of additional custom settings for the systemd service file |
| `grafana_agent_local_tmp_dir` | `/tmp/grafana-agent` | temporary directory to create on the controller/localhost where the archive will be downloaded to |
| `grafana_agent_data_dir` | `/var/lib/grafana-agent` | the data directory to create for the wal and positions |
| `grafana_agent_wal_dir` | `"{{ grafana_agent_data_dir }}/data"` | wal directory to use, should be a sub-folder of grafana_agent_data_dir, will automatically be created when the agent starts |
| `grafana_agent_positions_dir` | `"{{ grafana_agent_data_dir }}/data"` | positions directory to use, should be a sub-folder of grafana_agent_data_dir, will automatically be created when the agent starts |
| `grafana_agent_mode` | `static` | mode to run Grafana Agent in. Can be "flow" or "static", [Flow Docs](https://grafana.com/docs/agent/latest/flow/) |
| `grafana_agent_user` | `grafana-agent` | os user to create for the agent to run as |
| `grafana_agent_user_group` | `grafana-agent` | os user group to create for the agent |
| `grafana_agent_user_groups` | `[]` | Configurable user groups that the Grafana agent can be put in so that it can access logs |
| `grafana_agent_user_shell` | `/usr/sbin/nologin` | the shell for the user |
| `grafana_agent_user_createhome` | `false` | whether or not to create a home directory for the user |
| `grafana_agent_local_binary_file` | `""` | full path to the local binary if already downloaded or built on the controller, this should only be set, if ansible is not downloading the binary and you have manually downloaded the binary |
| `grafana_agent_flags_extra` | see [./defaults/main.yaml](./defaults/main.yaml) | dictionary of additional command-line flags, run grafana-agent --help for a complete list. [Docs](https://grafana.com/docs/agent/latest/configuration/flags/) |
| `grafana_agent_env_vars` | `{}` | sets Environment variables in the systemd service configuration. |
| `grafana_agent_env_file_vars` | `{}` | dictionary of key/pair values to write to the environment file that is loaded by the service, with the flag `--config.expand-env=true` any generated config files will support the expansion of environment variables at runtime by referencing ${ENVVAR}. be aware of boolean values, when output they will result in the proper-cased string "True" and "False" |
| `grafana_agent_provisioned_config_file` | `""` | path to a config file on the controller that will be used instead of the provided configs below if specified. |
| `grafana_agent_server_config` | see [./defaults/main.yaml](./defaults/main.yaml) | Configures the server of the Agent used to enable self-scraping, [Docs](https://grafana.com/docs/agent/latest/configuration/server-config/) |
| `grafana_agent_metrics_config` | see [./defaults/main.yaml](./defaults/main.yaml) | Configures metric collection, [Docs](https://grafana.com/docs/agent/latest/configuration/metrics-config/) |
| `grafana_agent_logs_config` | see [./defaults/main.yaml](./defaults/main.yaml) | Configures logs collection, [Docs](https://grafana.com/docs/agent/latest/configuration/logs-config/) |
| `grafana_agent_traces_config` | see [./defaults/main.yaml](./defaults/main.yaml) | Configures traces collection, [Docs](https://grafana.com/docs/agent/latest/configuration/traces-config/) |
| `grafana_agent_integrations_config` | see [./defaults/main.yaml](./defaults/main.yaml) | Configures integrations for the agent, [Docs](https://grafana.com/docs/agent/latest/configuration/integrations/) |

## OS Support
The Grafana Agent role has been tested on below Operating Systems
- Ubuntu 22.10, Ubunutu 22.04 LTS, Ubunutu 20.04 LTS, Ubunutu 18.04 LTS
- Fedora 37, Fedora 36
- Debian 11, Debian 10, Debian 9
- CentOS 9 Stream, CentOS 8 Stream, CentOS 7
- AlmaLinux 9, AlmaLinux 8
- RockyLinux 9, RockyLinux 8

## Example Playbooks

See [examples](../../examples)

## License

See [LICENSE](https://github.com/grafana/grafana-ansible-collection/blob/main/LICENSE)

## Author Information

-   [Grafana Labs](https://github.com/grafana)
-   [Ishan Jain](https://github.com/ishanjainn)
-   [Aaron Benton](https://github.com/bentonam)
-   [Vitaly Zhuravlev](https://github.com/v-zhuravlev)
