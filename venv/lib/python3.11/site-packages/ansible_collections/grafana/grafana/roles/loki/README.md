# Ansible role - Loki

[![License](https://img.shields.io/github/license/grafana/grafana-ansible-collection)](LICENSE)

The Ansible Loki Role allows you to effortlessly deploy and manage [Loki](https://grafana.com/oss/loki/), the log aggregation system. This role is tailored for operating systems such as **RedHat**, **Rocky Linux**, **AlmaLinux**, **Ubuntu**, and **Debian**.

**🔑 Key Features**
- **📦 Out-of-the-box Deployment**: Get Loki up and running quickly with default configurations.
- **🧹 Effortless Uninstall**: Easily remove Loki from your system setting the "loki_uninstall" variable.
- **🔔 Example Alerting Rules**: Benefit from the included sample Ruler configuration. Utilize the provided example alerting rules as a reference guide for structuring your own rules effectively.

## Table of Content

- [Requirements](#requirements)
- [Role Variables](#role-variables)
- - [Default Variables - `defaults/main.yml`](#default-variables---defaultsmainyml)
- - [Alerting Rules Variables](#alerting-rules-variables)
- - [Additional Config Variables for `/etc/loki/config.yml`](#additional-config-variables-for-etclokiconfigyml)
- [Playbook](#playbook)

## Requirements

- Ansible 2.10+

## Role Variables

- 📚 Official Loki configuration [documentation](https://grafana.com/docs/loki/latest/configuration/)
- 🏗️ Upgrading Loki [documentation](https://grafana.com/docs/loki/latest/upgrading/)

### **Default Variables - `defaults/main.yml`**

```yaml
loki_version: "latest"
```

The version of Loki to download and deploy. Supported standard version "3.0.0" format or "latest".

```yaml
loki_uninstall: "false"
```

If set to `true` will perfom uninstall instead of deployment.

```yaml
loki_http_listen_port: 3100
```
The TCP port on which Loki listens. By default, it listens on port `3100`.

```yaml
loki_http_listen_address: "0.0.0.0"
```
The address on which Loki listens for HTTP requests. By default, it listens on all interfaces.

```yaml
loki_expose_port: false
```
By default, this is set to `false`. It supports only simple `firewalld` configurations. If set to `true`, a firewalld rule is added to expose the TCP `loki_http_listen_port`. If set to `false`, the system ensures that the rule is not present. If the `firewalld.service` is not active, all firewalld tasks are skipped.

```yaml
loki_download_url_rpm: "https://github.com/grafana/loki/releases/download/v{{ loki_version }}/loki-{{ loki_version }}.{{ __loki_arch }}.rpm"
```
The default download URL for the Loki rpm package from GitHub.

```yaml
loki_download_url_deb: "https://github.com/grafana/loki/releases/download/v{{ loki_version }}/loki_{{ loki_version }}_{{ __loki_arch }}.deb"
```
The default download URL for the Loki deb package from GitHub.

```yaml
loki_working_path: "/var/lib/loki"
```
⚠️ Avoid using `/tmp/loki` as the working path. This role removes the /tmp/loki directory and replaces it with the specified working path to ensure a permanent configuration.

```yaml
loki_ruler_alert_path: "{{ loki_working_path }}/rules/fake"
```
The variable defines the location where the `ruler` configuration `alerts` are stored.
⚠️ Please note that the role currently does not support multi-tenancy for alerting, so there is no need to modify this variable for different tenants.

```yaml
loki_auth_enabled: false
```
Enables authentication through the X-Scope-OrgID header, which must be present if `true`. If `false`, the OrgID will always be set to `fake`.

```yaml
loki_target: "all"
```
A comma-separated list of components to run. The default value 'all' runs Loki in single binary mode.
Supported values: `all`, `compactor`, `distributor`, `ingester`, `querier`, `query-scheduler`, `ingester-querier`, `query-frontend`, `index-gateway`, `ruler`, `table-manager`, `read`, `write`.

```yaml
loki_ballast_bytes: 0
```
The amount of virtual memory in bytes to reserve as ballast in order to optimize garbage collection.

```yaml
loki_server:
  http_listen_address: "{{ loki_http_listen_address }}"
  http_listen_port: "{{ loki_http_listen_port }}"
  grpc_listen_port: 9096
```
Configures the `server` of the launched module(s). [All possible values for `server`](https://grafana.com/docs/loki/latest/configuration/#server)

```yaml
loki_common:
  instance_addr: 127.0.0.1
  path_prefix: "{{ loki_working_path }}"
  storage:
    filesystem:
      chunks_directory: "{{ loki_working_path }}/chunks"
      rules_directory: "{{ loki_working_path }}/rules"
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory
```
Common configuration to be shared between multiple modules. If a more specific configuration is given in other sections, the related configuration within this section will be ignored. [All possible values for `common`](https://grafana.com/docs/loki/latest/configuration/#common)

```yaml
loki_query_range:
  results_cache:
    cache:
      embedded_cache:
        enabled: true
        max_size_mb: 100
```
The `query_range` block configures the query splitting and caching in the Loki query-frontend. [All possible values for `query_range`](https://grafana.com/docs/loki/latest/configuration/#query_range)

```yaml
loki_schema_config:
  configs:
    - from: 2020-10-24
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h
```
Configures the chunk index schema and where it is stored. [All possible values for `schema_config`](https://grafana.com/docs/loki/latest/configuration/#schema_config)

```yaml
loki_ruler:
  storage:
    type: local
    local:
      directory: "{{ loki_working_path }}/rules"
  rule_path: "{{ loki_working_path }}/rules_tmp"
  ring:
    kvstore:
      store: inmemory
  enable_api: true
  enable_alertmanager_v2: true
  alertmanager_url: http://localhost:9093
```
The `ruler` block configures the Loki ruler. [All possible values for `ruler`](https://grafana.com/docs/loki/latest/configuration/#ruler)

```yaml
loki_analytics:
  reporting_enabled: false
```
Enable anonymous usage reporting. Disabled by default.


### **Alerting Rules Variables**
(not set by default)

```yaml
---
loki_ruler_alerts:
  - name: Logs.Nextcloud
    rules:
    - alert: NextcloudLoginFailed
      expr: |
        count by (filename,env,job) (count_over_time({job=~"nextcloud"} | json | message=~"Login failed.*" [10m])) > 4
      for: 0m
      labels:
        severity: critical
      annotations:
        summary: "{% raw %}On {{ $labels.job }} in log {{ $labels.filename }} failed login detected.{% endraw %}"
  - name: Logs.sshd
    rules:
    - alert: SshLoginFailed
      expr: |
        count_over_time({job=~"secure"} |="sshd[" |~": Failed|: Invalid|: Connection closed by authenticating user" | __error__="" [15m]) > 15
      for: 0m
      labels:
        severity: critical
      annotations:
        summary: "{% raw %}SSH authentication failure (instance {{ $labels.instance }}).{% endraw %}"
```
Example alerting rule configuration. You can add multiple alerting rules to suit your requirements. Please note that the alerting rules are not templated by default

### **Additional Config Variables for `/etc/loki/config.yml`**
(not set by default)

Below variables allow you to extend Loki configuration to fit your needs. Always refer to official [Loki configuration](https://grafana.com/docs/loki/latest/configuration/) to obtain possible configuration parameters.

| Variable Name | Description
| ----------- | ----------- |
| `loki_distributor` | Configures the `distributor`. 📚 [documentation](https://grafana.com/docs/loki/latest/configuration/#distributor)
| `loki_querier` | Configures the `querier`. Only appropriate when running all modules or just the querier. 📚 [documentation](https://grafana.com/docs/loki/latest/configuration/#querier)
| `loki_query_scheduler` | The `query_scheduler` block configures the Loki query scheduler. When configured it separates the tenant query queues from the query-frontend. 📚 [documentation](https://grafana.com/docs/loki/latest/configuration/#query_scheduler)
| `loki_frontend` | The `frontend` block configures the Loki query-frontend. 📚 [documentation](https://grafana.com/docs/loki/latest/configuration/#frontend)
| `loki_ingester_client` | The `ingester_client` block configures how the distributor will connect to ingesters. Only appropriate when running all components, the distributor, or the querier. 📚 [documentation](https://grafana.com/docs/loki/latest/configuration/#ingester_client)
| `loki_ingester` | The `ingester` block configures the ingester and how the ingester will register itself to a key value store. 📚 configuration [documentation](https://grafana.com/docs/loki/latest/configuration/#ingester)
| `loki_index_gateway` | The `index_gateway` block configures the Loki index gateway server, responsible for serving index queries without the need to constantly interact with the object store. 📚 [documentation](https://grafana.com/docs/loki/latest/configuration/#index_gateway)
| `loki_storage_config` | The `storage_config` block configures one of many possible stores for both the index and chunks. Which configuration to be picked should be defined in schema_config block. 📚 [documentation](https://grafana.com/docs/loki/latest/configuration/#storage_config)
| `loki_chunk_store_config` | The `chunk_store_config` block configures how chunks will be cached and how long to wait before saving them to the backing store. 📚 [documentation](https://grafana.com/docs/loki/latest/configuration/#chunk_store_config)
| `loki_compactor` | The `compactor` block configures the compactor component, which compacts index shards for performance. 📚 [documentation](https://grafana.com/docs/loki/latest/configure/#compactor)
| `loki_limits_config` | The `limits_config` block configures global and per-tenant limits in Loki. 📚 [documentation](https://grafana.com/docs/loki/latest/configuration/#limits_config)
| `loki_frontend_worker` | The `frontend_worker` configures the worker - running within the Loki querier - picking up and executing queries enqueued by the query-frontend. 📚 [documentation](https://grafana.com/docs/loki/latest/configuration/#frontend_worker)
| `loki_table_manager` | The `table_manager` block configures the table manager for retention. 📚 [documentation](https://grafana.com/docs/loki/latest/configuration/#table_manager)
| `loki_memberlist` | Configuration for memberlist client. Only applies if the selected kvstore is memberlist. 📚 [documentation](https://grafana.com/docs/loki/latest/configuration/#memberlist)
| `loki_runtime_config` | Configuration for `runtime config` module, responsible for reloading runtime configuration file. 📚 [documentation](https://grafana.com/docs/loki/latest/configuration/#runtime_config)
| `loki_operational_config` | These are values which allow you to control aspects of Loki's operation, most commonly used for controlling types of higher verbosity logging, the values here can be overridden in the configs section of the `runtime_config` file. 📚 [documentation](https://grafana.com/docs/loki/latest/configure/#operational_config)
| `loki_tracing` | Configuration for tracing. 📚 [documentation](https://grafana.com/docs/loki/latest/configuration/#tracing)
| `loki_bloom_build` | The `bloom_build` block configures the Loki bloom planner and builder servers, responsible for building bloom filters. 📚 [documentation](https://grafana.com/docs/loki/latest/configure/#bloom_build)
| `loki_bloom_gateway` | The `bloom_gateway` block configures the Loki bloom gateway server, responsible for serving queries for filtering chunks based on filter expressions. 📚 [documentation](https://grafana.com/docs/loki/latest/configure/#bloom_gateway)

## Playbook

- playbook
```yaml
- name: Manage loki service
  hosts: all
  become: true
  roles:
    - role: grafana.grafana.loki
```

- Playbook execution example
```shell
# Deployment
ansible-playbook -i inventory/hosts playbook/function_loki_play.yml

# Uninstall
ansible-playbook -i inventory/hosts playbook/function_loki_play.yml -e "loki_uninstall=true"
```

## License

See [LICENSE](https://github.com/grafana/grafana-ansible-collection/blob/main/LICENSE)

## Author Information

-   [VoidQuark](https://github.com/voidquark)
