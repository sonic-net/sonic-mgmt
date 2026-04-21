# Ansible Role for OpenTelemetry Collector

This Ansible role to install and configure the OpenTelemetry Collector, which can be used to collect traces, metrics, and logs.

## Requirements

Please ensure that `curl` is installed on Ansible controller.

## Role Variables

Available variables with their default values are listed below (`defaults/main.yml`):

| Variable Name | Description | Default Value |
|---------------|-------------|---------------|
| `otel_collector_version` | Version of OpenTelemetry Collector to install. Set to 'latest' to automatically determine and install the latest release | `"0.90.1"` |
| `otel_collector_binary_url` | URL for downloading the OpenTelemetry Collector binary. This URL is constructed based on the collector version, type, and architecture. | `"https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v{{ otel_collector_version }}/{% if otel_collector_type == 'contrib' %}otelcol-contrib_{{ otel_collector_version }}_linux_{{ otel_collector_arch }}{% else %}otelcol_{{ otel_collector_version }}_linux_{{ otel_collector_arch }}{% endif %}.tar.gz"` |
| `arch_mapping` | Mapping of `ansible_facts['architecture']` values to OpenTelemetry Collector binary architecture names. | See below\* |
| `otel_collector_arch` | Architecture for the OpenTelemetry Collector binary, determined based on the `ansible_facts['architecture']` fact. | `"{{ arch_mapping[ansible_facts['architecture']] | default('amd64') }}"` |
| `otel_collector_service_name` | The service name for the OpenTelemetry Collector. | `"otel-collector"` |
| `otel_collector_type` | Type of the OpenTelemetry Collector (`contrib` includes additional components). | `contrib` |
| `otel_collector_executable` | The executable name of the OpenTelemetry Collector, changes based on the collector type. | `{% if otel_collector_type == 'contrib' %}otelcol-contrib{% else %}otelcol{% endif %}` |
| `otel_collector_installation_dir` | Installation directory for the OpenTelemetry Collector. | `"/etc/otel-collector"` |
| `otel_collector_config_dir` | Directory for OpenTelemetry Collector configuration files. | `"/etc/otel-collector"` |
| `otel_collector_config_file` | The main configuration file name for the OpenTelemetry Collector. | `"config.yaml"` |
| `otel_collector_service_user` | The system user under which the OpenTelemetry Collector service will run. | `"otel"` |
| `otel_collector_service_group` | The system group under which the OpenTelemetry Collector service will run. | `"otel"` |
| `otel_collector_service_statedirectory` | The directory systemd should create under `/var/lib`. | `"otel-collector"` |
| `otel_collector_receivers` | Receivers configuration for the OpenTelemetry Collector. | `""` |
| `otel_collector_exporters` | Exporters configuration for the OpenTelemetry Collector. | `""` |
| `otel_collector_processors` | Processors configuration for the OpenTelemetry Collector. | `""` |
| `otel_collector_extensions` | Extensions configuration for the OpenTelemetry Collector. | `""` |
| `otel_collector_service` | Service configuration for the OpenTelemetry Collector. | `""` |
| `otel_collector_connectors` | Connectors configuration for the OpenTelemetry Collector (optional). | `""` |

\* For `arch_mapping`, the default mapping is as follows:
- `x86_64`: `amd64`
- `aarch64`: `arm64`
- `armv7l`: `armhf`
- `i386`: `i386`
- `ppc64le`: `ppc64le`

Users of the role can override these variables as needed.

## Example Playbook

Include this role in your playbook with default settings:

```yaml
- name: Install OpenTelemetry Collector
  hosts: all
  become: true

  tasks: 
    - name: Install OpenTelemetry Collector
      ansible.builtin.include_role:
        name: grafana.grafana.opentelemetry_collector
      vars:
        otel_collector_receivers:
          otlp:
            protocols:
              grpc:
                endpoint: 0.0.0.0:4317
              http:
                endpoint: 0.0.0.0:4318
        otel_collector_processors:
          batch:

        otel_collector_exporters:
          otlp:
            endpoint: otelcol:4317

        otel_collector_extensions:
          health_check:
          pprof:
          zpages:

        otel_collector_service:
          extensions: [health_check, pprof, zpages]
          pipelines:
            traces:
              receivers: [otlp]
              processors: [batch]
              exporters: [otlp]
            metrics:
              receivers: [otlp]
              processors: [batch]
              exporters: [otlp]
            logs:
              receivers: [otlp]
              processors: [batch]
              exporters: [otlp]

```

## License

See [LICENSE](https://github.com/grafana/grafana-ansible-collection/blob/main/LICENSE)

## Author Information

-   [Ishan Jain](https://github.com/ishanjainn)
