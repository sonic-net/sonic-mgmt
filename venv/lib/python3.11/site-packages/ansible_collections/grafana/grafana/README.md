# Ansible Collection for Grafana

[![Grafana](https://img.shields.io/badge/grafana-%23F46800.svg?&logo=grafana&logoColor=white)](https://grafana.com)
[![Ansible Collection](https://img.shields.io/badge/grafana.grafana-orange)](https://galaxy.ansible.com/ui/repo/published/grafana/grafana/)
[![GitHub tag](https://img.shields.io/github/tag/grafana/grafana-ansible-collection.svg)](https://github.com/grafana/grafana-ansible-collection/tags)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/grafana/grafana-ansible-collection)](https://github.com/grafana/grafana-ansible-collection/tags)
[![GitHub Contributors](https://img.shields.io/github/contributors/grafana/grafana-ansible-collection)](https://github.com/grafana/grafana-ansible-collection/tags)

This collection (`grafana.grafana`) contains modules and roles to assist in automating the management of resources in **Grafana**, **Grafana Agent**, **OpenTelemetry Collector**, **Loki**, **Mimir**, **Alloy**, and **Promtail** with Ansible.

-   [Ansible collection Documentation](https://docs.ansible.com/ansible/latest/collections/grafana/grafana/)
-   [Grafana](https://grafana.com)
-   [Grafana Cloud](https://grafana.com/products/cloud/)

## Ansible version compatibility

The collection is tested and supported with: `ansible >= 2.9`

## Installing the collection

Before using the Grafana collection, you need to install it using the below command:

```shell
ansible-galaxy collection install grafana.grafana
```

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: grafana.grafana
```

A specific version of the collection can be installed by using the version keyword in the `requirements.yml` file:

```yaml
---
collections:
  - name: grafana.grafana
    version: 1.0.0
```

## Roles included in the collection

This collection includes the following roles to help set up and manage Grafana, Grafana Agent, Alloy, OpenTelemetry Collector, Loki, Mimir and Promtail:

- **Grafana**: Installs and configures Grafana on your target hosts.
- **Grafana Agent**: Deploys and configures Grafana Agent, allowing for efficient metrics, logs, and trace data shipping to Grafana Cloud or other endpoints.
- **Alloy**: The replacement for Grafana Agent and Promtail. Alloy can be used to collect traces, metrics, and logs.
- **OpenTelemetry Collector**: Sets up and configures the OpenTelemetry Collector, enabling advanced observability features through data collection and transmission.
- **Loki**: Deploy and manage Loki, the log aggregation system.
- **Mimir**: Deploy and manage Mimir, the scalable long-term storage for Prometheus.
- **Promtail**: Deploy and manage Promtail, the agent which ships the contents of local logs to a private Grafana Loki.

## Using this collection

You can call modules by their Fully Qualified Collection Namespace (FQCN), such as `grafana.grafana.cloud_stack`:

```yaml
- name: Using grafana collection
  hosts: localhost
  tasks:
    - name: Create a Grafana Cloud stack
      grafana.grafana.cloud_stack:
        name: mystack
        stack_slug: mystack
        org_slug: myorg
        cloud_api_key: "{{ cloud_api_key }}"
        region: eu
        state: present
```

or you can add full namespace and collection name in the `collections` element in your playbook

```yaml
- name: Using grafana collection
  hosts: localhost
  collection:
    - grafana.grafana
  tasks:
    - name: Create a Grafana Cloud stack
      cloud_stack:
        name: mystack
        stack_slug: mystack
        org_slug: myorg
        cloud_api_key: "{{ cloud_api_key }}"
        region: eu
        state: present
```

## Contributing

We are accepting GitHub pull requests and issues. There are many ways in which you can participate in the project, for example:

-   Submit bugs and feature requests, and help us verify them
-   Submit and review source code changes in GitHub pull requests
-   Add new modules for more Grafana resources

## Testing and Development

If you want to develop new content for this collection or improve what is already
here, the easiest way to work on the collection is to clone it into one of the configured
[`COLLECTIONS_PATHS`](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths),
and work on it there.

### Testing with `ansible-test`

We use `ansible-test` for sanity.

## Commands

| Command | Description |
| :--- | :----------- |
| `make setup` | Checks to see if necessary tools are installed |
| `make install` | Installs project dependencies |
| `make lint` | Performs all linting commands |
| `make lint-sh` / `make lint-shell` | Performs shell script linting |
| `make lint-md` / `make lint-markdown` | Performs Markdown linting |
| `make lint-txt` / `make lint-text` | Performs text linting |
| `make lint-yml` / `make lint-yaml` | Performs Yaml linting |
| `make lint-ec` / `make lint-editorconfig` | Performs EditorConfig Checks |
| `make lint-ansible` | Performs Ansible linting |
| `make clean` | Removes the `./node_modules` and `./build` directories |
| `make reinstall` | Shortcut to `make clean` and `make install` |

## Releasing, Versioning and Deprecation

This collection follows [Semantic Versioning](https://semver.org/). More details on versioning can be found [in the Ansible docs](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections.html#collection-versions).

We plan to regularly release new minor or bugfix versions once new features or bugfixes have been implemented.

Releasing the current major version on GitHub happens from the `main` branch by the
[GitHub Release Workflow](https://github.com/grafana/grafana-ansible-collection/blob/main/.github/workflows/release.yml).
Before the [GitHub Release Workflow](https://github.com/grafana/grafana-ansible-collection/blob/main/.github/workflows/release.yml)
is run, Contributors should push the new version on Ansible Galaxy Manually.

To generate changelogs for a new release, Refer [Generating Changelogs](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections_changelogs.html#generating-changelogs) or run `antsibull-changelog generate`and `antsibull-changelog lint-changelog-yaml changelogs/changelog.yaml` to validate the YAML file.

To generate the tarball to be uploaded on Ansible Galaxy, Refer [Building collection tarball](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections_distributing.html#building-your-collection-tarball)

## Code of Conduct

This collection follows the Ansible project's [Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this doc

## More information

-   [Maintainer guidelines](https://docs.ansible.com/ansible/devel/community/maintainers.html)
-   Subscribe to the [news-for-maintainers](https://github.com/ansible-collections/news-for-maintainers) repository and track announcements there.
-   [Ansible Collection overview](https://github.com/ansible-collections/overview)
-   [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
-   [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
-   [Ansible Collection Developer Guide](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html)
-   [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## License

GPL-3.0-or-later
