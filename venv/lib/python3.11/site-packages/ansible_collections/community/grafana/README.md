# Grafana Collection for Ansible

[![Lint](https://github.com/ansible-collections/community.grafana/actions/workflows/lint.yml/badge.svg)](https://github.com/ansible-collections/community.grafana/actions/workflows/lint.yml)
[![CI](https://github.com/ansible-collections/community.grafana/actions/workflows/ansible-test.yml/badge.svg)](https://github.com/ansible-collections/community.grafana/actions/workflows/ansible-test.yml)
[![Check and Update Releases](https://github.com/ansible-collections/community.grafana/actions/workflows/check_releases.yml/badge.svg)](https://github.com/ansible-collections/community.grafana/actions/workflows/check_releases.yml)
[![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.grafana)](https://codecov.io/gh/ansible-collections/community.grafana)
<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-20-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

This repo hosts the `community.grafana` Ansible Collection.

The collection includes a variety of Ansible content to help automate the management of resources in Grafana.

## Communication

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others.
  * [Posts tagged with 'grafana'](https://forum.ansible.com/tag/grafana): subscribe to participate in collection-related conversations.
  * [Ansible Forum Group 'grafana-collection'](https://forum.ansible.com/g/grafana-collection): by joining the team you will automatically get subscribed to the posts tagged with [grafana](https://forum.ansible.com/tag/grafana).
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Included content

Click on the name of a plugin or module to view that content's documentation:

* **Connection Plugins**:
* **Filter Plugins**:
* **Inventory Source**:
* **Callback Plugins**:
  * [grafana_annotations](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_annotations_callback.html)
* **Lookup Plugins**:
  * [grafana_dashboard](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_dashboard_lookup.html)
* **Modules**:
  * [grafana_dashboard](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_dashboard_module.html)
  * [grafana_datasource](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_datasource_module.html)
  * [grafana_folder](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_folder_module.html)
  * [grafana_notification_channel](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_notification_channel_module.html)
  * [grafana_contact_point](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_contact_point_module.html)
  * [grafana_organization](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_organization_module.html)
  * [grafana_organization_user](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_organization_user_module.html)
  * [grafana_plugin](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_plugin_module.html)
  * [grafana_team](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_team_module.html)
  * [grafana_user](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_user_module.html)
  * [grafana_silence](https://docs.ansible.com/ansible/latest/collections/community/grafana/grafana_silence_module.html)

## Supported Versions

We aim to keep the last 3 major versions of both **Grafana** and **Ansible** tested.
This collection is currently testing the modules against the following versions:

```yaml
grafana_version: ["12.0.2", "11.6.3", "10.4.19"]
ansible_version: ["v2.19.0b7", "stable-2.18", "stable-2.17"]
```

## Installation and Usage

### Installing the Collection from Ansible Galaxy

Before using the Grafana collection, you need to install it with the Ansible Galaxy CLI:

    ansible-galaxy collection install community.grafana

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: community.grafana
    version: 1.3.1
```

### Using modules from the Grafana Collection in your playbooks

You can either call modules by their Fully Qualified Collection Namespace (FQCN), like `community.grafana.grafana_datasource`, or you can call modules by their short name if you list the `community.grafana` collection in the playbook's `collections`, like so:

```yaml
---
- hosts: localhost
  gather_facts: false
  connection: local

  tasks:
    - name: Ensure Influxdb datasource exists.
      community.grafana.grafana_datasource:
        name: "datasource-influxdb"
        grafana_url: "https://grafana.company.com"
        grafana_user: "admin"
        grafana_password: "xxxxxx"
        org_id: "1"
        ds_type: "influxdb"
        ds_url: "https://influx.company.com:8086"
        database: "telegraf"
        time_interval: ">10s"
        tls_ca_cert: "/etc/ssl/certs/ca.pem"
```

For documentation on how to use individual modules and other content included in this collection, please see the links in the 'Included content' section earlier in this README.

### Using module group defaults

In your playbooks, you can set [module defaults](https://github.com/ansible/ansible/blob/v2.12.3/docs/docsite/rst/user_guide/playbooks_module_defaults.rst#module-defaults-groups) for the `community.grafana.grafana` group to avoid repeating the same parameters (e.g., `grafana_url`, `grafana_user`, `grafana_password`) in your tasks:

```yaml
---
- hosts: localhost
  gather_facts: false
  connection: local

  module_defaults:
    group/community.grafana.grafana:
      grafana_url: "https://grafana.company.com"
      grafana_user: "admin"
      grafana_password: "xxxxxx"

  tasks:
    - name: Ensure Influxdb datasource exists.
      community.grafana.grafana_datasource:
        name: "datasource-influxdb"
        org_id: "1"
        ds_type: "influxdb"
        ds_url: "https://influx.company.com:8086"
        database: "telegraf"
        time_interval: ">10s"
        tls_ca_cert: "/etc/ssl/certs/ca.pem"

    - name: Create or update a Grafana user
      community.grafana.grafana_user:
        name: "Bruce Wayne"
        email: "batman@gotham.city"
        login: "batman"
        password: "robin"
        is_admin: true
```

## Testing and Development

If you want to develop new content for this collection or improve what's already here, the easiest way to work on the collection is to clone it into one of the configured [`COLLECTIONS_PATHS`](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths), and work on it there.

### Testing with `ansible-test`

The `tests` directory contains configuration for running sanity and integration tests using [`ansible-test`](https://docs.ansible.com/ansible/latest/dev_guide/testing_integration.html).

You can run the collection's test suites with the commands:

    ansible-test sanity --docker -v --color
    ansible-test units --docker -v --color
    ansible-test integration --docker -v --color

## Publishing New Versions

The collection is automatically released on [Galaxy](//galaxy.ansible.com/community/grafana) when a tag is created on the repository.
The release pipeline is managed by the Ansible Team as the collection is part of the `community` namespace.

The current process for creating a tag is manual.

## Changelogs

Abstract from Ansible requirements for Collections:

```
* Every change that does not only affect docs or tests must have a changelog fragment.
  * Exception: fixing/extending a feature that already has a changelog fragment and has not yet been released. Such PRs must always link to the original PR(s) they update.
  * Use your common sense!
  * (This might change later. The trivial category should then be used to document changes which are not important enough to end up in the text version of the changelog.)
  * Fragments must not be added for new module PRs and new plugin PRs. The only exception are test and filter plugins: these are not automatically documented yet.
* The (x+1).0.0 changelog continues the x.0.0 changelog.
  * A x.y.0 changelog with y > 0 is not part of a changelog of a later X.*.* (with X > x) or x,Y,* (with Y > y) release.
  * A x.y.z changelog with z > 0 is not part of a changelog of a later (x+1).*.* or x.Y.z (with Y > y) release.
Since everything adding to the minor/patch changelogs are backports, the same changelog fragments of these minor/patch releases will be in the next major release's changelog. (This is the same behavior as in ansible/ansible.)
* Changelogs do not contain previous major releases, and only use the ancestor feature (in changelogs/changelog.yaml) to point to the previous major release.
* Changelog fragments are removed after a release is made.
```

See [antsibull-changelog documentation](https://github.com/ansible-community/antsibull-changelog/blob/main/docs/changelogs.rst#changelog-fragment-categories) for fragments format.

Generate a new changelog:

1. Update the collection version in `galaxy.yml` if required.
2. Generate the changelog:

```shell
antsibull-changelog release
```

## License

GNU General Public License v3.0 or later

See LICENCE to see the full text.

## Contributing

Any contribution is welcome and we only ask contributors to:

* Provide *at least* integration tests for any contribution.
* The Pull Request *MUST* contain a changelog fragment. See [Ansible documentation](https://docs.ansible.com/ansible/latest/community/development_process.html#creating-a-changelog-fragment) about fragments.
* Create an issue for any significant contribution that would change a large portion of the code base.
* Use [ruff](https://github.com/astral-sh/ruff) to lint and [black](https://github.com/psf/black) to format your changes on python code.

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/gundalow"><img src="https://avatars1.githubusercontent.com/u/940557?v=4?s=100" width="100px;" alt="John R Barker"/><br /><sub><b>John R Barker</b></sub></a><br /><a href="#infra-gundalow" title="Infrastructure (Hosting, Build-Tools, etc)">🚇</a> <a href="https://github.com/ansible-collections/community.grafana/commits?author=gundalow" title="Tests">⚠️</a> <a href="https://github.com/ansible-collections/community.grafana/commits?author=gundalow" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/rrey"><img src="https://avatars1.githubusercontent.com/u/2752379?v=4?s=100" width="100px;" alt="Rémi REY"/><br /><sub><b>Rémi REY</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/commits?author=rrey" title="Tests">⚠️</a> <a href="https://github.com/ansible-collections/community.grafana/commits?author=rrey" title="Documentation">📖</a> <a href="https://github.com/ansible-collections/community.grafana/commits?author=rrey" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://aperogeek.fr"><img src="https://avatars1.githubusercontent.com/u/1336359?v=4?s=100" width="100px;" alt="Thierry Sallé"/><br /><sub><b>Thierry Sallé</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/commits?author=seuf" title="Code">💻</a> <a href="https://github.com/ansible-collections/community.grafana/commits?author=seuf" title="Tests">⚠️</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://antoine.tanzil.li"><img src="https://avatars0.githubusercontent.com/u/1068018?v=4?s=100" width="100px;" alt="Antoine"/><br /><sub><b>Antoine</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/commits?author=Tailzip" title="Code">💻</a> <a href="https://github.com/ansible-collections/community.grafana/commits?author=Tailzip" title="Tests">⚠️</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/pomverte"><img src="https://avatars0.githubusercontent.com/u/695230?v=4?s=100" width="100px;" alt="hvle"/><br /><sub><b>hvle</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/commits?author=pomverte" title="Code">💻</a> <a href="https://github.com/ansible-collections/community.grafana/commits?author=pomverte" title="Tests">⚠️</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/jual"><img src="https://avatars2.githubusercontent.com/u/4416541?v=4?s=100" width="100px;" alt="jual"/><br /><sub><b>jual</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/commits?author=jual" title="Code">💻</a> <a href="https://github.com/ansible-collections/community.grafana/commits?author=jual" title="Tests">⚠️</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/MCyprien"><img src="https://avatars2.githubusercontent.com/u/11160859?v=4?s=100" width="100px;" alt="MCyprien"/><br /><sub><b>MCyprien</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/commits?author=MCyprien" title="Code">💻</a> <a href="https://github.com/ansible-collections/community.grafana/commits?author=MCyprien" title="Tests">⚠️</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://twitter.com/RealRockaut"><img src="https://avatars0.githubusercontent.com/u/453368?v=4?s=100" width="100px;" alt="Markus Fischbacher"/><br /><sub><b>Markus Fischbacher</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/commits?author=rockaut" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/rverchere"><img src="https://avatars3.githubusercontent.com/u/232433?v=4?s=100" width="100px;" alt="Remi Verchere"/><br /><sub><b>Remi Verchere</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/commits?author=rverchere" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://akasurde.github.io"><img src="https://avatars1.githubusercontent.com/u/633765?v=4?s=100" width="100px;" alt="Abhijeet Kasurde"/><br /><sub><b>Abhijeet Kasurde</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/commits?author=Akasurde" title="Documentation">📖</a> <a href="https://github.com/ansible-collections/community.grafana/commits?author=Akasurde" title="Tests">⚠️</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/martinwangjian"><img src="https://avatars2.githubusercontent.com/u/1770277?v=4?s=100" width="100px;" alt="martinwangjian"/><br /><sub><b>martinwangjian</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/commits?author=martinwangjian" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/CWollinger"><img src="https://avatars2.githubusercontent.com/u/11299733?v=4?s=100" width="100px;" alt="cwollinger"/><br /><sub><b>cwollinger</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/commits?author=cwollinger" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Andersson007"><img src="https://avatars3.githubusercontent.com/u/34477873?v=4?s=100" width="100px;" alt="Andrew Klychkov"/><br /><sub><b>Andrew Klychkov</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/commits?author=Andersson007" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/vnea"><img src="https://avatars.githubusercontent.com/u/10775422?v=4?s=100" width="100px;" alt="Victor"/><br /><sub><b>Victor</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/commits?author=vnea" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/paytroff"><img src="https://avatars.githubusercontent.com/u/93038288?v=4?s=100" width="100px;" alt="paytroff"/><br /><sub><b>paytroff</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/commits?author=paytroff" title="Code">💻</a> <a href="https://github.com/ansible-collections/community.grafana/commits?author=paytroff" title="Tests">⚠️</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/jseiser"><img src="https://avatars.githubusercontent.com/u/4855527?v=4?s=100" width="100px;" alt="Justin Seiser"/><br /><sub><b>Justin Seiser</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/commits?author=jseiser" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/prndrbr"><img src="https://avatars.githubusercontent.com/u/96344856?v=4?s=100" width="100px;" alt="Pierre"/><br /><sub><b>Pierre</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/issues?q=author%3Aprndrbr" title="Bug reports">🐛</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/miksonx"><img src="https://avatars.githubusercontent.com/u/5308184?v=4?s=100" width="100px;" alt="MiksonX"/><br /><sub><b>MiksonX</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/issues?q=author%3Amiksonx" title="Bug reports">🐛</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/amenzhinsky"><img src="https://avatars.githubusercontent.com/u/1308953?v=4?s=100" width="100px;" alt="Aliaksandr Mianzhynski"/><br /><sub><b>Aliaksandr Mianzhynski</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/commits?author=amenzhinsky" title="Code">💻</a> <a href="https://github.com/ansible-collections/community.grafana/commits?author=amenzhinsky" title="Tests">⚠️</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://nemental.de"><img src="https://avatars.githubusercontent.com/u/15136847?v=4?s=100" width="100px;" alt="Moritz"/><br /><sub><b>Moritz</b></sub></a><br /><a href="https://github.com/ansible-collections/community.grafana/issues?q=author%3ANemental" title="Bug reports">🐛</a> <a href="https://github.com/ansible-collections/community.grafana/commits?author=Nemental" title="Code">💻</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
