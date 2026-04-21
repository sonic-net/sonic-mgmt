# RavenDB Community Collection

[![Documentation](https://img.shields.io/badge/docs-brightgreen.svg)](https://docs.ansible.com/ansible/devel/collections/ravendb/ravendb/)

This repo contains the `ravendb.ravendb` Ansible Collection. The collection includes many modules and plugins to work with RavenDB.
The modules present in Ansible 2.15.
If you like this collection please give us a rating on [Ansible Galaxy](https://galaxy.ansible.com/ravendb/ravendb).

## Code of Conduct

We follow [Ansible Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html) in all our interactions within this project.

If you encounter abusive behavior violating the [Ansible Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html), please refer to the [policy violations](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html#policy-violations) section of the Code of Conduct for information on how to raise a complaint.

## Communication

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others. Please add appropriate tags if you start new discussions, for example the `ravendb` tag.
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Tested with Ansible

Tested with the current ansible-core 2.15, ansible-core 2.16, ansible-core 2.17, and ansible-core 2.18 releases, and the current development version of ansible-core. Ansible/ansible-base versions before 2.15.0 are not supported.

## Requirements

- This collection is tested against the most recent two RavenDB releases, currently 6.2.X and 7.0.X.
- [ravendb-python-client](https://pypi.org/project/ravendb/) - latest version supported only. Please upgrade your ravendb-python-client driver version if you encounter difficulties.
- [requests](https://pypi.org/project/requests/);

All modules and plugins require Python 3.9 or later.

## Using this collection

Before using the RavenDB community collection, you need to install the collection with the `ansible-galaxy` CLI:

    ansible-galaxy collection install ravendb.ravendb

See [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.


## Usage Examples

Examples for each module and feature included in this collection can be found in the playbooks/ directory.


## Collection contents

### Roles

These roles prepare servers with Debian-based and RHEL-based distributions to run RavenDB.

- `ravendb.ravendb.ravendb_node`: Installs and configures a RavenDB server node. Handles service setup, secure and unsecured deployments, certificate management, and prerequisites installation.
- `ravendb.ravendb_python_client_prerequisites`: Installs the required Python packages (such as the RavenDB Python client library) needed to run Ansible modules that interact with RavenDB clusters.

### Plugins

#### Modules

These modules manage RavenDB clusters, databases, and indexes:

- `ravendb.ravendb.database`: Creates or deletes RavenDB databases, including support for secured and unsecured servers, replication factor settings, and certificate authentication.
- `ravendb.ravendb.index`: Creates, updates, or deletes RavenDB indexes, including support for multi-map indexes and managing index modes (enable, disable, pause, resume, reset).
- `ravendb.ravendb.node`: Adds nodes to an existing RavenDB cluster, supporting both regular members and watcher nodes.


## ravendb.ravendb Role Tags

### General role tags

These tags are used across roles for categorizing tasks:

| Tag               | Description                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| `ravendb`         | Tasks specific to managing RavenDB.                                         |
| `debian`          | Tasks targeting Debian-based systems.                                       |
| `redhat`          | Tasks targeting RedHat-based systems.                                       |
| `pkg`             | Package installation tasks (e.g., `apt`, `yum`).                            |
| `binaries`        | Handling RavenDB binaries and unpacking operations.                         |
| `config`          | Configuration tasks including system settings and `settings.json`.          |
| `service_mgmt`    | Service-related operations (e.g., start, stop, restart).                    |
| `user`            | Creating and managing `ravendb` user and group.                             |
| `download`        | Tasks involving downloading resources like `.deb` or `.tar.bz2` files.      |
| `self_signed`     | Tasks specific to setting up self-signed certificates.                      |
| `secured`         | Tasks for Let's Encrypt/secured RavenDB setup.                              |
| `ravendb_settings`| Overrides and manipulations on RavenDB configuration files.                 |

### CI-related tags

| Tag        | Description                                                          |
|------------|----------------------------------------------------------------------|
| `molecule` | Used to mark tasks that are conditional when running Molecule tests. |


## Release notes

Please refer to CHANGELOG.md of this repository.


## Running the integration and unit tests
TODO

## More information

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Collections Checklist](https://github.com/ansible-collections/overview/blob/master/collection_requirements.rst)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)
- [The Bullhorn (the Ansible Contributor newsletter)](https://us19.campaign-archive.com/home/?u=56d874e027110e35dea0e03c1&id=d6635f5420)
- [Changes impacting Contributors](https://github.com/ansible-collections/overview/issues/45)


## Licensing

This collection is licensed under the [GNU General Public License v3.0 or later (GPL-3.0-or-later)](https://www.gnu.org/licenses/gpl-3.0.html).
See the LICENSE file of this repository for full details.