# PostgreSQL collection for Ansible
| | | | |
|--|--|--|--|
|[![Build Status](https://dev.azure.com/ansible/community.postgres/_apis/build/status/CI?branchName=main)](https://dev.azure.com/ansible/community.postgres/_build?definitionId=28)|[![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.postgresql)](https://codecov.io/gh/ansible-collections/community.postgresql)| |[![Discuss on Matrix at #postgresql:ansible.com](https://img.shields.io/matrix/postgresql:ansible.com.svg?server_fqdn=ansible-accounts.ems.host&label=Discuss%20on%20Matrix%20at%20%23postgresql:ansible.com&logo=matrix)](https://matrix.to/#/#postgresql:ansible.com)|

This collection is a part of the Ansible package.

> NOTE: This collection is only for interacting with an existing database installation! If you are looking for a collection to *install* PostgreSQL you need to use another collection/role, for example, [galaxyproject.postgresql](https://galaxy.ansible.com/ui/standalone/roles/galaxyproject/postgresql/install/).

## Our mission

At the `community.postgresql` Ansible collection project,
our mission is to produce and maintain simple, flexible,
and powerful open-source software tailored to automating PostgreSQL-related tasks.

We welcome members from all skill levels to participate actively in our open, inclusive, and vibrant community.
Whether you are an expert or just beginning your journey with Ansible and PostgreSQL,
you are encouraged to contribute, share insights, and collaborate with fellow enthusiasts.

We strive to make managing PostgreSQL deployments as effortless and efficient as possible with automation,
enabling users to focus on their core objectives.

## Code of Conduct

We follow the [Ansible Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html) in all our interactions within this project.

If you encounter abusive behavior violating the [Ansible Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html), please refer to the [policy violations](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html#policy-violations) section of the Code of Conduct for information on how to raise a complaint.

## Communication

* Join the Ansible forum:
    * [PostgreSQL Team](https://forum.ansible.com/g/PostgreSQLTeam): by joining the team you will automatically get subscribed to the posts tagged with [postgresql](https://forum.ansible.com/tag/postgresql).
    * [Get Help](https://forum.ansible.com/c/help/6): get help or help others.
    * [Posts tagged with 'postgresql'](https://forum.ansible.com/tag/postgresql): leverage tags to narrow the scope.
    * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
    * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.
* [Matrix](https://docs.ansible.com/ansible/devel/community/communication.html#real-time-chat): chat real-time about contributing/maintenance-related topics in the [#postgresql:ansible.com](https://matrix.to/#/#postgresql:ansible.com) room.

For more information about communication see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Contributing to this collection

The content of this collection is made by [people](https://github.com/ansible-collections/community.postgresql/graphs/contributors) just like you; a community of individuals collaborating on making the world better through developing automation software.

We are actively accepting new contributors and all types of contributions are very welcome.

You don't know how to start? Refer to our [contribution guide](https://github.com/ansible-collections/community.postgresql/blob/main/CONTRIBUTING.md)!

We use the following guidelines:

* [CONTRIBUTING.md](https://github.com/ansible-collections/community.postgresql/blob/main/CONTRIBUTING.md)
* [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html)
* [Ansible Development Guide](https://docs.ansible.com/ansible/devel/dev_guide/index.html)
* [Ansible Collection Development Guide](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#contributing-to-collections)

## Collection maintenance

The current maintainers (contributors with `write` or higher access) are listed in the [MAINTAINERS](https://github.com/ansible-collections/community.postgresql/blob/main/MAINTAINERS) file. If you have questions or need help, feel free to mention them in the proposals.

To learn how to maintain / become a maintainer of this collection, refer to the [Maintainer guidelines](https://github.com/ansible-collections/community.postgresql/blob/main/MAINTAINING.md).

It is necessary for maintainers of this collection to be subscribed to:

* The collection itself (the `Watch` button -> `All Activity` in the upper right corner of the repository's homepage).
* The [news-for-maintainers repository](https://github.com/ansible-collections/news-for-maintainers).

They also should be subscribed to Ansible's [The Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn).

## Governance

We, [the PostgreSQL working group](https://forum.ansible.com/g/PostgreSQLTeam), use [the forum](https://forum.ansible.com/tag/postgresql) posts tagged with `postgresql` for general announcements and discussions.

The process of decision making in this collection is based on discussing and finding consensus among participants.

Every voice is important and every idea is valuable. If you have something on your mind, create an issue or dedicated forum [discussion](https://forum.ansible.com/new-topic?title=topic%20title&body=topic%20body&category=project&tags=postgresql) and let's discuss it!

## External requirements

The PostgreSQL modules rely on the [Psycopg](https://www.psycopg.org/) PostgreSQL database adapter.
Both versions [Psycopg2](https://www.psycopg.org/docs/) and [Psycopg3](https://www.psycopg.org/psycopg3/docs/) are supported.
The minimum supported and tested versions of Psycopg are 2.5.1 and 3.1.8 respectively.

## Releases Support Timeline

We maintain each major release version (1.x.y, 2.x.y, ...) for two years after the next major version is released.

Here is the table for the support timeline:
- 1.x.y: released 2020-11-17, EOL
- 2.x.y: released 2022-02-10, EOL
- 3.x.y: released 2023-06-09, maintained until 2027-05-06 (bugfixes only)
- 4.x.y: released 2025-05-06, current
- 5.x.y: to be released; not earlier than Ansible 14 release (~May 2026)

## PostgreSQL server version support

The collection supports PostgreSQL server versions officially supported by the PostgreSQL Global Development Group.
EOL versions are NOT taken into account during development.
Even if they are present in our test matrix now, they can be removed at any moment.

## Tested with ansible-core

Tested with the following `ansible-core` releases:
- 2.16
- 2.17
- 2.18
- 2.19
- 2.20
- current development version

Ansible-core versions before 2.12.0 are not supported.
Our AZP CI includes testing with the following docker images / PostgreSQL versions:

| Docker image | Psycopg version | PostgreSQL version |
|--------------|-----------------|--------------------|
| RHEL 9       |           2.9.6 |               13   |
| Fedora 39    |           2.9.6 |               15   |
| Ubuntu 22.04 |           3.1.9 |               16   |
| Fedora 40/41 |           2.9.9 |               16   |
| RHEL 10      |           2.9.9 |               16   |
| Ubuntu 24.04 |           3.2.2 |               17   |

## Included content

- **Info modules**:
  - [postgresql_info](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_info_module.html)
  - [postgresql_ping](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_ping_module.html)
  - [postgresql_user_obj_stat_info](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_user_obj_stat_info_module.html)

- **Basic modules**:
  - [postgresql_db](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_db_module.html)
  - [postgresql_ext](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_ext_module.html)
  - [postgresql_pg_hba](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_pg_hba_module.html)
  - [postgresql_privs](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_privs_module.html)
  - [postgresql_alter_system](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_alter_system_module.html) (will replace `postgresql_set`)
  - [postgresql_schema](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_schema_module.html)
  - [postgresql_tablespace](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_tablespace_module.html)
  - [postgresql_query](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_query_module.html)
  - [postgresql_user](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_user_module.html)

- **Other modules**:
  - [postgresql_copy](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_copy_module.html)
  - [postgresql_idx](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_idx_module.html)
  - [postgresql_membership](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_membership_module.html)
  - [postgresql_owner](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_owner_module.html)
  - [postgresql_publication](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_publication_module.html)
  - [postgresql_sequence](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_sequence_module.html)
  - [postgresql_slot](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_slot_module.html)
  - [postgresql_subscription](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_subscription_module.html)
  - [postgresql_table](https://docs.ansible.com/ansible/latest/collections/community/postgresql/postgresql_table_module.html)

## Using this collection

### Installing the Collection from Ansible Galaxy

Before using the PostgreSQL collection, you need to install it with the Ansible Galaxy command-line tool:

```bash
ansible-galaxy collection install community.postgresql
```

You can include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: community.postgresql
```

You can also download the tarball from [Ansible Galaxy](https://galaxy.ansible.com/ui/repo/published/community/postgresql) and install the collection manually wherever you need.

Note that if you install the collection from Ansible Galaxy with the command-line tool or tarball, it will not be upgraded automatically when you upgrade the Ansible package. To upgrade the collection to the latest available version, run the following command:

```bash
ansible-galaxy collection install community.postgresql --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax:

```bash
ansible-galaxy collection install community.postgresql:==X.Y.Z
```

See [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Release notes

See the [changelog](https://github.com/ansible-collections/community.postgresql/blob/main/CHANGELOG.rst).

## More information

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## Licensing

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
