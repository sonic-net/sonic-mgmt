# MongoDB Version and PyMongoDB Version Compatibility

- This collection is tested against at least the most recent two MongoDB releases.
- PyMongo - latest version supported only.
- Please upgrade your PyMongo driver version if you encounter difficulties.

# Mongodb Collection
|Category|Status|
|---|---|
|Github CI|![CI](https://github.com/ansible-collections/community.mongodb/workflows/CI/badge.svg)|
|Codecov|[![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.mongodb)](https://codecov.io/gh/ansible-collections/community.mongodb)|
|CI Roles|![CI_roles](https://github.com/ansible-collections/community.mongodb/workflows/CI_roles/badge.svg)|
|Latest Build|![Build & Publish Collection](https://github.com/ansible-collections/community.mongodb/workflows/Build%20&%20Publish%20Collection/badge.svg)|

This collection called `mongodb` aims at providing all Ansible modules allowing to interact with MongoDB.
The modules present in Ansible 2.9 are included in this collection and will benefit from the evolutions and quality requirements from this collection.

As this is an independent collection, it can be released on its own release cadence.

If you like this collection please give us a rating on [Ansible Galaxy](https://galaxy.ansible.com/community/mongodb).

## Communication

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others.
  * [Posts tagged with 'mongodb'](https://forum.ansible.com/tag/mongodb): subscribe to participate in collection-related conversations.
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Collection contents

### Roles

These roles prepare servers with Debian-based and RHEL-based distributions to run MongoDB. These roles should not be used to manage MongoDB instances that have been previously installed or configured through other means.

- `community.mongodb.mongodb_linux`: A simple role to configure Linux Operating System settings, as advised in the [MongoDB Production Notes](https://docs.mongodb.com/manual/administration/production-notes/).
- `community.mongodb.mongodb_selinux`: Configure SELinux for MongoDB.

- `community.mongodb.mongodb_repository`: Configures a package repository for MongoDB on Debian and RedHat based platforms.
- `community.mongodb.mongodb_install`: Install MongoDB packages on Debian and RedHat based platforms. This role, unlike all other roles, provides for installing specific versions of mongodb-org packages. Other roles merely validate that mongodb-org is installed/present; they do not install particular versions.

These roles manage configuring and starting various MongoDB services.

- `community.mongodb.mongodb_mongod`: Configure the `mongod` service (includes populating `mongod.conf`) which is a MongoDB replicaset or standalone server.
- `community.mongodb.mongodb_mongos`: Configure the `mongos` service (includes populating `mongos.conf`) which only runs in a sharded MongoDB cluster.
- `community.mongodb.mongodb_config`: Configure the CSRS Config Server Replicaset for a MongoDB sharded cluster. The CSRS is a special-purpose instance of `mongod` that hosts the `config` database for the sharded cluster. For standalone installations, please use the `mongodb_mongod` role instead.
- `community.mongodb.mongodb_auth`: Configure auth on MongoDB servers. NB: The other MongoDB server config roles (`mongodb_mongod`, `mongodb_mongos`, `mongodb_config`) do not configure auth. Use this role in conjunction with the other roles.

### Plugins

#### Lookup Plugins
- `community.mongodb.mongodb`: A lookup plugin that gets info from a collection using the MongoDB `find()` function.

#### Cache Plugins
- `community.mongodb.mongodb`: A cache plugin that stores the host fact cache records in MongoDB.

#### Modules

These modules are for any MongoDB cluster (standalone, replicaset, or sharded):

- `community.mongodb.mongodb_index`: Creates or drops indexes on MongoDB collections.
- `community.mongodb.mongodb_info`: Gather information about MongoDB instance.
- `community.mongodb.mongodb_oplog`: [Resizes](https://docs.mongodb.com/manual/tutorial/change-oplog-size) the MongoDB oplog (MongoDB 3.6+ only).
- `community.mongodb.mongodb_parameter`: Change an administrative parameter on a MongoDB server.
- `community.mongodb.mongodb_role`: Manage [MongoDB Roles](https://www.mongodb.com/docs/upcoming/tutorial/manage-users-and-roles/).
- `community.mongodb.mongodb_schema`: Manages MongoDB Document Schema Validators.
- `community.mongodb.mongodb_shell`: Run commands via the MongoDB shell.
- `community.mongodb.mongodb_shutdown`: Cleans up all database resources and then terminates the mongod/mongos process.
- `community.mongodb.mongodb_user`: Adds or removes a user from a MongoDB database.

These modules are only useful for replicaset (or sharded) MongoDB clusters:

- `community.mongodb.mongodb_maintenance`: Enables or disables [maintenance](https://docs.mongodb.com/manual/reference/command/replSetMaintenance/) mode for a secondary member.
- `community.mongodb.mongodb_replicaset`: Initialises a MongoDB replicaset.
- `community.mongodb.mongodb_status`: Validates the status of the replicaset.
- `community.mongodb.mongodb_stepdown`: [Step down](https://docs.mongodb.com/manual/reference/command/replSetStepDown/) the MongoDB node from a PRIMARY state.

These modules are only useful for sharded MongoDB clusters:

- `community.mongodb.mongodb_balancer`: Manages the MongoDB Sharded Cluster Balancer.
- `community.mongodb.mongodb_shard`: Add or remove shards from a MongoDB Cluster.
- `community.mongodb.mongodb_shard_tag`: Manage Shard Tags.
- `community.mongodb.mongodb_shard_zone`: Manage Shard Zones.

These modules are only useful for MongoDB Atlas clusters:

- `community.mongodb.mongodb_atlas_cluster`: Manage MongoDB clusters in Atlas.
- `community.mongodb.mongodb_atlas_ldap_user`: Manage LDAP users in Atlas.
- `community.mongodb.mongodb_atlas_user`: Manage users in Atlas.
- `community.mongodb.mongodb_atlas_whitelist`: Manage IP whitelists in Atlas.

## community.mongodb Role Tags

### General role tags

These tags are applicable across all roles.

|tags|comment|
|----|-------|
|mongodb|Tasks specific to MongoDB.|
|debian|Tasks specific to Debian Family Operating Systems.|
|redhat|Tasks specific to RedHat Family Operating Systems.|
|pip|Tasks working with pip.|
|vars|Tasks that load variables.|
|pkg|Tasks that install packages.|
|debug|Tasks that output debugging info.|
|service|Tasks dealing with system services.|
|setup|Tasks that are mainly executed during initial deployment.|
|ci|Tasks that are specific to the community.mongodb CI code.|
|linux|Tasks affecting Linux OS settings.|

### Role Specific Tags

These tags apply to the specific roles as indicated.

|role|tag|comment|
|----|---|-------|
|mongodb_auth|admin_user|Tasks that work with the MongoDB Administrator user.|
|mongodb_auth|app_user|Tasks that work with MongoDB app users.|

## Usage Examples

The following links provide various examples for how the community.mongodb roles and modules can be used in real projects.

* https://github.com/rhysmeister/AutomatingMongoDBWithAnsible (no longer maintained)
* https://github.com/superset1/Ansible_role_mongodb
* https://github.com/ansible-collections/community.mongodb/tree/master/roles/ROLENAME/molecule (replace ROLENAME, some full examples that we use in our testing)

## Running the integration and unit tests

* Requirements
  * [Python 3.5+](https://www.python.org/)
  * [pip](https://pypi.org/project/pip/)
  * [virtualenv](https://virtualenv.pypa.io/en/latest/) or [pipenv](https://pypi.org/project/pipenv/) if you prefer.
  * [git](https://git-scm.com/)
  * [docker](https://www.docker.com/)

* Useful Links
  * [Pip & Virtual Environments](https://docs.python-guide.org/dev/virtualenvs/)
  * [Ansible Integration Tests](https://docs.ansible.com/ansible/latest/dev_guide/testing_integration.html)

The ansible-test tool requires a specific directory hierarchy to function correctly so please follow carefully.

* Create the required directory structure. N-B. The ansible-test tool requires this format.

```bash
mkdir -p git/ansible_collections/community
cd git/ansible_collections/community
```

* Clone the required projects.

```bash
git clone  https://github.com/ansible-collections/community.mongodb.git ./mongodb
git clone  https://github.com/ansible-collections/community.general.git ./general
git clone  https://github.com/ansible-collections/community.crypto.git ./crypto
```

* Create and activate a virtual environment.

```bash
virtualenv venv
source venv/bin/activate
```

* Change to the project directory.

```bash
cd mongodb
```

* Install the devel branch of ansible-base.

```bash
pip install https://github.com/ansible/ansible/archive/devel.tar.gz --disable-pip-version-check
```

* Run integration tests for the mongodb_shard module.

```bash
ansible-test integration --docker default -v --color --python 3.6 mongodb_shard
```

* Run integration tests for the mongodb_status module.

```bash
ansible-test integration --docker default -v --color --python 3.6 mongodb_status
```

* Run integration tests for the mongodb_oplog module.

```bash
ansible-test integration --docker ubuntu1804 -v --color --python 3.6 mongodb_oplog
```

* Run tests for everything in the collection.

```bash
ansible-test integration --docker default -v --color --python 3.6
```

* Run the units tests

```bash
ansible-test units --docker default -v --color --python 3.6
```

## Release Notes

Needs improvement but the general process for issuing a new release to Ansible Galaxy is as follows...

- View commits since last release and copy text for release notes

```bash
git log 1.3.0..HEAD
git log 1.3.0..HEAD --oneline
```

- Create a new branch
- Update galaxy.yml with version and any other appropriate info
- Update changelogs/changelog.yaml
- Update CHANGELOG.rst
- Create a pull request
- Review and merge when happy
- Tag release on the master branch

```bash
git tag <release>
git push --tags
```

Automation will bundle the release and push to Galaxy. Should take around 10-15 minutes.

## GitHub workflow

* Maintainers would be members of this GitHub Repo
* Branch protections could be used to enforce 1 (or 2) reviews from relevant maintainers [CODEOWNERS](.github/CODEOWNERS)

## Contributing

Any contribution is welcome and we only ask contributors to:
* Provide *at least* integration tests for any contribution.
* Create an issue for any significant contribution that would change a large portion of the codebase.
* Unless there's a very good reason for it, i.e. it's a bug, we aim not to change default behaviour.

## Stargazers over time

[![Stargazers over time](https://starchart.cc/ansible-collections/community.mongodb.svg)](https://starchart.cc/ansible-collections/community.mongodb)

## License

GNU General Public License v3.0 or later

See LICENSING to see the full text.
