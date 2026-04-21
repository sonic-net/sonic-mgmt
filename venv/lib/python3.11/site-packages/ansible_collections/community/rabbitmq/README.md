# community.rabbitmq Collection
[![Build Status](
https://dev.azure.com/ansible/community.rabbitmq/_apis/build/status/CI?branchName=main)](https://dev.azure.com/ansible/community.rabbitmq/_build?definitionId=29)

<!-- Add CI and code coverage badges here. -->
<!-- Describe the collection and why a user would want to use it. What does the collection do? -->

This repository hosts the `community.rabbitmq` Ansible Collection.

The collection includes the rabbitmq modules and plugins supported by Ansible
rabbitmq community to help the management of rabbitmq infrastructure.

This collection is a part of the Ansible package.

## Code of Conduct

We follow the [Ansible Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html) in all our interactions within this project.

If you encounter abusive behavior violating the [Ansible Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html), please refer to the [policy violations](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html#policy-violations) section of the Code of Conduct for information on how to raise a complaint.

## Communication

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others. Please add appropriate tags if you start new discussions, for example the `rabbitmq` tag.
  * [Posts tagged with 'rabbitmq'](https://forum.ansible.com/tag/rabbitmq): subscribe to participate in collection-related conversations.
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Included content
<!-- Galaxy will eventually list the module docs within the UI, but until that is ready, you may need to either describe your plugins etc here, or point to an external docsite to cover that information. -->
- Modules:
  - `rabbitmq_binding`: Manage rabbitMQ bindings.
  - `rabbitmq_exchange`: Manage rabbitMQ exchanges.
  - `rabbitmq_feature_flag`: Enables feature flag.
  - `rabbitmq_global_parameter`: Manage RabbitMQ global parameters.
  - `rabbitmq_parameter`: Manage RabbitMQ parameters.
  - `rabbitmq_plugin`: Manage RabbitMQ plugins.
  - `rabbitmq_policy`: Manage the state of policies in RabbitMQ.
  - `rabbitmq_publish`: Publish a message to a RabbitMQ queue.
  - `rabbitmq_queue`: Manage rabbitMQ queues.
  - `rabbitmq_upgrade`: Execute rabbitmq-upgrade commands.
  - `rabbitmq_user_limits`: Manage RabbitMQ user limits.
  - `rabbitmq_user`: Manage RabbitMQ users.
  - `rabbitmq_vhost_limits`: Manage the state of virtual host limits in RabbitMQ.
  - `rabbitmq_vhost`: Manage the state of a virtual host in RabbitMQ.

- Lookup:
  - `rabbitmq`: Retrieve messages from an AMQP/AMQPS RabbitMQ queue.

## Using this collection
<!--Include some quick examples that cover the most common use cases for your collection content. -->

### Installing the Collection from Ansible Galaxy

Before using the collection, you need to install it with the Ansible Galaxy command-line tool:

```bash
ansible-galaxy collection install community.rabbitmq
```

You can include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: community.rabbitmq
```

You can also download the tarball from [Ansible Galaxy](https://galaxy.ansible.com/community/rabbitmq) and install the collection manually wherever you need.

Note that if you install the collection from Ansible Galaxy with the command-line tool or tarball, it will not be upgraded automatically when you upgrade the Ansible package. To upgrade the collection to the latest available version, run the following command:

```bash
ansible-galaxy collection install community.rabbitmq --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax:

```bash
ansible-galaxy collection install community.rabbitmq:==X.Y.Z
```

See [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection
<!--Describe how the community can contribute to your collection. At a minimum, include how and where users can create issues to report problems or request features for this collection.  List contribution requirements, including preferred workflows and necessary testing, so you can benefit from community PRs. -->

The content of this collection is made by people just like you, a community of individuals collaborating on making the world better through developing automation software.

We are actively accepting new contributors.

All types of contributions are very welcome.

You don't know how to start? Refer to our [contribution guide](https://github.com/ansible-collections/community.rabbitmq/blob/main/CONTRIBUTING.md)!

The aspiration is to follow the following general guidelines:

- Changes should include tests and documentation where appropriate.
- Changes will be lint tested using standard python lint tests.
- No changes which do not pass CI testing will be approved/merged.
- The collection plugins must provide the same coverage of python support as
  the versions of Ansible supported.
- The versions of Ansible supported by the collection must be the same as
  those in developed, or those maintained, as shown in the Ansible [Release and Maintenance][4] documentation.

[4]: https://docs.ansible.com/ansible/latest/reference_appendices/release_and_maintenance.html

We use the following guidelines:

* [CONTRIBUTING.md](https://github.com/ansible-collections/community.rabbitmq/blob/main/CONTRIBUTING.md)
* [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html)
* [Ansible Development Guide](https://docs.ansible.com/ansible/devel/dev_guide/index.html)
* [Ansible Collection Development Guide](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#contributing-to-collections)

### Local Testing

* Requirements
  * [Python 3.5+](https://www.python.org/)
  * [pip](https://pypi.org/project/pip/)
  * [virtualenv](https://virtualenv.pypa.io/en/latest/) or [pipenv](https://pypi.org/project/pipenv/) if you prefer.
  * [git](https://git-scm.com/)
  * [docker](https://www.docker.com/)

* Useful Links
  * [Pip & Virtual Environments](https://docs.python-guide.org/dev/virtualenvs/)
  * [Ansible Integration Tests](https://docs.ansible.com/ansible/latest/dev_guide/testing_integration.html)

Local testing is done with the ``ansible-test`` tool which requires a specific
directory hierarchy to function correctly so please follow carefully.

```bash
# These base directory environment variables can be adjusted to suit personal preferences
SRC_BASE_DIR="~/code"
VENV_BASE_DIR="~/.venvs"

# These should not be altered
COLL_DIR="${SRC_BASE_DIR}/ansible/ansible_collections/community/rabbitmq"
VENV_DIR="${VENV_BASE_DIR}/ansible"

# Create the required directory structure
mkdir -p $(basename ${COLL_DIR})

# Clone the collection repository
git clone https://github.com/ansible-collections/community.rabbitmq.git ${COLL_DIR}

# Create and activate a virtual environment.
virtualenv ${VENV_DIR}
source ${VENV_DIR}/bin/activate

# Install the devel branch of ansible-base
pip install https://github.com/ansible/ansible/archive/devel.tar.gz --disable-pip-version-check

# Switch into the collection directory
cd ${COLL_DIR}

# Run the integration tests
ansible-test integration --docker default -v --color --python 3.6

# Run the unit tests
ansible-test units --docker default -v --color --python 3.6
```

## Collection maintenance

The current maintainers (contributors with `write` or higher access) are listed in the [MAINTAINERS](https://github.com/ansible-collections/community.rabbitmq/blob/main/MAINTAINERS) file. If you have questions or need help, feel free to mention them in the proposals.

To learn how to maintain / become a maintainer of this collection, refer to the [Maintainer guidelines](https://github.com/ansible-collections/community.rabbitmq/blob/main/MAINTAINING.md).

It is necessary for maintainers of this collection to be subscribed to:

* The collection itself (the `Watch` button -> `All Activity` in the upper right corner of the repository's homepage).
* The "Changes Impacting Collection Contributors and Maintainers" [issue](https://github.com/ansible-collections/overview/issues/45).

They also should be subscribed to Ansible's [The Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn).

### Publishing New Version

See the [Releasing guidelines](https://github.com/ansible/community-docs/blob/main/releasing_collections_without_release_branches.rst).

## Tested with Ansible
<!-- List the versions of Ansible the collection has been tested with. Must match what is in galaxy.yml. -->
TBD

## External requirements
<!-- List any external resources the collection depends on, for example minimum versions of an OS, libraries, or utilities. Do not list other Ansible collections here. -->
TBD

### Supported connections
<!-- Optional. If your collection supports only specific connection types (such as HTTPAPI, netconf, or others), list them here. -->
TBD

## More Information
<!-- List out where the user can find additional information, such as working group meeting times, slack/IRC channels, or documentation for the product this collection automates. -->

### Reference

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## License
<!-- Include the appropriate license information here and a pointer to the full licensing details. If the collection contains modules migrated from the ansible/ansible repo, you must use the same license that existed in the ansible/ansible repo. See the GNU license example below. -->

GNU General Public License v3.0 or later.

See [LICENCE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
