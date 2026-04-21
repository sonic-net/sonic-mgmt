# community.libvirt Collection
[![Build Status](
https://dev.azure.com/ansible/community.libvirt/_apis/build/status/CI?branchName=main)](https://dev.azure.com/ansible/community.libvirt/_build?definitionId=27)
[![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.libvirt)](https://codecov.io/gh/ansible-collections/community.libvirt)

This repo hosts the `community.libvirt` Ansible Collection.

The collection includes the libvirt modules and plugins supported by Ansible
libvirt community to help the management of virtual machines and/or containers
via the [libvirt](https://libvirt.org/) API.

This collection is shipped with the `ansible` package.

## Communication

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others. Please add appropriate tags if you start new discussions, for example the `libvirt` tag.
  * [Posts tagged with 'libvirt'](https://forum.ansible.com/tag/libvirt): subscribe to participate in related conversations.
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Tested with Ansible
<!-- List the versions of Ansible the collection has been tested with. Must match what is in galaxy.yml. -->

- 2.9
- 2.10
- 2.11
- devel

## External requirements
<!-- List any external resources the collection depends on, for example minimum versions of an OS, libraries, or utilities. Do not list other Ansible collections here. -->
- python >= 2.6
- [libvirt python bindings](https://pypi.org/project/libvirt-python/)
- lxml

## Included content
<!-- Galaxy will eventually list the module docs within the UI, but until that is ready, you may need to either describe your plugins etc here, or point to an external docsite to cover that information. -->

Modules:

- [virt](https://docs.ansible.com/ansible/latest/collections/community/libvirt/virt_module.html)
- [virt_net](https://docs.ansible.com/ansible/latest/collections/community/libvirt/virt_net_module.html)
- [virt_pool](https://docs.ansible.com/ansible/latest/collections/community/libvirt/virt_pool_module.html)

Inventory:

- [libvirt](https://docs.ansible.com/ansible/latest/collections/community/libvirt/libvirt_inventory.html#ansible-collections-community-libvirt-libvirt-inventory)

Connection:

- [libvirt_lxc](https://docs.ansible.com/ansible/latest/collections/community/libvirt/libvirt_lxc_connection.html#ansible-collections-community-libvirt-libvirt-lxc-connection)
- [libvirt_qemu](https://docs.ansible.com/ansible/latest/collections/community/libvirt/libvirt_qemu_connection.html#ansible-collections-community-libvirt-libvirt-qemu-connection)

## Using this collection
<!--Include some quick examples that cover the most common use cases for your collection content. -->

Before using the libvirt collection, you need to install it with the Ansible Galaxy command-line tool:

```bash
ansible-galaxy collection install community.libvirt
```

You can include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: community.libvirt
```

You can also download the tarball from [Ansible Galaxy](https://galaxy.ansible.com/community/libvirt) and install the collection manually wherever you need.

Note that if you install the collection from Ansible Galaxy with the command-line tool or tarball, it will not be upgraded automatically when you upgrade the Ansible package. To upgrade the collection to the latest available version, run the following command:

```bash
ansible-galaxy collection install community.libvirt --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax:

```bash
ansible-galaxy collection install community.libvirt:==X.Y.Z
```

See [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Contributing to this collection
<!--Describe how the community can contribute to your collection. At a minimum, include how and where users can create issues to report problems or request features for this collection.  List contribution requirements, including preferred workflows and necessary testing, so you can benefit from community PRs. -->

The content of this collection is made by people just like you, a community of individuals collaborating on making the world better through developing automation software.

We are actively accepting new contributors.

All types of contributions are very welcome.

You don't know how to start? Refer to our [contribution guide](https://github.com/ansible-collections/community.libvirt/blob/main/CONTRIBUTING.md)!

The aspiration is to follow the following general guidelines:

- Changes should include tests and documentation where appropriate.
- Changes will be lint tested using standard python lint tests.
- No changes which do not pass CI testing will be approved/merged.
- The collection plugins must provide the same coverage of python support as
  the versions of Ansible supported.
- The versions of Ansible supported by the collection must be the same as
  those in developed, or those maintained, as shown in the Ansible [Release and Maintenance](https://docs.ansible.com/ansible/latest/reference_appendices/release_and_maintenance.html) documentation.

We use the following guidelines:

* [CONTRIBUTING.md](https://github.com/ansible-collections/community.libvirt/blob/main/CONTRIBUTING.md)
* [REVIEW_CHECKLIST.md](https://github.com/ansible-collections/community.libvirt/blob/main/REVIEW_CHECKLIST.md)
* [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html)
* [Ansible Development Guide](https://docs.ansible.com/ansible/devel/dev_guide/index.html)
* [Ansible Collection Development Guide](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#contributing-to-collections)

### Local Testing

To learn how to test your pull request locally, refer to the [Quick-start guide](https://github.com/ansible/community-docs/blob/main/create_pr_quick_start_guide.rst#id3).

To learn how to test a pull request made by another person in your local environment, refer to the [Test PR locally guide](https://github.com/ansible/community-docs/blob/main/test_pr_locally_guide.rst).

## Collection maintenance

The current maintainers (contributors with `write` or higher access) are listed in the [MAINTAINERS](https://github.com/ansible-collections/community.libvirt/blob/main/MAINTAINERS) file. If you have questions or need help, feel free to mention them in the proposals.

To learn how to maintain / become a maintainer of this collection, refer to the [Maintainer guidelines](https://github.com/ansible-collections/community.libvirt/blob/main/MAINTAINING.md).

It is necessary for maintainers of this collection to be subscribed to:

* The collection itself (the `Watch` button -> `All Activity` in the upper right corner of the repository's homepage).
* The "Changes Impacting Collection Contributors and Maintainers" [issue](https://github.com/ansible-collections/overview/issues/45).

They also should be subscribed to Ansible's [The Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn).

### Publishing New Version

See the [Releasing guidelines](https://github.com/ansible/community-docs/blob/main/releasing_collections_without_release_branches.rst) to learn more.

## Reference

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## License
<!-- Include the appropriate license information here and a pointer to the full licensing details. If the collection contains modules migrated from the ansible/ansible repo, you must use the same license that existed in the ansible/ansible repo. See the GNU license example below. -->

GNU General Public License v3.0 or later.

See [LICENCE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
