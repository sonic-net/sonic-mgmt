[![OpenDev Zuul Builds - Ansible OpenStack Collection](https://zuul-ci.org/gated.svg)](
http://zuul.opendev.org/t/openstack/builds?project=openstack%2Fansible-collections-openstack)

# Ansible OpenStack Collection

Ansible OpenStack collection aka `openstack.cloud` provides Ansible modules and Ansible plugins for managing OpenStack
clouds. It is supported and maintained by the OpenStack community.

**NOTE:** We need and value your contributions! Maintaining this collection is a community effort. We are all both users
and developers of this collection at the same time. If you find a bug, please report it. If you have fixed a bug, please
submit a patch. If you need new functionality which is not covered by this collection yet, please extend an existing
module or submit a new one. Our [Contributing](#contributing) section below has tons of docs to check out. Please get in
touch!

## Branches and Non Backward Compatibility ⚠️

Our codebase has been split into two separate release series, `2.x.x` and `1.x.x`:

* `2.x.x` releases of Ansible OpenStack collection are compatible with [OpenStack SDK][openstacksdk] `1.x.x` and its
  release candidates `0.99.0` and later *only* (OpenStack Zed and later). Our `master` branch tracks our `2.x.x`
  releases.
* `1.x.x` releases of Ansible OpenStack collection are compatible with [OpenStack SDK][openstacksdk] `0.x.x` prior to
  `0.99.0` *only* (OpenStack Yoga and earlier). Our `stable/1.0.0` branch tracks our `1.x.x` releases.
* `2.x.x` releases of Ansible OpenStack collection are not backward compatible to `1.x.x` releases ⚠️

For rationale and details please read our [branching docs](docs/branching.md). Both branches will be developed in
parallel for the time being. Patches from `master` will be backported to `stable/1.0.0` on a best effort basis but
expect new features to be introduced in our `master` branch only. Contributions are welcome for both branches!

[openstacksdk]: https://opendev.org/openstack/openstacksdk

## Installation

For using this collection, first you have to install both Python packages `ansible` and `openstacksdk` on your Ansible
controller:

```sh
pip install "ansible>=2.9" "openstacksdk>=1.0.0"
```

[OpenStack SDK][openstacksdk] has to be available on the Ansible host running the OpenStack modules. Depending on the
Ansible playbook and roles you use, this host is not necessarily the Ansible controller. Sometimes Ansible might invoke
a non-standard Python interpreter on the target Ansible host. Using Python 3.6 is required for modules in this
collection.

Always use the last stable version of [OpenStack SDK][openstacksdk] if possible, also when running against older
OpenStack deployments. OpenStack SDK is backward compatible to older OpenStack deployments, so its safe to run last
version of the SDK against older OpenStack clouds. The installed version of the OpenStack SDK does not have to match
your OpenStack cloud, but it has to match the release series of this collection which you are using. For notes about
our release series and branches please read the introduction above.

Before using this collection, you have to install it with `ansible-galaxy`:

```sh
ansible-galaxy collection install openstack.cloud
```

You can also include it in a `requirements.yml` file:

```yaml
collections:
- name: openstack.cloud
```

And then install it with:

```sh
ansible-galaxy collection install -r requirements.yml
```

## Usage

To use a module from the Ansible OpenStack collection, call them by their Fully Qualified Collection Name (FQCN),
composed of their namespace, collection name and module name:

```yaml
---
- hosts: localhost
  tasks:
    - name: Create server in an OpenStack cloud
      openstack.cloud.server:
        name: vm
        state: present
        cloud: openstack
        region_name: ams01
        image: Ubuntu Server 14.04
        flavor_ram: 4096
        boot_from_volume: True
        volume_size: 75
```

Or you can add the full namespace and collection name in the `collections` element:

```yaml
---
- hosts: localhost
  collections:
    - openstack.cloud
  tasks:
    - name: Create server in an OpenStack cloud
      server_volume:
        state: present
        cloud: openstack
        server: Mysql-server
        volume: mysql-data
        device: /dev/vdb
```

For powerful generic [CRUD][crud]-style resource management use Ansible module
[`openstack.cloud.resource`](plugins/modules/resource.py):

```yaml
---
- hosts: localhost
  tasks:
    - name: Create security group
      openstack.cloud.resource:
        cloud: openstack
        service: network
        type: security_group
        attributes:
          name: ansible_security_group
          description: 'ansible security group'

    - name: Update security group description
      openstack.cloud.resource:
        cloud: openstack
        service: network
        type: security_group
        attributes:
          name: ansible_security_group
          description: 'ansible neutron security group'

    - name: Delete security group
      openstack.cloud.resource:
        cloud: openstack
        service: network
        type: security_group
        attributes:
          name: ansible_security_group
        state: absent
```

For generic resource listing use Ansible module [`openstack.cloud.resources`](plugins/modules/resources.py):

```yaml
---
- hosts: localhost
  tasks:
    - name: List images
      openstack.cloud.resources:
        cloud: openstack
        service: image
        type: image

    - name: List compute flavors
      openstack.cloud.resources:
        cloud: openstack
        service: compute
        type: flavor

    - name: List networks with name 'public'
      openstack.cloud.resources:
        cloud: openstack
        service: network
        type: network
        parameters:
          name: public
```

[Ansible module defaults][ansible-module-defaults] are supported as well:

```yaml
---
- module_defaults:
    group/openstack.cloud.openstack:
      cloud: devstack-admin
    #
    #
    # Listing modules individually is required for
    # backward compatibility with Ansible 2.9 only
    openstack.cloud.compute_flavor_info:
      cloud: devstack-admin
    openstack.cloud.server_info:
      cloud: devstack-admin
  block:
    - name: List compute flavors
      openstack.cloud.compute_flavor_info:

    - name: List servers
      openstack.cloud.server_info:
```

[ansible-module-defaults]: https://docs.ansible.com/ansible/latest/user_guide/playbooks_module_defaults.html
[crud]: https://en.wikipedia.org/wiki/CRUD

## Documentation

See collection docs at Ansible's main page:

* [openstack.cloud collection docs (version released in Ansible package)](
  https://docs.ansible.com/ansible/latest/collections/openstack/cloud/index.html)

* [openstack.cloud collection docs (devel version)](
  https://docs.ansible.com/ansible/devel/collections/openstack/cloud/index.html)

## Contributing

Thank you for your interest in our Ansible OpenStack collection ☺️

There are many ways in which you can participate in the project, for example:

- [Report and verify bugs and help with solving issues](
  https://bugs.launchpad.net/ansible-collections-openstack).
- [Submit and review patches](
  https://review.opendev.org/#/q/project:openstack/ansible-collections-openstack).
- Follow OpenStack's [How To Contribute](https://wiki.openstack.org/wiki/How_To_Contribute) guide.

Please read our [Contributions and Development Guide](docs/contributing.md) (⚠️) and our [Review Guide](
docs/reviewing.md) (⚠️) before sending your first patch. Pull requests submitted through GitHub will be ignored.

## Communication

We have a Special Interest Group for the Ansible OpenStack collection. Join us in `#openstack-ansible-sig` on
[OFTC IRC](https://www.oftc.net/) 🍪

## License

GNU General Public License v3.0 or later

See [LICENCE](COPYING) to see the full text.
