# Lean Ansible bindings for KubeVirt
<!--start build_status -->
[![Build Status](https://github.com/kubevirt/kubevirt.core/workflows/CI/badge.svg?event=push)](https://github.com/kubevirt/kubevirt.core/actions)
<!--end build_status -->

This repository hosts the `kubevirt.core` Ansible Collection, which provides virtual machine operations and an inventory source for use with Ansible.

<!--start requires_ansible -->
## Ansible and Python version compatibility

This collection has been tested against Ansible versions **>=2.16,<=2.19** and Python versions **>=3.10,<=3.13**.

See the [Ansible core support matrix](https://docs.ansible.com/ansible/latest/reference_appendices/release_and_maintenance.html#ansible-core-support-matrix) for supported combinations.
<!--end requires_ansible -->

## Included content

### Plugins

* `kubevirt`: Inventory source for KubeVirt VirtualMachines
* `kubevirt_vm`: Create or delete KubeVirt VirtualMachines
* `kubevirt_vm_info`: Describe KubeVirt VirtualMachines
* `kubevirt_vmi_info`: Describe KubeVirt VirtualMachineInstances

## Using this collection

<!--start galaxy_download -->
### Installing the Collection from Ansible Galaxy

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:
```bash
ansible-galaxy collection install kubevirt.core
```
<!--end galaxy_download -->

### Build and install locally

Clone the repository, checkout the tag you want to build, or pick the main branch for the development version; then:
```bash
ansible-galaxy collection build .
ansible-galaxy collection install kubevirt-kubevirt.core-*.tar.gz
```

### Dependencies

<!--start collection_dependencies -->
#### Ansible collections

* [kubernetes.core](https://galaxy.ansible.com/ui/repo/published/kubernetes/core)>=5.2.0,<7.0.0

To install all the dependencies:
```bash
ansible-galaxy collection install -r requirements.yml
```
<!--end collection_dependencies -->

#### Python libraries

- jsonpatch
- kubernetes>=28.1.0
- PyYAML>=3.11

To install all the dependencies:
```bash
pip install -r requirements.txt
```

See [Ansible Using collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

<!--start community_readme -->
## Code of Conduct

We follow the [KubeVirt Code of Conduct](https://github.com/kubevirt/kubevirt/blob/main/CODE_OF_CONDUCT.md).

## Contributing to this collection

The content of this collection is made by people like you, a community of individuals collaborating on making the world better through developing automation software.

We are actively accepting new contributors.

Any kind of contribution is very welcome.

You don't know how to start? Refer to our [contribution guide](CONTRIBUTING.md)!

We use the following guidelines:

* [CONTRIBUTING.md](CONTRIBUTING.md)
* [REVIEW_CHECKLIST.md](REVIEW_CHECKLIST.md)
* [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html)
* [Ansible Development Guide](https://docs.ansible.com/ansible/devel/dev_guide/index.html)
* [Ansible Collection Development Guide](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#contributing-to-collections)

## Collection maintenance

The current maintainers are listed in the [OWNERS](OWNERS) file. If you have questions or need help, feel free to mention them in the proposals.

To learn how to maintain / become a maintainer of this collection, refer to the [Maintainer guidelines](https://docs.ansible.com/ansible/devel/community/maintainers.html).

## Release policy

The release policy of the collection can be found at [docs/releasing.md](docs/releasing.md).

## Governance

The process of decision making in this collection is based on discussing and finding consensus among participants.

Every voice is important. If you have something on your mind, create an issue or dedicated discussion and let's discuss it!
<!--end community_readme -->

<!--start support -->
<!--end support -->

## Licensing

Apache License 2.0

See [LICENSE](./LICENSE) to see the full text.
