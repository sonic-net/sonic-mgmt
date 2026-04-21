# Contributing

## Getting Started

General information about setting up your Python environment, testing modules,
Ansible coding styles, and more can be found in the [Ansible Community Guide](
https://docs.ansible.com/ansible/latest/community/index.html).


## Kubernetes Collections

### community.okd

This collection contains modules and plugins contributed and maintained by the Ansible Kubernetes
community.

New modules and plugins developed by the community should be proposed to `community.okd`.

## Submitting Issues
All software has bugs, and the `community.okd` collection is no exception. When you find a bug,
you can help tremendously by [telling us about it](https://github.com/ansible-collections/community.okd/issues/new/choose).

If you should discover that the bug you're trying to file already exists in an issue,
you can help by verifying the behavior of the reported bug with a comment in that
issue, or by reporting any additional information.

## Pull Requests

All modules MUST have integration tests for new features.
Bug fixes for modules that currently have integration tests SHOULD have tests added.
New modules should be submitted to the [community.okd](https://github.com/ansible-collections/community.okd) collection and MUST have integration tests.

Expected test criteria:
* Resource creation under check mode
* Resource creation
* Resource creation again (idempotency) under check mode
* Resource creation again (idempotency)
* Resource modification under check mode
* Resource modification
* Resource modification again (idempotency) under check mode
* Resource modification again (idempotency)
* Resource deletion under check mode
* Resource deletion
* Resource deletion (of a non-existent resource) under check mode
* Resource deletion (of a non-existent resource)

Where modules have multiple parameters we recommend running through the 4-step modification cycle for each parameter the module accepts, as well as a modification cycle where as most, if not all, parameters are modified at the same time.

For general information on running the integration tests see the
[Integration Tests page of the Module Development Guide](https://docs.ansible.com/ansible/devel/dev_guide/testing_integration.html#testing-integration),
especially the section on configuration for cloud tests. For questions about writing tests the Ansible Kubernetes community can be found on Libera.Chat IRC as detailed below.


### Code of Conduct
The `community.okd` collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.

### IRC
Our IRC channels may require you to register your nickname. If you receive an error when you connect, see
[Libera.Chat's Nickname Registration guide](https://libera.chat/guides/registration) for instructions.

The `#ansible-kubernetes` channel on [irc.libera.chat](https://libera.chat/) is the main and official place to discuss use and development of the `community.okd` collection.

For more information about Ansible's Kubernetes and OpenShift integration, browse the resources in the [Kubernetes Working Group](https://github.com/ansible/community/wiki/Kubernetes) Community wiki page.
