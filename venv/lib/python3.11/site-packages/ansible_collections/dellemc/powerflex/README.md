# Ansible Modules for Dell Technologies PowerFlex

[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](https://github.com/dell/ansible-powerflex/blob/main/docs/CODE_OF_CONDUCT.md)
[![License](https://img.shields.io/github/license/dell/ansible-powerflex)](https://github.com/dell/ansible-powerflex/blob/main/LICENSE)
[![Python version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Ansible version](https://img.shields.io/badge/ansible-2.16+-blue.svg)](https://pypi.org/project/ansible/)
[![PyPowerFlex](https://img.shields.io/github/v/release/dell/python-powerflex?include_prereleases&label=PyPowerFlex&style=flat-square)](https://github.com/dell/python-powerflex/releases)
[![GitHub release (latest by date including pre-releases)](https://img.shields.io/github/v/release/dell/ansible-powerflex?include_prereleases&label=latest&style=flat-square)](https://github.com/dell/ansible-powerflex/releases)
[![codecov](https://codecov.io/gh/dell/ansible-powerflex/branch/main/graph/badge.svg)](https://app.codecov.io/gh/dell/ansible-powerflex)

The Ansible Modules for Dell Technologies (Dell) PowerFlex allow Data Center and IT administrators to use RedHat Ansible to automate and orchestrate the provisioning and management of Dell PowerFlex storage systems.

The capabilities of the Ansible modules are managing SDCs, volumes, snapshots, snapshot policy, storage pools, replication consistency groups, replication pairs, SDSs, SDTs, NVMe hosts, devices, protection domains, MDM cluster, Fault Set and to gather high level facts from the storage system. The options available are list, show, create, modify and delete. These tasks can be executed by running simple playbooks written in yaml syntax. The modules are written so that all the operations are idempotent, so making multiple identical requests has the same effect as making a single request.

## Table of contents

* [Code of conduct](https://github.com/dell/ansible-powerflex/blob/main/docs/CODE_OF_CONDUCT.md)
* [Maintainer guide](https://github.com/dell/ansible-powerflex/blob/main/docs/MAINTAINER_GUIDE.md)
* [Committer guide](https://github.com/dell/ansible-powerflex/blob/main/docs/COMMITTER_GUIDE.md)
* [Contributing guide](https://github.com/dell/ansible-powerflex/blob/main/docs/CONTRIBUTING.md)
* [Branching strategy](https://github.com/dell/ansible-powerflex/blob/main/docs/BRANCHING.md)
* [List of adopters](https://github.com/dell/ansible-powerflex/blob/main/docs/ADOPTERS.md)
* [Maintainers](https://github.com/dell/ansible-powerflex/blob/main/docs/MAINTAINERS.md)
* [Support](https://github.com/dell/ansible-powerflex/blob/main/docs/SUPPORT.md)
* [License](#license)
* [Security](https://github.com/dell/ansible-powerflex/blob/main/docs/SECURITY.md)
* [Prerequisites](#prerequisites)
* [List of Ansible modules for Dell PowerFlex](#list-of-ansible-modules-for-dell-powerflex)
* [Installation and execution of Ansible modules for Dell PowerFlex](#installation-and-execution-of-ansible-modules-for-dell-powerflex)
* [Releasing, Maintenance and Deprecation](#releasing-maintenance-and-deprecation)



## Requirements

| **Ansible Modules** | **PowerFlex/VxFlex OS Version** | **SDK version** | **Python version** | **Ansible**              |
|---------------------|-----------------------|-------|--------------------|--------------------------|
| v2.6.1 |3.6 <br> 4.5 <br> 4.6 <br> APEX Block Storage for Mircrosoft Azure <br> APEX Block Storage for AWS | 1.14.1 | 3.10.x <br> 3.11.x <br> 3.12.x | <br> 2.16 <br> 2.17 <br> 2.18 |

  * Please follow PyPowerFlex installation instructions on [PyPowerFlex Documentation](https://github.com/dell/python-powerflex)

## Installation and execution of Ansible modules for Dell PowerFlex
The installation and execution steps of Ansible modules for Dell PowerFlex can be found [here](https://github.com/dell/ansible-powerflex/blob/main/docs/INSTALLATION.md).

## Use Cases
Refer the [example playbooks](https://github.com/dell/ansible-powerflex/tree/main/playbooks) on how the collection can be used for [modules](https://github.com/dell/ansible-powerflex/tree/main/playbooks/modules) and [roles](https://github.com/dell/ansible-powerflex/tree/main/playbooks/roles). 

## Testing
The following tests are done on ansible-powerflex collection
- Unit tests
- Integration tests.

## Support
Refer [Support](https://github.com/dell/ansible-powerflex/blob/main/docs/SUPPORT.md) documenetation for more information on the support from Dell Technologies.

## Release Notes, Maintenance and Deprecation
Ansible Modules for Dell Technologies PowerFlex follows [Semantic Versioning](https://semver.org/).

New version will be release regularly if significant changes (bug fix or new feature) are made in the collection.

Released code versions are located on "release" branches with names of the form "release-x.y.z" where x.y.z corresponds to the version number. More information on branching strategy followed can be found [here](https://github.com/dell/ansible-powerflex/blob/main/docs/BRANCHING.md).

Ansible Modules for Dell Technologies PowerFlex deprecation cycle is aligned with that of [Ansible](https://docs.ansible.com/ansible/latest/dev_guide/module_lifecycle.html).

See [change logs](https://github.com/dell/ansible-powerflex/blob/main/CHANGELOG.rst) for more information on what is new in the releases.

## Related Information

### Idempotency
The modules are written in such a way that all requests are idempotent and hence fault-tolerant. It essentially means that the result of a successfully performed request is independent of the number of times it is executed.

### List of Ansible modules for Dell PowerFlex
  * [Info module](https://github.com/dell/ansible-powerflex/blob/main/docs/modules/info.rst)
  * [Snapshot module](https://github.com/dell/ansible-powerflex/blob/main/docs/modules/snapshot.rst)
  * [SDC module](https://github.com/dell/ansible-powerflex/blob/main/docs/modules/sdc.rst)
  * [Storage pool module](https://github.com/dell/ansible-powerflex/blob/main/docs/modules/storagepool.rst)
  * [Volume module](https://github.com/dell/ansible-powerflex/blob/main/docs/modules/volume.rst)
  * [SDS module](https://github.com/dell/ansible-powerflex/blob/main/docs/modules/sds.rst)
  * [SDT module](https://github.com/dell/ansible-powerflex/blob/main/docs/modules/sdt.rst)
  * [NVMe Host module](https://github.com/dell/ansible-powerflex/blob/main/docs/modules/nvme_host.rst)
  * [Device Module](https://github.com/dell/ansible-powerflex/blob/main/docs/modules/device.rst)
  * [Protection Domain Module](https://github.com/dell/ansible-powerflex/blob/main/docs/modules/protection_domain.rst)
  * [MDM Cluster Module](https://github.com/dell/ansible-powerflex/blob/main/docs/modules/mdm_cluster.rst)
  * [Replication Consistency Group Module](https://github.com/dell/ansible-powerflex/blob/main/docs/modules/replication_consistency_group.rst)
  * [Replication Pair Module](https://github.com/dell/ansible-powerflex/blob/main/docs/modules/replication_pair.rst)
  * [Snapshot Policy Module](https://github.com/dell/ansible-powerflex/blob/main/docs/modules/snapshot_policy.rst)
  * [Fault Sets Module](https://github.com/dell/ansible-powerflex/blob/main/docs/modules/fault_set.rst)


## License
The Ansible collection for PowerFlex is released and licensed under the GPL-3.0 license. See [LICENSE](https://github.com/dell/ansible-powerflex/blob/main/LICENSE) for the full terms.