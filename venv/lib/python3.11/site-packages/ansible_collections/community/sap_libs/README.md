# community.sap_libs Ansible Collection

[![CI](https://github.com/sap-linuxlab/community.sap_libs/workflows/CI/badge.svg)](https://github.com/sap-linuxlab/community.sap_libs/actions) [![Codecov](https://img.shields.io/codecov/c/github/sap-linuxlab/community.sap_libs)](https://codecov.io/gh/sap-linuxlab/community.sap_libs)

## Description
This Ansible Collection provides a set of Ansible Modules designed to automate various operations on SAP systems.  

It was migrated from repository `ansible-collections/community.sap`.

## Requirements
Some modules have external dependencies.
- `SAPCAR` binaries are required for:
  - `sapcar_extract`

- Python Library `pyrfc >= 2.4.0` is required for:
  - `sap_company`
  - `sap_snote`
  - `sap_task_list_execute`
  - `sap_user`
  - `sap_pyrfc`

### Important: PyRFC dependency is deprecated
**SAP has discontinued development on `PyRFC` in 2024.**  
You can find more details in the [announcement](https://github.com/SAP-archive/PyRFC/issues/372) or in [deprecation notice](https://github.com/SAP-archive/PyRFC?tab=readme-ov-file#deprecation-notice).  

The `PyRFC` library is a critical dependency for several modules in this collection, as it is a Python wrapper for the `SAP NW RFC SDK` libraries. While both `PyRFC` and the `SAP NW RFC SDK` are still available for installation and download at this time, their deprecation means they could be removed without notice.  

We will continue to support the modules that depend on `PyRFC` for as long as both the `PyRFC` library and the `SAP NW RFC SDK` remain available. However, the moment either of them becomes unavailable, we will be forced to cease support for these modules, as they will no longer be functional.  

We are investigating potential alternatives, but there is no clear path forward at this time. Users should be aware of this risk when using the affected modules.

## Installation Instructions

### Installation
Install this collection with Ansible Galaxy command:
```console
ansible-galaxy collection install community.sap_libs
```

### Upgrade
Installed Ansible Collection will not be upgraded automatically when Ansible package is upgraded.

To upgrade the collection to the latest available version, run the following command:
```console
ansible-galaxy collection install community.sap_libs --upgrade
```

You can also install a specific version of the collection, when you encounter issues with latest version. Please report these issues in affected Role repository if that happens.
Example of downgrading collection to version 1.4.0:
```
ansible-galaxy collection install community.sap_libs:==1.4.0
```

See [Installing collections](https://docs.ansible.com/ansible/latest/collections_guide/collections_installing.html) for more details on installation methods.

## Ansible Modules
The following Ansible Modules are included in this collection.
- [sap_hdbsql](https://docs.ansible.com/ansible/latest/collections/community/sap_libs/sap_hdbsql_module.html)
- [sap_task_list_execute](https://docs.ansible.com/ansible/latest/collections/community/sap_libs/sap_task_list_execute_module.html)
- [sapcar_extract](https://docs.ansible.com/ansible/latest/collections/community/sap_libs/sapcar_extract_module.html)
- [sap_company](https://docs.ansible.com/ansible/latest/collections/community/sap_libs/sap_company_module.html)
- [sap_snote](https://docs.ansible.com/ansible/latest/collections/community/sap_libs/sap_snote_module.html)
- [sap_user](https://docs.ansible.com/ansible/latest/collections/community/sap_libs/sap_user_module.html)
- [sap_system_facts](https://docs.ansible.com/ansible/latest/collections/community/sap_libs/sap_system_facts_module.html)
- [sap_control_exec](https://docs.ansible.com/ansible/latest/collections/community/sap_libs/sap_control_exec_module.html)
- [sap_pyrfc](https://docs.ansible.com/ansible/latest/collections/community/sap_libs/sap_pyrfc_module.html)

## Testing
This Ansible Collection was tested across different versions of Ansible and Python.  
The automated [CI](https://github.com/sap-linuxlab/community.sap_libs/blob/main/.github/workflows/ansible-test.yml) workflow is executing Sanity and Unit tests on following versions.

Supported ansible-core versions:
- `2.18` with Python `3.11 - 3.13`
- `2.19` with Python `3.11 - 3.13`
- `devel` with Python `3.11 - 3.13`

End-of-life ansible-core versions are only tested for backwards compatibility.
- `2.14` with Python `3.9 - 3.11`
- `2.15` with Python `3.9 - 3.11`
- `2.16` with Python `3.10 - 3.12`
- `2.17` with Python `3.10 - 3.12`

**Support for Python 2 has been dropped in release `1.5.0`.**

Due to SAP licensing and hardware requirements, integration tests are momentarily not feasible.  
The modules are tested manually against SAP systems until we found a solution or have some
modules where we are able to execute integration test we decided to disable these tests.

**NOTE:** All tests combinations were configured following official [ansible-core-support-matrix](https://docs.ansible.com/ansible/latest/reference_appendices/release_and_maintenance.html#ansible-core-support-matrix).

## Maintainers
You can find more information about maintainers of this Ansible Collection at [MAINTAINERS.md](https://github.com/sap-linuxlab/community.sap_libs/blob/main/MAINTAINERS.md).

## Contributing
You can find more information about ways you can contribute at [sap-linuxlab website](https://sap-linuxlab.github.io/initiative_contributions/).

## Support
You can report any issues using [Issues](https://github.com/sap-linuxlab/community.sap_libs/issues) section.

## Release Notes and Roadmap
The release notes for this collection can be found in the [CHANGELOG file](https://github.com/sap-linuxlab/community.sap_libs/blob/main/CHANGELOG.rst).


## Further Information

### Additional sources
You can find more information at following sources:
- [Ansible User guide](https://docs.ansible.com/ansible/devel/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/devel/dev_guide/index.html)
- [Ansible Community Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html)
- [News for Maintainers](https://github.com/ansible-collections/news-for-maintainers)

## License
[Apache 2.0](https://github.com/sap-linuxlab/community.sap_libs/blob/main/LICENSE)
