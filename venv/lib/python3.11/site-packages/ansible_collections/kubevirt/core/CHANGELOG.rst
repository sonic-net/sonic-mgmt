=============================================
KubeVirt Collection for Ansible Release Notes
=============================================

.. contents:: Topics

This changelog describes changes after version 1.0.0.

v2.2.2
======

Release Summary
---------------

This is a maintenance release to trigger a rebuild. No functional changes.

v2.2.1
======

Release Summary
---------------

This release brings some new features and enables compatibility with ansible-core-2.19.
The inventory now tries to lookup winrm services for Windows hosts if enabled.
The unset_ansible_port option was added to the inventory. It allows to control if the value of ansible_port should be unset if no non-default value was found.
The hidden_fields argument was added to kubevirt_vm and kubevirt_{vm,vmi}_info which allows to hide and ignore certain fields in the returned definition of a VM or VMI.
If no namespaces were configured the inventory now tries to use OCP Projects if available.
It is now possible to switch between running and run_strategy with kubevirt_vm.
This is a maintenance release with no functional changes compared to version 2.2.0. Only the changelog was fixed.

Minor Changes
-------------

- chore: Bump supported python and ansible-core versions `#176 <https://github.com/kubevirt/kubevirt.core/pull/176>`_
- feat(inventory): Add unset_ansible_port option `#173 <https://github.com/kubevirt/kubevirt.core/pull/173>`_
- feat(inventory): Lookup winrm services for Windows hosts `#171 <https://github.com/kubevirt/kubevirt.core/pull/171>`_
- feat(inventory): Use OCP projects if available `#179 <https://github.com/kubevirt/kubevirt.core/pull/179>`_
- feat(modules): Add hidden_fields argument `#178 <https://github.com/kubevirt/kubevirt.core/pull/178>`_
- fix(kubevirt_vm): Allow switching between running and run_strategy `#180 <https://github.com/kubevirt/kubevirt.core/pull/180>`_
- fix: Ensure compatibility with ansible-core >= 2.19 `#175 <https://github.com/kubevirt/kubevirt.core/pull/175>`_

v2.2.0
======

Release Summary
---------------

This release brings some new features and enables compatibility with ansible-core-2.19.

v2.1.0
======

Release Summary
---------------

The kubevirt_vmi_info module was added to this collection.

Minor Changes
-------------

- Run integration tests in random namespaces `#130 <https://github.com/kubevirt/kubevirt.core/pull/130>`_
- feat: Add kubevirt_vmi_info module `#129 <https://github.com/kubevirt/kubevirt.core/pull/129>`_

v2.0.0
======

Release Summary
---------------

The deprecation of the 'connections' parameter is continued by dropping support for multiple connections. Inventory configurations with a single connection remain working for now. This backwards compatibility will be dropped in version 3.0.0 of the collection.
Inventory source caching is now working and allows to reduce the load on the control plane of a cluster from which an inventory is built.

Minor Changes
-------------

- Several small cleanups `#122 <https://github.com/kubevirt/kubevirt.core/pull/122>`_
- feat(kubevirt_vm): Add support for RunStrategy `#124 <https://github.com/kubevirt/kubevirt.core/pull/124>`_

Breaking Changes / Porting Guide
--------------------------------

- chore: Bump version to 2.0.0 `#125 <https://github.com/kubevirt/kubevirt.core/pull/125>`_
- cleanup(inventory): Drop support for multiple connections `#117 <https://github.com/kubevirt/kubevirt.core/pull/117>`_

Bugfixes
--------

- fix(inventory): Fix inventory source caching `#119 <https://github.com/kubevirt/kubevirt.core/pull/119>`_

v1.5.0
======

Release Summary
---------------

Support for stopped VMs, deprecation of the 'connections' parameter and many cleanups.

Major Changes
-------------

- chore: Update supported ansible-core versions to >=2.15 `#105 <https://github.com/kubevirt/kubevirt.core/pull/105>`_
- feat,test(inventory): Support listing stopped VMs and major rework of unit tests  `#114 <https://github.com/kubevirt/kubevirt.core/pull/114>`_

Minor Changes
-------------

- Bump e2e software versions `#109 <https://github.com/kubevirt/kubevirt.core/pull/109>`_
- Make kubevirt_vm tests more robust `#103 <https://github.com/kubevirt/kubevirt.core/pull/103>`_
- Several minor improvements `#115 <https://github.com/kubevirt/kubevirt.core/pull/115>`_
- chore: Ensure compatibility with kubernetes.core >=3.1.0,<6.0.0 `#111 <https://github.com/kubevirt/kubevirt.core/pull/111>`_
- kubevirt_vm integration tests: changed ssh key type to RSA for FIPS mode `#108 <https://github.com/kubevirt/kubevirt.core/pull/108>`_

Bugfixes
--------

- fix(tests,kubevirt_vm): Fix assertion in verify.yml `#106 <https://github.com/kubevirt/kubevirt.core/pull/106>`_

v1.4.0
======

Release Summary
---------------

Compatibility with kubernetes.core >=3.1.0,<4.1.0 and some minor enhancements.

Minor Changes
-------------

- Provide links for docsite and improve docs by adding markup `#95 <https://github.com/kubevirt/kubevirt.core/pull/95>`_
- cleanup: Cleanup YAML passed to k8s module `#88 <https://github.com/kubevirt/kubevirt.core/pull/88>`_
- docs: Use proper type for connections parameter `#90 <https://github.com/kubevirt/kubevirt.core/pull/90>`_
- feat(kubevirt_vm_info): Set wait_condition based on running `#91 <https://github.com/kubevirt/kubevirt.core/pull/91>`_

Bugfixes
--------

- fix(kubevirt_vm): Set wait_condition based on running `#89 <https://github.com/kubevirt/kubevirt.core/pull/89>`_
- fix: Ensure compatibility with kubernetes.core >=3.10,<4.1.0 `#100 <https://github.com/kubevirt/kubevirt.core/pull/100>`_

v1.3.2
======

Release Summary
---------------

No functional changes, hotfix release to retrigger the downstream build and to keep in sync with Ansible Automation Hub.

v1.3.1
======

Release Summary
---------------

No functional changes, only updates to the shipped documentation.

v1.3.0
======

Minor Changes
-------------

- feat: Add append_base_domain option to connections `#72 <https://github.com/kubevirt/kubevirt.core/pull/72>`_
- feat: Give secondary interfaces a higher priority over services `#76 <https://github.com/kubevirt/kubevirt.core/pull/76>`_

Bugfixes
--------

- feat: Set ansible_connection to winrm for Windows hosts `#75 <https://github.com/kubevirt/kubevirt.core/pull/75>`_
- fix: Explicity set ansible_port `#70 <https://github.com/kubevirt/kubevirt.core/pull/70>`_
- fix: Return early to avoid adding empty groups. `#73 <https://github.com/kubevirt/kubevirt.core/pull/73>`_

v1.2.3
======

Release Summary
---------------

No functional changes, hotfix release to retrigger the downstream build and to keep in sync with Ansible Automation Hub.

v1.2.2
======

Release Summary
---------------

No functional changes, only cleanup of files included in the release tarball and vendoring of documentation fragments.

v1.2.1
======

Release Summary
---------------

Mostly code cleanups and dependency updates to ensure compatibility with KubeVirt >= 1.1.0

v1.2.0
======

Release Summary
---------------

Not released due to issues in the release process

v1.1.0
======

Minor Changes
-------------

- Add kubevirt_vm_info module to describe existing VirtualMachines
- inventory: Allow to control creation of additional groups
- inventory: Drop creation of the namespace_vmis_group as it is redundant

v1.0.0
======

Release Summary
---------------

Initial release
