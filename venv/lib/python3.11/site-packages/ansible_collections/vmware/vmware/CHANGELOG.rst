===========================
vmware.vmware Release Notes
===========================

.. contents:: Topics

v2.6.0
======

Minor Changes
-------------

- esxi_hosts - Added option to rename reserved variables to avoid potential conflicts with ansible-core and resolve warnings. fixes https://github.com/ansible-collections/vmware.vmware/issues/273
- module_deploy_vm_base - Removed redundant code by using new vm placement service methods in deploy modules
- vm_apply_customization - Added module to apply different customization specs to a VM
- vms - Added option to rename reserved variables to avoid potential conflicts with ansible-core and resolve warnings. fixes https://github.com/ansible-collections/vmware.vmware/issues/273

Bugfixes
--------

- Updated common VM deployment module docs to mention that name or MOID can be used for the resource pool, cluster, datastore, and datastore cluster parameters. This allows users to work around issues where the name is not unique. Fixes https://github.com/ansible-collections/vmware.vmware/issues/239
- deploy_content_library_ovf - Remove invalid storage provisioning option 'eagerzeroedthick' from module's argument spec. (Fixes https://github.com/ansible-collections/vmware.vmware/issues/278)

v2.5.0
======

Major Changes
-------------

- Replace ``ansible.module_utils._text`` (https://github.com/ansible-collections/vmware.vmware/issues/268).
- Replace ``ansible.module_utils.common._collections_compat`` (https://github.com/ansible-collections/vmware.vmware/issues/271).

Minor Changes
-------------

- content_library_item_info - Add item storage information to item result
- vm - Add module to manage virtual machines

Bugfixes
--------

- Fix issue where modules that used the proxy_host and proxy_port arguments were ignoring these arguments when initializing clients. (https://github.com/ansible-collections/vmware.vmware/issues/259)

v2.4.0
======

Minor Changes
-------------

- Add module for importing iso images to content library.
- Remove six imports from _facts.py and _vsphere_tasks.py due to new sanity rules. Python 2 (already not supported) will fail to execute these files.
- tag_associations - Add module to manage tag associations with objects
- tag_categories - Add module to manage tag categories
- tags - Add module to manage tags
- vms - Add option to inventory plugin to gather cluster and ESXi host name for VMs. (Fixes https://github.com/ansible-collections/vmware.vmware/issues/215)

Bugfixes
--------

- Drop incorrect requirement on aiohttp (https://github.com/ansible-collections/vmware.vmware/pull/230).
- cluster_ha - Fix admission control policy not being updated when ac is disabled
- content_template - Fix typo in code for check mode that tried to access a module param which doesn't exist.
- import_content_library_ovf - Fix large file import by using requests instead of open_url. Requests allows for streaming uploads, instead of reading the entire file into memory. (Fixes https://github.com/ansible-collections/vmware.vmware/issues/220)
- vm_powerstate - Ensure timeout option also applies to the shutdown-guest state

v2.3.0
======

Minor Changes
-------------

- add folder_paths_are_absolute option to all modules that support folder paths, allowing users to specify if folder paths are absolute and override the default behavior of intelligently determining if the path is absolute or relative. (https://github.com/ansible-collections/vmware.vmware/issues/202)
- vcsa_settings - Add always_update_password parameter to proxy settings, which can be used to control if the password should be updated.

Bugfixes
--------

- vcsa_settings - Fix bug where proxy settings cannot be disabled, even if enabled is set to false. (https://github.com/ansible-collections/vmware.vmware/issues/207)

v2.2.0
======

Minor Changes
-------------

- Fixed ansible-lint errors in examples.
- cluster_ha - Add module required_by rules for admission control arguments that are mentioned in the docs (https://github.com/ansible-collections/vmware.vmware/issues/201)
- cluster_ha - admission_control_failover_level can now always be managed by the user's inputs, and the default value for dedicated_host policy type is the number of dedicated failover hosts (https://github.com/ansible-collections/vmware.vmware/issues/201)

Bugfixes
--------

- content_template - Fix error when creating template from VM and not specifying certain non-critical placement options
- content_template - Replace non-existent method used when handling api errors
- pyvmomi - Replace deprecated JSON encoder with new one from pyvmomi package (https://github.com/vmware/pyvmomi/blob/e6cc09f32593d263b9ea0b611596a2c505786c6b/CHANGELOG.md?plain=1#L72)

v2.1.0
======

Minor Changes
-------------

- moid_from_path - Add lookup plugins to get an objects MOID (https://github.com/ansible-collections/vmware.vmware/issues/191)

Bugfixes
--------

- Make integration tests compatible with ansible-core 2.19 (https://github.com/ansible-collections/vmware.vmware/issues/194)
- cluster_drs - Fix error when non-string advanced settings are applied (https://github.com/ansible-collections/vmware.vmware/issues/190)
- cluster_ha - Fix error when non-string advanced settings are applied (https://github.com/ansible-collections/vmware.vmware/issues/190)
- tests/integration/vmware_folder_template_from_vm - Fix tests for 2.19

v2.0.1
======

Bugfixes
--------

- cluster_ha - fix typo that causes PDL response mode 'restart' to throw an error
- deploy_* - Fix issue where datastore was expected even though it is optional
- deploy_content_library_ovf - fix error when deploying from a datastore cluster by simplifying the ds selection process
- inventory plugins - fix issue where cache did not work (https://github.com/ansible-collections/vmware.vmware/issues/175)

v2.0.0
======

Major Changes
-------------

- cluster modules - Add identifying information about the cluster managed to the output of cluster modules
- folder_paths - Throw an error when a relative folder path is provided and the datacenter name is not provided
- module_utils/argument_spec - make argument specs public so other collections can use them https://github.com/ansible-collections/vmware.vmware/issues/144
- module_utils/clients - make client utils public so other collections can use them https://github.com/ansible-collections/vmware.vmware/issues/144
- update query file to include cluster module queries

Minor Changes
-------------

- Warn the user when more than one host has the same name in the inventory plugins. Throw an error if strict is true
- content_template - Added more options to search for the source VM like uuid and moid. Also made argument validation more accurate
- guest_info - Allow user to specify folder path to help select the VM to query
- rename private module_utils to drop the redundant vmware prefix
- vcsa_backup_schedule - Add module to manage the vCenter backup schedule
- vcsa_backup_schedule_info - Add module to gather info about the vCenter backup schedules
- vm_advanced_settings - Add module to manage the advanced settings on a VM
- vm_powerstate - Add better error message when scheduling a power state task in the past
- vm_snapshot - migrate vmware_guest_snapshot module from community to here
- vms inventory - Fixed issue where a user could accidentally not collect a required parameter, config.guestId

Breaking Changes / Porting Guide
--------------------------------

- drop support for ansible 2.15 since it is EOL https://github.com/ansible-collections/vmware.vmware/issues/103
- updated minimum pyVmomi version to 8.0.3.0.1 https://github.com/ansible-collections/vmware.vmware/issues/56

Removed Features (previously deprecated)
----------------------------------------

- vm_list_group_by_clusters - Tombstone module in favor of vmware.vmware.vm_list_group_by_clusters_info

Bugfixes
--------

- cluster_ha - Fix exception when cluster ha module checks for differences with VM monitoring configs
- fix method to lookup datastore clusters by name or moid https://github.com/ansible-collections/vmware.vmware/issues/152
- vm_snapshot - Make sure snapshot output is always included if state is present

v1.11.0
=======

Minor Changes
-------------

- _module_pyvmomi_base - Make sure to use the folder param when searching for VMs based on other common params in get_vms_using_params
- added vm_resource_info module to collect cpu/memory facts about vms
- clients/_pyvmomi - adds explicit init params instead of using dict
- clients/_rest - adds explicit init params instead of using dict
- esxi_hosts - Add inventory host filtering based on jinja statements
- esxi_hosts inventory - include moid property in output always
- pyvmomi - update object search by name method to use propertycollector, which speeds up results significantly
- upload_content_library_ovf - Add module to upload an ovf/ova to a content library
- vm_powerstate - migrate vmware_guest_powerstate module from community to here
- vms - Add inventory host filtering based on jinja statements
- vms inventory - include moid property in output always

Bugfixes
--------

- vms inventory - fix handling of VMs within VApps

v1.10.1
=======

Bugfixes
--------

- folder - replaced non-existent 'storage' type with 'datastore' type
- module_deploy_vm_base - fix attribute error when deploying to a resource pool

v1.10.0
=======

Minor Changes
-------------

- cluster_ha - migrate the vmware_cluster_ha module from community to here
- deploy_content_library_ovf - migrate the vmware_content_deploy_ovf_template module from community to here
- deploy_content_library_ovf - update parameters to be consistent with other deploy modules
- deploy_content_library_template - migrate the vmware_content_deploy_template module from community to here
- deploy_content_library_template - update parameters to be consistent with other deploy modules
- deploy_folder_template - add module to deploy a vm from a template in a vsphere folder
- esxi_connection - migrate the vmware_host module from community to here
- esxi_host - migrate the vmware_host module from community to here
- folder - migrate vmware_folder module from community to here
- local_content_library - migrate the vmware_content_library_manager module from community to here
- subscribed_content_library - migrate the vmware_content_library_manager module from community to here

v1.9.0
======

Minor Changes
-------------

- esxi_maintenance_mode - migrate esxi maintenance module from community
- info - Made vm_name variable required only when state is set to present in content_template module
- pyvmomi module base - refactor class to use the pyvmomi shared client util class as a base
- rest module base - refactor class to use the rest shared client util class as a base
- vms - added vms inventory plugin. consolidated shared docs/code with esxi hosts inventory plugin

Bugfixes
--------

- client utils - Fixed error message when required library could not be imported

v1.8.0
======

Minor Changes
-------------

- _vmware - standardize getter method names and documentation
- argument specs - Remove redundant argument specs. Update pyvmomi modules to use new consolidated spec
- content_template - Fix bad reference of library variable that was refactored to library_id
- doc fragments - Remove redundant fragments. Update pyvmomi modules to use new consolidated docs
- esxi_host - Added inventory plugin to gather info about ESXi hosts

v1.7.1
======

Bugfixes
--------

- content_library_item_info - Library name and ID are ignored if item ID is provided so updated docs and arg parse rules to reflect this

v1.7.0
======

Minor Changes
-------------

- cluster_info - Migrate cluster_info module from the community.vmware collection to here
- content_library_item_info - Migrate content_library_item_info module from the vmware.vmware_rest collection to here

v1.6.0
======

Minor Changes
-------------

- cluster_dpm - Migrated module from community.vmware to configure DPM in a vCenter cluster
- cluster_drs_recommendations - Migrated module from community.vmware to apply any DRS recommendations the vCenter cluster may have

Bugfixes
--------

- Fix typos in all module documentation and README
- cluster_drs - fixed backwards vMotion rate (input 1 set rate to 5 in vCenter) (https://github.com/ansible-collections/vmware.vmware/issues/68)

v1.5.0
======

Minor Changes
-------------

- Add action group (https://github.com/ansible-collections/vmware.vmware/pull/59).
- cluster - Added cluster module, which is meant to succeed the community.vmware.vmware_cluster module (https://github.com/ansible-collections/vmware.vmware/pull/60).
- cluster_vcls - Added module to manage vCLS settings, based on community.vmware.vmware_cluster_vcls (https://github.com/ansible-collections/vmware.vmware/pull/61).
- folder_template_from_vm - Use a more robust method when waiting for tasks to complete to improve accuracy (https://github.com/ansible-collections/vmware.vmware/pull/64).

Bugfixes
--------

- README - Fix typos in README (https://github.com/ansible-collections/vmware.vmware/pull/66).

v1.4.0
======

Minor Changes
-------------

- cluster_drs - added cluster_drs module to manage DRS settings in vcenter
- folder_template_from_vm - add module and tests to create a template from an existing VM in vcenter and store the template in a folder
- guest_info - migrated functionality from community vmware_guest_info and vmware_vm_info into guest_info. Changes are backwards compatible but legacy outputs are deprecated
- module_utils/vmware_tasks - added shared utils to monitor long running tasks in vcenter
- module_utils/vmware_type_utils - added shared utils for validating, transforming, and comparing vcenter settings with python variables
- vm_portgroup_info - add module to get all the portgroups that associated with VMs

Bugfixes
--------

- _vmware_facts - fixed typo in hw_interfaces fact key and added missing annotation fact key and value
- _vmware_folder_paths - fixed issue where resolved folder paths incorrectly included a leading slash
- guest_info - added more optional attributes to the example
- module_utils/vmware_rest_client - rename get_vm_by_name method as there is same signature already

New Modules
-----------

- vmware.vmware.vm_portgroup_info - Returns information about the portgroups of virtual machines

v1.3.0
======

Minor Changes
-------------

- content_template - Add new module to manage templates in content library
- vm_list_group_by_clusters_info - Add the appropriate returned value for the deprecated module ``vm_list_group_by_clusters``

v1.2.0
======

Minor Changes
-------------

- Clarify pyVmomi requirement (https://github.com/ansible-collections/vmware.vmware/pull/15).
- vcsa_settings - Add new module to configure VCSA settings

Deprecated Features
-------------------

- vm_list_group_by_clusters - deprecate the module since it was renamed to ``vm_list_group_by_clusters_info``

Bugfixes
--------

- guest_info - Fixed bugs that caused module failure when specifying the guest_name attribute

v1.1.0
======

Minor Changes
-------------

- Added module vm_list_group_by_clusters

v1.0.0
======

Release Summary
---------------

Initial release 1.0.0

Major Changes
-------------

- Added module appliance_info
- Added module guest_info
- Added module license_info
- Release 1.0.0
