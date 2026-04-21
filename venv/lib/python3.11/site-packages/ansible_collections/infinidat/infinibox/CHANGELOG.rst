==========
Change Log
==========

-------------------
v1.6.0 (2024-09-04)
-------------------

^^^^^^^^^^^^^^^^^^^^
Project Enhancements
^^^^^^^^^^^^^^^^^^^^
* psdev-1352: Add state search_iboxes to infini_infinimetrics module. Allows one to find the Infiniboxes registered with an Infinimetrics.

-------------------
v1.5.0 (2024-07-10)
-------------------

^^^^^^^^^^^^^^^^^^^^
Project Enhancements
^^^^^^^^^^^^^^^^^^^^
* psdev-1330: Support serializing session data to disk to reduce log in/out events and to improve performance. Credentials will be saved to a file named '/tmp/infinibox_pickle_<IBOX>'. The collection uses the Python pickle module to save the API session data to file. The next Infinidat module executed is then able to load the session data. An optional parameter name 'stay_logged_in' has been added.  It defaults to False.  If True, session pickle files will be loaded if available when modules starts. When modules complete, session data will be persisted to this file and the module will not log out from the Infinibox. If False, modules will not use persistent sessions.
* psdev-1341: Add API pagination support to metadata search (GET).

-------------------
v1.4.6 (2024-04-26)
-------------------

^^^^^^^^^^^^^^^^^^^^
Project Enhancements
^^^^^^^^^^^^^^^^^^^^
* Add test_create_resources_demo and test_remove_resources_demo playbooks.

-------------------
v1.4.5 (2024-04-11)
-------------------

^^^^^^^^^^^^^^^^^^^^
Project Enhancements
^^^^^^^^^^^^^^^^^^^^
* Update CHANGELOG.

-------------------
v1.4.4 (2024-04-09)
-------------------

^^^^^^^^^^^^^^^^^^^^
Feature Enhancements
^^^^^^^^^^^^^^^^^^^^
* psdev-1178: Add infini_infinimetrics module. Allows adding an Infinibox to Infinimetrics.
* psdev-1108: Extend configure_array example playbook to further demonstrate extensive customization of an Infinibox using Ansible.
* psdev-1222: Add pool threshold alarm setting support to infini_pool.

^^^^^^^^^
Bug Fixes
^^^^^^^^^
* psdev-1221: Fix infini_notification_rule. Find the correct target ID when using a recipient. The ID cannot be assumed to be 3.

^^^^^^^^^^^^^^^^^^^^
Project Enhancements
^^^^^^^^^^^^^^^^^^^^
* psdev-1188: Refactor CICD to use Infinibox 2503.

-------------------
v1.4.3 (2024-02-13)
-------------------

^^^^^^^^^^^^^^^^^^^^
Project Enhancements
^^^^^^^^^^^^^^^^^^^^
* psdev-1150: Update galaxy.yml for publication on Automation Hub.

-------------------
v1.4.2 (2024-02-12)
-------------------

^^^^^^^^^^^^^^^^^^^^
Project Enhancements
^^^^^^^^^^^^^^^^^^^^
* psdev-1150: Update galaxy.yml for publication on Automation Hub.

-------------------
v1.4.1 (2024-02-06)
-------------------

^^^^^^^^^^^^^^^^^^^^
Feature Enhancements
^^^^^^^^^^^^^^^^^^^^
* Require Ansible >= 2.14.0

-------------------
v1.4.0 (2024-02-05)
-------------------

^^^^^^^^^
Bug Fixes
^^^^^^^^^
* The default for the write_protected parameter when creating a master volume or master file system has changed from true to false. For snapshots, the default is true.
* psdev-1147: Fix an issue network space module where when removing a space the management interface was not removed last. This is required.

^^^^^^^^^^^^^^^^^^^^
Feature Enhancements
^^^^^^^^^^^^^^^^^^^^
* psdev-1138: Add infini_sso module. Allow SSO configuration.
* psdev-1151: Add infini_fibre_channel_switch module. Allow renaming of FC switches.
* psdev-1148: Add infini_certificate module. Allow uploading SSL certificates.
* psdev-1045: Add infini_event module. Allow posting of custom events.
* Add infini_config module.
* Add infini_notification_rule module.
* Add infini_notification_target module.
* psdev-1108: Provide configure_array.yml playbook. This is an example playbook demonstrating detailed configuration of Infiniboxes. It is idempotent so may be run against new or existing Infiniboxes repeatedly.
* psdev-1147: Implement network space module present state to handle updating parameters in an existing network space. Add support for is_async option.
* psdev-1108: Add state "login" to infini_user module. This tests credentials. Added to support Active Directory testing.
* Add syslog_server script to allow testing of syslog notifications.
* Add new infini_users_repository module. Use this module to configure Active Directory and LDAP resournces on an Infinibox.
* Add new infini_metadata module. This module will set, get and remove metadata (keys and values) to and from objects of these types: ["cluster", "fs", "fs-snap", "host", "pool", "system", "vol", "vol-snap"].
* Add snapshot support to the infini_fs module. File system snapshot locks, regular and immutable are supported.

-------------------
v1.3.12 (2022-12-04)
-------------------

^^^^^^^^^
Bug Fixes
^^^^^^^^^
* Fix infini_vol's write_protected field handling.

-------------------
v1.3.11 (2022-12-03)
-------------------

^^^^^^^^^^^^^^^^^^^^
Feature Enhancements
^^^^^^^^^^^^^^^^^^^^
* Fix module sanity errors not flagged when run locally, but flagged when uploaded to the automation hub for certification.

--------------------
v1.3.10 (2022-12-03)
--------------------

^^^^^^^^^^^^^^^^^^^^
Feature Enhancements
^^^^^^^^^^^^^^^^^^^^
* Add documentation for the delta-time filter. The delta-time filter is used in test_create_resources.yml playbook.

-------------------
v1.3.9 (2022-12-02)
-------------------

^^^^^^^^^^^^^^^^^^^^
Feature Enhancements
^^^^^^^^^^^^^^^^^^^^
* Fix module sanity errors not flagged when run locally, but flagged when uploaded to the automation hub for certification.

-------------------
v1.3.8 (2022-12-01)
-------------------

^^^^^^^^^^^^^^^^^^^^
Feature Enhancements
^^^^^^^^^^^^^^^^^^^^
* Support thin and thick provisioning in infini_fs.
* Refactor module imports.
* In the test_create_resources.yml and test_remove_resources.yml example playbooks, run rescan-scsi-bus.sh on host.

^^^^^^^^^
Bug Fixes
^^^^^^^^^
* Fix infini_vol stat state. Return the provisioning type (thin or thick) properly.

-------------------
v1.3.7 (2022-10-03)
-------------------

^^^^^^^^^^^^^^^^^^^^
Project Enhancements
^^^^^^^^^^^^^^^^^^^^
* Execute and pass `Ansible Sanity Tests <https://docs.ansible.com/ansible/devel/dev_guide/developing_collections_testing.html#testing-tools>`_. This is in preparation for Ansible Automation Hub (AAH) certification.
* No longer pin module versions in requirements.txt. Record module versions used while testing within CICD using pip freeze.

^^^^^^^^^^^^^^^^^^^^
Feature Enhancements
^^^^^^^^^^^^^^^^^^^^
* Add volume restore to infini_vol.

^^^^^^^^^^^
New Modules
^^^^^^^^^^^
* infini_cluster: Create, delete and modify host clusters on an Infinibox.
* infini_network_space: Create, delete and modify network spaces on an Infinibox.

^^^^^^^^^^^^^
New Playbooks
^^^^^^^^^^^^^
* infinisafe_demo_runtest.yml
* infinisafe_demo_setup.yml
* infinisafe_demo_teardown.yml

^^^^^^^^^
Bug Fixes
^^^^^^^^^
* Fix collection path to module_utils when importing utility modules.
