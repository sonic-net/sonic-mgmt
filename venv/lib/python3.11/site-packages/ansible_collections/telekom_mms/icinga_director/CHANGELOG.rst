===========================================
telekom\_mms.icinga\_director Release Notes
===========================================

.. contents:: Topics

v2.5.0
======

Minor Changes
-------------

- Feat: add some parameters to the icinga service module (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/289)

Bugfixes
--------

- Fix diff in check mode by normalising the boolean values (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/295)
- Fix doc generation and remove need for iteritems (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/296)
- Fix: remove default for states parameter in icinga_dependency_apply (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/290)

v2.4.1
======

Bugfixes
--------

- Fix: remove default for states parameter in icinga_dependency_apply (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/290)

v2.3.1
======

Minor Changes
-------------

- Add zone option for icinga_user_group module (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/286)

v2.3.0
======

Minor Changes
-------------

- Add API timeout option for all modules (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/282)
- Add support for IcingaDB in inventory plugin (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/274)
- Icinga dependency modules implementation (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/272)

Bugfixes
--------

- Bug: dependency apply module raises error when using a variable for parent host or service (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/276)
- Extend checks in diff as a workaround for type confusion with the Director API (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/278)
- add 'groups' parameter to task 'icinga_user.yml' (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/284)

New Modules
-----------

- telekom_mms.icinga_director.icinga_dependency_apply - Manage dependency apply rules in Icinga2

v2.2.3
======

Minor Changes
-------------

- Icinga dependency modules implementation (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/272)

Bugfixes
--------

- Bug: dependency apply module raises error when using a variable for parent host or service (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/276)

v2.2.2
======

v2.2.1
======

Bugfixes
--------

- Add Icinga notification template imports (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/267)

v2.1.3
======

Minor Changes
-------------

- Add vars parameter to user_template and user modules (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/262)

v2.1.2
======

v2.1.1
======

Bugfixes
--------

- change notification interval variable to int-type (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/254)
- set user_groups in notification to empty list (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/255)

v2.1.0
======

Minor Changes
-------------

- Increase sleep to 5 seconds (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/245)

v2.0.5
======

v2.0.4
======

v2.0.3
======

v2.0.2
======

v2.0.1
======

Bugfixes
--------

- Fixes #190 - Workaround for service apply bug (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/239)

v1.35.0
=======

Minor Changes
-------------

- Extended docs and examples for multiple assign_filter conditions (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/227)

v1.34.2
=======

v1.34.1
=======

Bugfixes
--------

- add more http-options for inventory module (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/221)

v1.33.3
=======

Minor Changes
-------------

- add command_endpoint var for service templates (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/222)

v1.33.2
=======

v1.33.1
=======

Bugfixes
--------

- add icinga_deploy_* to action_group and test it (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/214)

v1.33.0
=======

Minor Changes
-------------

- Add Icinga Deploy handler and module (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/205)

New Modules
-----------

- telekom_mms.icinga_director.icinga_deploy - Trigger deployment in Icinga2
- telekom_mms.icinga_director.icinga_deploy_info - Get deployment information through the director API

v1.32.3
=======

v1.32.2
=======

v1.32.1
=======

v1.32.0
=======

Minor Changes
-------------

- Add zone to user and notification template (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/198)

v1.31.5
=======

v1.31.4
=======

v1.31.3
=======

v1.31.2
=======

v1.31.1
=======

v1.31.0
=======

Minor Changes
-------------

- Add flapping support to service template module (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/180)
- Add icon support to service template (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/179)

v1.30.2
=======

v1.30.1
=======

Bugfixes
--------

- Add exception handling to diff and exist functions (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/176)

v1.30.0
=======

Minor Changes
-------------

- Add action_group to enable module default groups (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/175)

v1.29.1
=======

v1.29.0
=======

Minor Changes
-------------

- Add icinga_serviceset module (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/163)
- Test more ansible versions (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/162)

New Modules
-----------

- telekom_mms.icinga_director.icinga_serviceset - Manage servicesets in Icinga2

v1.28.1
=======

Minor Changes
-------------

- Test more ansible versions (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/162)

v1.28.0
=======

Minor Changes
-------------

- Added missing fields to 'icinga_host' and 'icinga_host_template' (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/158)

Bugfixes
--------

- role: add check_command to icinga_service_apply (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/161)

v1.27.2
=======

v1.27.1
=======

v1.27.0
=======

Minor Changes
-------------

- Add possibility to use Compose and keyed groups in inventory-module (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/155)

v1.26.0
=======

Minor Changes
-------------

- add option to append arguments to all modules (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/153)

v1.25.1
=======

v1.25.0
=======

Minor Changes
-------------

- Add Icinga scheduled downtime module (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/146)

Bugfixes
--------

- added a fix for the new scheduled_downtime module (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/150)

v1.23.1
=======

Minor Changes
-------------

- add resolve option to inventory-plugin (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/147)

v1.23.0
=======

v1.22.1
=======

v1.22.0
=======

Minor Changes
-------------

- Add support for retry_interval and max_check_attempts to host template (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/140)

v1.21.2
=======

v1.21.1
=======

Bugfixes
--------

- Changed place in the creation order of service object in ansible_icinga role (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/135)

v1.21.0
=======

Minor Changes
-------------

- Add event_command parameter to icinga_service_apply module (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/132)
- Add event_command parameter to service apply playbook to enable usage (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/133)

v1.20.1
=======

v1.20.0
=======

Minor Changes
-------------

- Add some more documentation on command template (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/128)
- add "vars" variable to icinga_notification in the role (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/129)

v1.19.0
=======

Minor Changes
-------------

- add notification_template to role (https://github.com/telekom-mms/ansible-collection-icinga-director/pull/125)

v1.18.1
=======

