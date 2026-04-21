===================================
IBM Qradar Collection Release Notes
===================================

.. contents:: Topics

v4.0.0
======

Release Summary
---------------

With this release, the minimum required version of `ansible-core` for this collection is `2.15.0`. The last version known to be compatible with `ansible-core` versions below `2.15` is v3.0.0.

Major Changes
-------------

- Bumping `requires_ansible` to `>=2.15.0`, since previous ansible-core versions are EoL now.

v3.0.0
======

Release Summary
---------------

Starting from this release, the minimum `ansible-core` version this collection requires is `2.14.0`. The last known version compatible with ansible-core<2.14 is `v2.1.0`.

Major Changes
-------------

- Bumping `requires_ansible` to `>=2.14.0`, since previous ansible-core versions are EoL now.

Bugfixes
--------

- A bunch of ansible-lint and ansible-test sanity issues have been fixed.

v2.1.0
======

Minor Changes
-------------

- Add Qradar Analytics rules resource module.
- Add Qradar Log Sources Management resource module.

New Modules
-----------

- qradar_analytics_rules - Qradar Analytics Rules Management resource module
- qradar_log_sources_management - Qradar Log Sources Management resource module

v2.0.0
======

Major Changes
-------------

- Minimum required ansible.netcommon version is 2.5.1.
- Updated base plugin references to ansible.netcommon.

v1.0.3
======

Release Summary
---------------

Re-releasing 1.0.2 with updated galaxy file.

v1.0.2
======

Release Summary
---------------

Releasing 1.0.2 with updated changelog.

v1.0.1
======

Release Summary
---------------

Removed tech preview from collection Readme file.

v1.0.0
======

New Modules
-----------

- ibm.qradar.deploy - Trigger a qradar configuration deployment
- ibm.qradar.log_source_management - Manage Log Sources in QRadar
- ibm.qradar.offense_action - Take action on a QRadar Offense
- ibm.qradar.offense_info - Obtain information about one or many QRadar Offenses, with filter options
- ibm.qradar.offense_note - Create or update a QRadar Offense Note
- ibm.qradar.rule - Manage state of QRadar Rules, with filter options
- ibm.qradar.rule_info - Obtain information about one or many QRadar Rules, with filter options
