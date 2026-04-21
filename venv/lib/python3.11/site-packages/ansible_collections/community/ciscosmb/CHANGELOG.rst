=====================================
CiscoSMB Ansible module Release Notes
=====================================

.. contents:: Topics

v1.0.11
=======

Release Summary
---------------

Release Date: 2025-07-14

Minor Changes
-------------

- Update modules to conform core 2.19 and templating changes
- solves

v1.0.10
=======

Release Summary
---------------

Release Date: 2024-12-10
Add compatibility with Cisco Catalyst C1300 by solving issue #79 thanx to @alexandrud .

Minor Changes
-------------

- added Catalyst 1300 to supported platforms
- parsing neighbour table allowes empty 4th column to allow Cisco Catalyst 1300 support

v1.0.9
======

Release Summary
---------------

Primarily revert release. Previous release (1.0.8) fixed typo in attribute name, but it was breaking change.
This release brought the typo back (bandwith) and just added the new attribute with correct name "bandwidth" as a copy of the mistypped attribute.

Attribude "bandwith" will be removed in next minor release.

Minor Changes
-------------

- added additional attribute - add interface 'bandwidth' attribute
- reverted attribute change - keep interface 'bandwith' attribute

Bugfixes
--------

- typo in changelog fragment template
- typo in test script

v1.0.8
======

Release Summary
---------------

Release Date: 2024-04-09

  Minor bugfixes, updated CI

Minor Changes
-------------

- docs - addeed info about SG-250 support and testing

Breaking Changes / Porting Guide
--------------------------------

- in facts of interface 'bandwith' changed to 'bandwidth'

Bugfixes
--------

- issue
- solved issue

v1.0.7
======

Release Summary
---------------

Release Date: 2023-10-30
Fix issue on CSB-350 #69
Clarify configuration doc #66 #64

Bugfixes
--------

- added Cisco device config guide to address issue
- added extra "\n" to sending commands to address issue

v1.0.6
======

Release Summary
---------------

Code cleaning, better documentation   

Minor Changes
-------------

- added Ansible playbook examples ``cismosmb_inventory_template.yml``, ``cismosmb_gather_facts.yml``, ``cismosmb_commands.yml``
- no longer testing for ansible 2.9 and for Python 2.6 / 2.7
- removed unused portion of code in cliconf/ciscosmb.yml
- test Ansible 2.14

Deprecated Features
-------------------

- support for Python 2.6 nad 2.7
- support for ansible 2.9

Removed Features (previously deprecated)
----------------------------------------

- remove testing for Python 2.6 nad 2.7
- remove testing for ansible 2.9

v1.0.5
======

Minor Changes
-------------

- CI  change <plugin_type> <name> to name <name> for validate-module
- CI - add ansible 2.13 to test matrix

v1.0.4
======

Release Summary
---------------

Release Date: 2021-09-13

Bugfixes
--------

- Module command does not support check_mode - https://github.com/ansible-collections/community.ciscosmb/pull/45

v1.0.3
======

Release Summary
---------------

Release Date: 2019-10-31
Minor changes in documentation, adding Python 3.6 as a supported version

Minor Changes
-------------

- Add Py 3.6 to supported python versions (https://github.com/ansible-collections/community.ciscosmb/pull/44)
- Fix link to issue tracker in galaxy.yml (https://github.com/ansible-collections/community.ciscosmb/pull/42)
- Misc doc fixes for collection inclusion (https://github.com/ansible-collections/community.ciscosmb/pull/41)

v1.0.2
======

Release Summary
---------------

Release Date: 2021-08-09 bugfix release

Minor Changes
-------------

- remove unnecersary parameters on function re.sub()

Bugfixes
--------

- solves issue

v1.0.1
======

Release Summary
---------------

Minor fixes for ansible collections inclusion

Minor Changes
-------------

- Added Releasing, CoC and Contributing to README.md
- Added author
- Added license header
- Release policy, versioning, deprecation
- Updated CoC, added email address
- more descriptiove Release section on README.md

v1.0.0
======

Major Changes
-------------

- transform collection qaxi.ciscosmb to community.ciscosmb
- transform community.ciscosmb.ciscosmb_command to community.ciscosmb.command
- transform community.ciscosmb.ciscosmb_facts to community.ciscosmb.facts

Minor Changes
-------------

- setup standard Ansible CI

v0.9.1
======

Minor Changes
-------------

- correct version bumping

v0.9.0
======

Major Changes
-------------

- interface name canonicalization

v0.8.0
======

Major Changes
-------------

- add antsibull-changelog support

Minor Changes
-------------

- Python 2.6, 2.7, 3.5 compatibility
- add Code of conduct
- add Contribution
- add required files for community inclusion
- added ansible dev-guide manual test
- better tests requirements
- check tags and add tag switch
- cluter removed
- code cleaning
- update my tests

v0.1.1
======

Major Changes
-------------

- Python 2.6, 2.7, 3.5 is required
- add antsibull-changelog support

Minor Changes
-------------

- add Code of conduct
- add Contribution
- add required files for community inclusion
- check tags and add tag switch
- cluter removed
- code cleaning

v0.1.0
======

Major Changes
-------------

- added facts subset "interfaces"

Minor Changes
-------------

- remove mock warning

v0.0.6
======

Major Changes
-------------

- add CBS350 support
- unit tests for CBS350

Minor Changes
-------------

- doc update

v0.0.5
======

Major Changes
-------------

- add ciscosmb_command

v0.0.4
======

Minor Changes
-------------

- uptime in seconds

v0.0.2
======

Major Changes
-------------

- ciscosmb_facts with default subset and unit tests
