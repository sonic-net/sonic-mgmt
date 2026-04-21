==============================
Fortinet.Fortios Release Notes
==============================

.. contents:: Topics

v2.4.2
======

Release Summary
---------------

patch release of 2.4.2

Major Changes
-------------

- Supported default_group feature for the all of the modules.

Bugfixes
-------------

- Fixed authentication issue in v7.6.4 when using access_token.

v2.4.1
======

Release Summary
---------------

patch release of 2.4.1

Major Changes
-------------

- Supported new versions 7.6.3 and 7.6.4.
- Supported the authentication method when using username and password in v7.6.4.

Bugfixes
--------

- Fix the issue in check_modu when backend returns invallid IP address.
- Fix the issue in configuration_fact and monitor_fact when omitting vdom or assigning vdom to "".

v2.4.0
======

Release Summary
---------------

minor release of 2.4.0

Major Changes
-------------

- Supported new versions 7.6.1 and 7.6.2.
- Updated the examples with correct values that have minimum or maximum values.

Bugfixes
--------

- Github Issue
- Github Issue
- Github Issue
- Github Issue
- Github Issue
- Github Issue
- Github Issue
- Mantis Issue

v2.3.9
======

Release Summary
---------------

patch release of 2.3.9

Major Changes
-------------

- Support check_mode on all the configuration modules.

Bugfixes
--------

- Fix errors in Ansible sanity test with Ansible-core 2.18
- Github
- Github
- Github
- Github

v2.3.8
======

Release Summary
---------------

patch release of 2.3.8

Major Changes
-------------

- Improve the logic for SET function to send GET request first then PUT or POST
- Mantis
- Remove Tokens from URLs for Improved Security
- Support new FOS versions 7.6.0.

Bugfixes
--------

- Fix the issue using diff feature in check_mode.
- Github
- Github
- Github
- Mantis
- Mantis
- Mantis
- Mantis
- Mantis
- Mantis
- Mantis
- Return invalid json content instead of error while adding redundant comma at the end of the last variable in `fortios_json_generic`.

v2.3.7
======

Release Summary
---------------

patch release of 2.3.7

Major Changes
-------------

- Add a sanity_test.yaml file to trigger CI tests in GitHub.
- Support Ansible-core 2.17.
- Support new FOS versions 7.4.4.

Bugfixes
--------

- Fix some issues in sanity test.
- Github issue
- Github issue
- Github issue
- Github issue
- Github issue
- Github issue
- Github issue
- Github issue
- mantis issue
- mantis issue
- mantis issue

v2.3.6
======

Release Summary
---------------

patch release of 2.3.6

Major Changes
-------------

- Add notes for backup modules in the documentation in both monitor and monitor_fact modules.
- Supported new FOS versions 7.4.2 and 7.4.3, and support data type mac_address in the collection.
- Update the documentation for the supported versions from latest to a fix version number.
- Update the required ansible version to 2.15.

Bugfixes
--------

- Fix the issue that ssl-certificate cannot be set in `fortios_firewall_vip` and `fortios_firewall_vip6`.
- Github issue
- Github issue
- Github issue
- Github issue
- Github issue
- Github issue
- mantis issue

v2.3.5
======

Release Summary
---------------

patch release of 2.3.5

Major Changes
-------------

- Update all the boolean values to true/false in the documents and examples.
- Update the document of log_fact.
- Update the mismatched version message with version ranges.
- Update the required ansible version to 2.14.
- Update the supported version ranges instead of concrete version numbers to reduce the collection size.

Bugfixes
--------

- Github issue
- Github issue
- Github issue

v2.3.4
======

Release Summary
---------------

patch release of 2.3.4

Major Changes
-------------

- Format the contents in the changelog.yml file.
- update the required Ansible version to 2.14.0 in the runtime.yml file.

v2.3.3
======

Release Summary
---------------

patch release of 2.3.3

Major Changes
-------------

- Add new fortios version 7.4.1.
- Update Ansible version from 2.9 to 2.14.
- Update Q&A with a resolution for Ansible Always Sending GET/PUT Requests as POST Requests.
- Update the requirement.txt file to specify the sphinx_rtd_theme==1.3.0

Bugfixes
--------

- Fix the issue of one session remaining open after the task is finished.
- To optimize the json_generic module and reduce the time spent while sending GET requests.

v2.3.2
======

Release Summary
---------------

patch release of 2.3.2

Major Changes
-------------

- Improve the document for adding notes and examples in Q&A for modules using Integer number as the mkey.

Bugfixes
--------

- Fix the hyperlink issue for the supported FOS versions in USER's GUIDE.

v2.3.1
======

Release Summary
---------------

patch release of 2.3.1

Major Changes
-------------

- Add readthedocs.yaml file.
- Update Q&A regarding setting up FortiToken multi-factor authentication;

Bugfixes
--------

- Fix the issue while comparing the changes in before and after data in check_mode;
- Fix the issues that some parameters are not in a specific fos vm versions.
- Fix the request error when updating global object;
- Fix the sanity test error;
- Fix the wrong credential error when using username/password in fos verion 6;

v2.3.0
======

Release Summary
---------------

patch release of 2.3.0

Major Changes
-------------

- Improve the `no_log` feature in some modules;
- Improve the documentation and example for `seq_num` in `fortios_router_static`;
- Improve the documentation for `member_path` in all the modules;
- Support new FOS versions.

Bugfixes
--------

- Fix the error of pure number password.

v2.2.3
======

Release Summary
---------------

patch release of 2.2.3

Major Changes
-------------

- Add annotations of member operation for every module.
- Update ``fortios.py`` for higher performance;
- supports temporary session key and pre/post login banner;
- update the examples on how to use member operation in Q&A.

Bugfixes
--------

- Fix the issue that all the params with underscore cannot be set under member operation;
- Fix the login issue (#232);
- Fix the output path issue (#227);

v2.2.2
======

Release Summary
---------------

patch release of 2.2.2

Bugfixes
--------

- Add required field for module log_fact;
- Fix runtime issue (#214);
- Fix sanity test errors in validate-modules test;

v2.2.1
======

Release Summary
---------------

patch release of 2.2.1

Bugfixes
--------

- Fix invalid arguments in version_schemas;
- Fix list type arguments inconsistency;
- Fix supports_check_mode issue for _info and _facts modules;

v2.2.0
======

Release Summary
---------------

patch release of 2.2.0

Major Changes
-------------

- Support FortiOS v7.0.6, v7.0.7, v7.0.8, v7.2.1, v7.2.2.

Bugfixes
--------

- Fix issue of filter content could not contain spaces (#208);
- Fix issue of missing some options for monitor modules (#196);
- Fix list type not match issue;

v2.1.7
======

Release Summary
---------------

patch release of 2.1.7

Major Changes
-------------

- Support Diff feature in check_mode.
- Support Fortios 7.2.0.

Bugfixes
--------

- Fix the Github Issue 187.
- Fix the Github Issue 188 and 189.
- Fix the Github Issue 190.
- Fix the Github Issue 191.
- Fix the error message in the debugging log when using ``access_token``.
- Fix the issue when filtering out parameter with space in the module ``fortios_configuration_fact``.
- Fix typo in the documentation of ``Install FortiOS Galaxy Collection``.

v2.1.6
======

Release Summary
---------------

patch release of 2.1.6

Bugfixes
--------

- Add defaut value for enable_log param.
- Fix import issues in sanity-test and improve unit tests.
- Fix parameter-list-no-elements error in sanity-test.
- Fix syntax issue in python2.7.
- Fix the syntax error in the three wireless_controller_hotspot20 modules.
- Relicense the FortiOS Collection under GPLv3+.
- Update the logic in check_legacy_fortiosapi.
- Use collection version number in the doc.

v2.1.5
======

Release Summary
---------------

patch release of 2.1.5

Major Changes
-------------

- Support FortiOS 7.0.2, 7.0.3, 7.0.4, 7.0.5.

Bugfixes
--------

- Fix issues in version mismatch logic.
- Fix status issue in fortios_json_generic().
- Fix the issue of inconsistent data types in different schemas.

v2.1.4
======

v2.1.3
======

Release Summary
---------------

patch release of 2.1.3

Major Changes
-------------

- Add real-world use cases in the example section for some configuration modules.
- Collect the current configurations of the modules and convert them into playbooks.
- Support FortiOS 7.0.1.
- Support member operation (delete/add extra members) on an object that has a list of members in it.
- Support selectors feature in ``fortios_monitor_fact`` and ``fortios_log_fact``.

Bugfixes
--------

- Fix Github issue
- Fix the corner cases that response does not have status in it.
- Fix the filters error when fetching multiple facts with selectors for a configuration module (Github issue

v2.1.2
======

Release Summary
---------------

patch release of 2.1.2

Bugfixes
--------

- Fix a regression bug caused by non-required attributes.
- Fix an intentional exception for listed options.

v2.1.1
======

Release Summary
---------------

patch release of 2.1.1

Bugfixes
--------

- Fix the KeyError caused by non-required multi-value attributes in an object.

v2.1.0
======

Release Summary
---------------

minor release of 2.1.0

Major Changes
-------------

- New module fortios_monitor_fact.
- Support Fortios 7.0.
- Support Log APIs.

Bugfixes
--------

- Disable check_mode feature from all global objects of configuration modules due to 'state' issue.
- Fix a bug in IP_PREFIX.match().
- Fix the issue that the ``server_type`` is not updated in ``fortios_system_central_management``.
- Fix the unexpected warning caused by optinal params in ``fortios_monitor_fact`` and ``fortios_monitor``.

v2.0.2
======

Release Summary
---------------

patch release of 2.0.2

Major Changes
-------------

- Improve ``fortios_configuration_fact`` to use multiple selectors concurrently.
- Support ``check_mode`` in all cofigurationAPI-based modules.
- Support filtering for fact gathering modules ``fortios_configuration_fact`` and ``fortios_monitor_fact``.
- Support moving policy in ``firewall_central_snat_map``.
- Unify schemas for monitor API.

Bugfixes
--------

- Fix the authorization fails at log in with username and password in FOS7.0.
- Github Issue 103
- Github Issue 105

v2.0.1
======

Minor Changes
-------------

- fixed pylint testing errors.

v2.0.0
======

Release Summary
---------------

The major breaking release of FOS 2.x collections.

Major Changes
-------------

- New module fortios_configuration_fact
- New module fortios_json_generic
- New module fortios_monitor
- New module fortios_monitor_fact

Breaking Changes / Porting Guide
--------------------------------

- Generic FortiOS Module - FOS module to issue generic request with Ansible.
- Support for FOS Monitor API - several modules are new for monitor API.
- Unified Collection - The fortios collection itself will be adapting any FOS platforms.

Removed Features (previously deprecated)
----------------------------------------

- Removed module fortios_facts
- Removed module fortios_registration_forticare
- Removed module fortios_registration_vdom
- Removed module fortios_system_config_backup_restore
- Removed module fortios_system_vmlicense

Bugfixes
--------

- Deprecated second-layer state module parameter
- enable_log - Explicit logging option.

Known Issues
------------

- Modules for monitor API are not versioned yet.
