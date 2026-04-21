================================
Grafana Collection Release Notes
================================

.. contents:: Topics

v2.3.0
======

Minor Changes
-------------

- grafana_team - integrate parameter ``org_id``
- grafana_team - integrate parameter ``org_name``

Bugfixes
--------

- Fix parsing of grafana version for pre-releases and security releases
- grafana_dashboard - fix change detection for dashboards in folders

v2.2.0
======

Minor Changes
-------------

- Add argument `tls_servername` for `grafana_datasource`
- Support `alertmanager` as type for `grafana_datasource`
- grafana_dashboard - allow creating dashboards in subfolders

Bugfixes
--------

- Remove field `apiVersion` from return of current `grafana_datasource` for working diff
- grafana_dashboard - add uid to payload
- test: replace more deprecated `TestCase.assertEquals` to support Python 3.12

v2.1.0
======

Minor Changes
-------------

- Manage subfolders for `grafana_folder` and specify uid

Deprecated Features
-------------------

- Deprecate `grafana_notification_channel`. It will be removed in version 3.0.0

Bugfixes
--------

- Add missing function argument in `grafana_contact_point` for org handling
- Fix var prefixes in silence-task in role
- Fixed check if grafana_api_key is defined for `grafana_dashboard` lookup

v2.0.0
======

Minor Changes
-------------

- Add `grafana_contact_point` module
- Add support of `grafana_contact_point` in grafana role
- add org switch by `org_id` and `org_name` in `grafana_silence`

Removed Features (previously deprecated)
----------------------------------------

- removed check and handling of mangled api key in `grafana_dashboard` lookup
- removed deprecated `message` argument in `grafana_dashboard`

New Modules
-----------

- community.grafana.grafana_contact_point - Manage Grafana Contact Points

v1.9.1
======

Bugfixes
--------

- undo removed deprecated `message` argument in `grafana_dashboard`

v1.9.0
======

Minor Changes
-------------

- Add new module `grafana_silence` to create and delete silences through the API
- Add role components for `grafana_silence` module
- lookup - grafana_dashboards - add `validate_certs` and `ca_path` options to plugin for custom certs validation

Removed Features (previously deprecated)
----------------------------------------

- removed deprecated `message` argument in `grafana_dashboard`

Bugfixes
--------

- Handling of desired default state for first `grafana_datasource`
- Ignore `type` argument for diff comparison if `grafana-postgresq-datasource` alias `postgres` is used
- Set umask for `grafana_plugin` command

v1.8.0
======

Minor Changes
-------------

- Manage `grafana_folder` for organizations
- Merged ansible role telekom-mms/ansible-role-grafana into ansible-collections/community.grafana
- added `community.grafana.notification_channel` to role
- grafana_dashboard - add check_mode support

Bugfixes
--------

- test: replace deprecated `TestCase.assertEquals` to support Python 3.12

v1.7.0
======

Minor Changes
-------------

- Add Quickwit search engine datasource (https://quickwit.io).
- Add parameter `org_name` to `grafana_dashboard`
- Add parameter `org_name` to `grafana_datasource`
- Add parameter `org_name` to `grafana_organization_user`
- Add support for Grafana Tempo datasource type (https://grafana.com/docs/grafana/latest/datasources/tempo/)
- default to true/false in docs and code

Bugfixes
--------

- Add `grafana_organiazion_user` to `action_groups.grafana`
- Fixed orgId handling in diff comparison for `grafana_datasource` if using org_name

v1.6.1
======

Minor Changes
-------------

- Bump version of Python used in tests to 3.10
- Enable datasource option `time_interval` for prometheus
- Fix documentation url for Ansible doc website
- Now testing against Grafana 9.5.13, 8.5.27, 10.2.0

Bugfixes
--------

- Fix error with datasources configured without basicAuth
- grafana_folder, fix an issue during delete (starting Grafana 9.3)

v1.6.0
======

Minor Changes
-------------

- Add `grafana_organization_user` module

New Modules
-----------

- community.grafana.grafana_organization_user - Manage Grafana Organization Users.

v1.5.4
======

Minor Changes
-------------

- able to set `uid` for datasources in grafana via module grafana_datasource

Bugfixes
--------

- Fixed validate_certs missing parameter for --insecure option in grafana plugins
- URL encode issue in grafana_organization.py (method get_actual_org ) fixed.
- grafana_dashboard, now opens json files with utf-8 encoding (#191)

v1.5.3
======

Bugfixes
--------

- Add support for more elasticsearch version as datasource (#263)

v1.5.2
======

Bugfixes
--------

- Ensure user email/login is url encoded when searching for the user (#264)

v1.5.1
======

Minor Changes
-------------

- Export dashboard with pretty printed JSON so that it becomes easier to compare changes with the previous version (#257)

v1.5.0
======

Minor Changes
-------------

- community.grafana.grafana_datasource supports grafana-azure-monitor-datasource.

Bugfixes
--------

- Fix a bug that causes a fatal error when using `url` parameter in `grafana_dashboard` and `grafana_notification_channel` modules.
- Fix a bug that causes an update error when using the `grafana_datasource` module on Grafana >=9.0.0 (https://github.com/ansible-collections/community.grafana/issues/248).

v1.4.0
======

Minor Changes
-------------

- Remove requirement for `ds_type` and `ds_url` parameters when deleting a datasource
- add `grafana` action group in `meta/runtime.yml` to support for module group defaults
- refactor grafana_notification_channel module

v1.3.3
======

Bugfixes
--------

- Fix an issue with grafana_datasource for Prometheus with basic auth credential management. (#204)

v1.3.2
======

Bugfixes
--------

- Fix an issue with threema notification channel that was not creating gateway, recipient and api_secret in Grafana. (#208)

v1.3.1
======

Minor Changes
-------------

- community.grafana.grafana_datasource supports aws_auth_type of default.

v1.3.0
======

Bugfixes
--------

- Fix issue with datasource names that could not contain slashes (#125)

New Modules
-----------

- community.grafana.grafana_organization - Manage Grafana Organization

v1.2.3
======

Bugfixes
--------

- Fix issue with trailing '/' in provided grafana_url. The modules now support values with trailing slashes.

v1.2.2
======

Deprecated Features
-------------------

- grafana_dashboard lookup - Providing a mangled version of the API key is no longer preferred.

Bugfixes
--------

- Fix an issue with datasource uid now returned by the Grafana API (#176)
- grafana_dashboard lookup - All valid API keys can be used, not just keys ending in '=='.
- grafana_dashboard now explicitely fails if the folder doesn't exist upon creation. It would previously silently pass but not create the dashboard. (https://github.com/ansible-collections/community.grafana/issues/153)
- grafana_team now able to handle spaces and other utf-8 chars in the name parameter. (https://github.com/ansible-collections/community.grafana/issues/164)

v1.2.1
======

Bugfixes
--------

- Fix issue with grafana_user that failed to create admin user (#142)

v1.2.0
======

Major Changes
-------------

- introduce "skip_version_check" parameter in grafana_teams and grafana_folder modules (#147)

Bugfixes
--------

- Fix issue with url when grafana_url has a trailing slash (#135)
- grafana_dashboard, Fix reference before assignment issue (#146)

v1.1.0
======

Minor Changes
-------------

- Update the version where `message` alias will disappear from `grafana_dashboard`. (Now 2.0.0)

New Modules
-----------

- community.grafana.grafana_notification_channel - Manage Grafana Notification Channels

v1.0.0
======

Release Summary
---------------

Stable release for Ansible 2.10 and beyond

Major Changes
-------------

- Add changelog management for ansible 2.10 (#112)
- grafana_datasource ; adding additional_json_data param

Known Issues
------------

- grafana_datasource doesn't set password correctly (#113)

v0.2.2
======

Bugfixes
--------

- Fix an issue in `grafana_dashboard` that made dashboard import no more detecting changes and fail.
- Refactor module `grafana_datasource` to ease its support.

v0.2.1
======

Bugfixes
--------

- Fix an issue with `grafana_datasource` idempotency

v0.2.0
======

Minor Changes
-------------

- Add Thruk as Grafana Datasource
- Add `grafana_folder` module
- Add `grafana_user` module
- Use `module_utils` to allow code factorization

Bugfixes
--------

- Fix issue `#45` in `grafana_plugin`

v0.1.0
======

Release Summary
---------------

Initial migration of Grafana content from Ansible core (2.9/devel)
