============================
Community SOPS Release Notes
============================

.. contents:: Topics

v2.2.7
======

Release Summary
---------------

Maintenance release.

Known Issues
------------

- When using the ``community.sops.load_vars`` with ansible-core 2.20, note that the deprecation of ``INJECT_FACTS_AS_VARS`` causes deprecation warnings to be shown every time a variable loaded with ``community.sops.load_vars`` is used. This is due to ansible-core deprecating ``INJECT_FACTS_AS_VARS`` without providing an alternative for modules like ``community.sops.load_vars`` to use. If you do not like these deprecation warnings, you have to explicitly set ``INJECT_FACTS_AS_VARS`` to ``true``. **DO NOT** change the use of SOPS encrypted variables to ``ansible_facts``. The situation will hopefully improve in ansible-core 2.21 through the promised API that allows action plugins to set variables; community.sops will adapt to use it, which will make the warning go away. (The API was originally promised for ansible-core 2.20, but then delayed.)

v2.2.6
======

Release Summary
---------------

Bugfix and maintenance release.

Bugfixes
--------

- Clean up plugin code that does not run on the target (https://github.com/ansible-collections/community.sops/pull/275).
- Note that the MIT licenced code in ``plugins/module_utils/_six.py`` has been removed (https://github.com/ansible-collections/community.sops/pull/275).
- sops vars plugin - ensure that loaded vars are evaluated also with ansible-core 2.19+ (https://github.com/ansible-collections/community.sops/pull/273).

v2.2.5
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- load_vars action - avoid another deprecated module utils from ansible-core (https://github.com/ansible-collections/community.sops/pull/270).
- load_vars action - avoid deprecated import from ansible-core that will be removed in ansible-core 2.21 (https://github.com/ansible-collections/community.sops/pull/272).

v2.2.4
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- Fix accidental type extensions (https://github.com/ansible-collections/community.sops/pull/269).

v2.2.3
======

Release Summary
---------------

Maintenance release.

Minor Changes
-------------

- Note that some new code in ``plugins/module_utils/_six.py`` is MIT licensed (https://github.com/ansible-collections/community.sops/pull/268).

Bugfixes
--------

- Avoid using ``ansible.module_utils.six`` to avoid deprecation warnings with ansible-core 2.20 (https://github.com/ansible-collections/community.sops/pull/268).

v2.2.2
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- Avoid deprecated functionality in ansible-core 2.20 (https://github.com/ansible-collections/community.sops/pull/260).
- all modules and plugins - the default of ``enable_local_keyservice`` changed from ``false`` to ``true``, and explicitly setting it to ``false`` now passes ``--enable-local-keyservice=false``. SOPS' default has always been ``true``, and when setting this option to ``true`` so far it resulted in passing ``--enable-local-keyservice``, which is equivalent to ``--enable-local-keyservice=true`` and had no effect. This means that from now on, setting ``enable_local_keyservice`` explicitly to ``false`` has an effect. If ``enable_local_keyservice`` was not set before, or was set to ``true``, nothing will change (https://github.com/ansible-collections/community.sops/issues/261, https://github.com/ansible-collections/community.sops/pull/262).

v2.2.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- install role - avoid deprecated parameter value for the ``ansible.builtin.uri`` module (https://github.com/ansible-collections/community.sops/pull/255).

v2.2.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- load_vars - expressions can now be lazily evaluated when using ansible-core 2.19 or newer (https://github.com/ansible-collections/community.sops/pull/229).

v2.1.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- Now supports specifying SSH private keys for age with the new ``age_ssh_private_keyfile`` option (https://github.com/ansible-collections/community.sops/pull/241).

v2.0.5
======

Release Summary
---------------

Maintenance release with updated SOPS version test coverage.

v2.0.4
======

Release Summary
---------------

Maintenance release with Data Tagging support.

Bugfixes
--------

- load_vars - make evaluation compatible with Data Tagging in upcoming ansible-core release (https://github.com/ansible-collections/community.sops/pull/225).

v2.0.3
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- install role - ``sops_install_on_localhost=false`` was not working properly if the role was running on more than one host due to a bug in ansible-core (https://github.com/ansible-collections/community.sops/issues/223, https://github.com/ansible-collections/community.sops/pull/224).

v2.0.2
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- install role - when used with Debian on ARM architecture, the architecture name is now correctly translated from ``aarch64`` to ``arm64`` (https://github.com/ansible-collections/community.sops/issues/220, https://github.com/ansible-collections/community.sops/pull/221).

v2.0.1
======

Release Summary
---------------

Maintenance release with updated documentation.

v2.0.0
======

Release Summary
---------------

Major verison that drops support for End of Life Ansible/ansible-base/ansible-core versions.

Removed Features (previously deprecated)
----------------------------------------

- The collection no longer supports Ansible 2.9, ansible-base 2.10, ansible-core 2.11, ansible-core 2.12, ansible-core 2.13, and ansible-core 2.14. If you need to continue using End of Life versions of Ansible/ansible-base/ansible-core, please use community.sops 1.x.y (https://github.com/ansible-collections/community.sops/pull/206).

v1.9.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- sops_encrypt - pass absolute paths to ``module.atomic_move()`` (https://github.com/ansible/ansible/issues/83950, https://github.com/ansible-collections/community.sops/pull/208).

v1.9.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- decrypt filter plugin - now supports the input and output type ``ini`` (https://github.com/ansible-collections/community.sops/pull/204).
- sops lookup plugin - new option ``extract`` allows extracting a single key out of a JSON or YAML file, equivalent to sops' ``decrypt --extract`` (https://github.com/ansible-collections/community.sops/pull/200).
- sops lookup plugin - now supports the input and output type ``ini`` (https://github.com/ansible-collections/community.sops/pull/204).

v1.8.2
======

Release Summary
---------------

Maintenance release with updated documentation and changelog.

Deprecated Features
-------------------

- The collection deprecates support for all Ansible/ansible-base/ansible-core versions that are currently End of Life, `according to the ansible-core support matrix <https://docs.ansible.com/ansible-core/devel/reference_appendices/release_and_maintenance.html#ansible-core-support-matrix>`__. This means that the next major release of the collection will no longer support Ansible 2.9, ansible-base 2.10, ansible-core 2.11, ansible-core 2.12, ansible-core 2.13, and ansible-core 2.14.

v1.8.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- Pass ``config_path`` on SOPS 3.9.0 before the subcommand instead of after it (https://github.com/ansible-collections/community.sops/issues/195, https://github.com/ansible-collections/community.sops/pull/197).

v1.8.0
======

Release Summary
---------------

Feature release for supporting improvements coming with SOPS 3.9.0.

Minor Changes
-------------

- Detect SOPS 3.9.0 and use new ``decrypt`` and ``encrypt`` subcommands (https://github.com/ansible-collections/community.sops/pull/190).
- sops vars plugin - new option ``handle_unencrypted_files`` allows to control behavior when encountering unencrypted files with SOPS 3.9.0+ (https://github.com/ansible-collections/community.sops/pull/190).

Bugfixes
--------

- sops_encrypt - properly support ``path_regex`` in ``.sops.yaml`` when SOPS 3.9.0 or later is used (https://github.com/ansible-collections/community.sops/issues/153, https://github.com/ansible-collections/community.sops/pull/190).

v1.7.0
======

Release Summary
---------------

Bugfix and feature release to fix installation issues with SOPS 3.9.0.

Minor Changes
-------------

- sops vars plugin - allow to configure the valid extensions with an ``ansible.cfg`` entry or with an environment variable (https://github.com/ansible-collections/community.sops/pull/185).

Bugfixes
--------

- Fix RPM URL for the 3.9.0 release (https://github.com/ansible-collections/community.sops/pull/188).

v1.6.7
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- sops_encrypt - ensure that output-type is set to ``yaml`` when the file extension ``.yml`` is used. Now both ``.yaml`` and ``.yml`` files use the SOPS ``--output-type=yaml`` formatting (https://github.com/ansible-collections/community.sops/issues/164).

v1.6.6
======

Release Summary
---------------

Make fully compatible with and test against sops 3.8.0.

Bugfixes
--------

- Fix RPM URL for the 3.8.0 release (https://github.com/ansible-collections/community.sops/pull/161).

v1.6.5
======

Release Summary
---------------

Make compatible with and test against sops 3.8.0-rc.1.

Bugfixes
--------

- Avoid pre-releases when picking the latest version when using the GitHub API method (https://github.com/ansible-collections/community.sops/pull/159).
- Fix changed DEB and RPM URLs for 3.8.0 and its prerelease(s) (https://github.com/ansible-collections/community.sops/pull/159).

v1.6.4
======

Release Summary
---------------

Maintenance/bugfix release for the move of sops to the new `getsops GitHub organization <https://github.com/getsops>`__.

Bugfixes
--------

- install role - fix ``sops_github_latest_detection=latest-release``, which broke due to sops moving to another GitHub organization (https://github.com/ansible-collections/community.sops/pull/151).

v1.6.3
======

Release Summary
---------------

Maintenance release with updated documentation.

From this version on, community.sops is using the new `Ansible semantic markup
<https://docs.ansible.com/ansible/devel/dev_guide/developing_modules_documenting.html#semantic-markup-within-module-documentation>`__
in its documentation. If you look at documentation with the ansible-doc CLI tool
from ansible-core before 2.15, please note that it does not render the markup
correctly. You should be still able to read it in most cases, but you need
ansible-core 2.15 or later to see it as it is intended. Alternatively you can
look at `the devel docsite <https://docs.ansible.com/ansible/devel/collections/community/sops/>`__
for the rendered HTML version of the documentation of the latest release.

Known Issues
------------

- Ansible markup will show up in raw form on ansible-doc text output for ansible-core before 2.15. If you have trouble deciphering the documentation markup, please upgrade to ansible-core 2.15 (or newer), or read the HTML documentation on https://docs.ansible.com/ansible/devel/collections/community/sops/.

v1.6.2
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- install role - make sure that the ``pkg_mgr`` fact is definitely available when installing on ``localhost``. This can improve error messages in some cases (https://github.com/ansible-collections/community.sops/issues/145, https://github.com/ansible-collections/community.sops/pull/146).

v1.6.1
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- action plugin helper - fix handling of deprecations for ansible-core 2.14.2 (https://github.com/ansible-collections/community.sops/pull/136).
- various plugins - remove unnecessary imports (https://github.com/ansible-collections/community.sops/pull/133).

v1.6.0
======

Release Summary
---------------

Feature release improving the installation role.

Minor Changes
-------------

- install role - add ``sops_github_latest_detection`` option that allows to configure which method to use for detecting the latest release on GitHub. By default (``auto``) first tries to retrieve a list of recent releases using the API, and if that fails due to rate limiting, tries to obtain the latest GitHub release from a semi-documented URL (https://github.com/ansible-collections/community.sops/pull/133).
- install role - add ``sops_github_token`` option to allow passing a GitHub token. This can for example be used to avoid rate limits when using the role in GitHub Actions (https://github.com/ansible-collections/community.sops/pull/132).
- install role - implement another method to determine the latest release on GitHub than using the GitHub API, which can make installation fail due to rate-limiting (https://github.com/ansible-collections/community.sops/pull/131).

v1.5.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- Automatically install GNU Privacy Guard (GPG) in execution environments. To install Mozilla sops a manual step needs to be added to the EE definition, see the collection's documentation for details (https://github.com/ansible-collections/community.sops/pull/98).

New Playbooks
-------------

- community.sops.install - Installs sops and GNU Privacy Guard on all remote hosts
- community.sops.install_localhost - Installs sops and GNU Privacy Guard on localhost

New Roles
---------

- community.sops.install - Install Mozilla sops

v1.4.1
======

Release Summary
---------------

Maintenance release to improve compatibility with future ansible-core releases.

Bugfixes
--------

- load_vars - ensure compatibility with newer versions of ansible-core (https://github.com/ansible-collections/community.sops/pull/121).

v1.4.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- Allow to specify age keys as ``age_key``, or age keyfiles as ``age_keyfile`` (https://github.com/ansible-collections/community.sops/issues/116, https://github.com/ansible-collections/community.sops/pull/117).
- sops_encrypt - allow to specify age recipients (https://github.com/ansible-collections/community.sops/issues/116, https://github.com/ansible-collections/community.sops/pull/117).

v1.3.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- All software licenses are now in the ``LICENSES/`` directory of the collection root, and the collection repository conforms to the `REUSE specification <https://reuse.software/spec/>`__ except for the changelog fragments (https://github.com/ansible-collections/community.crypto/sops/108, https://github.com/ansible-collections/community.sops/pull/113).
- sops vars plugin - added a configuration option to temporarily disable the vars plugin (https://github.com/ansible-collections/community.sops/pull/114).

v1.2.3
======

Release Summary
---------------

Fix formatting bug in documentation. No code changes.

v1.2.2
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- Include ``simplified_bsd.txt`` license file for the ``sops`` module utils.

v1.2.1
======

Release Summary
---------------

Maintenance release with updated documentation.

v1.2.0
======

Release Summary
---------------

Collection release for inclusion in Ansible 4.9.0 and 5.1.0.

This release contains a change allowing to configure generic plugin options with ansible.cfg keys and env variables.

Minor Changes
-------------

- sops lookup and vars plugin - allow to configure almost all generic options by ansible.cfg entries and environment variables (https://github.com/ansible-collections/community.sops/pull/81).

Bugfixes
--------

- Fix error handling in calls of the ``sops`` binary when negative errors are returned (https://github.com/ansible-collections/community.sops/issues/82, https://github.com/ansible-collections/community.sops/pull/83).

v1.1.0
======

Release Summary
---------------

A minor release for inclusion in Ansible 4.2.0.

Minor Changes
-------------

- Avoid internal ansible-core module_utils in favor of equivalent public API available since at least Ansible 2.9 (https://github.com/ansible-collections/community.sops/pull/73).

New Plugins
-----------

Filter
~~~~~~

- community.sops.decrypt - Decrypt sops-encrypted data

v1.0.6
======

Release Summary
---------------

This release makes the collection compatible to the latest beta release of ansible-core 2.11.

Bugfixes
--------

- action_module plugin helper - make compatible with latest changes in ansible-core 2.11.0b3 (https://github.com/ansible-collections/community.sops/pull/58).
- community.sops.load_vars - make compatible with latest changes in ansible-core 2.11.0b3 (https://github.com/ansible-collections/community.sops/pull/58).

v1.0.5
======

Release Summary
---------------

This release fixes a bug that prevented correct YAML file to be created when the output was ending in ``.yaml``.

Bugfixes
--------

- community.sops.sops_encrypt - use output type ``yaml`` when path ends with ``.yaml`` (https://github.com/ansible-collections/community.sops/pull/56).

v1.0.4
======

Release Summary
---------------

This is a security release, fixing a potential information leak in the ``community.sops.sops_encrypt`` module.

Security Fixes
--------------

- community.sops.sops_encrypt - mark the ``aws_secret_access_key`` and ``aws_session_token`` parameters as ``no_log`` to avoid leakage of secrets (https://github.com/ansible-collections/community.sops/pull/54).

v1.0.3
======

Release Summary
---------------

This release include some fixes to Ansible docs and required changes for inclusion in Ansible.

Bugfixes
--------

- community.sops.sops lookup plugins - fix wrong format of Ansible variables so that these are actually used (https://github.com/ansible-collections/community.sops/pull/51).
- community.sops.sops vars plugins - remove non-working Ansible variables (https://github.com/ansible-collections/community.sops/pull/51).

v1.0.2
======

Release Summary
---------------

Fix of 1.0.1 release which had no changelog entry.

v1.0.1
======

Release Summary
---------------

Re-release of 1.0.0 to counteract error during release.

v1.0.0
======

Release Summary
---------------

First stable release. This release is expected to be included in Ansible 3.0.0.

Minor Changes
-------------

- All plugins and modules: allow to pass generic sops options with new options ``config_path``, ``enable_local_keyservice``, ``keyservice``. Also allow to pass AWS parameters with options ``aws_profile``, ``aws_access_key_id``, ``aws_secret_access_key``, and ``aws_session_token`` (https://github.com/ansible-collections/community.sops/pull/47).
- community.sops.sops_encrypt - allow to pass encryption-specific options ``kms``, ``gcp_kms``, ``azure_kv``, ``hc_vault_transit``, ``pgp``, ``unencrypted_suffix``, ``encrypted_suffix``, ``unencrypted_regex``, ``encrypted_regex``, ``encryption_context``, and ``shamir_secret_sharing_threshold`` to sops (https://github.com/ansible-collections/community.sops/pull/47).

v0.2.0
======

Release Summary
---------------

This release adds features for the lookup and vars plugins.

Minor Changes
-------------

- community.sops.sops lookup plugin - add ``empty_on_not_exist`` option which allows to return an empty string instead of an error when the file does not exist (https://github.com/ansible-collections/community.sops/pull/33).
- community.sops.sops vars plugin - add option to control caching (https://github.com/ansible-collections/community.sops/pull/32).
- community.sops.sops vars plugin - add option to determine when vars are loaded (https://github.com/ansible-collections/community.sops/pull/32).

v0.1.0
======

Release Summary
---------------

First release of the ``community.sops`` collection!
This release includes multiple plugins: an ``action`` plugin, a ``lookup`` plugin and a ``vars`` plugin.

New Plugins
-----------

Lookup
~~~~~~

- community.sops.sops - Read sops encrypted file contents

Vars
~~~~

- community.sops.sops - Loading sops-encrypted vars files

New Modules
-----------

- community.sops.load_vars - Load sops-encrypted variables from files, dynamically within a task
- community.sops.sops_encrypt - Encrypt data with sops
