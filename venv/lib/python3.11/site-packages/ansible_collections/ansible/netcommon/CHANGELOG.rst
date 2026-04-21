==========================================
Ansible Netcommon Collection Release Notes
==========================================

.. contents:: Topics

v8.2.0
======

Minor Changes
-------------

- Exposes new libssh option to configure key_exchange_algorithms. This requires ansible-pylibssh v1.3.0 or higher.

Bugfixes
--------

- Added support for private key passphrase in libssh connection plugin, when using encrypted private keys specified by the C(ansible_private_key_file) attribute.
- Avoid legacy imports deprecated in ansible-core 2.20 (https://github.com/ansible-collections/ansible.netcommon/pull/720).
- Avoid merging module_defaults for all ansible.netcommon.grpc_* modules.
- Set libssh logging level to DEBUG when Ansible verbosity is greater than 3, to aid in troubleshooting connection issues.

v8.1.0
======

Minor Changes
-------------

- Changes to supplement direct execution of Ansible module in validate_config(utils.py) and _patch_update_module(network.py) added.
- Override new 2.19.1+ AnsibleModule._record_module_result hook in network action plugin to bypass module result serialization when direct execution is enabled

Bugfixes
--------

- Improved error handling in DirectExecutionModule._record_module_result method for better compatibility with core<=2.18

v8.0.1
======

Bugfixes
--------

- (#633) Fixed typo in ansible.netcommon.telnet parameter crlf (was clrf by mistake)
- netconf - Adds check for netconf session_close RPC happens only if connection is alive.

v8.0.0
======

Release Summary
---------------

With this release, the minimum required version of `ansible-core` for this collection is `2.16.0`. The last version known to be compatible with `ansible-core` versions below `2.16` is v7.2.0.

Major Changes
-------------

- Bumping `requires_ansible` to `>=2.16.0`, since previous ansible-core versions are EoL now.

v7.2.0
======

Minor Changes
-------------

- Exposes new libssh options to configure publickey_accepted_algorithms and hostkeys. This requires ansible-pylibssh v1.1.0 or higher.

Deprecated Features
-------------------

- Added deprecation warnings for the above plugins, displayed when running respective filter plugins.
- `parse_cli_textfsm` filter plugin is deprecated and will be removed in a future release after 2027-02-01. Use `ansible.utils.cli_parse` with the `ansible.utils.textfsm_parser` parser as a replacement.
- `parse_cli` filter plugin is deprecated and will be removed in a future release after 2027-02-01. Use `ansible.utils.cli_parse` as a replacement.
- `parse_xml` filter plugin is deprecated and will be removed in a future release after 2027-02-01. Use `ansible.utils.cli_parse` with the `ansible.utils.xml_parser` parser as a replacement.

Bugfixes
--------

- libssh connection plugin - stop using long-deprecated and now removed internal field from ansible-core's base connection plugin class (https://github.com/ansible-collections/ansible.netcommon/issues/522, https://github.com/ansible-collections/ansible.netcommon/issues/690, https://github.com/ansible-collections/ansible.netcommon/pull/691).

Documentation Changes
---------------------

- Includes a new support related section in the README.

v7.1.0
======

Minor Changes
-------------

- ansible.netcommon.persistent - Connection local is marked deprecated and all dependent collections are advised to move to a proper connection plugin, complete support of connection local will be removed in a release after 01-01-2027.

Bugfixes
--------

- Updated the error message for the content_templates parser to include the correct parser name and detailed error information.

Documentation Changes
---------------------

- Add a simple regexp match example for multiple prompt with multiple answers. This example could be used to for restarting a network device with a delay.

v7.0.0
======

Release Summary
---------------

Starting from this release, the minimum `ansible-core` version this collection requires is `2.15.0`. The last known version compatible with ansible-core<2.15 is v6.1.3.

Major Changes
-------------

- Bumping `requires_ansible` to `>=2.15.0`, since previous ansible-core versions are EoL now.

Bugfixes
--------

- Fix get api call during scp with libssh.
- Handle sftp error messages for file not present for routerOS.

Known Issues
------------

- libssh - net_put and net_get fail when the destination file intended to be fetched is not present.

v6.1.3
======

Bugfixes
--------

- The v6.1.2 release introduced a change in cliconfbase's edit_config() signature which broke many platform cliconfs. This patch release reverts that change.

v6.1.2
======

Documentation Changes
---------------------

- Fixed module name and log consistency in parse_cli_textfsm filter doc.

v6.1.1
======

Bugfixes
--------

- Added guidance for users to open an issue for the respective platform if plugin support is needed.
- Improved module execution to gracefully handle cases where plugin support is required, providing a clear error message to the user.

v6.1.0
======

Minor Changes
-------------

- Add new module cli_restore that exclusively handles restoring of backup configuration to target applaince.

Bugfixes
--------

- libssh connection plugin - stop using deprecated ``PlayContext.verbosity`` property that is no longer present in ansible-core 2.18 (https://github.com/ansible-collections/ansible.netcommon/pull/626).
- network_cli - removed deprecated play_context.verbosity property.

New Modules
-----------

- cli_restore - Restore device configuration to network devices over network_cli

v6.0.0
======

Release Summary
---------------

Starting from this release, the minimum `ansible-core` version this collection requires is `2.14.0`. That last known version compatible with ansible-core<2.14 is `v5.3.0`.

Major Changes
-------------

- Bumping `requires_ansible` to `>=2.14.0`, since previous ansible-core versions are EoL now.

v5.3.0
======

Minor Changes
-------------

- Add new module cli_backup that exclusively handles configuration backup.

Bugfixes
--------

- Fix attribute types from string to str in filter plugins.

v5.2.0
======

Minor Changes
-------------

- Add a new cliconf plugin ``default`` that can be used when no cliconf plugin is found for a given network_os. This plugin only supports ``get()``. (https://github.com/ansible-collections/ansible.netcommon/pull/569)
- httpapi - Add additional option ``ca_path``, ``client_cert``, ``client_key``, and ``http_agent`` that are available in open_url but not to httpapi. (https://github.com/ansible-collections/ansible.netcommon/issues/528)
- telnet - add crlf option to send CRLF instead of just LF (https://github.com/ansible-collections/ansible.netcommon/pull/440).

Deprecated Features
-------------------

- libssh - the ssh_*_args options are now marked that they will be removed after 2026-01-01.

Bugfixes
--------

- Ensure that all connection plugin options that should be strings are actually strings (https://github.com/ansible-collections/ansible.netcommon/pull/549).

New Plugins
-----------

Cliconf
~~~~~~~

- default - General purpose cliconf plugin for new platforms

v5.1.3
======

Bugfixes
--------

- Vendor telnetlib from cpython (https://github.com/ansible-collections/ansible.netcommon/pull/546)

v5.1.2
======

Bugfixes
--------

- Ensure that all connection plugin options that should be strings are actually strings (https://github.com/ansible-collections/ansible.netcommon/pull/549).

v5.1.1
======

Bugfixes
--------

- network_resource - do not append network_os to module names when building supported resources list. This fix is only valid for cases where FACTS_RESOURCE_SUBSETS is undefined.

v5.1.0
======

Minor Changes
-------------

- libssh - add ``config_file`` option to specify an alternate SSH config file to use.
- parse_cli - add support for multiple matches inside a block by adding new dictionary key to result
- telnet - add ``stdout`` and ``stdout_lines`` to module output.
- telnet - add support for regexes to ``login_prompt`` and ``password_prompt``.
- telnet - apply ``timeout`` to command prompts.

Bugfixes
--------

- httpapi - ``send()`` method no longer applied leftover kwargs to ``open_url()``. Fix applies those arguments as intended (https://github.com/ansible-collections/ansible.netcommon/pull/524).
- network_cli - network cli connection avoids traceback when using invalid user
- network_cli - when receiving longer responses with libssh, parts of the response were sometimes repeated. The response is now returned as it is received (https://github.com/ansible-collections/community.routeros/issues/132).
- network_resource - fix a potential UnboundLocalError if the module fails to import a Resource Module. (https://github.com/ansible-collections/ansible.netcommon/pull/513)
- restconf - creation of new resources is no longer erroneously forced to use POST. (https://github.com/ansible-collections/ansible.netcommon/issues/502)

v5.0.0
======

Minor Changes
-------------

- httpapi - Add option netcommon_httpapi_ciphers to allow overriding default SSL/TLS ciphers. (https://github.com/ansible-collections/ansible.netcommon/pull/494)

Breaking Changes / Porting Guide
--------------------------------

- NetworkConnectionBase now inherits from PersistentConnectionBase in ansible.utils. As a result, the minimum ansible.utils version has increased to 2.7.0.
- NetworkTemplate is no longer importable from ansible_collections.ansible.netcommon.plugins.module_utils.network.common and should now be found at its proper location ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.network_template
- ResourceModule is no longer importable from ansible_collections.ansible.netcommon.plugins.module_utils.network.common and should now be found at its proper location ansible_collections.ansible.netcommon.plugins.module_utils.network.common.rm_base.resource_module
- VALID_MASKS, is_masklen, is_netmask, to_bits, to_ipv6_network, to_masklen, to_netmask, and to_subnet are no longer importable from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils and should now be found at their proper location ansible.module_utils.common.network

Removed Features (previously deprecated)
----------------------------------------

- cli_parse - This plugin was moved to ansible.utils in version 1.0.0, and the redirect to that collection has now been removed.

Bugfixes
--------

- Cast AnsibleUnsafeText to str in convert_doc_to_ansible_module_kwargs() to keep CSafeLoader happy. This fixes issues with content scaffolding tools.

v4.1.0
======

Minor Changes
-------------

- Add implementation for content_templates_parser.

Bugfixes
--------

- restconf_get - fix direction of XML deserialization when ``output == 'xml'``

v4.0.0
======

Removed Features (previously deprecated)
----------------------------------------

- napalm - Removed unused connection plugin.
- net_banner - Use <network_os>_banner instead.
- net_interface - Use <network_os>_interfaces instead.
- net_l2_interface - Use <network_os>_l2_interfaces instead.
- net_l3_interface - Use <network_os>_l3_interfaces instead.
- net_linkagg - Use <network_os>_lag_interfaces instead.
- net_lldp - Use <network_os>_lldp_global instead.
- net_lldp_interface - Use <network_os>_lldp_interfaces instead.
- net_logging - Use <network_os>_logging_global instead.
- net_static_route - Use <network_os>_static_routes instead.
- net_system - Use <network_os>_system instead.
- net_user - Use <network_os>_user instead.
- net_vlan - Use <network_os>_vlans instead.
- net_vrf - Use <network_os>_vrf instead.

v3.1.3
======

Release Summary
---------------

The v3.1.2 is unavailable on Ansible Automation Hub because a technical issue. Please download and use v3.1.3 from Automation Hub.

v3.1.2
======

Bugfixes
--------

- libssh - check for minimum ansible-pylibssh version before using password_prompt option. (https://github.com/ansible-collections/ansible.netcommon/pull/467)

v3.1.1
======

Bugfixes
--------

- Fix a small number of potential use-before-assignment issues.
- Fix to set connection plugin options correctly.
- libssh - Removed the wording "Tech preview". From version 3.0.0 the default if installed.
- libssh - add ssh_args, ssh_common_args, and ssh_extra_args options. These options are exclusively for collecting proxy information from as an alternative to the proxy_command option.

v3.1.0
======

Minor Changes
-------------

- Add grpc connection plugin support.
- Adds a new option `terminal_errors` in network_cli, that determines how terminal setting failures are handled.
- libssh - Added `password_prompt` option to override default "password:" prompt used by pylibssh

New Plugins
-----------

Connection
~~~~~~~~~~

- grpc - Provides a persistent connection using the gRPC protocol

New Modules
-----------

- grpc_config - Fetch configuration/state data from gRPC enabled target hosts.
- grpc_get - Fetch configuration/state data from gRPC enabled target hosts.

v3.0.1
======

Bugfixes
--------

- httpapi - Fix for improperly set hostname in url
- libssh - Fix for improperly set hostname in connect
- restconf - When non-JSON data is encountered, return the bytes found instead of nothing.

v3.0.0
======

Major Changes
-------------

- cli_parse - this module has been moved to the ansible.utils collection. ``ansible.netcommon.cli_parse`` will continue to work to reference the module in its new location, but this redirect will be removed in a future release
- network_cli - Change default value of `ssh_type` option from `paramiko` to `auto`. This value will use libssh if the ansible-pylibssh module is installed, otherwise will fallback to paramiko.

Breaking Changes / Porting Guide
--------------------------------

- httpapi - Change default value of ``import_modules`` option from ``no`` to ``yes``
- netconf - Change default value of ``import_modules`` option from ``no`` to ``yes``
- network_cli - Change default value of ``import_modules`` option from ``no`` to ``yes``

Known Issues
------------

- eos - When using eos modules on Ansible 2.9, tasks will occasionally fail with ``import_modules`` enabled. This can be avoided by setting ``import_modules: no``

v2.6.1
======

Release Summary
---------------

Rereleased 2.6.0 with updated utils dependancy.

Bugfixes
--------

- Fix validate-module sanity test.

v2.6.0
======

Minor Changes
-------------

- Redirected ipaddr filters to ansible.utils (https://github.com/ansible-collections/ansible.netcommon/pull/359).
- httpapi - new parameter retries in send() method limits the number of times a request is retried when a HTTP error that can be worked around is encountered. The default is to retry indefinitely to maintain old behavior, but this default may change in a later breaking release.

Bugfixes
--------

- Fix issue with cli_parse native_parser plugin when input is empty (https://github.com/ansible-collections/ansible.netcommon/issues/347).
- No activity on the transport's channel was triggering a socket.timeout() after 30 secs, even if persistent_command_timeout is set to a higher value. This patch fixes it.

v2.5.1
======

Bugfixes
--------

- Fixed plugins inheriting from netcommon's base plugins (for example httpapi/restconf or netconf/default) so that they can be properly loaded (https://github.com/ansible-collections/ansible.netcommon/issues/356).

v2.5.0
======

Minor Changes
-------------

- Copied the cliconf, httpapi, netconf, and terminal base plugins and NetworkConnectionBase into netcommon. These base plugins may now be imported from netcommmon instead of ansible if a collection depends on netcommon versions newer than this version, allowing features and bugfixes to flow to those collections without upgrading ansible.
- Make ansible_network_os as optional param for httpapi connection plugin.
- Support removal of non-config lines from running config while taking backup.
- `network_cli` - added new option 'become_errors' to determine how privilege escalation failures are handled.

Bugfixes
--------

- network_cli - Provide clearer error message when a prompt regex fails to compile
- network_cli - fix issue when multiple terminal_initial_(prompt|answer) values are given (https://github.com/ansible-collections/ansible.netcommon/issues/331).

v2.4.0
======

Minor Changes
-------------

- Add network_resource plugin to manage and provide single entry point for all resource modules for higher oder roles.

Deprecated Features
-------------------

- network_cli - The paramiko_ssh setting ``look_for_keys`` was set automatically based on the values of the ``password`` and ``private_key_file`` options passed to network_cli. This option can now be set explicitly, and the automatic setting of ``look_for_keys`` will be removed after 2024-01-01  (https://github.com/ansible-collections/ansible.netcommon/pull/271).

Bugfixes
--------

- network_cli - Add ability to set options inherited from paramiko/libssh in ansible >= 2.11 (https://github.com/ansible-collections/ansible.netcommon/pull/271).

New Modules
-----------

- network_resource - Manage resource modules

v2.3.0
======

Minor Changes
-------------

- Add vlan_expander filter
- Persistent connection options (persistent_command_timeout, persistent_log_messages, etc.) have been unified across all persistent connections. New persistent connections may also now get these options by extending the connection_persistent documentation fragment.

v2.2.0
======

Minor Changes
-------------

- Add variable to control ProxyCommand with libssh connection.
- NetworkTemplate and ResouceModule base classes have been moved under module_utils.network.common.rm_base. Stubs have been kept for backwards compatibility. These will be removed after 2023-01-01. Please update imports for existing modules that subclass them. The `cli_rm_builder <https://github.com/ansible-network/cli_rm_builder>`_ has been updated to use the new imports.

Bugfixes
--------

- libssh - Fix fromatting of authenticity error message when not prompting for input (https://github.com/ansible-collections/ansible.netcommon/issues/283)
- netconf - Fix connection with ncclient versions < 0.6.10
- network_cli - Fix for execution failing when ansible_ssh_password is used to specify password (https://github.com/ansible-collections/ansible.netcommon/issues/288)

v2.1.0
======

Minor Changes
-------------

- Add support for ProxyCommand with netconf connection.

Bugfixes
--------

- Variables in play_context will now be updated for netconf connections on each task run.
- fix SCP/SFTP when using network_cli with libssh

v2.0.2
======

Bugfixes
--------

- Fix cli_parse issue with parsers in utils collection (https://github.com/ansible-collections/ansible.netcommon/pull/270)
- Support single_user_mode with Ansible 2.9.

v2.0.1
======

Minor Changes
-------------

- Several module_utils files were intended to be licensed BSD, but missing a license preamble in the files. The preamble has been added, and all authors for the files have given their assent to the intended license https://github.com/ansible-collections/ansible.netcommon/pull/122

Bugfixes
--------

- Allow setting `host_key_checking` through a play/task var for `network_cli`.
- Ensure passed-in terminal_initial_prompt and terminal_initial_answer values are cast to bytes before using
- Update valid documentation for net_ping module.
- ncclient - catch and handle exception to prevent stack trace when running in FIPS mode
- net_put - Remove temp file created when file already exist on destination when mode is 'text'.

v2.0.0
======

Major Changes
-------------

- Remove deprecated connection arguments from netconf_config

Minor Changes
-------------

- Add SCP support when using ssh_type libssh
- Add `single_user_mode` option for command output caching.
- Move cli_config idempotent warning message with the task response under `warnings` key if `changed` is `True`
- Reduce CPU usage and network module run time when using `ansible_network_import_modules`
- Support any() and all() filters in Jinja2.

Breaking Changes / Porting Guide
--------------------------------

- Removed vendored ipaddress package from collection. If you use ansible_collections.ansible.netcommon.plugins.module_utils.compat.ipaddress in your collection, you will need to change this to import ipaddress instead. If your content using ipaddress supports Python 2.7, you will additionally need to make sure that the user has the ipaddress package installed. Please refer to https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_best_practices.html#importing-and-using-shared-code to see how to safely import external packages that may be missing from the user's system A backport of ipaddress for Python 2.7 is available at https://pypi.org/project/ipaddress/

Deprecated Features
-------------------

- Deprecate cli_parse module and textfsm, ttp, xml, json parser plugins as they are moved to ansible.utils collection (https://github.com/ansible-collections/ansible.netcommon/pull/182 https://github.com/ansible-collections/ansible.utils/pull/28)

Bugfixes
--------

- Expose connection class object to rm_template (https://github.com/ansible-collections/ansible.netcommon/pull/180)
- network_cli - When using ssh_type libssh, handle closed connection gracefully instead of throwing an exception

New Plugins
-----------

Cache
~~~~~

- memory - RAM backed, non persistent cache.

v1.5.0
======

Minor Changes
-------------

- Add 'purged' to ACTION_STATES.

Bugfixes
--------

- Add netconf_config integration tests for nxos (https://github.com/ansible-collections/ansible.netcommon/pull/185)
- Fix GetReply object has no attribute strip() (https://github.com/ansible-collections/cisco.iosxr/issues/97)
- Fix config diff logic if parent configuration is present more than once in the candidate config and update docs (https://github.com/ansible-collections/ansible.netcommon/pull/189)
- Fix missing changed from net_get (https://github.com/ansible-collections/ansible.netcommon/issues/198)
- Fix netconf_config module integration test issuea (https://github.com/ansible-collections/ansible.netcommon/pull/177)
- Fix restconf_config incorrectly spoofs HTTP 409 codes (https://github.com/ansible-collections/ansible.netcommon/issues/191)
- Split checks for prompt and errors in network_cli so that detected errors are not lost if the prompt is in a later chunk.

v1.4.1
======

Release Summary
---------------

Change how black config is specified to avoid issues with Automation Hub release process

v1.4.0
======

Minor Changes
-------------

- 'prefix' added to NetworkTemplate class, inorder to handle the negate operation for vyos config commands.
- Add support for json format input format for netconf modules using ``xmltodict``
- Update docs for netconf_get and netconf_config examples using display=native

Bugfixes
--------

- Added support for private key based authentication with libssh transport (https://github.com/ansible-collections/ansible.netcommon/issues/168)
- Fixed ipaddr filter plugins in ansible.netcommon collections is not working with latest Ansible (https://github.com/ansible-collections/ansible.netcommon/issues/157)
- Fixed netconf_rpc task fails due to encoding issue in the response (https://github.com/ansible-collections/ansible.netcommon/issues/151)
- Fixed ssh_type none issue while using net_put and net_get module (https://github.com/ansible-collections/ansible.netcommon/issues/153)
- Fixed unit tests under python3.5
- ipaddr filter - query "address/prefix" (also: "gateway", "gw", "host/prefix", "hostnet", and "router") now handles addresses with /32 prefix or /255.255.255.255 netmask
- network_cli - Update underlying ssh connection's play_context in update_play_context, so that the username or password can be updated

v1.3.0
======

Minor Changes
-------------

- Confirmed commit fails with TypeError in IOS XR netconf plugin (https://github.com/ansible-collections/cisco.iosxr/issues/74)
- The netconf_config module now allows root tag with namespace prefix.
- cli_config: Add new return value diff which is returned when the cliconf plugin supports onbox diff
- cli_config: Clarify when commands is returned when the module is run

Bugfixes
--------

- cli_parse - Ensure only native types are returned to the control node from the parser.
- netconf - Changed log level for message of using default netconf plugin to match the level used when a platform-specific netconf plugin is found

v1.2.1
======

Bugfixes
--------

- Fixed "Object of type Capabilities is not JSON serializable" when using default netconf plugin.

v1.2.0
======

Minor Changes
-------------

- Added description to collection galaxy.yml file.
- NetworkConfig objects now have an optional `comment_tokens` parameter which takes a list of strings which will override the DEFAULT_COMMENT_TOKENS list.
- New cli_parse module for parsing structured text using a variety of parsers. The initial implemetation of cli_parse can be used with json, native, ntc_templates, pyats, textfsm, ttp, and xml.
- The httpapi connection plugin now works with `wait_for_connection`. This will periodically request the root page of the server described by the plugin's options until the request succeeds. This can only test that the server is reachable, the correctness or usability of the API is not guaranteed.

Bugfixes
--------

- cli_config fixes issue when rollback_id = 0 evalutes to False
- sort_list will sort a list of dicts using the sorted method with key as an argument.

v1.1.2
======

Release Summary
---------------

Rereleased 1.1.1 with updated changelog.

v1.1.1
======

Release Summary
---------------

Rereleased 1.1.0 with regenerated documentation.

v1.1.0
======

Major Changes
-------------

- Add libssh connection plugin and refactor network_cli (https://github.com/ansible-collections/ansible.netcommon/pull/30)

Minor Changes
-------------

- Add content option validation for netconf_config module (https://github.com/ansible-collections/ansible.netcommon/pull/66)
- Documentation of module arguments updated to match expected types where missing.
- Resource Modules: changed flag is set to true in check_mode for all ACTION_STATES (https://github.com/ansible-collections/ansible.netcommon/pull/82)

Removed Features (previously deprecated)
----------------------------------------

- module_utils.network.common.utils.ComplexDict has been removed

Bugfixes
--------

- Replace deprecated `getiterator` call with `iter`
- ipaddr - "host" query supports /31 subnets properly
- ipaddr filter - Fixed issue where the first IPv6 address in a subnet was not being considered a valid address.
- ipaddr filter now returns empty list instead of False on empty list input
- net_put - Restore missing function removed when action plugin stopped inheriting NetworkActionBase
- nthhost filter now returns str instead of IPAddress object
- slaac filter now returns str instead of IPAddress object

v1.0.0
======

New Plugins
-----------

Become
~~~~~~

- enable - Switch to elevated permissions on a network device

Connection
~~~~~~~~~~

- httpapi - Use httpapi to run command on network appliances
- netconf - Provides a persistent connection using the netconf protocol
- network_cli - Use network_cli to run command on network appliances
- persistent - Use a persistent unix socket for connection

Httpapi
~~~~~~~

- restconf - HttpApi Plugin for devices supporting Restconf API

Netconf
~~~~~~~

- default - Use default netconf plugin to run standard netconf commands as per RFC

New Modules
-----------

- cli_command - Run a cli command on cli-based network devices
- cli_config - Push text based configuration to network devices over network_cli
- net_get - Copy a file from a network device to Ansible Controller
- net_ping - Tests reachability using ping from a network device
- net_put - Copy a file from Ansible Controller to a network device
- netconf_config - netconf device configuration
- netconf_get - Fetch configuration/state data from NETCONF enabled network devices.
- netconf_rpc - Execute operations on NETCONF enabled network devices.
- restconf_config - Handles create, update, read and delete of configuration data on RESTCONF enabled devices.
- restconf_get - Fetch configuration/state data from RESTCONF enabled devices.
- telnet - Executes a low-down and dirty telnet command
