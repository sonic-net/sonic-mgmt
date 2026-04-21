====================================
Community DigitalOcean Release Notes
====================================

.. contents:: Topics


v1.27.0
=======

Release Summary
---------------

CI, documentation, and Python updates.


v1.26.0
=======

Minor Changes
-------------

- digital_ocean_kubernetes - add project_name parameter (https://github.com/ansible-collections/community.digitalocean/issues/264).

Bugfixes
--------

- The C(project_name) parameter for many modules was used by alias C(project) internally in the codebase, but to work properly C(project_name) must be used in the code. Replace self.module.params.get("project") with self.module.params.get("project_name") (https://github.com/ansible-collections/community.digitalocean/issues/326).
- digital_ocean_kubernetes - module didn't return kubeconfig properly, return documentation was invalid. Fixed version returns data with the same structure all the time, also it is aligned with M(community.digitalocean.digital_ocean_kubernetes_info) documentation return data now. (https://github.com/ansible-collections/community.digitalocean/issues/322).

v1.25.0
=======

Minor Changes
-------------

- fix sanity tests (https://github.com/ansible-collections/community.digitalocean/issues/323).

Bugfixes
--------

- inventory plugin - restore reading auth token from env variables (https://github.com/ansible-collections/community.digitalocean/pull/315).

New Modules
-----------

- digital_ocean_project_resource_info - Gather information about DigitalOcean Project Resources

v1.24.0
=======

Minor Changes
-------------

- documentation - use C(true) and C(false) for boolean values in documentation and examples (https://github.com/ansible-collections/community.digitalocean/issues/303).
- inventory plugin - drop C(api_token) in favor of C(oauth_token) for consistency (https://github.com/ansible-collections/community.digitalocean/issues/300).
- tests - add C(sanity), C(units), and C(psf/black) back on merge into C(main) (https://github.com/ansible-collections/community.digitalocean/pull/311).
- tests - drop Ansible 2.9 and Ansible Core 2.10 and 2.11 (https://github.com/ansible-collections/community.digitalocean/pull/310).
- tests - remove the daily runs (https://github.com/ansible-collections/community.digitalocean/pull/310).
- tests - run C(psf/black) across all files (https://github.com/ansible-collections/community.digitalocean/pull/310).
- tests - test against Ansible Core 2.12, 2.13, and 2.14 (https://github.com/ansible-collections/community.digitalocean/pull/310).

Bugfixes
--------

- digital_ocean_domain - fix ``all_domains`` by using ``get_paginated_data`` to retrieve all of the domains in the account from the paginated domains api endpoint (https://github.com/ansible-collections/community.digitalocean/pull/307).

v1.23.0
=======

Minor Changes
-------------

- digital_ocean_load_balancer - add support for C(size_unit) over deprecated C(size); deprecate C(algorithm) completely (https://github.com/ansible-collections/community.digitalocean/issues/270).
- documentation - refresh the "Testing and Development" section of the C(README.md) (https://github.com/ansible-collections/community.digitalocean/issues/268).
- integration tests - add a dedicated integration test for C(digital_ocean_database_info) (https://github.com/ansible-collections/community.digitalocean/issues/289).
- integration tests - set pull request integration tests to run against branch instead of last commit (https://github.com/ansible-collections/community.digitalocean/issues/291).

Bugfixes
--------

- integration tests - add missing `environment` directive on pull request integration testing (https://github.com/ansible-collections/community.digitalocean/issues/293).
- inventory plugin - bugfix for baseurl parameter (https://github.com/ansible-collections/community.digitalocean/pull/297).

v1.22.0
=======

Minor Changes
-------------

- collection - added an action group C(community.digitalocean.all) for use with module defaults (https://docs.ansible.com/ansible/latest/user_guide/playbooks_module_defaults.html) (https://github.com/ansible-collections/community.digitalocean/issues/281).
- digital_ocean_vpc - add C(vpc) key to returned VPC data on create (https://github.com/ansible-collections/community.digitalocean/issues/276).
- integration tests - perform integration testing on all modules for changes in C(plugins/module_utils) or by changed module in C(plugins/modules) (https://github.com/ansible-collections/community.digitalocean/issues/286).
- integration tests - split the integration tests by module and run them serially (https://github.com/ansible-collections/community.digitalocean/issues/280).

v1.21.0
=======

Minor Changes
-------------

- digital_ocean - add sanity test ignores for Ansible 2.12 and 2.13 (https://github.com/ansible-collections/community.digitalocean/issues/247).

Bugfixes
--------

- digital_ocean_droplet - if the JSON response lacks a key and the associated variable is set to ``None``, then don't treat that variable like a ``dict`` and call ``get()`` on it without first testing it (https://github.com/ansible-collections/community.digitalocean/issues/272).

v1.20.0
=======

Minor Changes
-------------

- digital_ocean_cdn_endpoints - update Spaces endpoint and add a few delays to the integration test (https://github.com/ansible-collections/community.digitalocean/issues/267).
- digital_ocean_load_balancer - Allow creating a load balancer and associating droplets by tag as an alternative to ``droplet_ids``.

Bugfixes
--------

- digital_ocean_droplet - fix regression in droplet deletion where ``name`` and ``unique_name`` (set to true) are required and ``id`` alone is insufficient (though ``id`` is sufficient to uniquely identify a droplet for deletion). (https://github.com/ansible-collections/community.digitalocean/issues/260)
- digital_ocean_droplet - fix regression where droplet info (for example networking) doesn't update when waiting during creation unless ``unique_name`` is set to true (https://github.com/ansible-collections/community.digitalocean/issues/220).

v1.19.0
=======

Minor Changes
-------------

- digital_ocean - reference C(DO_API_TOKEN) consistently in module documentation and examples (https://github.com/ansible-collections/community.digitalocean/issues/248).

Bugfixes
--------

- digital_ocean_cdn_endpoints - remove non-API parameters before posting to the API (https://github.com/ansible-collections/community.digitalocean/issues/252).
- digital_ocean_cdn_endpoints - use the correct module name in the C(EXAMPLES) (https://github.com/ansible-collections/community.digitalocean/issues/251).

v1.18.0
=======

Minor Changes
-------------

- ci - adding stable-2.13 to sanity and unit testing (https://github.com/ansible-collections/community.digitalocean/issues/239).
- digital_ocean_spaces - set C(no_log=True) for C(aws_access_key_id) parameter (https://github.com/ansible-collections/community.digitalocean/issues/243).
- digital_ocean_spaces_info - set C(no_log=True) for C(aws_access_key_id) parameter (https://github.com/ansible-collections/community.digitalocean/issues/243).

v1.17.0
=======

Minor Changes
-------------

- digital_ocean - parameterize the DigitalOcean API base url (https://github.com/ansible-collections/community.digitalocean/issues/237).

v1.16.0
=======

Minor Changes
-------------

- black test - added a 15 minute timeout (https://github.com/ansible-collections/community.digitalocean/issues/228).
- digital_ocean_domain - add support for IPv6 apex domain records (https://github.com/ansible-collections/community.digitalocean/issues/226).
- integration tests - added a 120 minute timeout (https://github.com/ansible-collections/community.digitalocean/issues/228).
- sanity and unit tests - added a 30 minute timeout (https://github.com/ansible-collections/community.digitalocean/issues/228).

Bugfixes
--------

- digital_ocean_kubernetes - add missing elements type to C(node_pools.tags) and C(node_pools.taints) options (https://github.com/ansible-collections/community.digitalocean/issues/232).

New Modules
-----------

- digital_ocean_domain_record_info - Gather information about DigitalOcean domain records

v1.15.1
=======

Minor Changes
-------------

- Updates DigitalOcean API documentation links to current domain with working URL anchors (https://github.com/ansible-collections/community.digitalocean/issues/223).

Bugfixes
--------

- digital_ocean_droplet - fix reporting of changed state when ``firewall`` argument is present (https://github.com/ansible-collections/community.digitalocean/pull/219).

v1.15.0
=======

Bugfixes
--------

- digital_ocean_droplet - move Droplet data under "droplet" key in returned payload (https://github.com/ansible-collections/community.digitalocean/issues/211).

New Modules
-----------

- digital_ocean_spaces - Create and remove DigitalOcean Spaces.
- digital_ocean_spaces_info - List DigitalOcean Spaces.

v1.14.0
=======

Minor Changes
-------------

- digital_ocean_kubernetes_info - switching C(changed=True) to C(changed=False) since getting information is read-only in nature (https://github.com/ansible-collections/community.digitalocean/issues/204).

Bugfixes
--------

- Update README.md with updated Droplet examples (https://github.com/ansible-collections/community.digitalocean/issues/199).
- digital_ocean_cdn_endpoints - defaulting optional string parameters as strings (https://github.com/ansible-collections/community.digitalocean/issues/205).
- digital_ocean_cdn_endpoints - updating Spaces endpoint for the integration test (https://github.com/ansible-collections/community.digitalocean/issues/205).
- digital_ocean_droplet - ensure that Droplet creation is successful (https://github.com/ansible-collections/community.digitalocean/issues/197).
- digital_ocean_droplet - fixing project assignment for the C(unique_name=False) case (https://github.com/ansible-collections/community.digitalocean/issues/201).
- digital_ocean_droplet - update Droplet examples (https://github.com/ansible-collections/community.digitalocean/issues/199).

v1.13.0
=======

Minor Changes
-------------

- Set Python 3.9 as the C(python-version) and C(target-python-version) in the integration, sanity, and unit tests for Ansible > 2.9 (3.8 otherwise).
- digital_ocean_droplet - allow the user to override the Droplet action and status polling interval (https://github.com/ansible-collections/community.digitalocean/issues/194).
- digital_ocean_kubernetes - adding support for HA control plane (https://github.com/ansible-collections/community.digitalocean/issues/190).

v1.12.0
=======

Minor Changes
-------------

- digital_ocean_block_storage - adding Project support (https://github.com/ansible-collections/community.digitalocean/issues/171).
- digital_ocean_database - adding Project support (https://github.com/ansible-collections/community.digitalocean/issues/171).
- digital_ocean_domain - adding Project support (https://github.com/ansible-collections/community.digitalocean/issues/171).
- digital_ocean_droplet - adding Project support (https://github.com/ansible-collections/community.digitalocean/issues/171).
- digital_ocean_droplet - adding ability to apply and remove firewall by using droplet module (https://github.com/ansible-collections/community.digitalocean/issues/159).
- digital_ocean_droplet - require unique_name for state=absent to avoid unintentional droplet deletions.
- digital_ocean_firewall - inbound_rules and outbound_rules are no longer required for firewall removal (https://github.com/ansible-collections/community.digitalocean/issues/181).
- digital_ocean_floating_ip - adding Project support (https://github.com/ansible-collections/community.digitalocean/issues/171).
- digital_ocean_floating_ip - adding attach and detach states to floating ip module (https://github.com/ansible-collections/community.digitalocean/issues/170).
- digital_ocean_load_balancer - adding Project support (https://github.com/ansible-collections/community.digitalocean/issues/171).
- digitalocean integration tests - adding integration tests for CDN Endpoints (https://github.com/ansible-collections/community.digitalocean/issues/179).

Bugfixes
--------

- Update the tests so that they only run once (https://github.com/ansible-collections/community.digitalocean/issues/186).
- digital_ocean_droplet - fix resizing with C(state: active) does not actually turn Droplet on (https://github.com/ansible-collections/community.digitalocean/issues/140).
- digital_ocean_kubernetes - fix return value consistency (https://github.com/ansible-collections/community.digitalocean/issues/174).

v1.11.0
=======

Minor Changes
-------------

- digitalocean inventory script - add support for Droplet tag filtering (https://github.com/ansible-collections/community.digitalocean/issues/7).

Bugfixes
--------

- Adding missing status badges for black and unit tests (https://github.com/ansible-collections/community.digitalocean/pull/164).
- Documentation URLs are fixed for the C(digital_ocean_domain_record) and C(digital_ocean_droplet_info) modules (https://github.com/ansible-collections/community.digitalocean/pull/163).
- Serializing the cloud integration tests (https://github.com/ansible-collections/community.digitalocean/pull/165).
- digital_ocean_floating_ip - make floating ip return data idempotent (https://github.com/ansible-collections/community.digitalocean/pull/162).
- digitalocean inventory - enforce the C(timeout) parameter (https://github.com/ansible-collections/community.digitalocean/issues/168).

v1.10.0
=======

Minor Changes
-------------

- digital_ocean_kubernetes - adding the C(taints), C(auto_scale), C(min_nodes) and C(max_nodes) parameters to the C(node_pools) definition (https://github.com/ansible-collections/community.digitalocean/issues/157).

Bugfixes
--------

- digital_ocean_block_storage - fix block volumes detach idempotency (https://github.com/ansible-collections/community.digitalocean/issues/149).
- digital_ocean_droplet - ensure "active" state before issuing "power on" action (https://github.com/ansible-collections/community.digitalocean/issues/150)
- digital_ocean_droplet - power on should poll/wait, resize should support "active" state (https://github.com/ansible-collections/community.digitalocean/pull/143).
- digital_ocean_load_balancer - C(droplet_ids) are not required when C(state=absent) is chosen (https://github.com/ansible-collections/community.digitalocean/pull/147).
- digital_ocean_load_balancer - when C(state=absent) is chosen the API returns an empty response (https://github.com/ansible-collections/community.digitalocean/pull/147).

New Modules
-----------

- digital_ocean_cdn_endpoints - Create and delete DigitalOcean CDN Endpoints
- digital_ocean_cdn_endpoints_info - Gather information about DigitalOcean CDN Endpoints
- digital_ocean_load_balancer - Manage DigitalOcean Load Balancers
- digital_ocean_monitoring_alerts - Create and delete DigitalOcean Monitoring alerts
- digital_ocean_monitoring_alerts_info - Gather information about DigitalOcean Monitoring alerts

v1.9.0
======

Minor Changes
-------------

- digital_ocean - running and enforcing psf/black in the codebase (https://github.com/ansible-collections/community.digitalocean/issues/136).
- digital_ocean_floating_ip_info - new integration test for the `digital_ocean_floating_ip_info` module (https://github.com/ansible-collections/community.digitalocean/issues/130).

Bugfixes
--------

- digital_ocean_database - increase the database creation integration test timeout (https://github.com/ansible-collections/community.digitalocean).
- digital_ocean_floating_ip - delete all Floating IPs initially during the integration test run (https://github.com/ansible-collections/community.digitalocean/issues/129).
- digitalocean inventory - respect the TRANSFORM_INVALID_GROUP_CHARS configuration setting (https://github.com/ansible-collections/community.digitalocean/pull/138).
- info modules - adding missing check mode support (https://github.com/ansible-collections/community.digitalocean/issues/139).

v1.8.0
======

Minor Changes
-------------

- digital_ocean_database - add support for MongoDB (https://github.com/ansible-collections/community.digitalocean/issues/124).

Bugfixes
--------

- digital_ocean - integration tests need community.general and jmespath (https://github.com/ansible-collections/community.digitalocean/issues/121).
- digital_ocean_firewall - fixed idempotence (https://github.com/ansible-collections/community.digitalocean/issues/122).

v1.7.0
======

Minor Changes
-------------

- digital_ocean_kubernetes - set "latest" as the default version for new clusters (https://github.com/ansible-collections/community.digitalocean/issues/114).

Bugfixes
--------

- digital_ocean_certificate - fixing integration test (https://github.com/ansible-collections/community.digitalocean/issues/114).
- digital_ocean_droplet - state `present` with `wait` was not waiting (https://github.com/ansible-collections/community.digitalocean/issues/116).
- digital_ocean_firewall - fixing integration test (https://github.com/ansible-collections/community.digitalocean/issues/114).
- digital_ocean_tag - fixing integration test (https://github.com/ansible-collections/community.digitalocean/issues/114).
- digitalocean - update README.md with project_info and project module (https://github.com/ansible-collections/community.digitalocean/pull/112).

New Modules
-----------

- digital_ocean_snapshot - Create and delete DigitalOcean snapshots
- digital_ocean_vpc - Create and delete DigitalOcean VPCs
- digital_ocean_vpc_info - Gather information about DigitalOcean VPCs

v1.6.0
======

Bugfixes
--------

- digital_ocean_certificate_info - ensure return type is a list (https://github.com/ansible-collections/community.digitalocean/issues/55).
- digital_ocean_domain_info - ensure return type is a list (https://github.com/ansible-collections/community.digitalocean/issues/55).
- digital_ocean_firewall_info - ensure return type is a list (https://github.com/ansible-collections/community.digitalocean/issues/55).
- digital_ocean_load_balancer_info - ensure return type is a list (https://github.com/ansible-collections/community.digitalocean/issues/55).
- digital_ocean_tag_info - ensure return type is a list (https://github.com/ansible-collections/community.digitalocean/issues/55).
- digitalocean inventory plugin - attributes available to filters are limited to explicitly required attributes and are prefixed with ``var_prefix`` (https://github.com/ansible-collections/community.digitalocean/pull/102).

New Modules
-----------

- digital_ocean_project - Manage a DigitalOcean project
- digital_ocean_project_info - Gather information about DigitalOcean Projects

v1.5.1
======

Bugfixes
--------

- digitalocean inventory plugin - Wire up advertised caching functionality (https://github.com/ansible-collections/community.digitalocean/pull/97).

v1.5.0
======

Minor Changes
-------------

- digitalocean - Filter droplets in dynamic inventory plugin using arbitrary. jinja2 expressions (https://github.com/ansible-collections/community.digitalocean/pull/96).
- digitalocean - Support templates in API tokens when using the dynamic inventory plugin (https://github.com/ansible-collections/community.digitalocean/pull/98).

Bugfixes
--------

- digital_ocean_database - Fixed DB attribute settings (https://github.com/ansible-collections/community.digitalocean/issues/94).
- digital_ocean_database_info - Cleanup unused attribs (https://github.com/ansible-collections/community.digitalocean/pulls/100).
- digital_ocean_snapshot_info - Fix lookup of snapshot_info by_id (https://github.com/ansible-collections/community.digitalocean/issues/92).
- digital_ocean_tag - Fix tag idempotency (https://github.com/ansible-collections/community.digitalocean/issues/61).

v1.4.2
======

Bugfixes
--------

- digital_ocean_droplet - Fixed Droplet inactive state (https://github.com/ansible-collections/community.digitalocean/pull/88).
- digital_ocean_sshkey - Fixed SSH Key Traceback Issue (https://github.com/ansible-collections/community.digitalocean/issues/68).

v1.4.1
======

Bugfixes
--------

- digital_ocean_droplet - Add integration tests for Droplet active and inactive states (https://github.com/ansible-collections/community.digitalocean/issues/66).
- digital_ocean_droplet - Fix Droplet inactive state (https://github.com/ansible-collections/community.digitalocean/issues/83).

v1.4.0
======

Bugfixes
--------

- digital_ocean_droplet_info - Fix documentation link for `digital_ocean_droplet_info` (https://github.com/ansible-collections/community.digitalocean/pull/81).
- digitalocean - Fix return docs for digital_ocean_sshkey_info (https://github.com/ansible-collections/community.digitalocean/issues/56).
- digitalocean - Update README.md for K8s and databases (https://github.com/ansible-collections/community.digitalocean/pull/80).

New Modules
-----------

- digital_ocean_droplet_info - Gather information about DigitalOcean Droplets

v1.3.0
======

New Modules
-----------

- digital_ocean_database - Create and delete a DigitalOcean database
- digital_ocean_database_info - Gather information about DigitalOcean databases
- digital_ocean_kubernetes - Create and delete a DigitalOcean Kubernetes cluster
- digital_ocean_kubernetes_info - Returns information about an existing DigitalOcean Kubernetes cluster

v1.2.0
======

Minor Changes
-------------

- digital_ocean - ``ssh_key_ids`` list entries are now validated to be strings (https://github.com/ansible-collections/community.digitalocean/issues/13).
- digital_ocean_droplet - ``ssh_keys``, ``tags``, and ``volumes`` list entries are now validated to be strings (https://github.com/ansible-collections/community.digitalocean/issues/13).
- digital_ocean_droplet - adding ``active`` and ``inactive`` states (https://github.com/ansible-collections/community.digitalocean/issues/23).
- digital_ocean_droplet - adds Droplet resize functionality (https://github.com/ansible-collections/community.digitalocean/issues/4).

Bugfixes
--------

- digital_ocean inventory script - fail cleaner on invalid ``HOST`` argument to ``--host`` option (https://github.com/ansible-collections/community.digitalocean/pull/44).
- digital_ocean inventory script - implement unimplemented ``use_private_network`` option and register missing ``do_ip_address``, ``do_private_ip_address`` host vars (https://github.com/ansible-collections/community.digitalocean/pull/45/files).
- digital_ocean inventory script - return JSON consistent with specification with ``--host`` (https://github.com/ansible-collections/community.digitalocean/pull/44).
- digital_ocean_domain - return zone records when creating a new zone (https://github.com/ansible-collections/community.digitalocean/issues/46).
- digital_ocean_droplet - add missing ``required=True`` on ``do_oauth_token`` in ``argument_spec`` (https://github.com/ansible-collections/community.digitalocean/issues/13).
- digital_ocean_floating_ip - fixes idempotence (https://github.com/ansible-collections/community.digitalocean/issues/5).

New Modules
-----------

- digital_ocean_balance_info - Display DigitalOcean customer balance

v1.1.1
======

Bugfixes
--------

- digitalocean - Drop collection version from README.md (https://github.com/ansible-collections/community.digitalocean/issues/63).

v1.1.0
======

Minor Changes
-------------

- digital_ocean_block_storage - included ability to resize Block Storage Volumes (https://github.com/ansible-collections/community.digitalocean/issues/38).

Bugfixes
--------

- digital_ocean_certificate_info - fix retrieving certificate by ID (https://github.com/ansible-collections/community.digitalocean/issues/35).
- digital_ocean_domain - module is now idempotent when called without IP (https://github.com/ansible-collections/community.digitalocean/issues/21).
- digital_ocean_load_balancer_info - fix retrieving load balancer by ID (https://github.com/ansible-collections/community.digitalocean/issues/35).

New Plugins
-----------

Inventory
~~~~~~~~~

- digitalocean - DigitalOcean Inventory Plugin

New Modules
-----------

- digital_ocean_domain_record - Manage DigitalOcean domain records
- digital_ocean_firewall - Manage cloud firewalls within DigitalOcean

v1.0.0
======

Bugfixes
--------

- Sanity test documentation fixes (https://github.com/ansible-collections/community.digitalocean/pull/3).
- Update docs examples to use FQCN (https://github.com/ansible-collections/community.digitalocean/issues/14).

v0.1.0
======

Release Summary
---------------

Initial release of the collection after extracing the modules from `community.general <https://github.com/ansible-collections/community.general/>`_.
