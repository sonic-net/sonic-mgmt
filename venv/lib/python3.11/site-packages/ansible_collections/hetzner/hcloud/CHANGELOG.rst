==============================================
Hetzner Cloud Ansible Collection Release Notes
==============================================

.. contents:: Topics

v5.4.0
======

Release Summary
---------------

This release adds support for the new `DNS API`_.

The DNS API is currently in **beta**, which will likely end on 10
November 2025. After the beta ended, it will no longer be possible to
create new zones in the old DNS system. See the `DNS Beta FAQ`_ for more
details.

Future minor releases of this project may include breaking changes for
features that are related to the DNS API.

See the `DNS API Beta changelog`_ for more details.

**Examples**

.. code:: yaml

    - name: Create a primary Zone
      hetzner.hcloud.zone:
        name: example.com
        mode: primary
        labels:
          key: value
        state: present

    - name: Create a Zone RRSet
      hetzner.hcloud.zone_rrset:
        zone: example.com
        name: "@"
        type: A
        records:
          - comment: server1
            value: 201.118.10.2
        state: present

.. _DNS Beta FAQ: https://docs.hetzner.com/networking/dns/faq/beta
.. _DNS API: https://docs.hetzner.cloud/reference/cloud#dns
.. _DNS API Beta changelog: https://docs.hetzner.cloud/changelog#2025-10-07-dns-beta

Minor Changes
-------------

- zone - New module to manage DNS Zones in Hetzner Cloud.
- zone_info - New module to fetch DNS Zones details.
- zone_rrset - New module to manage DNS Zone RRSets in the Hetzner Cloud.
- zone_rrset_info - New module to fetch DNS RRSets details.

v5.3.1
======

Bugfixes
--------

- server - Also check server type deprecation after server creation.

v5.3.0
======

Release Summary
---------------

`Server Types`_ now depend on `Locations`_.

- We added a new ``locations`` property to the `Server Types`_ resource. The new
  property defines a list of supported `Locations`_ and additional per `Locations`_
  details such as deprecations information.

- We deprecated the ``deprecation`` property from the `Server Types`_ resource. The
  property will gradually be phased out as per `Locations`_ deprecations are being
  announced. Please use the new per `Locations`_ deprecation information instead.

See our `changelog`_ for more details.

**Upgrading**

.. code:: yaml

    # Before
    ---
    - name: Validate server type
      hosts: localhost
      connection: local
      tasks:
        - name: Fetch server type info
          hetzner.hcloud.server_type_info:
            name: cx22
          register: server_type

        - name: Ensure server type exists
          ansible.builtin.assert:
            fail_msg: server type does not exists
            that:
              - server_type.hcloud_server_type_info | count == 1

        - name: Ensure server type is not deprecated
          ansible.builtin.assert:
            fail_msg: server type is deprecated
            that:
              - server_type.hcloud_server_type_info[0].deprecation is none

.. code:: yaml

    # After
    ---
    - name: Validate server type
      hosts: localhost
      connection: local
      tasks:
        - name: Fetch location info
          hetzner.hcloud.location_info:
            name: fsn1
          register: location

        - name: Fetch server type info
          hetzner.hcloud.server_type_info:
            name: cx22
          register: server_type

        - name: Ensure server type exists
          ansible.builtin.assert:
            fail_msg: server type does not exists
            that:
              - server_type.hcloud_server_type_info | count == 1

        - name: Extract server type location info
          ansible.builtin.set_fact:
            server_type_location: >
              {{
                server_type.hcloud_server_type_info[0].locations
                | selectattr("name", "eq", location.hcloud_location_info[0].name)
                | first
              }}

        - name: Ensure server type is not deprecated
          ansible.builtin.assert:
            fail_msg: server type is deprecated in location
            that:
              - server_type_location.deprecation is none

.. _Server Types: https://docs.hetzner.cloud/reference/cloud#server-types
.. _Locations: https://docs.hetzner.cloud/reference/cloud#locations
.. _changelog: https://docs.hetzner.cloud/changelog#2025-09-24-per-location-server-types

Minor Changes
-------------

- server_type_info - Return new Server Type ``category`` property.
- server_type_info - Return new Server Type ``locations`` property.

Deprecated Features
-------------------

- server_type_info - Deprecate Server Type ``deprecation`` property.

Bugfixes
--------

- floating_ip - Wait for the Floating IP assign action to complete to reduce chances of running into ``locked`` errors.

v5.2.0
======

Minor Changes
-------------

- volume - Allow renaming a volume.

Bugfixes
--------

- volume_attachment - Add ``hcloud_volume_attachment`` alias to ``volume_attachment`` module.
- volume_attachment - Add ``volume_attachment`` module to action group ``all``.

v5.1.0
======

Minor Changes
-------------

- ssh_key - Log a warning when the provided public key does not match one in the API.
- ssh_key - When the public key does not match the one in the API, allow recreating the SSH Key in the API using the ``force=true`` argument.

Bugfixes
--------

- All returned resource IDs are now integers instead of strings.
- server - The ``placement_group`` argument now correctly handles placement group IDs during updates.

v5.0.1
======

Breaking Changes / Porting Guide
--------------------------------

- server - The deprecated ``force_upgrade`` argument is removed from the server module. Please use the ``force`` argument instead.

v5.0.0
======

Minor Changes
-------------

- server - Allow renaming a server.
- volume_attachment - Add new `volume_attachment` module to manage Volumes attachment.

Breaking Changes / Porting Guide
--------------------------------

- Drop support for ansible-core 2.15.
- Drop support for ansible-core 2.16.
- Drop support for python 3.8.
- inventory - The default value for the `hostvars_prefix` option is now set to `hcloud_`. Make sure to update all references to host variables provided by the inventory. You may revert this change by setting the `hostvars_prefix` option to `""`.
- volume - Volumes are no longer detached when the server argument is not provided. Please use the ``volume_attachment`` module to manage volume attachments.

v4.3.0
======

Minor Changes
-------------

- server - Add `created` state that creates a server but do not start it.

v4.2.2
======

Bugfixes
--------

- hcloud_load_balancer_service - Improve unknown certificate id or name error.
- hcloud_server - Only rebuild existing servers, skip rebuild if the server was just created.

v4.2.1
======

Bugfixes
--------

- server - Wait up to 30 minutes for every action returned from server create

v4.2.0
======

Minor Changes
-------------

- load_balancer_status - Add new filter to compute the status of a Load Balancer based on its targets.

v4.1.0
======

Release Summary
---------------

**API Changes for Traffic Prices and Server Type Included Traffic**

There will be a breaking change in the API regarding Traffic Prices and Server Type
Included Traffic on 2024-08-05. This release marks the affected fields as
`Deprecated`. Please check if this affects any of your code.

You can learn more about this change in `our changelog <https://docs.hetzner.cloud/changelog#2024-07-25-cloud-api-returns-traffic-information-in-different-format>`_.

Minor Changes
-------------

- Use a truncated exponential backoff algorithm when polling actions from the API.
- server_type_info - The 'included_traffic' return value is deprecated and will be set to 'None' on 5 August 2024. See https://docs.hetzner.cloud/changelog#2024-07-25-cloud-api-returns-traffic-information-in-different-format.

v4.0.1
======

Bugfixes
--------

- server - Keep `force_upgrade` deprecated alias for another major version.

v4.0.0
======

Breaking Changes / Porting Guide
--------------------------------

- Drop support for ansible-core 2.14.

v3.1.1
======

Bugfixes
--------

- inventory - Ensure inventory host variables are serializable and can be cached.

v3.1.0
======

Minor Changes
-------------

- primary_ip - Use the `server` option to assign a Primary IP being created to a server.
- server - Allow passing Datacenter name or ID to the `datacenter` argument.
- server - Allow passing Image name or ID to the `image` argument.
- server - Allow passing Location name or ID to the `location` argument.
- server - Allow passing SSH Keys names or IDs to the `ssh_keys` argument.
- server - Allow passing Volume names or IDs to the `volumes` argument.
- server - Renamed the `allow_deprecated_image` option to `image_allow_deprecated`.

Bugfixes
--------

- primary_ip - Added the missing `auto_delete` field to the return values.
- primary_ip - The `auto_delete` option is now used when creating or updating a Primary IP.
- primary_ip_info - Added the missing `auto_delete` field to the return values.
- server - Do not remove the server from its placement group when the `placement_group` argument is not specified.
- server - Pass an empty string to the `placement_group` argument to remove a server from its placement group.
- server_network - The returned `alias_ips` list is now sorted.

v3.0.0
======

Minor Changes
-------------

- inventory - Add `hostname` option used to template the hostname of the instances.
- network - Allow renaming networks.

Breaking Changes / Porting Guide
--------------------------------

- Drop support for ansible-core 2.13.
- certificate - The `not_valid_before` and `not_valid_after` values are now returned as ISO-8601 formatted strings.
- certificate_info - The `not_valid_before` and `not_valid_after` values are now returned as ISO-8601 formatted strings.
- inventory - Remove the deprecated `api_token_env` option, you may use the `ansible.builtin.env` lookup as alternative.
- iso_info - The `deprecated` value is now returned as ISO-8601 formatted strings.

Bugfixes
--------

- load_balancer_info - Correctly return the `cookie_lifetime` value.
- load_balancer_service - Correctly return the `cookie_lifetime` value.

v2.5.0
======

Minor Changes
-------------

- Replace deprecated `ansible.netcommon` ip utils with python `ipaddress` module. The `ansible.netcommon` collection is no longer required by the collections.
- firewall - Allow forcing the deletion of firewalls that are still in use.
- firewall - Do not silence 'firewall still in use' delete failures.
- firewall - Return resources the firewall is `applied_to`.
- firewall_info - Add new `firewall_info` module to gather firewalls info.
- firewall_resource - Add new `firewall_resource` module to manage firewalls resources.
- inventory - Add `hostvars_prefix` and hostvars_suffix` options to customize the inventory host variables keys.

New Modules
-----------

- firewall_resource - Manage Resources a Hetzner Cloud Firewall is applied to.

v2.4.1
======

Bugfixes
--------

- hcloud inventory - Ensure the API client use a new cache for every *cached session*.

v2.4.0
======

Minor Changes
-------------

- Add the `hetzner.hcloud.all` group to configure all the modules using `module_defaults`.
- Allow to set the `api_endpoint` module argument using the `HCLOUD_ENDPOINT` environment variable.
- Removed the `hcloud_` prefix from all modules names, e.g. `hetzner.hcloud.hcloud_firewall` was renamed to `hetzner.hcloud.firewall`. Old module names will continue working.
- Renamed the `endpoint` module argument to `api_endpoint`, backward compatibility is maintained using an alias.
- hcloud inventory - Add the `api_endpoint` option.
- hcloud inventory - Deprecate the `api_token_env` option, suggest using a lookup plugin (`{{ lookup('ansible.builtin.env', 'YOUR_ENV_VAR') }}`) or use the well-known `HCLOUD_TOKEN` environment variable name.
- hcloud inventory - Rename the `token_env` option to `api_token_env`, use aliases for backward compatibility.
- hcloud inventory - Rename the `token` option to `api_token`, use aliases for backward compatibility.

v2.3.0
======

Minor Changes
-------------

- hcloud_datacenter_info - Add `server_types` field
- hcloud_server - Add `created` field
- hcloud_server_info - Add `created` field

v2.2.0
======

Minor Changes
-------------

- hcloud_iso_info - Add deprecation field
- hcloud_load_balancer_network - Allow selecting a `load_balancer` or `network` using its ID.
- hcloud_load_balancer_service - Allow selecting a `load_balancer` using its ID.
- hcloud_load_balancer_target - Allow selecting a `load_balancer` or `server` using its ID.
- hcloud_rdns - Allow selecting a `server`, `floating_ip`, `primary_ip` or `load_balancer` using its ID.
- hcloud_route - Allow selecting a `network` using its ID.
- hcloud_server_network - Allow selecting a `network` or `server` using its ID.
- hcloud_subnetwork - Allow selecting to a `network` using its ID.

v2.1.2
======

Bugfixes
--------

- hcloud_firewall - The port argument is required when the firewall rule protocol is `udp` or `tcp`.
- hcloud_load_balancer_service - In the returned data, the invalid `health_check.http.certificates` field was renamed to `health_check.http.status_codes`.

v2.1.1
======

Bugfixes
--------

- hcloud_server - Fix string formatting error on deprecated server type warning

v2.1.0
======

Minor Changes
-------------

- Use the collection version in the hcloud user-agent instead of the ansible-core version.
- hcloud_floating_ip_info - Allow querying floating ip by name.
- hcloud_load_balancer_info - Add targets health status field.
- inventory - Allow caching the hcloud inventory.

Bugfixes
--------

- `*_info` - Consistently fail on invalid ID in `*_info` modules.

v2.0.0
======

Release Summary
---------------

This release bundles the hcloud dependency in the collection, this allows us to ship new features or bug fixes without having to release new major versions and require the users to upgrade their version of the hcloud dependency.

Minor Changes
-------------

- Bundle hcloud python dependency inside the collection.
- python-dateutil >= 2.7.5 is now required by the collection. If you already have the hcloud package installed, this dependency should also be installed.
- requests >= 2.20 is now required by the collection. If you already have the hcloud package installed, this dependency should also be installed.

Breaking Changes / Porting Guide
--------------------------------

- Drop support for ansible-core 2.12
- Drop support for python 3.7
- inventory plugin - Don't set the server image variables (`image_id`, `image_os_flavor` and `image_name`) when the server image is not defined.

Removed Features (previously deprecated)
----------------------------------------

- hcloud_datacenter_facts Removed deprecated facts module
- hcloud_floating_ip_facts Removed deprecated facts module
- hcloud_image_facts Removed deprecated facts module
- hcloud_location_facts Removed deprecated facts module
- hcloud_server_facts Removed deprecated facts module
- hcloud_server_type_facts Removed deprecated facts module
- hcloud_ssh_key_facts Removed deprecated facts module
- hcloud_volume_facts Removed deprecated facts module

v1.16.0
=======

Release Summary
---------------

This release bundles the hcloud dependency in the collection, this allows us to ship new features or bug fixes without having to release new major versions and require the users to upgrade their version of the hcloud dependency.

Minor Changes
-------------

- Bundle hcloud python dependency inside the collection.
- python-dateutil >= 2.7.5 is now required by the collection. If you already have the hcloud package installed, this dependency should also be installed.
- requests >= 2.20 is now required by the collection. If you already have the hcloud package installed, this dependency should also be installed.

v1.15.0
=======

Minor Changes
-------------

- hcloud_iso_info Create hcloud_iso_info module

Bugfixes
--------

- hcloud_image_info Fix facts modules deprecated result key
- hcloud_location_info Fix facts modules deprecation warnings
- hcloud_server_type_info Fix facts modules deprecated result dict
- hcloud_server_type_info Fix facts modules deprecation warnings

v1.14.0
=======

Minor Changes
-------------

- hcloud_network Add expose_routes_to_vswitch field.
- hcloud_network_info Return expose_routes_to_vswitch for network.

v1.13.0
=======

Minor Changes
-------------

- hcloud_primary_ip_info Create hcloud_primary_ip_info module
- hcloud_server Show warning if used server_type is deprecated.
- hcloud_server_type_info Return deprecation info for server types.

Bugfixes
--------

- hcloud_server - TypeError when trying to use deprecated image with allow_deprecated_image

v1.12.0
=======

Minor Changes
-------------

- hcloud_server_type_info - Add field included_traffic to returned server types

Breaking Changes / Porting Guide
--------------------------------

- hcloud-python 1.20.0 is now required for full compatibility

v1.11.0
=======

Minor Changes
-------------

- hcloud_image_info - Add cpu architecture field to return value.
- hcloud_image_info - Allow filtering images by cpu architecture.
- hcloud_server - Select matching image for the cpu architecture of the server type on create & rebuild.
- hcloud_server_type_info - Add cpu architecture field to return value.
- inventory plugin - Add cpu architecture to server variables.

v1.10.1
=======

Bugfixes
--------

- hcloud_server - Prevent backups from being disabled when undefined
- hcloud_server - Server locked after attaching to placement group

v1.10.0
=======

Minor Changes
-------------

- hcloud_server - add private_networks_info containing name and private ip in responses
- hcloud_server_info - add private_networks_info containing name and private ip in responses
- inventory plugin - Add list of all private networks to server variables.
- inventory plugin - Add new connect_with setting public_ipv6 to connect to discovered servers via public IPv6 address.
- inventory plugin - Add public IPv6 address to server variables.
- inventory plugin - Log warning instead of crashing when some servers do not work with global connect_with setting.

Breaking Changes / Porting Guide
--------------------------------

- inventory plugin - Python v3.5+ is now required.

v1.9.1
======

Bugfixes
--------

- hcloud_server - externally attached networks (using hcloud_server_network) were removed when not specified in the hcloud_server resource

v1.9.0
======

Minor Changes
-------------

- dynamic inventory - add support changing the name of the top level group all servers are added to
- hcloud_firewall - add support for esp and gre protocols

Bugfixes
--------

- hcloud_firewall - the deletion could fail if the firewall was referenced right before
- hcloud_server - fix backup window was given out as "None" instead of null
- hcloud_server_info - fix backup window was given out as "None" instead of null
- hcloud_volume - fix server name was given out as "None" instead of null if no server was attached
- hcloud_volume_info - fix server name was given out as "None" instead of null if no server was attached

v1.8.2
======

Bugfixes
--------

- dynamic inventory - fix crash when having servers without IPs (flexible networks)
- hcloud_server - When state stopped and server is created, do not start the server
- hcloud_server_info - fix crash when having servers without IPs (flexible networks)

v1.8.1
======

v1.8.0
======

New Modules
-----------

Hetzner
~~~~~~~

hcloud
^^^^^^

- hetzner.hcloud.hcloud_primary_ip - Create and manage cloud Primary IPs on the Hetzner Cloud.

v1.7.1
======

Minor Changes
-------------

- inventory - allow filtering by server status

Bugfixes
--------

- hcloud_server_network - fixes changed alias_ips by using sorted

v1.7.0
======

Minor Changes
-------------

- inventory - support jinjia templating within `network`

v1.6.0
======

Minor Changes
-------------

- hcloud_rdns Add support for load balancer

v1.5.0
======

Major Changes
-------------

- Introduction of placement groups

Minor Changes
-------------

- hcloud_firewall Add description field to firewall rules

Bugfixes
--------

- hcloud_rdns improve error message on not existing server/Floating IP
- hcloud_server backups property defaults to None now instead of False

v1.4.4
======

Bugfixes
--------

- hcloud_server Improve Error Message when attaching a not existing firewall to a server
- hcloud_volume Force detaching of volumes on servers before deletion

v1.4.3
======

Bugfixes
--------

- hcloud_server Fix incompatbility with python < 3.6
- hcloud_server Improve error handling when using not existing server types

v1.4.2
======

Bugfixes
--------

- inventory fix image name was set as server type instead of the correct server type

v1.4.1
======

Minor Changes
-------------

- hcloud_server - improve the handling of deprecated images
- hcloud_server - improve the validation and error response for not existing images
- inventory - support jinjia templating within `token`

v1.4.0
======

Security Fixes
--------------

- hcloud_certificate - mark the ``private_key`` parameter as ``no_log`` to prevent potential leaking of secret values (https://github.com/ansible-collections/hetzner.hcloud/pull/70).

Bugfixes
--------

- hcloud_firewall - fix idempotence related to rules comparison (https://github.com/ansible-collections/hetzner.hcloud/pull/71).
- hcloud_load_balancer_service - fix imported wrong HealthCheck from hcloud-python (https://github.com/ansible-collections/hetzner.hcloud/pull/73).
- hcloud_server - fix idempotence related to firewall handling (https://github.com/ansible-collections/hetzner.hcloud/pull/71).

v1.3.1
======

Bugfixes
--------

- hcloud_server - fix a crash related to check mode if ``state=started`` or ``state=stopped`` (https://github.com/ansible-collections/hetzner.hcloud/issues/54).

v1.3.0
======

Minor Changes
-------------

- Add firewalls to hcloud_server module

New Modules
-----------

- hcloud_firewall - Manage Hetzner Cloud Firewalls

v1.2.1
======

Bugfixes
--------

- Inventory Restore Python 2.7 compatibility

v1.2.0
======

Minor Changes
-------------

- Dynamic Inventory Add option to specifiy the token_env variable which is used for identification if now token is set
- Improve imports of API Exception
- hcloud_server_network Allow updating alias ips
- hcloud_subnetwork Allow creating vswitch subnetworks

New Modules
-----------

- hcloud_load_balancer_info - Gather infos about your Hetzner Cloud load_balancers.

v1.1.0
======

Minor Changes
-------------

- hcloud_floating_ip Allow creating Floating IP with protection
- hcloud_load_balancer Allow creating Load Balancer with protection
- hcloud_network Allow creating Network with protection
- hcloud_server Allow creating server with protection
- hcloud_volume Allow creating Volumes with protection

Bugfixes
--------

- hcloud_floating_ip Fix idempotency when floating ip is assigned to server

v1.0.0
======

Minor Changes
-------------

- hcloud_load_balancer Allow changing the type of a Load Balancer
- hcloud_server Allow the creation of servers with enabled backups

v0.2.0
======

Bugfixes
--------

- hcloud inventory plugin - Allow usage of hcloud.yml and hcloud.yaml - this was removed by error within the migration from build-in ansible to our collection

v0.1.0
======

New Modules
-----------

- hcloud_floating_ip - Create and manage cloud Floating IPs on the Hetzner Cloud.
- hcloud_load_balancer - Create and manage cloud Load Balancers on the Hetzner Cloud.
- hcloud_load_balancer_network - Manage the relationship between Hetzner Cloud Networks and Load Balancers
- hcloud_load_balancer_service - Create and manage the services of cloud Load Balancers on the Hetzner Cloud.
- hcloud_load_balancer_target - Manage Hetzner Cloud Load Balancer targets
- hcloud_load_balancer_type_info - Gather infos about the Hetzner Cloud Load Balancer types.
