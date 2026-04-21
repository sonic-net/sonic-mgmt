================================
Community.Rabbitmq Release Notes
================================

.. contents:: Topics

v1.6.0
======

Release Summary
---------------

This is the minor release of the ``community.rabbitmq`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- rabbitmq_policy - add support to policy manipulation through RabbitMQ API (https://github.com/ansible-collections/community.rabbitmq/issues/203)
- rabbitmq_vhost - make rabbitmqctl optional when configuring vhosts using the RabbitMQ API (https://github.com/ansible-collections/community.rabbitmq/issues/201)

Bugfixes
--------

- rabbitmq_user - URL encode the `vhost` and `user` fields to allow for input with '/' characters. (https://github.com/ansible-collections/community.rabbitmq/issues/205)
- rabbitmq_vhost - Fail module if the requests library is missing. This maintains the same behavior across all the modules.
- setup_rabbitmq - incorrect SSL library was selected for install on Ubuntu Noble. Fix now installs the correct version on newer Ubuntu versions. (https://github.com/ansible-collections/community.rabbitmq/issues/199)

v1.5.0
======

Release Summary
---------------

This is the minor release of the ``community.rabbitmq`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- rabbitmq_vhost - add support to vhost manipulation through RabbitMQ API (https://github.com/ansible-collections/community.rabbitmq/issues/171)

Bugfixes
--------

- rabbitmq_binding - fix idempotency when arguments and/or routing_key are given (https://github.com/ansible-collections/community.rabbitmq/pull/191)

v1.4.0
======

Release Summary
---------------

This is the minor release of the ``community.rabbitmq`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the previous release.

Minor Changes
-------------

- rabbitmq_policy - adjust the `apply_to` parameter to also accept the new options `classic_queues`, `quorum_queues` and `streams` which are supported since rabbitmq 3.12

Bugfixes
--------

- rabbitmq_publish - fix support for publishing headers as a part of a message (https://github.com/ansible-collections/community.rabbitmq/pull/182)

v1.3.0
======

Release Summary
---------------

This is the minor release of the ``community.rabbitmq`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the 1.2.3 release.

Minor Changes
-------------

- rabbitmq_user - add support to user manipulation through RabbitMQ API (https://github.com/ansible-collections/community.rabbitmq/issues/76)

v1.2.3
======

Release Summary
---------------

This is the minor release of the ``community.rabbitmq`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the 1.2.2 release.

Minor Changes
-------------

- rabbitmq_exchange - adding ability to specify exchange types that are enabled via plugins. I(x-random), I(x-consistent-hash) and I(x-recent-history) (https://github.com/ansible-collections/community.rabbitmq/pull/142).
- rabbitmq_publish - fixing issue with publishing to exchanges and adding exchange documentation examples. Publishing to an exchange or queue is now mutually exclusive (https://github.com/ansible-collections/community.rabbitmq/pull/140).

Bugfixes
--------

- Various CI fixes (https://github.com/ansible-collections/community.rabbitmq/pull/139 & https://github.com/ansible-collections/community.rabbitmq/pull/141).
- rabbitmq_queue - fixing an issue where a special character in the queue name would result in an API error (https://github.com/ansible-collections/community.rabbitmq/issues/114).

v1.2.2
======

Release Summary
---------------

This is the minor release of the ``community.rabbitmq`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the 1.2.1 release.

Bugfixes
--------

- user module - set supports_check_mode flag to False, as the module does not actually support check mode.

v1.2.1
======

Release Summary
---------------

This is the minor release of the ``community.rabbitmq`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the 1.2.0 release.

Bugfixes
--------

- Include ``PSF-license.txt`` file for ``plugins/module_utils/_version.py``.

v1.2.0
======

Release Summary
---------------

This is the minor release of the ``community.rabbitmq`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after the 1.1.0 release.

Minor Changes
-------------

- rabbitmq_user - add support for `topic authorization <https://www.rabbitmq.com/access-control.html#topic-authorisation>`_ (featured in RabbitMQ 3.7.0) (https://github.com/ansible-collections/community.rabbitmq/pull/73).

Bugfixes
--------

- Collection core functions - use vendored version of ``distutils.version`` instead of the deprecated Python standard library ``distutils``.

v1.1.0
======

Release Summary
---------------

This is the minor release of the ``community.rabbitmq`` collection.
This changelog contains all changes to the modules and plugins in this collection
that have been made after release 1.0.3.

Bugfixes
--------

- rabbitmq_policy - The ``_policy_check`` piece of the policy module (``policy_data``) is typically list based on a split of the variable ``policy``. However ``policy`` in some cases does not contain data. The fix allows ``tags`` to attempt to load as json first but in the case of failure, assign ``tags`` without using the json loader (https://github.com/ansible-collections/community.rabbitmq/pull/28).

New Modules
-----------

- community.rabbitmq.rabbitmq_feature_flag - Enables feature flag
- community.rabbitmq.rabbitmq_upgrade - Execute rabbitmq-upgrade commands
- community.rabbitmq.rabbitmq_user_limits - Manage RabbitMQ user limits

v1.0.0
======

Minor Changes
-------------

- rabbitmq_publish - Support for connecting with SSL certificates.

Bugfixes
--------

- Refactor RabbitMQ user module to first check the version of the daemon and then, when possible add flags to `rabbitmqctl` so that a machine readable  output is returned. Also, depending on the version, parse the output in correctly. Expands tests accordingly. (https://github.com/ansible/ansible/issues/48890)
- rabbitmq lookup plugin - Fix for rabbitmq lookups failing when using pika v1.0.0 and newer.
- rabbitmq_publish - Fix to ensure the module works correctly for pika v1.0.0 and later. (https://github.com/ansible/ansible/pull/61960)
