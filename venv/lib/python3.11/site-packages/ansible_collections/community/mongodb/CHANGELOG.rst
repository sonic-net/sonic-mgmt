===============================
Community.MongoDB Release Notes
===============================

.. contents:: Topics

v1.7.10:
=========

Release Summary
----------------

This release is a maintenance release.

Minor Changes
--------------

- 695 - mongodb_linux - New method for managing THP (#697).
- 696 & 703 - Minor documentation improvements.

v1.7.9:
=========

Release Summary
----------------

This release is a maintenance release.

Bugfixes
---------
- 684 - mongodb_shell / Rework escapre_param to work on Python 3.13.
- 689 - mongodb_mongod & mongodb_config - Make version compare Jinja2 filter more robust to work across Python versions.

v 1.7.8:
=========

Release Summary
----------------

This release is a maintenance release.

Minor Changes
--------------
      
- 681 - mongodb_repository - Updates the default of apt_key_url.

v 1.7.7:
=========

Release Summary
----------------

This release is a maintenance release.

Bug Fixes
----------

- 678 - mongodb_shell - This module did not implement the standard connection_options 
        feature since it is not a pymongo module. This has now been implemented in this module.
        The connection_options parameter will be parsed, in a similar way to pymongo based modules,
        and those options will be appended to the mongodb connection url. 
        e.g. mongodb://localhost:3001/test?replicaSet=myReplSet

Minor Changes
--------------

- 675 & 673 - Minor documentation updates.

v 1.7.6:
=========

Release Summary
----------------

This release is a maintenance release.

Bug Fixes
----------
      
- 666 - mongodb_linux - Fix check for Transparent Huge Pages.
- 669 - mongodb_common - Replaces readfp function with read_file to support Python 3.12.

Minor Changes
--------------

- 667 - Several modules - Minor documentation update.

v1.7.5:
=========

Release Summary
----------------

This release is a maintenance release.

Minor Changes
-------------
      
- 648 - mongodb_auth - make create_for_localhost_exception configurable.
- 653 - mongodb_auth - Use mongod_host variable instead of hardcoded localhost.
- 657 - mongodb_common (all modules) - Handle arbiters in test for auth. This was done for the mongodb_status module but affects all modules using this shared code.
- 660 - runtime.yml - Adds atlas, mongodb and all action_groups to collection.

v1.7.4:
=========

Release Summary
----------------

This release is a maintenance release.

Minor Changes
-------------

- 644 - mongodb_shell - Add ssl/tls options.

v1.7.3:
=========

Release Summary
----------------

This release is a maintenance release.

Bug Fixes
----------

- 641 - mongodb_mongod -  Add test condition for storage option in mongod.conf template file.

v1.7.2:
=========

Release Summary
----------------

This release is a maintenance release.

Bug Fixes
----------

- 638 - mongodb_replicaset - Allow module to update replicaset horizons.

v1.7.1:
=========

Release Summary
----------------

This release is a maintenance release.

Bug Fixes
----------

- 631 - cache/mongodb.py - Support pymongo 4.0+. This plugin no longer support pymongo 3.12.*.

v1.7.0:
=========

Release Summary
----------------

This release is a maintenance release.

Minor Changes
--------------

- 622 - mongodb_mongod - Allow systemd configuration override.
- 620 - mongodb_common - Use SSL constants in shared connection code.
- 609 - mongodb_mongod, mongodb_mongos, mongodb_config - support for allowConnectionsWithoutCertificates.
- 605 - mongodb_mongod, mongodb_mongos, mongodb_config - support for security.disabledProtocols.

Bug Fixes
----------

- 614 - mongodb_replicaset - Count voting members based on the sum of "votes" and using a comprehension list.
- 611 - mongodb_role - lambda function changed to support non-existing keys.

Modules
---------

- 612 - mongodb_atlas_cluster - Manage database clusters in Atlas (#612).
- 612 - mongodb_atlas_ldap_user - Manage ldap users in Atlas (#612).
- 612 - mongodb_atlas_user - Manage database users in Atlas (#612).
- 612 - mongodb_atlas_whitelist - Manage IP whitelists in Atlas (#612).

v1.6.3:
========

Release Summary
---------------

This release is a maintenance release.

Minor Changes
--------------

- 600 - Remove delete module from README.md.
- 601 - mongodb_install - Fix issue with specific_mongodb_version on RedHat OS family.

v1.6.2:
========

Release Summary
---------------

This release is a maintenance release.

Minor Changes
--------------

- 583 - mongodb_linux - Add vars for RedHat 9 to role.
- 586 - mongodb_auth - Add ssl vars to role.
- 589 - mongodb_linux - Adds vars to better handle ntp package installation and handling.
- 588 - mongodb_linux - Default ntp system to systemd-timesyncd for Debian12.
- 593 - mongodb_linux - Add vm.max_map_count = 128000 sysctl config.
- 597 - mongodb_monitoring - Module has been deleted as Free Monitoring service has been stopped.
- 595 - mongodb_linux - Improvements to transparent_hugepage handling.

v1.6.1:
========

Release Summary
---------------

This release is a maintenance release.

Minor Changes
--------------

- 578 - mongodb_role - More robust comparison of user roles.

v1.6.0:
========

Release Summary
---------------

This release is a maintenance release.

Minor Changes
--------------

- 569 - All pymongo modules - Better support for MongoDB Atlas.
- 568 - Minor documentation updates.

v1.5.2
=======

Release Summary
---------------

This release is a maintenance release.

Minor Changes
--------------

- 558 mongodb_replicaset - Minor documentation update.

Bug Fixes
----------

- 558 mongodb_replicaset - Minor documentation update.


v1.5.1
=======

Release Summary
---------------

This release is a maintenance release.


Bug Fixes
----------

- 534 mongodb_selinux - Reinstall SELinux policy when changed.

v1.5.0
=======

Release Summary
---------------

This release is a maintenance release.

Minor Changes
--------------

- 544 mongodb_replicaset - Module documentation improvements.
- 494 mongodb_shutdown - Fix examples block.
- 491 mongodb_shell - Add feature to detect if mongo or mongosh is available.
- 530 mongodb_role - Adds new module to manage MongoDB roles.
- 547 mongodb_repository - Bump default of MongoDB to 6.0.
- 536 mongodb_auth - Add user after enabling authentication.
- 528 multiple roles - Use first ip address when multiple bind IPs provided.
- 524 mongodb_auth - Add supports for Amazon Linux 2.
- 514 mongodb_linux - Remove extended FQCN for pam_limits.
- 511 mongodb_auth - Adds support for deletion of users.
- 494 mongodb_auth - Removes module_defaults from role.

Bug Fixes
----------

- 540 mongodb_replicaset - replicaset member priority updates.
- 488 mongodb_info - Better handling of json data types.

Modules
--------

- 533 - mongodb_role - Manage MongoDB User Roles-

v1.4.2
=======

Release Summary
---------------

This release is a maintenance release.

Minor Changes
--------------

- 483 - Removes previous upper bound restriction for communiry.general collection,
- 483 - Use extended FQCN for pam_limits (community.general.system.pam_limits instead of community.general.pam_limits).

v1.4.1
=======

Release Summary
---------------

This release is a maintenance release.

Minor Changes
--------------

- 474 - Adds log_path parameter to mongodb_mongod, mongodb_mongos and mongodb_config roles.

Bugfixes
--------

- 479 - mongodb_shell - Correct supports_check_mode value. Used to be true, which is wrong, now false.

v1.4.0
=======

Release Summary
---------------

This release is a maintenance release.
Pymongo versions 3.12.* or 4.* are now required.
MongoDB version 4+ are also required but can be overriden if desired.

Major Changes
---------------

- 470 - Removes depreciated distutils package and require Pymongo 3.12+ and MongoDB 4+
  Adds a new parameter strict_compatibility (default true).
  Set to false to disable Pymongo and MongoDB requirements.

v1.3.4
=======

Release Summary
---------------

This release is a maintenance release.

Bug Fixes
---------

- 466 & 467 - Fixes localhost exception bug due to directConnection parameter in newer pymongo versions.

v1.3.3
=======

Release Summary
---------------

This release is a maintenance release.

Bug Fixes
---------

- 448 - Fix issue in roles where mongod does not restart when a custom bind_ip is set.
- 440 - Fix incorrect alias ssl_crlfile.
- 450 - Fix issues with mongodb_replicaset connecting with the pymongo 4.0.X driver.

Minor Changes
---------------

- 450 - mongodb_replicaset. Introduce cluster_cmd parameter. Can be set to isMaster or hello.
  Hello is the default. isMaster is useful for older versions of MongoDB.
  See [db.hello()](https://www.mongodb.com/docs/manual/reference/method/db.hello/) for more.

v1.3.2
=======

Release Summary
---------------

This release is a maintenance release.

Minor Changes
---------------

- 413 - mongodb_shell - Adds escape_param function that will work better across various python versions.
- 414-416 - Minor documentation improvements.
- 411 - mongodb_shell - FIx missing db parameter when fiel parmeter is used.
- 403 - Make db path configurable in roles.
- 401 - mongodb_replicaset - Add further examples.
- 399 - Removes unused imports from modules.
- 396 - Add tags to roles.
- 387 - Fix doucmentation for mongod cache plugin.

Major Changes
---------------

- 397 & 376 - mongodb_replicaset - Add reconfigure abilities to module. Add and removes members from replicasets.

v1.3.1
======

Release Summary
---------------

This release is a maintenance release. The GitHub CI has been updated to include MongoDB 5.0 as well
as a few new features. The mongosh shell is now supported in the mongodb_shell module. Support for the
old mongo shell will be removed in a future release.

Minor Changes
-------------

- 360 - mongodb_shell - Adds support for the mongosh shell now available with MongoDB 5.0.
- 368 - mongodb_shell - Use shlex escape function.
- 370 - mongodb_install - Adds mongodb_hold_packages variable. Runs the lock_mongodb_packages.sh script
  to either lock mongodb-org packages at a specific version or to release the lock.
  Set to "HOLD" or "NOHOLD" as desired. No checks are made to see if the hold already exists or not.
  By default this variable is undefined and the script is not executed.
  The task is executed at the end and it is possible that packages could be upgraded
  before the lock is initially applied.

Deprecated Features
-------------------

- mongodb_shell - Support for the mongo shell is deprecated and will be removed in a future version.

v1.3.0
======

Release Summary
---------------

This release improves sharded cluster management, and adds schema validator management.
Several bug fixes improve compatibility with python3.6.


Minor Changes
-------------

- 338 - role monogdb_repository - Variablize repository details.
- 345 - roles mongodb_config, mongodb_mongod, mongodb_mongos - Make security.keyFile configurable.
- 346 - roles mongodb_config, mongodb_mongod, mongodb_mongos - Allow using net.bindIpAll instead of net.bindIp.
- 347 - roles mongodb_config, mongodb_mongod, mongodb_mongos - Allow overriding net.compression.compressors in mongo*.conf

Security Fixes
--------------

- 312 - Set no_log True for ssl_keyfile.

Bugfixes
--------

- 315 - Fix exception handling for mongodb_stepdown module on python3.6
- 320 - Fix exception handling for modules mongodb_balancer, mongodb_shard, and mongodb_status.
- 352 - Add ansible.posix collection to dependencies list.

New Modules
-----------

- community.mongodb.mongodb_monitoring - Manages the free monitoring feature.
- community.mongodb.mongodb_schema - Manages MongoDB Document Schema Validators.
- community.mongodb.mongodb_shard_tag - Manage Shard Tags.
- community.mongodb.mongodb_shard_zone - Manage Shard Zones.

v1.2.1
======

Minor Changes
-------------

- 304 - Adds validate parameter to mongodb_status module.

v1.2.0
======

Release Summary
---------------

A variety of idempotency and reliability improvements.


Bugfixes
--------

- 281 - mongodb_linux Fixes disable-transparent-huge-pages.service idempotency.
- 282 - Add restart handler, and bool variable to control to mongofb_config/mongod/mongos roles.
- 285 - Output users and roles dict by database to avoid overwriting entries.
- 287 - Fixes return value on older versions of MongoDB.
- 290 - Adds pseudo-idempotency feature to module.

v1.1.2
======

Bugfixes
--------

- 252 - Fix config template override in various roles.
- 255 - Add replica_set param to mongodb_index module.
- 264 - Only add force parameter to shutdown command when set to true.
- 275 - Use OrderedDict class in the following modules, mongodb_balancer, mongodb_oplog, mongodb_shutdown.

v1.1.1
======

Bugfixes
--------

- 235 - Fix namespace.

v1.1.0
======

Release Summary
---------------

This release adds the mongodb_shell module and the mongodb_auth role.


New Modules
-----------

- community.mongodb.mongodb_shell - Run commands via the MongoDB shell.

New Roles
---------

- community.mongodb.mongodb_auth - Configure auth on MongoDB servers.

v1.0.0
======

Release Summary
---------------

The first stable release of the commmunity.mongodb collection.
Many of the plugins and modules were previously released in ansible itself.


New Plugins
-----------

Cache
~~~~~

- community.mongodb.mongodb - This cache uses per host records saved in MongoDB.

Lookup
~~~~~~

- community.mongodb.mongodb - The ``MongoDB`` lookup runs the *find()* command on a given *collection* on a given *MongoDB* server.

New Modules
-----------

- community.mongodb.mongodb_balancer - Manages the MongoDB Sharded Cluster Balancer.
- community.mongodb.mongodb_index - Creates or drops indexes on MongoDB collections.
- community.mongodb.mongodb_info - Gather information about MongoDB instance.
- community.mongodb.mongodb_maintenance - Enables or disables maintenance mode for a secondary member.
- community.mongodb.mongodb_oplog - Resizes the MongoDB oplog.
- community.mongodb.mongodb_parameter - Change an administrative parameter on a MongoDB server
- community.mongodb.mongodb_replicaset - Initialises a MongoDB replicaset.
- community.mongodb.mongodb_shard - Add or remove shards from a MongoDB Cluster
- community.mongodb.mongodb_shutdown - Cleans up all database resources and then terminates the mongod/mongos process.
- community.mongodb.mongodb_status - Validates the status of the cluster.
- community.mongodb.mongodb_stepdown - Step down the MongoDB node from a PRIMARY state.
- community.mongodb.mongodb_user - Adds or removes a user from a MongoDB database

New Roles
---------

- community.mongodb.mongodb_config - Configure the CSRS Config Server Replicaset for a MongoDB sharded cluster. (Use mongodb_mongod for Standalone installations - this does not create mongo.conf)
- community.mongodb.mongodb_install - Install MongoDB packages on Debian and RedHat based platforms.
- community.mongodb.mongodb_linux - A simple role to configure Linux Operating System settings, as advised in the MongoDB Production Notes.
- community.mongodb.mongodb_mongod - Configure the mongod service (includes populating mongod.conf) which is a MongoDB replicaset or standalone server.
- community.mongodb.mongodb_mongos - Configure the mongos service (includes populating mongos.conf) which only runs in a sharded MongoDB cluster.
- community.mongodb.mongodb_repository - Configures a package repository for MongoDB on Debian and RedHat based platforms.
- community.mongodb.mongodb_selinux - Configure SELinux for MongoDB.
