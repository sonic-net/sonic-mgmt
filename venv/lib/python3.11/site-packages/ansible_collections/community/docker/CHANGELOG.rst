=========================================
Docker Community Collection Release Notes
=========================================

.. contents:: Topics

v4.8.5
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- CLI-based modules - when parsing JSON output fails, also provide standard error output. Also provide information on the command and its result in machine-readable way (https://github.com/ansible-collections/community.docker/issues/1216, https://github.com/ansible-collections/community.docker/pull/1221).
- docker_compose_v2* modules - fix Python 2 compatibility when parsing JSON events (https://github.com/ansible-collections/community.docker/pull/1220).
- docker_compose_v2, docker_compose_v2_pull - adjust parsing from image pull events to changes in Docker Compose 5.0.0 (https://github.com/ansible-collections/community.docker/pull/1219).

v4.8.4
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker_container - when the same port is mapped more than once for the same protocol without specifying an interface, a bug caused an invalid value to be passed for the interface (https://github.com/ansible-collections/community.docker/issues/1213, https://github.com/ansible-collections/community.docker/pull/1214).

v4.8.3
======

Release Summary
---------------

Bugfix release for Docker 29.

Bugfixes
--------

- Docker CLI based modules - work around bug in Docker 29.0.0 that caused a breaking change in ``docker version --format json`` output (https://github.com/ansible-collections/community.docker/issues/1185, https://github.com/ansible-collections/community.docker/pull/1187).
- docker_container - fix ``pull`` idempotency with Docker 29.0.0 (https://github.com/ansible-collections/community.docker/pull/1192).
- docker_container - fix handling of exposed port ranges. So far, the module used an undocumented feature of Docker that was removed from Docker 29.0.0, that allowed to pass the range to the deamon and let handle it. Now the module explodes ranges into a list of all contained ports, same as the Docker CLI does. For backwards compatibility with Docker < 29.0.0, it also explodes ranges returned by the API for existing containers so that comparison should only indicate a difference if the ranges actually change (https://github.com/ansible-collections/community.docker/pull/1192).
- docker_container - fix idempotency for IPv6 addresses with Docker 29.0.0 (https://github.com/ansible-collections/community.docker/pull/1192).
- docker_image - fix ``source=pull`` idempotency with Docker 29.0.0 (https://github.com/ansible-collections/community.docker/pull/1192).
- docker_image, docker_image_push - adjust image push detection to Docker 29 (https://github.com/ansible-collections/community.docker/pull/1199).
- docker_image_pull - fix idempotency with Docker 29.0.0 (https://github.com/ansible-collections/community.docker/pull/1192).
- docker_network - fix idempotency for IPv6 addresses and networks with Docker 29.0.0 (https://github.com/ansible-collections/community.docker/pull/1201).

Known Issues
------------

- docker_container - when specifying IPv6 addresses for networks, Docker since version 29 no longer returns the orignal address used when adding a container to a network, but normalizes them. The module will try to normalize IP addresses for comparison, but it uses the ``ipaddress`` module from the Python 3 standard library for that. When using the module with Python 2, please install the `ipaddress backport for Python 2.x <https://pypi.org/project/ipaddress/>`__ (https://github.com/ansible-collections/community.docker/pull/1198).
- docker_image, docker_image_export - idempotency for archiving images depends on whether the image IDs used by the image storage backend correspond to the IDs used in the tarball's ``manifest.json`` files. The new default backend in Docker 29 apparently uses image IDs that no longer correspond, whence idempotency no longer works (https://github.com/ansible-collections/community.docker/pull/1199).
- docker_network - when specifying IPv6 addresses or networks, Docker since version 29 no longer returns the orignal address/network used when creating a network, but normalizes them. The module will try to normalize IP addresses for comparison, but it uses the ``ipaddress`` module from the Python 3 standard library for that. When using the module with Python 2, please install the `ipaddress backport for Python 2.x <https://pypi.org/project/ipaddress/>`__ (https://github.com/ansible-collections/community.docker/pull/1203).

v4.8.2
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker connection plugin - fix crash instead of warning if Docker version does not support ``remote_user`` (https://github.com/ansible-collections/community.docker/pull/1161).
- docker, nsenter connection plugins - fix handling of ``become`` plugin password prompt handling in case multiple events arrive at the same time (https://github.com/ansible-collections/community.docker/pull/1158).
- docker_api connection plugin - fix bug that could lead to loss of data when waiting for ``become`` plugin prompt (https://github.com/ansible-collections/community.docker/pull/1152).
- docker_compose_v2_exec - fix crash instead of reporting error if ``detach=true`` and ``stdin`` is provided (https://github.com/ansible-collections/community.docker/pull/1161).
- docker_compose_v2_run - fix crash instead of reporting error if ``detach=true`` and ``stdin`` is provided (https://github.com/ansible-collections/community.docker/pull/1161).
- docker_container_exec - fix bug that could lead to loss of stdout/stderr data (https://github.com/ansible-collections/community.docker/pull/1152).
- docker_container_exec - make ``detach=true`` work. So far this resulted in no execution being done (https://github.com/ansible-collections/community.docker/pull/1145).
- docker_plugin - fix diff mode for plugin options (https://github.com/ansible-collections/community.docker/pull/1146).

v4.8.1
======

Release Summary
---------------

Maintenance release.

Minor Changes
-------------

- Note that some new code in ``plugins/module_utils/_six.py`` is MIT licensed (https://github.com/ansible-collections/community.docker/pull/1138).

Bugfixes
--------

- Avoid remaining usages of deprecated ``ansible.module_utils.six`` (https://github.com/ansible-collections/community.docker/pull/1133).
- Avoid usage of deprecated ``ansible.module_utils.six`` in all code that does not have to support Python 2 (https://github.com/ansible-collections/community.docker/pull/1137, https://github.com/ansible-collections/community.docker/pull/1139).
- Avoid usage of deprecated ``ansible.module_utils.six`` in some of the code that still supports Python 2 (https://github.com/ansible-collections/community.docker/pull/1138).

v4.8.0
======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- docker_container - support missing fields and new mount types in ``mounts`` (https://github.com/ansible-collections/community.docker/issues/1129, https://github.com/ansible-collections/community.docker/pull/1134).

Bugfixes
--------

- Avoid deprecated functionality in ansible-core 2.20 (https://github.com/ansible-collections/community.docker/pull/1117).

v4.7.0
======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- docker_swarm_service - add support for ``replicated-job`` mode for Swarm services (https://github.com/ansible-collections/community.docker/issues/626, https://github.com/ansible-collections/community.docker/pull/1108).

Bugfixes
--------

- docker_image, docker_image_push - work around a bug in Docker 28.3.3 that prevents pushing without authentication to a registry (https://github.com/ansible-collections/community.docker/pull/1110).

v4.6.2
======

Release Summary
---------------

Bugfix release for Docker Compose 2.39.0+.

Bugfixes
--------

- docker_compose_v2 - adjust to new dry-run build events in Docker Compose 2.39.0+ (https://github.com/ansible-collections/community.docker/pull/1101).

v4.6.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker_compose_v2 - handle a (potentially unintentional) breaking change in Docker Compose 2.37.0. Note that ``ContainerName`` is no longer part of the return value (https://github.com/ansible-collections/community.docker/issues/1082, https://github.com/ansible-collections/community.docker/pull/1083).
- docker_container - fix idempotency if ``command=[]`` and ``command_handling=correct`` (https://github.com/ansible-collections/community.docker/issues/1080, https://github.com/ansible-collections/community.docker/pull/1085).

v4.6.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- docker_container_copy_into - add ``mode_parse`` parameter which determines how ``mode`` is parsed (https://github.com/ansible-collections/community.docker/pull/1074).

v4.5.2
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker_compose_v2 - fix version check for ``assume_yes`` (https://github.com/ansible-collections/community.docker/pull/1054).
- docker_compose_v2 - use ``--yes`` instead of ``-y`` from Docker Compose 2.34.0 on (https://github.com/ansible-collections/community.docker/pull/1060).

v4.5.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker_compose_v2 - rename flag for ``assume_yes`` parameter for ``docker compose up`` to ``-y`` (https://github.com/ansible-collections/community.docker/pull/1054).

v4.5.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- docker_compose_v2 - add ``assume_yes`` parameter for ``docker compose up`` (https://github.com/ansible-collections/community.docker/pull/1045).
- docker_network - add ``enable_ipv4`` option (https://github.com/ansible-collections/community.docker/issues/1047, https://github.com/ansible-collections/community.docker/pull/1049).

v4.4.0
======

Release Summary
---------------

Feature and bugfix release.

Bugfixes
--------

- docker_compose_v2_run - the module has a conflict between the type of parameter it expects and the one it tries to sanitize. Fix removes the label sanitization step because they are already validated by the parameter definition (https://github.com/ansible-collections/community.docker/pull/1034).
- vendored Docker SDK for Python - do not assume that ``KeyError`` is always for ``ApiVersion`` when querying version fails (https://github.com/ansible-collections/community.docker/issues/1033, https://github.com/ansible-collections/community.docker/pull/1034).

New Modules
-----------

- community.docker.docker_context_info - Retrieve information on Docker contexts for the current user.

v4.3.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- Fix label sanitization code to avoid crashes in case of errors (https://github.com/ansible-collections/community.docker/issues/1028, https://github.com/ansible-collections/community.docker/pull/1029).

v4.3.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- docker_compose_v2* modules - determine compose version with ``docker compose version`` and only then fall back to ``docker info`` (https://github.com/ansible-collections/community.docker/pull/1021).

v4.2.0
======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- docker_compose_v2 - add ``ignore_build_events`` option (default value ``true``) which allows to (not) ignore build events for change detection (https://github.com/ansible-collections/community.docker/issues/1005, https://github.com/ansible-collections/community.docker/issues/pull/1011).
- docker_image_build - ``outputs[].name`` can now be a list of strings (https://github.com/ansible-collections/community.docker/pull/1006).
- docker_image_build - the executed command is now returned in the ``command`` return value in case of success and some errors (https://github.com/ansible-collections/community.docker/pull/1006).
- docker_network - added ``ingress`` option (https://github.com/ansible-collections/community.docker/pull/999).

Bugfixes
--------

- docker_compose_v2 - when using Compose 2.31.0 or newer, revert to the old behavior that image rebuilds, for example if ``rebuild=always``, only result in ``changed`` if a container has been restarted (https://github.com/ansible-collections/community.docker/issues/1005, https://github.com/ansible-collections/community.docker/issues/pull/1011).
- docker_image_build - work around bug resp. very unexpected behavior in Docker buildx that overwrites all image names in ``--output`` parameters if ``--tag`` is provided, which the module did by default in the past. The module now only supplies ``--tag`` if ``outputs`` is empty. If ``outputs`` has entries, it will add an additional entry with ``type=image`` if no entry of ``type=image`` contains the image name specified by the ``name`` and ``tag`` options (https://github.com/ansible-collections/community.docker/issues/1001, https://github.com/ansible-collections/community.docker/pull/1006).
- docker_network - added waiting while container actually disconnect from Swarm network (https://github.com/ansible-collections/community.docker/pull/999).
- docker_network - containers are only reconnected to a network if they really exist (https://github.com/ansible-collections/community.docker/pull/999).
- docker_network - enabled "force" option in Docker network container disconnect API call (https://github.com/ansible-collections/community.docker/pull/999).
- docker_swarm_info - do not crash when finding Swarm jobs if ``services=true`` (https://github.com/ansible-collections/community.docker/issues/1003).

v4.1.0
======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- docker_stack - allow to add ``--detach=false`` option to ``docker stack deploy`` command (https://github.com/ansible-collections/community.docker/pull/987).

Bugfixes
--------

- docker_compose_v2_exec, docker_compose_v2_run - fix missing ``--env`` flag while assembling env arguments (https://github.com/ansible-collections/community.docker/pull/992).
- docker_host_info - ensure that the module always returns ``can_talk_to_docker``, and that it provides the correct value even if ``api_version`` is specified (https://github.com/ansible-collections/community.docker/issues/993, https://github.com/ansible-collections/community.docker/pull/995).

v4.0.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker_compose_v2_run - make sure to sanitize ``labels`` before sending them to the Docker Daemon (https://github.com/ansible-collections/community.docker/pull/985).
- docker_config - make sure to sanitize ``labels`` before sending them to the Docker Daemon (https://github.com/ansible-collections/community.docker/pull/985).
- docker_network - make sure to sanitize ``labels`` before sending them to the Docker Daemon (https://github.com/ansible-collections/community.docker/pull/985).
- docker_node - make sure to sanitize ``labels`` before sending them to the Docker Daemon (https://github.com/ansible-collections/community.docker/pull/985).
- docker_secret - make sure to sanitize ``labels`` before sending them to the Docker Daemon (https://github.com/ansible-collections/community.docker/pull/985).
- docker_swarm - make sure to sanitize ``labels`` before sending them to the Docker Daemon (https://github.com/ansible-collections/community.docker/pull/985).
- docker_swarm_service - make sure to sanitize ``labels`` and ``container_labels`` before sending them to the Docker Daemon (https://github.com/ansible-collections/community.docker/pull/985).
- docker_volume - make sure to sanitize ``labels`` before sending them to the Docker Daemon (https://github.com/ansible-collections/community.docker/pull/985).

v4.0.0
======

Release Summary
---------------

Major release with removed deprecated features.

Minor Changes
-------------

- docker_compose_v2 - add ``renew_anon_volumes`` parameter for ``docker compose up`` (https://github.com/ansible-collections/community.docker/pull/977).

Breaking Changes / Porting Guide
--------------------------------

- docker_container - the default of ``image_name_mismatch`` changed from ``ignore`` to ``recreate`` (https://github.com/ansible-collections/community.docker/pull/971).

Removed Features (previously deprecated)
----------------------------------------

- The collection no longer supports ansible-core 2.11, 2.12, 2.13, and 2.14. You need ansible-core 2.15.0 or newer to use community.docker 4.x.y (https://github.com/ansible-collections/community.docker/pull/971).
- The docker_compose module has been removed. Please migrate to community.docker.docker_compose_v2 (https://github.com/ansible-collections/community.docker/pull/971).
- docker_container - the ``ignore_image`` option has been removed. Use ``image: ignore`` in ``comparisons`` instead (https://github.com/ansible-collections/community.docker/pull/971).
- docker_container - the ``purge_networks`` option has been removed. Use ``networks: strict`` in ``comparisons`` instead and make sure that ``networks`` is specified (https://github.com/ansible-collections/community.docker/pull/971).
- various modules and plugins - remove the ``ssl_version`` option (https://github.com/ansible-collections/community.docker/pull/971).

v3.13.1
=======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker_compose_v2 - improve parsing of dry-run image build operations from JSON events (https://github.com/ansible-collections/community.docker/issues/975, https://github.com/ansible-collections/community.docker/pull/976).

v3.13.0
=======

Release Summary
---------------

Feature release.

New Modules
-----------

- community.docker.docker_compose_v2_exec - Run command in a container of a Compose service.
- community.docker.docker_compose_v2_run - Run command in a new container of a Compose service.

v3.12.2
=======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker_prune - fix handling of lists for the filter options (https://github.com/ansible-collections/community.docker/issues/961, https://github.com/ansible-collections/community.docker/pull/966).

v3.12.1
=======

Release Summary
---------------

Maintenance release with updated documentation and changelog.

Deprecated Features
-------------------

- The collection deprecates support for all ansible-core versions that are currently End of Life, `according to the ansible-core support matrix <https://docs.ansible.com/ansible-core/devel/reference_appendices/release_and_maintenance.html#ansible-core-support-matrix>`__. This means that the next major release of the collection will no longer support ansible-core 2.11, ansible-core 2.12, ansible-core 2.13, and ansible-core 2.14.

v3.12.0
=======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- docker, docker_api connection plugins - allow to determine the working directory when executing commands with the new ``working_dir`` option (https://github.com/ansible-collections/community.docker/pull/943).
- docker, docker_api connection plugins - allow to execute commands with extended privileges with the new ``privileges`` option (https://github.com/ansible-collections/community.docker/pull/943).
- docker, docker_api connection plugins - allow to pass extra environment variables when executing commands with the new ``extra_env`` option (https://github.com/ansible-collections/community.docker/issues/937, https://github.com/ansible-collections/community.docker/pull/940).
- docker_compose_v2* modules - support Docker Compose 2.29.0's ``json`` progress writer to avoid having to parse text output (https://github.com/ansible-collections/community.docker/pull/931).
- docker_compose_v2_pull - add new options ``ignore_buildable``, ``include_deps``, and ``services`` (https://github.com/ansible-collections/community.docker/issues/941, https://github.com/ansible-collections/community.docker/pull/942).
- docker_container - when creating a container, directly pass all networks to connect to to the Docker Daemon for API version 1.44 and newer. This makes creation more efficient and works around a bug in Docker Daemon that does not use the specified MAC address in at least some cases, though only for creation (https://github.com/ansible-collections/community.docker/pull/933).

Bugfixes
--------

- docker_compose_v2 - handle yet another random unstructured error output from pre-2.29.0 Compose versions (https://github.com/ansible-collections/community.docker/issues/948, https://github.com/ansible-collections/community.docker/pull/949).
- docker_compose_v2 - make sure that services provided in ``services`` are appended to the command line after ``--`` and not before it (https://github.com/ansible-collections/community.docker/pull/942).
- docker_compose_v2* modules, docker_image_build - provide better error message when required fields are not present in ``docker version`` or ``docker info`` output. This can happen if Podman is used instead of Docker (https://github.com/ansible-collections/community.docker/issues/891, https://github.com/ansible-collections/community.docker/pull/935).
- docker_container - fix idempotency if ``network_mode=default`` and Docker 26.1.0 or later is used. There was a breaking change in Docker 26.1.0 regarding normalization of ``NetworkMode`` (https://github.com/ansible-collections/community.docker/issues/934, https://github.com/ansible-collections/community.docker/pull/936).
- docker_container - restore behavior of the module from community.docker 2.x.y that passes the first network to the Docker Deamon while creating the container (https://github.com/ansible-collections/community.docker/pull/933).
- docker_image_build - fix ``--output`` parameter composition for ``type=docker`` and ``type=image`` (https://github.com/ansible-collections/community.docker/issues/946, https://github.com/ansible-collections/community.docker/pull/947).

Known Issues
------------

- docker_container - when specifying a MAC address for a container's network, and the network is attached after container creation (for example, due to idempotency checks), the MAC address is at least in some cases ignored by the Docker Daemon (https://github.com/ansible-collections/community.docker/pull/933).

v3.11.0
=======

Minor Changes
-------------

- docker_container - add support for ``device_cgroup_rules`` (https://github.com/ansible-collections/community.docker/pull/910).
- docker_container - the new ``state=healthy`` allows to wait for a container to become healthy on startup. The ``healthy_wait_timeout`` option allows to configure the maximum time to wait for this to happen (https://github.com/ansible-collections/community.docker/issues/890, https://github.com/ansible-collections/community.docker/pull/921).

Bugfixes
--------

- docker_compose_v2* modules - fix parsing of skipped pull messages for Docker Compose 2.28.x (https://github.com/ansible-collections/community.docker/issues/911, https://github.com/ansible-collections/community.docker/pull/916).
- docker_compose_v2*, docker_stack*, docker_image_build modules - using ``cli_context`` no longer leads to an invalid parameter combination being passed to the corresponding Docker CLI tool, unless ``docker_host`` is also provided. Combining ``cli_context`` and ``docker_host`` is no longer allowed (https://github.com/ansible-collections/community.docker/issues/892, https://github.com/ansible-collections/community.docker/pull/895).
- docker_container - fix possible infinite loop if ``removal_wait_timeout`` is set (https://github.com/ansible-collections/community.docker/pull/922).
- vendored Docker SDK for Python - use ``LooseVersion`` instead of ``StrictVersion`` to compare urllib3 versions. This is needed for development versions (https://github.com/ansible-collections/community.docker/pull/902).

v3.10.4
=======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker_compose - make sure that the module uses the ``api_version`` parameter (https://github.com/ansible-collections/community.docker/pull/881).
- docker_compose_v2* modules - there was no check to make sure that one of ``project_src`` and ``definition`` is provided. The modules crashed if none were provided (https://github.com/ansible-collections/community.docker/issues/885, https://github.com/ansible-collections/community.docker/pull/886).

v3.10.3
=======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker and nsenter connection plugins, docker_container_exec module - avoid using the deprecated ``ansible.module_utils.compat.selectors`` module util with Python 3 (https://github.com/ansible-collections/community.docker/issues/870, https://github.com/ansible-collections/community.docker/pull/871).

v3.10.2
=======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- vendored Docker SDK for Python - include a fix requests 2.32.2+ compatibility (https://github.com/ansible-collections/community.docker/issues/860, https://github.com/psf/requests/issues/6707, https://github.com/ansible-collections/community.docker/pull/864).

v3.10.1
=======

Release Summary
---------------

Hotfix release for requests 2.32.0 compatibility.

Bugfixes
--------

- vendored Docker SDK for Python - include a hotfix for requests 2.32.0 compatibility (https://github.com/ansible-collections/community.docker/issues/860, https://github.com/docker/docker-py/issues/3256, https://github.com/ansible-collections/community.docker/pull/861).

Known Issues
------------

- Please note that the fix for requests 2.32.0 included in community.docker 3.10.1 only
  fixes problems with the *vendored* Docker SDK for Python code. Modules and plugins that
  use Docker SDK for Python can still fail due to the SDK currently being incompatible
  with requests 2.32.0.

  If you still experience problems with requests 2.32.0, such as error messages like
  ``Not supported URL scheme http+docker``, please restrict requests to ``<2.32.0``.

v3.10.0
=======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- docker_container - adds ``healthcheck.start_interval`` to support healthcheck start interval setting on containers (https://github.com/ansible-collections/community.docker/pull/848).
- docker_container - adds ``healthcheck.test_cli_compatible`` to allow omit test option on containers without remove existing image test (https://github.com/ansible-collections/community.docker/pull/847).
- docker_image_build - add ``outputs`` option to allow configuring outputs for the build (https://github.com/ansible-collections/community.docker/pull/852).
- docker_image_build - add ``secrets`` option to allow passing secrets to the build (https://github.com/ansible-collections/community.docker/pull/852).
- docker_image_build - allow ``platform`` to be a list of platforms instead of only a single platform for multi-platform builds (https://github.com/ansible-collections/community.docker/pull/852).
- docker_network - adds ``config_only`` and ``config_from`` to support creating and using config only networks (https://github.com/ansible-collections/community.docker/issues/395).
- docker_prune - add new options ``builder_cache_all``, ``builder_cache_filters``, and ``builder_cache_keep_storage``, and a new return value ``builder_cache_caches_deleted`` for pruning build caches (https://github.com/ansible-collections/community.docker/issues/844, https://github.com/ansible-collections/community.docker/issues/845).
- docker_swarm_service - adds ``sysctls`` to support sysctl settings on swarm services (https://github.com/ansible-collections/community.docker/issues/190).

Deprecated Features
-------------------

- docker_compose - the Docker Compose v1 module is deprecated and will be removed from community.docker 4.0.0. Please migrate to the ``community.docker.docker_compose_v2`` module, which works with Docker Compose v2 (https://github.com/ansible-collections/community.docker/issues/823, https://github.com/ansible-collections/community.docker/pull/833).
- various modules and plugins - the ``ssl_version`` option has been deprecated and will be removed from community.docker 4.0.0. It has already been removed from Docker SDK for Python 7.0.0, and was only necessary in the past to work around SSL/TLS issues (https://github.com/ansible-collections/community.docker/pull/853).

v3.9.0
======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- The EE requirements now include PyYAML, since the ``docker_compose_v2*`` modules depend on it when the ``definition`` option is used. This should not have a noticable effect on generated EEs since ansible-core itself depends on PyYAML as well, and ansible-builder explicitly ignores this dependency (https://github.com/ansible-collections/community.docker/pull/832).
- docker_compose_v2* - the new option ``check_files_existing`` allows to disable the check for one of the files ``compose.yaml``, ``compose.yml``, ``docker-compose.yaml``, and ``docker-compose.yml`` in ``project_src`` if ``files`` is not specified. This is necessary if a non-standard compose filename is specified through other means, like the ``COMPOSE_FILE`` environment variable (https://github.com/ansible-collections/community.docker/issues/838, https://github.com/ansible-collections/community.docker/pull/839).
- docker_compose_v2* modules - allow to provide an inline definition of the compose content instead of having to provide a ``project_src`` directory with the compose file written into it (https://github.com/ansible-collections/community.docker/issues/829, https://github.com/ansible-collections/community.docker/pull/832).
- vendored Docker SDK for Python - remove unused code that relies on functionality deprecated in Python 3.12 (https://github.com/ansible-collections/community.docker/pull/834).

Bugfixes
--------

- docker_compose_v2* - allow ``project_src`` to be a relative path, by converting it to an absolute path before using it (https://github.com/ansible-collections/community.docker/issues/827, https://github.com/ansible-collections/community.docker/pull/828).
- docker_compose_v2* modules - abort with a nice error message instead of crash when the Docker Compose CLI plugin version is ``dev`` (https://github.com/ansible-collections/community.docker/issues/825, https://github.com/ansible-collections/community.docker/pull/826).
- inventory plugins - add unsafe wrapper to avoid marking strings that do not contain ``{`` or ``}`` as unsafe, to work around a bug in AWX (https://github.com/ansible-collections/community.docker/pull/835).

v3.8.1
======

Release Summary
---------------

Bugfix release

Security Fixes
--------------

- docker_containers, docker_machine, and docker_swarm inventory plugins - make sure all data received from the Docker daemon / Docker machine is marked as unsafe, so remote code execution by obtaining texts that can be evaluated as templates is not possible (https://www.die-welt.net/2024/03/remote-code-execution-in-ansible-dynamic-inventory-plugins/, https://github.com/ansible-collections/community.docker/pull/815).

Bugfixes
--------

- docker_compose_v2 - do not fail when non-fatal errors occur. This can happen when pulling an image fails, but then the image can be built for another service. Docker Compose emits an error in that case, but ``docker compose up`` still completes successfully (https://github.com/ansible-collections/community.docker/issues/807, https://github.com/ansible-collections/community.docker/pull/810, https://github.com/ansible-collections/community.docker/pull/811).
- docker_compose_v2* modules - correctly parse ``Warning`` events emitted by Docker Compose (https://github.com/ansible-collections/community.docker/issues/807, https://github.com/ansible-collections/community.docker/pull/811).
- docker_compose_v2* modules - parse ``logfmt`` warnings emitted by Docker Compose (https://github.com/ansible-collections/community.docker/issues/787, https://github.com/ansible-collections/community.docker/pull/811).
- docker_compose_v2_pull - fixing idempotence by checking actual pull progress events instead of service-level pull request when ``policy=always``. This stops the module from reporting ``changed=true`` if no actual change happened when pulling. In check mode, it has to assume that a change happens though (https://github.com/ansible-collections/community.docker/issues/813, https://github.com/ansible-collections/community.docker/pull/814).

v3.8.0
======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- docker_compose_v2 - allow to wait until containers are running/health when running ``docker compose up`` with the new ``wait`` option (https://github.com/ansible-collections/community.docker/issues/794, https://github.com/ansible-collections/community.docker/pull/796).
- docker_container - the ``pull_check_mode_behavior`` option now allows to control the module's behavior in check mode when ``pull=always`` (https://github.com/ansible-collections/community.docker/issues/792, https://github.com/ansible-collections/community.docker/pull/797).
- docker_container - the ``pull`` option now accepts the three values ``never``, ``missing_image`` (default), and ``never``, next to the previously valid values ``true`` (equivalent to ``always``) and ``false`` (equivalent to ``missing_image``). This allows the equivalent to ``--pull=never`` from the Docker command line (https://github.com/ansible-collections/community.docker/issues/783, https://github.com/ansible-collections/community.docker/pull/797).

Bugfixes
--------

- docker_compose_v2 - do not consider a ``Waiting`` event as an action/change (https://github.com/ansible-collections/community.docker/pull/804).
- docker_compose_v2 - do not treat service-level pull events as changes to avoid incorrect ``changed=true`` return value of ``pull=always`` (https://github.com/ansible-collections/community.docker/issues/802, https://github.com/ansible-collections/community.docker/pull/803).
- docker_compose_v2, docker_compose_v2_pull - fix parsing of pull messages for Docker Compose 2.20.0 (https://github.com/ansible-collections/community.docker/issues/785, https://github.com/ansible-collections/community.docker/pull/786).

v3.7.0
======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- docker_compose_v2 - add ``scale`` option to allow to explicitly scale services (https://github.com/ansible-collections/community.docker/pull/776).
- docker_compose_v2, docker_compose_v2_pull - support ``files`` parameter to specify multiple Compose files (https://github.com/ansible-collections/community.docker/issues/772, https://github.com/ansible-collections/community.docker/pull/775).

Bugfixes
--------

- docker_compose_v2 - properly parse dry-run build events from ``stderr`` (https://github.com/ansible-collections/community.docker/issues/778, https://github.com/ansible-collections/community.docker/pull/779).
- docker_compose_v2_pull - the module was documented as part of the ``community.docker.docker`` action group, but was not actually part of it. That has now been fixed (https://github.com/ansible-collections/community.docker/pull/773).

New Modules
-----------

- community.docker.docker_image_export - Export (archive) Docker images

v3.6.0
======

Release Summary
---------------

Bugfix and feature release.

The collection now includes a bunch of new ``docker_image_*`` modules that move features out of the
rather complex ``docker_image`` module. These new modules are easier to use and can better declare whether
they support check mode, diff mode, or none of them.

This version also features modules that support the Docker CLI plugins ``buildx`` and ``compose``.
The ``docker_image_build`` module uses the ``docker buildx`` command under the hood, and the ``docker_compose_v2``
and ``docker_compose_v2_pull`` modules uses the ``docker compose`` command. All these modules use the Docker CLI
instead of directly talking to the API. The modules support mostly the same interface as the API based modules,
so the main difference is that instead of some Python requirements, they depend on the Docker CLI tool ``docker``.

Major Changes
-------------

- The ``community.docker`` collection now depends on the ``community.library_inventory_filtering_v1`` collection. This utility collection provides host filtering functionality for inventory plugins. If you use the Ansible community package, both collections are included and you do not have to do anything special. If you install the collection with ``ansible-galaxy collection install``, it will be installed automatically. If you install the collection by copying the files of the collection to a place where ansible-core can find it, for example by cloning the git repository, you need to make sure that you also have to install the dependency if you are using the inventory plugins (https://github.com/ansible-collections/community.docker/pull/698).

Minor Changes
-------------

- The ``ca_cert`` option available to almost all modules and plugins has been renamed to ``ca_path``. The name ``ca_path`` is also used for similar options in ansible-core and other collections. The old name has been added as an alias and can still be used (https://github.com/ansible-collections/community.docker/pull/744).
- The ``docker_stack*`` modules now use the common CLI-based module code added for the ``docker_image_build`` and ``docker_compose_v2`` modules. This means that the modules now have various more configuration options with respect to talking to the Docker Daemon, and now also are part of the ``community.docker.docker`` and ``docker`` module default groups (https://github.com/ansible-collections/community.docker/pull/745).
- docker_container - add ``networks[].mac_address`` option for Docker API 1.44+. Note that Docker API 1.44 no longer uses the global ``mac_address`` option, this new option is the only way to set the MAC address for a container (https://github.com/ansible-collections/community.docker/pull/763).
- docker_image - allow to specify labels and ``/dev/shm`` size when building images (https://github.com/ansible-collections/community.docker/issues/726, https://github.com/ansible-collections/community.docker/pull/727).
- docker_image - allow to specify memory size and swap memory size in other units than bytes (https://github.com/ansible-collections/community.docker/pull/727).
- inventory plugins - add ``filter`` option which allows to include and exclude hosts based on Jinja2 conditions (https://github.com/ansible-collections/community.docker/pull/698, https://github.com/ansible-collections/community.docker/issues/610).

Bugfixes
--------

- Use ``unix:///var/run/docker.sock`` instead of the legacy ``unix://var/run/docker.sock`` as default for ``docker_host`` (https://github.com/ansible-collections/community.docker/pull/736).
- docker_image - fix archiving idempotency with Docker API 1.44 or later (https://github.com/ansible-collections/community.docker/pull/765).

New Modules
-----------

- community.docker.docker_compose_v2 - Manage multi-container Docker applications with Docker Compose CLI plugin
- community.docker.docker_compose_v2_pull - Pull a Docker compose project
- community.docker.docker_image_build - Build Docker images using Docker buildx
- community.docker.docker_image_pull - Pull Docker images from registries
- community.docker.docker_image_push - Push Docker images to registries
- community.docker.docker_image_remove - Remove Docker images
- community.docker.docker_image_tag - Tag Docker images with new names and/or tags

v3.5.0
======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- docker_container - implement better ``platform`` string comparisons to improve idempotency (https://github.com/ansible-collections/community.docker/issues/654, https://github.com/ansible-collections/community.docker/pull/705).
- docker_container - internal refactorings which allow comparisons to use more information like details of the current image or the Docker host config (https://github.com/ansible-collections/community.docker/pull/713).

Deprecated Features
-------------------

- docker_container - the default ``ignore`` for the ``image_name_mismatch`` parameter has been deprecated and will switch to ``recreate`` in community.docker 4.0.0. A deprecation warning will be printed in situations where the default value is used and where a behavior would change once the default changes (https://github.com/ansible-collections/community.docker/pull/703).

Bugfixes
--------

- modules and plugins using the Docker SDK for Python - remove ``ssl_version`` from the parameters passed to Docker SDK for Python 7.0.0+. Explicitly fail with a nicer error message if it was explicitly set in this case (https://github.com/ansible-collections/community.docker/pull/715).
- modules and plugins using the Docker SDK for Python - remove ``tls_hostname`` from the parameters passed to Docker SDK for Python 7.0.0+. Explicitly fail with a nicer error message if it was explicitly set in this case (https://github.com/ansible-collections/community.docker/pull/721).
- vendored Docker SDK for Python - avoid passing on ``ssl_version`` and ``tls_hostname`` if they were not provided by the user. Remove dead code. (https://github.com/ansible-collections/community.docker/pull/722).

v3.4.11
=======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker_volume - fix crash caused by accessing an empty dictionary. The ``has_different_config()`` was raising an ``AttributeError`` because the ``self.existing_volume["Labels"]`` dictionary was ``None`` (https://github.com/ansible-collections/community.docker/pull/702).

v3.4.10
=======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker_swarm - make init and join operations work again with Docker SDK for Python before 4.0.0 (https://github.com/ansible-collections/community.docker/issues/695, https://github.com/ansible-collections/community.docker/pull/696).

v3.4.9
======

Release Summary
---------------

Maintenance release with updated documentation and vendored Docker SDK for Python code.

Bugfixes
--------

- vendored Docker SDK for Python code - cherry-pick changes from the Docker SDK for Python code to align code. These changes should not affect the parts used by the collection's code (https://github.com/ansible-collections/community.docker/pull/694).

v3.4.8
======

Release Summary
---------------

Maintenance release with updated documentation.

From this version on, community.docker is using the new `Ansible semantic markup
<https://docs.ansible.com/ansible/devel/dev_guide/developing_modules_documenting.html#semantic-markup-within-module-documentation>`__
in its documentation. If you look at documentation with the ansible-doc CLI tool
from ansible-core before 2.15, please note that it does not render the markup
correctly. You should be still able to read it in most cases, but you need
ansible-core 2.15 or later to see it as it is intended. Alternatively you can
look at `the devel docsite <https://docs.ansible.com/ansible/devel/collections/community/docker/>`__
for the rendered HTML version of the documentation of the latest release.

Known Issues
------------

- Ansible markup will show up in raw form on ansible-doc text output for ansible-core before 2.15. If you have trouble deciphering the documentation markup, please upgrade to ansible-core 2.15 (or newer), or read the HTML documentation on https://docs.ansible.com/ansible/devel/collections/community/docker/.

v3.4.7
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker_swarm_info - if ``service=true`` is used, do not crash when a service without an endpoint spec is encountered (https://github.com/ansible-collections/community.docker/issues/636, https://github.com/ansible-collections/community.docker/pull/637).

v3.4.6
======

Release Summary
---------------

Bugfix release with documentation warnings about using certain functionality when connecting to the Docker daemon with TCP TLS.

Bugfixes
--------

- socket_handler module utils - make sure this fully works when Docker SDK for Python is not available (https://github.com/ansible-collections/community.docker/pull/620).
- vendored Docker SDK for Python code - fix for errors on pipe close in Windows (https://github.com/ansible-collections/community.docker/pull/619).
- vendored Docker SDK for Python code - respect timeouts on Windows named pipes (https://github.com/ansible-collections/community.docker/pull/619).
- vendored Docker SDK for Python code - use ``poll()`` instead of ``select()`` except on Windows (https://github.com/ansible-collections/community.docker/pull/619).

Known Issues
------------

- docker_api connection plugin - does **not work with TCP TLS sockets**! This is caused by the inability to send an ``close_notify`` TLS alert without closing the connection with Python's ``SSLSocket`` (https://github.com/ansible-collections/community.docker/issues/605, https://github.com/ansible-collections/community.docker/pull/621).
- docker_container_exec - does **not work with TCP TLS sockets** when the ``stdin`` option is used! This is caused by the inability to send an ``close_notify`` TLS alert without closing the connection with Python's ``SSLSocket`` (https://github.com/ansible-collections/community.docker/issues/605, https://github.com/ansible-collections/community.docker/pull/621).

v3.4.5
======

Release Summary
---------------

Maintenance release which adds compatibility with requests 2.29.0 and 2.30.0 and urllib3 2.0.

Bugfixes
--------

- Make vendored Docker SDK for Python code compatible with requests 2.29.0 and urllib3 2.0 (https://github.com/ansible-collections/community.docker/pull/613).

v3.4.4
======

Release Summary
---------------

Maintenance release with updated EE requirements and updated documentation.

Minor Changes
-------------

- Restrict requests to versions before 2.29.0, and urllib3 to versions before 2.0.0. This is necessary until the vendored code from Docker SDK for Python has been fully adjusted to work with a feature of urllib3 that is used since requests 2.29.0 (https://github.com/ansible-collections/community.docker/issues/611, https://github.com/ansible-collections/community.docker/pull/612).

Known Issues
------------

- The modules and plugins using the vendored code from Docker SDK for Python currently do not work with requests 2.29.0 and/or urllib3 2.0.0. The same is currently true for the latest version of Docker SDK for Python itself (https://github.com/ansible-collections/community.docker/issues/611, https://github.com/ansible-collections/community.docker/pull/612).

v3.4.3
======

Release Summary
---------------

Maintenance release with improved documentation.

v3.4.2
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker_prune - return correct value for ``changed``. So far the module always claimed that nothing changed (https://github.com/ansible-collections/community.docker/pull/593).

v3.4.1
======

Release Summary
---------------

Regular bugfix release.

Bugfixes
--------

- docker_api connection plugin, docker_container_exec, docker_container_copy_into - properly close socket to Daemon after executing commands in containers (https://github.com/ansible-collections/community.docker/pull/582).
- docker_container - fix ``tmfs_size`` and ``tmpfs_mode`` not being set (https://github.com/ansible-collections/community.docker/pull/580).
- various plugins and modules - remove unnecessary imports (https://github.com/ansible-collections/community.docker/pull/574).

v3.4.0
======

Release Summary
---------------

Regular bugfix and feature release.

Minor Changes
-------------

- docker_api connection plugin - when copying files to/from a container, stream the file contents instead of first reading them to memory (https://github.com/ansible-collections/community.docker/pull/545).
- docker_host_info - allow to list all containers with new option ``containers_all`` (https://github.com/ansible-collections/community.docker/issues/535, https://github.com/ansible-collections/community.docker/pull/538).

Bugfixes
--------

- docker_api connection plugin - fix error handling when 409 Conflict is returned by the Docker daemon in case of a stopped container (https://github.com/ansible-collections/community.docker/pull/546).
- docker_container_exec - fix error handling when 409 Conflict is returned by the Docker daemon in case of a stopped container (https://github.com/ansible-collections/community.docker/pull/546).
- docker_plugin - do not crash if plugin is installed in check mode (https://github.com/ansible-collections/community.docker/issues/552, https://github.com/ansible-collections/community.docker/pull/553).
- most modules - fix handling of ``DOCKER_TIMEOUT`` environment variable, and improve handling of other fallback environment variables (https://github.com/ansible-collections/community.docker/issues/551, https://github.com/ansible-collections/community.docker/pull/554).

New Modules
-----------

- community.docker.docker_container_copy_into - Copy a file into a Docker container

v3.3.2
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker_container - when ``detach=false``, wait indefinitely and not at most one minute. This was the behavior with Docker SDK for Python, and was accidentally changed in 3.0.0 (https://github.com/ansible-collections/community.docker/issues/526, https://github.com/ansible-collections/community.docker/pull/527).

v3.3.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- current_container_facts - make container detection work better in more cases (https://github.com/ansible-collections/community.docker/pull/522).

v3.3.0
======

Release Summary
---------------

Feature and bugfix release.

Minor Changes
-------------

- current_container_facts - make work with current Docker version, also support Podman (https://github.com/ansible-collections/community.docker/pull/510).
- docker_image - when using ``archive_path``, detect whether changes are necessary based on the image ID (hash). If the existing tar archive matches the source, do nothing. Previously, each task execution re-created the archive (https://github.com/ansible-collections/community.docker/pull/500).

Bugfixes
--------

- docker_container_exec - fix ``chdir`` option which was ignored since community.docker 3.0.0 (https://github.com/ansible-collections/community.docker/issues/517, https://github.com/ansible-collections/community.docker/pull/518).
- vendored latest Docker SDK for Python bugfix (https://github.com/ansible-collections/community.docker/pull/513, https://github.com/docker/docker-py/issues/3045).

v3.2.2
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker_container - the ``kill_signal`` option erroneously did not accept strings anymore since 3.0.0 (https://github.com/ansible-collections/community.docker/issues/505, https://github.com/ansible-collections/community.docker/pull/506).

v3.2.1
======

Release Summary
---------------

Maintenance release with improved documentation.

v3.2.0
======

Release Summary
---------------

Feature and deprecation release.

Minor Changes
-------------

- docker_container - added ``image_name_mismatch`` option which allows to control the behavior if the container uses the image specified, but the container's configuration uses a different name for the image than the one provided to the module (https://github.com/ansible-collections/community.docker/issues/485, https://github.com/ansible-collections/community.docker/pull/488).

Deprecated Features
-------------------

- docker_container - the ``ignore_image`` option is deprecated and will be removed in community.docker 4.0.0. Use ``image: ignore`` in ``comparisons`` instead (https://github.com/ansible-collections/community.docker/pull/487).
- docker_container - the ``purge_networks`` option is deprecated and will be removed in community.docker 4.0.0. Use ``networks: strict`` in ``comparisons`` instead, and make sure to provide ``networks``, with value ``[]`` if all networks should be removed (https://github.com/ansible-collections/community.docker/pull/487).

v3.1.0
======

Release Summary
---------------

Feature release.

Minor Changes
-------------

- The collection repository conforms to the `REUSE specification <https://reuse.software/spec/>`__ except for the changelog fragments (https://github.com/ansible-collections/community.docker/pull/462).
- docker_swarm - allows usage of the ``data_path_port`` parameter when initializing a swarm (https://github.com/ansible-collections/community.docker/issues/296).

v3.0.2
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker_image - fix build argument handling (https://github.com/ansible-collections/community.docker/issues/455, https://github.com/ansible-collections/community.docker/pull/456).

v3.0.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker_container - fix handling of ``env_file`` (https://github.com/ansible-collections/community.docker/issues/451, https://github.com/ansible-collections/community.docker/pull/452).

v3.0.0
======

Release Summary
---------------

The 3.0.0 release features a rewrite of the ``docker_container`` module, and many modules and plugins no longer depend on the Docker SDK for Python.

Major Changes
-------------

- The collection now contains vendored code from the Docker SDK for Python to talk to the Docker daemon. Modules and plugins using this code no longer need the Docker SDK for Python installed on the machine the module or plugin is running on (https://github.com/ansible-collections/community.docker/pull/398).
- docker_api connection plugin - no longer uses the Docker SDK for Python. It requires ``requests`` to be installed, and depending on the features used has some more requirements. If the Docker SDK for Python is installed, these requirements are likely met (https://github.com/ansible-collections/community.docker/pull/414).
- docker_container - no longer uses the Docker SDK for Python. It requires ``requests`` to be installed, and depending on the features used has some more requirements. If the Docker SDK for Python is installed, these requirements are likely met (https://github.com/ansible-collections/community.docker/pull/422).
- docker_container - the module was completely rewritten from scratch (https://github.com/ansible-collections/community.docker/pull/422).
- docker_container_exec - no longer uses the Docker SDK for Python. It requires ``requests`` to be installed, and depending on the features used has some more requirements. If the Docker SDK for Python is installed, these requirements are likely met (https://github.com/ansible-collections/community.docker/pull/401).
- docker_container_info - no longer uses the Docker SDK for Python. It requires ``requests`` to be installed, and depending on the features used has some more requirements. If the Docker SDK for Python is installed, these requirements are likely met (https://github.com/ansible-collections/community.docker/pull/402).
- docker_containers inventory plugin - no longer uses the Docker SDK for Python. It requires ``requests`` to be installed, and depending on the features used has some more requirements. If the Docker SDK for Python is installed, these requirements are likely met (https://github.com/ansible-collections/community.docker/pull/413).
- docker_host_info - no longer uses the Docker SDK for Python. It requires ``requests`` to be installed, and depending on the features used has some more requirements. If the Docker SDK for Python is installed, these requirements are likely met (https://github.com/ansible-collections/community.docker/pull/403).
- docker_image - no longer uses the Docker SDK for Python. It requires ``requests`` to be installed, and depending on the features used has some more requirements. If the Docker SDK for Python is installed, these requirements are likely met (https://github.com/ansible-collections/community.docker/pull/404).
- docker_image_info - no longer uses the Docker SDK for Python. It requires ``requests`` to be installed, and depending on the features used has some more requirements. If the Docker SDK for Python is installed, these requirements are likely met (https://github.com/ansible-collections/community.docker/pull/405).
- docker_image_load - no longer uses the Docker SDK for Python. It requires ``requests`` to be installed, and depending on the features used has some more requirements. If the Docker SDK for Python is installed, these requirements are likely met (https://github.com/ansible-collections/community.docker/pull/406).
- docker_login - no longer uses the Docker SDK for Python. It requires ``requests`` to be installed, and depending on the features used has some more requirements. If the Docker SDK for Python is installed, these requirements are likely met (https://github.com/ansible-collections/community.docker/pull/407).
- docker_network - no longer uses the Docker SDK for Python. It requires ``requests`` to be installed, and depending on the features used has some more requirements. If the Docker SDK for Python is installed, these requirements are likely met (https://github.com/ansible-collections/community.docker/pull/408).
- docker_network_info - no longer uses the Docker SDK for Python. It requires ``requests`` to be installed, and depending on the features used has some more requirements. If the Docker SDK for Python is installed, these requirements are likely met (https://github.com/ansible-collections/community.docker/pull/409).
- docker_plugin - no longer uses the Docker SDK for Python. It requires ``requests`` to be installed, and depending on the features used has some more requirements. If the Docker SDK for Python is installed, these requirements are likely met (https://github.com/ansible-collections/community.docker/pull/429).
- docker_prune - no longer uses the Docker SDK for Python. It requires ``requests`` to be installed, and depending on the features used has some more requirements. If the Docker SDK for Python is installed, these requirements are likely met (https://github.com/ansible-collections/community.docker/pull/410).
- docker_volume - no longer uses the Docker SDK for Python. It requires ``requests`` to be installed, and depending on the features used has some more requirements. If the Docker SDK for Python is installed, these requirements are likely met (https://github.com/ansible-collections/community.docker/pull/411).
- docker_volume_info - no longer uses the Docker SDK for Python. It requires ``requests`` to be installed, and depending on the features used has some more requirements. If the Docker SDK for Python is installed, these requirements are likely met (https://github.com/ansible-collections/community.docker/pull/412).

Minor Changes
-------------

- All software licenses are now in the ``LICENSES/`` directory of the collection root. Moreover, ``SPDX-License-Identifier:`` is used to declare the applicable license for every file that is not automatically generated (https://github.com/ansible-collections/community.docker/pull/430).
- Remove vendored copy of ``distutils.version`` in favor of vendored copy included with ansible-core 2.12+. For ansible-core 2.11, uses ``distutils.version`` for Python < 3.12. There is no support for ansible-core 2.11 with Python 3.12+ (https://github.com/ansible-collections/community.docker/pull/271).
- docker_container - add a new parameter ``image_comparison`` to control the behavior for which image will be used for idempotency checks (https://github.com/ansible-collections/community.docker/issues/421, https://github.com/ansible-collections/community.docker/pull/428).
- docker_container - add support for ``cgroupns_mode`` (https://github.com/ansible-collections/community.docker/issues/338, https://github.com/ansible-collections/community.docker/pull/427).
- docker_container - allow to specify ``platform`` (https://github.com/ansible-collections/community.docker/issues/123, https://github.com/ansible-collections/community.docker/pull/426).
- modules and plugins communicating directly with the Docker daemon - improve default TLS version selection for Python 3.6 and newer. This is only a change relative to older community.docker 3.0.0 pre-releases or with respect to Docker SDK for Python < 6.0.0. Docker SDK for Python 6.0.0 will also include this change (https://github.com/ansible-collections/community.docker/pull/434).
- modules and plugins communicating directly with the Docker daemon - simplify use of helper function that was removed in Docker SDK for Python to find executables (https://github.com/ansible-collections/community.docker/pull/438).
- socker_handler and socket_helper module utils - improve Python forward compatibility, create helper functions for file blocking/unblocking (https://github.com/ansible-collections/community.docker/pull/415).

Breaking Changes / Porting Guide
--------------------------------

- This collection does not work with ansible-core 2.11 on Python 3.12+. Please either upgrade to ansible-core 2.12+, or use Python 3.11 or earlier (https://github.com/ansible-collections/community.docker/pull/271).
- docker_container - ``exposed_ports`` is no longer ignored in ``comparisons``. Before, its value was assumed to be identical with the value of ``published_ports`` (https://github.com/ansible-collections/community.docker/pull/422).
- docker_container - ``log_options`` can no longer be specified when ``log_driver`` is not specified (https://github.com/ansible-collections/community.docker/pull/422).
- docker_container - ``publish_all_ports`` is no longer ignored in ``comparisons`` (https://github.com/ansible-collections/community.docker/pull/422).
- docker_container - ``restart_retries`` can no longer be specified when ``restart_policy`` is not specified (https://github.com/ansible-collections/community.docker/pull/422).
- docker_container - ``stop_timeout`` is no longer ignored for idempotency if told to be not ignored in ``comparisons``. So far it defaulted to ``ignore`` there, and setting it to ``strict`` had no effect (https://github.com/ansible-collections/community.docker/pull/422).
- modules and plugins communicating directly with the Docker daemon - when connecting by SSH and not using ``use_ssh_client=true``, reject unknown host keys instead of accepting them. This is only a breaking change relative to older community.docker 3.0.0 pre-releases or with respect to Docker SDK for Python < 6.0.0. Docker SDK for Python 6.0.0 will also include this change (https://github.com/ansible-collections/community.docker/pull/434).

Removed Features (previously deprecated)
----------------------------------------

- Execution Environments built with community.docker no longer include docker-compose < 2.0.0. If you need to use it with the ``docker_compose`` module, please install that requirement manually (https://github.com/ansible-collections/community.docker/pull/400).
- Support for Ansible 2.9 and ansible-base 2.10 has been removed. If you need support for Ansible 2.9 or ansible-base 2.10, please use community.docker 2.x.y (https://github.com/ansible-collections/community.docker/pull/400).
- Support for Docker API versions 1.20 to 1.24 has been removed. If you need support for these API versions, please use community.docker 2.x.y (https://github.com/ansible-collections/community.docker/pull/400).
- Support for Python 2.6 has been removed. If you need support for Python 2.6, please use community.docker 2.x.y (https://github.com/ansible-collections/community.docker/pull/400).
- Various modules - the default of ``tls_hostname`` (``localhost``) has been removed. If you want to continue using ``localhost``, you need to specify it explicitly (https://github.com/ansible-collections/community.docker/pull/363).
- docker_container - the ``all`` value is no longer allowed in ``published_ports``. Use ``publish_all_ports=true`` instead (https://github.com/ansible-collections/community.docker/pull/399).
- docker_container - the default of ``command_handling`` was changed from ``compatibility`` to ``correct``. Older versions were warning for every invocation of the module when this would result in a change of behavior (https://github.com/ansible-collections/community.docker/pull/399).
- docker_stack - the return values ``out`` and ``err`` have been removed. Use ``stdout`` and ``stderr`` instead (https://github.com/ansible-collections/community.docker/pull/363).

Security Fixes
--------------

- modules and plugins communicating directly with the Docker daemon - when connecting by SSH and not using ``use_ssh_client=true``, reject unknown host keys instead of accepting them. This is only a change relative to older community.docker 3.0.0 pre-releases or with respect to Docker SDK for Python < 6.0.0. Docker SDK for Python 6.0.0 will also include this change (https://github.com/ansible-collections/community.docker/pull/434).

Bugfixes
--------

- docker_image - when composing the build context, trim trailing whitespace from ``.dockerignore`` entries. This is only a change relative to older community.docker 3.0.0 pre-releases or with respect to Docker SDK for Python < 6.0.0. Docker SDK for Python 6.0.0 will also include this change (https://github.com/ansible-collections/community.docker/pull/434).
- docker_plugin - fix crash when handling plugin options (https://github.com/ansible-collections/community.docker/issues/446, https://github.com/ansible-collections/community.docker/pull/447).
- docker_stack - fix broken string formatting when reporting error in case ``compose`` was containing invalid values (https://github.com/ansible-collections/community.docker/pull/448).
- modules and plugins communicating directly with the Docker daemon - do not create a subshell for SSH connections when using ``use_ssh_client=true``. This is only a change relative to older community.docker 3.0.0 pre-releases or with respect to Docker SDK for Python < 6.0.0. Docker SDK for Python 6.0.0 will also include this change (https://github.com/ansible-collections/community.docker/pull/434).
- modules and plugins communicating directly with the Docker daemon - fix ``ProxyCommand`` handling for SSH connections when not using ``use_ssh_client=true``. This is only a change relative to older community.docker 3.0.0 pre-releases or with respect to Docker SDK for Python < 6.0.0. Docker SDK for Python 6.0.0 will also include this change (https://github.com/ansible-collections/community.docker/pull/434).
- modules and plugins communicating directly with the Docker daemon - fix parsing of IPv6 addresses with a port in ``docker_host``. This is only a change relative to older community.docker 3.0.0 pre-releases or with respect to Docker SDK for Python < 6.0.0. Docker SDK for Python 6.0.0 will also include this change (https://github.com/ansible-collections/community.docker/pull/434).
- modules and plugins communicating directly with the Docker daemon - prevent crash when TLS is used (https://github.com/ansible-collections/community.docker/pull/432).

v2.7.0
======

Release Summary
---------------

Bugfix and deprecation release. The next 2.x.y releases will only be bugfix releases, the next expect minor/major release will be 3.0.0 with some major changes.

Minor Changes
-------------

- Move common utility functions from the ``common`` module_util to a new module_util called ``util``. This should not have any user-visible effect (https://github.com/ansible-collections/community.docker/pull/390).

Deprecated Features
-------------------

- Support for Docker API version 1.20 to 1.24 has been deprecated and will be removed in community.docker 3.0.0. The first Docker version supporting API version 1.25 was Docker 1.13, released in January 2017. This affects the modules ``docker_container``, ``docker_container_exec``, ``docker_container_info``, ``docker_compose``, ``docker_login``, ``docker_image``, ``docker_image_info``, ``docker_image_load``, ``docker_host_info``, ``docker_network``, ``docker_network_info``, ``docker_node_info``, ``docker_swarm_info``, ``docker_swarm_service``, ``docker_swarm_service_info``, ``docker_volume_info``, and ``docker_volume``, whose minimally supported API version is between 1.20 and 1.24 (https://github.com/ansible-collections/community.docker/pull/396).
- Support for Python 2.6 is deprecated and will be removed in the next major release (community.docker 3.0.0). Some modules might still work with Python 2.6, but we will no longer try to ensure compatibility (https://github.com/ansible-collections/community.docker/pull/388).

Bugfixes
--------

- Docker SDK for Python based modules and plugins - if the API version is specified as an option, use that one to validate API version requirements of module/plugin options instead of the latest API version supported by the Docker daemon. This also avoids one unnecessary API call per module/plugin (https://github.com/ansible-collections/community.docker/pull/389).

v2.6.0
======

Release Summary
---------------

Bugfix and feature release.

Minor Changes
-------------

- docker_container - added ``image_label_mismatch`` parameter (https://github.com/ansible-collections/community.docker/issues/314, https://github.com/ansible-collections/community.docker/pull/370).

Deprecated Features
-------------------

- Support for Ansible 2.9 and ansible-base 2.10 is deprecated, and will be removed in the next major release (community.docker 3.0.0). Some modules might still work with these versions afterwards, but we will no longer keep compatibility code that was needed to support them (https://github.com/ansible-collections/community.docker/pull/361).
- The dependency on docker-compose for Execution Environments is deprecated and will be removed in community.docker 3.0.0. The `Python docker-compose library <https://pypi.org/project/docker-compose/>`__ is unmaintained and can cause dependency issues. You can manually still install it in an Execution Environment when needed (https://github.com/ansible-collections/community.docker/pull/373).
- Various modules - the default of ``tls_hostname`` that was supposed to be removed in community.docker 2.0.0 will now be removed in version 3.0.0 (https://github.com/ansible-collections/community.docker/pull/362).
- docker_stack - the return values ``out`` and ``err`` that were supposed to be removed in community.docker 2.0.0 will now be removed in version 3.0.0 (https://github.com/ansible-collections/community.docker/pull/362).

Bugfixes
--------

- docker_container - fail with a meaningful message instead of crashing if a port is specified with more than three colon-separated parts (https://github.com/ansible-collections/community.docker/pull/367, https://github.com/ansible-collections/community.docker/issues/365).
- docker_container - remove unused code that will cause problems with Python 3.13 (https://github.com/ansible-collections/community.docker/pull/354).

v2.5.1
======

Release Summary
---------------

Maintenance release.

Bugfixes
--------

- Include ``PSF-license.txt`` file for ``plugins/module_utils/_version.py``.

v2.5.0
======

Release Summary
---------------

Regular feature release.

Minor Changes
-------------

- docker_config - add support for ``template_driver`` with one option ``golang`` (https://github.com/ansible-collections/community.docker/issues/332, https://github.com/ansible-collections/community.docker/pull/345).
- docker_swarm - adds ``data_path_addr`` parameter during swarm initialization or when joining (https://github.com/ansible-collections/community.docker/issues/339).

v2.4.0
======

Release Summary
---------------

Regular feature and bugfix release.

Minor Changes
-------------

- Prepare collection for inclusion in an Execution Environment by declaring its dependencies. The ``docker_stack*`` modules are not supported (https://github.com/ansible-collections/community.docker/pull/336).
- current_container_facts - add detection for GitHub Actions (https://github.com/ansible-collections/community.docker/pull/336).
- docker_container - support returning Docker container log output when using Docker's ``local`` logging driver, an optimized local logging driver introduced in Docker 18.09 (https://github.com/ansible-collections/community.docker/pull/337).

Bugfixes
--------

- docker connection plugin - make sure that ``docker_extra_args`` is used for querying the Docker version. Also ensures that the Docker version is only queried when needed. This is currently the case if a remote user is specified (https://github.com/ansible-collections/community.docker/issues/325, https://github.com/ansible-collections/community.docker/pull/327).

v2.3.0
======

Release Summary
---------------

Regular feature and bugfix release.

Minor Changes
-------------

- docker connection plugin - implement connection reset by clearing internal container user cache (https://github.com/ansible-collections/community.docker/pull/312).
- docker connection plugin - simplify ``actual_user`` handling code (https://github.com/ansible-collections/community.docker/pull/311).
- docker connection plugin - the plugin supports new ways to define the timeout. These are the ``ANSIBLE_DOCKER_TIMEOUT`` environment variable, the ``timeout`` setting in the ``docker_connection`` section of ``ansible.cfg``, and the ``ansible_docker_timeout`` variable (https://github.com/ansible-collections/community.docker/pull/297).
- docker_api connection plugin - implement connection reset by clearing internal container user/group ID cache (https://github.com/ansible-collections/community.docker/pull/312).
- docker_api connection plugin - the plugin supports new ways to define the timeout. These are the ``ANSIBLE_DOCKER_TIMEOUT`` environment variable, the ``timeout`` setting in the ``docker_connection`` section of ``ansible.cfg``, and the ``ansible_docker_timeout`` variable (https://github.com/ansible-collections/community.docker/pull/308).

Bugfixes
--------

- docker connection plugin - fix option handling to be compatible with ansible-core 2.13 (https://github.com/ansible-collections/community.docker/pull/297, https://github.com/ansible-collections/community.docker/issues/307).
- docker_api connection plugin - fix option handling to be compatible with ansible-core 2.13 (https://github.com/ansible-collections/community.docker/pull/308).

v2.2.1
======

Release Summary
---------------

Regular bugfix release.

Bugfixes
--------

- docker_compose - fix Python 3 type error when extracting warnings or errors from docker-compose's output (https://github.com/ansible-collections/community.docker/pull/305).

v2.2.0
======

Release Summary
---------------

Regular feature and bugfix release.

Minor Changes
-------------

- docker_config - add support for rolling update, set ``rolling_versions`` to ``true`` to enable (https://github.com/ansible-collections/community.docker/pull/295, https://github.com/ansible-collections/community.docker/issues/109).
- docker_secret - add support for rolling update, set ``rolling_versions`` to ``true`` to enable (https://github.com/ansible-collections/community.docker/pull/293, https://github.com/ansible-collections/community.docker/issues/21).
- docker_swarm_service - add support for setting capabilities with the ``cap_add`` and ``cap_drop`` parameters. Usage is the same as with the ``capabilities`` and ``cap_drop`` parameters for ``docker_container`` (https://github.com/ansible-collections/community.docker/pull/294).

Bugfixes
--------

- docker_container, docker_image - adjust image finding code to peculiarities of ``podman-docker``'s API emulation when Docker short names like ``redis`` are used (https://github.com/ansible-collections/community.docker/issues/292).

v2.1.1
======

Release Summary
---------------

Emergency release to amend breaking change in previous release.

Bugfixes
--------

- Fix unintended breaking change caused by `an earlier fix <https://github.com/ansible-collections/community.docker/pull/258>`_ by vendoring the deprecated Python standard library ``distutils.version`` until this collection stops supporting Ansible 2.9 and ansible-base 2.10 (https://github.com/ansible-collections/community.docker/issues/267, https://github.com/ansible-collections/community.docker/pull/269).

v2.1.0
======

Release Summary
---------------

Feature and bugfix release.

Minor Changes
-------------

- docker_container_exec - add ``detach`` parameter (https://github.com/ansible-collections/community.docker/issues/250, https://github.com/ansible-collections/community.docker/pull/255).
- docker_container_exec - add ``env`` option (https://github.com/ansible-collections/community.docker/issues/248, https://github.com/ansible-collections/community.docker/pull/254).

Bugfixes
--------

- Various modules and plugins - use vendored version of ``distutils.version`` included in ansible-core 2.12 if available. This avoids breakage when ``distutils`` is removed from the standard library of Python 3.12. Note that ansible-core 2.11, ansible-base 2.10 and Ansible 2.9 are right now not compatible with Python 3.12, hence this fix does not target these ansible-core/-base/2.9 versions (https://github.com/ansible-collections/community.docker/pull/258).
- docker connection plugin - replace deprecated ``distutils.spawn.find_executable`` with Ansible's ``get_bin_path`` to find the ``docker`` executable (https://github.com/ansible-collections/community.docker/pull/257).
- docker_container_exec - disallow using the ``chdir`` option for Docker API before 1.35 (https://github.com/ansible-collections/community.docker/pull/253).

v2.0.2
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker_api connection plugin - avoid passing an unnecessary argument to a Docker SDK for Python call that is only supported by version 3.0.0 or later (https://github.com/ansible-collections/community.docker/pull/243).
- docker_container_exec - ``chdir`` is only supported since Docker SDK for Python 3.0.0. Make sure that this option can only use when 3.0.0 or later is installed, and prevent passing this parameter on when ``chdir`` is not provided to this module (https://github.com/ansible-collections/community.docker/pull/243, https://github.com/ansible-collections/community.docker/issues/242).
- nsenter connection plugin - ensure the ``nsenter_pid`` option is retrieved in ``_connect`` instead of ``__init__`` to prevent a crash due to bad initialization order (https://github.com/ansible-collections/community.docker/pull/249).
- nsenter connection plugin - replace the use of ``--all-namespaces`` with specific namespaces to support compatibility with Busybox nsenter (used on, for example, Alpine containers) (https://github.com/ansible-collections/community.docker/pull/249).

v2.0.1
======

Release Summary
---------------

Maintenance release with some documentation fixes.

v2.0.0
======

Release Summary
---------------

New major release with some deprecations removed and a breaking change in the ``docker_compose`` module regarding the ``timeout`` parameter.

Breaking Changes / Porting Guide
--------------------------------

- docker_compose - fixed ``timeout`` defaulting behavior so that ``stop_grace_period``, if defined in the compose file, will be used if ``timeout`` is not specified (https://github.com/ansible-collections/community.docker/pull/163).

Deprecated Features
-------------------

- docker_container - using the special value ``all`` in ``published_ports`` has been deprecated. Use ``publish_all_ports=true`` instead (https://github.com/ansible-collections/community.docker/pull/210).

Removed Features (previously deprecated)
----------------------------------------

- docker_container - the default value of ``container_default_behavior`` changed to ``no_defaults`` (https://github.com/ansible-collections/community.docker/pull/210).
- docker_container - the default value of ``network_mode`` is now the name of the first network specified in ``networks`` if such are specified and ``networks_cli_compatible=true`` (https://github.com/ansible-collections/community.docker/pull/210).
- docker_container - the special value ``all`` can no longer be used in ``published_ports`` next to other values. Please use ``publish_all_ports=true`` instead (https://github.com/ansible-collections/community.docker/pull/210).
- docker_login - removed the ``email`` option (https://github.com/ansible-collections/community.docker/pull/210).

v1.10.0
=======

Release Summary
---------------

Regular feature and bugfix release.

Minor Changes
-------------

- Add the modules docker_container_exec, docker_image_load and docker_plugin to the ``docker`` module defaults group (https://github.com/ansible-collections/community.docker/pull/209).
- docker_config - add option ``data_src`` to read configuration data from target (https://github.com/ansible-collections/community.docker/issues/64, https://github.com/ansible-collections/community.docker/pull/203).
- docker_secret - add option ``data_src`` to read secret data from target (https://github.com/ansible-collections/community.docker/issues/64, https://github.com/ansible-collections/community.docker/pull/203).

v1.9.1
======

Release Summary
---------------

Regular bugfix release.

Bugfixes
--------

- docker_compose - fixed incorrect ``changed`` status for services with ``profiles`` defined, but none enabled (https://github.com/ansible-collections/community.docker/pull/192).

v1.9.0
======

Release Summary
---------------

New bugfixes and features release.

Minor Changes
-------------

- docker_* modules - include ``ImportError`` traceback when reporting that Docker SDK for Python could not be found (https://github.com/ansible-collections/community.docker/pull/188).
- docker_compose - added ``env_file`` option for specifying custom environment files (https://github.com/ansible-collections/community.docker/pull/174).
- docker_container - added ``publish_all_ports`` option to publish all exposed ports to random ports except those explicitly bound with ``published_ports`` (this was already added in community.docker 1.8.0) (https://github.com/ansible-collections/community.docker/pull/162).
- docker_container - added new ``command_handling`` option with current deprecated default value ``compatibility`` which allows to control how the module handles shell quoting when interpreting lists, and how the module handles empty lists/strings. The default will switch to ``correct`` in community.docker 3.0.0 (https://github.com/ansible-collections/community.docker/pull/186).
- docker_container - lifted restriction preventing the creation of anonymous volumes with the ``mounts`` option (https://github.com/ansible-collections/community.docker/pull/181).

Deprecated Features
-------------------

- docker_container - the new ``command_handling``'s default value, ``compatibility``, is deprecated and will change to ``correct`` in community.docker 3.0.0. A deprecation warning is emitted by the module in cases where the behavior will change. Please note that ansible-core will output a deprecation warning only once, so if it is shown for an earlier task, there could be more tasks with this warning where it is not shown (https://github.com/ansible-collections/community.docker/pull/186).

Bugfixes
--------

- docker_compose - fixes task failures when bringing up services while using ``docker-compose <1.17.0`` (https://github.com/ansible-collections/community.docker/issues/180).
- docker_container - make sure to also return ``container`` on ``detached=false`` when status code is non-zero (https://github.com/ansible-collections/community.docker/pull/178).
- docker_stack_info - make sure that module isn't skipped in check mode (https://github.com/ansible-collections/community.docker/pull/183).
- docker_stack_task_info - make sure that module isn't skipped in check mode (https://github.com/ansible-collections/community.docker/pull/183).

New Plugins
-----------

Connection
~~~~~~~~~~

- community.docker.nsenter - execute on host running controller container

v1.8.0
======

Release Summary
---------------

Regular bugfix and feature release.

Minor Changes
-------------

- Avoid internal ansible-core module_utils in favor of equivalent public API available since at least Ansible 2.9 (https://github.com/ansible-collections/community.docker/pull/164).
- docker_compose - added ``profiles`` option to specify service profiles when starting services (https://github.com/ansible-collections/community.docker/pull/167).
- docker_containers inventory plugin - when ``connection_type=docker-api``, now pass Docker daemon connection options from inventory plugin to connection plugin. This can be disabled by setting ``configure_docker_daemon=false`` (https://github.com/ansible-collections/community.docker/pull/157).
- docker_host_info - allow values for keys in ``containers_filters``, ``images_filters``, ``networks_filters``, and ``volumes_filters`` to be passed as YAML lists (https://github.com/ansible-collections/community.docker/pull/160).
- docker_plugin - added ``alias`` option to specify local names for docker plugins (https://github.com/ansible-collections/community.docker/pull/161).

Bugfixes
--------

- docker_compose - fix idempotence bug when using ``stopped: true`` (https://github.com/ansible-collections/community.docker/issues/142, https://github.com/ansible-collections/community.docker/pull/159).

v1.7.0
======

Release Summary
---------------

Small feature and bugfix release.

Minor Changes
-------------

- docker_image - allow to tag images by ID (https://github.com/ansible-collections/community.docker/pull/149).

v1.6.1
======

Release Summary
---------------

Bugfix release to reduce deprecation warning spam.

Bugfixes
--------

- docker_* modules and plugins, except ``docker_swarm`` connection plugin and ``docker_compose`` and ``docker_stack*` modules - only emit ``tls_hostname`` deprecation message if TLS is actually used (https://github.com/ansible-collections/community.docker/pull/143).

v1.6.0
======

Release Summary
---------------

Regular bugfix and feature release.

Minor Changes
-------------

- common module utils - correct error messages for guiding to install proper Docker SDK for Python module (https://github.com/ansible-collections/community.docker/pull/125).
- docker_container - allow ``memory_swap: -1`` to set memory swap limit to unlimited. This is useful when the user cannot set memory swap limits due to cgroup limitations or other reasons, as by default Docker will try to set swap usage to two times the value of ``memory`` (https://github.com/ansible-collections/community.docker/pull/138).

Deprecated Features
-------------------

- docker_* modules and plugins, except ``docker_swarm`` connection plugin and ``docker_compose`` and ``docker_stack*` modules - the current default ``localhost`` for ``tls_hostname`` is deprecated. In community.docker 2.0.0 it will be computed from ``docker_host`` instead (https://github.com/ansible-collections/community.docker/pull/134).

Bugfixes
--------

- docker-compose - fix not pulling when ``state: present`` and ``stopped: true`` (https://github.com/ansible-collections/community.docker/issues/12, https://github.com/ansible-collections/community.docker/pull/119).
- docker_plugin - also configure plugin after installing (https://github.com/ansible-collections/community.docker/issues/118, https://github.com/ansible-collections/community.docker/pull/135).
- docker_swarm_services - avoid crash during idempotence check if ``published_port`` is not specified (https://github.com/ansible-collections/community.docker/issues/107, https://github.com/ansible-collections/community.docker/pull/136).

v1.5.0
======

Release Summary
---------------

Regular feature release.

Minor Changes
-------------

- Add the ``use_ssh_client`` option to most docker modules and plugins (https://github.com/ansible-collections/community.docker/issues/108, https://github.com/ansible-collections/community.docker/pull/114).

Bugfixes
--------

- all modules - use ``to_native`` to convert exceptions to strings (https://github.com/ansible-collections/community.docker/pull/121).

New Modules
-----------

- community.docker.docker_container_exec - Execute command in a docker container

v1.4.0
======

Release Summary
---------------

Security release to address another potential secret leak. Also includes regular bugfixes and features.

Minor Changes
-------------

- docker_swarm_service - change ``publish.published_port`` option from mandatory to optional. Docker will assign random high port if not specified (https://github.com/ansible-collections/community.docker/issues/99).

Breaking Changes / Porting Guide
--------------------------------

- docker_swarm - if ``join_token`` is specified, a returned join token with the same value will be replaced by ``VALUE_SPECIFIED_IN_NO_LOG_PARAMETER``. Make sure that you do not blindly use the join tokens from the return value of this module when the module is invoked with ``join_token`` specified! This breaking change appears in a minor release since it is necessary to fix a security issue (https://github.com/ansible-collections/community.docker/pull/103).

Security Fixes
--------------

- docker_swarm - the ``join_token`` option is now marked as ``no_log`` so it is no longer written into logs (https://github.com/ansible-collections/community.docker/pull/103).

Bugfixes
--------

- ``docker_swarm_service`` - fix KeyError on caused by reference to deprecated option ``update_failure_action`` (https://github.com/ansible-collections/community.docker/pull/100).
- docker_swarm_service - mark ``secrets`` module option with ``no_log=False`` since it does not leak secrets (https://github.com/ansible-collections/community.general/pull/2001).

v1.3.0
======

Release Summary
---------------

Regular feature and bugfix release.

Minor Changes
-------------

- docker_container - add ``storage_opts`` option to specify storage options (https://github.com/ansible-collections/community.docker/issues/91, https://github.com/ansible-collections/community.docker/pull/93).
- docker_image - allows to specify platform to pull for ``source=pull`` with new option ``pull_platform`` (https://github.com/ansible-collections/community.docker/issues/79, https://github.com/ansible-collections/community.docker/pull/89).
- docker_image - properly support image IDs (hashes) for loading and tagging images (https://github.com/ansible-collections/community.docker/issues/86, https://github.com/ansible-collections/community.docker/pull/87).
- docker_swarm_service - adding support for maximum number of tasks per node (``replicas_max_per_node``) when running swarm service in replicated mode. Introduced in API 1.40 (https://github.com/ansible-collections/community.docker/issues/7, https://github.com/ansible-collections/community.docker/pull/92).

Bugfixes
--------

- docker_container - fix healthcheck disabling idempotency issue with strict comparison (https://github.com/ansible-collections/community.docker/issues/85).
- docker_image - prevent module failure when removing image that is removed between inspection and removal (https://github.com/ansible-collections/community.docker/pull/87).
- docker_image - prevent module failure when removing non-existent image by ID (https://github.com/ansible-collections/community.docker/pull/87).
- docker_image_info - prevent module failure when image vanishes between listing and inspection (https://github.com/ansible-collections/community.docker/pull/87).
- docker_image_info - prevent module failure when querying non-existent image by ID (https://github.com/ansible-collections/community.docker/pull/87).

New Modules
-----------

- community.docker.docker_image_load - Load docker image(s) from archives
- community.docker.docker_plugin - Manage Docker plugins

v1.2.2
======

Release Summary
---------------

Security bugfix release to address CVE-2021-20191.

Security Fixes
--------------

- docker_swarm - enabled ``no_log`` for the option ``signing_ca_key`` to prevent accidental disclosure (CVE-2021-20191, https://github.com/ansible-collections/community.docker/pull/80).

v1.2.1
======

Release Summary
---------------

Bugfix release.

Bugfixes
--------

- docker connection plugin - fix Docker version parsing, as some docker versions have a leading ``v`` in the output of the command ``docker version --format "{{.Server.Version}}"`` (https://github.com/ansible-collections/community.docker/pull/76).

v1.2.0
======

Release Summary
---------------

Feature release with one new feature and two bugfixes.

Minor Changes
-------------

- docker_container - added ``default_host_ip`` option which allows to explicitly set the default IP string for published ports without explicitly specified IPs. When using IPv6 binds with Docker 20.10.2 or newer, this needs to be set to an empty string (``""``) (https://github.com/ansible-collections/community.docker/issues/70, https://github.com/ansible-collections/community.docker/pull/71).

Bugfixes
--------

- docker_container - allow IPv6 zones (RFC 4007) in bind IPs (https://github.com/ansible-collections/community.docker/pull/66).
- docker_image - fix crash on loading images with versions of Docker SDK for Python before 2.5.0 (https://github.com/ansible-collections/community.docker/issues/72, https://github.com/ansible-collections/community.docker/pull/73).

v1.1.0
======

Release Summary
---------------

Feature release with three new plugins and modules.

Minor Changes
-------------

- docker_container - support specifying ``cgroup_parent`` (https://github.com/ansible-collections/community.docker/issues/6, https://github.com/ansible-collections/community.docker/pull/59).
- docker_container - when a container is started with ``detached=false``, ``status`` is now also returned when it is 0 (https://github.com/ansible-collections/community.docker/issues/26, https://github.com/ansible-collections/community.docker/pull/58).
- docker_image - support ``platform`` when building images (https://github.com/ansible-collections/community.docker/issues/22, https://github.com/ansible-collections/community.docker/pull/54).

Deprecated Features
-------------------

- docker_container - currently ``published_ports`` can contain port mappings next to the special value ``all``, in which case the port mappings are ignored. This behavior is deprecated for community.docker 2.0.0, at which point it will either be forbidden, or this behavior will be properly implemented similar to how the Docker CLI tool handles this (https://github.com/ansible-collections/community.docker/issues/8, https://github.com/ansible-collections/community.docker/pull/60).

Bugfixes
--------

- docker_image - if ``push=true`` is used with ``repository``, and the image does not need to be tagged, still push. This can happen if ``repository`` and ``name`` are equal (https://github.com/ansible-collections/community.docker/issues/52, https://github.com/ansible-collections/community.docker/pull/53).
- docker_image - report error when loading a broken archive that contains no image (https://github.com/ansible-collections/community.docker/issues/46, https://github.com/ansible-collections/community.docker/pull/55).
- docker_image - report error when the loaded archive does not contain the specified image (https://github.com/ansible-collections/community.docker/issues/41, https://github.com/ansible-collections/community.docker/pull/55).

New Plugins
-----------

Connection
~~~~~~~~~~

- community.docker.docker_api - Run tasks in docker containers

Inventory
~~~~~~~~~

- community.docker.docker_containers - Ansible dynamic inventory plugin for Docker containers.

New Modules
-----------

- community.docker.current_container_facts - Return facts about whether the module runs in a Docker container

v1.0.1
======

Release Summary
---------------

Maintenance release with a bugfix for ``docker_container``.

Bugfixes
--------

- docker_container - the validation for ``capabilities`` in ``device_requests`` was incorrect (https://github.com/ansible-collections/community.docker/issues/42, https://github.com/ansible-collections/community.docker/pull/43).

v1.0.0
======

Release Summary
---------------

This is the first production (non-prerelease) release of ``community.docker``.

Minor Changes
-------------

- Add collection-side support of the ``docker`` action group / module defaults group (https://github.com/ansible-collections/community.docker/pull/17).
- docker_image - return docker build output (https://github.com/ansible-collections/community.general/pull/805).
- docker_secret - add a warning when the secret does not have an ``ansible_key`` label but the ``force`` parameter is not set (https://github.com/ansible-collections/community.docker/issues/30, https://github.com/ansible-collections/community.docker/pull/31).

v0.1.0
======

Release Summary
---------------

The ``community.docker`` continues the work on the Ansible docker modules and plugins from their state in ``community.general`` 1.2.0. The changes listed here are thus relative to the modules and plugins ``community.general.docker*``.

All deprecation removals planned for ``community.general`` 2.0.0 have been applied. All deprecation removals scheduled for ``community.general`` 3.0.0 have been re-scheduled for ``community.docker`` 2.0.0.

Minor Changes
-------------

- docker_container - now supports the ``device_requests`` option, which allows to request additional resources such as GPUs (https://github.com/ansible/ansible/issues/65748, https://github.com/ansible-collections/community.general/pull/1119).

Removed Features (previously deprecated)
----------------------------------------

- docker_container - no longer returns ``ansible_facts`` (https://github.com/ansible-collections/community.docker/pull/1).
- docker_container - the default of ``networks_cli_compatible`` changed to ``true`` (https://github.com/ansible-collections/community.docker/pull/1).
- docker_container - the unused option ``trust_image_content`` has been removed (https://github.com/ansible-collections/community.docker/pull/1).
- docker_image - ``state=build`` has been removed. Use ``present`` instead (https://github.com/ansible-collections/community.docker/pull/1).
- docker_image - the ``container_limits``, ``dockerfile``, ``http_timeout``, ``nocache``, ``rm``, ``path``, ``buildargs``, ``pull`` have been removed. Use the corresponding suboptions of ``build`` instead (https://github.com/ansible-collections/community.docker/pull/1).
- docker_image - the ``force`` option has been removed. Use the more specific ``force_*`` options instead (https://github.com/ansible-collections/community.docker/pull/1).
- docker_image - the ``source`` option is now mandatory (https://github.com/ansible-collections/community.docker/pull/1).
- docker_image - the ``use_tls`` option has been removed. Use ``tls`` and ``validate_certs`` instead (https://github.com/ansible-collections/community.docker/pull/1).
- docker_image - the default of the ``build.pull`` option changed to ``false`` (https://github.com/ansible-collections/community.docker/pull/1).
- docker_image_facts - this alias is on longer available, use ``docker_image_info`` instead (https://github.com/ansible-collections/community.docker/pull/1).
- docker_network - no longer returns ``ansible_facts`` (https://github.com/ansible-collections/community.docker/pull/1).
- docker_network - the ``ipam_options`` option has been removed. Use ``ipam_config`` instead (https://github.com/ansible-collections/community.docker/pull/1).
- docker_service - no longer returns ``ansible_facts`` (https://github.com/ansible-collections/community.docker/pull/1).
- docker_swarm - ``state=inspect`` has been removed. Use ``docker_swarm_info`` instead (https://github.com/ansible-collections/community.docker/pull/1).
- docker_swarm_service - the ``constraints`` option has been removed. Use ``placement.constraints`` instead (https://github.com/ansible-collections/community.docker/pull/1).
- docker_swarm_service - the ``limit_cpu`` and ``limit_memory`` options has been removed. Use the corresponding suboptions in ``limits`` instead (https://github.com/ansible-collections/community.docker/pull/1).
- docker_swarm_service - the ``log_driver`` and ``log_driver_options`` options has been removed. Use the corresponding suboptions in ``logging`` instead (https://github.com/ansible-collections/community.docker/pull/1).
- docker_swarm_service - the ``reserve_cpu`` and ``reserve_memory`` options has been removed. Use the corresponding suboptions in ``reservations`` instead (https://github.com/ansible-collections/community.docker/pull/1).
- docker_swarm_service - the ``restart_policy``, ``restart_policy_attempts``, ``restart_policy_delay`` and ``restart_policy_window`` options has been removed. Use the corresponding suboptions in ``restart_config`` instead (https://github.com/ansible-collections/community.docker/pull/1).
- docker_swarm_service - the ``update_delay``, ``update_parallelism``, ``update_failure_action``, ``update_monitor``, ``update_max_failure_ratio`` and ``update_order`` options has been removed. Use the corresponding suboptions in ``update_config`` instead (https://github.com/ansible-collections/community.docker/pull/1).
- docker_volume - no longer returns ``ansible_facts`` (https://github.com/ansible-collections/community.docker/pull/1).
- docker_volume - the ``force`` option has been removed. Use ``recreate`` instead (https://github.com/ansible-collections/community.docker/pull/1).

Bugfixes
--------

- docker_login - fix internal config file storage to handle credentials for more than one registry (https://github.com/ansible-collections/community.general/issues/1117).
