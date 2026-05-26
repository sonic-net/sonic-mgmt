Vendor JSON files in this directory
====================================

- cisco-8000_utility_docker.json — Cisco 8000 utility container (default path when DUT
  ``asic_type`` is ``cisco-8000``: ``files/<asic_type>_utility_docker.json``).

Other ASICs: add ``files/<asic_type>_utility_docker.json`` (match ``duthost.facts['asic_type']``), or run pytest with:

  --utility-docker-config tests/live_addon_docker/files/<your>_utility_docker.json

Command lines executed on the DUT are built only from that JSON (see utility_docker_helpers.py).
After tests, cleanup verification (cores, syslog, container gone) is implemented in code, not in JSON.

Live-addon image repository name
--------------------------------

The top-level ``vendor`` field drives the docker image repository name on pull/load/run::

  docker-live-addon-<vendor>[:tag]

For example ``"vendor": "cisco"`` resolves to ``docker-live-addon-cisco:latest``. Other vendors use
the same pattern (``docker-live-addon-abc``, ``docker-live-addon-xyz``, …). Optional
``docker_run.image_tag`` overrides the tag (default ``latest``). ``container_name`` remains
vendor-specific in JSON (e.g. ``cisco-utility``).

Registry pull (docker pull on DUT, same config as syncd-rpc)
-------------------------------------------------------------

**By default** a registry pull runs **first** (no extra keys in vendor JSON). It uses the same
Ansible ``docker_registry_host`` / ``docker_registry_username`` / ``docker_registry_password`` as
``swap_syncd`` (see ``tests.common.system_utils.docker.load_docker_registry_info``). Pull ref is
``{docker_registry_host}/{repository}:{duthost.os_version}`` where ``repository`` is
``docker-live-addon-<vendor>`` (derived from the JSON ``vendor`` field), matching the tag convention
used for RPC images. Then ``docker tag`` to ``docker_run.image_ref`` when the pulled ref differs.

If pull or tag fails or ``docker_registry_host`` is unset (registry step skipped), the framework
falls back to a tarball on the DUT, tarball on the test runner, then an image already on the DUT.

Pass pytest ``--public_docker_registry`` to pull from ``public_docker_registry_host`` without
registry login, same as the QoS ``swap_syncd`` path (``tests/conftest.py``).

Optional version_matrix (skip when utility vs DUT SONiC is not listed as compatible)
---------------------------------------------------------------------------------

Omit the key, use null, or [] to disable. The check runs after the image is on the DUT
(``docker load`` or already present) and before ``docker run``, using ``docker image inspect``
(full JSON, no fragile ``-f`` templates).

Each row may filter the **utility** side by any combination of (both use the same metadata
string, not the Docker ``:tag``):

- ``utility_image_version_glob`` — fnmatch on ``package.version`` from label ``com.azure.sonic.manifest``.
- ``utility_package_version_glob`` — fnmatch on the same ``package.version`` value.

Omit a key to skip that dimension. If either glob key is set but the manifest / ``package.version``
is missing, that row does not match.

**SONiC** side: ``compatible_sonic_globs`` are matched (fnmatch) against ``duthost.os_version``,
``duthost.sonic_release``, and the first line of ``show version``. Trains like ``202411``,
``202505`` in builds such as ``SONiC.azure_cisco_202411.39653-dirty-...`` are matched with
globs like ``202411*``, ``202505*``.

Examples::

  "version_matrix": [
    {
      "utility_package_version_glob": "202405*",
      "compatible_sonic_globs": ["202411*", "202505*"]
    }
  ]

sonic-mgmt also has generic release helpers (tests/common/utilities.py: check_skip_release,
skip_release) and many tests use duthost.os_version / pytest_require(parse_version(...)) —
there is no separate built-in matrix for vendor docker vs SONiC; this JSON field is for that.
