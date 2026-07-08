Vendor JSON files in this directory
====================================

- cisco-8000_utility_docker.json — default when DUT ``asic_type`` is ``cisco-8000``
  (``files/<asic_type>_utility_docker.json``).

Other ASICs: add ``files/<asic_type>_utility_docker.json`` or pass:

  --utility-docker-config tests/vendor_utility_docker/files/myvendor_utility_docker.json

CI image tag and registry (pytest)
----------------------------------

  --live_addon_docker_image_tag <tag>
  --live_addon_docker_registry <host>

Aliases: ``--utility-docker-image-tag``, ``--utility-docker-registry``.

The tag overrides ``docker_run.image_ref`` in JSON and is used for ``docker pull`` (instead of
``duthost.os_version`` when set). Example::

  pytest tests/vendor_utility_docker/ ... \
    --live_addon_docker_image_tag=kube-20260527-202505-amd64

``test_utility_docker_image_upgrade`` requires ``--live_addon_docker_image_tag``: baseline pull
uses DUT ``os_version``; upgrade pull uses the CLI tag.

Command lines executed on the DUT are built only from vendor JSON (see utility_docker_helpers.py).
After tests, cleanup verification (cores, syslog, container gone) is implemented in code, not in JSON.

Registry pull (docker pull on DUT, same config as syncd-rpc)
-------------------------------------------------------------

**By default** a registry pull runs **first** (no extra keys in vendor JSON). It uses the same
Ansible ``docker_registry_host`` / ``docker_registry_username`` / ``docker_registry_password`` as
``swap_syncd`` (see ``tests.common.system_utils.docker.load_docker_registry_info``). Pull ref is
``{docker_registry_host}/{repository}:{duthost.os_version}`` where ``repository`` is parsed from
``docker_run.image_ref`` (text before the last ``:``), matching the tag convention used for RPC
images. Then ``docker tag`` to ``docker_run.image_ref`` when the pulled ref differs.

If pull or tag fails or ``docker_registry_host`` is unset (registry step skipped), the framework
falls back to a tarball on the DUT, tarball on the test runner, then an image already on the DUT.

Pass pytest ``--public_docker_registry`` to pull from ``public_docker_registry_host`` without
registry login, same as the QoS ``swap_syncd`` path (``tests/conftest.py``).

Optional version_matrix (log only; tests are not skipped on mismatch)
---------------------------------------------------------------------

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

Mismatch is logged only; tests continue. For skip-on-mismatch behavior see live-addon
(``tests/live_addon_docker/`` and ``require_version_matrix_or_skip``).
