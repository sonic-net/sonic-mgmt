"""Helpers for loading, installing, and validating vendor utility docker images on the DUT.

Commands run on the DUT are built only from the vendor JSON (see ``files/*.json``).
- Default path: ``files/<asic_type>_utility_docker.json`` (from DUT ``facts['asic_type']``),
  for example ``files/cisco-8000_utility_docker.json``. Override with ``--utility-docker-config``.

The JSON must define ``vendor``, ``docker_run`` (``docker load`` if needed, then ``docker run``),
``health``, and ``validation`` (container name for checks). ``docker_run.image_ref`` is derived as
``docker-live-addon-<vendor>[:tag]`` (optional ``docker_run.image_tag``, default ``latest``).
Optional fields: ``tarball_filename``, ``version_matrix``, ``candidate_image_refs``.
Registry pull (on by default when ``docker_registry_host`` is set) uses the same Ansible
``docker_registry_*`` fields as ``swap_syncd``; pass pytest ``--public_docker_registry`` to use
``public_docker_registry_host`` with no login, same as the QoS swap_syncd path.
Optional ``version_matrix`` lists compatible pairs of utility ``package.version`` (from image label
``com.azure.sonic.manifest``) vs SONiC trains (see ``require_version_matrix_or_skip``).
Container running / name lists use shared helpers
(``tests.common.helpers.dut_utils.is_container_running``, ``SonicHost.get_all_containers``).
Post-install teardown checks (no new cores, container removed, syslog grep) are fixed in this module.
"""

import collections
import copy
import fnmatch
import json
import logging
import os
import re
import shlex
import time

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import creds_on_dut, is_container_running
from tests.common.system_utils.docker import download_image, load_docker_registry_info
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))


def default_vendor_config_path(asic_type):
    """
    Return absolute path to ``files/<asic_type>_utility_docker.json`` under this package.

    ``asic_type`` is typically ``duthost.facts['asic_type']`` (e.g. ``cisco-8000``).
    """
    name = (asic_type or "").strip()
    if not name:
        raise ValueError("asic_type is empty")
    return os.path.abspath(os.path.join(MODULE_DIR, "files", "{}_utility_docker.json".format(name)))


# SONiC DUT default login home (same idea as admin $HOME for pre-staged tarballs)
DUT_ADMIN_HOME = "/home/admin"

# Post-teardown checks (always on; not configurable via vendor JSON)
_DEFAULT_SYSLOG_TAIL_LINES = 400
_DOCKER_RUN_UP_TIMEOUT = 120
_DOCKER_RUN_UP_INTERVAL = 3
_DEFAULT_SYSLOG_ERROR_PATTERN = (
    "(segfault|SIGSEGV|SIGABRT|Out of memory|oom-kill|FATAL|panic)"
)

# Used by ``run_config_reload_utility_start_reload_health``: pause after first reload before ``docker run``.
CONFIG_RELOAD_UTILITY_CYCLE_WAIT_SECONDS = 60

# ACR/docker repository name: docker-live-addon-<vendor> (e.g. docker-live-addon-cisco).
LIVE_ADDON_IMAGE_REPO_PREFIX = "docker-live-addon"
DEFAULT_LIVE_ADDON_IMAGE_TAG = "latest"

InstallSource = collections.namedtuple(
    "InstallSource", ["kind", "remote_tarball_path", "image_ref"]
)
# kind: "image_present" | "dut_home_tarball" | "runner_tarball" | "none"
# Registry installs use kind "image_present" after pull+tag (see try_registry_pull_utility_image).


def live_addon_image_repository(vendor):
    """
    Return the live-addon image repository name for a vendor (``docker-live-addon-<vendor>``).

    ``vendor`` comes from the top-level ``vendor`` field in the vendor JSON (e.g. ``cisco``).
    """
    name = (vendor or "").strip().lower()
    if not name:
        raise ValueError("vendor config must set 'vendor' for live-addon image repository name")
    return "{}-{}".format(LIVE_ADDON_IMAGE_REPO_PREFIX, name)


def resolve_docker_run_image_ref(cfg):
    """
    Build ``docker_run.image_ref`` from ``vendor`` and optional ``docker_run.image_tag``.

    Repository is always ``docker-live-addon-<vendor>``. Tag defaults to ``latest``; an explicit
    ``docker_run.image_tag`` or legacy ``docker_run.image_ref`` (tag portion only) overrides it.
    """
    dr = cfg.get("docker_run") or {}
    tag = dr.get("image_tag")
    if tag is None and dr.get("image_ref"):
        tag = image_ref_to_tag(dr["image_ref"])
    if not tag:
        tag = DEFAULT_LIVE_ADDON_IMAGE_TAG
    return "{}:{}".format(live_addon_image_repository(cfg.get("vendor")), str(tag).strip())


def normalize_vendor_config(cfg):
    """Set ``docker_run.image_ref`` from ``vendor`` (and optional tag) after loading JSON."""
    cfg.setdefault("docker_run", {})
    resolved = resolve_docker_run_image_ref(cfg)
    cfg["docker_run"]["image_ref"] = resolved
    logger.info("Resolved docker_run.image_ref from vendor: %s", resolved)
    return cfg


def load_vendor_config(config_path):
    """Load vendor JSON parameters and resolve ``docker_run.image_ref`` from ``vendor``."""
    with open(config_path, encoding="utf-8") as handle:
        cfg = json.load(handle)
    return normalize_vendor_config(cfg)


def image_ref_to_tag(image_ref):
    """Return the tag or digest label after ':' in a docker image ref, or 'latest' if missing."""
    if not image_ref or not isinstance(image_ref, str):
        return "latest"
    ref = image_ref.strip()
    if ":" in ref:
        return ref.split(":")[-1].strip()
    return "latest"


def utility_image_tag_for_matrix(cfg, install_source):
    """
    Docker image ref tag (part after ``:``), for logging / resolution only.

    ``version_matrix`` uses ``package.version`` from image metadata, not this tag.

    If the image is already on the DUT, use that ref's tag. Otherwise use docker_run.image_ref
    (expected tag after docker load).
    """
    if install_source.kind == "image_present" and install_source.image_ref:
        return image_ref_to_tag(install_source.image_ref)
    dr = cfg.get("docker_run") or {}
    return image_ref_to_tag(dr.get("image_ref", ""))


def sonic_matches_sonic_glob(duthost, glob_pattern):
    """
    True if DUT ``os_version``, ``sonic_release``, or ``show version`` one-liner matches glob.

    Trains like ``202411``, ``202505`` appear in strings such as
    ``SONiC.azure_cisco_202411.39653-dirty-...`` or ``202411.1.2.3.4``; globs like ``202411*``
    match the full ``os_version`` line.
    """
    if fnmatch.fnmatch(duthost.os_version, glob_pattern):
        return True
    sr = getattr(duthost, "sonic_release", None)
    if sr and fnmatch.fnmatch(str(sr), glob_pattern):
        return True
    try:
        ver_line = duthost.shell("show version | head -1", module_ignore_errors=True).get("stdout", "")
        if ver_line.strip() and fnmatch.fnmatch(ver_line.strip(), glob_pattern):
            return True
    except Exception as exc:
        logger.warning(
            "sonic_matches_sonic_glob: optional show version line probe failed (ignored): %s",
            exc,
        )
    return False


def get_docker_image_config_labels(duthost, image_ref):
    """
    Return ``Config.Labels`` from ``docker image inspect`` (full JSON, no Go ``-f`` templates).

    Azure/Cisco utility images often set ``com.azure.sonic.manifest`` (JSON string) and ``Tag``.
    """
    if not image_ref or not str(image_ref).strip():
        return {}
    qref = shlex.quote(str(image_ref).strip())
    out = duthost.shell("sudo docker image inspect {}".format(qref), module_ignore_errors=True)
    if out.get("rc") != 0:
        logger.warning("docker image inspect failed for %s: %s", image_ref, out.get("stderr", ""))
        return {}
    try:
        data = json.loads(out["stdout"])
        if not data:
            return {}
        return data[0].get("Config", {}).get("Labels") or {}
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        logger.warning("Could not parse docker image inspect JSON for %s: %s", image_ref, exc)
        return {}


def package_version_from_azure_sonic_manifest_labels(labels):
    """
    Parse ``package.version`` from label ``com.azure.sonic.manifest`` (JSON), e.g. ``202405.1.0-0``.
    """
    if not labels:
        return None
    raw = labels.get("com.azure.sonic.manifest")
    if not raw or not isinstance(raw, str):
        return None
    try:
        manifest = json.loads(raw)
        pkg = manifest.get("package") or {}
        ver = pkg.get("version")
        return str(ver).strip() if ver is not None else None
    except (ValueError, TypeError, AttributeError):
        return None


def tag_label_from_image_labels(labels):
    """Optional ``Tag`` label on the image (e.g. build id string)."""
    if not labels:
        return None
    t = labels.get("Tag")
    return str(t).strip() if t else None


def _version_matrix_row_matches_utility(row, package_version):
    """
    Row may filter by ``utility_image_version_glob`` and/or ``utility_package_version_glob``.

    Both keys apply to ``package.version`` parsed from label ``com.azure.sonic.manifest`` (not the
    Docker image ``:tag``). If a key is set but ``package_version`` is missing, the row does not
    match.
    """
    if "utility_image_version_glob" in row and row["utility_image_version_glob"] is not None:
        if not package_version:
            return False
        if not fnmatch.fnmatch(package_version, row["utility_image_version_glob"]):
            return False
    if "utility_package_version_glob" in row and row["utility_package_version_glob"] is not None:
        if not package_version:
            return False
        if not fnmatch.fnmatch(package_version, row["utility_package_version_glob"]):
            return False
    return True


def require_version_matrix_or_skip(duthost, cfg, resolved_image_ref):
    """
    Optional JSON ``version_matrix``: skip when utility ``package.version`` (image metadata) and
    DUT SONiC build are not declared compatible.

    Call **after** the image exists on the DUT (``docker load`` / present) and **before**
    ``docker run``, passing ``resolved_image_ref`` (e.g. ``docker-live-addon-cisco:latest``).

    Schema (each row: globs match ``package.version`` from ``com.azure.sonic.manifest``; not the
    Docker ``:tag``). Both ``utility_image_version_glob`` and ``utility_package_version_glob`` use
    that same metadata string when present::

        "version_matrix": [
          {
            "utility_package_version_glob": "202405*",
            "compatible_sonic_globs": ["202411*", "202505*"]
          }
        ]

    ``compatible_sonic_globs`` match ``duthost.os_version``, ``sonic_release``, or the first line
    of ``show version`` (fnmatch).

    Omitted, null, or ``[]`` disables this check.
    """
    matrix = cfg.get("version_matrix")
    if not matrix:
        return

    labels = get_docker_image_config_labels(duthost, resolved_image_ref)
    utility_tag = image_ref_to_tag(resolved_image_ref)
    package_ver = package_version_from_azure_sonic_manifest_labels(labels)

    matching_rows = []
    for row in matrix:
        if _version_matrix_row_matches_utility(row, package_ver):
            matching_rows.append(row)

    if not matching_rows:
        pytest.skip(
            "version_matrix: no row matches package.version={!r} (image ref {!r}, ref tag={!r}, "
            "labels Tag={!r}).".format(
                package_ver,
                resolved_image_ref,
                utility_tag,
                tag_label_from_image_labels(labels),
            )
        )

    allowed = []
    for row in matching_rows:
        allowed.extend(row.get("compatible_sonic_globs") or [])

    if not allowed:
        pytest.skip(
            "version_matrix: matching row has no compatible_sonic_globs (package.version={!r})".format(
                package_ver
            )
        )

    if any(sonic_matches_sonic_glob(duthost, g) for g in allowed):
        return

    pytest.skip(
        "version_matrix: DUT SONiC not compatible: os_version={!r} sonic_release={!r}; "
        "package.version={!r} (ref tag={!r}); allowed sonic globs: {}".format(
            duthost.os_version,
            getattr(duthost, "sonic_release", ""),
            package_ver,
            utility_tag,
            allowed,
        )
    )


def _image_refs_to_try(cfg):
    """Names/tags to match swap_syncd-style 'already on DUT' behavior (docker image inspect)."""
    refs = []
    dr = cfg.get("docker_run") or {}
    if dr.get("image_ref"):
        refs.append(dr["image_ref"].strip())
    for extra in cfg.get("candidate_image_refs", []):
        ex = extra.strip()
        if ex and ex not in refs:
            refs.append(ex)
    return refs


def find_existing_utility_image(duthost, cfg):
    """
    Return first image ref that exists in local docker storage on the DUT, or None.
    Same idea as swap_syncd checking `docker image inspect docker-syncd-<vendor>-rpc`.
    """
    for ref in _image_refs_to_try(cfg):
        if image_exists(duthost, ref):
            logger.info("Found existing utility image on DUT: %s", ref)
            return ref
    return None


def dut_home_tarball_path(cfg):
    """Path under admin home for a pre-copied .gz (e.g. ~/docker-cisco-utility.gz)."""
    name = cfg.get("tarball_filename")
    if not name:
        raise ValueError("vendor config must set tarball_filename")
    home = cfg.get("dut_tarball_home", DUT_ADMIN_HOME)
    return os.path.join(home, name)


def dut_file_exists(duthost, path):
    return duthost.command("sudo test -f {}".format(path), module_ignore_errors=True)["rc"] == 0


def _image_repository_from_image_ref(image_ref):
    """Return repository part before the last ':' in ``name:tag``; ``image_ref`` if no colon."""
    ref = (image_ref or "").strip()
    if not ref:
        return None
    pos = ref.rfind(":")
    if pos <= 0:
        return ref
    return ref[:pos].strip()


def _utility_registry_pull_settings(cfg):
    """
    Return settings for a utility image ``docker pull`` using the same registry as syncd-rpc
    (``docker_registry_host`` / login from ``creds_on_dut``). No separate vendor JSON for the registry.

    Pull uses repository from ``docker_run.image_ref`` (text before the last ``:``) and tag
    ``duthost.os_version``, same tag convention as ``swap_syncd`` / ``download_image`` for RPC images.

    Returns None when ``docker_run.image_ref`` is missing.
    """
    dr = cfg.get("docker_run") or {}
    target_ref = (dr.get("image_ref") or "").strip()
    if not target_ref:
        return None

    image_name = _image_repository_from_image_ref(target_ref)
    if not image_name:
        logger.warning("utility registry pull: cannot parse repository from docker_run.image_ref")
        return None

    return {"image_name": image_name, "image_version": None, "target_ref": target_ref}


def resolve_utility_install_source(
    duthost,
    cfg,
    local_runner_tarball_path,
    public_docker_registry=False,
    docker_registry_host_override=None,
):
    """
    Resolve where to get the image from.

    **Registry is tried first** when ``docker_run.image_ref`` is set and Ansible defines
    ``docker_registry_host`` (after applying ``public_docker_registry`` the same way as
    ``swap_syncd``: host becomes ``public_docker_registry_host``, username/password cleared).
    Image name is derived from ``docker_run.image_ref``, tag from ``duthost.os_version``. On failure
    or missing registry host, resolution continues with DUT tarball, runner tarball, then an image
    already in docker storage.

    1) ``docker pull`` + ``docker tag`` to ``docker_run.image_ref`` (when registry path active).
    2) Tarball under admin home on DUT — ``docker load -i``.
    3) Tarball on the ansible test runner — copy to /tmp on DUT, then ``docker load -i``.
    4) Image already on DUT (docker image inspect).

    If none apply, returns InstallSource(kind='none', ...).
    """
    reg_settings = _utility_registry_pull_settings(cfg)
    if reg_settings is not None:
        ref = try_registry_pull_utility_image(
            duthost,
            reg_settings,
            public_docker_registry=public_docker_registry,
            docker_registry_host_override=docker_registry_host_override,
        )
        if ref:
            logger.info("Utility docker image from registry: %s", ref)
            return InstallSource("image_present", None, ref)
        logger.info("Utility registry pull did not produce an image; trying DUT tarball, runner tarball, local image")

    dut_path = dut_home_tarball_path(cfg)
    if dut_file_exists(duthost, dut_path):
        logger.info("Utility docker tarball on DUT (will docker load): %s", dut_path)
        return InstallSource("dut_home_tarball", dut_path, None)

    if local_runner_tarball_path and os.path.isfile(local_runner_tarball_path):
        base = os.path.basename(local_runner_tarball_path)
        remote = "/tmp/{}".format(base)
        logger.info("Utility docker tarball on test runner (will copy to DUT then docker load): %s", remote)
        return InstallSource("runner_tarball", remote, None)

    ref = find_existing_utility_image(duthost, cfg)
    if ref:
        logger.info("Utility docker image already on DUT (no docker load): %s", ref)
        return InstallSource("image_present", None, ref)

    return InstallSource("none", None, None)


def resolve_local_tarball_path(config, search_dir, tarball_override):
    """
    Resolve path to the .gz image on the ansible test server (before copy to DUT).

    Search order:
    1) tarball_override (pytest --utility-docker-tarball)
    2) search_dir / config['tarball_filename'] (default search_dir is this test module directory)
    """
    if tarball_override:
        return os.path.abspath(tarball_override)
    name = config.get("tarball_filename")
    if not name:
        raise ValueError("vendor config must set tarball_filename")
    return os.path.abspath(os.path.join(search_dir, name))


def try_registry_pull_utility_image(
    duthost, settings, public_docker_registry=False, docker_registry_host_override=None
):
    """
    Pull ``{registry}/{image_name}:{image_version}`` on the DUT (Ansible ``creds`` / registry same
    as ``swap_syncd`` / ``download_image``), then ``docker tag`` to ``settings['target_ref']``
    when the pulled ref differs.

    When ``public_docker_registry`` is true, applies the same credential override as the
    ``swap_syncd`` fixture in ``tests/conftest.py`` (``docker_registry_host`` from
    ``public_docker_registry_host``, clear username/password).

    ``settings`` comes from ``_utility_registry_pull_settings``. Returns ``target_ref`` on success,
    or None on failure (caller tries tarballs / local image).
    """
    image_name = settings["image_name"]
    target_ref = settings["target_ref"]

    creds = copy.deepcopy(creds_on_dut(duthost))
    if public_docker_registry:
        creds["docker_registry_host"] = creds.get("public_docker_registry_host")
        creds["docker_registry_username"] = ""
        creds["docker_registry_password"] = ""
    if docker_registry_host_override and str(docker_registry_host_override).strip():
        creds["docker_registry_host"] = str(docker_registry_host_override).strip()
    try:
        registry = load_docker_registry_info(duthost, creds)
    except ValueError as exc:
        logger.warning("utility registry pull: %s", exc)
        return None

    ver = settings.get("image_version")
    if ver is not None and str(ver).strip():
        image_version = str(ver).strip()
    else:
        image_version = duthost.os_version

    logger.info(
        "utility registry pull: docker pull %s/%s:%s then tag as %s",
        registry.host,
        image_name,
        image_version,
        target_ref,
    )
    try:
        download_image(duthost, registry, image_name, image_version)
    except RuntimeError as exc:
        logger.warning("utility registry pull: download failed: %s", exc)
        return None

    source_ref = "{}/{}:{}".format(registry.host, image_name, image_version)
    if source_ref != target_ref:
        duthost.command(
            "docker tag {} {}".format(shlex.quote(source_ref), shlex.quote(target_ref))
        )
    if not image_exists(duthost, target_ref):
        logger.warning("utility registry pull: target image %r not present after pull/tag", target_ref)
        return None
    return target_ref


def build_docker_load_command(remote_tarball):
    """``docker load`` line; ``remote_tarball`` is path on the DUT."""
    return "sudo docker load -i {}".format(remote_tarball)


def build_docker_run_command(cfg):
    """
    Full ``docker run`` command from ``cfg['docker_run']``.

    Uses ``detach`` (default true) -> ``-d``, then ``cli_args``, then
    ``--name <container_name> <image_ref>``.
    """
    dr = cfg["docker_run"]
    image_ref = dr["image_ref"]
    name = dr["container_name"]
    args = dr.get("cli_args", [])
    if not isinstance(args, list):
        raise ValueError("docker_run.cli_args must be a list of argv tokens")
    parts = []
    if dr.get("sudo", True):
        parts.append("sudo")
    parts.extend(["docker", "run"])
    if dr.get("detach", True):
        parts.append("-d")
    parts.extend(args)
    parts.extend(["--name", name, image_ref])
    return " ".join(parts)


def parse_image_from_docker_load(load_output):
    """
    Try to extract name:tag from `docker load` stdout/stderr.
    Example: 'Loaded image: docker-cisco-utility:20241110.22'
    """
    match = re.search(r"Loaded image:\s*(\S+)", load_output)
    if match:
        return match.group(1).strip()
    return None


def docker_load(duthost, remote_tarball):
    """
    Run ``sudo docker load -i <tarball>`` on the DUT. Fails the ansible command if load fails.
    Returns combined stdout+stderr for parsing (some docker builds log ``Loaded image`` on stderr).
    """
    cmd = build_docker_load_command(remote_tarball)
    logger.info("Running: %s", cmd)
    result = duthost.command(cmd)
    out = (result.get("stdout") or "").strip()
    err = (result.get("stderr") or "").strip()
    combined = (out + "\n" + err).strip()
    logger.info("docker load stdout: %s", out)
    if err:
        logger.info("docker load stderr: %s", err)
    return combined


def docker_run_manual(duthost, cfg):
    """Run container using ``build_docker_run_command(cfg)`` (all options from vendor JSON)."""
    cmd = build_docker_run_command(cfg)
    logger.info("Running: %s", cmd)
    duthost.command(cmd)
    cname = (cfg.get("docker_run") or {}).get("container_name")
    if not cname:
        return

    def _running():
        return is_container_running(duthost, cname)

    if wait_until(_DOCKER_RUN_UP_TIMEOUT, _DOCKER_RUN_UP_INTERVAL, 0, _running):
        return

    ps_out = duthost.command(
        "sudo docker ps -a --filter name={} --no-trunc".format(cname),
        module_ignore_errors=True,
    ).get("stdout", "")
    log_out = duthost.command(
        "sudo docker logs --tail 120 {} 2>&1".format(cname),
        module_ignore_errors=True,
    ).get("stdout", "")
    pytest_assert(
        False,
        "Container {!r} did not stay running after docker run (waited {}s). "
        "docker ps -a:\n{}\n\ndocker logs:\n{}".format(
            cname, _DOCKER_RUN_UP_TIMEOUT, ps_out, log_out
        ),
    )


def image_exists(duthost, image_ref):
    # Quote for refs that contain special chars
    out = duthost.command(
        "sudo docker image inspect {}".format(image_ref), module_ignore_errors=True
    )
    return out["rc"] == 0


def build_health_check_curl_command(health_cfg):
    """curl used for validation; fields from JSON ``health`` section."""
    port = int(health_cfg["port"])
    path = health_cfg.get("url_path", "/health")
    host = health_cfg.get("bind_host", "127.0.0.1")
    return (
        "curl -sS -m 15 -o /tmp/utility_docker_health.out -w '%{{http_code}}' "
        "http://{}:{}{}".format(host, port, path)
    )


def http_health_check(duthost, health_cfg):
    """
    Query HTTP health endpoint from the DUT (container typically uses --net=host).
    Returns (ok: bool, http_code: str, body_snippet: str).
    """
    expect = str(health_cfg.get("expect_http_code", 200))
    curl = build_health_check_curl_command(health_cfg)
    code = duthost.command(curl)["stdout"].strip()
    body = duthost.command("sudo cat /tmp/utility_docker_health.out", module_ignore_errors=True).get(
        "stdout", ""
    )[:500]
    ok = code == expect
    return ok, code, body


def run_config_reload_utility_start_reload_health(duthost, resolved_cfg):
    """
    Run: stop utility container, ``config reload``, sleep, ``docker run`` (utility), ``config reload``,
    then HTTP health (same semantics as ``wait_for_health_ready``).

    ``resolved_cfg`` must be the vendor JSON dict with ``docker_run.image_ref`` set after tarball load
    or image resolution (same object the module fixture uses for ``docker_run_manual``).
    """
    from tests.common.config_reload import config_reload

    docker_manual_teardown(duthost, resolved_cfg["docker_run"])
    logger.info("First config reload (utility container stopped)")
    config_reload(
        duthost,
        config_source="config_db",
        safe_reload=True,
        wait_for_bgp=True,
    )
    logger.info(
        "Waiting %s s after first config reload before starting utility container",
        CONFIG_RELOAD_UTILITY_CYCLE_WAIT_SECONDS,
    )
    time.sleep(CONFIG_RELOAD_UTILITY_CYCLE_WAIT_SECONDS)

    cfg_run = copy.deepcopy(resolved_cfg)
    docker_run_manual(duthost, cfg_run)
    logger.info("Second config reload (utility container running)")
    config_reload(
        duthost,
        config_source="config_db",
        safe_reload=True,
        wait_for_bgp=True,
    )
    return wait_for_health_ready(duthost, resolved_cfg["health"])


def wait_for_health_ready(duthost, health_cfg):
    """
    Honor ``health.wait_seconds_before_check`` (e.g. 900 for slow readiness), then either a
    single probe or repeated probes per ``probe_timeout_seconds`` / ``probe_interval_seconds``.
    Returns (ok, http_code, body) from the last attempt.
    """
    initial = int(health_cfg.get("wait_seconds_before_check", 0))
    if initial > 0:
        logger.info("Health: sleeping %s s before first probe (JSON wait_seconds_before_check)", initial)
        time.sleep(initial)

    timeout = int(health_cfg.get("probe_timeout_seconds", 0))
    interval = int(health_cfg.get("probe_interval_seconds", 30))
    if timeout <= 0:
        return http_health_check(duthost, health_cfg)

    last = (False, "", "")

    def _probe():
        nonlocal last
        last = http_health_check(duthost, health_cfg)
        return last[0]

    polled = wait_until(timeout, interval, 0, _probe)
    pytest_assert(polled, "Health endpoint did not return expect_http_code within {} s".format(timeout))
    return last


def docker_manual_teardown(duthost, docker_run_cfg):
    name = docker_run_cfg["container_name"]
    logger.info("Teardown docker: stop and remove %s", name)
    duthost.command("sudo docker stop {} 2>/dev/null || true".format(name), module_ignore_errors=True)
    duthost.command("sudo docker rm -f {}".format(name), module_ignore_errors=True)


def remove_configured_utility_images(duthost, cfg):
    """
    Best-effort ``docker rmi -f`` for ``docker_run.image_ref`` and ``candidate_image_refs``.
    Used immediately before ``docker load`` so the tarball load does not layer on old tags.
    """
    for ref in _image_refs_to_try(cfg):
        logger.info("Removing utility image before docker load (best-effort): %s", ref)
        duthost.command("sudo docker rmi -f {}".format(ref), module_ignore_errors=True)


def prepare_utility_docker_install(duthost, cfg, install_source):
    """
    At test start: stop and remove the utility container if it is still running.
    When install uses a tarball (``docker load``), remove configured image refs before load.
    When using an image already on the DUT (no tarball), only the container is removed.
    """
    dr = cfg.get("docker_run")
    if not dr:
        return
    docker_manual_teardown(duthost, dr)
    if install_source.kind == "image_present":
        return
    remove_configured_utility_images(duthost, cfg)


def get_core_filenames(duthost):
    """Filenames under /var/core/ (same rules as platform tests)."""
    if "20191130" in duthost.os_version:
        out = duthost.shell("ls /var/core/ 2>/dev/null | grep -v python || true")["stdout"]
    else:
        out = duthost.shell("ls /var/core/ 2>/dev/null || true")["stdout"]
    return set(line.strip() for line in out.splitlines() if line.strip())


def verify_no_new_core_files(duthost, pre_cores):
    post = get_core_filenames(duthost)
    new_files = post - pre_cores
    pytest_assert(
        not new_files,
        "New core file(s) appeared under /var/core/: {}".format(", ".join(sorted(new_files))),
    )


def verify_container_absent(duthost, container_name):
    """Use ``SonicHost.get_all_containers()`` (escaped docker format, same as rest of sonic-mgmt)."""
    if not container_name:
        return
    all_names = duthost.get_all_containers()
    pytest_assert(
        container_name not in all_names,
        "Container {} still present after teardown".format(container_name),
    )


def verify_syslog_clean_after_teardown(duthost, cfg):
    """
    Tail syslog; if any line mentions the utility (hints) and matches the default error pattern, fail.
    """
    tail_lines = _DEFAULT_SYSLOG_TAIL_LINES
    err_pat = _DEFAULT_SYSLOG_ERROR_PATTERN
    hints = []
    val = cfg.get("validation") or {}
    if val.get("docker_container_name"):
        hints.append(val["docker_container_name"])
    dr = cfg.get("docker_run") or {}
    if dr.get("container_name"):
        cname = dr["container_name"]
        if cname not in hints:
            hints.append(cname)
    image_ref = dr.get("image_ref", "")
    if image_ref:
        base = image_ref.split(":")[0].split("/")[-1]
        if base and base not in hints:
            hints.append(base)
    if not hints:
        return
    hint_alt = "|".join(re.escape(h) for h in hints)
    script = (
        "sudo tail -n {n} /var/log/syslog 2>/dev/null | grep -iE '({hints})' | grep -iE '{err}' || true"
    ).format(n=tail_lines, hints=hint_alt, err=err_pat)
    bad = duthost.command(script, module_ignore_errors=True).get("stdout", "").strip()
    pytest_assert(
        not bad,
        "Syslog lines after teardown matched error pattern for utility hints:\n{}".format(bad[:2000]),
    )


def verify_post_teardown(duthost, cfg, pre_core_filenames):
    """
    After stop/uninstall: assert no new core files, utility container absent, syslog spot-check.
    Behavior is fixed in code (not vendor JSON).

    Relation to sonic-mgmt infra (keep these checks):
    - Loganalyzer runs per test and does not analyze syslog after the last test returns; uninstall
      in the module fixture runs after that, so a tail+grep for utility hints still adds coverage.
    - core_dump_and_config_check (module autouse) compares /var/core at module boundaries but does
      not pytest.fail on new cores; it logs and records cache for telemetry. The assert here fails
      the run if new cores appeared during this fixture.
    """
    val = cfg.get("validation") or {}
    cname = val.get("docker_container_name", (cfg.get("docker_run") or {}).get("container_name"))

    verify_no_new_core_files(duthost, pre_core_filenames)
    verify_container_absent(duthost, cname)
    verify_syslog_clean_after_teardown(duthost, cfg)
