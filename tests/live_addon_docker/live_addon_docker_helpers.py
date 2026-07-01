"""Helpers for loading, installing, and validating live-addon docker images on the DUT.

Commands run on the DUT are built from the vendor JSON (see ``files/*.json``).
Default path: ``files/<asic_type>_live_addon_docker.json`` (from DUT ``facts['asic_type']``),
for example ``files/<asic_type>_live_addon_docker.json``. Override with ``--live-addon-docker-config``.

The JSON must define ``vendor``, ``docker_run`` (``docker load`` if needed, then ``docker run``),
``health``, and ``validation`` (container name for checks). ``docker_run.image_ref`` is derived as
``docker-live-addon-<vendor>[:tag]`` unless set explicitly (must match ACR repo for registry pull).
Optional fields: ``tarball_filename``, ``version_matrix``, ``candidate_image_refs``.
Registry pull uses Ansible ``docker_registry_*`` or pytest ``--live_addon_docker_registry``;
``--live_addon_docker_image_tag`` overrides pull/run tag. ``--public_docker_registry`` for public host.
Optional ``version_matrix`` skips when live-addon vs DUT SONiC is not declared compatible
(see ``require_version_matrix_or_skip``).
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


def default_live_addon_config_path(asic_type):
    """
    Return absolute path to ``files/<asic_type>_live_addon_docker.json`` under this package.

    ``asic_type`` is ``duthost.facts['asic_type']`` (selects ``files/<asic_type>_live_addon_docker.json``).
    """
    name = (asic_type or "").strip()
    if not name:
        raise ValueError("asic_type is empty")
    return os.path.abspath(os.path.join(MODULE_DIR, "files", "{}_live_addon_docker.json".format(name)))


# SONiC DUT default login home (same idea as admin $HOME for pre-staged tarballs)
DUT_ADMIN_HOME = "/home/admin"

# Post-teardown checks (always on; not configurable via vendor JSON)
_DEFAULT_SYSLOG_TAIL_LINES = 400
_DOCKER_RUN_UP_TIMEOUT = 120
_DOCKER_RUN_UP_INTERVAL = 3
_DEFAULT_SYSLOG_ERROR_PATTERN = (
    "(segfault|SIGSEGV|SIGABRT|Out of memory|oom-kill|FATAL|panic)"
)

# Default supervisord-managed programs (names from ``supervisorctl status`` in live-addon container).
DEFAULT_LIVE_ADDON_EXPECTED_PROCESSES = (
    "start",
    "health-monitor",
    "health-server",
)


def expected_processes_from_validation(val):
    """Return ``validation.expected_processes`` or the default list; empty list means skip process checks."""
    if not val:
        return list(DEFAULT_LIVE_ADDON_EXPECTED_PROCESSES)
    expected = val.get("expected_processes")
    if expected is None:
        return list(DEFAULT_LIVE_ADDON_EXPECTED_PROCESSES)
    return expected


# Generic poll timing for ``validation.startup_log`` (vendor JSON overrides ``wait_seconds``).
# How long supervisord/diagnostic lines take depends on the vendor; set ``wait_seconds`` per vendor JSON.
DEFAULT_STARTUP_LOG_WAIT_SECONDS = 120
DEFAULT_STARTUP_LOG_POLL_INTERVAL_SECONDS = 30
# supervisord ``RUNNING`` poll only (does not use startup_log or health ``probe_timeout_seconds``).
DEFAULT_PROCESS_WAIT_SECONDS = 120
DEFAULT_PROCESS_POLL_INTERVAL_SECONDS = 30
_STARTUP_LOG_FAILURE_SNIPPET_CHARS = 6000

# ``docker inspect -f`` Go template for current container start time (used with ``docker logs --since``).
_DOCKER_INSPECT_STARTED_AT_FMT = "{{.State.StartedAt}}"
_STARTED_AT_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")

# ACR/docker repository name: docker-live-addon-<vendor> (from JSON ``vendor`` field).
LIVE_ADDON_IMAGE_REPO_PREFIX = "docker-live-addon"
DEFAULT_LIVE_ADDON_IMAGE_TAG = "latest"

InstallSource = collections.namedtuple(
    "InstallSource", ["kind", "remote_tarball_path", "image_ref"]
)
# kind: "image_present" | "dut_home_tarball" | "runner_tarball" | "none"
# Registry installs use kind "image_present" after pull+tag (see try_registry_pull_live_addon_image).


def _apply_live_addon_registry_creds(creds, public_docker_registry=False, docker_registry_host_override=None):
    """Update *creds* in place for live-addon registry pull. Do not log *creds* (contains secrets)."""
    if public_docker_registry:
        creds["docker_registry_host"] = (creds.get("public_docker_registry_host") or "").strip()
        creds["docker_registry_username"] = ""
        creds["docker_registry_password"] = ""
    override = (docker_registry_host_override or "").strip()
    if override:
        creds["docker_registry_host"] = override
    return creds


def live_addon_image_repository(vendor):
    """
    Return the live-addon image repository name for a vendor (``docker-live-addon-<vendor>``).

    ``vendor`` comes from the top-level ``vendor`` field in the vendor JSON.
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


def normalize_live_addon_config(cfg):
    """Set ``docker_run.image_ref`` from ``vendor`` (and optional tag) after loading JSON."""
    cfg.setdefault("docker_run", {})
    dr = cfg["docker_run"]
    explicit_ref = (dr.get("image_ref") or "").strip()
    if explicit_ref:
        repo = _image_repository_from_image_ref(explicit_ref)
        expected_repo = live_addon_image_repository(cfg.get("vendor"))
        if repo and repo != expected_repo:
            logger.warning(
                "docker_run.image_ref repository %r does not match vendor-derived %r; using vendor repo",
                repo,
                expected_repo,
            )
    resolved = resolve_docker_run_image_ref(cfg)
    dr["image_ref"] = resolved
    logger.info("Resolved docker_run.image_ref: %s", resolved)
    return cfg


def apply_image_tag_to_config(cfg, image_tag):
    """Return config copy with ``docker_run.image_tag`` set and ``image_ref`` re-resolved."""
    tag = (image_tag or "").strip()
    if not tag:
        return cfg
    out = copy.deepcopy(cfg)
    out.setdefault("docker_run", {})
    out["docker_run"]["image_tag"] = tag
    return normalize_live_addon_config(out)


def load_live_addon_config(config_path):
    """Load vendor JSON parameters and resolve ``docker_run.image_ref`` from ``vendor``."""
    with open(config_path, encoding="utf-8") as handle:
        cfg = json.load(handle)
    return normalize_live_addon_config(cfg)


def image_ref_to_tag(image_ref):
    """Return the tag or digest label after ':' in a docker image ref, or 'latest' if missing."""
    if not image_ref or not isinstance(image_ref, str):
        return "latest"
    ref = image_ref.strip()
    if ":" in ref:
        return ref.split(":")[-1].strip()
    return "latest"


def live_addon_image_tag_for_matrix(cfg, install_source):
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

    Trains like ``202411``, ``202505`` appear in ``os_version`` strings such as
    ``SONiC.<platform>_202411.<build>-...`` or ``202411.1.2.3.4``; globs like ``202411*``
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

    Some live-addon images set ``com.azure.sonic.manifest`` (JSON string) and ``Tag`` labels.
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
    Optional JSON ``version_matrix``: skip when live-addon ``package.version`` (image metadata) and
    DUT SONiC build are not declared compatible.

    Call **after** the image exists on the DUT (``docker load`` / present) and **before**
    ``docker run``, passing ``resolved_image_ref`` from ``docker_run.image_ref``.

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


def find_existing_live_addon_image(duthost, cfg):
    """
    Return first image ref that exists in local docker storage on the DUT, or None.
    Same idea as swap_syncd checking `docker image inspect docker-syncd-<vendor>-rpc`.
    """
    for ref in _image_refs_to_try(cfg):
        if image_exists(duthost, ref):
            logger.info("Found existing live-addon image on DUT: %s", ref)
            return ref
    return None


def dut_home_tarball_path(cfg):
    """Path under admin home for a pre-copied .gz (``~/`` + ``tarball_filename`` from JSON)."""
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


def _live_addon_registry_pull_settings(cfg, registry_image_tag=None):
    """
    Return settings for live-addon ``docker pull``.

    Repository from ``docker_run.image_ref`` (``docker-live-addon-<vendor>``). Tag is
    ``registry_image_tag`` when set (CLI), else tag from ``image_ref`` if not ``latest``,
    else ``duthost.os_version`` at pull time.
    """
    dr = cfg.get("docker_run") or {}
    target_ref = (dr.get("image_ref") or "").strip()
    if not target_ref:
        return None

    image_name = _image_repository_from_image_ref(target_ref)
    if not image_name:
        logger.warning("live-addon registry pull: cannot parse repository from docker_run.image_ref")
        return None

    if registry_image_tag and str(registry_image_tag).strip():
        image_version = str(registry_image_tag).strip()
    else:
        ref_tag = image_ref_to_tag(target_ref)
        image_version = None if ref_tag == DEFAULT_LIVE_ADDON_IMAGE_TAG else ref_tag

    return {"image_name": image_name, "image_version": image_version, "target_ref": target_ref}


def resolve_live_addon_install_source(
    duthost,
    cfg,
    local_runner_tarball_path,
    public_docker_registry=False,
    docker_registry_host_override=None,
    registry_image_tag=None,
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
    reg_settings = _live_addon_registry_pull_settings(cfg, registry_image_tag=registry_image_tag)
    if reg_settings is not None:
        ref = try_registry_pull_live_addon_image(
            duthost,
            reg_settings,
            public_docker_registry=public_docker_registry,
            docker_registry_host_override=docker_registry_host_override,
        )
        if ref:
            logger.info("Live-addon docker image from registry: %s", ref)
            return InstallSource("image_present", None, ref)
        logger.info(
            "Live-addon registry pull did not produce an image; "
            "trying DUT tarball, runner tarball, local image"
        )

    dut_path = dut_home_tarball_path(cfg)
    if dut_file_exists(duthost, dut_path):
        logger.info("Live-addon docker tarball on DUT (will docker load): %s", dut_path)
        return InstallSource("dut_home_tarball", dut_path, None)

    if local_runner_tarball_path and os.path.isfile(local_runner_tarball_path):
        base = os.path.basename(local_runner_tarball_path)
        remote = "/tmp/{}".format(base)
        logger.info("Live-addon docker tarball on test runner (will copy to DUT then docker load): %s", remote)
        return InstallSource("runner_tarball", remote, None)

    ref = find_existing_live_addon_image(duthost, cfg)
    if ref:
        logger.info("Live-addon docker image already on DUT (no docker load): %s", ref)
        return InstallSource("image_present", None, ref)

    return InstallSource("none", None, None)


def resolve_local_tarball_path(config, search_dir, tarball_override):
    """
    Resolve path to the .gz image on the ansible test server (before copy to DUT).

    Search order:
    1) tarball_override (pytest --live-addon-docker-tarball)
    2) search_dir / config['tarball_filename'] (default search_dir is this test module directory)
    """
    if tarball_override:
        return os.path.abspath(tarball_override)
    name = config.get("tarball_filename")
    if not name:
        raise ValueError("vendor config must set tarball_filename")
    return os.path.abspath(os.path.join(search_dir, name))


def try_registry_pull_live_addon_image(
    duthost, settings, public_docker_registry=False, docker_registry_host_override=None
):
    """
    Pull ``{registry}/{image_name}:{image_version}`` on the DUT (Ansible ``creds`` / registry same
    as ``swap_syncd`` / ``download_image``), then ``docker tag`` to ``settings['target_ref']``
    when the pulled ref differs.

    When ``public_docker_registry`` is true, applies the same credential override as the
    ``swap_syncd`` fixture in ``tests/conftest.py`` (``docker_registry_host`` from
    ``public_docker_registry_host``, clear username/password).

    ``settings`` comes from ``_live_addon_registry_pull_settings``. Returns ``target_ref`` on success,
    or None on failure (caller tries tarballs / local image).
    """
    image_name = settings["image_name"]
    target_ref = settings["target_ref"]

    creds = copy.deepcopy(creds_on_dut(duthost))
    _apply_live_addon_registry_creds(
        creds,
        public_docker_registry=public_docker_registry,
        docker_registry_host_override=docker_registry_host_override,
    )
    try:
        registry = load_docker_registry_info(duthost, creds)
    except ValueError as exc:
        logger.warning("live-addon registry pull: %s", exc)
        return None

    ver = settings.get("image_version")
    if ver is not None and str(ver).strip():
        image_version = str(ver).strip()
    else:
        image_version = duthost.os_version

    try:
        download_image(duthost, registry, image_name, image_version)
    except RuntimeError as exc:
        logger.warning("live-addon registry pull: download failed: %s", exc)
        return None

    source_ref = "{}/{}:{}".format(registry.host, image_name, image_version)
    if source_ref != target_ref:
        duthost.command(
            "docker tag {} {}".format(shlex.quote(source_ref), shlex.quote(target_ref))
        )
    if not image_exists(duthost, target_ref):
        logger.warning("live-addon registry pull: target image %r not present after pull/tag", target_ref)
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
    Example: 'Loaded image: docker-live-addon-<vendor>:<tag>'
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
        "sudo docker logs --tail 120 {}".format(cname),
        module_ignore_errors=True,
    )
    log_out = _command_stdout_stderr(log_out)
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


def container_name_from_cfg(cfg):
    val = cfg.get("validation") or {}
    return val.get("docker_container_name", (cfg.get("docker_run") or {}).get("container_name"))


def _docker_exact_name_filter(container_name):
    """Docker ``ps`` filter for an exact container name (not substring match)."""
    return "name=^/{}$".format(container_name)


def list_live_addon_container_ids(duthost, container_name, running_only=False):
    """
    Return container IDs whose name matches *container_name* exactly.

    Uses anchored ``name=^/<name>$`` so only the configured container name matches (not substrings).
    """
    if not container_name:
        return []
    name_filter = _docker_exact_name_filter(container_name)
    ps_cmd = "sudo docker ps"
    if not running_only:
        ps_cmd += " -a"
    cmd = "{} --filter {} -q".format(ps_cmd, shlex.quote(name_filter))
    out = duthost.command(cmd, module_ignore_errors=True)
    return [line.strip() for line in (out.get("stdout") or "").splitlines() if line.strip()]


def list_running_container_ids_by_image(duthost, image_ref):
    """Return IDs of running containers started from *image_ref* (``ancestor`` filter)."""
    if not image_ref:
        return []
    image_filter = "ancestor={}".format(image_ref)
    cmd = "sudo docker ps --filter {} -q".format(shlex.quote(image_filter))
    out = duthost.command(cmd, module_ignore_errors=True)
    return [line.strip() for line in (out.get("stdout") or "").splitlines() if line.strip()]


def verify_single_live_addon_container_instance(duthost, cfg):
    """
    Assert ``docker run`` / start did not leave multiple live-addon container instances.

    Checks exact container name and (by default) running containers from ``docker_run.image_ref``.
    """
    cname = container_name_from_cfg(cfg)
    if not cname:
        logger.warning("verify_single_live_addon_container_instance: no container name in cfg; skipping")
        return

    val = cfg.get("validation") or {}
    expected = int(val.get("max_running_instances", 1))
    if expected < 0:
        return

    image_ref = (cfg.get("docker_run") or {}).get("image_ref")
    enforce_image = val.get("enforce_single_image_instance", True)

    running_by_name = list_live_addon_container_ids(duthost, cname, running_only=True)
    all_by_name = list_live_addon_container_ids(duthost, cname, running_only=False)
    running_by_image = list_running_container_ids_by_image(duthost, image_ref) if image_ref else []

    logger.info(
        "Live-addon instance check %r: running_by_name=%s all_by_name=%s running_by_image=%s (image=%r)",
        cname,
        running_by_name,
        all_by_name,
        running_by_image,
        image_ref,
    )

    pytest_assert(
        len(running_by_name) == expected,
        "Expected exactly {} running container(s) named {!r}, found {} (ids={}). "
        "Check for duplicate docker run/start.".format(
            expected, cname, len(running_by_name), running_by_name
        ),
    )
    pytest_assert(
        len(all_by_name) <= expected,
        "Expected at most {} container record(s) named {!r}, found {} (ids={}). "
        "Stale stopped containers or duplicate names may be present.".format(
            expected, cname, len(all_by_name), all_by_name
        ),
    )
    if enforce_image and image_ref:
        pytest_assert(
            len(running_by_image) == expected,
            "Expected exactly {} running container(s) from image {!r}, found {} (ids={}). "
            "Multiple live-addon instances may have been started.".format(
                expected, image_ref, len(running_by_image), running_by_image
            ),
        )


def _normalize_supervisor_program_name(name):
    """Normalize program names for comparison (``health_monitor`` vs ``health-monitor``)."""
    return (name or "").replace("_", "-").lower()


def get_supervisorctl_status(duthost, container_name):
    """
    Return ``(program_status_map, raw_output)`` from ``docker exec <container> supervisorctl status``.

    *program_status_map* keys are supervisord program names; values are status strings (e.g. ``RUNNING``).
    """
    cname = shlex.quote(container_name)
    out = duthost.command(
        "sudo docker exec {} supervisorctl status".format(cname),
        module_ignore_errors=True,
    )
    raw = _command_stdout_stderr(out)
    statuses = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        program, status = parts[0], parts[1]
        statuses[program] = status
    return statuses, raw


def _find_supervisor_program_status(statuses, expected_program):
    """Match *expected_program* to a supervisord entry (exact name, ignoring ``group:`` prefix)."""
    norm_expected = _normalize_supervisor_program_name(expected_program)
    for program, status in statuses.items():
        base = program.split(":")[-1]
        if _normalize_supervisor_program_name(base) == norm_expected:
            return program, status
    return None, None


def _evaluate_live_addon_processes(statuses, expected_processes):
    """
    Compare *expected_processes* to *statuses* from ``supervisorctl status``.

    Returns ``(missing, not_running)`` where *not_running* entries are
    ``(expected_name, supervisord_program, status)``.
    """
    expected = expected_processes or DEFAULT_LIVE_ADDON_EXPECTED_PROCESSES
    missing = []
    not_running = []
    for proc in expected:
        program, status = _find_supervisor_program_status(statuses, proc)
        if program is None:
            missing.append(proc)
        elif status != "RUNNING":
            not_running.append((proc, program, status))
    return missing, not_running


def _check_live_addon_container_processes(duthost, container_name, expected_processes=None):
    """
    Query supervisord once; return ``(ok, statuses, raw, missing, not_running)``.

    *ok* is False when ``supervisorctl status`` is empty or expected programs are not ``RUNNING``.
    """
    if expected_processes is not None and len(expected_processes) == 0:
        return True, {}, "", [], []
    statuses, raw = get_supervisorctl_status(duthost, container_name)
    if not statuses:
        return False, {}, raw, [], []
    missing, not_running = _evaluate_live_addon_processes(statuses, expected_processes)
    return (not missing and not not_running), statuses, raw, missing, not_running


def wait_for_live_addon_container_processes(
    duthost,
    container_name,
    expected_processes=None,
    timeout=DEFAULT_PROCESS_WAIT_SECONDS,
    interval=DEFAULT_PROCESS_POLL_INTERVAL_SECONDS,
):
    """Poll until expected supervisord programs are ``RUNNING``, then assert on timeout."""
    if expected_processes is not None and len(expected_processes) == 0:
        return

    logger.info(
        "Waiting up to %ss for supervisord programs RUNNING in container %r",
        timeout,
        container_name,
    )
    last_raw = ""

    def _ready():
        nonlocal last_raw
        ok, _statuses, raw, _missing, _not_running = _check_live_addon_container_processes(
            duthost, container_name, expected_processes
        )
        if ok:
            last_raw = raw
        return ok

    if not wait_until(timeout, interval, 0, _ready):
        verify_live_addon_container_processes(duthost, container_name, expected_processes=expected_processes)
        return

    logger.info("Live-addon container %r supervisord programs ready:\n%s", container_name, last_raw)


def verify_live_addon_container_processes(duthost, container_name, expected_processes=None):
    """Assert expected supervisord programs are ``RUNNING`` (``docker exec … supervisorctl status``)."""
    _ok, statuses, raw, missing, not_running = _check_live_addon_container_processes(
        duthost, container_name, expected_processes
    )
    if expected_processes is not None and len(expected_processes) == 0:
        return
    logger.info("Live-addon container %r supervisorctl status:\n%s", container_name, raw)
    pytest_assert(
        statuses,
        "Container {!r} supervisorctl status is empty or unavailable".format(container_name),
    )
    pytest_assert(
        not missing,
        "Container {!r} missing expected supervisord program(s) {} (supervisorctl: {!r})".format(
            container_name, missing, statuses
        ),
    )
    pytest_assert(
        not not_running,
        "Container {!r} supervisord program(s) not RUNNING: {} (supervisorctl: {!r})".format(
            container_name, not_running, statuses
        ),
    )


def _command_stdout_stderr(result):
    """Merge ansible command stdout and stderr (no shell redirect; ``command`` uses argv)."""
    stdout = (result.get("stdout") or "").strip()
    stderr = (result.get("stderr") or "").strip()
    if stdout and stderr:
        return stdout + "\n" + stderr
    return stdout or stderr


def _is_valid_container_started_at(started_at):
    """True when *started_at* looks like docker ``State.StartedAt`` RFC3339, not a broken template."""
    if not started_at:
        return False
    if started_at.startswith("0001-01-01"):
        return False
    if "{" in started_at or "}" in started_at:
        return False
    return bool(_STARTED_AT_TIMESTAMP_RE.match(started_at))


def get_container_started_at(duthost, container_name):
    """
    Return ``State.StartedAt`` (RFC3339) for the current container instance from ``docker inspect``.

    Used with ``docker logs --since`` so pattern checks ignore log lines from prior runs/restarts.
    """
    cname = shlex.quote(container_name)
    # Go template requires ``{{.State.StartedAt}}``; do not pass through str.format (collapses braces).
    fmt = shlex.quote(_DOCKER_INSPECT_STARTED_AT_FMT)
    out = duthost.command(
        "sudo docker inspect -f {} {}".format(fmt, cname),
        module_ignore_errors=True,
    )
    if out.get("rc") != 0:
        return None
    started_at = (out.get("stdout") or "").strip()
    if not _is_valid_container_started_at(started_at):
        logger.warning(
            "docker inspect StartedAt for %r is invalid (%r); will not use docker logs --since",
            container_name,
            started_at,
        )
        return None
    return started_at


def _logs_since_latest_session(logs, session_start_pattern):
    """Keep log text from the last occurrence of *session_start_pattern* (fallback when ``--since`` unavailable)."""
    if not session_start_pattern or not logs:
        return logs
    haystack = logs.lower()
    needle = session_start_pattern.lower()
    idx = haystack.rfind(needle)
    if idx < 0:
        return logs
    return logs[idx:]


def fetch_container_logs(duthost, container_name, tail=None, since=None):
    """
    Return ``docker logs`` stdout for *container_name*.

    Prefer ``since`` (container ``StartedAt``) to scope logs to the current run; ``tail`` applies only
    when ``since`` is not set.
    """
    cname = shlex.quote(container_name)
    parts = ["sudo", "docker", "logs"]
    if since:
        parts.extend(["--since", shlex.quote(since)])
    elif tail is not None:
        parts.extend(["--tail", str(int(tail))])
    parts.append(cname)
    cmd = " ".join(parts)
    out = duthost.command(cmd, module_ignore_errors=True)
    return _command_stdout_stderr(out)


def startup_log_validation_enabled(val):
    """True when vendor JSON defines non-empty ``validation.startup_log.required_patterns``."""
    val = val or {}
    slog = val.get("startup_log")
    if not slog:
        return False
    required = slog.get("required_patterns")
    return bool(required)


def resolve_startup_log_validation(startup_log_cfg):
    """
    Build startup log check settings from vendor ``validation.startup_log``.

    ``required_patterns`` and ``forbidden_patterns`` are vendor-specific (JSON only).
    ``wait_seconds`` is the max time to wait for **all** required patterns; vendors override when
    startup depends on external readiness (e.g. syncd container uptime before online diagnostic).
    """
    slog = startup_log_cfg or {}
    return {
        "required_patterns": list(slog.get("required_patterns") or []),
        "forbidden_patterns": list(slog.get("forbidden_patterns") or []),
        "wait_seconds": int(slog.get("wait_seconds", DEFAULT_STARTUP_LOG_WAIT_SECONDS)),
        "poll_interval_seconds": float(
            slog.get("poll_interval_seconds", DEFAULT_STARTUP_LOG_POLL_INTERVAL_SECONDS)
        ),
        "log_tail": slog.get("log_tail"),
        "session_start_pattern": slog.get("session_start_pattern"),
    }


def _match_log_patterns(logs, patterns, case_insensitive=True):
    """Return patterns from *patterns* that appear in *logs* (substring match)."""
    haystack = logs.lower() if case_insensitive else logs
    hits = []
    for pattern in patterns:
        needle = pattern.lower() if case_insensitive else pattern
        if needle in haystack:
            hits.append(pattern)
    return hits


def verify_live_addon_container_startup_logs(duthost, container_name, startup_log_cfg=None):
    """
    Poll container logs every ``poll_interval_seconds`` until all ``required_patterns`` appear or
    ``wait_seconds`` elapses (vendor JSON overrides timing; code default is generic only).

    Log lines are scoped to the current container run via ``docker logs --since <StartedAt>``.
    """
    if not startup_log_cfg or not startup_log_cfg.get("required_patterns"):
        logger.info("Startup log validation skipped (no vendor validation.startup_log.required_patterns)")
        return

    cfg = resolve_startup_log_validation(startup_log_cfg)
    required = cfg["required_patterns"]
    forbidden = cfg["forbidden_patterns"]
    wait_seconds = cfg["wait_seconds"]
    poll_interval = cfg["poll_interval_seconds"]
    log_tail = cfg["log_tail"]
    session_start_pattern = cfg.get("session_start_pattern")
    started_at = get_container_started_at(duthost, container_name)
    if started_at:
        logger.info(
            "Startup log validation for %r: current run StartedAt=%s (docker logs --since)",
            container_name,
            started_at,
        )
    elif session_start_pattern:
        logger.warning(
            "Startup log validation for %r: StartedAt unavailable; slicing from last %r",
            container_name,
            session_start_pattern,
        )
    else:
        logger.warning(
            "Startup log validation for %r: StartedAt unavailable and no session_start_pattern; "
            "checking full docker logs (may include prior runs)",
            container_name,
        )
    logger.info(
        "Startup log validation for %r: wait up to %ss (poll every %ss) for %s required pattern(s)",
        container_name,
        wait_seconds,
        poll_interval,
        len(required),
    )

    if not required and not forbidden:
        logger.info("Startup log validation disabled (empty required_patterns)")
        return

    def _fetch_current_logs():
        if started_at:
            return fetch_container_logs(duthost, container_name, since=started_at)
        logs = fetch_container_logs(duthost, container_name, tail=log_tail)
        if session_start_pattern:
            return _logs_since_latest_session(logs, session_start_pattern)
        return logs

    last_logs = ""
    last_missing = list(required)

    def _startup_logs_ready():
        nonlocal last_logs, last_missing
        last_logs = _fetch_current_logs()
        forbidden_hits = _match_log_patterns(last_logs, forbidden)
        if forbidden_hits:
            snippet = last_logs[-_STARTUP_LOG_FAILURE_SNIPPET_CHARS:]
            logger.error(
                "Live-addon container %r startup logs — forbidden pattern(s) %s:\n%s",
                container_name,
                forbidden_hits,
                snippet,
            )
            pytest_assert(
                False,
                "Container {!r} logs contain failure pattern(s) {}. See test log for docker logs snippet.".format(
                    container_name, forbidden_hits
                ),
            )

        matched = _match_log_patterns(last_logs, required)
        last_missing = [p for p in required if p not in matched]
        if not last_missing:
            return True

        logger.debug(
            "Live-addon container %r waiting for log patterns (missing %s); retry in %ss",
            container_name,
            last_missing,
            poll_interval,
        )
        return False

    if wait_until(wait_seconds, poll_interval, 0, _startup_logs_ready):
        logger.info(
            "Live-addon container %r startup logs OK (required patterns matched within %ss)",
            container_name,
            wait_seconds,
        )
        logger.info(
            "Live-addon container %r startup logs (last %s chars):\n%s",
            container_name,
            min(len(last_logs), 4000),
            last_logs[-4000:],
        )
        return

    snippet = last_logs[-_STARTUP_LOG_FAILURE_SNIPPET_CHARS:]
    logger.error(
        "Live-addon container %r startup logs — still missing %s after %ss:\n%s",
        container_name,
        last_missing,
        wait_seconds,
        snippet,
    )
    pytest_assert(
        False,
        (
            "Container {!r} logs missing required pattern(s) {} after {}s wait. "
            "See test log for docker logs snippet."
        ).format(container_name, last_missing, wait_seconds),
    )


def verify_live_addon_post_start(duthost, cfg, full_readiness=True):
    """
    Run post-``docker run`` checks: single instance, then readiness from JSON.

    Called after every ``docker run`` (fixture, config-reload cycle, restarts).

    When ``validation.startup_log`` is enabled and *full_readiness=True*, poll log patterns first,
    then assert ``expected_processes`` via ``supervisorctl`` (one-shot after logs pass).

    When startup logs are skipped (*full_readiness=False* on restart, or no log config), poll
    ``expected_processes`` for up to ``DEFAULT_PROCESS_WAIT_SECONDS`` (120s).
    """
    cname = container_name_from_cfg(cfg)
    if not cname:
        logger.warning("verify_live_addon_post_start: no container name in cfg; skipping")
        return

    verify_single_live_addon_container_instance(duthost, cfg)

    val = cfg.get("validation") or {}
    expected_procs = expected_processes_from_validation(val)
    startup_log_cfg = val.get("startup_log")
    logs_enabled = full_readiness and startup_log_validation_enabled(val)

    if logs_enabled:
        verify_live_addon_container_startup_logs(duthost, cname, startup_log_cfg=startup_log_cfg)

    if not expected_procs:
        return

    if logs_enabled:
        verify_live_addon_container_processes(duthost, cname, expected_processes=expected_procs)
    else:
        wait_for_live_addon_container_processes(duthost, cname, expected_processes=expected_procs)


def build_health_check_curl_command(health_cfg):
    """curl used for validation; fields from JSON ``health`` section."""
    port = int(health_cfg["port"])
    path = health_cfg.get("url_path", "/health")
    host = health_cfg.get("bind_host", "127.0.0.1")
    return (
        "curl -sS -m 15 -o /tmp/live_addon_docker_health.out -w '%{{http_code}}' "
        "http://{}:{}{}".format(host, port, path)
    )


def http_health_check(duthost, health_cfg):
    """
    Query HTTP health endpoint from the DUT (container typically uses --net=host).

    Returns (ok: bool, http_code: str, body_snippet: str). Uses ``module_ignore_errors`` so
    connection failures during polling do not raise (curl rc 7 → code ``000``, ok False).
    """
    expect = str(health_cfg.get("expect_http_code", 200))
    curl = build_health_check_curl_command(health_cfg)
    out = duthost.command(curl, module_ignore_errors=True)
    code = (out.get("stdout") or "").strip()
    if out.get("rc", 0) != 0 and not code:
        code = "000"
    body = duthost.command("sudo cat /tmp/live_addon_docker_health.out", module_ignore_errors=True).get(
        "stdout", ""
    )[:500]
    ok = code == expect
    return ok, code, body


def run_config_reload_live_addon_start_reload_health(duthost, resolved_cfg, loganalyzer=None):
    """
    Config-reload cycle for live-addon persistence:

    1. Stop/remove live-addon container (``docker_run.container_name``; fixture may still have it running).
    2. First ``config reload`` (``safe_reload`` waits for critical services).
    3. ``docker run`` live-addon + post-start checks (logs/processes).
    4. Second ``config reload``.
    5. ``docker_manual_teardown`` + ``docker_run_manual`` + post-start (process poll only).
    6. HTTP health probe (``wait_for_health_ready``).
    """
    from tests.common.config_reload import config_reload

    docker_manual_teardown(duthost, resolved_cfg["docker_run"])
    logger.info("First config reload (live-addon container stopped)")
    config_reload(
        duthost,
        config_source="config_db",
        safe_reload=True,
        ignore_loganalyzer=loganalyzer,
    )

    cfg_run = copy.deepcopy(resolved_cfg)
    docker_run_manual(duthost, cfg_run)
    verify_live_addon_post_start(duthost, cfg_run)
    logger.info("Second config reload (live-addon container was running)")
    config_reload(
        duthost,
        config_source="config_db",
        safe_reload=True,
        ignore_loganalyzer=loganalyzer,
    )
    logger.info("Re-start live-addon container after second config reload (teardown + docker run)")
    docker_manual_teardown(duthost, cfg_run["docker_run"])
    docker_run_manual(duthost, cfg_run)
    verify_live_addon_post_start(duthost, cfg_run, full_readiness=False)
    health_cfg = resolved_cfg.get("health") or {}
    return wait_for_health_ready(duthost, health_cfg)


def wait_for_health_ready(duthost, health_cfg):
    """
    Honor ``health.wait_seconds_before_check``, then HTTP probe(s) per
    ``probe_timeout_seconds`` / ``probe_interval_seconds``.
    Returns (ok, http_code, body) from the last attempt.

    Call ``verify_live_addon_post_start`` before this when the container was just started.
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


def remove_configured_live_addon_images(duthost, cfg):
    """
    Best-effort ``docker rmi -f`` for ``docker_run.image_ref`` and ``candidate_image_refs``.
    Used immediately before ``docker load`` so the tarball load does not layer on old tags.
    """
    for ref in _image_refs_to_try(cfg):
        logger.info("Removing live-addon image before docker load (best-effort): %s", ref)
        duthost.command("sudo docker rmi -f {}".format(ref), module_ignore_errors=True)


def prepare_live_addon_docker_install(duthost, cfg, install_source):
    """
    At test start: stop and remove the live-addon container if it is still running.
    When install uses a tarball (``docker load``), remove configured image refs before load.
    When using an image already on the DUT (no tarball), only the container is removed.
    """
    dr = cfg.get("docker_run")
    if not dr:
        return
    docker_manual_teardown(duthost, dr)
    if install_source.kind == "image_present":
        return
    remove_configured_live_addon_images(duthost, cfg)


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
    Tail syslog; if any line mentions the live-addon (hints) and matches the default error pattern, fail.
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
        "Syslog lines after teardown matched error pattern for live-addon hints:\n{}".format(bad[:2000]),
    )


def verify_post_teardown(duthost, cfg, pre_core_filenames):
    """
    After stop/uninstall: assert no new core files, live-addon container absent, syslog spot-check.
    Behavior is fixed in code (not vendor JSON).

    Relation to sonic-mgmt infra (keep these checks):
    - Loganalyzer runs per test and does not analyze syslog after the last test returns; uninstall
      in the module fixture runs after that, so a tail+grep for live-addon hints still adds coverage.
    - core_dump_and_config_check (module autouse) compares /var/core at module boundaries but does
      not pytest.fail on new cores; it logs and records cache for telemetry. The assert here fails
      the run if new cores appeared during this fixture.
    """
    val = cfg.get("validation") or {}
    cname = val.get("docker_container_name", (cfg.get("docker_run") or {}).get("container_name"))

    verify_no_new_core_files(duthost, pre_core_filenames)
    verify_container_absent(duthost, cname)
    verify_syslog_clean_after_teardown(duthost, cfg)
