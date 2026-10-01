"""Shared helpers for validating packages published by the sonic-operations pipeline."""

import json
import logging
import os
import re
import shlex
import time
import uuid
from collections.abc import Mapping
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime

logger = logging.getLogger(__name__)

# Lab download access is separate from the producer's public publication endpoint.
DELIVERY_BASE = "http://10.1.3.6/azmirrors/ACS/sonic-upgrade-packages/"
BJW_DELIVERY_BASE = "http://10.150.22.222/azmirrors/ACS/sonic-upgrade-packages/"


def _packages_at_base(base):
    return {
        "cphc": {
            "url": base + "sonic-upgrade-package-1.0.0.tar",
            "filename": "sonic-upgrade-package-1.0.0.tar",
            "selector": base + "critical-process-health-checker.latest.buildinfo.json",
        },
        "postupgrade": {
            "url": base + "sonic-upgrade-package.tar.gz",
            "filename": "sonic-upgrade-package.tar.gz",
            "selector": base + "postupgrade_actions.latest.buildinfo.json",
        },
    }


DELIVERY_PACKAGES = _packages_at_base(DELIVERY_BASE)
BJW_DELIVERY_PACKAGES = _packages_at_base(BJW_DELIVERY_BASE)
BJW_INVENTORIES = frozenset(("bjw", "bjw2", "bjw3"))


def delivery_package_source(request, package):
    """Use the selected testbed's authoritative inventory, not its display name or source options."""
    tbinfo = request.getfixturevalue("tbinfo")
    inventory = tbinfo.get("inv_name") if isinstance(tbinfo, Mapping) else None
    if not isinstance(inventory, str) or not inventory.strip():
        raise ValueError("Package mirror selection requires the selected testbed's inv_name")
    inventory = inventory.strip().lower()
    if inventory in BJW_INVENTORIES:
        region, packages = "bjw", BJW_DELIVERY_PACKAGES
    else:
        region, packages = "default", DELIVERY_PACKAGES
    selected = getattr(request.config, "_sonic_operations_mirror_region", None)
    if selected is not None and selected != region:
        raise ValueError("Package mirror changed within this pytest run; refusing to switch regions")
    request.config._sonic_operations_mirror_region = region
    return packages[package]


def delivery_package_url(request, package):
    """Select the producer's shared latest route, never a saved manual-plan source."""
    if request.config.getoption("--cphc_tar_version") != "1.0.0":
        raise ValueError("--cphc_tar_version must be 1.0.0 for the HWP archive filename contract")
    ignored = []
    for option in ("--image_server_url", "--sonic_ops_branch", "--cphc_package_url", "--sup_package_url",
                   "--cphc_package_path", "--sup_package_path", "--use_mirror_layout", "--package_sas_token"):
        if request.config.getoption(option):
            ignored.append(option)
    if ignored:
        # Never log supplied values: even a legacy location may contain credentials.
        logger.warning("Latest package publication: ignoring source options %s; anonymous code-owned URLs are used. "
                       "Local preload mirrors are unchanged.", ", ".join(ignored))
    return delivery_package_source(request, package)["url"]


def _delivery_url(url):
    return any(url == package["selector"] or url in (
        package["url"], package["url"] + ".md5", package["url"] + ".buildinfo.json")
        for packages in (DELIVERY_PACKAGES, BJW_DELIVERY_PACKAGES) for package in packages.values())


class DutPathState:
    """Own temporary replacements, retaining originals beside their fixed paths."""

    def __init__(self, duthost):
        self.duthost = duthost
        self.paths = []
        self.directories = []

    def directory(self, path):
        if not self.duthost.stat(path=path)['stat']['exists']:
            self.directories.append(path)
            self.duthost.shell("mkdir -- {}".format(shlex.quote(path)))

    def preserve(self, path):
        if not path.startswith("/") or path.rstrip("/") != path or path in ("/tmp", "/host"):
            raise ValueError("Refusing to replace non-leaf path {!r}".format(path))
        for saved in self.paths:
            if saved[0] == path:
                return saved[1] if saved[2] else None
        backup = "{}.sonic-ops-{}.original".format(path, uuid.uuid4().hex)
        stat = self.duthost.stat(path=path, follow=False)['stat']
        existed = stat['exists'] or stat.get('islnk', False)
        entry = [path, backup, existed, False]
        self.paths.append(entry)
        if existed:
            self.duthost.shell("mv -T -- {} {}".format(shlex.quote(path), shlex.quote(backup)))
            entry[3] = True
        return backup if existed else None

    def restore(self):
        errors = []
        for path, backup, existed, moved in reversed(self.paths):
            try:
                saved = self.duthost.stat(path=backup, follow=False)['stat']
                if saved['exists'] or saved.get('islnk', False):
                    self.duthost.shell("rm -rf -- {} && mv -T -- {} {}".format(
                        shlex.quote(path), shlex.quote(backup), shlex.quote(path)))
                elif existed:
                    # A failed atomic rename may leave the original untouched.
                    original = self.duthost.stat(path=path, follow=False)['stat']
                    if moved or not (original['exists'] or original.get('islnk', False)):
                        raise RuntimeError("Expected original backup is unavailable; refusing to discard current path")
                else:
                    self.duthost.shell("rm -rf -- {}".format(shlex.quote(path)))
            except Exception as exc:
                logger.error("Could not restore %s; retain backup %s: %s", path, backup, exc)
                errors.append("{} (backup {}): {}".format(path, backup, exc))
        if not errors:
            for directory in reversed(self.directories):
                try:
                    self.duthost.shell("rmdir -- {}".format(shlex.quote(directory)))
                except Exception as exc:
                    logger.error("Retaining nonempty or inaccessible owned directory %s: %s", directory, exc)
                    errors.append("{}: {}".format(directory, exc))
        if errors:
            raise RuntimeError("DUT state restoration failed: " + "; ".join(errors))
        self.paths = []
        self.directories = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.restore()


@contextmanager
def dut_workspace(duthost, prefix, keep_on_error=False):
    """Create a unique owned directory; never clear a preexisting workspace."""
    path = "/tmp/{}-{}".format(prefix, uuid.uuid4().hex)
    created = False
    failed = False
    try:
        duthost.shell("mkdir -- {}".format(shlex.quote(path)))
        created = True
        yield path
    except BaseException:
        failed = True
        raise
    finally:
        if created and failed and keep_on_error:
            logger.error("Retaining recovery material at %s after failure", path)
        elif created:
            duthost.shell("rm -rf -- {}".format(shlex.quote(path)))


def require_package_integrity(duthost, tarball, md5, metadata=None):
    """Validate sidecar syntax, actual bytes and archive before any execution."""
    matched, actual, expected = verify_md5_like_wrapper(duthost, tarball, md5)
    if not expected or not re.fullmatch(r"[0-9a-fA-F]{32}", expected):
        raise AssertionError("Invalid MD5 sidecar {}: {!r}; possible HTTP error body".format(md5, expected))
    assert matched, "Package checksum mismatch for {}: got {}, expected {}".format(tarball, actual, expected)
    if metadata is not None:
        assert actual == metadata["md5"], "Package MD5 disagrees with the selected buildinfo"
        assert tarball.rsplit("/", 1)[-1] == metadata["package"], "Unexpected downloaded package filename"
        sidecar = duthost.shell("cat {}".format(shlex.quote(md5)))["stdout"].strip()
        assert re.fullmatch(metadata["md5"] + r" [ *]" + re.escape(metadata["package"]), sidecar), (
            "MD5 sidecar does not identify the selected package")
        sha256 = duthost.shell("sha256sum {} | awk '{{print $1}}'".format(shlex.quote(tarball)))["stdout"].strip()
        size = duthost.shell("stat -c %s {}".format(shlex.quote(tarball)))["stdout"].strip()
        assert sha256 == metadata["sha256"], "Package SHA256 disagrees with the selected buildinfo"
        assert size == str(metadata["sizeBytes"]), "Package size disagrees with the selected buildinfo"
    valid, members = archive_listing(duthost, tarball)
    assert valid and members, "Unreadable or empty package archive: {}".format(tarball)
    if metadata is not None:
        names = [name[2:] if name.startswith("./") else name for name in members]
        assert all(not name.startswith("/") and ".." not in name.split("/") for name in names), (
            "Package contains non-relative archive members")
        if metadata["archiveVersion"] is not None:
            assert "installer.py" in names, "CPHC package is missing installer.py"
            assert cphc_archive_wheel_version(names) == metadata["wheelVersion"], (
                "CPHC archive wheel version disagrees with its buildinfo")
        else:
            assert all(name in names for name in ("postupgrade_actions", "postupgrade_infra.py")), (
                "SUP package is missing its entrypoint or infrastructure module")
            assert any(name.startswith("postupgrade_actions_data/") for name in names), (
                "SUP package is missing patch data")
        members = names
    return members


def cphc_archive_wheel_version(members):
    """Identify one consistent py2/py3 wheel release from an integrity-checked tar listing."""
    wheels = {}
    for member in members:
        name = member[2:] if member.startswith("./") else member
        if not name.endswith(".whl"):
            continue
        match = re.fullmatch(r"sonic_critical_process_checker-([0-9][A-Za-z0-9.!+_]*)-(py2|py3)-none-any\.whl", name)
        if not match:
            raise AssertionError("Unexpected CPHC wheel member: {}".format(member))
        version, tag = match.groups()
        if tag in wheels:
            raise AssertionError("Multiple CPHC wheels for {}".format(tag))
        wheels[tag] = version
    if set(wheels) != {"py2", "py3"} or wheels["py2"] != wheels["py3"]:
        raise AssertionError("CPHC archive must contain matching py2/py3 wheel versions: {}".format(wheels))
    return wheels["py3"]


def parse_package_buildinfo(contents, package, filename):
    """Validate the producer's versioned, digest-bound per-package publication record."""
    try:
        info = json.loads(contents)
    except (TypeError, ValueError) as exc:
        raise AssertionError("Package buildinfo is not valid JSON") from exc
    if not isinstance(info, dict) or type(info.get("schemaVersion")) is not int or info["schemaVersion"] != 1:
        raise AssertionError("Unsupported or missing package buildinfo schemaVersion")
    if not all(field in info for field in ("archiveVersion", "wheelVersion", "reportVersion")):
        raise AssertionError("Missing package buildinfo version fields")
    for field in ("buildId", "buildNumber", "branch", "commit", "publishedUtc", "package", "md5", "sha256"):
        if not isinstance(info.get(field), str) or not info[field].strip():
            raise AssertionError("Missing or invalid package buildinfo field: {}".format(field))
    if not re.fullmatch(r"[0-9]+", info["buildId"]) or int(info["buildId"]) <= 0:
        raise AssertionError("Invalid package buildId")
    if not re.fullmatch(r"[0-9a-f]{40}", info["commit"]):
        raise AssertionError("Invalid package source commit")
    try:
        published = datetime.fromisoformat(info["publishedUtc"].replace("Z", "+00:00"))
        if published.utcoffset() is None or published.utcoffset().total_seconds() != 0:
            raise ValueError("Timestamp must be UTC")
    except ValueError as exc:
        raise AssertionError("Invalid package publishedUtc") from exc
    for field, length in (("md5", 32), ("sha256", 64)):
        if not re.fullmatch(r"[0-9a-f]{" + str(length) + "}", info[field]):
            raise AssertionError("Invalid package {}".format(field))
    if type(info.get("sizeBytes")) is not int or info["sizeBytes"] <= 0:
        raise AssertionError("Invalid package sizeBytes")
    if info["package"] != filename or "/" in filename or "\\" in filename:
        raise AssertionError("Package buildinfo filename does not match the consumer URL")
    if package == "cphc":
        version_fields = ("archiveVersion", "wheelVersion")
        if info.get("reportVersion") is not None:
            raise AssertionError("Unexpected CPHC reportVersion")
    elif package == "postupgrade":
        version_fields = ("reportVersion",)
        if info.get("archiveVersion") is not None or info.get("wheelVersion") is not None:
            raise AssertionError("Unexpected SUP archive/wheel version")
    else:
        raise AssertionError("Unsupported package identity")
    for field in version_fields:
        if not isinstance(info.get(field), str) or not re.fullmatch(r"[0-9][A-Za-z0-9.!+_]*", info[field]):
            raise AssertionError("Invalid package {}".format(field))
    if package == "cphc" and (info["archiveVersion"] != "1.0.0"
                              or filename != "sonic-upgrade-package-1.0.0.tar"):
        raise AssertionError("CPHC archiveVersion disagrees with its filename")
    if package == "postupgrade" and filename != "sonic-upgrade-package.tar.gz":
        raise AssertionError("Unexpected SUP artifact filename")
    return info


def require_coherent_package_metadata(before, after):
    """A moving package generation must not change during a verified download."""
    if before != after:
        raise AssertionError("Package publication changed during download; refusing a torn latest generation")


def _redact_transport_message(message):
    """Preserve transport errors while removing credentials from any embedded URLs."""
    return re.sub(
        r"""https?://[^\s'"<>]+""",
        lambda match: re.sub(r"^(https?://)[^/]*@", r"\1[redacted]@", redact(match.group(0))),
        str(message))


def _read_package_metadata(duthost, localhost, url, package):
    filename = DELIVERY_PACKAGES[package]["filename"]
    command = "curl -fL -sS --connect-timeout 5 --max-time 30 {}".format(shlex.quote(url))
    attempts = []
    for where, host in (("DUT", duthost), ("runner", localhost)):
        if host is None:
            continue
        result = host.shell(command, module_ignore_errors=True)
        if not isinstance(result, Mapping):
            attempts.append("{}: rc=<missing>; invalid module result ({})".format(where, type(result).__name__))
            continue
        rc = result.get("rc")
        if isinstance(rc, int) and not isinstance(rc, bool) and rc == 0:
            return parse_package_buildinfo(result.get("stdout"), package, filename)
        stderr = _redact_transport_message(result.get("stderr") or "").strip() or "<empty>"
        attempt = "{}: rc={}; stderr={}".format(where, rc if rc is not None else "<missing>", stderr)
        if result.get("msg"):
            attempt += "; msg=" + _redact_transport_message(result["msg"])
        attempts.append(attempt)
    raise RuntimeError(
        "Could not read package buildinfo from its exact anonymous URL {}.\n"
        "Metadata download attempts:\n  {}".format(_redact_transport_message(url), "\n  ".join(attempts)))


def publication_info(request, package):
    """The first validated selector for this package in this pytest run."""
    selected = getattr(request.config, "_sonic_operations_publications", {})
    assert package in selected, "Package publication has not been selected: {}".format(package)
    return deepcopy(selected[package])


def select_package_publication(request, duthost, localhost, package):
    """Read selector A and pin a separate identity per package for the entire pytest run."""
    delivery_package_url(request, package)
    source = delivery_package_source(request, package)
    metadata = _read_package_metadata(duthost, localhost, source["selector"], package)
    if package == "cphc":
        expected = request.config.getoption("--cphc_wheel_version")
        if expected is not None and expected != metadata["wheelVersion"]:
            raise ValueError(
                "--cphc_wheel_version disagrees with the selected latest build: expected {}, found {}".format(
                    expected, metadata["wheelVersion"]))
    selected = getattr(request.config, "_sonic_operations_publications", None)
    if selected is None:
        selected = {}
        request.config._sonic_operations_publications = selected
    if package in selected:
        require_coherent_package_metadata(selected[package], metadata)
    else:
        selected[package] = deepcopy(metadata)
    logger.info("Selected %s package publication from %s: %s",
                package, source["selector"], json.dumps(metadata, sort_keys=True))
    return metadata


def download_latest_package(request, duthost, localhost, package, directory, consumer_curl=None, metadata=None):
    """Bind selector A, tar/MD5, per-tar buildinfo and selector B before accepting bytes."""
    url = delivery_package_url(request, package)
    if metadata is None:
        metadata = select_package_publication(request, duthost, localhost, package)
    require_coherent_package_metadata(publication_info(request, package), metadata)
    filename = DELIVERY_PACKAGES[package]["filename"]
    tarball, md5 = directory + "/" + filename, directory + "/" + filename + ".md5"
    for suffix, destination in ((".md5", md5), ("", tarball)):
        if consumer_curl is None:
            fetch_to_dut(duthost, localhost, url + suffix, directory, filename + suffix)
        else:
            result = consumer_curl(duthost, url + suffix, destination)
            assert result["rc"] == 0, "Consumer curl failed for {}: {}".format(url + suffix, result)
    per_tar = _read_package_metadata(duthost, localhost, url + ".buildinfo.json", package)
    require_coherent_package_metadata(metadata, per_tar)
    members = require_package_integrity(duthost, tarball, md5, metadata)
    after = _read_package_metadata(duthost, localhost, delivery_package_source(request, package)["selector"], package)
    require_coherent_package_metadata(metadata, after)
    logger.info("Verified %s build %s source %s, md5=%s sha256=%s size=%s",
                package, metadata["buildId"], metadata["commit"],
                metadata["md5"], metadata["sha256"], metadata["sizeBytes"])
    return {"url": url, "tarball": tarball, "md5_file": md5, "buildinfo": deepcopy(metadata), "members": members}


# Do not pass become= to any duthost module call. AnsibleHostBase builds the
# host with ansible_adhoc(become=True) (tests/common/devices/base.py), so every
# duthost.shell/copy already runs as root. become is not a module argument, so
# passing it is forwarded to the module, which rejects it with Unsupported
# parameters for (ansible.legacy.command) module: become - and because that
# rejection returns a dict with no rc key, the first line that reads the rc
# dies with a bare KeyError that looks nothing like the real cause. Running
# as root matches production: hardware proxy and the postupgrade wrapper
# both run as root.

# Blob path prefix the publish pipeline writes under. This is a contract with
# .azure-pipelines/sonic-operations-packages-Official.yml in sonic-operations
# (parameter IMAGE_DEST_PREFIX); changing it there means changing it here.
PIPELINE_PREFIX = "pipelines/sonic-operations-packages-Official"

# Which endpoint a testbed can actually reach is not knowable from outside the
# lab. The public front end and the internal mirror are reachable from
# different networks. Workstation downloads through /azmirrors succeed, but do
# not prove lab reachability. Try the configured endpoint first and then the
# known alternates, preserving the entire path, and log which one answered.
#
# The mirror address is not invented here: every physical-testbed pipeline in
# .azure-pipelines/ already overrides image URLs to this host.
FALLBACK_BASE_URLS = ("http://10.150.22.222",)


# The two published package folders. Each is refreshed only by merges that
# touched that package's own source folder in sonic-operations, so the two can
# legitimately hold artifacts produced by two different builds. These names are
# a contract with the publish pipeline's staging step; renaming one there means
# renaming it here.
CPHC_PACKAGE_DIR = "critical-process-health-checker"        # from critical-process-checker/
POSTUPGRADE_PACKAGE_DIR = "postupgrade_actions"             # from sonic-upgrade-scripts/

# Where hardware proxy actually reads packages from on a real device.
#
# download_util() in preload_firmware does not take a URL: it is handed the
# *host* and rebuilds the location itself as
# "http://<host>/networkfirmware/ACS/<subpath><file>". So this prefix, and plain
# HTTP, are baked into production - a package is only reachable by hardware
# proxy if it is served under this path.
MIRROR_PACKAGE_PREFIX = "networkfirmware/ACS"

# ...and the two shipped copies of preload_firmware disagree about <subpath>.
#
# There is no single "the" script. The hardware proxy copy,
# sonic-metadata/scripts/preload_firmware, calls
#     download_util "${IP_ADDR}" "${FILENAME}" "${MD5_FILE}" ...
# so there is no subpath and the package sits directly under the prefix. The
# copy shipped to devices,
# Networking-Metadata/src/data/Network/SONiC/scripts/preload_firmware, added a
# subpath parameter and calls
#     download_util "${IP_ADDR}" "sonic-upgrade-packages/" "${FILENAME}" ...
# so it looks one directory deeper. The same commit renumbered the exit codes:
# EXIT_CPHC_DOWNLOAD_FAILURE is 33 in the proxy copy and 34 in the device copy,
# with 33 reused there for the postupgrade package. That is why these tests
# assert a non-zero exit rather than a specific code - no single number is
# correct for both.
#
# Which copy a given DUT runs cannot be known from here, so a test mirror serves
# the package at both locations and lets the script choose. Whichever one it
# fetches identifies the variant that DUT is running, which is worth recording.
MIRROR_CPHC_SUBPATH = "sonic-upgrade-packages"


def published_package_path(package_dir, branch="main"):
    """Path of the published copy of one package.

    main publishes straight to <prefix>/<package>/, because that URL is the
    contract consumers hold and must not encode a build id, a branch, or the
    pipeline's name. Any other branch publishes under
    <prefix>/branches/<branch>/<package>/, so a hand-queued build from a feature
    branch cannot overwrite what everything else is reading.

    Each package folder is refreshed independently, so asking for one package
    never depends on what the other package last published.

    This is a CI path, not the device-facing one. Devices resolve a version
    through the SUP selection map to an immutable, version-keyed location, and
    must never be pointed at a moving target - see section 11.2 of
    docs/sup-versioning-and-rollout.md in sonic-operations.
    """
    branch = (branch or "main").strip('/')
    if branch == "main":
        return "{}/{}".format(PIPELINE_PREFIX, package_dir)
    return "{}/branches/{}/{}".format(PIPELINE_PREFIX, branch, package_dir)


def build_package_url(base_url, package_path, filename):
    """Compose the URL of a published package file."""
    return "{}/{}/{}".format(base_url.rstrip('/'), package_path.strip('/'), filename)


def mirror_package_url(base_url, filename, subpath=""):
    """Compose a package URL the way hardware proxy does.

    Hardware proxy cannot be pointed at an arbitrary path: download_util()
    derives the location from the host alone, so the file must sit at
    <host>/networkfirmware/ACS/<subpath>/<filename>. Use this when the test
    needs the address production would use, rather than the CI publish path.

    `subpath` selects between the two shipped layouts; see MIRROR_CPHC_SUBPATH.
    """
    parts = [base_url.rstrip('/'), MIRROR_PACKAGE_PREFIX]
    if subpath:
        parts.append(subpath.strip('/'))
    parts.append(filename)
    return "/".join(parts)


def mirror_serve_dirs():
    """Relative directories a mirror must populate to satisfy either variant.

    Ordered shallowest first so callers can create them in sequence.
    """
    return (
        MIRROR_PACKAGE_PREFIX,
        "{}/{}".format(MIRROR_PACKAGE_PREFIX, MIRROR_CPHC_SUBPATH),
    )


def sibling_url(url, suffix):
    """Return `url` with `suffix` appended to its path, preserving any query.

    A package URL may already carry a SAS token, so appending directly would
    produce `...tar?sig=xyz.md5` - a different query rather than a different
    blob. The suffix has to go on the path.
    """
    base, sep, tail = url.partition('?')
    if not sep:
        base, sep, tail = url.partition('#')
    return "{}{}{}{}".format(base, suffix, sep, tail)


def redact(url):
    """Drop the query string from a URL so a SAS token is never logged."""
    return url.split('?', 1)[0].split('#', 1)[0]


def with_sas_token(url, sas_token):
    """Append a SAS token to a URL, if one was supplied.

    The storage account the pipeline publishes to has public access disabled at
    the account level - an anonymous request is answered with
    ``PublicAccessNotPermitted`` - so reading a blob URL directly requires a SAS
    token. Requests through the image server front end may not, which is why the
    token is optional.
    """
    if _delivery_url(url):
        if sas_token:
            logger.warning("Ignoring --package_sas_token for the anonymous latest package endpoint")
        return url
    if not sas_token:
        return url
    return "{}{}{}".format(url, '&' if '?' in url else '?', sas_token.lstrip('?'))


def log_package_provenance(duthost, localhost, url, sas_token=None):
    """Log which build produced the package under test.

    Code-owned latest URLs require the producer schema; missing or invalid
    provenance fails. download_latest_package additionally brackets and pins
    the metadata and verifies its byte identity before execution.
    Generic callers retain best-effort diagnostic behavior.
    Moving publication folders are refreshed in place, so "it downloaded
    the published package" does not by itself say what was tested: the same URL
    means different bytes on different days, and because each package folder is
    refreshed independently, the two packages under test are frequently from two
    different builds. The publish pipeline writes a .buildinfo.json next to each
    package naming the build and commit that produced it, and recording that here
    is what lets a nightly failure be traced back to the change that caused it.

    For generic URLs, provenance is diagnostic, and a package published
    before the pipeline began writing it has none, so failing the run over a
    missing diagnostic would turn a reporting gap into a false package failure.
    """
    info_url = sibling_url(url, '.buildinfo.json')

    # Try the same endpoints fetch_to_dut will. Otherwise provenance gets
    # reported missing whenever this testbed simply cannot route to the first
    # endpoint, which reads as "unknown build" when the build is in fact known.
    for candidate in candidate_urls(info_url):
        cmd = "curl -fL -sS --connect-timeout 5 --max-time 30 '{}'".format(
            with_sas_token(candidate, sas_token))
        for host, where in ((duthost, 'DUT'), (localhost, 'test runner')):
            result = host.shell(cmd, module_ignore_errors=True)
            if result['rc'] == 0 and result['stdout'].strip():
                provenance = result['stdout'].strip()
                if _delivery_url(url):
                    package = next(key for packages in (DELIVERY_PACKAGES, BJW_DELIVERY_PACKAGES)
                                   for key, value in packages.items() if value["url"] == url)
                    parse_package_buildinfo(provenance, package, DELIVERY_PACKAGES[package]["filename"])
                logger.info("Package under test was produced by %s", provenance)
                return provenance
            logger.debug("No provenance from the %s at %s (rc=%s)",
                         where, redact(candidate), result['rc'])

    if _delivery_url(url):
        raise RuntimeError("Could not verify latest package provenance at {}".format(info_url))
    logger.warning("No provenance found at %s; the build that produced this "
                   "package cannot be identified", redact(info_url))
    return None


def candidate_urls(url):
    """Code-owned latest URLs have no alternates; generic URLs retain their original fallback.

    Generic candidates are returned in preference order, preserving the path.
    """
    urls = [url]
    if _delivery_url(url):
        return urls
    if "://" in url:
        rest = url.split("://", 1)[1]
        path = rest.split("/", 1)[1] if "/" in rest else ""
        for base in FALLBACK_BASE_URLS:
            alt = base.rstrip("/") + "/" + path
            if alt not in urls:
                urls.append(alt)
    return urls


def _http_code(result):
    """The HTTP status a curl run with -w '%{http_code}' reported.

    curl writes "000" when it never received a response, which is the one thing
    that separates "this testbed cannot route to that host" from "the host
    answered and refused". Both look identical in an exit code, and telling
    them apart is usually the whole question.
    """
    stdout = (result.get('stdout') or '').strip()
    match = re.search(r"(\d{3})\s*$", stdout)
    return match.group(1) if match else "?"


def probe_url(host, url, sas_token=None):
    """What one host gets back for one URL, without downloading it.

    Asks for the first byte only (-r 0-0), so probing a multi-megabyte tarball
    costs nothing; a good answer is therefore 206 as often as 200. HEAD is
    deliberately not used - the image server front end has been observed to
    ignore HEAD while answering GET perfectly well.

    No -f here, on purpose: the point is to read the status the server sent,
    not to collapse it into a curl exit code. Returns (http_code, curl_rc).
    """
    cmd = ("curl -sSL -o /dev/null -w '%{{http_code}}' -r 0-0 "
           "--connect-timeout 10 --max-time 60 '{}'").format(
               with_sas_token(url, sas_token))
    result = host.shell(cmd, module_ignore_errors=True)
    return _http_code(result), result['rc']


def fetch_to_dut(duthost, localhost, url, dest_dir, filename, sas_token=None):
    """Download one file into dest_dir on the DUT.

    The DUT downloads for itself, which is what hardware proxy does in
    production. KVM testbeds are network isolated, so fall back to downloading
    on the test runner and copying the file across. Either way the bytes are
    checksummed on the DUT afterwards, so the fallback cannot mask a corrupt
    transfer.

    Each candidate endpoint is tried from both places before moving on. A
    failure here is far more often "this testbed cannot route to that host"
    than "the package is missing", so on total failure report every endpoint
    tried rather than a bare curl exit code.

    Every curl carries an explicit --connect-timeout for that reason: the
    alternates exist precisely because they may be unreachable, and curl's
    default connect timeout is the OS TCP timeout of roughly two minutes. With
    two files per package, two packages, and a DUT and runner attempt for each
    endpoint, relying on the default turns "this testbed cannot reach the image
    server" into a run that stalls for tens of minutes before saying so. The
    production wrapper uses --connect-timeout 10 for the same reason.

    Only redacted URLs are ever logged: the real one may carry a SAS token, and
    test logs are widely readable.
    """
    dest = os.path.join(dest_dir, filename)
    staged = os.path.join("/tmp", "sonic-ops-{}-{}".format(uuid.uuid4().hex, filename))
    attempts = []

    for candidate in candidate_urls(url):
        safe_url = redact(candidate)
        authed_url = with_sas_token(candidate, sas_token)
        # -f so HTTP errors fail loudly instead of writing the error body to
        # disk, -L to follow the redirects the image server front end issues,
        # and -w so the status survives -f: without it every HTTP failure is
        # exit code 22 and a missing package is indistinguishable from an
        # unauthenticated one.
        curl = ("curl -fL -sS --connect-timeout 10 --max-time 600 "
                "-w '%{{http_code}}' -o {} '{}'").format(dest, authed_url)

        result = duthost.shell(curl, module_ignore_errors=True)
        if result['rc'] == 0:
            logger.info("Downloaded %s on the DUT", safe_url)
            return dest
        attempts.append("DUT    -> {} (curl rc={}, HTTP {})".format(
            safe_url, result['rc'], _http_code(result)))

        try:
            runner = localhost.shell(
                ("curl -fL -sS --connect-timeout 10 --max-time 600 "
                 "-w '%{{http_code}}' -o {} '{}'").format(staged, authed_url),
                module_ignore_errors=True)
            if runner['rc'] == 0:
                logger.info("DUT could not fetch %s; downloaded on the test runner instead",
                            safe_url)
                duthost.copy(src=staged, dest=dest)
                return dest
        finally:
            localhost.shell("rm -f -- {}".format(shlex.quote(staged)))
        attempts.append("runner -> {} (curl rc={}, HTTP {})".format(
            safe_url, runner['rc'], _http_code(runner)))

    if _delivery_url(url):
        raise RuntimeError(
            "Could not download the latest package from its exact anonymous URL {}.\n"
            "No alternate endpoint or legacy source option is used.\nTried:\n  {}".format(
                url, "\n  ".join(attempts)))
    raise RuntimeError(
        "Could not download {} from any known image server endpoint.\n"
        "Tried:\n  {}\n"
        "\n"
        "Reading the HTTP column:\n"
        "  000      no HTTP status received; inspect curl's error for timeout,\n"
        "           DNS, TLS or connection failures, not just routing issues.\n"
        "  404      the endpoint is reachable and serves this tree, but the\n"
        "           file is not in it - check --sonic_ops_branch, and note\n"
        "           that a branch build publishes under branches/<branch>/.\n"
        "  403, 409 the file may well be there, but the request carried no\n"
        "           usable credential. 409 PublicAccessNotPermitted means the\n"
        "           storage account refuses anonymous reads outright; 403\n"
        "           means a token was sent and was not accepted. Pass a read\n"
        "           SAS with --package_sas_token.".format(
            filename, "\n  ".join(attempts)))


def verify_md5_like_wrapper(duthost, binary_path, md5_path):
    """Check a downloaded file against its .md5 the way the production wrapper does.

    The wrapper compares the first field of ``md5sum <file>`` against the first
    field of the .md5 file rather than using ``md5sum -c``, because the .md5 it
    fetches may name a different path than the one it downloaded to. Mirroring
    that here keeps the test honest about what production actually verifies.

    Returns (matched, actual, expected).
    """
    actual = duthost.shell(
        "md5sum {} | awk '{{ print $1; }}'".format(binary_path)
    )['stdout'].strip()
    expected = duthost.shell(
        "awk '{{ print $1; }}' {}".format(md5_path)
    )['stdout'].strip()
    return actual == expected, actual, expected


def verify_md5_like_preload_firmware(duthost, package_path, md5_path):
    """Check a package against its .md5 exactly the way hardware proxy does.

    This mirrors download_util() in sonic-metadata/scripts/preload_firmware,
    which is the code that actually gates a CPHC package on a real device. It
    differs from ``md5sum -c`` in two ways that matter:

    * it compares only the *hash field* of each side, so it does not care what
      filename the .md5 records - a .md5 that names a different path still
      passes in production, and a test using ``md5sum -c`` would wrongly fail;
    * it strips carriage returns from the .md5 before reading the hash, so a
      CRLF .md5 is accepted in production - a test using ``md5sum -c`` would
      wrongly fail there too.

    Asserting the production algorithm is the point: this test exists to prove
    the published package passes *the check hardware proxy performs*, not a
    stricter one we invented.

    Returns (matched, actual, expected).
    """
    actual = duthost.shell(
        "md5sum {} | awk '{{ print $1; }}'".format(package_path)
    )['stdout'].strip()
    expected = duthost.shell(
        "cat {} | tr -d '\\r' | awk '{{ print $1; }}'".format(md5_path)
    )['stdout'].strip()
    return actual == expected, actual, expected


# --- Driving the real preload_firmware on a DUT ---------------------------------
#
# ONE script downloads BOTH packages, through the same branch of it. In
# sonic-metadata/scripts/preload_firmware the dispatch is on the filename:
#
#     download_CPHC_without_md5sum() {
#         if [[ "$FILENAME" == *"sonic-upgrade-package"* ]]; then
#             IP_ADDR=$(echo $URL | awk -F/ '{print $3}')
#             MD5_FILE="${FILENAME}.md5"
#             download_util "${IP_ADDR}" "${FILENAME}" "${MD5_FILE}" EXIT_CPHC_DOWNLOAD_FAILURE
#             exit 0
#
# Both published tarballs match that pattern - "sonic-upgrade-package-1.0.0.tar"
# (CPHC) and "sonic-upgrade-package.tar.gz" (postupgrade_actions) - so the two are
# fetched by identical code with only the filename differing:
#
#     preload_firmware <tarball> http://<host>/
#
# Everything else the script derives for itself: the md5 filename by appending
# ".md5", the host by taking the third /-delimited field of the URL, and the
# location by rebuilding it as http://<host>/networkfirmware/ACS/<subpath><file>.
# Both files land in the *current working directory* - there is no destination
# argument - and the hashes are compared before it exits 0. The third argument, a
# checksum, is mandatory for every other kind of file and deliberately optional
# for these two.
#
# The device copy reaches the postupgrade package by a second route as well:
# download_postupgrade_binaries() lists it in binary_info unconditionally and
# moves both files into /host/postupgrade-binaries afterwards. That move is the
# *next* hardware proxy step rather than part of the download, so a test that
# drives the real script has to perform it in turn to reproduce the flow.

# Where a device may already have the script. /tmp/anpscripts is where hardware
# proxy stages it, so it is checked first.
PRELOAD_FIRMWARE_CANDIDATES = (
    "/tmp/anpscripts/preload_firmware",
    "/usr/local/bin/preload_firmware",
    "/usr/bin/preload_firmware",
    "/host/preload_firmware",
)

# download_util() prints this once the hash comparison has passed. Asserting on it
# distinguishes "the script succeeded" from "the script exited 0 without checking",
# which matters because the package branch exits 0 explicitly.
PRELOAD_SUCCESS_MARKER = "downloaded successfully and md5sum validated"


class MirrorUnavailable(Exception):
    """The package could not be served on the DUT, so the script cannot be driven.

    Raised rather than skipped directly to keep pytest out of this module: the
    caller decides whether an unusable mirror is a skip or a failure.
    """


def find_preload_firmware(duthost, configured=None, src=None, addfinalizer=None):
    """Locate the real preload_firmware on the DUT, copying one over if configured.

    Prefers a copy already on the device, because that is the one production
    would run, and which of the two variants it is becomes an observable fact of
    the run rather than a choice made by the test.
    """
    if configured:
        result = duthost.shell("test -f {} && test -r {}".format(
            shlex.quote(configured), shlex.quote(configured)), module_ignore_errors=True)
        assert result.get('rc') == 0, "Configured preload_firmware is not readable: {}: {}".format(configured, result)
        return configured

    if src:
        if addfinalizer is None:
            raise ValueError("A cleanup finalizer is required when copying preload_firmware")
        dest = "/tmp/preload_firmware-{}".format(uuid.uuid4().hex)
        addfinalizer(lambda: duthost.shell("rm -f -- {}".format(shlex.quote(dest))))
        duthost.copy(src=src, dest=dest, mode="0755")
        return dest

    for path in PRELOAD_FIRMWARE_CANDIDATES:
        if duthost.shell("test -f {}".format(path), module_ignore_errors=True)['rc'] == 0:
            return path
    return None


_START_MIRROR = """
import json, os, subprocess, sys
root, log, identity, port, address = sys.argv[1:]
with open(log, 'ab') as output:
    child = subprocess.Popen([sys.executable, '-m', 'http.server', port, '--bind', address,
                              '--directory', root], stdin=subprocess.DEVNULL,
                             stdout=output, stderr=output, start_new_session=True)
try:
    with open('/proc/%d/stat' % child.pid) as stream:
        start = stream.read().rsplit(')', 1)[1].split()[19]
    with open(identity, 'w') as stream:
        json.dump({'pid': child.pid, 'start': start}, stream)
except BaseException:
    child.terminate()
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=5)
    raise
"""

_MIRROR_PROCESS = """
import json, os, signal, sys, time
identity, root, action = sys.argv[1:]
if not os.path.exists(identity):
    if action == 'stop':
        sys.exit(0)
    raise RuntimeError('Mirror process identity was not recorded')
with open(identity) as stream:
    owned = json.load(stream)
pid = owned['pid']
def live_identity():
    try:
        with open('/proc/%d/stat' % pid) as stream:
            fields = stream.read().rsplit(')', 1)[1].split()
    except FileNotFoundError:
        return False
    if fields[19] != owned['start']:
        raise RuntimeError('Mirror PID was reused; refusing to signal it')
    return fields[0] not in ('Z', 'X', 'x')
def alive():
    for attempt in range(5):
        if not live_identity():
            return False
        try:
            with open('/proc/%d/cmdline' % pid, 'rb') as stream:
                args = stream.read().decode().split(chr(0))
        except FileNotFoundError:
            args = []
        # stat and cmdline are separate snapshots. Exit can clear cmdline after
        # the first stat sample, so establish identity/liveness again.
        if not live_identity():
            return False
        directory = args.index('--directory') + 1 if '--directory' in args else len(args)
        if 'http.server' in args and directory < len(args) and args[directory] == root:
            return True
        if any(args):
            raise RuntimeError('Mirror command identity changed; refusing to signal it')
        if attempt < 4:
            time.sleep(0.02)
    raise RuntimeError('Live mirror command identity unavailable; refusing to signal it')
def send(sig):
    if not alive():
        return
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        # ESRCH means the checked process exited before the signal syscall.
        return
if action == 'check':
    if not alive():
        raise RuntimeError('Owned mirror is no longer running')
elif alive():
    send(signal.SIGTERM)
    for _ in range(50):
        if not alive():
            break
        time.sleep(0.1)
    if alive():
        send(signal.SIGKILL)
        for _ in range(50):
            if not alive():
                break
            time.sleep(0.1)
        if alive():
            raise RuntimeError('Owned mirror did not stop')
"""


class PackageMirror(object):
    """Serve a published package on the DUT at the path preload_firmware expects.

    preload_firmware cannot be pointed at the publish path: download_util()
    derives the location from the host alone and always appends
    /networkfirmware/ACS/. So the bytes fetched from the image server are
    re-served on the DUT under exactly that layout and the genuine script is
    asked to fetch them. What is under test is the script's download and
    verification of *the bytes the pipeline published*, which is the step that
    decides whether a real device accepts the package.

    The package is served at both shipped layouts - with and without the
    "sonic-upgrade-packages/" subpath - because the proxy copy and the device
    copy look in different places (see MIRROR_CPHC_SUBPATH). The access log then
    says which one this DUT actually asked for, so a run reports the deployed
    variant instead of assuming it.

    Each test module uses its own port so that two mirrors can never be confused
    for one another, even if a teardown somewhere failed.
    """

    def __init__(self, duthost, name, port):
        self.duthost = duthost
        self.name = name
        self.package_metadata = {}
        self.port = port
        self.workspace = "/tmp/{}-mirror-{}".format(name, uuid.uuid4().hex)
        self.root = self.workspace + "/www"
        self.log = self.workspace + "/server.log"
        self.pid_file = self.workspace + "/process.json"
        self.offset_file = self.workspace + "/request.offset"
        self.scratch = self.workspace + "/run"
        self.created = False
        self.nonce_file = "mirror-nonce.txt"
        self.base_url = None

    def docroots(self):
        """Absolute paths on the DUT, one per shipped layout."""
        return ["{}/{}".format(self.root, d) for d in mirror_serve_dirs()]

    def served_copies(self, filename):
        """Every path this mirror holds `filename` at, one per shipped layout."""
        return ["{}/{}".format(docroot, filename) for docroot in self.docroots()]

    def start(self, src_dir, filenames, package_metadata=None):
        """Clean up owned files/process even when setup fails before fixture yield."""
        self.package_metadata = package_metadata or {}
        try:
            self.duthost.shell("mkdir -- {}".format(shlex.quote(self.workspace)))
            self.created = True
            return self._start(src_dir, filenames)
        except BaseException:
            self.stop()
            raise

    def _start(self, src_dir, filenames):
        """Serve `filenames` (and their .md5 siblings) from `src_dir` on the DUT.

        Returns the base URL to hand to preload_firmware. Raises
        MirrorUnavailable if the DUT cannot serve or reach it, rather than
        letting the run stall - see the timeout note below.
        """
        duthost = self.duthost
        ip_addr = dut_eth0_ip(duthost)
        if not ip_addr:
            raise MirrorUnavailable(
                "Could not determine the DUT's eth0 address, so the package cannot be "
                "served where preload_firmware would look for it.")

        docroots = self.docroots()
        duthost.shell("mkdir -p {}".format(" ".join(shlex.quote(path) for path in docroots)))
        for docroot in docroots:
            for filename in filenames:
                duthost.shell("cp {0}/{1} {0}/{1}.md5 {2}/".format(
                    src_dir, filename, docroot))

        # A token identifying *this* mirror, checked once it is up.
        nonce = uuid.uuid4().hex
        duthost.shell("echo {} > {}/{}".format(nonce, self.root, self.nonce_file))

        duthost.shell(
            "python3 -c {} {}".format(shlex.quote(_START_MIRROR), " ".join(
                shlex.quote(str(value)) for value in
                (self.root, self.log, self.pid_file, self.port, ip_addr))))

        self.base_url = "http://{}:{}/".format(ip_addr, self.port)
        probes = [mirror_package_url(self.base_url, filename, subpath)
                  for filename in filenames
                  for subpath in ("", MIRROR_CPHC_SUBPATH)]

        # Pre-flight with the *exact* curl preload_firmware will run, including
        # the interface specifier, and give up rather than proceed if it fails.
        #
        # This is not defensive padding. preload_firmware's first curl has no
        # connect timeout, so if the interface cannot reach the mirror the script
        # sits there for over two minutes per file before falling back -
        # measured, not assumed. Worse, its fallback extracts the host with
        # `awk -F/ '{print $3}'`, which here yields "<ip>:<port>"; that fails its
        # IPv4/IPv6 regex, so the mgmt-address retry cannot engage for a URL with
        # a port and the run degrades to the slowest path available. Far better
        # to stop with a clear reason than to hang a nightly.
        ready = False
        for _ in range(10):
            checks = [duthost.shell(
                "curl --interface eth0 --connect-timeout 5 --max-time 10 -f -s -o /dev/null {}".format(url),
                module_ignore_errors=True)['rc'] for url in probes]
            if all(rc == 0 for rc in checks):
                ready = True
                break
            time.sleep(1)

        if not ready:
            log = duthost.shell("cat {}".format(self.log),
                                module_ignore_errors=True)['stdout']
            raise MirrorUnavailable(
                "Could not serve the package on the DUT at {} over eth0, which is how "
                "preload_firmware fetches. python3 http.server may be unavailable, or "
                "eth0 may not reach the DUT's own address. Log:\n{}".format(
                    ", ".join(probes), log))

        # Confirm the thing answering is our mirror. A server left behind on this
        # port from an earlier run passes the pre-flight perfectly well while
        # serving entirely different bytes, which would make every assertion
        # afterwards meaningless without saying so.
        seen = duthost.shell(
            "curl --interface eth0 --connect-timeout 5 --max-time 10 -f -s {}{}".format(
                self.base_url, self.nonce_file),
            module_ignore_errors=True)['stdout'].strip()
        if seen != nonce:
            raise MirrorUnavailable(
                "Port {} on the DUT is answering, but not from the mirror this test "
                "started: expected token {}, got {!r}. Something else is bound to that "
                "port, so the bytes under test cannot be trusted.".format(
                    self.port, nonce, seen))

        # Record where the pre-flight requests end so the real script's choice can
        # be read back without them. The pre-flight deliberately probes every
        # layout, so without this every variant would look like it was fetched.
        self._process("check")
        duthost.shell("wc -l < {} > {}".format(self.log, self.offset_file))

        logger.info("Serving the published package(s) at %s", " and ".join(probes))
        return self.base_url

    def stop(self):
        """Stop only our recorded process; retain files if ownership is uncertain."""
        if self.created:
            self._process("stop")
            self.duthost.shell("rm -rf -- {}".format(shlex.quote(self.workspace)))
            self.created = False

    def _process(self, action):
        self.duthost.shell("python3 -c {} {} {} {}".format(
            shlex.quote(_MIRROR_PROCESS), shlex.quote(self.pid_file), shlex.quote(self.root), action))

    def run_preload_firmware(self, preload, filename):
        """Invoke the real script exactly as hardware proxy does, for any package.

        `preload_firmware <filename> <url>` is the whole contract: the same two
        arguments fetch the CPHC tarball and the postupgrade tarball, because the
        script selects that branch on the filename alone. download_util writes
        into the current directory, so this runs from a scratch directory whose
        contents are then the script's output.
        """
        self.duthost.shell("rm -rf {0} && mkdir -p {0}".format(self.scratch))
        self.duthost.shell("wc -l < {} > {}".format(self.log, self.offset_file))
        result = self.duthost.shell(
            "cd {} && timeout --signal=TERM --kill-after=10 300 bash {} {} {}".format(
                shlex.quote(self.scratch), shlex.quote(preload), shlex.quote(filename), shlex.quote(self.base_url)),
            module_ignore_errors=True)
        assert isinstance(result.get('rc'), int), (
            "preload_firmware command failed without an exit status: {}".format(result))
        logger.info("preload_firmware %s: rc=%s stdout=%r",
                    filename, result['rc'], result['stdout'])
        return result

    def assert_valid_download(self, preload, filename):
        result = self.run_preload_firmware(preload, filename)
        assert result['rc'] == 0 and PRELOAD_SUCCESS_MARKER in result['stdout'], (
            "preload_firmware positive control did not validate the package: {}".format(result))
        require_package_integrity(self.duthost, self.scratch + "/" + filename,
                                  self.scratch + "/" + filename + ".md5",
                                  self.package_metadata.get(filename))

    def assert_rejects_corruption(self, preload, filename):
        """Use valid/corrupt/valid controls and observed HTTP200 fetches, not exit numbers."""
        self.assert_valid_download(preload, filename)
        with DutPathState(self.duthost) as state:
            for served in self.served_copies(filename):
                original = state.preserve(served)
                assert original is not None, "Mirror source vanished before corruption: {}".format(served)
                self.duthost.shell("cp -- {} {}".format(shlex.quote(original), shlex.quote(served)))
                self.duthost.shell("dd if=/dev/zero of={} bs=1 count=64 conv=notrunc".format(shlex.quote(served)))
                matched, actual, expected = verify_md5_like_wrapper(self.duthost, served, served + ".md5")
                assert not matched and actual != expected, "Corruption did not change {}".format(served)
            result = self.run_preload_firmware(preload, filename)
            assert result['rc'] not in (0, 124, 126, 127, 137), (
                "Consumer did not reject corrupt bytes, or could not run: {}".format(result))
            assert PRELOAD_SUCCESS_MARKER not in result['stdout'], "Corrupt payload was reported as validated"
            log = self._requests()
            for suffix in ("", ".md5"):
                pattern = r'"GET /[^"]*/{} HTTP/[^"]+" 200 '.format(re.escape(filename + suffix))
                assert re.search(pattern, log), (
                    "No successful fetch of corrupt payload/sidecar {}; "
                    "cannot attribute failure to integrity:\n{}".format(
                        filename + suffix, log))
        self.assert_valid_download(preload, filename)

    def _requests(self):
        start = self.duthost.shell("cat {}".format(self.offset_file))['stdout'].strip()
        return self.duthost.shell("tail -n +{} {}".format(int(start) + 1, self.log))['stdout']

    def fetched_variant(self):
        """Report which layout preload_firmware actually requested, from the log.

        python3 -m http.server logs one line per request, so the path the script
        chose is recorded rather than inferred. This is the only direct evidence
        of which copy of preload_firmware a DUT is running.

        The log is read from the offset recorded after the pre-flight, rather
        than truncated. Truncating a file the server still holds open leaves it
        writing at its old offset, so the gap comes back as NUL bytes and the log
        stops being readable text - observed, not theorised.

        Lines are scanned newest first so the answer describes the run that just
        happened rather than an earlier one in the same module.
        """
        log = self._requests()
        subpath = "/{}/{}/".format(MIRROR_PACKAGE_PREFIX, MIRROR_CPHC_SUBPATH)
        flat = "/{}/".format(MIRROR_PACKAGE_PREFIX)
        for line in reversed(log.splitlines()):
            if subpath in line:
                return "device copy (Networking-Metadata, {})".format(subpath)
            if flat in line:
                return "hardware proxy copy (sonic-metadata, no subpath)"
        return "unknown - no matching request in the mirror log"


def dut_eth0_ip(duthost):
    """The DUT's own eth0 address, found the way preload_firmware finds it.

    The script downloads with ``--interface eth0``, so the mirror has to be
    reachable on that interface. Serving on loopback would still work - curl
    fails, then retries without the specifier - but it would exercise the
    fallback path instead of the normal one.
    """
    result = duthost.shell(
        "ip -4 addr show dev eth0 scope global | grep inet | awk '{print $2}' "
        "| awk -F/ '{print $1}' | head -1", module_ignore_errors=True)
    return result['stdout'].strip() if result['rc'] == 0 else ""


# ---------------------------------------------------------------------------
# How production actually fetches these packages
# ---------------------------------------------------------------------------
# Neither consumer uses preload_firmware for these two packages. Both use plain
# curl over plain HTTP, and both read from the *same* directory on the image
# server. Verified against the shipping source:
#
#   hardware proxy - HwSonicSwitch.cs, GetDeviceCriticalProcessHealth() ->
#   DownloadFileFromUrl():
#       curl -f <url> -o <file>
#   run over telnet from /tmp/sonic-upgrade-scripts, and a download is treated
#   as failed when the output matches curl's own error format.
#
#   the device wrapper - Networking-Metadata
#   src/data/Network/SONiC/scripts/postupgrade_actions,
#   download_postupgrade_binary():
#       curl [--interface eth0 ]-s --connect-timeout 10 <url> -o <file>
#   into /host/postupgrade-binaries.
#
# Both compose the URL as
#     http://<image server>/networkfirmware/ACS/sonic-upgrade-packages/<file>
# (hardware proxy from SonicFirmwareFolder + SonicUpgradePackagesDir; the
# wrapper by passing "sonic-upgrade-packages/<file>" as the binary name to a
# base of http://<ip>/networkfirmware/ACS). So the two packages are siblings in
# one directory, and MIRROR_PACKAGE_PREFIX + MIRROR_CPHC_SUBPATH already
# describes it.
#
# The two curl invocations differ in ways worth keeping distinct in tests:
# hardware proxy passes -f, so an HTTP error is a non-zero exit; the wrapper
# does not, so an HTTP error body is written to the file and only the md5 check
# afterwards catches it. That asymmetry is exactly why the md5 check matters
# more for the postupgrade package than for CPHC.

# Working directories the two consumers download into, from the same sources.
HWPROXY_CPHC_WORK_DIR = "/tmp/sonic-upgrade-scripts"
WRAPPER_BINARIES_DIR = "/host/postupgrade-binaries"

# Hardware proxy reads the expected hash out of `cat <file>.md5` with this
# regex (HwSonicSwitch.GetExpectedMd5, @"\s*([A-Za-z0-9]{32})\r*"). It takes
# the first 32-character token in the output and ignores the filename field
# entirely, which is why a .md5 naming a different path still passes there.
HWPROXY_MD5_RE = re.compile(r"([A-Za-z0-9]{32})")

# curl commands, verbatim in shape from each consumer. Kept as templates rather
# than inlined so a test asserts the production form rather than one we made up.
HWPROXY_CURL = "curl -f {url} -o {dest}"
WRAPPER_CURL = "curl -s --connect-timeout 10 {url} -o {dest}"


def curl_like_hwproxy(duthost, url, dest, sas_token=None):
    """Download one file on the DUT using hardware proxy's exact curl form.

    Returns the CommandResult; the caller decides what a failure means. Only a
    redacted URL is logged - the real one may carry a SAS token.
    """
    cmd = HWPROXY_CURL.format(url=with_sas_token(url, sas_token), dest=dest)
    result = duthost.shell(cmd, module_ignore_errors=True)
    logger.info("hwproxy-style curl %s -> %s: rc=%s", redact(url), dest, result['rc'])
    return result


def curl_like_wrapper(duthost, url, dest, sas_token=None):
    """Download one file on the DUT using the postupgrade wrapper's curl form.

    Note the absence of -f: the wrapper accepts whatever the server returns and
    relies on the md5 comparison to reject an error page. Tests that assert the
    md5 gate should use this, because it is the path where the gate is the only
    protection.
    """
    cmd = WRAPPER_CURL.format(url=with_sas_token(url, sas_token), dest=dest)
    result = duthost.shell(cmd, module_ignore_errors=True)
    logger.info("wrapper-style curl %s -> %s: rc=%s", redact(url), dest, result['rc'])
    return result


def read_md5_like_hwproxy(duthost, md5_path):
    """Extract the expected hash the way hardware proxy does (cat + regex).

    Returns the hash, or None when the file holds nothing that looks like one -
    which is what hardware proxy reports as InformationMissingInCommandOutput.
    """
    result = duthost.shell("cat {}".format(md5_path), module_ignore_errors=True)
    if result['rc'] != 0:
        return None
    match = HWPROXY_MD5_RE.search(result['stdout'])
    return match.group(1) if match else None


def read_md5_like_wrapper(duthost, md5_path):
    """Extract the expected hash the way the wrapper does (awk '{print $1}')."""
    result = duthost.shell("awk '{{ print $1; }}' {}".format(md5_path),
                           module_ignore_errors=True)
    if result['rc'] != 0:
        return None
    return result['stdout'].strip() or None


def md5_on_dut(duthost, path):
    """The DUT's own md5 of a file, first field only, as both consumers take it."""
    return duthost.shell("md5sum {} | awk '{{ print $1; }}'".format(path))['stdout'].strip()


def archive_listing(duthost, path):
    """List an archive on the DUT with `tar -tf`, the wrapper's corruption gate.

    The wrapper runs exactly this against an already-present tarball and, on a
    non-zero exit, deletes it and re-downloads. Returns (ok, members).

    `tar -tf` auto-detects compression, so this is correct for both the plain
    .tar CPHC package and the gzipped postupgrade package.
    """
    result = duthost.shell("tar -tf {}".format(path), module_ignore_errors=True)
    members = [line.strip() for line in result['stdout'].splitlines() if line.strip()]
    return result['rc'] == 0, members
