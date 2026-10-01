"""Nightly verification of the two published SONiC upgrade packages on a device.

This module closes the most basic gap first: *are the published bytes intact and
usable on a device*. It downloads both packages with plain ``curl`` the way
production does, then applies exactly the checks production applies before it
will run anything.

Why curl, and why here
----------------------
Neither consumer of these packages uses ``preload_firmware``. Both use curl over
plain HTTP, and both read the two packages out of one directory on the image
server, ``/networkfirmware/ACS/sonic-upgrade-packages/``:

* hardware proxy, ``HwSonicSwitch.GetDeviceCriticalProcessHealth()``, fetches
  ``sonic-upgrade-package-<ver>.tar`` with ``curl -f <url> -o <file>``, reads the
  expected hash out of the ``.md5`` with ``cat`` plus a 32-hex-character regex,
  compares it to the device's own ``md5sum``, and on a mismatch deletes the
  tarball and fails the operation outright;
* the device wrapper, ``Networking-Metadata .../scripts/postupgrade_actions``,
  fetches ``sonic-upgrade-package.tar.gz`` with
  ``curl -s --connect-timeout 10 <url> -o <file>`` and compares
  ``md5sum <file> | awk '{print $1}'`` against ``awk '{print $1}' <file>.md5``.
  It also runs ``tar -tf`` against any tarball already on disk and re-downloads
  when that fails.

The difference between those two curl invocations is why this module exists as
its own layer. Hardware proxy passes ``-f``, so an HTTP error is a non-zero exit
and never reaches the integrity check. The wrapper does not, so an HTTP error
page is written to the file and the *only* thing standing between a 404 body and
``tar -xf`` is the md5 comparison. A published ``.md5`` that is missing,
malformed, or stale therefore fails silently on the path where it matters most
-- which is precisely the gap these tests close.

Scope
-----
Delivery and integrity only. Installing, executing and uninstalling the packages
is covered by ``test_cphc_package_nightly.py`` and
``test_postupgrade_package_nightly.py``. Nothing here writes to the directories
real upgrade flows read from: everything is staged under a scratch directory and
removed afterwards, so a corrupted-tarball test can never leave a device holding
a package that a later, genuine run would pick up.
"""

import logging
import os

import pytest

from sonic_operations_helper import (CPHC_PACKAGE_DIR,
                                     POSTUPGRADE_PACKAGE_DIR, archive_listing,
                                     delivery_package_url, candidate_urls, curl_like_hwproxy,
                                     curl_like_wrapper, download_latest_package,
                                     md5_on_dut, probe_url,
                                     read_md5_like_hwproxy,
                                     read_md5_like_wrapper, redact,
                                     dut_workspace)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
]

logger = logging.getLogger(__name__)

# Staged here rather than in /tmp/sonic-upgrade-scripts or
# /host/postupgrade-binaries on purpose. Those are the directories hardware
# proxy and the postupgrade wrapper read from, and this module deliberately
# writes corrupt and truncated copies; leaving one behind would change what a
# subsequent real run consumes.
WORK_DIR = "/tmp/sonic-upgrade-packages-verify"

CPHC = "cphc"
POSTUPGRADE = "postupgrade"

# The script hardware proxy runs out of the extracted CPHC package.
INSTALLER = "installer.py"


class _Package(object):
    """One published package and what production expects to find inside it."""

    def __init__(self, key, filename, package_dir, required_members, curl, consumer,
                 gzipped):
        self.key = key
        self.filename = filename
        self.package_dir = package_dir
        self.required_members = required_members
        # The exact curl form the real consumer of this package uses.
        self.curl = curl
        self.consumer = consumer
        # Whether the archive carries a compression layer with its own integrity
        # check. Decides whether `tar -tf` is a reliable corruption detector.
        self.gzipped = gzipped

    def __repr__(self):
        return "<{}: {}>".format(self.key, self.filename)


def _normalise(members):
    """Archive members as plain relative paths.

    tar listings may carry a ``./`` prefix and directories a trailing slash,
    neither of which says anything about whether the file is present.
    """
    cleaned = set()
    for member in members:
        name = member.lstrip('./').rstrip('/')
        if name:
            cleaned.add(name)
    return cleaned


def _has_member(members, wanted):
    """Whether `wanted` is present, matching either a full path or a basename.

    The two packages are built with different tar invocations, so one stores
    bare names and the other stores paths. Requiring a specific spelling here
    would assert the packaging layout rather than the package's contents.
    """
    if wanted.endswith('/'):
        prefix = wanted.rstrip('/')
        return any(name == prefix or name.startswith(prefix + '/') for name in members)
    return any(name == wanted or os.path.basename(name) == wanted for name in members)


@pytest.fixture(scope="module")
def packages(request):
    """Both published packages, described the way their consumers see them."""
    delivery_package_url(request, CPHC)
    tar_version = request.config.getoption("--cphc_tar_version")
    return {
        CPHC: _Package(
            key=CPHC,
            filename="sonic-upgrade-package-{}.tar".format(tar_version),
            package_dir=CPHC_PACKAGE_DIR,
            # installer.py plus at least one wheel; which wheel gets installed
            # depends on the DUT's OS train and is asserted by the CPHC module.
            required_members=(INSTALLER,),
            curl=curl_like_hwproxy,
            consumer="hardware proxy (HwSonicSwitch)",
            gzipped=False,
        ),
        POSTUPGRADE: _Package(
            key=POSTUPGRADE,
            filename="sonic-upgrade-package.tar.gz",
            package_dir=POSTUPGRADE_PACKAGE_DIR,
            # The wrapper execs ./postupgrade_actions from the extracted tree,
            # which imports postupgrade_infra and reads postupgrade_actions_data.
            required_members=("postupgrade_actions", "postupgrade_infra.py",
                              "postupgrade_actions_data/"),
            curl=curl_like_wrapper,
            consumer="the postupgrade_actions wrapper",
            gzipped=True,
        ),
    }


def _package_url(request, package):
    """The latest route is selected by code, not by manual-plan arguments."""
    return delivery_package_url(request, package.key)


@pytest.fixture(scope="module")
def staged(duthosts, rand_one_dut_hostname, localhost, request, packages):
    """Download both packages and their .md5 files onto the DUT.

    Downloaded in production's order - the ``.md5`` first, then the tarball -
    because that is what hardware proxy does, and because it means a run that
    cannot even fetch the checksum fails before spending time on the payload.

    The download is attempted on the DUT first, which is what production does.
    ``fetch_to_dut`` falls back to the test runner for network-isolated
    testbeds; the bytes are checksummed on the DUT either way, so the fallback
    cannot mask a corrupt transfer. That fallback is why the integrity tests
    still run on a KVM testbed, while ``test_package_downloads_with_curl``
    separately asserts the production-faithful DUT-side download.
    """
    duthost = duthosts[rand_one_dut_hostname]
    staged_files = {}

    with dut_workspace(duthost, "package-verify") as workspace:
        for package in packages.values():
            url = _package_url(request, package)
            logger.info("Verifying %s package %s from %s",
                        package.key, package.filename, redact(url))
            staged_files[package.key] = download_latest_package(
                request, duthost, localhost, package.key, workspace)
        yield staged_files


@pytest.fixture(params=[CPHC, POSTUPGRADE])
def package(request, packages):
    """Run each test once per published package."""
    return packages[request.param]


def test_image_server_is_reachable(duthosts, rand_one_dut_hostname, localhost, request,
                                   packages):
    """Report what every candidate endpoint actually answers, before fetching.

    This exists because the interesting failure is not "the download failed" but
    *why*, and that answer is only obtainable from inside the lab. Whether a
    testbed can route to a given image server, and whether that server will
    serve a package anonymously, cannot be determined from a dev box or a
    pipeline agent - both sit on different networks than the DUT.

    So this runs first, depends on nothing that downloads, and always logs the
    full endpoint-by-endpoint table. A run that cannot fetch anything still
    comes back with the facts needed to fix it, instead of a wall of identical
    errors from every downstream test.

    Both the DUT and the test runner are probed for each endpoint, because they
    have different network positions and the download path falls back from one
    to the other.
    """
    duthost = duthosts[rand_one_dut_hostname]
    sas_token = request.config.getoption("--package_sas_token")

    rows = []
    reachable = []
    for pkg in packages.values():
        url = _package_url(request, pkg)
        for candidate in candidate_urls(url):
            for where, host in (("DUT", duthost), ("runner", localhost)):
                code, rc = probe_url(host, candidate, sas_token=sas_token)
                rows.append("  {:<6} HTTP {:<4} curl rc={:<3} {}".format(
                    where, code, rc, redact(candidate)))
                # 206 because the probe asks for a byte range, not the file.
                if code in ("200", "206"):
                    reachable.append("{} from the {}".format(redact(candidate), where))

    table = "\n".join(rows)
    logger.info("Image server reachability:\n%s", table)

    assert reachable, (
        "No image server endpoint served either package to this testbed.\n{}\n"
        "\n"
        "000 means no HTTP status was received; inspect curl's error for timeout,\n"
        "    DNS, TLS or connection failures. It does not identify a routing cause.\n"
        "404 means the endpoint is reachable but the shared latest package is not published there.\n"
        "403 or 409 means anonymous access to the required route was refused.\n"
        "Legacy source options and SAS tokens cannot redirect or authenticate this route.".format(table))


def test_package_downloads_with_curl(duthosts, rand_one_dut_hostname, request, package):
    """The DUT can fetch the package with its consumer's own curl command.

    Runs the exact curl form the real consumer uses rather than a normalised
    one, so this fails when the package is unreachable *the way production
    reaches it* - including cases a friendlier curl would paper over.

    A routing failure and a missing package are different problems, so the
    failure message names the endpoint that was tried.
    """
    duthost = duthosts[rand_one_dut_hostname]
    url = _package_url(request, package)
    with dut_workspace(duthost, "package-curl-" + package.key) as scratch:
        entry = download_latest_package(request, duthost, None, package.key, scratch, consumer_curl=package.curl)
        logger.info("%s downloaded %s (%s bytes) from %s",
                    package.consumer, package.filename, entry["buildinfo"]["sizeBytes"], redact(url))


def test_md5_file_is_parseable_by_both_consumers(duthosts, rand_one_dut_hostname,
                                                 staged, package):
    """Both production parsers read the same hash out of the published .md5.

    The two consumers parse the file differently - hardware proxy takes the
    first 32-hex-character token out of ``cat``, the wrapper takes the first
    whitespace-delimited field via ``awk``. They agree on a well-formed file and
    disagree on a malformed one, so comparing them detects a bad .md5 that
    either parser alone would accept. An HTML error page saved as a .md5 is the
    case that matters: ``awk`` happily returns its first word.
    """
    duthost = duthosts[rand_one_dut_hostname]
    md5_file = staged[package.key]["md5_file"]

    hwproxy_hash = read_md5_like_hwproxy(duthost, md5_file)
    wrapper_hash = read_md5_like_wrapper(duthost, md5_file)
    contents = duthost.shell("cat {}".format(md5_file))['stdout']

    assert hwproxy_hash is not None, (
        "hardware proxy could not find a 32-character hash in {}.md5. It contains: "
        "{!r}".format(package.filename, contents[:200]))
    assert wrapper_hash == hwproxy_hash, (
        "the published .md5 for {} parses differently in the two consumers: hardware "
        "proxy reads {!r}, the wrapper reads {!r}. Contents: {!r}".format(
            package.filename, hwproxy_hash, wrapper_hash, contents[:200]))
    logger.info("%s.md5 parses consistently as %s", package.filename, hwproxy_hash)


def test_tarball_matches_published_md5(duthosts, rand_one_dut_hostname, staged, package):
    """The published tarball matches its published checksum, checked on the DUT.

    This is the single check both consumers gate on, and the only thing
    protecting the wrapper's path from executing an HTTP error body. Computed on
    the device rather than the runner so the bytes that are verified are the
    bytes that would be extracted.
    """
    duthost = duthosts[rand_one_dut_hostname]
    entry = staged[package.key]

    actual = md5_on_dut(duthost, entry["tarball"])
    expected = read_md5_like_wrapper(duthost, entry["md5_file"])

    assert actual == expected, (
        "{} does not match its published checksum: the device computed {}, the "
        "published .md5 says {}. The package at {} is corrupt, truncated, or its .md5 "
        "is stale - production would refuse to install it.".format(
            package.filename, actual, expected, redact(entry["url"])))
    logger.info("%s matches its published md5 (%s)", package.filename, actual)


def test_tarball_is_a_readable_archive(duthosts, rand_one_dut_hostname, staged, package):
    """``tar -tf`` succeeds, which is the wrapper's own corruption gate.

    The wrapper runs exactly this against a tarball already on disk and, when it
    fails, deletes the package and downloads again. A package that is published
    intact but not readable as an archive would put a device into that loop
    forever, so it is worth asserting separately from the checksum.
    """
    duthost = duthosts[rand_one_dut_hostname]
    ok, members = archive_listing(duthost, staged[package.key]["tarball"])

    assert ok, ("tar -tf failed on {} - the wrapper treats this as a corrupt package "
                "and re-downloads".format(package.filename))
    assert members, "{} is a readable archive but contains no members".format(
        package.filename)
    logger.info("%s lists %d members", package.filename, len(members))


def test_tarball_contains_expected_members(duthosts, rand_one_dut_hostname, staged, package):
    """Everything the consumer execs after extraction is actually in the archive.

    A package can pass its checksum and still be unusable if the build dropped a
    file, and the consumer only discovers that after it has extracted and tried
    to run it. Checking the manifest here turns a runtime failure on a device
    into a delivery failure in the nightly.
    """
    duthost = duthosts[rand_one_dut_hostname]
    ok, raw_members = archive_listing(duthost, staged[package.key]["tarball"])
    assert ok, "could not list {}".format(package.filename)
    members = _normalise(raw_members)

    missing = [want for want in package.required_members
               if not _has_member(members, want)]
    assert not missing, (
        "{} is missing {} - {} would extract it and then fail at runtime. Archive "
        "contains: {}".format(package.filename, ", ".join(missing), package.consumer,
                              sorted(members)))

    if package.key == CPHC:
        wheels = [name for name in members if name.endswith(".whl")]
        assert wheels, (
            "the CPHC package contains installer.py but no wheel for it to install. "
            "Archive contains: {}".format(sorted(members)))
        logger.info("CPHC package ships wheels: %s", sorted(wheels))


def test_corrupted_tarball_fails_md5(duthosts, rand_one_dut_hostname, staged, package):
    """A modified tarball is rejected by the checksum both consumers apply.

    Proves the gate is real rather than assumed. Without this, every positive
    result above is equally consistent with a comparison that always passes - a
    stale .md5 or an empty hash on both sides would look identical.

    Operates on a copy; the verified download is left untouched.
    """
    duthost = duthosts[rand_one_dut_hostname]
    entry = staged[package.key]
    corrupt = entry["tarball"] + ".corrupt"

    try:
        # Appending guarantees a different digest. Flipping a byte in place does
        # not: the chosen offset may already hold the replacement value.
        duthost.shell("cp {} {} && printf 'corrupted' >> {}".format(
            entry["tarball"], corrupt, corrupt))

        actual = md5_on_dut(duthost, corrupt)
        expected = read_md5_like_wrapper(duthost, entry["md5_file"])

        assert actual != expected, (
            "a deliberately corrupted copy of {} still matched the published checksum - "
            "the integrity check is not actually comparing the payload".format(
                package.filename))
        logger.info("corrupted %s is correctly rejected (%s != %s)",
                    package.filename, actual, expected)
    finally:
        duthost.shell("rm -f {}".format(corrupt), module_ignore_errors=True)


def test_truncated_tarball_is_rejected(duthosts, rand_one_dut_hostname, staged, package):
    """A partial download is rejected before anything is extracted.

    An interrupted download leaving a partial file on disk is the failure the
    wrapper explicitly handles, and the two consumers catch it differently:

    * the checksum catches it for both packages, always - a shorter file cannot
      produce the published digest;
    * ``tar -tf`` catches it for the gzipped postupgrade package, because a
      truncated gzip stream cannot be inflated. That is the wrapper's own gate,
      and the one it uses to decide to re-download.

    ``tar -tf`` is deliberately *not* asserted for the plain CPHC tar. tar has no
    whole-archive checksum, so a truncation landing in a member's zero padding
    reads as a clean end-of-archive and lists without error. That is precisely
    why hardware proxy gates the CPHC package on md5 alone and never runs
    ``tar -tf`` against it; asserting otherwise here would encode a guarantee
    production does not have, and would flake depending on where the cut lands.
    """
    duthost = duthosts[rand_one_dut_hostname]
    entry = staged[package.key]
    truncated = entry["tarball"] + ".partial"

    try:
        size = int(duthost.shell("stat -c %s {}".format(
            entry["tarball"]))['stdout'].strip())
        duthost.shell("head -c {} {} > {}".format(max(size // 2, 1), entry["tarball"],
                                                  truncated))

        actual = md5_on_dut(duthost, truncated)
        expected = read_md5_like_wrapper(duthost, entry["md5_file"])
        assert actual != expected, (
            "a half-sized copy of {} still matched the published checksum, so a partial "
            "download would be accepted as a good package".format(package.filename))

        ok, _ = archive_listing(duthost, truncated)
        if package.gzipped:
            assert not ok, (
                "a half-sized copy of {} still listed cleanly with tar -tf. The wrapper "
                "uses that listing to decide whether a cached package is usable, so a "
                "partial download would be extracted and executed".format(
                    package.filename))
            logger.info("truncated %s is rejected by both md5 and tar -tf",
                        package.filename)
        else:
            # Recorded rather than asserted: see the docstring. Worth logging
            # because it shows which gate actually fired on this package.
            logger.info("truncated %s rejected by md5; tar -tf %s (not a guarantee for "
                        "an uncompressed tar)", package.filename,
                        "also rejected it" if not ok else "still listed it")
    finally:
        duthost.shell("rm -f {}".format(truncated), module_ignore_errors=True)
