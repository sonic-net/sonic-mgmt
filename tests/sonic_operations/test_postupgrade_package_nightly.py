"""Nightly validation of the published postupgrade_actions package.

Default cases verify and execute the package directly, without a production
wrapper: consumer-style curl, pinned provenance/MD5 checks, extraction to
``/tmp/postupgrade-actions``, then ``python ./postupgrade_actions -e <UUID>``.
Completion requires a fresh matching report and process result, not just rc0.

``--sonic_operations_integration`` additionally selects genuine Networking-Metadata
wrapper and preload_firmware cases. These need the real deployed scripts; direct
package smoke coverage does not establish their production-consumer behavior.

.. warning::
   Default direct execution runs the real postupgrade_actions on the DUT. That script applies
   patches, rewrites configuration and restarts services; it has no dry-run mode.
   Run it only on a testbed where that is acceptable. Pass
   ``--postupgrade_skip_execute`` to skip direct package execution and every real-wrapper invocation.
"""

import json
import logging
import shlex
import uuid

import pytest

from sonic_operations_helper import (
    delivery_package_url,
    download_latest_package,
    publication_info,
    find_preload_firmware,
    MirrorUnavailable,
    PackageMirror,
    PRELOAD_FIRMWARE_CANDIDATES,
    PRELOAD_SUCCESS_MARKER,
    redact,
    verify_md5_like_wrapper,
    DutPathState,
    dut_workspace,
    require_package_integrity,
    curl_like_wrapper,
)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
]

logger = logging.getLogger(__name__)

# Paths the production wrapper uses. These are hardcoded in it, so the test must
# use the same ones for the wrapper to find what has been staged.
BINARIES_DIR = "/host/postupgrade-binaries"
TARBALL = "sonic-upgrade-package.tar.gz"
EXTRACT_DIR = "/tmp/postupgrade-actions"
REPORTS_DIR = "/host/sonic-upgrade-reports"
# The pinned main waits for 420 seconds of uptime, then performs serial patches.
DIRECT_EXECUTION_TIMEOUT = 1800
HEALTH_CHECK_FAILURE = 125

# Where the wrapper may already be installed on a device.
WRAPPER_CANDIDATES = (
    "/usr/bin/postupgrade_actions",
    "/usr/local/bin/postupgrade_actions",
    "/host/postupgrade_actions",
    "/tmp/postupgrade_actions_wrapper",
)


def _tarball_url(request):
    """Shared latest route; old plan URLs cannot redirect this package."""
    return delivery_package_url(request, "postupgrade")


@pytest.fixture(scope="module")
def wrapper_path(duthosts, rand_one_dut_hostname, request):
    """Path to the production wrapper on the DUT.

    Prefers a wrapper already installed on the device, since that is the one
    production would run. Falls back to copying one over, which is how a lab DUT
    that has never been managed by hardware proxy gets it.
    """
    duthost = duthosts[rand_one_dut_hostname]

    configured = request.config.getoption("--postupgrade_wrapper")
    candidates = [configured] if configured else list(WRAPPER_CANDIDATES)
    for candidate in candidates:
        if duthost.stat(path=candidate)['stat']['exists']:
            logger.info("Using postupgrade wrapper already on the DUT: %s", candidate)
            yield candidate
            return

    src = request.config.getoption("--postupgrade_wrapper_src")
    if not src:
        pytest.skip(
            "No postupgrade_actions wrapper found on the DUT (looked in {}). Pass "
            "--postupgrade_wrapper with its path on the device, or "
            "--postupgrade_wrapper_src with a local copy of the wrapper from "
            "Networking-Metadata (src/data/Network/SONiC/scripts/postupgrade_actions) "
            "to copy over.".format(", ".join(candidates)))

    with dut_workspace(duthost, "postupgrade-wrapper") as directory:
        dest = directory + "/postupgrade_actions"
        logger.info("Copying wrapper %s to %s on the DUT", src, dest)
        duthost.copy(src=src, dest=dest, mode="0755")
        yield dest


@pytest.fixture
def postupgrade_state(duthosts, rand_one_dut_hostname):
    """Restore fixed consumer paths, not the real payload's OS/service changes."""
    duthost = duthosts[rand_one_dut_hostname]
    with DutPathState(duthost) as state:
        state.directory(BINARIES_DIR)
        state.preserve(BINARIES_DIR + "/" + TARBALL)
        state.preserve(BINARIES_DIR + "/" + TARBALL + ".md5")
        state.preserve(EXTRACT_DIR)
        yield state


@pytest.fixture
def staged_package(duthosts, rand_one_dut_hostname, localhost, request, postupgrade_state):
    """Download the published package and stage it where the wrapper looks for it.

    Yields (tarball_path, md5_path) on the DUT. Staging rather than letting the
    wrapper download is what makes this runnable in a lab: the wrapper's mirrors
    are production-only. The wrapper still validates and extracts what it finds.
    """
    duthost = duthosts[rand_one_dut_hostname]
    url = _tarball_url(request)

    logger.info("Staging postupgrade package from %s", redact(url))
    entry = download_latest_package(request, duthost, localhost, "postupgrade", BINARIES_DIR)
    yield entry["tarball"], entry["md5_file"]


def test_postupgrade_package_integrity(duthosts, rand_one_dut_hostname, staged_package):
    """The published tarball must match its md5 and be a readable archive.

    Checked the same way the wrapper does: comparing the first field of md5sum
    against the first field of the .md5 file, then ``tar -tf``, which is the
    wrapper's own corruption test before it will use a cached tarball.
    """
    duthost = duthosts[rand_one_dut_hostname]
    tarball, md5 = staged_package

    matched, actual, expected = verify_md5_like_wrapper(duthost, tarball, md5)
    assert matched, \
        "md5 mismatch for the published package: got {}, expected {}".format(actual, expected)
    logger.info("Package md5 verified: %s", actual)

    duthost.shell("tar -tf {} > /dev/null".format(tarball))

    listing = duthost.shell("tar -tzf {}".format(tarball))['stdout']
    assert "postupgrade_actions" in listing, \
        "Published tarball does not contain postupgrade_actions:\n{}".format(listing[:2000])
    assert "postupgrade_infra.py" in listing, \
        "Published tarball does not contain postupgrade_infra.py:\n{}".format(listing[:2000])
    logger.info("Package contains %d entries", len(listing.splitlines()))


def _assert_direct_execution_report(report, event_guid, result, report_version):
    """Require the selected package's final report, including caught patch exceptions."""
    assert isinstance(report, dict), "SUP report must be an object"
    summary = report.get("sonic_upgrade_summary")
    details = report.get("sonic_upgrade_report")
    assert isinstance(summary, dict) and isinstance(details, dict), "SUP report is incomplete"
    assert summary.get("guid") == event_guid, "SUP report belongs to another invocation"
    assert summary.get("script_name") == "postupgrade_actions", "Unexpected SUP report script"
    assert summary.get("sonic_upgrade_package_version") == report_version, "Unexpected SUP report package version"
    stages = details.get("stages")
    assert isinstance(stages, list) and len(stages) >= 2, "SUP report has no completed patch stages"
    assert all(isinstance(stage, dict) and isinstance(stage.get("name"), str)
               and isinstance(stage.get("rc"), str) for stage in stages), "Invalid SUP patch stage"
    assert stages[0]["name"] == "patch_process_reboot_cause" and stages[-1]["name"] == "check_device_health", (
        "SUP main did not report its complete patch/health sequence")
    failed = [stage for stage in stages[:-1] if stage["rc"] != "0"]
    assert not failed, "SUP patches failed (including caught exceptions): {}".format(failed)
    assert stages[-1]["rc"] in ("0", str(HEALTH_CHECK_FAILURE)), "SUP health-check execution failed"
    assert summary.get("fault_code") == stages[-1]["rc"], "SUP fault code disagrees with completed stages"
    assert result["rc"] == int(summary["fault_code"]), "SUP exit code disagrees with its report"
    health_checks = details.get("health_checks")
    errors = details.get("errors")
    assert isinstance(health_checks, list) and health_checks and all(
        isinstance(check, dict) and isinstance(check.get("name"), str)
        and isinstance(check.get("success"), bool) for check in health_checks), "Invalid SUP health-check report"
    assert isinstance(errors, list) and all(
        isinstance(error, dict) and isinstance(error.get("message"), str) for error in errors), (
        "Invalid SUP error report")
    assert not any(error["message"] == "Unknown error" for error in errors), "SUP health check threw an exception"
    logger.info("SUP package completed; device-health findings (not an upgrade verdict): %s",
                json.dumps(report, indent=2))


def test_postupgrade_package_runs_directly(duthosts, rand_one_dut_hostname, localhost, request):
    """Curl, verify, extract and execute the actual package without a production wrapper."""
    if request.config.getoption("--postupgrade_skip_execute"):
        pytest.skip("--postupgrade_skip_execute was passed; not staging or executing the real package")
    duthost = duthosts[rand_one_dut_hostname]
    state = request.getfixturevalue("postupgrade_state")
    entry = download_latest_package(request, duthost, localhost, "postupgrade", BINARIES_DIR,
                                    consumer_curl=curl_like_wrapper)
    tarball = entry["tarball"]
    duthost.shell("mkdir -p {}".format(EXTRACT_DIR))
    duthost.shell("tar -xf {} -C {}".format(shlex.quote(tarball), EXTRACT_DIR))

    event_guid = str(uuid.uuid4())
    report_path = REPORTS_DIR + "/postupgrade_actions." + event_guid + ".json"
    state.directory(REPORTS_DIR)
    state.preserve(report_path)
    logger.warning("Executing the real SUP package: patches/config/service changes are NOT rolled back by file cleanup")
    result = duthost.shell(
        "cd {0} && timeout --signal=TERM --kill-after=30s {1}s python ./postupgrade_actions -e {2}".format(
            EXTRACT_DIR, DIRECT_EXECUTION_TIMEOUT, event_guid), module_ignore_errors=True)
    assert result["rc"] in (0, HEALTH_CHECK_FAILURE), "SUP execution failed or timed out: {}".format(result)
    assert duthost.stat(path=report_path)["stat"]["exists"], "SUP did not write this invocation's report"
    report = json.loads(duthost.shell("cat {}".format(shlex.quote(report_path)))["stdout"])
    _assert_direct_execution_report(report, event_guid, result, entry["buildinfo"]["reportVersion"])


@pytest.mark.sonic_operations_integration
def test_postupgrade_wrapper_runs_real_script(duthosts, rand_one_dut_hostname,
                                              staged_package, wrapper_path, request, postupgrade_state):
    """Run the production wrapper end to end against the published package.

    The wrapper extracts the staged tarball and executes the real
    postupgrade_actions. What is asserted is that the packaged script *ran to
    completion* - it extracted, started, and wrote its report. Its fault code is
    logged rather than asserted, because a non-zero code means this DUT failed a
    health check, which is a statement about the device rather than about the
    package that was published.
    """
    duthost = duthosts[rand_one_dut_hostname]
    tarball, _md5 = staged_package

    if request.config.getoption("--postupgrade_skip_execute"):
        pytest.skip("--postupgrade_skip_execute was passed; not running the real script")

    # The wrapper names its report after the event guid, exactly as hardware proxy
    # supplies one, which is also how the test finds the report afterwards.
    event_guid = str(uuid.uuid4())
    logger.info("Running wrapper %s with event guid %s", wrapper_path, event_guid)
    report = "{}/postupgrade_actions.{}.json".format(REPORTS_DIR, event_guid)
    postupgrade_state.directory(REPORTS_DIR)
    postupgrade_state.preserve(report)
    require_package_integrity(duthost, tarball, _md5, publication_info(request, "postupgrade"))
    duthost.shell("rm -rf -- {}".format(EXTRACT_DIR))

    result = duthost.shell(
        "python {} -e {}".format(shlex.quote(wrapper_path), event_guid),
        module_ignore_errors=True)

    # Wrapper exit code 3 is its own failure to download or extract, so it never
    # reached the packaged script. That is a packaging or delivery fault and must
    # fail the test, unlike a non-zero fault code from the script itself.
    assert result['rc'] != 3, (
        "The wrapper failed to obtain or extract the package (rc=3). It should have used "
        "the staged tarball at {}/{}.\nstdout:\n{}\nstderr:\n{}".format(
            BINARIES_DIR, TARBALL, result['stdout'], result['stderr']))

    # The wrapper extracts here before executing; its absence means it never got
    # far enough to run the packaged script.
    extracted = duthost.stat(path="{}/postupgrade_actions".format(EXTRACT_DIR))
    assert extracted['stat']['exists'], \
        "The wrapper did not extract postupgrade_actions to {}".format(EXTRACT_DIR)

    report = "{}/postupgrade_actions.{}.json".format(REPORTS_DIR, event_guid)
    assert duthost.stat(path=report)['stat']['exists'], (
        "postupgrade_actions did not write its report to {}, so it did not run to "
        "completion.\nWrapper rc={}\nstdout:\n{}\nstderr:\n{}".format(
            report, result['rc'], result['stdout'], result['stderr']))

    summary = json.loads(duthost.shell("cat {}".format(report))['stdout'])
    logger.info("postupgrade_actions report:\n%s", json.dumps(summary, indent=2))

    # Exit code is the fault code, so it describes the device, not the package.
    fault_code = summary.get("sonic_upgrade_summary", {}).get("fault_code")
    if result['rc'] != 0:
        logger.warning(
            "postupgrade_actions reported fault code %s (wrapper rc=%s). The package ran "
            "correctly; this reflects the state of %s.",
            fault_code, result['rc'], duthost.hostname)
    else:
        logger.info("postupgrade_actions completed with no faults on %s", duthost.hostname)


@pytest.mark.sonic_operations_integration
def test_wrapper_rejects_corrupted_cached_package(request):
    """Declare the unsupported external-recovery contract without executing it."""
    if request.config.getoption("--postupgrade_skip_execute"):
        pytest.skip("--postupgrade_skip_execute was passed; not running the real wrapper")
    pytest.skip(
        "Cached-wrapper corruption recovery is not covered: the production wrapper deletes "
        "invalid cache files and re-downloads from hardcoded external mirrors, possibly executing "
        "an unpinned replacement. A supported controlled recovery endpoint is required before "
        "this case can safely run. Generic nonzero exits do not prove corruption rejection; "
        "the separate real-preload corruption cases remain enabled.")


# --- Running the real hardware proxy download path ------------------------------
#
# Everything above stages the tarball itself and then drives the production
# wrapper. That covers the wrapper, but it leaves the *delivery* step - the one
# hardware proxy actually performs - untested, and a re-implementation of it can
# only ever test itself.
#
# The tests below close that gap by handing the job to the genuine
# sonic-metadata/scripts/preload_firmware, which is the same script and the same
# code path that fetches the CPHC package:
#
#     preload_firmware sonic-upgrade-package.tar.gz http://<host>/
#
# download_CPHC_without_md5sum() selects that branch for any filename matching
# *sonic-upgrade-package*, which both published tarballs do, so nothing here is a
# special case - it is the CPHC path carrying the other package. The script
# appends ".md5" itself, derives the host from the URL, and writes both files
# into the current directory.
#
# Hardware proxy then continues, and so does the test: the device copy of
# preload_firmware moves both files into /host/postupgrade-binaries, and the
# wrapper takes over from there - validate, extract to /tmp/postupgrade-actions,
# execute, write the report. Reproducing that sequence in order is what makes
# this the production flow rather than an approximation of it.

POSTUPGRADE_WORKSPACE = "/tmp/postupgrade-package-workspace"

# A port of its own, so this mirror and the CPHC one can never be mistaken for
# each other even if a teardown somewhere failed.
POSTUPGRADE_MIRROR_PORT = 8911


def _preload_or_skip(duthost, request):
    """The real preload_firmware on this DUT, or skip explaining how to supply one."""
    preload = find_preload_firmware(
        duthost,
        request.config.getoption("--preload_firmware"),
        request.config.getoption("--preload_firmware_src"),
        addfinalizer=request.addfinalizer)
    if not preload:
        pytest.skip(
            "preload_firmware is not on this DUT (looked in {}). It is deployed from "
            "sonic-metadata; pass --preload_firmware to point at it, or "
            "--preload_firmware_src to copy one across.".format(
                ", ".join(PRELOAD_FIRMWARE_CANDIDATES)))
    return preload


@pytest.fixture(scope="module")
def postupgrade_workspace(duthosts, rand_one_dut_hostname, localhost, request):
    """Fetch the published package to a scratch directory on the DUT.

    Kept separate from /host/postupgrade-binaries deliberately: this is only the
    source the mirror serves from, and putting it where the wrapper looks would
    let a test pass because the file was staged rather than because
    preload_firmware delivered it.
    """
    duthost = duthosts[rand_one_dut_hostname]
    url = _tarball_url(request)
    with dut_workspace(duthost, "postupgrade-source") as source:
        logger.info("Fetching postupgrade package from %s", redact(url))
        download_latest_package(request, duthost, localhost, "postupgrade", source)
        yield source


@pytest.fixture(scope="module")
def postupgrade_mirror(duthosts, rand_one_dut_hostname, postupgrade_workspace, request):
    """Serve the published package where preload_firmware looks for it."""
    duthost = duthosts[rand_one_dut_hostname]
    _preload_or_skip(duthost, request)
    mirror = PackageMirror(duthost, "postupgrade", POSTUPGRADE_MIRROR_PORT)
    try:
        mirror.start(postupgrade_workspace, [TARBALL],
                     package_metadata={TARBALL: publication_info(request, "postupgrade")})
    except MirrorUnavailable as exc:
        pytest.skip(str(exc))
    try:
        yield mirror
    finally:
        mirror.stop()


@pytest.mark.sonic_operations_integration
def test_postupgrade_package_downloads_via_real_preload_firmware(
        duthosts, rand_one_dut_hostname, postupgrade_mirror, request):
    """The genuine preload_firmware must accept the published postupgrade package.

    This is the delivery step exactly as a device performs it: the real script,
    its real curl invocation and its real hash comparison, against the exact
    bytes the pipeline published. A failure here means the package as published
    would not reach a device, whatever the wrapper would have done with it.
    """
    duthost = duthosts[rand_one_dut_hostname]
    preload = _preload_or_skip(duthost, request)

    logger.info("Running the real %s against %s", preload, postupgrade_mirror.base_url)
    result = postupgrade_mirror.run_preload_firmware(preload, TARBALL)

    assert result['rc'] == 0, (
        "The real preload_firmware rejected the published postupgrade package (rc={}).\n"
        "stdout:\n{}\nstderr:\n{}\n"
        "This is the check a device performs, so a failure here means the package as "
        "published would not be accepted in production.".format(
            result['rc'], result['stdout'], result['stderr']))

    assert PRELOAD_SUCCESS_MARKER in result['stdout'], (
        "preload_firmware exited 0 but never reported a validated download, so the hash "
        "comparison did not run. stdout:\n{}".format(result['stdout']))

    # The script is only useful if it left both files behind for the next step.
    duthost.shell("test -f {}/{}".format(postupgrade_mirror.scratch, TARBALL))
    duthost.shell("test -f {}/{}.md5".format(postupgrade_mirror.scratch, TARBALL))
    logger.info("The real preload_firmware downloaded and validated the published "
                "postupgrade package; this DUT runs the %s",
                postupgrade_mirror.fetched_variant())


@pytest.mark.sonic_operations_integration
def test_real_preload_firmware_rejects_corrupted_postupgrade_package(
        duthosts, rand_one_dut_hostname, postupgrade_mirror, request):
    """The genuine preload_firmware must refuse a package whose bytes changed.

    Proving the real script fails is what shows a device is protected. The
    positive test alone cannot: a script that never compared anything would pass
    it just as well.
    """
    duthost = duthosts[rand_one_dut_hostname]
    preload = _preload_or_skip(duthost, request)

    postupgrade_mirror.assert_rejects_corruption(preload, TARBALL)


@pytest.mark.sonic_operations_integration
def test_postupgrade_hwproxy_flow_end_to_end(duthosts, rand_one_dut_hostname,
                                             postupgrade_mirror, wrapper_path, request, postupgrade_state):
    """Follow the whole hardware proxy sequence, with nothing re-implemented.

    In order, and each step performed by the production code that owns it:

    1. preload_firmware downloads the tarball and its md5 and verifies the hash
    2. both files are moved to /host/postupgrade-binaries, as
       download_postupgrade_binaries() does after its own download_util call
    3. the wrapper finds them there, validates and extracts to /tmp/postupgrade-actions
    4. the packaged postupgrade_actions runs and writes its report

    What is asserted is that the packaged script *ran to completion*. Its fault
    code is logged rather than asserted, because a non-zero code means this DUT
    failed a health check, which is a statement about the device rather than
    about the package that was published.
    """
    duthost = duthosts[rand_one_dut_hostname]
    preload = _preload_or_skip(duthost, request)

    if request.config.getoption("--postupgrade_skip_execute"):
        pytest.skip("--postupgrade_skip_execute was passed; not running the real script")

    # 1. Delivery, by the real script.
    result = postupgrade_mirror.run_preload_firmware(preload, TARBALL)
    assert result['rc'] == 0, (
        "preload_firmware did not deliver the postupgrade package (rc={}), so the rest "
        "of the hardware proxy flow cannot be exercised.\nstdout:\n{}\nstderr:\n{}".format(
            result['rc'], result['stdout'], result['stderr']))
    logger.info("preload_firmware delivered the package; this DUT runs the %s",
                postupgrade_mirror.fetched_variant())

    # 2. The move hardware proxy performs next. Clearing the directory first
    #    matters: a tarball left by an earlier test would be used instead of the
    #    one preload_firmware just fetched, and the test would pass without the
    #    delivery step having contributed anything.
    require_package_integrity(duthost, postupgrade_mirror.scratch + "/" + TARBALL,
                              postupgrade_mirror.scratch + "/" + TARBALL + ".md5",
                              publication_info(request, "postupgrade"))
    duthost.shell("mv {0}/{1} {0}/{1}.md5 {2}/".format(
        postupgrade_mirror.scratch, TARBALL, BINARIES_DIR))

    # 3 and 4. The wrapper owns everything from here.
    event_guid = str(uuid.uuid4())
    logger.info("Running wrapper %s with event guid %s", wrapper_path, event_guid)
    report = "{}/postupgrade_actions.{}.json".format(REPORTS_DIR, event_guid)
    postupgrade_state.directory(REPORTS_DIR)
    postupgrade_state.preserve(report)
    duthost.shell("rm -rf -- {}".format(EXTRACT_DIR))

    wrapper = duthost.shell("python {} -e {}".format(shlex.quote(wrapper_path), event_guid),
                            module_ignore_errors=True)

    # Wrapper exit code 3 is its own failure to download or extract, so it never
    # reached the packaged script. Here that is unambiguous: preload_firmware had
    # already delivered a hash-verified tarball to the directory it reads.
    assert wrapper['rc'] != 3, (
        "The wrapper failed to obtain or extract the package (rc=3) even though "
        "preload_firmware had delivered and verified it to {}/{}.\nstdout:\n{}\n"
        "stderr:\n{}".format(BINARIES_DIR, TARBALL, wrapper['stdout'], wrapper['stderr']))

    extracted = duthost.stat(path="{}/postupgrade_actions".format(EXTRACT_DIR))
    assert extracted['stat']['exists'], \
        "The wrapper did not extract postupgrade_actions to {}".format(EXTRACT_DIR)

    report = "{}/postupgrade_actions.{}.json".format(REPORTS_DIR, event_guid)
    assert duthost.stat(path=report)['stat']['exists'], (
        "postupgrade_actions did not write its report to {}, so it did not run to "
        "completion.\nWrapper rc={}\nstdout:\n{}\nstderr:\n{}".format(
            report, wrapper['rc'], wrapper['stdout'], wrapper['stderr']))

    summary = json.loads(duthost.shell("cat {}".format(report))['stdout'])
    logger.info("postupgrade_actions report:\n%s", json.dumps(summary, indent=2))

    fault_code = summary.get("sonic_upgrade_summary", {}).get("fault_code")
    if wrapper['rc'] != 0:
        logger.warning(
            "postupgrade_actions reported fault code %s (wrapper rc=%s). The package was "
            "delivered and ran correctly; this reflects the state of %s.",
            fault_code, wrapper['rc'], duthost.hostname)
    else:
        logger.info("The full hardware proxy flow completed with no faults on %s",
                    duthost.hostname)
