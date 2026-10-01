"""Nightly validation of the published CPHC (critical process health checker) package.

This exercises the package exactly the way hardware proxy does on a real device:
download the tarball and its md5 from the image server, verify integrity, unpack,
install with the bundled ``installer.py``, confirm the install, run the checker,
then uninstall and restore the device to its original state.

Two layers, deliberately:

* the tests that drive the package directly, which can validate installation and
  execution on this OS version;
* optional ``--sonic_operations_integration`` tests that hand the published bytes
  to the *real* ``preload_firmware`` from sonic-metadata, which actually accepts or rejects a CPHC
  package in production. Re-implementing that check can only ever test our reading
  of it, so the genuine script is run as well.

Scope: this validates *delivery and installation of the package* - that what the
pipeline published is intact, installs on this OS version, and runs. It is
deliberately not a device-health test: the checker's own verdict about the DUT is
logged rather than asserted, so an unhealthy DUT does not look like a broken
package.
"""

import json
import logging
import re
import shlex
from datetime import datetime, timedelta

import pytest

from sonic_operations_helper import (delivery_package_url, download_latest_package,
                                     select_package_publication, publication_info,
                                     redact, verify_md5_like_preload_firmware,
                                     find_preload_firmware, MirrorUnavailable, PackageMirror,
                                     PRELOAD_FIRMWARE_CANDIDATES, PRELOAD_SUCCESS_MARKER,
                                     DutPathState, dut_workspace, require_package_integrity)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
]

logger = logging.getLogger(__name__)

PACKAGE_NAME = "sonic_critical_process_checker"
INSTALLER = "installer.py"
CALLER = "sonic_critical_process_checker_caller"

# installer.py installs the py2 wheel only on these trains, and py3 everywhere else.
# Kept in sync with critical-process-checker/installer.py.
PY2_OS_VERSIONS = ("201811", "201911")

# Where the checker writes its report, from script/sonic_critical_process_checker.py.
CHECKER_OUTPUT_DIR = "/tmp/sonic-upgrade-scripts"

WORK_DIR = "/tmp/cphc-nightly"


def _tar_name(tar_version):
    return "sonic-upgrade-package-{}.tar".format(tar_version)


def _wheel_name(wheel_version, py_tag):
    return "{}-{}-{}-none-any.whl".format(PACKAGE_NAME, wheel_version, py_tag)


def _expected_py_tag(duthost):
    """Which wheel installer.py will choose for this DUT."""
    if any(ver in duthost.os_version for ver in PY2_OS_VERSIONS):
        return "py2"
    return "py3"


def _installed_version(duthost):
    """Return the installed package version, or None when it is not installed."""
    result = duthost.shell("pip show {}".format(PACKAGE_NAME),
                           module_ignore_errors=True)
    assert result.get('rc') in (0, 1), "Cannot inspect installed CPHC with pip: {}".format(result)
    if result['rc'] == 1:
        assert re.search(r"Package(?:\(s\))? not found:", result['stderr'], re.IGNORECASE), (
            "pip show failed without establishing package absence: {}".format(result))
        return None
    match = re.search(r"^Version:\s*(\S+)", result['stdout'], re.MULTILINE)
    assert match, "pip show did not return a package version: {}".format(result)
    return match.group(1)


def _validate_says_installed(duthost, work_dir):
    """Run `installer.py --validate` and return whether it reports the package.

    installer.py exits 0 whether or not the package is present, so its stdout is
    the only usable signal - the return code cannot be used here.
    """
    result = duthost.shell("cd {} && python {} --validate".format(work_dir, INSTALLER),
                           module_ignore_errors=True)
    logger.info("installer --validate: rc=%s stdout=%r", result['rc'], result['stdout'])
    return "is installed" in result['stdout'] and "is not installed" not in result['stdout']


@pytest.fixture(scope="module")
def package_url(request):
    """Shared latest route, independent of saved manual-plan source arguments."""
    return delivery_package_url(request, "cphc")


@pytest.fixture(scope="module")
def cphc_workspace(duthosts, rand_one_dut_hostname, localhost, package_url, request):
    """Download and unpack the package, and restore the DUT afterwards.

    Yields the working directory on the DUT.

    The device is left with the package state it started in. If it already had
    CPHC installed at the version under test, that install is restored at the end
    rather than removed - otherwise a nightly run would strip a device of a
    package it was meant to be running. If it has a *different* version
    installed, the test refuses to run at all, because the original wheel is not
    available here and so could not be put back.
    """
    duthost = duthosts[rand_one_dut_hostname]
    metadata = select_package_publication(request, duthost, localhost, "cphc")
    tar_file = metadata["package"]
    wheel_version = metadata["wheelVersion"]

    preexisting_version = _installed_version(duthost)
    logger.info("CPHC version installed before the test: %s", preexisting_version)

    if preexisting_version and preexisting_version != wheel_version:
        pytest.skip(
            "{} {} is already installed on {}, but this run validates {}. Installing over "
            "it would leave the device on the wrong version, and the original wheel is not "
            "available here to restore. Use a "
            "device without CPHC installed.".format(
                PACKAGE_NAME, preexisting_version, duthost.hostname, wheel_version))

    with dut_workspace(duthost, "cphc-source", keep_on_error=True) as source:
        entry = download_latest_package(request, duthost, localhost, "cphc", source, metadata=metadata)
        members = entry["members"]
        for required in (INSTALLER, _wheel_name(wheel_version, _expected_py_tag(duthost))):
            assert required in members, "CPHC recovery material is missing {} in {}".format(required, tar_file)
        try:
            yield source
        finally:
            # Uninstall deletes its own directory's installer/wheels/tar. Never
            # run it in the protected source or depend on an earlier extraction.
            with dut_workspace(duthost, "cphc-restore") as restore_dir:
                duthost.shell("tar -xf {} -C {}".format(
                    shlex.quote(source + "/" + tar_file), shlex.quote(restore_dir)))
                action = "--install" if preexisting_version else "--uninstall"
                duthost.shell("cd {} && python {} {}".format(
                    shlex.quote(restore_dir), INSTALLER, action))
                restored = _installed_version(duthost)
                assert restored == preexisting_version, (
                    "CPHC restoration failed: expected {}, found {}; recovery source {}".format(
                        preexisting_version, restored, source))


@pytest.fixture
def cphc_install_dir(duthosts, rand_one_dut_hostname, cphc_workspace):
    """Keep destructive installer operations separate from verified source bytes."""
    with dut_workspace(duthosts[rand_one_dut_hostname], "cphc-install") as directory:
        yield directory


def test_cphc_package_install_from_image_server(duthosts, rand_one_dut_hostname,
                                                cphc_workspace, package_url, request, cphc_install_dir):
    """Download, verify, install, exercise and remove the published CPHC package."""
    duthost = duthosts[rand_one_dut_hostname]
    work_dir = cphc_workspace
    tar_version = request.config.getoption("--cphc_tar_version")
    metadata = publication_info(request, "cphc")
    wheel_version = metadata["wheelVersion"]
    tar_file = _tar_name(tar_version)

    logger.info("Validating CPHC package %s on %s (OS %s)",
                redact(package_url), duthost.hostname, duthost.os_version)

    # 1. Integrity, checked the way hardware proxy checks it. download_util() in
    #    preload_firmware compares only the hash field of each side and strips CR
    #    from the .md5 first, so this asserts the package passes *the production
    #    gate* rather than a stricter check of our own invention.
    matched, actual, expected = verify_md5_like_preload_firmware(
        duthost, "{}/{}".format(work_dir, tar_file), "{}/{}.md5".format(work_dir, tar_file))
    assert matched, (
        "Published CPHC package fails the integrity check hardware proxy performs.\n"
        "  md5sum of the downloaded tarball: {}\n"
        "  hash recorded in {}.md5         : {}\n"
        "The package and its .md5 disagree, so a real device would refuse this "
        "package.".format(actual, tar_file, expected))
    logger.info("Package md5 %s matches its .md5, by the hardware proxy algorithm", actual)

    # md5sum -c is not what production runs, but it is what a human will reach for
    # when reproducing a failure by hand, and it only works if the .md5 names the
    # tarball. Assert that separately so a .md5 naming some build-agent path is
    # reported as the packaging defect it is, rather than passing unnoticed.
    named = duthost.shell("cd {} && md5sum -c {}.md5".format(work_dir, tar_file),
                          module_ignore_errors=True)
    assert named['rc'] == 0, (
        "The package matches its .md5 by hash, but `md5sum -c` fails, which means "
        "the .md5 does not name {} as published. Contents:\n{}".format(
            tar_file,
            duthost.shell("cat {}/{}.md5".format(work_dir, tar_file))['stdout']))

    # 2. Unpack, and confirm the tarball carries what installer.py expects. A missing
    #    wheel would otherwise surface only as a confusing pip failure.
    require_package_integrity(duthost, work_dir + "/" + tar_file, work_dir + "/" + tar_file + ".md5", metadata)
    duthost.shell("tar -xf {} -C {}".format(
        shlex.quote(work_dir + "/" + tar_file), shlex.quote(cphc_install_dir)))
    work_dir = cphc_install_dir
    listing = duthost.shell("ls -1 {}".format(work_dir))['stdout']
    logger.info("Package contents:\n%s", listing)

    expected_wheel = _wheel_name(wheel_version, _expected_py_tag(duthost))
    for expected in (INSTALLER, expected_wheel):
        assert expected in listing, \
            "{} is missing from {}; package contained:\n{}".format(expected, tar_file, listing)

    # 3. Install through installer.py rather than pip directly, so the wheel selection
    #    for this OS version is exercised as well.
    duthost.shell("cd {} && python {} --install".format(work_dir, INSTALLER))

    # 4. The installer's own check must agree the package is now present.
    assert _validate_says_installed(duthost, work_dir), \
        "installer.py --validate does not report {} as installed after --install".format(
            PACKAGE_NAME)

    installed_version = _installed_version(duthost)
    assert installed_version == wheel_version, \
        "Expected CPHC {} to be installed, found {}".format(wheel_version, installed_version)

    # 5. A package that installs but cannot run is still broken, so exercise the entry
    #    point the upgrade flow uses. The checker reports on the DUT: assert that it ran
    #    and produced a well formed report, but only log its verdict, so an unhealthy DUT
    #    is not mistaken for a broken package.
    clock = duthost.shell("date -u +%Y-%m-%dT%H:%M:%SZ", module_ignore_errors=True)
    assert clock['rc'] == 0, "Cannot sample DUT UTC time: {}".format(clock)
    now = datetime.strptime(clock['stdout'].strip(), "%Y-%m-%dT%H:%M:%SZ")
    window = "{},{}".format(
        (now - timedelta(hours=1)).strftime("%m/%d/%Y %H:%M:%S"),
        now.strftime("%m/%d/%Y %H:%M:%S"))
    logger.info("Package smoke window (DUT UTC, not an actual upgrade interval): %s", window)

    report = "{}/process_checker-{}.json".format(
        CHECKER_OUTPUT_DIR, re.sub(r'[\\/:* ]', '_', re.sub(r',', '-', window)))
    with DutPathState(duthost) as state:
        state.directory(CHECKER_OUTPUT_DIR)
        state.preserve(report)
        result = duthost.shell('{} -m {}'.format(CALLER, shlex.quote(window)), module_ignore_errors=True)
        assert result['rc'] == 0, \
            "{} failed (rc={}):\n{}".format(CALLER, result['rc'], result['stderr'])
        try:
            summary = json.loads(result['stdout'])
        except ValueError:
            pytest.fail("{} did not print a JSON summary; got:\n{}".format(CALLER, result['stdout']))
        assert isinstance(summary, dict), "Checker summary must be an object: {!r}".format(summary)
        assert summary.get("succeeded") is True and summary.get("execution_error", "missing") in (None, []), (
            "Checker failed to execute: {!r}".format(summary))
        written = json.loads(duthost.shell("cat {}".format(shlex.quote(report)))['stdout'])
        assert written == summary, "Checker report does not match this invocation's stdout"
        logger.info("Checker execution succeeded; health findings: %s", json.dumps(summary, indent=2))

    # 6. Uninstall must genuinely remove the package. The fixture uninstalls too, but
    #    asserting it here is what proves the documented flow works.
    duthost.shell("cd {} && python {} --uninstall".format(work_dir, INSTALLER))
    assert _installed_version(duthost) is None, \
        "{} is still installed after installer.py --uninstall".format(PACKAGE_NAME)
    logger.info("CPHC package installed, exercised and removed successfully")


def test_cphc_package_rejects_corrupted_download(duthosts, rand_one_dut_hostname,
                                                 cphc_workspace, request):
    """A corrupted tarball must fail the check hardware proxy performs.

    That check is the only thing between a truncated or substituted download and an
    install, so confirm it actually rejects bad bytes rather than assuming it was
    wired up correctly.

    The corruption is checked with the production algorithm rather than
    ``md5sum -c``. Those are not equivalent: because production compares only the
    hash field, a .md5 that still names the original file would satisfy
    ``md5sum -c`` semantics in some cases while production still rejects it. Only
    the production algorithm proves the device is actually protected.
    """
    duthost = duthosts[rand_one_dut_hostname]
    work_dir = cphc_workspace
    tar_file = _tar_name(request.config.getoption("--cphc_tar_version"))
    corrupted_tar = "corrupted-{}".format(tar_file)

    # Overwrite the first 64 bytes in place, so the file keeps its length and only
    # its content changes - a truncation would also be caught by a size check,
    # which would not prove the hash comparison did the work.
    duthost.shell("cd {} && cp {} {}".format(work_dir, tar_file, corrupted_tar))
    duthost.shell("cd {} && dd if=/dev/zero of={} bs=1 count=64 conv=notrunc".format(
        work_dir, corrupted_tar))

    # Deliberately keep the *published* .md5, which is exactly the situation on a
    # device: the .md5 is genuine, the payload is not.
    matched, actual, expected = verify_md5_like_preload_firmware(
        duthost, "{}/{}".format(work_dir, corrupted_tar),
        "{}/{}.md5".format(work_dir, tar_file))
    assert not matched, (
        "A corrupted tarball passed the hardware proxy integrity check "
        "(hash {}); the check is not protecting anything".format(actual))
    logger.info("Corrupted package correctly rejected: got %s, expected %s", actual, expected)


# --- Running the real hardware proxy download path ------------------------------
#
# Everything above re-implements what hardware proxy does. That is useful, but a
# re-implementation can only ever test itself: if preload_firmware changes, or if
# our reading of it was wrong, these tests would keep passing. The tests below
# close that gap by invoking the *real* script. The postupgrade module drives the
# very same script for its own package - the filename is the only difference,
# because download_CPHC_without_md5sum() matches any *sonic-upgrade-package* - and
# then continues into the rest of the hardware proxy sequence.
#
# preload_firmware cannot be pointed at our publish path: download_util() derives
# the location from the host alone and always appends /networkfirmware/ACS/. So
# the package is re-served on the DUT under exactly that layout, and the genuine
# script is asked to fetch it. What is being tested is the script's download and
# verification of *the bytes we published*, which is precisely the step that
# decides whether a real device accepts this package.
#
# The package is served at both shipped layouts - with and without the
# "sonic-upgrade-packages/" subpath - because the proxy copy and the device copy
# of preload_firmware look in different places (see MIRROR_CPHC_SUBPATH). The
# mirror's access log then tells us which one this DUT actually ran, so the test
# reports the deployed variant instead of assuming it.

# Each test module serves on its own port, so two mirrors can never be mistaken
# for one another even if a teardown somewhere failed.
CPHC_MIRROR_PORT = 8910


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
def cphc_mirror(duthosts, rand_one_dut_hostname, cphc_workspace, request):
    """Serve the downloaded package on the DUT at hardware proxy's fixed path.

    Yields the mirror itself; its ``base_url`` is what preload_firmware is handed,
    and it also owns the scratch directory the script downloads into. Serving
    locally is what makes this runnable on any testbed: the real regional mirrors
    are not reachable from a lab, and the point here is to exercise the script,
    not the lab's routing.
    """
    duthost = duthosts[rand_one_dut_hostname]
    _preload_or_skip(duthost, request)
    tar_file = _tar_name(request.config.getoption("--cphc_tar_version"))

    mirror = PackageMirror(duthost, "cphc", CPHC_MIRROR_PORT)
    try:
        mirror.start(cphc_workspace, [tar_file], package_metadata={tar_file: publication_info(request, "cphc")})
    except MirrorUnavailable as exc:
        pytest.skip(str(exc))

    try:
        yield mirror
    finally:
        mirror.stop()


@pytest.mark.sonic_operations_integration
def test_cphc_package_downloads_via_real_preload_firmware(duthosts, rand_one_dut_hostname,
                                                          cphc_mirror, request):
    """The genuine preload_firmware must accept the published package.

    This is the closest thing to the production check that can be run in a lab:
    the real script, its real curl invocation, and its real hash comparison,
    against the exact bytes the pipeline published.
    """
    duthost = duthosts[rand_one_dut_hostname]
    preload = _preload_or_skip(duthost, request)

    tar_file = _tar_name(request.config.getoption("--cphc_tar_version"))
    logger.info("Running the real %s against %s", preload, cphc_mirror.base_url)
    result = cphc_mirror.run_preload_firmware(preload, tar_file)

    assert result['rc'] == 0, (
        "The real preload_firmware rejected the published CPHC package (rc={}).\n"
        "stdout:\n{}\nstderr:\n{}\n"
        "This is the check a device performs, so a failure here means the package "
        "as published would not be accepted in production.".format(
            result['rc'], result['stdout'], result['stderr']))

    assert PRELOAD_SUCCESS_MARKER in result['stdout'], (
        "preload_firmware exited 0 but never reported a validated download, so the "
        "hash comparison did not run. stdout:\n{}".format(result['stdout']))

    # The script is only useful if it left the package behind for the installer.
    duthost.shell("test -f {}/{}".format(cphc_mirror.scratch, tar_file))
    duthost.shell("test -f {}/{}.md5".format(cphc_mirror.scratch, tar_file))
    logger.info("The real preload_firmware downloaded and validated the published package; "
                "this DUT runs the %s", cphc_mirror.fetched_variant())


@pytest.mark.sonic_operations_integration
def test_real_preload_firmware_rejects_corrupted_package(duthosts, rand_one_dut_hostname,
                                                         cphc_mirror, request):
    """The genuine preload_firmware must refuse a package whose bytes changed.

    Proving the real script fails is what shows a device is protected. The
    positive test alone cannot: a script that never compared anything would also
    pass it.
    """
    duthost = duthosts[rand_one_dut_hostname]
    preload = _preload_or_skip(duthost, request)

    tar_file = _tar_name(request.config.getoption("--cphc_tar_version"))
    cphc_mirror.assert_rejects_corruption(preload, tar_file)
