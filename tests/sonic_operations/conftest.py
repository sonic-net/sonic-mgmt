import json
from pathlib import Path

import pytest


INTEGRATION_MARKER = "sonic_operations_integration"
PACKAGE_ROOT = Path(__file__).resolve().parent


def pytest_addoption(parser):
    """Paths-only latest package validation, with compatibility for saved source options."""
    group = parser.getgroup("sonic-operations packages")
    group.addoption(
        "--sonic_operations_integration",
        action="store_true",
        default=False,
        help="Include 7 optional production-consumer cases in addition to the default 19 package cases. "
             "Requires real preload/wrapper scripts; cached-wrapper recovery remains an explicit coverage-gap skip.")

    # Shared image server location -------------------------------------------------

    # Source options are retained for cloned manual plans, not used for selection.
    group.addoption(
        "--image_server_url",
        action="store",
        default="https://sonic.packages.trafficmanager.net/azmirrors",
        help="Legacy source option; ignored with a warning for the code-owned latest package route.")

    # Never forward a legacy Blob credential to the anonymous pinned frontend.
    group.addoption(
        "--package_sas_token",
        action="store",
        default=None,
        help="Legacy credential option; ignored without logging its value for anonymous latest URLs.")

    # Hardware proxy and the postupgrade wrapper do not read the CI publish
    # path. Both build their URL as
    # http://<server>/networkfirmware/ACS/sonic-upgrade-packages/<file>, so the
    # two packages are siblings in one directory. The local preload mirrors still
    # serve this layout; this legacy option cannot change initial artifact sourcing.
    group.addoption(
        "--use_mirror_layout",
        action="store_true",
        default=False,
        help="Legacy source-layout option; ignored for latest URLs. Local preload mirrors remain enabled.")

    # This is not MGMT_BRANCH, which still selects the testcase checkout.
    group.addoption(
        "--sonic_ops_branch",
        action="store",
        default="main",
        help="Legacy package source branch; ignored for the shared latest package route.")

    # CPHC package -----------------------------------------------------------------

    group.addoption(
        "--cphc_package_url",
        action="store",
        default=None,
        help="Legacy CPHC URL; ignored for the shared latest package route.")

    group.addoption(
        "--cphc_package_path",
        action="store",
        default=None,
        help="Legacy CPHC path; ignored for the shared latest package route.")

    # HWP fixes the tar name, but each release's wheel version comes from buildinfo.
    group.addoption(
        "--cphc_tar_version",
        action="store",
        default="1.0.0",
        help="Must be 1.0.0 for the HWP archive filename contract.")

    group.addoption(
        "--cphc_wheel_version",
        action="store",
        default=None,
        help="Optional expected wheel version; must match latest buildinfo and verified archive. "
             "Auto-detected otherwise.")

    # The hardware proxy download script. It is deployed to devices from
    # sonic-metadata (scripts/preload_firmware) and is what actually fetches and
    # verifies a CPHC package in production, so the test prefers whichever copy is
    # already on the device over any reimplementation of it.
    group.addoption(
        "--preload_firmware",
        action="store",
        default=None,
        help="Path to the preload_firmware script on the DUT. Defaults to searching "
             "the usual install locations.")

    group.addoption(
        "--preload_firmware_src",
        action="store",
        default=None,
        help="Local path to a copy of the sonic-metadata preload_firmware script, "
             "copied to the DUT when it does not already have one.")

    # postupgrade_actions package --------------------------------------------------

    group.addoption(
        "--sup_package_url",
        action="store",
        default=None,
        help="Legacy postupgrade URL; ignored for the shared latest package route.")

    group.addoption(
        "--sup_package_path",
        action="store",
        default=None,
        help="Legacy postupgrade path; ignored for the shared latest package route.")

    # The wrapper is deployed to devices from Networking-Metadata
    # (src/data/Network/SONiC/scripts/postupgrade_actions) and is what hardware proxy
    # invokes, so the test prefers whichever copy is already on the device.
    group.addoption(
        "--postupgrade_wrapper",
        action="store",
        default=None,
        help="Path to the postupgrade_actions wrapper on the DUT. Defaults to searching "
             "the usual install locations.")

    group.addoption(
        "--postupgrade_wrapper_src",
        action="store",
        default=None,
        help="Local path to a copy of the Networking-Metadata postupgrade_actions "
             "wrapper, copied to the DUT when it does not already have one.")

    group.addoption(
        "--postupgrade_skip_execute",
        action="store_true",
        default=False,
        help="Skip direct package execution before staging, and prevent optional real-wrapper execution. "
             "The real script applies patches, rewrites config and "
             "restarts services, and has no dry-run mode.")


def pytest_collection_modifyitems(config, items):
    """Deselect only this suite's integration cases, before any fixture setup."""
    if config.getoption("--sonic_operations_integration"):
        return
    deselected = [
        item for item in items
        if PACKAGE_ROOT in Path(str(item.fspath)).resolve().parents
        and item.get_closest_marker(INTEGRATION_MARKER) is not None
    ]
    if deselected:
        items[:] = [item for item in items if item not in deselected]
        config.hook.pytest_deselected(items=deselected)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Keep the selected build identities in test results, including setup failures."""
    outcome = yield
    if PACKAGE_ROOT in Path(str(item.fspath)).resolve().parents:
        report = outcome.get_result()
        for package, metadata in sorted(getattr(item.config, "_sonic_operations_publications", {}).items()):
            report.user_properties.append(
                ("sonic_operations.{}.publication".format(package), json.dumps(metadata, sort_keys=True)))
