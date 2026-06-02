"""
Verify SAI versions on supported SONiC images.

Background
----------
Starting from SONiC build 20251110, different HwSKUs run different target
image types, each requiring specific BRCM SAI and OCP SAI versions:

  - "legacy-th"  : Arista 7060CX family keeps old BRCM SAI paired with the
                   latest OCP SAI header.

The test looks up the DUT's HwSKU in HWSKU_IMAGE_TYPE_MAP to determine which
image type (and therefore which expected versions) apply.  If the HwSKU is not
present in the map the test is skipped.

This test verifies:
  1. SONiC OS build version is at or after the cut-off (20251110).
  2. ASIC vendor is Broadcom.
  3. DUT HwSKU is present in HWSKU_IMAGE_TYPE_MAP; skip otherwise.
  4. Run `bcmcmd bsv` and parse BRCM SAI / OCP SAI / SDK versions.
  5. Compare parsed versions against the expected versions for the resolved
     image type.
"""
import logging
import re

import pytest

from tests.common.helpers.assertions import pytest_assert, pytest_require

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical'),
]

MIN_SONIC_BUILD_DATE = 20251110

# ---------------------------------------------------------------------------
# Image type definitions.
# Each entry maps an image-type name to the expected BRCM SAI and OCP SAI
# versions for that type.  Add new image types here as the support matrix
# evolves.
# ---------------------------------------------------------------------------
IMAGE_TYPE_VERSIONS = {
    # Arista 7060CX (Tomahawk) old BRCM SAI, latest OCP SAI header.
    "legacy-th": {
        "brcm_sai": "13.2.1.100",
        "ocp_sai":  "1.17.1",
    }
}

# ---------------------------------------------------------------------------
# HwSKU ΓåÆ image-type mapping.
# Only HwSKUs listed here are tested; any other HwSKU causes the test to skip.
# Add HwSKUs and their corresponding image type as the support matrix grows.
# ---------------------------------------------------------------------------
HWSKU_IMAGE_TYPE_MAP = {
    # --- legacy-th: Arista 7060CX (Tomahawk ASIC) ---------------------------
    "Arista-7060CX-32S-C32":  "legacy-th",
    "Arista-7060CX-32S-D48C8": "legacy-th",
    "Arista-7060CX-32S-Q32":  "legacy-th"
}

# `bcmcmd bsv` sample output:
#   BRCM SAI ver: [13.2.1.100], OCP SAI ver: [1.17.1], SDK ver: [sdk-6.5.32-SP2]
#   BRCM SAI cold boot ver:[13.2.1.100]
BSV_REGEX = re.compile(
    r"BRCM SAI ver:\s*\[(?P<brcm_sai>[^\]]+)\]\s*,\s*"
    r"OCP SAI ver:\s*\[(?P<ocp_sai>[^\]]+)\]\s*,\s*"
    r"SDK ver:\s*\[(?P<sdk>[^\]]+)\]"
)


RELEASE_VERSION_REGEX = re.compile(r"^(?:SONiC\.)?(20\d{6})\.\d+$")


def _parse_build_date(os_version):
    """Extract the YYYYMMDD build date from a SONiC release version string.

    Accepted release formats (as returned by `duthost.os_version` or shown
    in `show version`):
        "20251110.31"        -> 20251110
        "SONiC.20251110.31"  -> 20251110

    Anything else (master/internal/dev builds, empty input, etc.) returns
    None and emits a warning.
    """
    if not os_version:
        logger.warning("Empty SONiC version string; cannot parse build date")
        return None
    match = RELEASE_VERSION_REGEX.match(os_version.strip())
    if not match:
        logger.warning(
            "SONiC version '%s' is not a release version "
            "(expected 'YYYYMMDD.<build>' or 'SONiC.YYYYMMDD.<build>'); "
            "cannot parse build date",
            os_version,
        )
        return None
    return int(match.group(1))


def _parse_bsv_output(stdout):
    """Parse `bcmcmd bsv` output and return dict {brcm_sai, ocp_sai, sdk}."""
    for line in stdout.splitlines():
        match = BSV_REGEX.search(line)
        if match:
            return match.groupdict()
    return None


def _compare_sai_version(actual, expected):
    """Compare BRCM SAI versions of the form 'A.B.C.D'.

    Rule: the first three components (major.minor.patch) must match exactly;
    the last component (build) must be >= the expected build.

    Returns (ok: bool, reason: str). reason is "" when ok is True.
    """
    try:
        a_parts = [int(x) for x in actual.split(".")]
        e_parts = [int(x) for x in expected.split(".")]
    except (AttributeError, ValueError):
        return False, "unparseable version (actual='{}', expected='{}')".format(actual, expected)

    if len(a_parts) != 4 or len(e_parts) != 4:
        return False, "version must have 4 components (actual='{}', expected='{}')".format(
            actual, expected)

    if a_parts[:3] != e_parts[:3]:
        return False, "major.minor.patch differs: required '{}.x', got '{}'".format(
            ".".join(str(p) for p in e_parts[:3]), actual)

    if a_parts[3] < e_parts[3]:
        return False, "build component below minimum: required >= {}, got {}".format(
            e_parts[3], a_parts[3])

    return True, ""


def _compare_ocp_version(actual, expected):
    """Compare OCP SAI header versions (e.g. '1.17.1').

    Rule: actual must be >= expected, compared component-wise as integers.

    Returns (ok: bool, reason: str). reason is "" when ok is True.
    """
    try:
        a_parts = tuple(int(x) for x in actual.split("."))
        e_parts = tuple(int(x) for x in expected.split("."))
    except (AttributeError, ValueError):
        return False, "unparseable version (actual='{}', expected='{}')".format(actual, expected)

    if a_parts < e_parts:
        return False, "version below minimum: required >= '{}', got '{}'".format(expected, actual)

    return True, ""


def test_sai_ocp_version_per_hwsku(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Verify BRCM SAI / OCP SAI version matches the image-type-based matrix.

    Sequence:
      1. Read HwSKU from DUT facts.
      2. Look up HwSKU in HWSKU_IMAGE_TYPE_MAP; skip if not present.
      3. Resolve expected BRCM SAI and OCP SAI versions from IMAGE_TYPE_VERSIONS
         using the image type obtained in step 2.
      4. Read SONiC OS build version; skip when older than MIN_SONIC_BUILD_DATE.
      5. Skip when ASIC vendor is not Broadcom.
      6. Run `bcmcmd bsv` and parse BRCM SAI / OCP SAI / SDK versions.
      7. Assert parsed versions match the expected versions for the image type.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    # ---- Step 1: Get HwSKU -------------------------------------------------
    hwsku = duthost.facts.get("hwsku", "")
    logger.info("DUT %s HwSKU=%s", duthost.hostname, hwsku)

    # ---- Step 2: Resolve image type ----------------------------------------
    image_type = HWSKU_IMAGE_TYPE_MAP.get(hwsku)
    pytest_require(
        image_type is not None,
        "HwSKU '{}' is not in HWSKU_IMAGE_TYPE_MAP, skipping".format(hwsku),
    )
    logger.info("DUT %s HwSKU=%s resolved to image type '%s'",
                duthost.hostname, hwsku, image_type)

    # ---- Step 4: SONiC build version ---------------------------------------
    os_version = duthost.os_version
    build_date = _parse_build_date(os_version)
    logger.info("DUT %s SONiC version: %s (parsed build date: %s)",
                duthost.hostname, os_version, build_date)

    pytest_require(
        build_date is not None,
        "Cannot parse build date from SONiC version '{}', skipping".format(os_version),
    )
    pytest_require(
        build_date >= MIN_SONIC_BUILD_DATE,
        "SONiC build {} is older than cut-off {}, skipping".format(
            build_date, MIN_SONIC_BUILD_DATE),
    )

    # ---- Step 5: Vendor check ----------------------------------------------
    asic_type = duthost.facts.get("asic_type", "").lower()
    pytest_require(
        asic_type == "broadcom",
        "ASIC type '{}' is not broadcom, this test is broadcom-only".format(asic_type),
    )
    logger.info("DUT %s ASIC=%s", duthost.hostname, asic_type)

    # ---- Step 6: Read SAI / OCP / SDK versions from DUT -------------------
    result = duthost.shell("bcmcmd bsv", module_ignore_errors=True)
    pytest_assert(
        result.get("rc") == 0,
        "`bcmcmd bsv` failed (rc={}): {}".format(result.get("rc"), result.get("stderr")),
    )

    parsed = _parse_bsv_output(result.get("stdout", ""))
    pytest_assert(
        parsed is not None,
        "Could not parse `bcmcmd bsv` output:\n{}".format(result.get("stdout")),
    )

    brcm_sai = parsed["brcm_sai"]
    ocp_sai = parsed["ocp_sai"]
    sdk_ver = parsed["sdk"]
    logger.info("DUT %s BRCM SAI=%s OCP SAI=%s SDK=%s",
                duthost.hostname, brcm_sai, ocp_sai, sdk_ver)

    # ---- Step 3: Resolve required versions ---------------------------------
    required_versions = IMAGE_TYPE_VERSIONS[image_type]
    required_brcm_sai = required_versions["brcm_sai"]
    required_ocp_sai = required_versions["ocp_sai"]
    logger.info(
        "Required for image type '%s': BRCM SAI baseline=%s (same major.minor.patch, build >= %s), "
        "OCP SAI header minimum=%s",
        image_type, required_brcm_sai, required_brcm_sai.split(".")[-1], required_ocp_sai,
    )

    # ---- Step 7: Validate versions against the per-image-type baseline -----
    ok, reason = _compare_sai_version(brcm_sai, required_brcm_sai)
    pytest_assert(
        ok,
        "BRCM SAI version check failed on {} (HwSKU={}, image_type={}): "
        "required '{}' (same major.minor.patch, build >= {}), got '{}' -- {}".format(
            duthost.hostname, hwsku, image_type,
            required_brcm_sai, required_brcm_sai.split(".")[-1],
            brcm_sai, reason),
    )
    ok, reason = _compare_ocp_version(ocp_sai, required_ocp_sai)
    pytest_assert(
        ok,
        "OCP SAI header version check failed on {} (HwSKU={}, image_type={}): "
        "required >= '{}', got '{}' -- {}".format(
            duthost.hostname, hwsku, image_type,
            required_ocp_sai, ocp_sai, reason),
    )
