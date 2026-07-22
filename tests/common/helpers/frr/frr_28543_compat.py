"""TEMPORARY compatibility shim -- DELETE THIS ENTIRE FILE when sonic-buildimage#28543
("[frrcfgd] BGP feature parity with bgpcfgd") is in the images under test.

Removal is intentionally two steps, both trivial:

  1. ``git rm tests/common/helpers/frr/frr_28543_compat.py``
  2. in ``frr_config_mode_migrator.py``, delete the ``strip_unsupported_by_image`` import
     and the single call to it in ``to_frr_mgmt_framework()``

Nothing else references this module. In particular ``bgp_config_translation.py`` is
deliberately untouched: it keeps emitting the full, correct frrcfgd config (and its unit
tests keep asserting that), and this shim removes what the *image* cannot yet accept.
When the shim goes away the translator's real output simply reaches the DUT.

Why it is needed
----------------
sonic-buildimage#28543 adds both the frrcfgd handlers and the sonic-yang models for a
handful of CONFIG_DB names (see ``GATED_NAMES``). Writing one of those into CONFIG_DB on
an image that predates it is not merely inert: GCU's ``apply-patch`` runs YANG validation
over the *whole* CONFIG_DB, so a single unmodeled leaf in an otherwise-modeled table makes
**every** GCU operation on that DUT fail::

    sonic_yang(6):Note: Below table(s) have no YANG models: PROTOCOL_ROUTE_MAP
    exceptionList:["'ebgp_requires_policy'"]

-- not just a patch that touches BGP. That is what broke the frr_mgmt_framework variant of
every GCU-based BGP test (test_bgp_bbr, test_bgp_max_route, test_bgp_dual_asn, ...).

The tests that actually depend on these names are already skipped in frr mode via
``conditional_mark`` on sonic-buildimage#28482, so stripping them costs no coverage today.

Self-clearing
-------------
Support is probed from the DUT's own YANG models rather than hardcoded, so an image that
already carries #28543 keeps the full config with no code change -- this file becomes a
no-op before anyone gets around to deleting it.
"""
import logging

logger = logging.getLogger(__name__)

YANG_MODELS_DIR = "/usr/local/yang-models"

# CONFIG_DB names added by sonic-buildimage#28543 -- table names and leaf names alike.
# A name is stripped unless the DUT's YANG models mention it.
GATED_NAMES = (
    "PROTOCOL_ROUTE_MAP",            # table: zebra 'ip[v6] protocol <proto> route-map <rm>'
    "ebgp_requires_policy",          # BGP_GLOBALS: 'no bgp ebgp-requires-policy'
    "set_on_match_action",           # ROUTE_MAP: 'on-match next' / 'on-match goto <seq>'
    "set_on_match_goto",
    "set_src",                       # ROUTE_MAP: zebra 'set src <addr>'
    "set_extcommunity_bandwidth_type",   # ROUTE_MAP: 'set extcommunity bandwidth num-multipaths'
)


def _supported_names(duthost):
    """Return the subset of GATED_NAMES this image's sonic-yang models know about.

    SONiC YANG leaf names match their CONFIG_DB field names, so a plain word-match over
    the model files answers "will sonic_yang reject this?" without parsing YANG. On any
    probe failure return the empty set -- i.e. strip everything, which is the correct
    (pre-#28543) behavior for an image we cannot interrogate.
    """
    out = duthost.shell(
        "grep -rhowE '{}' {} | sort -u".format("|".join(GATED_NAMES), YANG_MODELS_DIR),
        module_ignore_errors=True)
    if out["rc"] not in (0, 1):    # grep exits 1 for "no matches", which is a real answer
        logger.warning("Could not read %s on %s (%s); assuming no sonic-buildimage#28543 support",
                       YANG_MODELS_DIR, duthost.hostname, out.get("stderr", "").strip())
        return set()
    return {ln.strip() for ln in out["stdout"].splitlines() if ln.strip()} & set(GATED_NAMES)


def strip_unsupported_by_image(duthost, config):
    """Remove every GATED_NAMES table/field this image has no YANG model for.

    Mutates and returns ``config`` (a translated CONFIG_DB dict). A no-op on an image
    that already carries sonic-buildimage#28543.
    """
    unsupported = set(GATED_NAMES) - _supported_names(duthost)
    if not unsupported:
        logger.info("Image on %s models all sonic-buildimage#28543 CONFIG_DB names; "
                    "frr_28543_compat is a no-op and this file can be deleted",
                    duthost.hostname)
        return config

    stripped = []
    for table in list(config):
        if table in unsupported:
            del config[table]
            stripped.append(table)
            continue
        rows = config[table]
        if not isinstance(rows, dict):
            continue
        for key, row in rows.items():
            if not isinstance(row, dict):
                continue
            for field in unsupported & set(row):
                del row[field]
                stripped.append("{}|{}.{}".format(table, key, field))
    if stripped:
        logger.info("Stripped CONFIG_DB names this image has no YANG model for (needs "
                    "sonic-buildimage#28543): %s. Keeping them would fail whole-config YANG "
                    "validation for every GCU operation on this DUT.", sorted(stripped))
    return config
