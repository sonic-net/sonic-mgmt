"""TEMPORARY shim: delete once sonic-buildimage#27192 (PROTOCOL_ROUTE_MAP, set_src) and #28543 (the rest)
are both in the images under test.

Strips GATED_NAMES an image has no YANG model for (one unmodeled leaf fails GCU's whole-config validation).
Support is probed per name from the DUT's YANG models, so it self-clears.
To delete: ``git rm`` this file and remove the ``strip_unsupported_by_image`` import and call in
``frr_config_mode_migrator.py``.
"""
import logging

logger = logging.getLogger(__name__)

YANG_MODELS_DIR = "/usr/local/yang-models"

# CONFIG_DB tables/leaves added by #27192 or #28543; stripped unless the DUT's YANG models mention them.
GATED_NAMES = (
    "PROTOCOL_ROUTE_MAP",            # #27192 table
    "ebgp_requires_policy",          # #28543 BGP_GLOBALS
    "set_on_match_action",           # #28543 ROUTE_MAP
    "set_on_match_goto",             # #28543 ROUTE_MAP
    "nexthop_group_keep_time",       # #28543 DEVICE_METADATA
    "set_src",                       # #27192 ROUTE_MAP
)


# Global FRR lines that legitimately vanish across a switch when their gated field is stripped.
# nexthop_group_keep_time stands in for #28543 on lines frrcfgd only renders with that PR.
GATED_GLOBAL_LINES = {
    "bgp ebgp-requires-policy": "ebgp_requires_policy",
    "no bgp ebgp-requires-policy": "ebgp_requires_policy",
    "zebra nexthop-group keep 1": "nexthop_group_keep_time",
    "zebra nexthop kernel enable": "nexthop_group_keep_time",
    "no zebra nexthop kernel enable": "nexthop_group_keep_time",
    "bgp suppress-fib-pending": "nexthop_group_keep_time",
}


# Route-map clauses (FRR line prefixes) whose CONFIG_DB field is gated (see GATED_NAMES).
GATED_ROUTE_MAP_CLAUSES = {
    "on-match ": "set_on_match_action",
    "set src ": "set_src",
}


def gated_route_map_clauses_missing_from_image(duthost):
    """Route-map clause prefixes this image cannot carry across a switch (see above)."""
    supported = _supported_names(duthost)
    return tuple(prefix for prefix, field in GATED_ROUTE_MAP_CLAUSES.items()
                 if field not in supported)


def gated_globals_missing_from_image(duthost):
    """Global running-config lines this image cannot carry across a switch (empty once it has #28543)."""
    supported = _supported_names(duthost)
    return {line for line, field in GATED_GLOBAL_LINES.items() if field not in supported}


def _supported_names(duthost):
    """Return the GATED_NAMES this image's YANG models mention (empty set on probe failure)."""
    out = duthost.shell(
        "grep -rhowE '{}' {} | sort -u".format("|".join(GATED_NAMES), YANG_MODELS_DIR),
        module_ignore_errors=True)
    if out["rc"] not in (0, 1):    # grep exits 1 for "no matches", which is a real answer
        logger.warning("Could not read %s on %s (%s); assuming no sonic-buildimage#27192/#28543 support",
                       YANG_MODELS_DIR, duthost.hostname, out.get("stderr", "").strip())
        return set()
    return {ln.strip() for ln in out["stdout"].splitlines() if ln.strip()} & set(GATED_NAMES)


def strip_unsupported_by_image(duthost, config):
    """Remove (in place) and return ``config`` minus every GATED_NAMES table/field the image lacks."""
    unsupported = set(GATED_NAMES) - _supported_names(duthost)
    if not unsupported:
        logger.info("Image on %s models all sonic-buildimage#27192/#28543 CONFIG_DB names; "
                    "frr_parity_compat is a no-op and this file can be deleted",
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
                    "sonic-buildimage#27192/#28543): %s. Keeping them would fail whole-config YANG "
                    "validation for every GCU operation on this DUT.", sorted(stripped))
    return config
