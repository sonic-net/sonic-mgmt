"""
Shared helpers for BGP aggregate-address tests.

Provides:
  - AggregateCfg named tuple
  - GCU patch helpers (add / remove / update / batch / safe-remove)
  - DB and running-config query helpers
  - Consistency and cleanup validators
"""

import ast
import logging
from collections import namedtuple

import pytest

from tests.common.gcu_utils import (
    apply_gcu_patch,
    apply_patch,
    generate_tmpfile,
    delete_tmpfile,
    create_checkpoint,
    rollback_or_reload,
    delete_checkpoint,
)
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

# ---- Constants & helper structures ----
BGP_AGGREGATE_ADDRESS = "BGP_AGGREGATE_ADDRESS"
PLACEHOLDER_PREFIX = "192.0.2.0/32"  # RFC5737 TEST-NET-1

AggregateCfg = namedtuple(
    "AggregateCfg", ["prefix", "bbr_required", "summary_only", "as_set"]
)


# ---- DB & running-config helpers ----
def dump_db(duthost, dbname, tablename):
    """Return current DB content as dict."""
    keys_out = duthost.shell(
        "sonic-db-cli {} keys '{}*'".format(dbname, tablename),
        module_ignore_errors=True,
    )["stdout"]
    logger.info(
        "dump %s db, table %s, keys output: %s",
        dbname, tablename, keys_out,
    )
    keys = keys_out.strip().splitlines() if keys_out.strip() else []
    res = {}
    for k in keys:
        fields = duthost.shell(
            "sonic-db-cli {} hgetall '{}'".format(dbname, k),
            module_ignore_errors=True,
        )["stdout"]
        logger.info("all fields:%s for key: %s", fields, k)
        prefix = k.removeprefix("{}|".format(tablename))
        res[prefix] = ast.literal_eval(fields)
        logger.info("dump config db result: %s", res)
    return res


def running_bgp_has_aggregate(duthost, prefix):
    """Grep FRR running BGP config for aggregate-address lines."""
    return duthost.shell(
        "show runningconfiguration bgp"
        " | grep -i 'aggregate-address {}'".format(prefix),
        module_ignore_errors=True,
    )["stdout"]


# ---- GCU JSON patch helpers ----
def gcu_add_placeholder_aggregate(duthost, prefix):
    patch = [
        {
            "op": "add",
            "path": "/BGP_AGGREGATE_ADDRESS/{}".format(
                prefix.replace("/", "~1")
            ),
            "value": {"summary-only": "false", "as-set": "false"},
        }
    ]
    logger.info(
        "Adding placeholder BGP aggregate %s",
        prefix.replace("/", "~1"),
    )
    return apply_gcu_patch(duthost, patch)


@pytest.fixture(scope="module", autouse=True)
def setup_teardown(duthost):
    """Create checkpoint before tests, rollback after."""
    create_checkpoint(duthost)

    # add placeholder aggregate to avoid GCU removing empty table
    default_aggregates = dump_db(
        duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS
    )
    if not default_aggregates:
        gcu_add_placeholder_aggregate(duthost, PLACEHOLDER_PREFIX)

    yield

    try:
        rollback_or_reload(duthost, fail_on_rollback_error=False)
    finally:
        delete_checkpoint(duthost)


def gcu_add_aggregate(duthost, aggregate_cfg):
    logger.info("Add BGP_AGGREGATE_ADDRESS by GCU cmd")
    patch = [
        {
            "op": "add",
            "path": "/BGP_AGGREGATE_ADDRESS/{}".format(
                aggregate_cfg.prefix.replace("/", "~1")
            ),
            "value": {
                "bbr-required": (
                    "true" if aggregate_cfg.bbr_required else "false"
                ),
                "summary-only": (
                    "true" if aggregate_cfg.summary_only else "false"
                ),
                "as-set": (
                    "true" if aggregate_cfg.as_set else "false"
                ),
            },
        }
    ]
    apply_gcu_patch(duthost, patch)


def gcu_remove_aggregate(duthost, prefix):
    patch = [
        {
            "op": "remove",
            "path": "/BGP_AGGREGATE_ADDRESS/{}".format(
                prefix.replace("/", "~1")
            ),
        }
    ]
    apply_gcu_patch(duthost, patch)


def safe_remove_aggregate(duthost, prefix):
    """Best-effort removal for cleanup — never raises."""
    try:
        patch = [
            {
                "op": "remove",
                "path": "/BGP_AGGREGATE_ADDRESS/{}".format(
                    prefix.replace("/", "~1")
                ),
            }
        ]
        tmpfile = generate_tmpfile(duthost)
        try:
            apply_patch(duthost, json_data=patch, dest_file=tmpfile)
        finally:
            delete_tmpfile(duthost, tmpfile)
    except Exception:
        logger.debug(
            "Cleanup: aggregate %s already absent "
            "or will be recovered by rollback",
            prefix,
        )


def gcu_add_multiple_aggregates(duthost, cfgs):
    """Add several aggregate entries in a single GCU patch."""
    patch = [
        {
            "op": "add",
            "path": "/BGP_AGGREGATE_ADDRESS/{}".format(
                c.prefix.replace("/", "~1")
            ),
            "value": {
                "bbr-required": (
                    "true" if c.bbr_required else "false"
                ),
                "summary-only": (
                    "true" if c.summary_only else "false"
                ),
                "as-set": "true" if c.as_set else "false",
            },
        }
        for c in cfgs
    ]
    apply_gcu_patch(duthost, patch)


def gcu_remove_multiple_aggregates(duthost, prefixes):
    """Remove several aggregate entries in a single GCU patch."""
    patch = [
        {
            "op": "remove",
            "path": "/BGP_AGGREGATE_ADDRESS/{}".format(
                p.replace("/", "~1")
            ),
        }
        for p in prefixes
    ]
    apply_gcu_patch(duthost, patch)


def gcu_update_aggregate_field(duthost, prefix, field, value):
    """Update a single field of an existing aggregate via GCU."""
    patch = [
        {
            "op": "replace",
            "path": "/BGP_AGGREGATE_ADDRESS/{}/{}".format(
                prefix.replace("/", "~1"), field
            ),
            "value": value,
        }
    ]
    apply_gcu_patch(duthost, patch)


# ---- Common Validators ----
def verify_bgp_aggregate_consistence(duthost, bbr_enabled, cfg):
    """Validate CONFIG_DB, STATE_DB, and FRR running-config match."""
    config_db = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
    pytest_assert(
        cfg.prefix in config_db,
        "Aggregate row {} not found in CONFIG_DB".format(cfg.prefix),
    )
    pytest_assert(
        config_db[cfg.prefix].get("bbr-required")
        == ("true" if cfg.bbr_required else "false"),
        "bbr-required flag mismatch",
    )
    pytest_assert(
        config_db[cfg.prefix].get("summary-only")
        == ("true" if cfg.summary_only else "false"),
        "summary-only flag mismatch",
    )
    pytest_assert(
        config_db[cfg.prefix].get("as-set")
        == ("true" if cfg.as_set else "false"),
        "as-set flag mismatch",
    )

    state_db = dump_db(duthost, "STATE_DB", BGP_AGGREGATE_ADDRESS)
    pytest_assert(
        cfg.prefix in state_db,
        "Aggregate row {} not found in STATE_DB".format(cfg.prefix),
    )

    running_config = running_bgp_has_aggregate(duthost, cfg.prefix)

    if cfg.bbr_required and not bbr_enabled:
        pytest_assert(
            state_db[cfg.prefix].get("state") == "inactive",
            "state flag mismatch",
        )
        pytest_assert(
            cfg.prefix not in running_config,
            "aggregate-address {} should not present in FRR "
            "running-config when bbr is disabled".format(cfg.prefix),
        )
    else:
        pytest_assert(
            state_db[cfg.prefix].get("state") == "active",
            "state flag mismatch",
        )
        pytest_assert(
            cfg.prefix in running_config,
            "aggregate-address {} not present in FRR "
            "running-config".format(cfg.prefix),
        )
        if cfg.summary_only:
            pytest_assert(
                "summary-only" in running_config,
                "summary-only expected in running-config",
            )
        else:
            pytest_assert(
                "summary-only" not in running_config,
                "summary-only should NOT be present for this scenario",
            )
        if cfg.as_set:
            pytest_assert(
                "as-set" in running_config,
                "as_set expected in running-config",
            )
        else:
            pytest_assert(
                "as-set" not in running_config,
                "as_set should NOT be present for this scenario",
            )


def verify_bgp_aggregate_cleanup(duthost, prefix):
    """Validate aggregate is fully removed from DB and running-config."""
    config_db = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
    pytest_assert(
        prefix not in config_db,
        "Aggregate row {} should be clean up from CONFIG_DB".format(
            prefix
        ),
    )

    state_db = dump_db(duthost, "STATE_DB", BGP_AGGREGATE_ADDRESS)
    pytest_assert(
        prefix not in state_db,
        "Aggregate row {} should be clean up from STATE_DB".format(
            prefix
        ),
    )

    running_config = running_bgp_has_aggregate(duthost, prefix)
    pytest_assert(
        prefix.split("/")[0] not in running_config,
        "aggregate-address {} should not present in FRR "
        "running-config".format(prefix),
    )
