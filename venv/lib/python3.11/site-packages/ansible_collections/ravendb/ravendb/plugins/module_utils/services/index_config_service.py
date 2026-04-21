# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.ravendb.ravendb.plugins.module_utils.core.configuration import (
    validate_kv, diff_kv, normalize_str_values
)
from ansible_collections.ravendb.ravendb.plugins.module_utils.services.index_service import (
    get_definition,
    _normalize_deployment_mode_value, _to_deployment_mode_enum
)


def validate_index_configuration(d):
    """Validate and normalize per-index configuration."""
    return validate_kv(d, "index_configuration", allow_none=True)


def get_current(ctx, db_name, index_name):
    """Return per-index configuration as a normalized dict."""
    definition = get_definition(ctx, db_name, index_name)
    if not definition:
        return {}
    cfg = getattr(definition, "configuration", None) or {}
    return normalize_str_values(cfg)


def diff(desired, current):
    """Compute config differences."""
    return diff_kv(desired, current)


def _build_index_definition(name, maps, reduce=None, configuration=None, deployment_mode=None):
    """Build a minimal IndexDefinition (name, maps, reduce, configuration)."""
    from ravendb.documents.indexes.definitions import IndexDefinition
    idx = IndexDefinition()
    idx.name = name
    if maps:
        if isinstance(maps, set):
            idx.maps = maps
        elif isinstance(maps, (list, tuple)):
            idx.maps = set(maps)
        else:
            raise TypeError("maps must be a list/tuple/set of strings")
    if reduce:
        idx.reduce = reduce
    cfg = normalize_str_values(configuration or {})
    if cfg:
        idx.configuration = cfg
    if deployment_mode:
        idx.deployment_mode = _to_deployment_mode_enum(deployment_mode)

    return idx


def _put_index_definition(ctx, db_name, index_definition):
    """PUT a single definition using PutIndexesOperation, handling older signatures."""
    from ravendb.documents.operations.indexes import PutIndexesOperation
    m = ctx.maintenance_for_db(db_name)
    try:
        op = PutIndexesOperation(index_definition)
        return m.send(op)
    except TypeError:
        op = PutIndexesOperation([index_definition])
        return m.send(op)


def apply(ctx, db_name, index_name, to_apply):
    """Merge and apply configuration changes to an index."""
    definition = get_definition(ctx, db_name, index_name)
    if not definition:
        raise RuntimeError("Index definition '{}' not found while applying configuration.".format(index_name))

    current_cfg = normalize_str_values(getattr(definition, "configuration", None) or {})
    merged_cfg = dict(current_cfg)
    merged_cfg.update(to_apply)

    maps = list(definition.maps) if getattr(definition, "maps", None) else []
    reduce = getattr(definition, "reduce", None)
    existing_dm = _normalize_deployment_mode_value(getattr(definition, "deployment_mode", None))

    new_def = _build_index_definition(index_name, maps, reduce, merged_cfg, deployment_mode=existing_dm)
    _put_index_definition(ctx, db_name, new_def)
