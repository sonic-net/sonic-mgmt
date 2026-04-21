# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import sys
from ansible_collections.ravendb.ravendb.plugins.module_utils.core import messages as msg


def _normalize_deployment_mode_value(value):
    if value is None:
        return None

    name = getattr(value, "name", None)
    s = str(name if name else value).strip().lower()
    if "rolling" in s:
        return "rolling"
    if "parallel" in s:
        return "parallel"
    return s


def _to_deployment_mode_enum(value):
    if value is None:
        return None
    from ravendb.documents.indexes.definitions import IndexDeploymentMode
    norm = _normalize_deployment_mode_value(value)
    if norm == "rolling":
        return IndexDeploymentMode.ROLLING
    if norm == "parallel":
        return IndexDeploymentMode.PARALLEL
    raise ValueError("Unknown deployment_mode: {}".format(value))


def create_dynamic_index(name, definition):
    """Dynamically create a single-map index class based on the given definition."""
    from ravendb import AbstractIndexCreationTask

    class DynamicIndex(AbstractIndexCreationTask):
        def __init__(self):
            super(DynamicIndex, self).__init__()
            self.map = definition.get("map")[0]
            reduce_def = definition.get("reduce")
            if reduce_def:
                self.reduce = reduce_def

            dm = definition.get("deployment_mode") or definition.get("DeploymentMode")
            if dm:
                self.deployment_mode = _to_deployment_mode_enum(dm)

    DynamicIndex.__name__ = name
    return DynamicIndex


def create_dynamic_multimap_index(name, definition):
    """Dynamically create a multi-map index class based on the given definition."""
    from ravendb.documents.indexes.abstract_index_creation_tasks import AbstractMultiMapIndexCreationTask

    class DynamicIndex(AbstractMultiMapIndexCreationTask):
        def __init__(self):
            super(DynamicIndex, self).__init__()
            maps_def = definition.get("map") or []
            for map_def in maps_def:
                self._add_map(map_def)

            reduce_def = definition.get("reduce")
            if reduce_def:
                self.reduce = reduce_def

            dm = definition.get("deployment_mode") or definition.get("DeploymentMode")
            if dm:
                self.deployment_mode = _to_deployment_mode_enum(dm)

    DynamicIndex.__name__ = name
    return DynamicIndex


def list_definitions(ctx, db_name):
    from ravendb.documents.operations.indexes import GetIndexesOperation
    return ctx.maintenance_for_db(db_name).send(GetIndexesOperation(0, sys.maxsize)) or []


def get_definition(ctx, db_name, index_name):
    defs = list_definitions(ctx, db_name)
    for d in defs:
        if getattr(d, "name", None) == index_name:
            return d
    return None


def index_matches(existing_index, definition):
    """Check if an existing index matches the expected definition (map/reduce)."""
    if definition is None:
        return True

    existing_maps = set(map(str.strip, existing_index.maps)) if getattr(existing_index, "maps", None) else set()
    existing_reduce = getattr(existing_index, "reduce", None)

    expected_maps = set(map(str.strip, definition.get("map", [])))
    normalized_existing_reduce = existing_reduce.strip() if isinstance(existing_reduce, str) and existing_reduce else None
    normalized_expected_reduce = (definition.get("reduce") or "").strip()
    if not normalized_expected_reduce:
        normalized_expected_reduce = None

    if not (existing_maps == expected_maps and normalized_existing_reduce == normalized_expected_reduce):
        return False

    desired_dm = _normalize_deployment_mode_value(definition.get("deployment_mode") or definition.get("DeploymentMode"))
    if desired_dm is None:
        return True

    existing_dm = _normalize_deployment_mode_value(getattr(existing_index, "deployment_mode", None))
    return desired_dm == existing_dm


def create_index(ctx, db_name, name, definition):
    """Create an index, handling both single-map and multi-map definitions."""
    if len(definition.get("map")) > 1:
        DynamicIndexClass = create_dynamic_multimap_index(name, definition)
    else:
        DynamicIndexClass = create_dynamic_index(name, definition)
    index = DynamicIndexClass()
    index.execute(ctx.store, db_name)


def delete_index(ctx, db_name, name):
    from ravendb.documents.operations.indexes import DeleteIndexOperation
    ctx.maintenance_for_db(db_name).send(DeleteIndexOperation(name))


def get_index_state(ctx, db_name, name):
    """Return the logical index state"""
    from ravendb.documents.operations.indexes import GetIndexStatisticsOperation
    stats = ctx.maintenance_for_db(db_name).send(GetIndexStatisticsOperation(name))
    return getattr(stats, "state", None)


def enable_index(ctx, db_name, name, cluster_wide, check_mode):
    """Enable a RavenDB index, optionally cluster-wide."""
    from ravendb.documents.indexes.definitions import IndexState
    from ravendb.documents.operations.indexes import EnableIndexOperation

    current = get_index_state(ctx, db_name, name)
    if current != IndexState.DISABLED:
        return False, msg.idx_already_enabled(name)

    if check_mode:
        return True, msg.idx_would_enable(name, cluster_wide)

    ctx.maintenance_for_db(db_name).send(EnableIndexOperation(name, cluster_wide))
    return True, msg.idx_enabled(name, cluster_wide=cluster_wide)


def disable_index(ctx, db_name, name, cluster_wide, check_mode):
    """Disable a RavenDB index, optionally cluster-wide."""
    from ravendb.documents.indexes.definitions import IndexState
    from ravendb.documents.operations.indexes import DisableIndexOperation

    current = get_index_state(ctx, db_name, name)
    if current == IndexState.DISABLED:
        return False, msg.idx_already_disabled(name)

    if check_mode:
        return True, msg.idx_would_disable(name, cluster_wide)

    ctx.maintenance_for_db(db_name).send(DisableIndexOperation(name, cluster_wide))
    return True, msg.idx_disabled(name, cluster_wide=cluster_wide)


def resume_index(ctx, db_name, name, check_mode):
    """Resume a paused RavenDB index."""
    from ravendb.documents.operations.indexes import GetIndexingStatusOperation, StartIndexOperation
    from ravendb.documents.indexes.definitions import IndexRunningStatus

    status = ctx.maintenance_for_db(db_name).send(GetIndexingStatusOperation())
    index = next((x for x in getattr(status, "indexes", []) if x.name == name), None)
    if index and index.status == IndexRunningStatus.RUNNING:
        return False, msg.idx_already_resumed(name)

    if check_mode:
        return True, msg.idx_would_resume(name)

    ctx.maintenance_for_db(db_name).send(StartIndexOperation(name))
    return True, msg.idx_resumed(name)


def pause_index(ctx, db_name, name, check_mode):
    """Pause a running RavenDB index."""
    from ravendb.documents.operations.indexes import GetIndexingStatusOperation, StopIndexOperation
    from ravendb.documents.indexes.definitions import IndexRunningStatus

    status = ctx.maintenance_for_db(db_name).send(GetIndexingStatusOperation())
    index = next((x for x in getattr(status, "indexes", []) if x.name == name), None)
    if index and index.status == IndexRunningStatus.PAUSED:
        return False, msg.idx_already_paused(name)

    if check_mode:
        return True, msg.idx_would_pause(name)

    ctx.maintenance_for_db(db_name).send(StopIndexOperation(name))
    return True, msg.idx_paused(name)


def reset_index(ctx, db_name, name, check_mode):
    """Reset an existing index."""
    from ravendb.documents.operations.indexes import ResetIndexOperation

    if check_mode:
        return True, msg.idx_would_reset(name)

    ctx.maintenance_for_db(db_name).send(ResetIndexOperation(name))
    return True, msg.idx_reset(name)


def apply_mode(ctx, db_name, name, mode, cluster_wide, check_mode):
    """Dispatch mode operation."""
    if mode == "enabled":
        return enable_index(ctx, db_name, name, cluster_wide, check_mode)
    if mode == "disabled":
        return disable_index(ctx, db_name, name, cluster_wide, check_mode)
    if mode == "resumed":
        return resume_index(ctx, db_name, name, check_mode)
    if mode == "paused":
        return pause_index(ctx, db_name, name, check_mode)
    if mode == "reset":
        return reset_index(ctx, db_name, name, check_mode)
    return False, "Unsupported mode '{}' specified.".format(mode)
