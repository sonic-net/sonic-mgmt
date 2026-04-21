# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.ravendb.ravendb.plugins.module_utils.core.result import ModuleResult
from ansible_collections.ravendb.ravendb.plugins.module_utils.core import messages as msg
from ansible_collections.ravendb.ravendb.plugins.module_utils.dto.index import IndexDefinitionSpec
from ansible_collections.ravendb.ravendb.plugins.module_utils.services import index_service as idxsvc
from ansible_collections.ravendb.ravendb.plugins.module_utils.services import index_config_service as cfgsvc


class IndexReconciler(object):
    def __init__(self, ctx, db_name):
        self.ctx = ctx
        self.db_name = db_name

    def _apply_index(self, name, raw_def, check_mode):
        """Create or update an index with the given raw definition."""
        if check_mode:
            return ModuleResult.ok(msg=msg.idx_would_create(name), changed=True)

        idxsvc.create_index(self.ctx, self.db_name, name, raw_def)
        return ModuleResult.ok(msg=msg.idx_created(name), changed=True)

    def ensure_absent(self, name, check_mode):
        """Delete the index if it exists."""
        existing_defs = idxsvc.list_definitions(self.ctx, self.db_name)
        existing_names = [getattr(i, "name", None) for i in existing_defs]

        if name not in existing_names:
            return ModuleResult.ok(msg=msg.idx_already_absent(name), changed=False)

        if check_mode:
            return ModuleResult.ok(msg=msg.idx_would_delete(name), changed=True)

        idxsvc.delete_index(self.ctx, self.db_name, name)
        return ModuleResult.ok(msg=msg.idx_deleted(name), changed=True)

    def ensure_present(self, spec, check_mode):
        """
        Create or update the index definition, optionally apply mode and per-index configuration.
        """
        existing_defs = idxsvc.list_definitions(self.ctx, self.db_name)
        existing_names = [getattr(i, "name", None) for i in existing_defs]
        base_msg = None
        changed_any = False

        if isinstance(spec.definition, IndexDefinitionSpec):
            raw_def = spec.definition.to_dict()
        else:
            raw_def = None

        if spec.name not in existing_names:
            if raw_def is None:
                return ModuleResult.error("index_definition is required when creating a new index.")

            result = self._apply_index(spec.name, raw_def, check_mode)
            base_msg, changed_any = result.msg, True

        else:
            existing_def = idxsvc.get_definition(self.ctx, self.db_name, spec.name)
            if raw_def and not idxsvc.index_matches(existing_def, raw_def):
                result = self._apply_index(spec.name, raw_def, check_mode)
                base_msg, changed_any = result.msg, True
            else:
                base_msg = msg.idx_exists(spec.name)

        if spec.mode:
            mode_changed, mode_msg = idxsvc.apply_mode(self.ctx, self.db_name, spec.name, spec.mode, spec.cluster_wide, check_mode)
            if mode_changed:
                changed_any = True
                if base_msg:
                    base_msg = "{} {}".format(base_msg, mode_msg).strip()
                else:
                    base_msg = mode_msg
            else:
                base_msg = mode_msg or base_msg

        if spec.configuration:
            current = cfgsvc.get_current(self.ctx, self.db_name, spec.name)
            to_apply = cfgsvc.diff(spec.configuration, current)
            if to_apply:
                keys_str = ", ".join(sorted(to_apply.keys()))
                if check_mode:
                    return ModuleResult.ok(msg="{} {}".format(base_msg, msg.idx_cfg_would_apply(spec.name, keys_str)), changed=True)

                cfgsvc.apply(self.ctx, self.db_name, spec.name, to_apply)
                return ModuleResult.ok(msg="{} {}".format(base_msg, msg.idx_cfg_applied(spec.name, keys_str)), changed=True)

        return ModuleResult.ok(msg=base_msg, changed=changed_any)
