# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
from ansible_collections.ravendb.ravendb.plugins.module_utils.core.result import ModuleResult
from ansible_collections.ravendb.ravendb.plugins.module_utils.core import messages as msg
from ansible_collections.ravendb.ravendb.plugins.module_utils.core import files as file
from ansible_collections.ravendb.ravendb.plugins.module_utils.services import database_service as dbs
from ansible_collections.ravendb.ravendb.plugins.module_utils.services import db_settings_service as setsvc
from ansible_collections.ravendb.ravendb.plugins.module_utils.services import encryption_service as encsvc
from ansible_collections.ravendb.ravendb.plugins.module_utils.services.cluster_service import fetch_topology, collect_tags


class DatabaseReconciler:
    def __init__(self, ctx):
        self.ctx = ctx

    def ensure_present(self, spec, tls, check_mode):
        """
        Ensure the specified database exists.
        Returns: ModuleResult: contains `changed` (bool) and `msg` (str).
        """
        existing_databases = dbs.list_databases(self.ctx)
        created = False

        if spec.name not in existing_databases:
            if spec.replication_factor is None:
                return ModuleResult.error(msg=msg.rf_required_on_create())

            if spec.members:
                wanted = list(dict.fromkeys(spec.members))
                if len(wanted) != spec.replication_factor:
                    return ModuleResult.error(
                        msg="topology_members length ({}) must equal replication_factor ({}).".format(
                            len(wanted), spec.replication_factor
                        )
                    )
                try:
                    cluster_tags = set(collect_tags(fetch_topology(self.ctx)))
                except Exception as e:
                    return ModuleResult.error(msg="Failed to fetch cluster topology: {}".format(str(e)))

                missing = [t for t in wanted if t not in cluster_tags]
                if missing:
                    return ModuleResult.error(msg="Unknown node tags in topology_members: {}".format(", ".join(missing)))

                spec.members = wanted

            if spec.encryption.enabled:
                if check_mode:
                    return ModuleResult.ok(msg=msg.db_would_create(spec.name, encrypted=True), changed=True)

                if spec.encryption.generate_key:
                    key = encsvc.fetch_generated_key(self.ctx, tls)
                    if spec.encryption.output_path:
                        file.write_key_safe(spec.encryption.output_path, key)
                else:
                    key = file.read_key(spec.encryption.key_path)
                encsvc.distribute_key(self.ctx, spec.name, key, tls, only_tags=(spec.members or None))

            if check_mode:
                return ModuleResult.ok(msg=msg.db_would_create(spec.name), changed=True)

            dbs.create_database(self.ctx, spec.name, spec.replication_factor, spec.encryption.enabled, members=(spec.members or None), tls=tls)
            created = True
            base_msg = msg.db_created(spec.name, encrypted=spec.encryption.enabled)

        else:
            record = dbs.get_record(self.ctx, spec.name)
            actual_flag = bool(getattr(record, "encrypted", False))
            if spec.encryption.enabled != actual_flag:
                # toggling between encrypted db and regular db is forbidden
                return ModuleResult.error(msg=msg.encryption_mismatch(spec.name, actual_flag, spec.encryption.enabled))
            base_msg = msg.db_exists(spec.name)

            if spec.members:
                return ModuleResult.error(
                    msg=(
                        "topology_members is only supported on database creation; "
                        "modifying an existing database topology is not supported."
                    )
                )

        if spec.settings:
            current = setsvc.get_current(self.ctx, spec.name)
            to_apply = setsvc.diff(spec.settings, current)
            if to_apply:
                if check_mode:
                    return ModuleResult.ok(msg=msg.settings_would_apply(base_msg, list(to_apply.keys())), changed=True)
                setsvc.apply(self.ctx, spec.name, to_apply)
                return ModuleResult.ok(msg=msg.settings_applied(base_msg, list(to_apply.keys())), changed=True)

        if created:
            return ModuleResult.ok(msg=base_msg, changed=True)
        return ModuleResult.ok(msg=msg.db_no_changes(base_msg), changed=False)

    def ensure_absent(self, name, check_mode):
        """
        Ensure the specified database is absent.
        Returns: ModuleResult: contains `changed` (bool) and `msg` (str).
        """
        existing = dbs.list_databases(self.ctx)
        if name not in existing:
            return ModuleResult.ok(msg=msg.db_not_exists(name), changed=False)

        if check_mode:
            return ModuleResult.ok(msg=msg.db_would_delete(name), changed=True)

        dbs.delete_database(self.ctx, name)
        return ModuleResult.ok(msg=msg.db_deleted(name), changed=True)
