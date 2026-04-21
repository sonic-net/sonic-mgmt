# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


def _enc_suffix(encrypted):
    return " (encrypted)" if encrypted else ""


def db_exists(n):
    return "Database '{}' already exists.".format(n)


def db_not_exists(n):
    return "Database '{}' does not exist.".format(n)


def db_created(n, encrypted=False):
    return "Database '{}' created successfully{}.".format(n, _enc_suffix(encrypted))


def db_would_create(n, encrypted=False):
    return "Database '{}' would be created{}.".format(n, _enc_suffix(encrypted))


def db_deleted(n):
    return "Database '{}' deleted successfully.".format(n)


def db_would_delete(n):
    return "Database '{}' would be deleted.".format(n)


def db_no_changes(base):
    return "{} No changes.".format(base)


def rf_required_on_create():
    return "replication_factor is required when creating a database."


def settings_applied(prefix, keys):
    ks = ", ".join(sorted(keys)) if not isinstance(keys, str) else keys
    return "{} Applied settings ({}) and reloaded.".format(prefix, ks)


def settings_would_apply(prefix, keys):
    ks = ", ".join(sorted(keys)) if not isinstance(keys, str) else keys
    return "{} Would apply settings ({}) and reload.".format(prefix, ks)


def would_assign_encryption_key(db):
    return "Would assign encryption key for database '{}'.".format(db)


def assigned_encryption_key(db):
    return "Assigned encryption key for database '{}'.".format(db)


def encryption_mismatch(name, actual, desired):
    return (
        "Database '{}' already exists but encryption status is '{}' while requested '{}'. "
        "RavenDB does not support toggling encryption on an existing database. "
        "Delete & recreate, or backup and restore with the desired key."
    ).format(name, actual, desired)


def _cluster_suffix(cluster_wide):
    return " cluster-wide" if cluster_wide else ""


def idx_cfg_applied(index_name, keys_str):
    return "Applied configuration for index '{}' (keys: {}).".format(index_name, keys_str)


def idx_cfg_would_apply(index_name, keys_str):
    return "Would apply configuration for index '{}' (keys: {}).".format(index_name, keys_str)


def idx_would_enable(name, cluster_wide=False):
    return "Index '{}' would be enabled{}.".format(name, _cluster_suffix(cluster_wide))


def idx_would_disable(name, cluster_wide=False):
    return "Index '{}' would be disabled{}.".format(name, _cluster_suffix(cluster_wide))


def idx_created(name):
    return "Index '{}' created successfully.".format(name)


def idx_would_create(name):
    return "Index '{}' would be created.".format(name)


def idx_deleted(name):
    return "Index '{}' deleted successfully.".format(name)


def idx_would_delete(name):
    return "Index '{}' would be deleted.".format(name)


def idx_enabled(name, cluster_wide=False):
    return "Index '{}' enabled successfully{}.".format(name, _cluster_suffix(cluster_wide))


def idx_disabled(name, cluster_wide=False):
    return "Index '{}' disabled successfully{}.".format(name, _cluster_suffix(cluster_wide))


def idx_already_enabled(name):
    return "Index '{}' is already enabled.".format(name)


def idx_already_disabled(name):
    return "Index '{}' is already disabled.".format(name)


def idx_resumed(name):
    return "Index '{}' resumed successfully.".format(name)


def idx_already_resumed(name):
    return "Index '{}' is already running.".format(name)


def idx_would_resume(name):
    return "Index '{}' would be resumed.".format(name)


def idx_paused(name):
    return "Index '{}' paused successfully.".format(name)


def idx_already_paused(name):
    return "Index '{}' is already paused.".format(name)


def idx_would_pause(name):
    return "Index '{}' would be paused.".format(name)


def idx_reset(name):
    return "Index '{}' reset successfully.".format(name)


def idx_would_reset(name):
    return "Index '{}' would be reset.".format(name)


def idx_exists(name):
    return "Index '{}' already exists.".format(name)


def idx_already_absent(name):
    return "Index '{}' is already absent.".format(name)


def idx_not_exist_cannot_apply_mode(name):
    return "Index '{}' does not exist. Cannot apply mode.".format(name)


def node_already_present(tag, role, url):
    return "Node '{}' already present as {} at {}.".format(tag, role, url)


def node_would_add(tag, node_type):
    return "Node '{}' would be added as {}.".format(tag, node_type)


def node_added(tag, node_type):
    return "Node '{}' added as {}.".format(tag, node_type)


def failed_add_node(tag, error):
    return "Failed to add node '{}': {}".format(tag, error)


def cs_exists(name, t):
    return "Connection string '{}' (type {}) already exists. No changes made.".format(name, t)


def cs_not_found(name, t):
    return "Connection string '{}' not found (type {}).".format(name, t)


def cs_created(name, t):
    return "Created connection string '{}' (type {}).".format(name, t)


def cs_would_create(name, t):
    return "Would create connection string '{}' (type {}).".format(name, t)


def cs_deleted(name, t):
    return "Deleted connection string '{}' (type {}).".format(name, t)


def cs_would_delete(name, t):
    return "Would delete connection string '{}' (type {}).".format(name, t)


def cs_no_changes():
    return "Connection strings: no changes."
