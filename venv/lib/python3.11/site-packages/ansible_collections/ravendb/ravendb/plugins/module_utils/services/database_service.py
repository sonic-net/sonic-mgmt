# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
from ansible_collections.ravendb.ravendb.plugins.module_utils.core.tls import TLSConfig


def list_databases(ctx, start=0, max=128):
    """Return a list of database names from the server."""
    from ravendb.serverwide.operations.common import GetDatabaseNamesOperation
    return ctx.maintenance_server().send(GetDatabaseNamesOperation(start, max))


def get_record(ctx, db_name):
    """
    Fetch the database record for the specified database.
    """
    from ravendb.serverwide.operations.common import GetDatabaseRecordOperation
    return ctx.maintenance_server().send(GetDatabaseRecordOperation(db_name))


def create_database(ctx, db_name, replication_factor, encrypted, members=None, tls=None):
    if members:
        import requests
        body = {
            "DatabaseName": db_name,
            "ReplicationFactor": replication_factor,
            "Encrypted": bool(encrypted),
            "DisableDynamicNodesDistribution": True,
            "Topology": {
                "Members": list(members),
                "ReplicationFactor": replication_factor,
                "DynamicNodesDistribution": False,
            },
        }
        base = ctx.store.urls[0].rstrip("/")
        url = base + "/admin/databases"  # todo: move to client operation when it will be supported
        cert, verify = (tls or TLSConfig()).to_requests_tuple()
        r = requests.put(url, json=body, cert=cert, verify=verify, timeout=30)
        r.raise_for_status()
        return

    from ravendb.serverwide.database_record import DatabaseRecord
    from ravendb.serverwide.operations.common import CreateDatabaseOperation
    rec = DatabaseRecord(db_name)
    if encrypted:
        rec.encrypted = True
    ctx.maintenance_server().send(CreateDatabaseOperation(rec, replication_factor))


def delete_database(ctx, db_name):
    from ravendb.serverwide.operations.common import DeleteDatabaseOperation
    ctx.maintenance_server().send(DeleteDatabaseOperation(db_name))
