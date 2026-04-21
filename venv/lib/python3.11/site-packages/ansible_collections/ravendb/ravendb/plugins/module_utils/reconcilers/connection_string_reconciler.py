# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.ravendb.ravendb.plugins.module_utils.core.result import ModuleResult
from ansible_collections.ravendb.ravendb.plugins.module_utils.core import messages as msg
from ansible_collections.ravendb.ravendb.plugins.module_utils.services import connection_string_service as cssvc


class ConnectionStringReconciler():
    def __init__(self, ctx):
        self.ctx = ctx

    def ensure_present(self, spec, tls, check_mode):
        name = str(spec.name).strip()
        cs_type = spec.cs_type
        type = (cs_type or "").upper()

        cssvc.require_min_version_for_type(spec, self.ctx, tls)
        if not cssvc.type_supported_on_server(self.ctx, type, tls):
            raise RuntimeError("Connection string type '{}' is not supported by this server.".format(cs_type))

        if cssvc.exists(self.ctx, type, name, tls):
            return ModuleResult.ok(msg=msg.cs_exists(name, cs_type), changed=False)

        builder = cssvc.builder_for(cs_type)
        obj = builder(name, spec.properties or {})

        if check_mode:
            return ModuleResult.ok(msg=msg.cs_would_create(name, cs_type), changed=True)

        cssvc.put(self.ctx, obj)
        return ModuleResult.ok(msg=msg.cs_created(name, cs_type), changed=True)

    def ensure_absent(self, cs_type, name, tls, check_mode):
        name = str(name).strip()
        type = (cs_type or "").upper()

        if not cssvc.type_supported_on_server(self.ctx, type, tls):
            return ModuleResult.ok(msg=msg.cs_not_found(name, cs_type), changed=False)

        if not cssvc.exists(self.ctx, type, name, tls):
            return ModuleResult.ok(msg=msg.cs_not_found(name, cs_type), changed=False)

        if check_mode:
            return ModuleResult.ok(msg=msg.cs_would_delete(name, cs_type), changed=True)

        cssvc.remove(self.ctx, cs_type, name)
        return ModuleResult.ok(msg=msg.cs_deleted(name, cs_type), changed=True)
