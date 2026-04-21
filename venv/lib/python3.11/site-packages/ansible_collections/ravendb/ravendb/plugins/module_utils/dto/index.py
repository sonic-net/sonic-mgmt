# -*- coding: utf-8 -*-
#
# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class IndexDefinitionSpec(object):
    def __init__(self, maps=None, reduce=None, deployment_mode=None):
        if maps is None:
            maps = []
        elif isinstance(maps, str):
            maps = [maps]
        else:
            maps = list(maps)

        self.maps = maps
        self.reduce = None if reduce == "" else reduce
        self.deployment_mode = deployment_mode

    @classmethod
    def from_dict(cls, d):
        if not d:
            return None
        maps = d.get("map") or []
        if isinstance(maps, str):
            maps = [maps]
        dm_raw = d.get("deployment_mode") or d.get("DeploymentMode")
        if dm_raw is None:
            dm_norm = None
        else:
            dm_norm = str(dm_raw).strip().lower()
        return cls(maps=maps, reduce=d.get("reduce"), deployment_mode=dm_norm)

    def to_dict(self):
        out = {}
        if self.maps:
            out["map"] = list(self.maps)
        if self.reduce:
            out["reduce"] = self.reduce
        if self.deployment_mode:
            out["deployment_mode"] = self.deployment_mode
        return out


class IndexSpec(object):
    def __init__(self, db_name, name, definition=None, mode=None, cluster_wide=False, configuration=None):
        self.db_name = db_name
        self.name = name
        self.definition = definition
        self.mode = mode
        self.cluster_wide = bool(cluster_wide)
        self.configuration = dict(configuration or {})
