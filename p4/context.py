# Copyright 2019 Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from collections import Counter
import enum
from functools import partialmethod


@enum.unique
class P4Type(enum.Enum):
    table = 1
    action = 2
    action_profile = 3
    counter = 4
    direct_counter = 5
    meter = 6
    direct_meter = 7


P4Type.table.p4info_name = "tables"
P4Type.action.p4info_name = "actions"
P4Type.action_profile.p4info_name = "action_profiles"
P4Type.counter.p4info_name = "counters"
P4Type.direct_counter.p4info_name = "direct_counters"
P4Type.meter.p4info_name = "meters"
P4Type.direct_meter.p4info_name = "direct_meters"


for obj_type in P4Type:
    obj_type.pretty_name = obj_type.name.replace('_', ' ')
    obj_type.pretty_names = obj_type.pretty_name + 's'


@enum.unique
class P4RuntimeEntity(enum.Enum):
    table_entry = 1
    action_profile_member = 2
    action_profile_group = 3
    meter_entry = 4
    direct_meter_entry = 5
    counter_entry = 6
    direct_counter_entry = 7
    packet_replication_engine_entry = 8


class Context:
    def __init__(self):
        self.p4info = None

    def set_p4info(self, p4info):
        self.p4info = p4info
        self.p4info_obj_map = {}
        self.p4info_obj_map_by_id = {}
        self.p4info_objs_by_type = {}
        self._import_p4info_names()

    def get_obj(self, obj_type, name):
        key = (obj_type, name)
        return self.p4info_obj_map.get(key, None)
        '''
        if (obj_type == P4Type.action):
            gg = list(self.p4info_obj_map.keys())
            for el in gg:
                if name in el:
                    rep = self.p4info_obj_map.get(el, None)
                    break
                else:
                    rep = "None"
        else:
            rep = self.p4info_obj_map.get(key, None)
        return rep
        '''

    def get_obj_id(self, obj_type, name):
        obj = self.get_obj(obj_type, name)
        if obj is None:
            return None
        return obj.preamble.id

    def get_param(self, action_name, name):
        a = self.get_obj(P4Type.action, action_name)
        if a is None:
            return None
        for p in a.params:
            if p.name == name:
                return p

    def get_mf(self, table_name, name):
        t = self.get_obj(P4Type.table, table_name)
        if t is None:
            return None
        for mf in t.match_fields:
            if mf.name == name:
                return mf

    def get_param_id(self, action_name, name):
        p = self.get_param(action_name, name)
        return None if p is None else p.id

    def get_mf_id(self, table_name, name):
        mf = self.get_mf(table_name, name)
        return None if mf is None else mf.id

    def get_param_name(self, action_name, id_):
        a = self.get_obj(P4Type.action, action_name)
        if a is None:
            return None
        for p in a.params:
            if p.id == id_:
                return p.name

    def get_mf_name(self, table_name, id_):
        t = self.get_obj(P4Type.table, table_name)
        if t is None:
            return None
        for mf in t.match_fields:
            if mf.id == id_:
                return mf.name

    def get_objs(self, obj_type):
        m = self.p4info_objs_by_type[obj_type]
        for name, obj in m.items():
            yield name, obj

    def get_name_from_id(self, id_):
        return self.p4info_obj_map_by_id[id_].preamble.name

    def get_obj_by_id(self, id_):
        return self.p4info_obj_map_by_id[id_]

    # In order to make the CLI easier to use, we accept any suffix that
    # uniquely identifies the object among p4info objects of the same type.
    def _import_p4info_names(self):
        suffix_count = Counter()
        for obj_type in P4Type:
            self.p4info_objs_by_type[obj_type] = {}
            for obj in getattr(self.p4info, obj_type.p4info_name):
                pre = obj.preamble
                self.p4info_obj_map_by_id[pre.id] = obj
                self.p4info_objs_by_type[obj_type][pre.name] = obj
                suffix = None
                for s in reversed(pre.name.split(".")):
                    suffix = s if suffix is None else s + "." + suffix
                    key = (obj_type, suffix)
                    self.p4info_obj_map[key] = obj
                    suffix_count[key] += 1
        for key, c in suffix_count.items():
            if c > 1:
                del self.p4info_obj_map[key]


# Add p4info object and object id "getters" for each object type; these are just
# wrappers around Context.get_obj and Context.get_obj_id.
# For example: get_table(x) and get_table_id(x) respectively call
# get_obj(P4Type.table, x) and get_obj_id(P4Type.table, x)
for obj_type in P4Type:
    name = "_".join(["get", obj_type.name])
    setattr(Context, name, partialmethod(
        Context.get_obj, obj_type))
    name = "_".join(["get", obj_type.name, "id"])
    setattr(Context, name, partialmethod(
        Context.get_obj_id, obj_type))

for obj_type in P4Type:
    name = "_".join(["get", obj_type.p4info_name])
    setattr(Context, name, partialmethod(Context.get_objs, obj_type))