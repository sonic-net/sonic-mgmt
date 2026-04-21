# Copyright [2017] [Red Hat, Inc.]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from __future__ import absolute_import, division, print_function

__metaclass__ = type


import kubernetes.dynamic


class ResourceList(kubernetes.dynamic.resource.ResourceList):
    def __init__(
        self,
        client,
        group="",
        api_version="v1",
        base_kind="",
        kind=None,
        base_resource_lookup=None,
    ):
        self.client = client
        self.group = group
        self.api_version = api_version
        self.kind = kind or "{0}List".format(base_kind)
        self.base_kind = base_kind
        self.base_resource_lookup = base_resource_lookup
        self.__base_resource = None

    def base_resource(self):
        if self.__base_resource:
            return self.__base_resource
        elif self.base_resource_lookup:
            self.__base_resource = self.client.resources.get(
                **self.base_resource_lookup
            )
            return self.__base_resource
        return None

    def to_dict(self):
        return {
            "_type": "ResourceList",
            "group": self.group,
            "api_version": self.api_version,
            "kind": self.kind,
            "base_kind": self.base_kind,
            "base_resource_lookup": self.base_resource_lookup,
        }
