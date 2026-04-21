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


from ansible_collections.kubernetes.core.plugins.module_utils.apply import k8s_apply
from ansible_collections.kubernetes.core.plugins.module_utils.exceptions import (
    ApplyException,
)
from kubernetes.dynamic import DynamicClient


class K8SDynamicClient(DynamicClient):
    def apply(self, resource, body=None, name=None, namespace=None, **kwargs):
        body = super().serialize_body(body)
        body["metadata"] = body.get("metadata", dict())
        name = name or body["metadata"].get("name")
        if not name:
            raise ValueError(
                "name is required to apply {0}.{1}".format(
                    resource.group_version, resource.kind
                )
            )
        if resource.namespaced:
            body["metadata"]["namespace"] = super().ensure_namespace(
                resource, namespace, body
            )
        try:
            return k8s_apply(resource, body, **kwargs)
        except ApplyException as e:
            raise ValueError(
                "Could not apply strategic merge to %s/%s: %s"
                % (body["kind"], body["metadata"]["name"], e)
            )
