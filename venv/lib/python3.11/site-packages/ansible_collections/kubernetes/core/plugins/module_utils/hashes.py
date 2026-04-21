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

# Implement ConfigMapHash and SecretHash equivalents
# Based on https://github.com/kubernetes/kubernetes/pull/49961

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import hashlib
import json

try:
    import string

    maketrans = string.maketrans
except AttributeError:
    maketrans = str.maketrans

try:
    from collections import OrderedDict
except ImportError:
    from orderreddict import OrderedDict


def sorted_dict(unsorted_dict):
    result = OrderedDict()
    for k, v in sorted(unsorted_dict.items()):
        if isinstance(v, dict):
            v = sorted_dict(v)
        result[k] = v
    return result


def generate_hash(resource):
    # Get name from metadata
    metada = resource.get("metadata", {})
    key = "name"
    resource["name"] = metada.get("name", "")
    generate_name = metada.get("generateName", "")
    if resource["name"] == "" and generate_name:
        del resource["name"]
        key = "generateName"
        resource["generateName"] = generate_name
    if resource["kind"] == "ConfigMap":
        marshalled = marshal(sorted_dict(resource), ["data", "kind", key])
        del resource[key]
        return encode(marshalled)
    if resource["kind"] == "Secret":
        marshalled = marshal(sorted_dict(resource), ["data", "kind", key, "type"])
        del resource[key]
        return encode(marshalled)
    raise NotImplementedError


def marshal(data, keys):
    ordered = OrderedDict()
    for key in keys:
        ordered[key] = data.get(key, "")
    return json.dumps(ordered, separators=(",", ":")).encode("utf-8")


def encode(resource):
    return (
        hashlib.sha256(resource).hexdigest()[:10].translate(maketrans("013ae", "ghkmt"))
    )
