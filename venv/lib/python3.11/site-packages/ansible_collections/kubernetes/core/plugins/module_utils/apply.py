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

import json
from collections import OrderedDict

from ansible.module_utils.common.dict_transformations import dict_merge
from ansible_collections.kubernetes.core.plugins.module_utils.exceptions import (
    ApplyException,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.core import (
    gather_versions,
)
from ansible_collections.kubernetes.core.plugins.module_utils.version import (
    LooseVersion,
)

try:
    from kubernetes.dynamic.exceptions import NotFoundError
except ImportError:
    pass


LAST_APPLIED_CONFIG_ANNOTATION = "kubectl.kubernetes.io/last-applied-configuration"

POD_SPEC_SUFFIXES = {
    "containers": "name",
    "initContainers": "name",
    "ephemeralContainers": "name",
    "volumes": "name",
    "imagePullSecrets": "name",
    "containers.volumeMounts": "mountPath",
    "containers.volumeDevices": "devicePath",
    "containers.env": "name",
    "containers.ports": "containerPort",
    "initContainers.volumeMounts": "mountPath",
    "initContainers.volumeDevices": "devicePath",
    "initContainers.env": "name",
    "initContainers.ports": "containerPort",
    "ephemeralContainers.volumeMounts": "mountPath",
    "ephemeralContainers.volumeDevices": "devicePath",
    "ephemeralContainers.env": "name",
    "ephemeralContainers.ports": "containerPort",
}

POD_SPEC_PREFIXES = [
    "Pod.spec",
    "Deployment.spec.template.spec",
    "DaemonSet.spec.template.spec",
    "StatefulSet.spec.template.spec",
    "Job.spec.template.spec",
    "Cronjob.spec.jobTemplate.spec.template.spec",
]

# patch merge keys taken from generated.proto files under
# staging/src/k8s.io/api in kubernetes/kubernetes
STRATEGIC_MERGE_PATCH_KEYS = {
    "Service.spec.ports": "port",
    "ServiceAccount.secrets": "name",
    "ValidatingWebhookConfiguration.webhooks": "name",
    "MutatingWebhookConfiguration.webhooks": "name",
}

STRATEGIC_MERGE_PATCH_KEYS.update(
    {
        "%s.%s" % (prefix, key): value
        for prefix in POD_SPEC_PREFIXES
        for key, value in POD_SPEC_SUFFIXES.items()
    }
)


def annotate(desired):
    return dict(
        metadata=dict(
            annotations={
                LAST_APPLIED_CONFIG_ANNOTATION: json.dumps(
                    desired, separators=(",", ":"), indent=None, sort_keys=True
                )
            }
        )
    )


def apply_patch(actual, desired):
    last_applied = (
        actual["metadata"].get("annotations", {}).get(LAST_APPLIED_CONFIG_ANNOTATION)
    )

    if last_applied:
        # ensure that last_applied doesn't come back as a dict of unicode key/value pairs
        # json.loads can be used if we stop supporting python 2
        last_applied = json.loads(last_applied)
        patch = merge(
            dict_merge(last_applied, annotate(last_applied)),
            dict_merge(desired, annotate(desired)),
            actual,
        )
        if patch:
            return actual, patch
        else:
            return actual, actual
    else:
        return actual, dict_merge(desired, annotate(desired))


def apply_object(resource, definition, server_side=False):
    try:
        actual = resource.get(
            name=definition["metadata"]["name"],
            namespace=definition["metadata"].get("namespace"),
        )
        if server_side:
            return actual, None
    except NotFoundError:
        return None, dict_merge(definition, annotate(definition))
    return apply_patch(actual.to_dict(), definition)


def k8s_apply(resource, definition, **kwargs):
    existing, desired = apply_object(resource, definition)
    server_side = kwargs.get("server_side", False)
    if server_side:
        versions = gather_versions()
        body = definition
        if LooseVersion(versions["kubernetes"]) < LooseVersion("25.0.0"):
            body = json.dumps(definition).encode()
        # server_side_apply is forces content_type to 'application/apply-patch+yaml'
        return resource.server_side_apply(
            body=body,
            name=definition["metadata"]["name"],
            namespace=definition["metadata"].get("namespace"),
            force_conflicts=kwargs.get("force_conflicts"),
            field_manager=kwargs.get("field_manager"),
            dry_run=kwargs.get("dry_run"),
            serialize=kwargs.get("serialize"),
        )
    if not existing:
        return resource.create(
            body=desired, namespace=definition["metadata"].get("namespace"), **kwargs
        )
    if existing == desired:
        return resource.get(
            name=definition["metadata"]["name"],
            namespace=definition["metadata"].get("namespace"),
            **kwargs
        )
    return resource.patch(
        body=desired,
        name=definition["metadata"]["name"],
        namespace=definition["metadata"].get("namespace"),
        content_type="application/merge-patch+json",
        **kwargs
    )


# The patch is the difference from actual to desired without deletions, plus deletions
# from last_applied to desired. To find it, we compute deletions, which are the deletions from
# last_applied to desired, and delta, which is the difference from actual to desired without
# deletions, and then apply delta to deletions as a patch, which should be strictly additive.
def merge(last_applied, desired, actual, position=None):
    deletions = get_deletions(last_applied, desired)
    delta = get_delta(last_applied, actual, desired, position or desired["kind"])
    return dict_merge(deletions, delta)


def list_to_dict(lst, key, position):
    result = OrderedDict()
    for item in lst:
        try:
            result[item[key]] = item
        except KeyError:
            raise ApplyException(
                "Expected key '%s' not found in position %s" % (key, position)
            )
    return result


# list_merge applies a strategic merge to a set of lists if the patchMergeKey is known
# each item in the list is compared based on the patchMergeKey - if two values with the
# same patchMergeKey differ, we take the keys that are in last applied, compare the
# actual and desired for those keys, and update if any differ
def list_merge(last_applied, actual, desired, position):
    result = list()
    if position in STRATEGIC_MERGE_PATCH_KEYS and last_applied:
        patch_merge_key = STRATEGIC_MERGE_PATCH_KEYS[position]
        last_applied_dict = list_to_dict(last_applied, patch_merge_key, position)
        actual_dict = list_to_dict(actual, patch_merge_key, position)
        desired_dict = list_to_dict(desired, patch_merge_key, position)
        for key in desired_dict:
            if key not in actual_dict or key not in last_applied_dict:
                result.append(desired_dict[key])
            else:
                patch = merge(
                    last_applied_dict[key],
                    desired_dict[key],
                    actual_dict[key],
                    position,
                )
                result.append(dict_merge(actual_dict[key], patch))
        for key in actual_dict:
            if key not in desired_dict and key not in last_applied_dict:
                result.append(actual_dict[key])
        return result
    else:
        return desired


def recursive_list_diff(list1, list2, position=None):
    result = (list(), list())
    if position in STRATEGIC_MERGE_PATCH_KEYS:
        patch_merge_key = STRATEGIC_MERGE_PATCH_KEYS[position]
        dict1 = list_to_dict(list1, patch_merge_key, position)
        dict2 = list_to_dict(list2, patch_merge_key, position)
        dict1_keys = set(dict1.keys())
        dict2_keys = set(dict2.keys())
        for key in dict1_keys - dict2_keys:
            result[0].append(dict1[key])
        for key in dict2_keys - dict1_keys:
            result[1].append(dict2[key])
        for key in dict1_keys & dict2_keys:
            diff = recursive_diff(dict1[key], dict2[key], position)
            if diff:
                # reinsert patch merge key to relate changes in other keys to
                # a specific list element
                diff[0].update({patch_merge_key: dict1[key][patch_merge_key]})
                diff[1].update({patch_merge_key: dict2[key][patch_merge_key]})
                result[0].append(diff[0])
                result[1].append(diff[1])
        if result[0] or result[1]:
            return result
    elif list1 != list2:
        return (list1, list2)
    return None


def recursive_diff(dict1, dict2, position=None):
    if not position:
        if "kind" in dict1 and dict1.get("kind") == dict2.get("kind"):
            position = dict1["kind"]
    left = dict((k, v) for (k, v) in dict1.items() if k not in dict2)
    right = dict((k, v) for (k, v) in dict2.items() if k not in dict1)
    for k in set(dict1.keys()) & set(dict2.keys()):
        if position:
            this_position = "%s.%s" % (position, k)
        if isinstance(dict1[k], dict) and isinstance(dict2[k], dict):
            result = recursive_diff(dict1[k], dict2[k], this_position)
            if result:
                left[k] = result[0]
                right[k] = result[1]
        elif isinstance(dict1[k], list) and isinstance(dict2[k], list):
            result = recursive_list_diff(dict1[k], dict2[k], this_position)
            if result:
                left[k] = result[0]
                right[k] = result[1]
        elif dict1[k] != dict2[k]:
            left[k] = dict1[k]
            right[k] = dict2[k]
    if left or right:
        return left, right
    else:
        return None


def get_deletions(last_applied, desired):
    patch = {}
    for k, last_applied_value in last_applied.items():
        desired_value = desired.get(k)
        if isinstance(last_applied_value, dict) and isinstance(desired_value, dict):
            p = get_deletions(last_applied_value, desired_value)
            if p:
                patch[k] = p
        elif last_applied_value != desired_value:
            patch[k] = desired_value
    return patch


def get_delta(last_applied, actual, desired, position=None):
    patch = {}

    for k, desired_value in desired.items():
        if position:
            this_position = "%s.%s" % (position, k)
        actual_value = actual.get(k)
        if actual_value is None:
            patch[k] = desired_value
        elif isinstance(desired_value, dict):
            p = get_delta(
                last_applied.get(k, {}), actual_value, desired_value, this_position
            )
            if p:
                patch[k] = p
        elif isinstance(desired_value, list):
            p = list_merge(
                last_applied.get(k, []), actual_value, desired_value, this_position
            )
            if p:
                patch[k] = [item for item in p if item is not None]
        elif actual_value != desired_value:
            patch[k] = desired_value
    return patch
