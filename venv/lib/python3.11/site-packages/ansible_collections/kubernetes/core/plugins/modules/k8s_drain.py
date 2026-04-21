#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Aubin Bikouo <@abikouo>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""

module: k8s_drain

short_description: Drain, Cordon, or Uncordon node in k8s cluster

version_added: 2.2.0

author: Aubin Bikouo (@abikouo)

description:
  - Drain node in preparation for maintenance same as kubectl drain.
  - Cordon will mark the node as unschedulable.
  - Uncordon will mark the node as schedulable.
  - The given node will be marked unschedulable to prevent new pods from arriving.
  - Then drain deletes all pods except mirror pods (which cannot be deleted through the API server).

extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options

options:
  state:
    description:
    - Determines whether to drain, cordon, or uncordon node.
    type: str
    default: drain
    choices: [ cordon, drain, uncordon ]
  name:
    description:
      - The name of the node.
    required: true
    type: str
  pod_selectors:
    description:
      - Label selector to filter pods on the node.
      - This option has effect only when C(state) is set to I(drain).
    type: list
    elements: str
    version_added: 3.0.0
    aliases:
    - label_selectors
  delete_options:
    type: dict
    default: {}
    description:
      - Specify options to delete pods.
      - This option has effect only when C(state) is set to I(drain).
    suboptions:
        terminate_grace_period:
            description:
            - Specify how many seconds to wait before forcefully terminating.
            - If not specified, the default grace period for the object type will be used.
            - The value zero indicates delete immediately.
            required: false
            type: int
        force:
            description:
            - Continue even if there are pods not managed by a ReplicationController, Job, or DaemonSet.
            type: bool
            default: False
        ignore_daemonsets:
            description:
            - Ignore DaemonSet-managed pods.
            type: bool
            default: False
        delete_emptydir_data:
            description:
            - Continue even if there are pods using emptyDir (local data that will be deleted when the node is drained).
            type: bool
            default: False
            version_added: 2.3.0
        disable_eviction:
            description:
            - Forces drain to use delete rather than evict.
            type: bool
            default: False
        wait_timeout:
            description:
            - The length of time to wait in seconds for pod to be deleted before giving up, zero means infinite.
            type: int
        wait_sleep:
            description:
            - Number of seconds to sleep between checks.
            - Ignored if C(wait_timeout) is not set.
            default: 5
            type: int

requirements:
  - python >= 3.9
  - kubernetes >= 24.2.0
"""

EXAMPLES = r"""
- name: Drain node "foo", even if there are pods not managed by a ReplicationController, Job, or DaemonSet on it.
  kubernetes.core.k8s_drain:
    state: drain
    name: foo
    delete_options:
      force: yes

- name: Drain node "foo", but abort if there are pods not managed by a ReplicationController, Job, or DaemonSet, and use a grace period of 15 minutes.
  kubernetes.core.k8s_drain:
    state: drain
    name: foo
    delete_options:
      terminate_grace_period: 900

- name: Mark node "foo" as schedulable.
  kubernetes.core.k8s_drain:
    state: uncordon
    name: foo

- name: Mark node "foo" as unschedulable.
  kubernetes.core.k8s_drain:
    state: cordon
    name: foo

- name: Drain node "foo" using label selector to filter the list of pods to be drained.
  kubernetes.core.k8s_drain:
    state: drain
    name: foo
    pod_selectors:
    - 'app!=csi-attacher'
    - 'app!=csi-provisioner'
"""

RETURN = r"""
result:
  description:
  - The node status and the number of pods deleted.
  returned: success
  type: str
"""

import copy
import json
import time
import traceback
from datetime import datetime

from ansible.module_utils._text import to_native
from ansible_collections.kubernetes.core.plugins.module_utils.ansiblemodule import (
    AnsibleModule,
)
from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
    AUTH_ARG_SPEC,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.client import (
    get_api_client,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.core import (
    AnsibleK8SModule,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.exceptions import (
    CoreException,
)

try:
    from kubernetes.client.api import core_v1_api
    from kubernetes.client.exceptions import ApiException
    from kubernetes.client.models import V1DeleteOptions, V1ObjectMeta
except ImportError:
    # ImportError are managed by the common module already.
    pass

HAS_EVICTION_API = True
k8s_import_exception = None
K8S_IMP_ERR = None

try:
    from kubernetes.client.models import V1beta1Eviction as v1_eviction
except ImportError:
    try:
        from kubernetes.client.models import V1Eviction as v1_eviction
    except ImportError as e:
        k8s_import_exception = e
        K8S_IMP_ERR = traceback.format_exc()
        HAS_EVICTION_API = False


def format_dynamic_api_exc(exc):
    if exc.body:
        if exc.headers and exc.headers.get("Content-Type") == "application/json":
            message = json.loads(exc.body).get("message")
            if message:
                return message
        return exc.body
    else:
        return "%s Reason: %s" % (exc.status, exc.reason)


def filter_pods(pods, force, ignore_daemonset, delete_emptydir_data):
    k8s_kind_mirror = "kubernetes.io/config.mirror"
    daemonSet, unmanaged, mirror, localStorage, to_delete = [], [], [], [], []
    for pod in pods:
        # check mirror pod: cannot be delete using API Server
        if pod.metadata.annotations and k8s_kind_mirror in pod.metadata.annotations:
            mirror.append((pod.metadata.namespace, pod.metadata.name))
            continue

        # Any finished pod can be deleted
        if pod.status.phase in ("Succeeded", "Failed"):
            to_delete.append((pod.metadata.namespace, pod.metadata.name))
            continue

        # Pod with local storage cannot be deleted
        if pod.spec.volumes and any(vol.empty_dir for vol in pod.spec.volumes):
            localStorage.append((pod.metadata.namespace, pod.metadata.name))
            continue

        # Check replicated Pod
        owner_ref = pod.metadata.owner_references
        if not owner_ref:
            unmanaged.append((pod.metadata.namespace, pod.metadata.name))
        else:
            for owner in owner_ref:
                if owner.kind == "DaemonSet":
                    daemonSet.append((pod.metadata.namespace, pod.metadata.name))
                else:
                    to_delete.append((pod.metadata.namespace, pod.metadata.name))

    warnings, errors = [], []
    if unmanaged:
        pod_names = ",".join([pod[0] + "/" + pod[1] for pod in unmanaged])
        if not force:
            errors.append(
                "cannot delete Pods not managed by ReplicationController, ReplicaSet, Job,"
                " DaemonSet or StatefulSet (use option force set to yes): {0}.".format(
                    pod_names
                )
            )
        else:
            # Pod not managed will be deleted as 'force' is true
            warnings.append(
                "Deleting Pods not managed by ReplicationController, ReplicaSet, Job, DaemonSet or StatefulSet: {0}.".format(
                    pod_names
                )
            )
            to_delete += unmanaged

    # mirror pods warning
    if mirror:
        pod_names = ",".join([pod[0] + "/" + pod[1] for pod in mirror])
        warnings.append(
            "cannot delete mirror Pods using API server: {0}.".format(pod_names)
        )

    # local storage
    if localStorage:
        pod_names = ",".join([pod[0] + "/" + pod[1] for pod in localStorage])
        if not delete_emptydir_data:
            errors.append(
                "cannot delete Pods with local storage: {0}.".format(pod_names)
            )
        else:
            warnings.append("Deleting Pods with local storage: {0}.".format(pod_names))
            for pod in localStorage:
                to_delete.append((pod[0], pod[1]))

    # DaemonSet managed Pods
    if daemonSet:
        pod_names = ",".join([pod[0] + "/" + pod[1] for pod in daemonSet])
        if not ignore_daemonset:
            errors.append(
                "cannot delete DaemonSet-managed Pods (use option ignore_daemonset set to yes): {0}.".format(
                    pod_names
                )
            )
        else:
            warnings.append("Ignoring DaemonSet-managed Pods: {0}.".format(pod_names))
    return to_delete, warnings, errors


class K8sDrainAnsible(object):
    def __init__(self, module, client):
        self._module = module
        self._api_instance = core_v1_api.CoreV1Api(client.client)

        # delete options
        self._drain_options = module.params.get("delete_options", {})
        self._delete_options = None
        if self._drain_options.get("terminate_grace_period"):
            self._delete_options = V1DeleteOptions(
                grace_period_seconds=self._drain_options.get("terminate_grace_period")
            )

        self._changed = False

    def wait_for_pod_deletion(self, pods, wait_timeout, wait_sleep):
        start = datetime.now()

        def _elapsed_time():
            return (datetime.now() - start).seconds

        response = None
        pod = None
        while (_elapsed_time() < wait_timeout or wait_timeout == 0) and pods:
            if not pod:
                pod = pods[-1]
            try:
                response = self._api_instance.read_namespaced_pod(
                    namespace=pod[0], name=pod[1]
                )
                if not response or response.spec.node_name != self._module.params.get(
                    "name"
                ):
                    pod = None
                    del pods[-1]
                time.sleep(wait_sleep)
            except ApiException as exc:
                if exc.reason != "Not Found":
                    self._module.fail_json(
                        msg="Exception raised: {0}".format(exc.reason)
                    )
                pod = None
                del pods[-1]
            except Exception as e:
                self._module.fail_json(msg="Exception raised: {0}".format(to_native(e)))
        if not pods:
            return None
        return "timeout reached while pods were still running."

    def evict_pods(self, pods):
        for namespace, name in pods:
            try:
                if self._drain_options.get("disable_eviction"):
                    self._api_instance.delete_namespaced_pod(
                        name=name, namespace=namespace, body=self._delete_options
                    )
                else:
                    body = v1_eviction(
                        delete_options=self._delete_options,
                        metadata=V1ObjectMeta(name=name, namespace=namespace),
                    )
                    self._api_instance.create_namespaced_pod_eviction(
                        name=name, namespace=namespace, body=body
                    )
                self._changed = True
            except ApiException as exc:
                if exc.reason != "Not Found":
                    self._module.fail_json(
                        msg="Failed to delete pod {0}/{1} due to: {2}".format(
                            namespace, name, to_native(format_dynamic_api_exc(exc))
                        )
                    )
            except Exception as exc:
                self._module.fail_json(
                    msg="Failed to delete pod {0}/{1} due to: {2}".format(
                        namespace, name, to_native(exc)
                    )
                )

    def list_pods(self):
        params = {
            "field_selector": "spec.nodeName={name}".format(
                name=self._module.params.get("name")
            )
        }
        pod_selectors = self._module.params.get("pod_selectors")
        if pod_selectors:
            params["label_selector"] = ",".join(pod_selectors)
        return self._api_instance.list_pod_for_all_namespaces(**params)

    def delete_or_evict_pods(self, node_unschedulable):
        # Mark node as unschedulable
        result = []
        if not node_unschedulable:
            self.patch_node(unschedulable=True)
            result.append(
                "node {0} marked unschedulable.".format(self._module.params.get("name"))
            )
            self._changed = True
        else:
            result.append(
                "node {0} already marked unschedulable.".format(
                    self._module.params.get("name")
                )
            )

        def _revert_node_patch():
            if self._changed:
                self._changed = False
                self.patch_node(unschedulable=False)

        try:
            pod_list = self.list_pods()
            # Filter pods
            force = self._drain_options.get("force", False)
            ignore_daemonset = self._drain_options.get("ignore_daemonsets", False)
            delete_emptydir_data = self._drain_options.get(
                "delete_emptydir_data", False
            )
            pods, warnings, errors = filter_pods(
                pod_list.items, force, ignore_daemonset, delete_emptydir_data
            )
            if errors:
                _revert_node_patch()
                self._module.fail_json(
                    msg="Pod deletion errors: {0}".format(" ".join(errors))
                )
        except ApiException as exc:
            if exc.reason != "Not Found":
                _revert_node_patch()
                self._module.fail_json(
                    msg="Failed to list pod from node {name} due to: {reason}".format(
                        name=self._module.params.get("name"), reason=exc.reason
                    ),
                    status=exc.status,
                )
            pods = []
        except Exception as exc:
            _revert_node_patch()
            self._module.fail_json(
                msg="Failed to list pod from node {name} due to: {error}".format(
                    name=self._module.params.get("name"), error=to_native(exc)
                )
            )

        # Delete Pods
        if pods:
            self.evict_pods(pods)
            number_pod = len(pods)
            if self._drain_options.get("wait_timeout") is not None:
                warn = self.wait_for_pod_deletion(
                    pods,
                    self._drain_options.get("wait_timeout"),
                    self._drain_options.get("wait_sleep"),
                )
                if warn:
                    warnings.append(warn)
            result.append("{0} Pod(s) deleted from node.".format(number_pod))
        if warnings:
            return dict(result=" ".join(result), warnings=warnings)
        return dict(result=" ".join(result))

    def patch_node(self, unschedulable):
        body = {"spec": {"unschedulable": unschedulable}}
        try:
            self._api_instance.patch_node(
                name=self._module.params.get("name"), body=body
            )
        except Exception as exc:
            self._module.fail_json(
                msg="Failed to patch node due to: {0}".format(to_native(exc))
            )

    def execute_module(self):
        state = self._module.params.get("state")
        name = self._module.params.get("name")
        try:
            node = self._api_instance.read_node(name=name)
        except ApiException as exc:
            if exc.reason == "Not Found":
                self._module.fail_json(msg="Node {0} not found.".format(name))
            self._module.fail_json(
                msg="Failed to retrieve node '{0}' due to: {1}".format(
                    name, exc.reason
                ),
                status=exc.status,
            )
        except Exception as exc:
            self._module.fail_json(
                msg="Failed to retrieve node '{0}' due to: {1}".format(
                    name, to_native(exc)
                )
            )

        result = {}
        if state == "cordon":
            if node.spec.unschedulable:
                self._module.exit_json(
                    result="node {0} already marked unschedulable.".format(name)
                )
            self.patch_node(unschedulable=True)
            result["result"] = "node {0} marked unschedulable.".format(name)
            self._changed = True

        elif state == "uncordon":
            if not node.spec.unschedulable:
                self._module.exit_json(
                    result="node {0} already marked schedulable.".format(name)
                )
            self.patch_node(unschedulable=False)
            result["result"] = "node {0} marked schedulable.".format(name)
            self._changed = True

        else:
            # drain node
            # Delete or Evict Pods
            ret = self.delete_or_evict_pods(node_unschedulable=node.spec.unschedulable)
            result.update(ret)

        self._module.exit_json(changed=self._changed, **result)


def argspec():
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            state=dict(default="drain", choices=["cordon", "drain", "uncordon"]),
            name=dict(required=True),
            delete_options=dict(
                type="dict",
                default={},
                options=dict(
                    terminate_grace_period=dict(type="int"),
                    force=dict(type="bool", default=False),
                    ignore_daemonsets=dict(type="bool", default=False),
                    delete_emptydir_data=dict(type="bool", default=False),
                    disable_eviction=dict(type="bool", default=False),
                    wait_timeout=dict(type="int"),
                    wait_sleep=dict(type="int", default=5),
                ),
            ),
            pod_selectors=dict(
                type="list",
                elements="str",
                aliases=["label_selectors"],
            ),
        )
    )
    return argument_spec


def main():
    module = AnsibleK8SModule(module_class=AnsibleModule, argument_spec=argspec())

    if not HAS_EVICTION_API:
        module.fail_json(
            msg="The kubernetes Python library missing with V1Eviction API",
            exception=K8S_IMP_ERR,
            error=to_native(k8s_import_exception),
        )

    try:
        client = get_api_client(module=module)
        k8s_drain = K8sDrainAnsible(module, client.client)
        k8s_drain.execute_module()
    except CoreException as e:
        module.fail_from_exception(e)


if __name__ == "__main__":
    main()
