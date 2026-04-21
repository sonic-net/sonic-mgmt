#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Fabian von Feilitzsch <@fabianvf>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
module: k8s_log

short_description: Fetch logs from Kubernetes resources

version_added: 0.10.0

author:
    - "Fabian von Feilitzsch (@fabianvf)"

description:
  - Use the Kubernetes Python client to perform read operations on K8s log endpoints.
  - Authenticate using either a config file, certificates, password or token.
  - Supports check mode.
  - Analogous to `kubectl logs` or `oc logs`
extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options
  - kubernetes.core.k8s_name_options
options:
  kind:
    description:
    - Use to specify an object model.
    - Use in conjunction with I(api_version), I(name), and I(namespace) to identify a specific object.
    - If using I(label_selectors), cannot be overridden.
    type: str
    default: Pod
  name:
    description:
    - Use to specify an object name.
    - Use in conjunction with I(api_version), I(kind) and I(namespace) to identify a specific object.
    - Only one of I(name) or I(label_selectors) may be provided.
    type: str
  label_selectors:
    description:
    - List of label selectors to use to filter results
    - Only one of I(name) or I(label_selectors) may be provided.
    type: list
    elements: str
    default: []
  container:
    description:
    - Use to specify the container within a pod to grab the log from.
    - If there is only one container, this will default to that container.
    - If there is more than one container, this option is required or set I(all_containers) to C(true).
    - mutually exclusive with C(all_containers).
    required: no
    type: str
  since_seconds:
    description:
    - A relative time in seconds before the current time from which to show logs.
    required: no
    type: str
    version_added: 2.2.0
  previous:
    description:
    - If C(true), print the logs for the previous instance of the container in a pod if it exists.
    required: no
    type: bool
    default: False
    version_added: 2.4.0
  tail_lines:
    description:
    - A number of lines from the end of the logs to retrieve.
    required: no
    type: int
    version_added: 2.4.0
  all_containers:
    description:
    - If set to C(true), retrieve all containers' logs in the pod(s).
    - mutually exclusive with C(container).
    type: bool
    version_added: 2.4.0

requirements:
  - "python >= 3.9"
  - "kubernetes >= 24.2.0"
  - "PyYAML >= 3.11"
"""

EXAMPLES = r"""
- name: Get a log from a Pod
  kubernetes.core.k8s_log:
    name: example-1
    namespace: testing
  register: log

# This will get the log from the first Pod found matching the selector
- name: Log a Pod matching a label selector
  kubernetes.core.k8s_log:
    namespace: testing
    label_selectors:
    - app=example
  register: log

# This will get the log from a single Pod managed by this Deployment
- name: Get a log from a Deployment
  kubernetes.core.k8s_log:
    api_version: apps/v1
    kind: Deployment
    namespace: testing
    name: example
    since_seconds: "4000"
  register: log

# This will get the log from a single Pod managed by this DeploymentConfig
- name: Get a log from a DeploymentConfig
  kubernetes.core.k8s_log:
    api_version: apps.openshift.io/v1
    kind: DeploymentConfig
    namespace: testing
    name: example
    tail_lines: 100
  register: log

# This will get the logs from all containers in Pod
- name: Get the logs from all containers in pod
  kubernetes.core.k8s_log:
    namespace: testing
    name: some-pod
    all_containers: true
"""

RETURN = r"""
log:
  type: str
  description:
  - The text log of the object
  returned: success
log_lines:
  type: list
  description:
  - The log of the object, split on newlines
  returned: success
"""


import copy
import json

from ansible_collections.kubernetes.core.plugins.module_utils.ansiblemodule import (
    AnsibleModule,
)
from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
    AUTH_ARG_SPEC,
    NAME_ARG_SPEC,
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
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.service import (
    K8sService,
)

try:
    from kubernetes.client.exceptions import ApiException
except ImportError:
    # ImportError are managed by the common module already.
    pass


def argspec():
    args = copy.deepcopy(AUTH_ARG_SPEC)
    args.update(NAME_ARG_SPEC)
    args.update(
        dict(
            kind=dict(type="str", default="Pod"),
            container=dict(),
            since_seconds=dict(),
            label_selectors=dict(type="list", elements="str", default=[]),
            previous=dict(type="bool", default=False),
            tail_lines=dict(type="int"),
            all_containers=dict(type="bool"),
        )
    )
    return args


def get_exception_message(exc):
    try:
        d = json.loads(exc.body.decode("utf8"))
        return d["message"]
    except Exception:
        return exc


def list_containers_in_pod(svc, resource, namespace, name):
    try:
        result = svc.client.get(resource, name=name, namespace=namespace)
        containers = [
            c["name"] for c in result.to_dict()["status"]["containerStatuses"]
        ]
        return containers
    except Exception as exc:
        raise CoreException(
            "Unable to retrieve log from Pod due to: {0}".format(
                get_exception_message(exc)
            )
        )


def execute_module(svc, params):
    name = params.get("name")
    namespace = params.get("namespace")
    label_selector = ",".join(params.get("label_selectors", {}))
    if name and label_selector:
        raise CoreException("Only one of name or label_selectors can be provided")

    resource = svc.find_resource(params["kind"], params["api_version"], fail=True)
    v1_pods = svc.find_resource("Pod", "v1", fail=True)

    if "log" not in resource.subresources:
        if not name:
            raise CoreException(
                "name must be provided for resources that do not support the log subresource"
            )
        instance = resource.get(name=name, namespace=namespace)
        label_selector = ",".join(extract_selectors(instance))
        resource = v1_pods

    if label_selector:
        instances = v1_pods.get(namespace=namespace, label_selector=label_selector)
        if not instances.items:
            raise CoreException(
                "No pods in namespace {0} matched selector {1}".format(
                    namespace, label_selector
                )
            )
        # This matches the behavior of kubectl when logging pods via a selector
        name = instances.items[0].metadata.name
        resource = v1_pods

    if "base" not in resource.log.urls and not name:
        raise CoreException(
            "name must be provided for resources that do not support namespaced base url"
        )

    kwargs = {}
    if params.get("container"):
        kwargs["query_params"] = {"container": params["container"]}

    if params.get("since_seconds"):
        kwargs.setdefault("query_params", {}).update(
            {"sinceSeconds": params["since_seconds"]}
        )

    if params.get("previous"):
        kwargs.setdefault("query_params", {}).update({"previous": params["previous"]})

    if params.get("tail_lines"):
        kwargs.setdefault("query_params", {}).update(
            {"tailLines": params["tail_lines"]}
        )

    pod_containers = [None]
    if params.get("all_containers"):
        pod_containers = list_containers_in_pod(svc, resource, namespace, name)

    log = ""
    try:
        for container in pod_containers:
            if container is not None:
                kwargs.setdefault("query_params", {}).update({"container": container})
            response = resource.log.get(
                name=name, namespace=namespace, serialize=False, **kwargs
            )
            log += response.data.decode("utf8")
    except ApiException as exc:
        if exc.reason == "Not Found":
            raise CoreException("Pod {0}/{1} not found.".format(namespace, name))
        raise CoreException(
            "Unable to retrieve log from Pod due to: {0}".format(
                get_exception_message(exc)
            )
        )

    return {"changed": False, "log": log, "log_lines": log.split("\n")}


def extract_selectors(instance):
    # Parses selectors on an object based on the specifications documented here:
    # https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
    selectors = []
    if not instance.spec.selector:
        raise CoreException(
            "{0} {1} does not support the log subresource directly, and no Pod selector was found on the object".format(
                "/".join(instance.group, instance.apiVersion), instance.kind
            )
        )

    if not (
        instance.spec.selector.matchLabels or instance.spec.selector.matchExpressions
    ):
        # A few resources (like DeploymentConfigs) just use a simple key:value style instead of supporting expressions
        for k, v in dict(instance.spec.selector).items():
            selectors.append("{0}={1}".format(k, v))
        return selectors

    if instance.spec.selector.matchLabels:
        for k, v in dict(instance.spec.selector.matchLabels).items():
            selectors.append("{0}={1}".format(k, v))

    if instance.spec.selector.matchExpressions:
        for expression in instance.spec.selector.matchExpressions:
            operator = expression.operator

            if operator == "Exists":
                selectors.append(expression.key)
            elif operator == "DoesNotExist":
                selectors.append("!{0}".format(expression.key))
            elif operator in ["In", "NotIn"]:
                selectors.append(
                    "{key} {operator} {values}".format(
                        key=expression.key,
                        operator=operator.lower(),
                        values="({0})".format(", ".join(expression.values)),
                    )
                )
            else:
                raise CoreException(
                    "The k8s_log module does not support the {0} matchExpression operator".format(
                        operator.lower()
                    )
                )

    return selectors


def main():
    module = AnsibleK8SModule(
        module_class=AnsibleModule,
        argument_spec=argspec(),
        supports_check_mode=True,
        mutually_exclusive=[("container", "all_containers")],
    )

    try:
        client = get_api_client(module=module)
        svc = K8sService(client, module)
        result = execute_module(svc, module.params)
        module.exit_json(**result)
    except CoreException as e:
        module.fail_from_exception(e)


if __name__ == "__main__":
    main()
