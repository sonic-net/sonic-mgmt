#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2020, Red Hat
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

# STARTREMOVE (downstream)
DOCUMENTATION = r"""
module: openshift_route

short_description: Expose a Service as an OpenShift Route.

version_added: "0.3.0"

author: "Fabian von Feilitzsch (@fabianvf)"

description:
  - Looks up a Service and creates a new Route based on it.
  - Analogous to `oc expose` and `oc create route` for creating Routes, but does not support creating Services.
  - For creating Services from other resources, see kubernetes.core.k8s.

extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options
  - kubernetes.core.k8s_wait_options
  - kubernetes.core.k8s_state_options

requirements:
  - "python >= 3.6"
  - "kubernetes >= 12.0.0"
  - "PyYAML >= 3.11"

options:
  service:
    description:
      - The name of the service to expose.
      - Required when I(state) is not absent.
    type: str
    aliases: ['svc']
  namespace:
    description:
      - The namespace of the resource being targeted.
      - The Route will be created in this namespace as well.
    required: yes
    type: str
  labels:
    description:
      - Specify the labels to apply to the created Route.
      - 'A set of key: value pairs.'
    type: dict
  annotations:
    description:
      - Specify the Route Annotations.
      - 'A set of key: value pairs.'
    type: dict
    version_added: "2.1.0"
  name:
    description:
      - The desired name of the Route to be created.
      - Defaults to the value of I(service)
    type: str
  hostname:
    description:
      - The hostname for the Route.
    type: str
  path:
    description:
      - The path for the Route
    type: str
  wildcard_policy:
    description:
      - The wildcard policy for the hostname.
      - Currently only Subdomain is supported.
      - If not provided, the default of None will be used.
    choices:
      - Subdomain
    type: str
  port:
    description:
      - Name or number of the port the Route will route traffic to.
    type: str
  tls:
    description:
      - TLS configuration for the newly created route.
      - Only used when I(termination) is set.
    type: dict
    suboptions:
      ca_certificate:
        description:
          - Path to a CA certificate file on the target host.
          - Not supported when I(termination) is set to passthrough.
        type: str
      certificate:
        description:
          - Path to a certificate file on the target host.
          - Not supported when I(termination) is set to passthrough.
        type: str
      destination_ca_certificate:
        description:
          - Path to a CA certificate file used for securing the connection.
          - Only used when I(termination) is set to reencrypt.
          - Defaults to the Service CA.
        type: str
      key:
        description:
          - Path to a key file on the target host.
          - Not supported when I(termination) is set to passthrough.
        type: str
      insecure_policy:
        description:
          - Sets the InsecureEdgeTerminationPolicy for the Route.
          - Not supported when I(termination) is set to reencrypt.
          - When I(termination) is set to passthrough, only redirect is supported.
          - If not provided, insecure traffic will be disallowed.
        type: str
        choices:
          - allow
          - redirect
          - disallow
        default: disallow
  termination:
    description:
      - The termination type of the Route.
      - If left empty no termination type will be set, and the route will be insecure.
      - When set to insecure I(tls) will be ignored.
    choices:
      - edge
      - passthrough
      - reencrypt
      - insecure
    default: insecure
    type: str
"""

EXAMPLES = r"""
- name: Create hello-world deployment
  community.okd.k8s:
    definition:
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        name: hello-kubernetes
        namespace: default
      spec:
        replicas: 3
        selector:
          matchLabels:
            app: hello-kubernetes
        template:
          metadata:
            labels:
              app: hello-kubernetes
          spec:
            containers:
              - name: hello-kubernetes
                image: paulbouwer/hello-kubernetes:1.8
                ports:
                  - containerPort: 8080

- name: Create Service for the hello-world deployment
  community.okd.k8s:
    definition:
      apiVersion: v1
      kind: Service
      metadata:
        name: hello-kubernetes
        namespace: default
      spec:
        ports:
          - port: 80
            targetPort: 8080
        selector:
          app: hello-kubernetes

- name: Expose the insecure hello-world service externally
  community.okd.openshift_route:
    service: hello-kubernetes
    namespace: default
    insecure_policy: allow
    annotations:
      haproxy.router.openshift.io/balance: roundrobin
  register: route
"""

RETURN = r"""
result:
  description:
    - The Route object that was created or updated. Will be empty in the case of deletion.
  returned: success
  type: complex
  contains:
    apiVersion:
      description: The versioned schema of this representation of an object.
      returned: success
      type: str
    kind:
      description: Represents the REST resource this object represents.
      returned: success
      type: str
    metadata:
      description: Standard object metadata. Includes name, namespace, annotations, labels, etc.
      returned: success
      type: complex
      contains:
          name:
              description: The name of the created Route
              type: str
          namespace:
              description: The namespace of the create Route
              type: str
    spec:
      description: Specification for the Route
      returned: success
      type: complex
      contains:
          host:
              description: Host is an alias/DNS that points to the service.
              type: str
          path:
              description: Path that the router watches for, to route traffic for to the service.
              type: str
          port:
              description: Defines a port mapping from a router to an endpoint in the service endpoints.
              type: complex
              contains:
                  targetPort:
                      description: The target port on pods selected by the service this route points to.
                      type: str
          tls:
              description: Defines config used to secure a route and provide termination.
              type: complex
              contains:
                  caCertificate:
                      description: Provides the cert authority certificate contents.
                      type: str
                  certificate:
                      description: Provides certificate contents.
                      type: str
                  destinationCACertificate:
                      description: Provides the contents of the ca certificate of the final destination.
                      type: str
                  insecureEdgeTerminationPolicy:
                      description: Indicates the desired behavior for insecure connections to a route.
                      type: str
                  key:
                      description: Provides key file contents.
                      type: str
                  termination:
                      description: Indicates termination type.
                      type: str
          to:
              description: Specifies the target that resolve into endpoints.
              type: complex
              contains:
                  kind:
                      description: The kind of target that the route is referring to. Currently, only 'Service' is allowed.
                      type: str
                  name:
                      description: Name of the service/target that is being referred to. e.g. name of the service.
                      type: str
                  weight:
                      description: Specifies the target's relative weight against other target reference objects.
                      type: int
          wildcardPolicy:
              description: Wildcard policy if any for the route.
              type: str
    status:
      description: Current status details for the Route
      returned: success
      type: complex
      contains:
          ingress:
              description: List of places where the route may be exposed.
              type: complex
              contains:
                conditions:
                    description: Array of status conditions for the Route ingress.
                    type: complex
                    contains:
                        type:
                            description: The type of the condition. Currently only 'Ready'.
                            type: str
                        status:
                            description: The status of the condition. Can be True, False, Unknown.
                            type: str
                host:
                    description: The host string under which the route is exposed.
                    type: str
                routerCanonicalHostname:
                    description: The external host name for the router that can be used as a CNAME for the host requested for this route. May not be set.
                    type: str
                routerName:
                    description: A name chosen by the router to identify itself.
                    type: str
                wildcardPolicy:
                    description: The wildcard policy that was allowed where this route is exposed.
                    type: str
duration:
  description: elapsed time of task in seconds
  returned: when C(wait) is true
  type: int
  sample: 48
"""
# ENDREMOVE (downstream)

import copy

from ansible.module_utils._text import to_native

from ansible_collections.community.okd.plugins.module_utils.openshift_common import (
    AnsibleOpenshiftModule,
)

try:
    from ansible_collections.kubernetes.core.plugins.module_utils.k8s.runner import (
        perform_action,
    )
    from ansible_collections.kubernetes.core.plugins.module_utils.k8s.waiter import (
        Waiter,
    )
    from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
        AUTH_ARG_SPEC,
        WAIT_ARG_SPEC,
        COMMON_ARG_SPEC,
    )
except ImportError as e:
    pass
    AUTH_ARG_SPEC = WAIT_ARG_SPEC = COMMON_ARG_SPEC = {}

try:
    from kubernetes.dynamic.exceptions import DynamicApiError, NotFoundError
except ImportError:
    pass


class OpenShiftRoute(AnsibleOpenshiftModule):
    def __init__(self):
        super(OpenShiftRoute, self).__init__(
            argument_spec=self.argspec,
            supports_check_mode=True,
        )

        self.append_hash = False
        self.apply = False
        self.warnings = []
        self.params["merge_type"] = None

    @property
    def argspec(self):
        spec = copy.deepcopy(AUTH_ARG_SPEC)
        spec.update(copy.deepcopy(WAIT_ARG_SPEC))
        spec.update(copy.deepcopy(COMMON_ARG_SPEC))

        spec["service"] = dict(type="str", aliases=["svc"])
        spec["namespace"] = dict(required=True, type="str")
        spec["labels"] = dict(type="dict")
        spec["name"] = dict(type="str")
        spec["hostname"] = dict(type="str")
        spec["path"] = dict(type="str")
        spec["wildcard_policy"] = dict(choices=["Subdomain"], type="str")
        spec["port"] = dict(type="str")
        spec["tls"] = dict(
            type="dict",
            options=dict(
                ca_certificate=dict(type="str"),
                certificate=dict(type="str"),
                destination_ca_certificate=dict(type="str"),
                key=dict(type="str", no_log=False),
                insecure_policy=dict(
                    type="str",
                    choices=["allow", "redirect", "disallow"],
                    default="disallow",
                ),
            ),
        )
        spec["termination"] = dict(
            choices=["edge", "passthrough", "reencrypt", "insecure"], default="insecure"
        )
        spec["annotations"] = dict(type="dict")

        return spec

    def execute_module(self):
        service_name = self.params.get("service")
        namespace = self.params["namespace"]
        termination_type = self.params.get("termination")
        if termination_type == "insecure":
            termination_type = None
        state = self.params.get("state")

        if state != "absent" and not service_name:
            self.fail_json("If 'state' is not 'absent' then 'service' must be provided")

        # We need to do something a little wonky to wait if the user doesn't supply a custom condition
        custom_wait = (
            self.params.get("wait")
            and not self.params.get("wait_condition")
            and state != "absent"
        )
        if custom_wait:
            # Don't use default wait logic in perform_action
            self.params["wait"] = False

        route_name = self.params.get("name") or service_name
        labels = self.params.get("labels")
        hostname = self.params.get("hostname")
        path = self.params.get("path")
        wildcard_policy = self.params.get("wildcard_policy")
        port = self.params.get("port")
        annotations = self.params.get("annotations")

        if termination_type and self.params.get("tls"):
            tls_ca_cert = self.params["tls"].get("ca_certificate")
            tls_cert = self.params["tls"].get("certificate")
            tls_dest_ca_cert = self.params["tls"].get("destination_ca_certificate")
            tls_key = self.params["tls"].get("key")
            tls_insecure_policy = self.params["tls"].get("insecure_policy")
            if tls_insecure_policy == "disallow":
                tls_insecure_policy = None
        else:
            tls_ca_cert = tls_cert = tls_dest_ca_cert = tls_key = (
                tls_insecure_policy
            ) = None

        route = {
            "apiVersion": "route.openshift.io/v1",
            "kind": "Route",
            "metadata": {
                "name": route_name,
                "namespace": namespace,
                "labels": labels,
            },
            "spec": {},
        }

        if annotations:
            route["metadata"]["annotations"] = annotations

        if state != "absent":
            route["spec"] = self.build_route_spec(
                service_name,
                namespace,
                port=port,
                wildcard_policy=wildcard_policy,
                hostname=hostname,
                path=path,
                termination_type=termination_type,
                tls_insecure_policy=tls_insecure_policy,
                tls_ca_cert=tls_ca_cert,
                tls_cert=tls_cert,
                tls_key=tls_key,
                tls_dest_ca_cert=tls_dest_ca_cert,
            )

        result = perform_action(self.svc, route, self.params)
        timeout = self.params.get("wait_timeout")
        sleep = self.params.get("wait_sleep")
        if custom_wait:
            v1_routes = self.find_resource("Route", "route.openshift.io/v1", fail=True)
            waiter = Waiter(self.client, v1_routes, wait_predicate)
            success, result["result"], result["duration"] = waiter.wait(
                timeout=timeout, sleep=sleep, name=route_name, namespace=namespace
            )

        self.exit_json(**result)

    def build_route_spec(
        self,
        service_name,
        namespace,
        port=None,
        wildcard_policy=None,
        hostname=None,
        path=None,
        termination_type=None,
        tls_insecure_policy=None,
        tls_ca_cert=None,
        tls_cert=None,
        tls_key=None,
        tls_dest_ca_cert=None,
    ):
        v1_services = self.find_resource("Service", "v1", fail=True)
        try:
            target_service = v1_services.get(name=service_name, namespace=namespace)
        except NotFoundError:
            if not port:
                self.fail_json(
                    msg="You need to provide the 'port' argument when exposing a non-existent service"
                )
            target_service = None
        except DynamicApiError as exc:
            self.fail_json(
                msg="Failed to retrieve service to be exposed: {0}".format(exc.body),
                error=exc.status,
                status=exc.status,
                reason=exc.reason,
            )
        except Exception as exc:
            self.fail_json(
                msg="Failed to retrieve service to be exposed: {0}".format(
                    to_native(exc)
                ),
                error="",
                status="",
                reason="",
            )

        route_spec = {
            "tls": {},
            "to": {
                "kind": "Service",
                "name": service_name,
            },
            "port": {
                "targetPort": self.set_port(target_service, port),
            },
            "wildcardPolicy": wildcard_policy,
        }

        # Want to conditionally add these so we don't overwrite what is automically added when nothing is provided
        if termination_type:
            route_spec["tls"] = dict(termination=termination_type.capitalize())
            if tls_insecure_policy:
                if termination_type == "edge":
                    route_spec["tls"][
                        "insecureEdgeTerminationPolicy"
                    ] = tls_insecure_policy.capitalize()
                elif termination_type == "passthrough":
                    if tls_insecure_policy != "redirect":
                        self.fail_json(
                            "'redirect' is the only supported insecureEdgeTerminationPolicy for passthrough routes"
                        )
                    route_spec["tls"][
                        "insecureEdgeTerminationPolicy"
                    ] = tls_insecure_policy.capitalize()
                elif termination_type == "reencrypt":
                    self.fail_json(
                        "'tls.insecure_policy' is not supported with reencrypt routes"
                    )
            else:
                route_spec["tls"]["insecureEdgeTerminationPolicy"] = None
            if tls_ca_cert:
                if termination_type == "passthrough":
                    self.fail_json(
                        "'tls.ca_certificate' is not supported with passthrough routes"
                    )
                route_spec["tls"]["caCertificate"] = tls_ca_cert
            if tls_cert:
                if termination_type == "passthrough":
                    self.fail_json(
                        "'tls.certificate' is not supported with passthrough routes"
                    )
                route_spec["tls"]["certificate"] = tls_cert
            if tls_key:
                if termination_type == "passthrough":
                    self.fail_json("'tls.key' is not supported with passthrough routes")
                route_spec["tls"]["key"] = tls_key
            if tls_dest_ca_cert:
                if termination_type != "reencrypt":
                    self.fail_json(
                        "'destination_certificate' is only valid for reencrypt routes"
                    )
                route_spec["tls"]["destinationCACertificate"] = tls_dest_ca_cert
        else:
            route_spec["tls"] = None
        if hostname:
            route_spec["host"] = hostname
        if path:
            route_spec["path"] = path

        return route_spec

    def set_port(self, service, port_arg):
        if port_arg:
            return port_arg
        for p in service.spec.ports:
            if p.protocol == "TCP":
                if p.name is not None:
                    return p.name
                return p.targetPort
        return None


def wait_predicate(route):
    if not (route.status and route.status.ingress):
        return False
    for ingress in route.status.ingress:
        match = [x for x in ingress.conditions if x.type == "Admitted"]
        if not match:
            return False
        match = match[0]
        if match.status != "True":
            return False
    return True


def main():
    OpenShiftRoute().run_module()


if __name__ == "__main__":
    main()
