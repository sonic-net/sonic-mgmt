#!/usr/bin/env python

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from datetime import datetime, timezone

from ansible.module_utils._text import to_native

from ansible_collections.community.okd.plugins.module_utils.openshift_common import (
    AnsibleOpenshiftModule,
)

try:
    from kubernetes import client
    from kubernetes.dynamic.exceptions import DynamicApiError
except ImportError as e:
    pass


def get_deploymentconfig_for_replicationcontroller(replica_controller):
    # DeploymentConfigAnnotation is an annotation name used to correlate a deployment with the
    # DeploymentConfig on which the deployment is based.
    # This is set on replication controller pod template by deployer controller.
    DeploymentConfigAnnotation = "openshift.io/deployment-config.name"
    try:
        deploymentconfig_name = replica_controller["metadata"]["annotations"].get(
            DeploymentConfigAnnotation
        )
        if deploymentconfig_name is None or deploymentconfig_name == "":
            return None
        return deploymentconfig_name
    except Exception:
        return None


class OpenShiftAdmPruneDeployment(AnsibleOpenshiftModule):
    def __init__(self, **kwargs):
        super(OpenShiftAdmPruneDeployment, self).__init__(**kwargs)

    def filter_replication_controller(self, replicacontrollers):
        def _deployment(obj):
            return get_deploymentconfig_for_replicationcontroller(obj) is not None

        def _zeroReplicaSize(obj):
            return obj["spec"]["replicas"] == 0 and obj["status"]["replicas"] == 0

        def _complete_failed(obj):
            DeploymentStatusAnnotation = "openshift.io/deployment.phase"
            try:
                # validate that replication controller status is either 'Complete' or 'Failed'
                deployment_phase = obj["metadata"]["annotations"].get(
                    DeploymentStatusAnnotation
                )
                return deployment_phase in ("Failed", "Complete")
            except Exception:
                return False

        def _younger(obj):
            creation_timestamp = datetime.strptime(
                obj["metadata"]["creationTimestamp"], "%Y-%m-%dT%H:%M:%SZ"
            )
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            age = (now - creation_timestamp).seconds / 60
            return age > self.params["keep_younger_than"]

        def _orphan(obj):
            try:
                # verify if the deploymentconfig associated to the replication controller is still existing
                deploymentconfig_name = get_deploymentconfig_for_replicationcontroller(
                    obj
                )
                params = dict(
                    kind="DeploymentConfig",
                    api_version="apps.openshift.io/v1",
                    name=deploymentconfig_name,
                    namespace=obj["metadata"]["name"],
                )
                exists = self.kubernetes_facts(**params)
                return not (exists.get["api_found"] and len(exists["resources"]) > 0)
            except Exception:
                return False

        predicates = [_deployment, _zeroReplicaSize, _complete_failed]
        if self.params["orphans"]:
            predicates.append(_orphan)
        if self.params["keep_younger_than"]:
            predicates.append(_younger)

        results = replicacontrollers.copy()
        for pred in predicates:
            results = filter(pred, results)
        return list(results)

    def execute_module(self):
        # list replicationcontroller candidate for pruning
        kind = "ReplicationController"
        api_version = "v1"
        resource = self.find_resource(kind=kind, api_version=api_version, fail=True)

        # Get ReplicationController
        params = dict(
            kind=kind,
            api_version="v1",
            namespace=self.params.get("namespace"),
        )
        candidates = self.kubernetes_facts(**params)
        candidates = self.filter_replication_controller(candidates["resources"])

        if len(candidates) == 0:
            self.exit_json(changed=False, replication_controllers=[])

        changed = True
        delete_options = client.V1DeleteOptions(propagation_policy="Background")
        replication_controllers = []
        for replica in candidates:
            try:
                result = replica
                if not self.check_mode:
                    name = replica["metadata"]["name"]
                    namespace = replica["metadata"]["namespace"]
                    result = resource.delete(
                        name=name, namespace=namespace, body=delete_options
                    ).to_dict()
                replication_controllers.append(result)
            except DynamicApiError as exc:
                msg = "Failed to delete ReplicationController {namespace}/{name} due to: {msg}".format(
                    namespace=namespace, name=name, msg=exc.body
                )
                self.fail_json(msg=msg)
            except Exception as e:
                msg = "Failed to delete ReplicationController {namespace}/{name} due to: {msg}".format(
                    namespace=namespace, name=name, msg=to_native(e)
                )
                self.fail_json(msg=msg)
        self.exit_json(changed=changed, replication_controllers=replication_controllers)
