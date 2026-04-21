import time
from functools import partial
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, Union

from ansible.module_utils.parsing.convert_bool import boolean
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.exceptions import (
    CoreException,
)

try:
    from kubernetes.dynamic.exceptions import NotFoundError
    from kubernetes.dynamic.resource import Resource, ResourceField, ResourceInstance
except ImportError:
    # These are defined only for the sake of Ansible's checked import requirement
    Resource = Any  # type: ignore
    ResourceInstance = Any  # type: ignore
    pass

try:
    from urllib3.exceptions import HTTPError
except ImportError:
    # Handled during module setup
    pass


def deployment_ready(deployment: ResourceInstance) -> bool:
    # FIXME: frustratingly bool(deployment.status) is True even if status is empty
    # Furthermore deployment.status.availableReplicas == deployment.status.replicas == None if status is empty
    # deployment.status.replicas is None is perfectly ok if desired replicas == 0
    # Scaling up means that we also need to check that we're not in a
    # situation where status.replicas == status.availableReplicas
    # but spec.replicas != status.replicas
    return bool(
        deployment.status
        and deployment.spec.replicas == (deployment.status.replicas or 0)
        and deployment.status.availableReplicas == deployment.status.replicas
        and deployment.status.observedGeneration == deployment.metadata.generation
        and not deployment.status.unavailableReplicas
    )


def pod_ready(pod: ResourceInstance) -> bool:
    return bool(
        pod.status
        and pod.status.containerStatuses is not None
        and all(container.ready for container in pod.status.containerStatuses)
    )


def daemonset_ready(daemonset: ResourceInstance) -> bool:
    return bool(
        daemonset.status
        and daemonset.status.desiredNumberScheduled is not None
        and (daemonset.status.updatedNumberScheduled or 0)
        == daemonset.status.desiredNumberScheduled
        and daemonset.status.numberReady == daemonset.status.desiredNumberScheduled
        and daemonset.status.observedGeneration == daemonset.metadata.generation
        and not daemonset.status.unavailableReplicas
    )


def statefulset_ready(statefulset: ResourceInstance) -> bool:
    if statefulset.spec.updateStrategy.type == "OnDelete":
        return bool(
            statefulset.status
            and statefulset.status.observedGeneration
            == (statefulset.metadata.generation or 0)
            and statefulset.status.replicas == statefulset.spec.replicas
        )
    # These may be None
    updated_replicas = statefulset.status.updatedReplicas or 0
    ready_replicas = statefulset.status.readyReplicas or 0
    return bool(
        statefulset.status
        and statefulset.spec.updateStrategy.type == "RollingUpdate"
        and statefulset.status.observedGeneration
        == (statefulset.metadata.generation or 0)
        and statefulset.status.updateRevision == statefulset.status.currentRevision
        and updated_replicas == statefulset.spec.replicas
        and ready_replicas == statefulset.spec.replicas
        and statefulset.status.replicas == statefulset.spec.replicas
    )


def custom_condition(condition: Dict, resource: ResourceInstance) -> bool:
    if not resource.status or not resource.status.conditions:
        return False
    matches = [x for x in resource.status.conditions if x.type == condition["type"]]
    if not matches:
        return False
    # There should never be more than one condition of a specific type
    match: ResourceField = matches[0]
    if match.status == "Unknown":
        if match.status == condition["status"]:
            if "reason" not in condition:
                return True
            if condition["reason"]:
                return match.reason == condition["reason"]
        return False
    status = True if match.status == "True" else False
    if status == boolean(condition["status"], strict=False):
        if condition.get("reason"):
            return match.reason == condition["reason"]
        return True
    return False


def resource_absent(resource: ResourceInstance) -> bool:
    return not exists(resource)


def exists(resource: Optional[ResourceInstance]) -> bool:
    """Simple predicate to check for existence of a resource.

    While a List type resource technically always exists, this will only return
    true if the List contains items."""
    return bool(resource) and not empty_list(resource)


def cluster_operator_ready(resource: ResourceInstance) -> bool:
    """
    Predicate to check if a single ClusterOperator is healthy.
    Returns True if:
      - "Available" is True
      - "Degraded" is False
      - "Progressing" is False
    """
    if not resource:
        return False

    # Extract conditions from the resource's status
    conditions = resource.get("status", {}).get("conditions", [])

    status = {x.get("type", ""): x.get("status") for x in conditions}
    return (
        (status.get("Degraded") == "False")
        and (status.get("Progressing") == "False")
        and (status.get("Available") == "True")
    )


RESOURCE_PREDICATES = {
    "DaemonSet": daemonset_ready,
    "Deployment": deployment_ready,
    "Pod": pod_ready,
    "StatefulSet": statefulset_ready,
    "ClusterOperator": cluster_operator_ready,
}


def empty_list(resource: ResourceInstance) -> bool:
    return resource["kind"].endswith("List") and not resource.get("items")


def clock(total: int, interval: int) -> Iterator[int]:
    start = time.monotonic()
    yield 0
    while (time.monotonic() - start) < total:
        time.sleep(interval)
        yield int(time.monotonic() - start)


class Waiter:
    def __init__(
        self, client, resource: Resource, predicate: Callable[[ResourceInstance], bool]
    ):
        self.client = client
        self.resource = resource
        self.predicate = predicate

    def wait(
        self,
        timeout: int,
        sleep: int,
        name: Optional[str] = None,
        namespace: Optional[str] = None,
        label_selectors: Optional[List[str]] = None,
        field_selectors: Optional[List[str]] = None,
    ) -> Tuple[bool, Dict, int]:
        params = {}

        if name:
            params["name"] = name

        if namespace:
            params["namespace"] = namespace

        if label_selectors:
            params["label_selector"] = ",".join(label_selectors)

        if field_selectors:
            params["field_selector"] = ",".join(field_selectors)

        instance = {}
        response = None
        elapsed = 0
        for i in clock(timeout, sleep):
            exception = None
            elapsed = i
            try:
                response = self.client.get(self.resource, **params)
            except NotFoundError:
                response = None
            # Retry connection errors as it may be intermittent network issues
            except HTTPError as e:
                exception = e
            if self.predicate(response):
                break
        if exception:
            msg = (
                "Exception '{0}' raised while trying to get resource using {1}".format(
                    exception, params
                )
            )
            raise CoreException(msg) from exception
        if response:
            instance = response.to_dict()
        return self.predicate(response), instance, elapsed


class DummyWaiter:
    """A no-op waiter that simply returns the item being waited on.

    No API call will be made with this waiter; the function returns
    immediately. This waiter is useful for waiting on resource instances in
    check mode, for example.
    """

    def wait(
        self,
        definition: Dict,
        timeout: int,
        sleep: int,
        label_selectors: Optional[List[str]] = None,
    ) -> Tuple[bool, Optional[Dict], int]:
        return True, definition, 0


# The better solution would be typing.Protocol, but this is only in 3.8+
SupportsWait = Union[Waiter, DummyWaiter]


def get_waiter(
    client,
    resource: Resource,
    state: str = "present",
    condition: Optional[Dict] = None,
    check_mode: Optional[bool] = False,
) -> SupportsWait:
    """Create a Waiter object based on the specified resource.

    This is a convenience method for creating a waiter from a resource.
    Based on the arguments and the kind of resource, an appropriate waiter
    will be returned. A waiter can also be created directly, of course.
    """
    if check_mode:
        return DummyWaiter()
    if state == "present":
        if condition:
            predicate: Callable[[ResourceInstance], bool] = partial(
                custom_condition, condition
            )
        else:
            predicate = RESOURCE_PREDICATES.get(resource.kind, exists)
    else:
        predicate = resource_absent
    return Waiter(client, resource, predicate)
