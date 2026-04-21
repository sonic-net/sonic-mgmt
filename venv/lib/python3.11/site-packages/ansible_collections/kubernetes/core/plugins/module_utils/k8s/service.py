# Copyright: (c) 2021, Red Hat | Ansible
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import copy
from json import loads
from re import compile
from typing import Any, Dict, List, Optional, Tuple, Union

from ansible.module_utils.common.dict_transformations import dict_merge
from ansible_collections.kubernetes.core.plugins.module_utils.hashes import (
    generate_hash,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.core import requires
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.exceptions import (
    CoreException,
)
from ansible_collections.kubernetes.core.plugins.module_utils.k8s.waiter import (
    Waiter,
    exists,
    get_waiter,
    resource_absent,
)

try:
    from kubernetes.dynamic.exceptions import (
        BadRequestError,
        ConflictError,
        ForbiddenError,
        MethodNotAllowedError,
        NotFoundError,
        ResourceNotFoundError,
        ResourceNotUniqueError,
    )
except ImportError:
    # Handled in module setup
    pass

try:
    from kubernetes.dynamic.resource import Resource, ResourceInstance
except ImportError:
    # These are defined only for the sake of Ansible's checked import requirement
    Resource = Any  # type: ignore
    ResourceInstance = Any  # type: ignore

try:
    from ansible_collections.kubernetes.core.plugins.module_utils.apply import (
        apply_object,
    )
except ImportError:
    # Handled in module setup
    pass

try:
    from ansible_collections.kubernetes.core.plugins.module_utils.apply import (
        recursive_diff,
    )
except ImportError:
    from ansible.module_utils.common.dict_transformations import recursive_diff


try:
    from ansible_collections.kubernetes.core.plugins.module_utils.common import (
        _encode_stringdata,
    )
except ImportError:
    # Handled in module setup
    pass


class K8sService:
    """A Service class for K8S modules.
    This class has the primary purpose is to perform work on the cluster (e.g., create, apply, replace, update, delete).
    """

    def __init__(self, client, module) -> None:
        self.client = client
        self.module = module

    @property
    def _client_side_dry_run(self):
        return self.module.check_mode and not self.client.dry_run

    def find_resource(
        self, kind: str, api_version: str, fail: bool = False
    ) -> Optional[Resource]:
        try:
            return self.client.resource(kind, api_version)
        except (ResourceNotFoundError, ResourceNotUniqueError):
            if fail:
                raise CoreException(
                    "Failed to find exact match for %s.%s by [kind, name, singularName, shortNames]"
                    % (api_version, kind)
                )

    def wait(
        self, resource: Resource, instance: Dict
    ) -> Tuple[bool, Optional[Dict], int]:
        wait_sleep = self.module.params.get("wait_sleep")
        wait_timeout = self.module.params.get("wait_timeout")
        wait_condition = None
        if self.module.params.get("wait_condition") and self.module.params[
            "wait_condition"
        ].get("type"):
            wait_condition = self.module.params["wait_condition"]
        state = "present"
        if self.module.params.get("state") == "absent":
            state = "absent"
        label_selectors = self.module.params.get("label_selectors")

        waiter = get_waiter(
            self.client, resource, condition=wait_condition, state=state
        )
        return waiter.wait(
            timeout=wait_timeout,
            sleep=wait_sleep,
            name=instance["metadata"].get("name"),
            namespace=instance["metadata"].get("namespace"),
            label_selectors=label_selectors,
        )

    def create_project_request(self, definition: Dict) -> Dict:
        definition["kind"] = "ProjectRequest"
        results = {"changed": False, "result": {}}
        resource = self.find_resource(
            "ProjectRequest", definition["apiVersion"], fail=True
        )
        if not self.module.check_mode:
            try:
                k8s_obj = self.client.create(resource, definition)
                results["result"] = k8s_obj.to_dict()
            except Exception as e:
                reason = e.body if hasattr(e, "body") else e
                msg = "Failed to create object: {0}".format(reason)
                raise CoreException(msg) from e

        results["changed"] = True

        return results

    def patch_resource(
        self,
        resource: Resource,
        definition: Dict,
        name: str,
        namespace: str,
        merge_type: str = None,
    ) -> Tuple[Dict, List[str]]:
        try:
            params = dict(name=name, namespace=namespace, serialize=False)
            if merge_type:
                params["content_type"] = "application/{0}-patch+json".format(merge_type)
            return decode_response(self.client.patch(resource, definition, **params))
        except Exception as e:
            reason = e.body if hasattr(e, "body") else e
            msg = "Failed to patch object: {0}".format(reason)
            raise CoreException(msg) from e

    def retrieve(self, resource: Resource, definition: Dict) -> ResourceInstance:
        state = self.module.params.get("state", None)
        append_hash = self.module.params.get("append_hash", False)
        name = definition["metadata"].get("name")
        generate_name = definition["metadata"].get("generateName")
        namespace = definition["metadata"].get("namespace")
        label_selectors = self.module.params.get("label_selectors")
        existing: ResourceInstance = None

        try:
            # ignore append_hash for resources other than ConfigMap and Secret
            if append_hash and definition["kind"] in ["ConfigMap", "Secret"]:
                if name:
                    name = "%s-%s" % (name, generate_hash(definition))
                    definition["metadata"]["name"] = name
                elif generate_name:
                    definition["metadata"]["generateName"] = "%s-%s" % (
                        generate_name,
                        generate_hash(definition),
                    )
            params = {}
            if name:
                params["name"] = name
            if namespace:
                params["namespace"] = namespace
            if label_selectors:
                params["label_selector"] = ",".join(label_selectors)
            if "name" in params or "label_selector" in params:
                existing = self.client.get(resource, **params)
        except (NotFoundError, MethodNotAllowedError):
            pass
        except ForbiddenError as e:
            if (
                definition["kind"] in ["Project", "ProjectRequest"]
                and state != "absent"
            ):
                return self.create_project_request(definition)
            reason = e.body if hasattr(e, "body") else e
            msg = "Failed to retrieve requested object: {0}".format(reason)
            raise CoreException(msg) from e
        except Exception as e:
            reason = e.body if hasattr(e, "body") else e
            msg = "Failed to retrieve requested object: {0}".format(reason)
            raise CoreException(msg) from e

        return existing

    def retrieve_all(
        self, resource: Resource, namespace: str, label_selectors: List[str] = None
    ) -> List[Dict]:
        definitions: List[ResourceInstance] = []

        try:
            params = dict(namespace=namespace)
            if label_selectors:
                params["label_selector"] = ",".join(label_selectors)
            resource_list = self.client.get(resource, **params)
            for item in resource_list.items:
                existing = self.client.get(
                    resource, name=item.metadata.name, namespace=namespace
                )
                definitions.append(existing.to_dict())
        except (NotFoundError, MethodNotAllowedError):
            pass
        except Exception as e:
            reason = e.body if hasattr(e, "body") else e
            msg = "Failed to retrieve requested object: {0}".format(reason)
            raise CoreException(msg) from e

        return definitions

    def find(
        self,
        kind: str,
        api_version: str,
        name: str = None,
        namespace: Optional[str] = None,
        label_selectors: Optional[List[str]] = None,
        field_selectors: Optional[List[str]] = None,
        wait: Optional[bool] = False,
        wait_sleep: Optional[int] = 5,
        wait_timeout: Optional[int] = 120,
        state: Optional[str] = "present",
        condition: Optional[Dict] = None,
        hidden_fields: Optional[List] = None,
    ) -> Dict:
        resource = self.find_resource(kind, api_version)
        api_found = bool(resource)
        if not api_found:
            return dict(
                resources=[],
                msg='Failed to find API for resource with apiVersion "{0}" and kind "{1}"'.format(
                    api_version, kind
                ),
                api_found=False,
            )

        if not label_selectors:
            label_selectors = []
        if not field_selectors:
            field_selectors = []

        result = {"resources": [], "api_found": True}

        # With a timeout of 0 the waiter will do a single check and return, effectively not waiting.
        if not wait:
            wait_timeout = 0

        if state == "present":
            predicate = exists
        else:
            predicate = resource_absent

        waiter = Waiter(self.client, resource, predicate)

        # This is an initial check to get the resource or resources that we then need to wait on individually.
        try:
            success, resources, duration = waiter.wait(
                timeout=wait_timeout,
                sleep=wait_sleep,
                name=name,
                namespace=namespace,
                label_selectors=label_selectors,
                field_selectors=field_selectors,
            )
        except BadRequestError:
            return result
        except CoreException as e:
            raise e
        except Exception as e:
            raise CoreException(
                "Exception '{0}' raised while trying to get resource using (name={1}, namespace={2}, label_selectors={3}, field_selectors={4})".format(
                    e, name, namespace, label_selectors, field_selectors
                )
            )

        # There is either no result or there is a List resource with no items
        if (
            not resources
            or resources["kind"].endswith("List")
            and not resources.get("items")
        ):
            return result

        instances = resources.get("items") or [resources]

        if not wait:
            result["resources"] = [
                hide_fields(instance, hidden_fields) for instance in instances
            ]
            return result

        # Now wait for the specified state of any resource instances we have found.
        waiter = get_waiter(self.client, resource, state=state, condition=condition)
        for instance in instances:
            name = instance["metadata"].get("name")
            namespace = instance["metadata"].get("namespace")
            success, res, duration = waiter.wait(
                timeout=wait_timeout,
                sleep=wait_sleep,
                name=name,
                namespace=namespace,
            )
            if not success:
                raise CoreException(
                    "Failed to gather information about %s(s) even"
                    " after waiting for %s seconds" % (res.get("kind"), duration)
                )
            result["resources"].append(hide_fields(res, hidden_fields))
        return result

    def create(self, resource: Resource, definition: Dict) -> Tuple[Dict, List[str]]:
        namespace = definition["metadata"].get("namespace")
        name = definition["metadata"].get("name")

        if self._client_side_dry_run:
            return _encode_stringdata(definition), []

        try:
            return decode_response(
                self.client.create(
                    resource, definition, namespace=namespace, serialize=False
                )
            )
        except ConflictError:
            # Some resources, like ProjectRequests, can't be created multiple times,
            # because the resources that they create don't match their kind
            # In this case we'll mark it as unchanged and warn the user
            self.module.warn(
                "{0} was not found, but creating it returned a 409 Conflict error. This can happen \
                        if the resource you are creating does not directly create a resource of the same kind.".format(
                    name
                )
            )
            return dict(), []
        except Exception as e:
            reason = e.body if hasattr(e, "body") else e
            msg = "Failed to create object: {0}".format(reason)
            raise CoreException(msg) from e

    def apply(
        self,
        resource: Resource,
        definition: Dict,
        existing: Optional[ResourceInstance] = None,
    ) -> Tuple[Dict, List[str]]:
        namespace = definition["metadata"].get("namespace")

        server_side_apply = self.module.params.get("server_side_apply")
        if server_side_apply:
            requires("kubernetes", "19.15.0", reason="to use server side apply")

        if self._client_side_dry_run:
            ignored, patch = apply_object(resource, _encode_stringdata(definition))
            if existing:
                return dict_merge(existing.to_dict(), patch), []
            else:
                return patch, []

        try:
            params = {}
            if server_side_apply:
                params["server_side"] = True
                params.update(server_side_apply)
            return decode_response(
                self.client.apply(
                    resource, definition, namespace=namespace, serialize=False, **params
                )
            )
        except Exception as e:
            reason = e.body if hasattr(e, "body") else e
            msg = "Failed to apply object: {0}".format(reason)
            raise CoreException(msg) from e

    def replace(
        self,
        resource: Resource,
        definition: Dict,
        existing: ResourceInstance,
    ) -> Tuple[Dict, List[str]]:
        append_hash = self.module.params.get("append_hash", False)
        name = definition["metadata"].get("name")
        namespace = definition["metadata"].get("namespace")

        if self._client_side_dry_run:
            return _encode_stringdata(definition), []

        try:
            return decode_response(
                self.client.replace(
                    resource,
                    definition,
                    name=name,
                    namespace=namespace,
                    append_hash=append_hash,
                    serialize=False,
                )
            )
        except Exception as e:
            reason = e.body if hasattr(e, "body") else e
            msg = "Failed to replace object: {0}".format(reason)
            raise CoreException(msg) from e

    def update(
        self, resource: Resource, definition: Dict, existing: ResourceInstance
    ) -> Tuple[Dict, List[str]]:
        name = definition["metadata"].get("name")
        namespace = definition["metadata"].get("namespace")

        if self._client_side_dry_run:
            return dict_merge(existing.to_dict(), _encode_stringdata(definition)), []

        exception = None
        for merge_type in self.module.params.get("merge_type") or [
            "strategic-merge",
            "merge",
        ]:
            try:
                return self.patch_resource(
                    resource,
                    definition,
                    name,
                    namespace,
                    merge_type=merge_type,
                )
            except CoreException as e:
                exception = e
                continue
        raise exception

    def delete(
        self,
        resource: Resource,
        definition: Dict,
        existing: Optional[ResourceInstance] = None,
    ) -> Dict:
        delete_options = self.module.params.get("delete_options")
        label_selectors = self.module.params.get("label_selectors")
        name = definition["metadata"].get("name")
        namespace = definition["metadata"].get("namespace")
        params = {}

        if not exists(existing):
            return {}

        # Delete the object
        if self._client_side_dry_run:
            return {}

        if name:
            params["name"] = name

        if namespace:
            params["namespace"] = namespace

        if label_selectors:
            params["label_selector"] = ",".join(label_selectors)

        if delete_options and not self.module.check_mode:
            body = {
                "apiVersion": "v1",
                "kind": "DeleteOptions",
            }
            body.update(delete_options)
            params["body"] = body

        try:
            k8s_obj = self.client.delete(resource, **params).to_dict()
        except Exception as e:
            reason = e.body if hasattr(e, "body") else e
            msg = "Failed to delete object: {0}".format(reason)
            raise CoreException(msg) from e
        return k8s_obj


def diff_objects(
    existing: Dict, new: Dict, hidden_fields: Optional[list] = None
) -> Tuple[bool, Dict]:
    result = {}
    diff = recursive_diff(existing, new)
    if not diff:
        return True, result

    result["before"] = hide_fields(diff[0], hidden_fields)
    result["after"] = hide_fields(diff[1], hidden_fields)

    if list(result["after"].keys()) == ["metadata"] and list(
        result["before"].keys()
    ) == ["metadata"]:
        # If only metadata.generation and metadata.resourceVersion changed, ignore it
        ignored_keys = set(["generation", "resourceVersion"])

        if set(result["after"]["metadata"].keys()).issubset(ignored_keys) and set(
            result["before"]["metadata"].keys()
        ).issubset(ignored_keys):
            return True, result

    return False, result


def hide_field_tree(hidden_field: str) -> List[str]:
    result = []
    key, rest = hide_field_split2(hidden_field)
    result.append(key)
    while rest:
        key, rest = hide_field_split2(rest)
        result.append(key)

    return result


def build_hidden_field_tree(hidden_fields: List[str]) -> Dict[str, Any]:
    """Group hidden field targeting the same json key
    Example:
        Input: ['env[3]', 'env[0]']
        Output: {'env': [0, 3]}
    """
    output = {}
    for hidden_field in hidden_fields:
        current = output
        tree = hide_field_tree(hidden_field)
        for idx, key in enumerate(tree):
            if current.get(key, "") is None:
                break
            if idx == (len(tree) - 1):
                current[key] = None
            elif key not in current:
                current[key] = {}
            current = current[key]
    return output


# hide_field should be able to cope with simple or more complicated
# field definitions
# e.g. status or metadata.managedFields or
# spec.template.spec.containers[0].env[3].value or
# metadata.annotations[kubectl.kubernetes.io/last-applied-configuration]
def hide_field(
    definition: Union[Dict[str, Any], List[Any]], hidden_field: Dict[str, Any]
) -> Dict[str, Any]:
    def dict_contains_key(obj: Dict[str, Any], key: str) -> bool:
        return key in obj

    def list_contains_key(obj: List[Any], key: str) -> bool:
        return int(key) < len(obj)

    hidden_keys = list(hidden_field.keys())
    field_contains_key = dict_contains_key
    field_get_key = str
    if isinstance(definition, list):
        # Sort with reverse=true so that when we delete an item from the list, the order is not changed
        hidden_keys = sorted(
            [k for k in hidden_field.keys() if k.isdecimal()], reverse=True
        )
        field_contains_key = list_contains_key
        field_get_key = int

    for key in hidden_keys:
        if field_contains_key(definition, key):
            value = hidden_field.get(key)
            convert_key = field_get_key(key)
            if value is None:
                del definition[convert_key]
            else:
                definition[convert_key] = hide_field(definition[convert_key], value)
                if (
                    definition[convert_key] == dict()
                    or definition[convert_key] == list()
                ):
                    del definition[convert_key]

    return definition


def hide_fields(
    definition: Dict[str, Any], hidden_fields: Optional[List[str]]
) -> Dict[str, Any]:
    if not hidden_fields:
        return definition
    result = copy.deepcopy(definition)
    hidden_field_tree = build_hidden_field_tree(hidden_fields)
    return hide_field(result, hidden_field_tree)


def decode_response(resp) -> Tuple[Dict, List[str]]:
    """
    This function decodes unserialized responses from the Kubernetes python
    client and decodes the RFC2616 14.46 warnings found in the response
    headers.
    """
    obj = ResourceInstance(None, loads(resp.data.decode("utf8"))).to_dict()
    warnings = []
    if (
        resp.headers is not None
        and "warning" in resp.headers
        and resp.headers["warning"] is not None
    ):
        warnings = resp.headers["warning"].split(", ")
    return obj, decode_warnings(warnings)


def decode_warnings(warnings: str) -> List[str]:
    """
    This function decodes RFC2616 14.46 warnings in a simplified way, where
    only the warn-texts are returned in a list.
    """
    p = compile('\\d{3} .+ (".+")')

    decoded = []
    for warning in warnings:
        m = p.match(warning)
        if m:
            try:
                parsed, unused = parse_quoted_string(m.group(1))
                decoded.append(parsed)
            except ValueError:
                continue

    return decoded


def parse_quoted_string(quoted_string: str) -> Tuple[str, str]:
    """
    This function was adapted from:
    https://github.com/kubernetes/apimachinery/blob/bb8822152cabfb4f34dbc26270f874ce53db50de/pkg/util/net/http.go#L609
    """
    if len(quoted_string) == 0:
        raise ValueError("invalid quoted string: 0-length")

    if quoted_string[0] != '"':
        raise ValueError("invalid quoted string: missing initial quote")

    quoted_string = quoted_string[1:]
    remainder = ""
    escaping = False
    closed_quote = False
    result = []

    for i, b in enumerate(quoted_string):
        if b == '"':
            if escaping:
                result.append(b)
                escaping = False
            else:
                closed_quote = True
                remainder_start = i + 1
                remainder = quoted_string[remainder_start:].strip()
                break
        elif b == "\\":
            if escaping:
                result.append(b)
                escaping = False
            else:
                escaping = True
        else:
            result.append(b)
            escaping = False

    if not closed_quote:
        raise ValueError("invalid quoted string: missing closing quote")

    return "".join(result), remainder


# hide_field_split2 returns the first key in hidden_field and the rest of the hidden_field
# We expect the first key to either be in brackets, to be terminated by the start of a left
# bracket, or to be terminated by a dot.

# examples would be:
# field.another.next -> (field, another.next)
# field[key].value -> (field, [key].value)
# [key].value -> (key, value)
# [one][two] -> (one, [two])


def hide_field_split2(hidden_field: str) -> Tuple[str, str]:
    lbracket = hidden_field.find("[")
    rbracket = hidden_field.find("]")
    dot = hidden_field.find(".")

    if lbracket == 0:
        # skip past right bracket and any following dot
        rest = hidden_field[rbracket + 1 :]  # noqa: E203
        if rest and rest[0] == ".":
            rest = rest[1:]
        return (hidden_field[lbracket + 1 : rbracket], rest)  # noqa: E203

    if lbracket != -1 and (dot == -1 or lbracket < dot):
        return (hidden_field[:lbracket], hidden_field[lbracket:])

    split = hidden_field.split(".", 1)
    if len(split) == 1:
        return split[0], ""
    return split
