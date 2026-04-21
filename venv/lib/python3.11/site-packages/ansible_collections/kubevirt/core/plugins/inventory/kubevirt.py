# -*- coding: utf-8 -*-
# Copyright 2023 Red Hat, Inc.
# Based on the kubernetes.core.k8s inventory
# Apache License 2.0 (see LICENSE or http://www.apache.org/licenses/LICENSE-2.0)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
name: kubevirt

short_description: Inventory source for KubeVirt VirtualMachines and VirtualMachineInstances

author:
- "KubeVirt.io Project (!UNKNOWN)"

description:
- Fetch virtual machines from one or more namespaces with an optional label selector.
- Groups by cluster name, namespaces and labels.
- Uses V(*.kubevirt.[yml|yaml]) YAML configuration file to set parameter values.
- By default it uses the active context in I(~/.kube/config) and will return all virtual machines
  for all namespaces the active user is authorized to access.

extends_documentation_fragment:
- kubevirt.core.kubevirt_auth_options
- inventory_cache
- constructed

options:
  plugin:
    description: Token that ensures this is a source file for the P(kubevirt.core.kubevirt#inventory) plugin.
    required: True
    choices: ["kubevirt", "kubevirt.core.kubevirt"]
  host_format:
    description:
    - 'Specify the format of the host in the inventory group. Available specifiers: V(name), V(namespace) and V(uid).'
    default: "{namespace}-{name}"
  name:
    description:
    - Optional name to assign to the cluster. If not provided, a name is constructed from the server
      and port.
  namespaces:
    description:
    - List of namespaces. If not specified, will fetch virtual machines from all namespaces
      the user is authorized to access.
  label_selector:
    description:
    - Define a label selector to select a subset of the fetched virtual machines.
  network_name:
    description:
    - In case multiple networks are attached to a virtual machine, define which interface should
      be returned as primary IP address.
    aliases: [ interface_name ]
  kube_secondary_dns:
    description:
    - Enable C(kubesecondarydns) derived host names when using a secondary network interface.
    type: bool
    default: False
  use_service:
    description:
    - Enable the use of C(Services) to establish an SSH connection to a virtual machine.
    - Services are only used if no O(network_name) was provided.
    type: bool
    default: True
  unset_ansible_port:
    description:
    - Try to unset the value of C(ansible_port) if no non-default value was found.
    type: bool
    default: True
    version_added: 2.2.0
  create_groups:
    description:
    - Enable the creation of groups from labels on C(VirtualMachines) and C(VirtualMachineInstances).
    type: bool
    default: False
  base_domain:
    description:
    - Override the base domain used to construct host names. Used in case of
      C(kubesecondarydns) or C(Services) of type C(NodePort) if O(append_base_domain) is set.
  append_base_domain:
    description:
    - Append the base domain of the cluster to host names constructed from SSH C(Services) of type C(NodePort).
    type: bool
    default: False
  api_version:
    description:
    - Specify the used KubeVirt API version.
    default: "kubevirt.io/v1"
  connections:
    description:
    - Optional list of cluster connection settings.
    - This parameter is deprecated. Split your connections into multiple configuration files and move
      parameters of each connection to the configuration top level.
    - Deprecated in version C(1.5.0), will be removed in version C(3.0.0).

requirements:
- "python >= 3.9"
- "kubernetes >= 28.1.0"
- "PyYAML >= 3.11"
"""

EXAMPLES = """
# Filename must end with kubevirt.[yml|yaml]

# Authenticate with token and return all virtual machines from all accessible namespaces
- plugin: kubevirt.core.kubevirt
  host: https://192.168.64.4:8443
  api_key: xxxxxxxxxxxxxxxx
  validate_certs: false

# Use default ~/.kube/config and return virtual machines from namespace testing connected to network bridge-network
- plugin: kubevirt.core.kubevirt
  namespaces:
    - testing
  network_name: bridge-network

# Use default ~/.kube/config and return virtual machines from namespace testing with label app=test
- plugin: kubevirt.core.kubevirt
  namespaces:
    - testing
  label_selector: app=test

# Use a custom config file and a specific context
- plugin: kubevirt.core.kubevirt
  kubeconfig: /path/to/config
  context: 'awx/192-168-64-4:8443/developer'
"""

from dataclasses import dataclass, InitVar
from json import loads
from re import compile as re_compile
from typing import (
    Any,
    Dict,
    List,
    Optional,
)

# Handle import errors of python kubernetes client.
# Set HAS_K8S_MODULE_HELPER and k8s_import exception accordingly to
# potentially print a warning to the user if the client is missing.
try:
    from kubernetes.dynamic.exceptions import DynamicApiError, ResourceNotFoundError

    HAS_K8S_MODULE_HELPER = True
    K8S_IMPORT_EXCEPTION = None
except ImportError as e:

    class DynamicApiError(Exception):
        """
        Dummy class, mainly used for ansible-test sanity.
        """

    class ResourceNotFoundError(Exception):
        """
        Dummy class, mainly used for ansible-test sanity.
        """

    HAS_K8S_MODULE_HELPER = False
    K8S_IMPORT_EXCEPTION = e

from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable

# Handle import errors of trust_as_template.
# It is only available on ansible-core >=2.19.
try:
    from ansible.template import trust_as_template
except ImportError:
    trust_as_template = None


from ansible_collections.kubernetes.core.plugins.module_utils.k8s.client import (
    get_api_client,
    K8SClient,
)

ANNOTATION_KUBEVIRT_IO_CLUSTER_PREFERENCE_NAME = "kubevirt.io/cluster-preference-name"
ANNOTATION_KUBEVIRT_IO_PREFERENCE_NAME = "kubevirt.io/preference-name"
ANNOTATION_VM_KUBEVIRT_IO_OS = "vm.kubevirt.io/os"
LABEL_KUBEVIRT_IO_DOMAIN = "kubevirt.io/domain"
TYPE_LOADBALANCER = "LoadBalancer"
TYPE_NODEPORT = "NodePort"
ID_MSWINDOWS = "mswindows"
SERVICE_TARGET_PORT_SSH = 22
SERVICE_TARGET_PORT_WINRM_HTTP = 5985
SERVICE_TARGET_PORT_WINRM_HTTPS = 5986


class KubeVirtInventoryException(Exception):
    """
    This class is used for exceptions raised by this inventory.
    """


@dataclass
class InventoryOptions:
    """
    This class holds the options defined by the user.
    """

    api_version: Optional[str] = None
    label_selector: Optional[str] = None
    network_name: Optional[str] = None
    kube_secondary_dns: Optional[bool] = None
    use_service: Optional[bool] = None
    unset_ansible_port: Optional[bool] = None
    create_groups: Optional[bool] = None
    base_domain: Optional[str] = None
    append_base_domain: Optional[bool] = None
    host_format: Optional[str] = None
    namespaces: Optional[List[str]] = None
    name: Optional[str] = None
    config_data: InitVar[Optional[Dict]] = None

    def __post_init__(self, config_data: Optional[Dict]) -> None:
        if not config_data or not isinstance(config_data, dict):
            config_data = {}

        # Copy values from config_data and set defaults for keys not present
        self.api_version = (
            self.api_version
            if self.api_version is not None
            else config_data.get("api_version", "kubevirt.io/v1")
        )
        self.label_selector = (
            self.label_selector
            if self.label_selector is not None
            else config_data.get("label_selector")
        )
        self.network_name = (
            self.network_name
            if self.network_name is not None
            else config_data.get("network_name", config_data.get("interface_name"))
        )
        self.kube_secondary_dns = (
            self.kube_secondary_dns
            if self.kube_secondary_dns is not None
            else config_data.get("kube_secondary_dns", False)
        )
        self.use_service = (
            self.use_service
            if self.use_service is not None
            else config_data.get("use_service", True)
        )
        self.unset_ansible_port = (
            self.unset_ansible_port
            if self.unset_ansible_port is not None
            else config_data.get("unset_ansible_port", True)
        )
        self.create_groups = (
            self.create_groups
            if self.create_groups is not None
            else config_data.get("create_groups", False)
        )
        self.base_domain = (
            self.base_domain
            if self.base_domain is not None
            else config_data.get("base_domain")
        )
        self.append_base_domain = (
            self.append_base_domain
            if self.append_base_domain is not None
            else config_data.get("append_base_domain", False)
        )
        self.host_format = (
            self.host_format
            if self.host_format is not None
            else config_data.get("host_format", "{namespace}-{name}")
        )
        self.namespaces = (
            self.namespaces
            if self.namespaces is not None
            else config_data.get("namespaces")
        )
        self.name = self.name if self.name is not None else config_data.get("name")


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):
    """
    This class implements the actual inventory module.
    """

    NAME = "kubevirt.core.kubevirt"

    # Used to convert camel case variable names into snake case
    _snake_case_pattern = re_compile(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")

    @staticmethod
    def _get_default_hostname(host: str) -> str:
        """
        _get_default_host_name strips URL schemes from the host name and
        replaces invalid characters.
        """
        return (
            host.replace("https://", "")
            .replace("http://", "")
            .replace(".", "-")
            .replace(":", "_")
        )

    @staticmethod
    def _format_dynamic_api_exc(exc: DynamicApiError) -> str:
        """
        _format_dynamic_api_exc tries to extract the message from the JSON body
        of a DynamicApiError.
        """
        if exc.body:
            if exc.headers and exc.headers.get("Content-Type") == "application/json":
                message = loads(exc.body).get("message")
                if message:
                    return message
            return exc.body

        return f"{exc.status} Reason: {exc.reason}"

    @staticmethod
    def _format_var_name(name: str) -> str:
        """
        _format_var_name formats a CamelCase variable name into a snake_case name
        suitable for use as a inventory variable name.
        """
        return InventoryModule._snake_case_pattern.sub("_", name).lower()

    @staticmethod
    def _obj_is_valid(obj: Dict) -> bool:
        """
        _obj_is_valid ensures commonly used keys are present in the passed object.
        """
        return bool(
            "spec" in obj
            and "status" in obj
            and "metadata" in obj
            and obj["metadata"].get("name")
            and obj["metadata"].get("namespace")
            and obj["metadata"].get("uid")
        )

    @staticmethod
    def _find_service_with_target_port(
        services: List[Dict], target_port: int
    ) -> Optional[Dict]:
        """
        _find_service_with_target_port returns the first found service with a given
        target port in the passed in list of services or otherwise None.
        """
        for service in services:
            if (
                (ports := service.get("spec", {}).get("ports")) is not None
                and len(ports) == 1
                and ports[0].get("targetPort", 0) == target_port
            ):
                return service

        return None

    @staticmethod
    def _get_host_from_service(
        service: Dict, node_name: Optional[str]
    ) -> Optional[str]:
        """
        _get_host_from_service extracts the hostname to be used from the
        passed in service.
        """
        service_type = service.get("spec", {}).get("type")
        if service_type == TYPE_LOADBALANCER:
            # LoadBalancer services can return a hostname or an IP address
            ingress = service.get("status", {}).get("loadBalancer", {}).get("ingress")
            if ingress is not None and len(ingress) > 0:
                hostname = ingress[0].get("hostname")
                ip_address = ingress[0].get("ip")
                return hostname if hostname is not None else ip_address
        elif service_type == TYPE_NODEPORT:
            # NodePort services use the node name as host
            return node_name

        return None

    @staticmethod
    def _get_port_from_service(service: Dict) -> Optional[str]:
        """
        _get_port_from_service extracts the port to be used from the
        passed in service.
        """
        ports = service.get("spec", {}).get("ports", [])
        if not ports:
            return None

        service_type = service.get("spec", {}).get("type")
        if service_type == TYPE_LOADBALANCER:
            # LoadBalancer services use the port attribute
            return ports[0].get("port")
        if service_type == TYPE_NODEPORT:
            # NodePort services use the nodePort attribute
            return ports[0].get("nodePort")

        return None

    @staticmethod
    def _is_windows(guest_os_info: Optional[Dict], annotations: Optional[Dict]) -> bool:
        """
        _is_windows checks whether a given VM is running a Windows guest
        by checking its GuestOSInfo and annotations.
        """
        if guest_os_info and "id" in guest_os_info:
            return guest_os_info["id"] == ID_MSWINDOWS

        if not annotations:
            return False

        if ANNOTATION_KUBEVIRT_IO_CLUSTER_PREFERENCE_NAME in annotations:
            return annotations[
                ANNOTATION_KUBEVIRT_IO_CLUSTER_PREFERENCE_NAME
            ].startswith("windows")

        if ANNOTATION_KUBEVIRT_IO_PREFERENCE_NAME in annotations:
            return annotations[ANNOTATION_KUBEVIRT_IO_PREFERENCE_NAME].startswith(
                "windows"
            )

        if ANNOTATION_VM_KUBEVIRT_IO_OS in annotations:
            return annotations[ANNOTATION_VM_KUBEVIRT_IO_OS].startswith("windows")

        return False

    def verify_file(self, path: str) -> None:
        """
        verify_file ensures the inventory file is compatible with this plugin.
        """
        return super().verify_file(path) and path.endswith(
            ("kubevirt.yml", "kubevirt.yaml")
        )

    def parse(self, inventory: Any, loader: Any, path: str, cache: bool = True) -> None:
        """
        parse is the main entry point of the inventory.
        It checks for availability of the Kubernetes Python client,
        gets the configuration, retrieves the cache or runs fetch_objects and
        populates the inventory.
        """
        if not HAS_K8S_MODULE_HELPER:
            raise KubeVirtInventoryException(
                "This module requires the Kubernetes Python client. "
                + f"Try `pip install kubernetes`. Detail: {K8S_IMPORT_EXCEPTION}"
            )

        super().parse(inventory, loader, path)

        config_data = self._read_config_data(path)
        cache_key = self.get_cache_key(path)
        user_cache_setting = self.get_option("cache")
        attempt_to_read_cache = user_cache_setting and cache
        cache_needs_update = user_cache_setting and not cache

        self._connections_compatibility(config_data)
        opts = InventoryOptions(config_data=config_data)

        results = {}
        if attempt_to_read_cache:
            try:
                results = self.cache[cache_key]
            except KeyError:
                cache_needs_update = True
        if not attempt_to_read_cache or cache_needs_update:
            results = self._fetch_objects(get_api_client(**config_data), opts)
        if cache_needs_update:
            self.cache[cache_key] = results

        self._populate_inventory(results, opts)

    def _connections_compatibility(self, config_data: Dict) -> None:
        """
        _connections_compatibility ensures compatibility with the connection
        parameter found in earlier versions of this inventory plugin (<1.5.0).
        """
        collection_name = "kubevirt.core"
        version_removed_in = "3.0.0"

        if (connections := config_data.get("connections")) is None:
            return

        self.display.deprecated(
            msg="The 'connections' parameter is deprecated and now supports only a single list entry.",
            version=version_removed_in,
            collection_name=collection_name,
        )

        if not isinstance(connections, list):
            raise KubeVirtInventoryException("Expecting connections to be a list.")

        if len(connections) == 1:
            if not isinstance(connections[0], dict):
                raise KubeVirtInventoryException(
                    "Expecting connection to be a dictionary."
                )
            # Copy the single connections entry into the top level
            for k, v in connections[0].items():
                config_data[k] = v
            self.display.deprecated(
                msg="Move all of your connection parameters to the configuration top level.",
                version=version_removed_in,
                collection_name=collection_name,
            )
        elif len(connections) > 1:
            self.display.deprecated(
                msg="Split your connections into multiple configuration files.",
                version="2.0.0",
                collection_name=collection_name,
                removed=True,
            )

    def _fetch_objects(self, client: Any, opts: InventoryOptions) -> Dict:
        """
        fetch_objects fetches all relevant objects from the K8S API.
        """
        namespaces = {}
        for namespace in (
            opts.namespaces
            if opts.namespaces
            else self._get_available_namespaces(client)
        ):
            vms = self._get_vms_for_namespace(client, namespace, opts)
            vmis = self._get_vmis_for_namespace(client, namespace, opts)

            if not vms and not vmis:
                # Continue if no VMs and VMIs were found to avoid adding empty groups.
                continue

            namespaces[namespace] = {
                "vms": vms,
                "vmis": vmis,
                "services": self._get_services_for_namespace(client, namespace),
            }

        return {
            "default_hostname": self._get_default_hostname(client.configuration.host),
            "cluster_domain": self._get_cluster_domain(client),
            "namespaces": namespaces,
        }

    def _get_cluster_domain(self, client: K8SClient) -> Optional[str]:
        """
        _get_cluster_domain tries to get the base domain of an OpenShift cluster.
        """
        try:
            v1_dns = client.resources.get(
                api_version="config.openshift.io/v1", kind="DNS"
            )
        except Exception:
            # If resource not found return None
            return None
        try:
            obj = v1_dns.get(name="cluster")
        except DynamicApiError as exc:
            self.display.debug(
                f"Failed to fetch cluster DNS config: {self._format_dynamic_api_exc(exc)}"
            )
            return None
        return obj.get("spec", {}).get("baseDomain")

    def _get_resources(
        self, client: K8SClient, api_version: str, kind: str, **kwargs
    ) -> List[Dict]:
        """
        _get_resources uses a dynamic K8SClient to fetch resources from the K8S API.
        """
        client = client.resources.get(api_version=api_version, kind=kind)
        try:
            result = client.get(**kwargs)
        except DynamicApiError as exc:
            self.display.debug(exc)
            raise KubeVirtInventoryException(
                f"Error fetching {kind} list: {self._format_dynamic_api_exc(exc)}"
            ) from exc

        return [item.to_dict() for item in result.items]

    def _get_available_namespaces(self, client: K8SClient) -> List[str]:
        """
        _get_available_namespaces lists all namespaces accessible with the
        configured credentials and returns them.
        """

        namespaces = []
        try:
            namespaces = self._get_resources(
                client, "project.openshift.io/v1", "Project"
            )
        except ResourceNotFoundError:
            namespaces = self._get_resources(client, "v1", "Namespace")

        return [
            namespace["metadata"]["name"]
            for namespace in namespaces
            if "metadata" in namespace and "name" in namespace["metadata"]
        ]

    def _get_vms_for_namespace(
        self, client: K8SClient, namespace: str, opts: InventoryOptions
    ) -> List[Dict]:
        """
        _get_vms_for_namespace returns a list of all VirtualMachines in a namespace.
        """
        return self._get_resources(
            client,
            opts.api_version,
            "VirtualMachine",
            namespace=namespace,
            label_selector=opts.label_selector,
        )

    def _get_vmis_for_namespace(
        self, client: K8SClient, namespace: str, opts: InventoryOptions
    ) -> List[Dict]:
        """
        _get_vmis_for_namespace returns a list of all VirtualMachineInstances in a namespace.
        """
        return self._get_resources(
            client,
            opts.api_version,
            "VirtualMachineInstance",
            namespace=namespace,
            label_selector=opts.label_selector,
        )

    def _get_services_for_namespace(
        self, client: K8SClient, namespace: str
    ) -> Dict[str, List[Dict]]:
        """
        _get_services_for_namespace retrieves all services of a namespace exposing ssh or winrm.
        The services are mapped to the name of the corresponding domain.
        """
        items = self._get_resources(
            client,
            "v1",
            "Service",
            namespace=namespace,
        )

        services = {}
        for service in items:
            # Continue if service is not of type LoadBalancer or NodePort
            if not (spec := service.get("spec")):
                continue

            if spec.get("type") not in (
                TYPE_LOADBALANCER,
                TYPE_NODEPORT,
            ):
                continue

            # Continue if ports are not defined, there are more than one port mapping
            # or the target port is not port 22 (ssh) or port 5985 or 5986 (winrm).
            if (
                (ports := spec.get("ports")) is None
                or len(ports) != 1
                or ports[0].get("targetPort")
                not in [
                    SERVICE_TARGET_PORT_SSH,
                    SERVICE_TARGET_PORT_WINRM_HTTP,
                    SERVICE_TARGET_PORT_WINRM_HTTPS,
                ]
            ):
                continue

            # Only add the service to the list if the domain selector is present
            if domain := spec.get("selector", {}).get(LABEL_KUBEVIRT_IO_DOMAIN):
                if domain not in services:
                    services[domain] = []
                services[domain].append(service)

        return services

    def _populate_inventory(self, results: Dict, opts: InventoryOptions) -> None:
        """
        _populate_inventory populates the inventory by completing the InventoryOptions
        and invoking populate_inventory_from_namespace for every namespace in results.
        """
        if opts.base_domain is None:
            opts.base_domain = results["cluster_domain"]
        if opts.name is None:
            opts.name = results["default_hostname"]
        for namespace, data in results["namespaces"].items():
            self._populate_inventory_from_namespace(namespace, data, opts)

    def _populate_inventory_from_namespace(
        self, namespace: str, data: Dict, opts: InventoryOptions
    ) -> None:
        """
        _populate_inventory_from_namespace adds groups and hosts from a
        namespace to the inventory.
        """
        vms = {
            vm["metadata"]["name"]: vm for vm in data["vms"] if self._obj_is_valid(vm)
        }
        vmis = {
            vmi["metadata"]["name"]: vmi
            for vmi in data["vmis"]
            if self._obj_is_valid(vmi)
        }

        if not vms and not vmis:
            # Return early if no VMs and VMIs were found to avoid adding empty groups.
            return

        services = {
            domain: [service for service in services if self._obj_is_valid(service)]
            for domain, services in data["services"].items()
        }

        name = self._sanitize_group_name(opts.name)
        namespace_group = self._sanitize_group_name(f"namespace_{namespace}")

        self.inventory.add_group(name)
        self.inventory.add_group(namespace_group)
        self.inventory.add_child(name, namespace_group)

        # Add found VMs and optionally enhance with VMI data
        for name, vm in vms.items():
            hostname = self._add_host(vm["metadata"], opts.host_format, namespace_group)
            self._set_vars_from_vm(hostname, vm, opts)
            if name in vmis:
                self._set_vars_from_vmi(hostname, vmis[name], services, opts)
            self._set_composable_vars(hostname)

        # Add remaining VMIs without VM
        for name, vmi in vmis.items():
            if name in vms:
                continue
            hostname = self._add_host(
                vmi["metadata"], opts.host_format, namespace_group
            )
            self._set_vars_from_vmi(hostname, vmi, services, opts)
            self._set_composable_vars(hostname)

    def _add_host(self, metadata: Dict, host_format: str, namespace_group: str) -> str:
        """
        _add_host adds a host to the inventory.
        """
        hostname = host_format.format(
            namespace=metadata["namespace"],
            name=metadata["name"],
            uid=metadata["uid"],
        )
        self.inventory.add_host(hostname)
        self.inventory.add_child(namespace_group, hostname)

        return hostname

    def _set_vars_from_vm(
        self, hostname: str, vm: Dict, opts: InventoryOptions
    ) -> None:
        """
        _set_vars_from_vm sets inventory variables from a VM prefixed with vm_.
        """
        self._set_common_vars(hostname, "vm", vm, opts)

    def _set_vars_from_vmi(
        self,
        hostname: str,
        vmi: Dict,
        services: Dict[str, List[Dict]],
        opts: InventoryOptions,
    ) -> None:
        """
        _set_vars_from_vmi sets inventory variables from a VMI prefixed with vmi_ and
        looks up the interface to set ansible_host and ansible_port.
        """
        self._set_common_vars(hostname, "vmi", vmi, opts)

        if not (interfaces := vmi["status"].get("interfaces")):
            return

        if opts.network_name is None:
            # Use first interface
            interface = interfaces[0]
        else:
            # Find interface by its name
            interface = next(
                (i for i in interfaces if i.get("name") == opts.network_name),
                None,
            )

        # If interface is not found or IP address is not reported skip this VMI
        if not interface or not interface.get("ipAddress"):
            return

        _services = services.get(
            vmi["metadata"].get("labels", {}).get(LABEL_KUBEVIRT_IO_DOMAIN), []
        )

        # Set up the connection
        service = None
        if self._is_windows(
            vmi["status"].get("guestOSInfo", {}),
            vmi["metadata"].get("annotations", {}),
        ):
            self.inventory.set_variable(hostname, "ansible_connection", "winrm")
            service = self._find_service_with_target_port(
                _services, SERVICE_TARGET_PORT_WINRM_HTTPS
            )
            if service is None:
                service = self._find_service_with_target_port(
                    _services, SERVICE_TARGET_PORT_WINRM_HTTP
                )
        else:
            service = self._find_service_with_target_port(
                _services, SERVICE_TARGET_PORT_SSH
            )

        self._set_ansible_host_and_port(
            vmi,
            hostname,
            interface["ipAddress"],
            service,
            opts,
        )

    def _set_common_vars(
        self, hostname: str, prefix: str, obj: Dict, opts: InventoryOptions
    ):
        """
        _set_common_vars sets common inventory variables from VMs or VMIs.
        """
        # Add hostvars from metadata
        if annotations := obj["metadata"].get("annotations"):
            self.inventory.set_variable(hostname, f"{prefix}_annotations", annotations)
        if labels := obj["metadata"].get("labels"):
            self.inventory.set_variable(hostname, f"{prefix}_labels", labels)
            # Create label groups and add vm to it if enabled
            if opts.create_groups:
                self._set_groups_from_labels(hostname, labels)
        if resource_version := obj["metadata"].get("resourceVersion"):
            self.inventory.set_variable(
                hostname, f"{prefix}_resource_version", resource_version
            )
        if uid := obj["metadata"].get("uid"):
            self.inventory.set_variable(hostname, f"{prefix}_uid", uid)

        # Add hostvars from status
        for key, value in obj["status"].items():
            self.inventory.set_variable(
                hostname, f"{prefix}_{self._format_var_name(key)}", value
            )

    def _set_groups_from_labels(self, hostname: str, labels: Dict) -> None:
        """
        _set_groups_from_labels adds groups for each label of a VM or VMI and
        adds the host to each group.
        """
        groups = []
        for key, value in labels.items():
            group_name = self._sanitize_group_name(f"label_{key}_{value}")
            if group_name not in groups:
                groups.append(group_name)
        # Add host to each label_value group
        for group in groups:
            self.inventory.add_group(group)
            self.inventory.add_child(group, hostname)

    def _set_ansible_host_and_port(
        self,
        vmi: Dict,
        hostname: str,
        ip_address: str,
        service: Optional[Dict],
        opts: InventoryOptions,
    ) -> None:
        """
        _set_ansible_host_and_port sets the ansible_host and possibly the ansible_port var.
        Secondary interfaces have priority over a service exposing SSH
        """
        ansible_host = None
        ansible_port = None
        if opts.kube_secondary_dns and opts.network_name:
            # Set ansible_host to the kubesecondarydns derived host name if enabled
            # See https://github.com/kubevirt/kubesecondarydns#parameters
            ansible_host = f"{opts.network_name}.{vmi['metadata']['name']}.{vmi['metadata']['namespace']}.vm"
            if opts.base_domain:
                ansible_host += f".{opts.base_domain}"
        elif opts.use_service and service and not opts.network_name:
            # Set ansible_host and ansible_port to the host and port from the LoadBalancer
            # or NodePort service exposing SSH
            node_name = vmi["status"].get("nodeName")
            if node_name and opts.append_base_domain and opts.base_domain:
                node_name += f".{opts.base_domain}"
            host = self._get_host_from_service(service, node_name)
            port = self._get_port_from_service(service)
            if host is not None and port is not None:
                ansible_host = host
                ansible_port = port

        # Default to the IP address of the interface if ansible_host was not set prior
        if ansible_host is None:
            ansible_host = ip_address

        self.inventory.set_variable(hostname, "ansible_host", ansible_host)
        if opts.unset_ansible_port or ansible_port is not None:
            self.inventory.set_variable(hostname, "ansible_port", ansible_port)

    def _set_composable_vars(self, hostname: str) -> None:
        """
        _set_composable_vars sets vars per
        https://docs.ansible.com/ansible/latest/dev_guide/developing_inventory.html
        """
        hostvars = self.inventory.get_host(hostname).get_vars()
        strict = self.get_option("strict")

        def trust_compose_groups(data: Dict) -> Dict:
            if trust_as_template is not None:
                return {k: trust_as_template(v) for k, v in data.items()}
            return data

        def trust_keyed_groups(data: List) -> List:
            if trust_as_template is not None:
                return [{**d, "key": trust_as_template(d["key"])} for d in data]
            return data

        self._set_composite_vars(
            trust_compose_groups(self.get_option("compose")),
            hostvars,
            hostname,
            strict=True,
        )
        self._add_host_to_composed_groups(
            trust_compose_groups(self.get_option("groups")),
            hostvars,
            hostname,
            strict=strict,
        )
        self._add_host_to_keyed_groups(
            trust_keyed_groups(self.get_option("keyed_groups")),
            hostvars,
            hostname,
            strict=strict,
        )
