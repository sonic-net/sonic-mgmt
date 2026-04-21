from dataclasses import dataclass
from typing import Optional, List

try:
    from .common_base_models import SingleBaseClass
except ImportError:
    from common_base_models import SingleBaseClass


@dataclass
class ClusterFactSpec:
    query: Optional[str] = None


@dataclass
class ControlNetworkSpec:
    control_network_ip: Optional[str] = None
    control_network_subnet: Optional[str] = "255.255.255.0"
    control_network_mtu_size: Optional[int] = 1500


@dataclass
class InternodeNetworkSpec:
    internode_network_ip: Optional[str] = None
    internode_network_subnet: Optional[str] = "255.255.255.0"
    internode_network_mtu_size: Optional[int] = 9000


@dataclass
class ComputeNetworkSpec:
    compute_port_protocol: Optional[str] = None
    compute_network_ip: Optional[str] = None
    compute_network_subnet: Optional[str] = "255.255.255.0"
    compute_network_gateway: Optional[str] = None
    is_compute_network_ipv6_mode: Optional[bool] = False
    compute_network_ipv6_globals: Optional[List[str]] = None
    compute_network_ipv6_subnet_prefix: Optional[str] = None
    compute_network_ipv6_gateway: Optional[str] = None
    compute_network_mtu_size: Optional[int] = 9000


@dataclass
class ControlInternodeNetworkSpec:
    control_internode_network_route_destinations: Optional[List[str]] = None
    control_internode_network_route_gateways: Optional[List[str]] = None
    control_internode_network_route_interfaces: Optional[List[str]] = None


@dataclass
class StorageNodeSpec(SingleBaseClass):
    host_name: Optional[str] = None
    fault_domain_name: Optional[str] = None
    is_cluster_master_role: Optional[bool] = False
    control_network: Optional[ControlNetworkSpec] = None
    internode_network: Optional[InternodeNetworkSpec] = None
    control_internode_network: Optional[ControlInternodeNetworkSpec] = None
    number_of_fc_target_port: Optional[int] = 0
    compute_networks: Optional[List[ComputeNetworkSpec]] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "control_network" in kwargs and kwargs.get("control_network") is not None:
            self.control_network = (
                ControlNetworkSpec(**kwargs.get("control_network"))
                if kwargs.get("control_network")
                else None
            )
        if (
            "internode_network" in kwargs
            and kwargs.get("internode_network") is not None
        ):
            self.internode_network = (
                InternodeNetworkSpec(**kwargs.get("internode_network"))
                if kwargs.get("internode_network")
                else None
            )
        if (
            "control_internode_network" in kwargs
            and kwargs.get("control_internode_network") is not None
        ):
            self.control_internode_network = (
                ControlInternodeNetworkSpec(**kwargs.get("control_internode_network"))
                if kwargs.get("control_internode_network")
                else None
            )
        if "compute_networks" in kwargs and kwargs.get("compute_networks") is not None:
            self.compute_networks = [
                ComputeNetworkSpec(**x) for x in self.compute_networks
            ]


@dataclass
class ClusterSpec(SingleBaseClass):
    configuration_file: Optional[str] = None
    setup_user_password: Optional[str] = None
    storage_nodes: Optional[List[StorageNodeSpec]] = None

    config_file_location: Optional[str] = None
    refresh: Optional[bool] = False
    export_file_type: Optional[str] = None
    node_id: Optional[str] = None
    node_name: Optional[str] = None
    machine_image_id: Optional[str] = None
    template_s3_url: Optional[str] = None
    vm_configuration_file_s3_uri: Optional[str] = None
    is_capacity_balancing_enabled: Optional[bool] = None
    controller_id: Optional[str] = None
    no_of_drives: Optional[int] = None
    should_recover_single_node: Optional[bool] = False
    system_requirement_file: Optional[str] = None

    force: Optional[bool] = False
    reboot: Optional[bool] = False
    config_parameter_setting_mode: Optional[bool] = False

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "storage_nodes" in kwargs and kwargs.get("storage_nodes") is not None:
            self.storage_nodes = [StorageNodeSpec(**x) for x in self.storage_nodes]
        self.__post_init__()

    def __post_init__(self):
        if self.export_file_type is not None:
            self.export_file_type = "".join(
                word.title() for word in self.export_file_type.split("_")
            )
