import time
import os
from typing import Any

try:
    from ..provisioner.sdsb_cluster_provisioner import SDSBClusterProvisioner
    from ..provisioner.sdsb_capacity_mgmt_settings_provisioner import (
        SDSBCapacityManagementSettingsProvisioner,
    )
    from ..provisioner.sdsb_storage_node_provisioner import SDSBStorageNodeProvisioner
    from ..common.hv_constants import StateValue
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        log_entry_exit,
        unzip_targz,
    )
    from ..model.sdsb_cluster_models import ControlInternodeNetworkSpec
    from ..message.sdsb_cluster_msgs import SDSBClusterValidationMsg
except ImportError:
    from provisioner.sdsb_cluster_provisioner import SDSBClusterProvisioner
    from provisioner.sdsb_capacity_mgmt_settings_provisioner import (
        SDSBCapacityManagementSettingsProvisioner,
    )
    from provisioner.sdsb_storage_node_provisioner import SDSBStorageNodeProvisioner
    from common.hv_log import Log
    from common.ansible_common import (
        log_entry_exit,
        unzip_targz,
    )
    from model.sdsb_cluster_models import ControlInternodeNetworkSpec
    from message.sdsb_cluster_msgs import SDSBClusterValidationMsg

logger = Log()


CLOUD_PLATFORMS = ["Google, Inc.", "Msft", "Amazon.com, Inc"]
AWS = "Amazon.com, Inc"
AZURE = "Msft"
GCP = "Google, Inc."
STORAGE_NODE_STATUS = [
    "maintenanceblockage",
    "persistentblockage",
    "removalfailedandtemporaryblockage",
    "removalfailedandmaintenanceblockage",
    "removalfailedandpersistentblockage",
]


def get_json_for_config_file(file_path):
    result = {}
    current_section = None
    headers = []

    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue  # skip empty lines

            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1]
                result[current_section] = []
                headers = []
                continue

            if current_section:
                # Handle the first line of the section as headers
                if not headers:
                    headers = line.split(",")
                    continue

                # Parse data lines
                values = line.split(",")
                row_dict = {
                    headers[i]: values[i] if i < len(values) else ""
                    for i in range(len(headers))
                }
                result[current_section].append(row_dict)

    return result


class SDSBClusterReconciler:

    def __init__(self, connection_info, state=None):
        self.connection_info = connection_info
        self.provisioner = SDSBClusterProvisioner(self.connection_info)
        self.storage_node_prov = SDSBStorageNodeProvisioner(connection_info)
        self.state = state

    @log_entry_exit
    def get_clusters(self, spec=None):
        json_object = self.get_cluster_config()
        new_json = SDSBClusterExtractor().extract(json_object)
        return new_json

    @log_entry_exit
    def get_cluster_config(self):
        dest_folder = self.download_and_unzip_config_file()
        file_name = "SystemConfigurationFile.csv"
        file_path = f"{dest_folder}/{file_name}"
        json_object = get_json_for_config_file(file_path)
        return json_object

    @log_entry_exit
    def reconcile_cluster(self, spec: Any) -> Any:
        state = self.state.lower()
        logger.writeDebug(f"spec = {spec}")
        resp_data = None
        if state == StateValue.PRESENT:
            resp_data = self.edit_capacity_management_settings(spec=spec)
        elif state == StateValue.ADD_STORAGE_NODE:
            resp_data = self.add_storage_node(spec=spec)
        elif state == StateValue.REMOVE_STORAGE_NODE:
            resp_data = self.remove_storage_node(spec=spec)
        elif state == StateValue.DOWNLOAD_CONFIG_FILE:
            resp_data = self.download_config_file(spec=spec)
        elif state == StateValue.STOP_REMOVING_STORAGE_NODE:
            resp_data = self.stop_removing_storage_nodes()
        elif state == StateValue.REPLACE_STORAGE_NODE:
            resp_data = self.replace_storage_node(spec=spec)
        elif state == StateValue.SYSTEM_REQUIREMENT_FILE_PRESENT:
            resp_data = self.import_system_requirement_file(spec=spec)
        elif state == StateValue.STOP_STORAGE_CLUSTER:
            resp_data = self.stop_storage_cluster(spec=spec)
        if resp_data:
            return resp_data

    @log_entry_exit
    def stop_storage_cluster(self, spec=None):
        if spec and spec.force and (spec.reboot or spec.config_parameter_setting_mode):
            raise ValueError(
                SDSBClusterValidationMsg.BAD_PARAMETERS_FOR_STOP_CLUSTER.value
            )
        try:
            resp = self.provisioner.stop_storage_cluster(spec)
            msg = SDSBClusterValidationMsg.STOP_CLUSTER_SUCCESS_MSG.value.format(resp)
            self.connection_info.changed = True
            return msg
        except Exception as e:
            logger.writeException(e)
            msg = SDSBClusterValidationMsg.STOP_CLUSTER_FAILURE_MSG.value
            return msg

    @log_entry_exit
    def import_system_requirement_file(self, spec=None):
        if spec.system_requirement_file is None:
            raise ValueError(
                SDSBClusterValidationMsg.SYSTEM_REQUIREMENT_FILE_REQD.value
            )
        else:
            if not spec.system_requirement_file.endswith("SystemRequirementsFile.yml"):
                raise ValueError(
                    SDSBClusterValidationMsg.BAD_SYSTEM_REQUIREMENT_FILE_NAME.value
                )
            if not os.path.exists(spec.system_requirement_file):
                raise ValueError(
                    SDSBClusterValidationMsg.SYSTEM_REQUIREMENT_FILE_DOES_NOT_EXIST.value.format(
                        spec.system_requirement_file
                    )
                )
        try:
            resp = self.provisioner.import_system_requirement_file(spec)
            msg = SDSBClusterValidationMsg.IMPORT_SYSTEM_REQUIREMET_FILE_SUCCESS_MSG.value.format(
                resp
            )
            self.connection_info.changed = True
            return msg
        except Exception as e:
            logger.writeException(e)
            msg = (
                SDSBClusterValidationMsg.IMPORT_SYSTEM_REQUIREMET_FILE_FAILURE_MSG.value
            )
            return msg

    @log_entry_exit
    def stop_removing_storage_nodes(self):
        try:
            resp = self.provisioner.stop_removing_storage_nodes()
            msg = SDSBClusterValidationMsg.STOP_REMOVING_STORAGE_NODE_SUCCESS_MSG.value.format(
                resp
            )
            self.connection_info.changed = True
            return msg
        except Exception as e:
            logger.writeException(e)
            msg = SDSBClusterValidationMsg.STOP_REMOVING_STORAGE_NODE_FAILURE_MSG.value.format(
                str(e)
            )
            return msg

    @log_entry_exit
    def edit_capacity_management_settings(self, spec):

        if spec.is_capacity_balancing_enabled is None:
            return
        capacity_setting_prov = SDSBCapacityManagementSettingsProvisioner(
            self.connection_info
        )
        response = capacity_setting_prov.get_capacity_management_settings()
        logger.writeDebug("RC:edit_capacity_management_settings:response={}", response)

        if not self.is_edit_capacity_needed(response, spec):
            return response

        resp = self.provisioner.edit_capacity_management_settings(
            spec.is_capacity_balancing_enabled, spec.controller_id
        )
        logger.writeDebug("RC:edit_capacity_management_settings:resp={}", resp)
        self.connection_info.changed = True
        response = capacity_setting_prov.get_capacity_management_settings()
        return self.display_response(response)

    @log_entry_exit
    def is_edit_capacity_needed(self, response, spec):
        if spec.controller_id is None:
            cluster_capacity_setting = response["storage_cluster"]["is_enabled"]
            if cluster_capacity_setting == spec.is_capacity_balancing_enabled:
                return False
            else:
                return True
        else:
            controllers = response["storage_controllers"]
            for x in controllers:
                if x["id"] == spec.controller_id:
                    if x["is_enabled"] == spec.is_capacity_balancing_enabled:
                        return False
                    else:
                        return True
        return False

    @log_entry_exit
    def display_response(self, response):
        return {
            "is_storage_cluster_capacity_balancing_enabled": response[
                "storage_cluster"
            ]["is_enabled"],
            "storage_controllers_capacity_balancing_settings": response[
                "storage_controllers"
            ],
        }

    @log_entry_exit
    def validate_input_for_storage_nodes(self, spec, json_object):
        logger.writeDebug(f"spec = {spec}")

        if spec.storage_nodes is None or len(spec.storage_nodes) == 0:
            raise ValueError(
                SDSBClusterValidationMsg.COFIG_FILE_OR_SROARGE_NODES_REQD.value
            )

        cluster_fault_domains = json_object.get("fault_domains")
        cluster_fault_domain_names = []
        for x in cluster_fault_domains:
            cluster_fault_domain_names.append(x.get("fault_domain_name"))

        cluster_control_nw_ips = []
        cluster_inter_node_nw_ips = []
        cluster_compute_nw_ips = []
        control_internode_nw_route_gws = set()
        cluster_nodes = json_object.get("nodes")
        logger.writeDebug(f"cluster_nodes = {cluster_nodes}")
        for x in cluster_nodes:
            cluster_control_nw_ips.append(x.get("control_network_ip"))
            cluster_inter_node_nw_ips.append(x.get("internode_network_ip"))
            cluster_compute_nw_ips.append(
                x.get("compute_network_ip_1")
            )  # Add logic to find out compute_network_ip_2 etc.
            control_internode_nw_route_gws.add(
                x.get("control_internode_network_route_gateway_1")
            )

        # logger.writeDebug(f"cluster_control_nw_ips = {cluster_control_nw_ips}")
        # logger.writeDebug(f"cluster_inter_node_nw_ips = {cluster_inter_node_nw_ips}")
        # logger.writeDebug(f"cluster_compute_nw_ips = {cluster_compute_nw_ips}")
        # logger.writeDebug(f"control_internode_nw_route_gws = {control_internode_nw_route_gws}")

        for storage_node in spec.storage_nodes:
            if storage_node.fault_domain_name not in cluster_fault_domain_names:
                raise ValueError(
                    SDSBClusterValidationMsg.FD_NOT_IN_CLUSTER.value.format(
                        storage_node.fault_domain_name, cluster_fault_domain_names
                    )
                )
            if (
                storage_node.control_network.control_network_ip
                in cluster_control_nw_ips
            ):
                raise ValueError(
                    SDSBClusterValidationMsg.CONTROL_IP_ALREADY_IN_CLUSTER.value.format(
                        storage_node.control_network.control_network_ip,
                        cluster_control_nw_ips,
                    )
                )
            if (
                storage_node.internode_network.internode_network_ip
                in cluster_inter_node_nw_ips
            ):
                raise ValueError(
                    SDSBClusterValidationMsg.INTER_NODE_IP_ALREADY_IN_CLUSTER.value.format(
                        storage_node.internode_network.internode_network_ip,
                        cluster_inter_node_nw_ips,
                    )
                )
            spec_compute_nws = storage_node.compute_networks
            for x in spec_compute_nws:
                if x.compute_network_ip in cluster_compute_nw_ips:
                    raise ValueError(
                        SDSBClusterValidationMsg.COMPUTE_IP_ALREADY_IN_CLUSTER.value.format(
                            x.compute_network_ip,
                            cluster_compute_nw_ips,
                        )
                    )
            if storage_node.control_network.control_network_subnet:
                subnet_mask = storage_node.control_network.control_network_subnet
                if subnet_mask == "255.255.255.255" or subnet_mask == "0.0.0.0":
                    raise ValueError(SDSBClusterValidationMsg.INVALID_SUBNET_MASK.value)
            if storage_node.internode_network.internode_network_subnet:
                subnet_mask = storage_node.internode_network.internode_network_subnet
                if subnet_mask == "255.255.255.255" or subnet_mask == "0.0.0.0":
                    raise ValueError(SDSBClusterValidationMsg.INVALID_SUBNET_MASK.value)
            if storage_node.compute_networks and len(storage_node.compute_networks):
                for cn in storage_node.compute_networks:
                    if cn.compute_network_subnet:
                        subnet_mask = cn.compute_network_subnet
                        if subnet_mask == "255.255.255.255" or subnet_mask == "0.0.0.0":
                            raise ValueError(
                                SDSBClusterValidationMsg.INVALID_SUBNET_MASK.value
                            )

            if storage_node.control_internode_network is None:
                storage_node.control_internode_network = ControlInternodeNetworkSpec()
                storage_node.control_internode_network.control_internode_network_route_destinations = [
                    "default"
                ]
                storage_node.control_internode_network.control_internode_network_route_gateways = list(
                    control_internode_nw_route_gws
                )
                storage_node.control_internode_network.control_internode_network_route_interfaces = [
                    "control"
                ]
            else:
                if (
                    storage_node.control_internode_network.control_internode_network_route_destinations
                    is None
                ):
                    storage_node.control_internode_network.control_internode_network_route_destinations = [
                        "default"
                    ]
                if (
                    storage_node.control_internode_network.control_internode_network_route_gateways
                    is None
                ):
                    storage_node.control_internode_network.control_internode_network_route_gateways = list(
                        control_internode_nw_route_gws
                    )
                if (
                    storage_node.control_internode_network.control_internode_network_route_interfaces
                    is None
                ):
                    storage_node.control_internode_network.control_internode_network_route_interfaces = [
                        "control"
                    ]

            logger.writeDebug(f"spec2 = {spec}")

    @log_entry_exit
    def get_line_entries(self, spec):
        lines = []
        for storage_node in spec.storage_nodes:
            host_name = storage_node.host_name
            fault_domain_name = storage_node.fault_domain_name
            cluster_master_role = ""
            if storage_node.is_cluster_master_role is True:
                cluster_master_role = "clustermaster"
            control_nw_ip_v4 = storage_node.control_network.control_network_ip
            control_nw_ip_v4_subnet = (
                storage_node.control_network.control_network_subnet
            )
            control_nw_ip_v4_size = (
                storage_node.control_network.control_network_mtu_size
            )

            internode_nw_ip_v4 = storage_node.internode_network.internode_network_ip
            internode_nw_ip_v4_subnet = (
                storage_node.internode_network.internode_network_subnet
            )
            internode_nw_ip_v4_size = (
                storage_node.internode_network.internode_network_mtu_size
            )
            control_internode_network = storage_node.control_internode_network
            ctrl_in_nw_route_dests = ""
            for (
                x
            ) in control_internode_network.control_internode_network_route_destinations:
                ctrl_in_nw_route_dests = ctrl_in_nw_route_dests + x + ","

            ctrl_in_nw_route_gws = ""
            for x in control_internode_network.control_internode_network_route_gateways:
                ctrl_in_nw_route_gws = ctrl_in_nw_route_gws + x + ","

            ctrl_in_nw_route_if = ""
            for (
                x
            ) in control_internode_network.control_internode_network_route_interfaces:
                ctrl_in_nw_route_if = ctrl_in_nw_route_if + x + ","

            no_of_fc_ports = 0
            if storage_node.number_of_fc_target_port:
                no_of_fc_ports = storage_node.number_of_fc_target_port

            compute_nw_str = ""
            for x in storage_node.compute_networks:
                if x.compute_port_protocol:
                    compute_nw_str = compute_nw_str + x.compute_port_protocol + ","
                else:
                    compute_nw_str = compute_nw_str + "iSCSI" + ","
                compute_nw_str = compute_nw_str + x.compute_network_ip + ","
                compute_nw_str = compute_nw_str + x.compute_network_subnet + ","
                compute_nw_str = (
                    compute_nw_str + x.compute_network_gateway + ","
                )  # Find the GW from the file??
                if (
                    x.is_compute_network_ipv6_mode
                    and x.is_compute_network_ipv6_mode is True
                ):
                    compute_nw_str = compute_nw_str + "Enable" + ","
                    # Add code for IP v6 entries
                else:
                    compute_nw_str = compute_nw_str + "Disable" + ","
                    compute_nw_str = compute_nw_str + ",,,"
                compute_nw_str = compute_nw_str + str(x.compute_network_mtu_size)

            line = (
                f"{host_name},{fault_domain_name},{cluster_master_role},{control_nw_ip_v4},{control_nw_ip_v4_subnet},{control_nw_ip_v4_size},"
                f"{internode_nw_ip_v4},{internode_nw_ip_v4_subnet},{internode_nw_ip_v4_size},{ctrl_in_nw_route_dests}{ctrl_in_nw_route_gws}"
                f"{ctrl_in_nw_route_if}{no_of_fc_ports},{compute_nw_str}"
            )

            lines.append(line)

        return lines

    @log_entry_exit
    def add_storage_node_azure(self, spec=None):
        self.create_config_file_for_add_storage_node(spec)
        exported_config_file = self.download_config_file_azure()
        resp = self.provisioner.add_storage_node(
            spec.setup_user_password, exported_config_file=exported_config_file
        )
        return resp

    @log_entry_exit
    def add_storage_node_aws(self, spec=None):
        if spec.configuration_file is None or spec.vm_configuration_file_s3_uri is None:
            raise ValueError(SDSBClusterValidationMsg.AWS_ADD_STORAGE_NODE_REQD.value)
        resp = self.provisioner.add_storage_node(
            spec.setup_user_password,
            config_file=spec.configuration_file,
            vm_configuration_file_s3_uri=spec.vm_configuration_file_s3_uri,
        )
        return resp

    @log_entry_exit
    def add_storage_node_gcp(self, spec=None):
        resp = self.provisioner.add_storage_node(
            spec.setup_user_password, config_file=spec.configuration_file
        )
        return resp

    @log_entry_exit
    def add_storage_node_bare_metal(self, spec=None):
        logger.writeDebug(f"PROV:add_storage_node_bare_metal={spec}")
        if spec.configuration_file:
            resp = self.provisioner.add_storage_node(
                spec.setup_user_password, config_file=spec.configuration_file
            )
        else:
            dest_folder = self.download_and_unzip_config_file()
            file_name = "SystemConfigurationFile.csv"
            file_path = f"{dest_folder}/{file_name}"
            json_object = get_json_for_config_file(file_path)
            logger.writeDebug(f"json_object = {json_object}")
            new_json = SDSBClusterExtractor().extract(json_object)
            logger.writeDebug(f"new_json = {new_json}")
            self.validate_input_for_storage_nodes(spec, new_json)
            line_entries = self.get_line_entries(spec)
            self.append_lines_to_config_file(file_path, line_entries)
            spec.configuration_file = file_path

            resp = self.provisioner.add_storage_node(
                spec.setup_user_password, config_file=spec.configuration_file
            )
        return resp

    @log_entry_exit
    def add_storage_node(self, spec=None):
        resp = None
        cloud_platforms = ["Google, Inc.", "Msft", "Amazon.com, Inc"]
        platform = self.provisioner.get_platform()
        logger.writeDebug(f"add_storage_node:spec = {spec}  platform = {platform}")
        if platform in cloud_platforms and spec.setup_user_password is None:
            spec.setup_user_password = (
                "CHANGE_ME_SET_YOUR_PASSWORD"  # set dummy password for clouds
            )

        if spec.setup_user_password is None:
            raise ValueError(
                SDSBClusterValidationMsg.STORAGE_NODE_SETUP_PASSWD_REQD.value
            )
        if spec.configuration_file:
            if not os.path.isfile(spec.configuration_file):
                raise ValueError(
                    SDSBClusterValidationMsg.CONFIG_FILE_DOES_NOT_EXIST.value.format(
                        spec.configuration_file
                    )
                )

        if platform == "Msft":
            resp = self.add_storage_node_azure(spec)

        elif platform == "Amazon.com, Inc":
            resp = self.add_storage_node_aws(spec)

        elif platform == "Google, Inc.":
            resp = self.add_storage_node_gcp(spec)

        else:  # Bare Metal
            resp = self.add_storage_node_bare_metal(spec)

        msg = SDSBClusterValidationMsg.ADD_STORAGE_NODE_SUCCESS_MSG.value.format(resp)
        self.connection_info.changed = True
        return msg

    @log_entry_exit
    def create_config_file_for_add_storage_node(self, spec=None):
        if spec is None:
            raise ValueError(SDSBClusterValidationMsg.SPEC_NONE.value)

        spec.export_file_type = "AddStorageNodes"
        if spec.machine_image_id is None:
            raise ValueError(SDSBClusterValidationMsg.SPEC_NONE.value)

        self.provisioner.create_config_file_for_add_storage_node(
            spec.machine_image_id, spec.template_s3_url
        )

    @log_entry_exit
    def append_lines_to_config_file(self, file_path, lines_to_append):
        try:
            # Open the file in append mode ('a')
            with open(file_path, "a") as file:
                # Iterate through the list of lines and write each to the file
                for line in lines_to_append:
                    file.write(line)
            logger.writeDebug(
                f"Lines {lines_to_append} successfully appended to {file_path}"
            )

        except IOError as e:
            raise ValueError(f"Error appending to file: {e}")

    @log_entry_exit
    def remove_storage_node(self, spec):
        if spec.node_id is None and spec.node_name is None:
            raise ValueError(
                SDSBClusterValidationMsg.NO_NAME_OR_ID_FOR_STORAGE_NODE.value
            )
        try:
            if spec.node_id is None:
                storage_node_prov = SDSBStorageNodeProvisioner(self.connection_info)
                spec.node_id = storage_node_prov.get_node_id_by_node_name(
                    spec.node_name
                )
                if spec.node_id is None:
                    raise ValueError(
                        SDSBClusterValidationMsg.STORAGE_NODE_NOT_FOUND.value.format(
                            spec.node_name
                        )
                    )
            resp = self.provisioner.remove_storage_node(spec.node_id)
            msg = SDSBClusterValidationMsg.REMOVE_STORAGE_NODE_SUCCESS_MSG.value.format(
                resp
            )
            self.connection_info.changed = True
            return msg
        except Exception as e:
            logger.writeException(e)
            raise Exception(e)

    @log_entry_exit
    def create_config_file(self, spec=None):
        platform = self.provisioner.get_platform()
        logger.writeDebug(f"PROV:create_config_file:platform={platform}")

        # This code is for testing on bare metal to check the request before testing on cloud.
        # comment this out when testing is done
        # if platform == "HP":
        # return self.create_config_file_gcp(spec)
        # return self.create_config_file_azure(spec)

        if platform == "Msft":
            return self.create_config_file_azure(spec)
        elif platform == "Google, Inc.":
            return self.create_config_file_gcp(spec)
        elif platform == "Amazon.com, Inc":
            return self.create_config_file_aws(spec)
        else:
            return self.create_config_file_bare_matel(spec)

    @log_entry_exit
    def create_config_file_azure(self, spec=None):
        if spec is None:
            raise ValueError(SDSBClusterValidationMsg.SPEC_REQD_CONFIG_CLOUD.value)
        azure_export_file_types = [
            "AddStorageNodes",
            "ReplaceStorageNode",
            "AddDrives",
            "Normal",
        ]
        platform = "Microsoft Azure"
        if spec.export_file_type is None:
            raise ValueError(
                SDSBClusterValidationMsg.EXPORT_FILE_TYPE_REQD_CONFIG_CLOUD.value.format(
                    platform
                )
            )
        else:
            exf_type = spec.export_file_type
            if exf_type not in azure_export_file_types:
                raise ValueError(
                    SDSBClusterValidationMsg.INVALID_EXPORT_FILE_TYPE.value.format(
                        platform, azure_export_file_types
                    )
                )

            if exf_type == "AddStorageNodes" or exf_type == "ReplaceStorageNode":
                if spec.machine_image_id is None:
                    raise ValueError(
                        SDSBClusterValidationMsg.MACHINE_IMAGE_ID_REQD_CONFIG_CLOUD.value.format(
                            platform
                        )
                    )
                if exf_type == "AddStorageNodes":
                    return self.provisioner.create_config_file_for_add_storage_node(
                        spec.machine_image_id
                    )
                if exf_type == "ReplaceStorageNode":
                    return self.provisioner.create_config_file_to_replace_storage_node(
                        spec
                    )
            elif exf_type == "AddDrives":
                if spec.no_of_drives is None:
                    raise ValueError(
                        SDSBClusterValidationMsg.NO_OF_DRIVES_REQD_CONFIG_CLOUD.value.format(
                            platform
                        )
                    )
                return self.provisioner.create_config_file_for_add_drives(
                    spec.no_of_drives
                )
            elif exf_type == "Normal":
                return self.provisioner.create_config_file("normal")

    @log_entry_exit
    def create_config_file_gcp(self, spec=None):
        if spec is None:
            raise ValueError(SDSBClusterValidationMsg.SPEC_REQD_CONFIG_CLOUD.value)
        gcp_export_file_types = [
            "AddStorageNodes",
            "ReplaceStorageNode",
            "AddDrives",
            "ReplaceDrive",
            "Normal",
        ]
        platform = "Google"
        if spec.export_file_type is None:
            raise ValueError(
                SDSBClusterValidationMsg.EXPORT_FILE_TYPE_REQD_CONFIG_CLOUD.value.format(
                    platform
                )
            )
        else:
            exf_type = spec.export_file_type
            if exf_type not in gcp_export_file_types:
                raise ValueError(
                    SDSBClusterValidationMsg.INVALID_EXPORT_FILE_TYPE.value.format(
                        platform, gcp_export_file_types
                    )
                )

            if exf_type == "AddStorageNodes" or exf_type == "ReplaceStorageNode":
                if spec.machine_image_id is None:
                    raise ValueError(
                        SDSBClusterValidationMsg.MACHINE_IMAGE_ID_REQD_CONFIG_CLOUD.value.format(
                            platform
                        )
                    )
                if exf_type == "AddStorageNodes":
                    return self.provisioner.create_config_file_for_add_storage_node(
                        spec.machine_image_id
                    )
                if exf_type == "ReplaceStorageNode":
                    if spec.node_id is None:
                        raise ValueError(
                            SDSBClusterValidationMsg.NODE_ID_IS_REQD.value.format(
                                platform
                            )
                        )
                    return self.provisioner.create_config_file_to_replace_storage_node(
                        spec
                    )
            elif exf_type == "AddDrives":
                if spec.no_of_drives is None:
                    raise ValueError(
                        SDSBClusterValidationMsg.NO_OF_DRIVES_REQD_CONFIG_CLOUD.value.format(
                            platform
                        )
                    )
                return self.provisioner.create_config_file_for_add_drives(
                    spec.no_of_drives
                )
            elif exf_type == "ReplaceDrive":
                raise ValueError(
                    SDSBClusterValidationMsg.OPERATION_NOT_SUPPORTED_YET.value.format(
                        platform
                    )
                )
            elif exf_type == "Normal":
                return self.provisioner.create_config_file("normal")

    @log_entry_exit
    def create_config_file_aws(self, spec=None):
        if spec is None:
            raise ValueError(SDSBClusterValidationMsg.SPEC_REQD_CONFIG_CLOUD.value)
        aws_export_file_types = [
            "AddStorageNodes",
            "ReplaceStorageNode",
            "AddDrives",
            "ReplaceDrive",
            "Normal",
        ]
        platform = "AWS"
        if spec.export_file_type is None:
            raise ValueError(
                SDSBClusterValidationMsg.EXPORT_FILE_TYPE_REQD_CONFIG_CLOUD.value.format(
                    platform
                )
            )
        else:
            exf_type = spec.export_file_type
            if exf_type not in aws_export_file_types:
                raise ValueError(
                    SDSBClusterValidationMsg.INVALID_EXPORT_FILE_TYPE.value.format(
                        platform, aws_export_file_types
                    )
                )

            if spec.template_s3_url is None:
                raise ValueError(SDSBClusterValidationMsg.MUST_SPECIFY_S3_URL.value)
            if not spec.template_s3_url.startswith("https://"):
                raise ValueError(SDSBClusterValidationMsg.MUST_SPECIFY_S3_URL.value)

            if exf_type == "AddStorageNodes" or exf_type == "ReplaceStorageNode":
                if spec.machine_image_id is None:
                    raise ValueError(
                        SDSBClusterValidationMsg.MACHINE_IMAGE_ID_REQD_CONFIG_CLOUD.value.format(
                            platform
                        )
                    )
                if exf_type == "AddStorageNodes":
                    return self.provisioner.create_config_file_for_add_storage_node(
                        spec.machine_image_id, spec.template_s3_url
                    )
                if exf_type == "ReplaceStorageNode":
                    return self.provisioner.create_config_file_to_replace_storage_node(
                        spec
                    )
            elif exf_type == "AddDrives":
                if spec.no_of_drives is None:
                    raise ValueError(
                        SDSBClusterValidationMsg.NO_OF_DRIVES_REQD_CONFIG_CLOUD.value.format(
                            platform
                        )
                    )
                return self.provisioner.create_config_file_for_add_drives(
                    spec.no_of_drives
                )
            elif exf_type == "ReplaceDrive":
                raise ValueError(
                    SDSBClusterValidationMsg.OPERATION_NOT_SUPPORTED_YET.value.format(
                        platform
                    )
                )
            elif exf_type == "Normal":
                return self.provisioner.create_config_file("normal")

    @log_entry_exit
    def create_config_file_bare_matel(self, spec=None):
        return self.provisioner.create_config_file("normal")

    @log_entry_exit
    def download_config_file_azure(self):
        try:
            time_stamp = time.time_ns()
            file_name = f"/tmp/config_file_{time_stamp}.tar.gz"
            self.provisioner.download_config_file(file_name)
            return file_name
        except Exception as e:
            logger.writeException(e)
            raise Exception(e)

    @log_entry_exit
    def download_and_unzip_config_file(self, spec=None):
        try:
            time_stamp = time.time_ns()
            file_name = f"/tmp/config_file_{time_stamp}.tar.gz"
            self.provisioner.download_config_file(file_name)

            file_to_unzip = file_name
            if spec is None or spec.config_file_location is None:
                destination_folder = f"/tmp/{time_stamp}"
            else:
                destination_folder = spec.config_file_location
            resp = unzip_targz(file_to_unzip, destination_folder)
            if "Successfully" in resp:
                return destination_folder
            else:
                return None
        except Exception as e:
            logger.writeException(e)
            raise Exception(e)

    @log_entry_exit
    def download_config_file(self, spec):
        try:
            if spec.refresh and spec.refresh is True:
                self.create_config_file(spec)
                self.connection_info.changed = True
            resp = self.download_and_unzip_config_file(spec)
            if resp:
                return f"Successfully downloaded SystemConfigurationFile.csv in the directory {resp}."
            else:
                return "Failed to  downloaded SystemConfigurationFile.csv in the directory."
        except Exception as e:
            logger.writeException(e)
            raise Exception(e)

    @log_entry_exit
    def replace_storage_node(self, spec):

        if (spec.node_id is None and spec.node_name is None) or (
            spec.node_id is not None and spec.node_name is not None
        ):
            raise ValueError(SDSBClusterValidationMsg.NODE_ID_REQUIRED.value)
        storage_node_prov = SDSBStorageNodeProvisioner(self.connection_info)

        storage_node = None
        if spec.node_id is None and spec.node_name is not None:
            storage_node = storage_node_prov.get_storage_node_by_name(spec.node_name)
            spec.node_id = storage_node.id if storage_node is not None else None
        else:
            storage_node = storage_node_prov.get_storage_node_by_id(spec.node_id)

        if storage_node is None:
            raise ValueError(
                SDSBClusterValidationMsg.NOT_FOUND_WITH_STORAGE_NODE_ID.value.format(
                    spec.node_id if spec.node_id is not None else spec.node_name
                )
            )

        if storage_node.status.lower() not in STORAGE_NODE_STATUS:
            raise ValueError(
                SDSBClusterValidationMsg.STORAGE_NODE_INVALID_STATE.value.format(
                    spec.node_id, storage_node.status, STORAGE_NODE_STATUS
                )
            )

        platform = self.provisioner.get_platform()

        if GCP in platform:
            try:
                logger.writeInfo("Replacing storage node on GCP")
                job_id = (
                    self.provisioner.gateway.replace_storage_node_with_config_file_gcp(
                        spec
                    )
                )
                self.connection_info.changed = True
                return SDSBClusterValidationMsg.REPLACE_STORAGE_NODE_SUCCESS_MSG.value.format(
                    job_id
                )
            except Exception as e:
                logger.writeError(f"Error replacing storage node on GCP: {e}")
                return (
                    SDSBClusterValidationMsg.FAILED_REPLACE_STORAGE_NODE.value.format(e)
                )
        elif AZURE in platform:
            try:
                # first create config file
                logger.writeInfo("Creating config file to replace storage node")
                self.provisioner.create_config_file_to_replace_storage_node(spec)
                # download the config file
                logger.writeInfo("Downloading config file to replace storage node")
                file_name = self.download_config_file_azure()
                spec.exported_config_file = file_name
                logger.writeDebug(f"exported_config_file = {spec.exported_config_file}")
                # replace the storage node
                logger.writeInfo("Replacing storage node on Azure")
                job_id = self.provisioner.gateway.replace_storage_node_with_config_file_azure(
                    spec
                )
                self.connection_info.changed = True
                return SDSBClusterValidationMsg.REPLACE_STORAGE_NODE_SUCCESS_MSG.value.format(
                    job_id
                )
            except Exception as e:
                logger.writeError(f"Error replacing storage node on Azure: {e}")
                return (
                    SDSBClusterValidationMsg.FAILED_REPLACE_STORAGE_NODE.value.format(e)
                )
        elif AWS in platform:
            try:
                if spec.vm_configuration_file_s3_uri is None:
                    raise ValueError(SDSBClusterValidationMsg.MUST_SPECIFY_S3_URL.value)

                if spec.configuration_file is None:
                    raise ValueError(SDSBClusterValidationMsg.CONFIG_FILE_REQD.value)

                job_id = (
                    self.provisioner.gateway.replace_storage_node_with_config_file_aws(
                        spec
                    )
                )
                self.connection_info.changed = True
                return SDSBClusterValidationMsg.REPLACE_STORAGE_NODE_SUCCESS_MSG.value.format(
                    job_id
                )
            except Exception as e:
                logger.writeError(f"Error replacing storage node on AWS: {e}")
                return (
                    SDSBClusterValidationMsg.FAILED_REPLACE_STORAGE_NODE.value.format(e)
                )
        else:
            try:
                if spec.setup_user_password is None:
                    raise ValueError(
                        SDSBClusterValidationMsg.STORAGE_NODE_SETUP_PASSWD_REQD.value
                    )
                job_id = self.provisioner.gateway.replace_storage_node_with_config_file_bare_metal(
                    spec
                )
                self.connection_info.changed = True
                return SDSBClusterValidationMsg.REPLACE_STORAGE_NODE_SUCCESS_MSG.value.format(
                    job_id
                )
            except Exception as e:
                logger.writeError(f"Error replacing storage node on BareMetal: {e}")
                return (
                    SDSBClusterValidationMsg.FAILED_REPLACE_STORAGE_NODE.value.format(e)
                )

    @log_entry_exit
    def get_storage_time_settings(self):
        return self.provisioner.get_storage_time_settings()


class SDSBClusterExtractor:
    def __init__(self):
        self.parameter_mapping = {
            "General": "general",
            "SSHConnectWait(sec)": "ssh_connection_wait_in_sec",
            "ClusterReadyWait(sec)": "cluster_ready_wait_in_sec",
            "StartupWait(sec)": "startup_wait_in_sec",
            "ReplicaSetMemberAddWait(sec)": "replica_set_member_add_wait_in_sec",
            "ReplicaSetCompletionWait(sec)": "replica_set_completion_wait_in_sec",
            "DataModelCRUDOperationWait(sec)": "data_model_crud_operation_wait_in_sec",
            "Watchdog-msec": "watchdog_in_msec",
            "CSVversion": "cvs_version",
            "Cluster": "cluster",
            "ClusterName": "cluster_name",
            "vCenterServerHostName": "vcenter_server_host_name",
            "DataCenterName": "data_center_name",
            "TemplateFileName": "template_file_name",
            "NtpServer1": "ntp_server_1",
            "NtpServer2": "ntp_server_2",
            "Timezone": "time_zone",
            "DnsServer1": "dns_server_1",
            "DnsServer2": "dns_server_2",
            "ClusterIpv4Address": "cluster_ip_v4_address",
            "ProtectionDomains": "protection_domains",
            "ProtectionDomainName": "protection_domain_name",
            "StoragePoolName": "storage_pool_name",
            "RedundantPolicy": "redundant_policy",
            "RedundantType": "redundant_type",
            "AsyncProcessingResourceUsageRate": "async_processing_resource_usage_rate",
            "FaultDomains": "fault_domains",
            "FaultDomainName": "fault_domain_name",
            "FCPortSetting": "fc_port_setting",
            "Topology": "topology",
            "Speed": "speed",
            "Nodes": "nodes",
            "HostName": "host_name",
            "VMName": "vm_name",
            "ClusterMasterRole": "cluster_master_role",
            "ControlNWIPv4": "control_network_ip",
            "ControlNWIPv4Subnet": "control_network_subnet",
            "ControlNWMTUSize": "control_network_mtu_size",
            "InterNodeNWPortGroupName": "internode_network_port_group_name",
            "InterNodeNWIPv4": "internode_network_ip",
            "InterNodeNWIPv4Subnet": "internode_network_subnet",
            "InterNodeNWMTUSize": "internode_network_mtu_size",
            "ControlInterNodeNWIPv4RouteDestination1": "control_internode_network_route_destination_1",
            "ControlInterNodeNWIPv4RouteGateway1": "control_internode_network_route_gateway_1",
            "ControlInterNodeNWIPv4RouteInterface1": "control_internode_network_route_interface_1",
            "NumberOfFCTargetPort": "number_of_fc_target_port",
            "ComputePortProtocol1": "compute_port_protocol_1",
            "ComputeNWPortGroupName1": "compute_network_port_group_name_1",
            "ComputeNWIPv4Address1": "compute_network_ip_1",
            "ComputeNWIPv4Subnet1": "compute_network_subnet_1",
            "ComputeNWIPv4Gateway1": "compute_network_gateway_1",
            "ComputeNWIPv6Mode1": "compute_network_ip_v6_mode_1",
            "ComputeNWIPv6Global1_1": "compute_network_ipv6_global_1_1",
            "ComputeNWIPv6SubnetPrefix1": "compute_network_ipv6_subnet_prefix_1",
            "ComputeNWIPv6Gateway1": "compute_network_ipv6_gateway_1",
            "ComputeNWMTUSize1": "compute_network_mtu_size_1",
        }

    def process_list(self, response_key):
        new_items = []

        if response_key is None:
            return []
        for item in response_key:
            new_dict = {}
            for key, value in item.items():
                key = self.parameter_mapping.get(key, None)
                # key = camel_to_snake_case(key)

                if value is None:
                    # default_value = get_default_value(value_type)
                    # value = default_value
                    continue
                if key is None:
                    continue
                new_dict[key] = value
            new_items.append(new_dict)

        return new_items

    def process_dict(self, response_key):

        if response_key is None:
            return {}

        new_dict = {}
        for key in response_key.keys():
            value = response_key.get(key, None)
            key = self.parameter_mapping.get(key, None)
            # key = camel_to_snake_case(key)

            if value is None:
                # default_value = get_default_value(value_type)
                # value = default_value
                continue
            if key is None:
                continue
            new_dict[key] = value

        return new_dict

    def extract(self, old_dict):
        new_dict = {}
        for key in old_dict.keys():
            # if key in self.parameter_mapping.keys():
            new_key = self.parameter_mapping.get(key, None)
            if new_key is None:
                continue
            # new_key = camel_to_snake_case(key)
            value = old_dict[key]
            value_type = type(value)
            if value_type == list:
                new_dict[new_key] = self.process_list(value)
            elif value_type == dict:
                new_dict[new_key] = self.process_dict(value)
            else:
                new_dict[new_key] = old_dict[key]

        return new_dict
