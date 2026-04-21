try:
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit

except ImportError:
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

DOWNLOAD_CONFIG_FILE = "v1/objects/configuration-file/download"
CREATE_CONFIG_FILE = "v1/objects/configuration-file/actions/create/invoke"
ADD_STORAGE_NODE = "v1/objects/storage-nodes"
DELETE_STORAGE_NODE = "v1/objects/storage-nodes/{}"
STOP_REMOVING_STORAGE_NODE = (
    "v1/objects/storage/actions/stop-removing-storage-nodes/invoke"
)
EDIT_CAPACITY_SETTING = "v1/objects/capacity-settings"
REPLACE_STORAGE_NODE_WITH_CONFIG_FILE = (
    "v1/objects/storage-nodes/{}/actions/replace-with-configuration-file/invoke"
)
REPLACE_STORAGE_NODE = "v1/objects/storage-nodes/{}/actions/replace/invoke"
IMPORT_SYSTEM_REQUIREMENTS_FILE = (
    "v1/objects/system-requirements-file/actions/import/invoke"
)
STOP_STORAGE_CLUSTER = "v1/objects/storage/actions/shutdown/invoke"
logger = Log()

export_file_type_map = {
    "normal": "Normal",
    "add_storage_nodes": "AddStorageNodes",
    "replace_storage_nodes": "ReplaceStorageNode",
    "add_drives": "AddDrives",
    "replace_drives": "ReplaceDrive",
}


class SDSBClusterGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def import_system_requirement_file(self, system_requirement_file):
        end_point = IMPORT_SYSTEM_REQUIREMENTS_FILE
        resp = self.connection_manager.upload_file(
            end_point, system_requirement_file, "systemRequirementsFile", True
        )
        logger.writeDebug(f"GW:import_system_requirement_file:resp={resp}")
        return resp

    @log_entry_exit
    def stop_storage_cluster(
        self, force=False, reboot=False, config_parameter_setting_mode=False
    ):
        end_point = STOP_STORAGE_CLUSTER
        payload = {
            "force": force,
            "reboot": reboot,
            "configParameterSettingMode": config_parameter_setting_mode,
        }
        resp = self.connection_manager.post(end_point, payload, long_running=True)
        logger.writeDebug(f"GW:stop_storage_cluster:resp={resp}")
        return resp

    def create_config_file(self, export_file_type):
        end_point = CREATE_CONFIG_FILE
        payload = {"exportFileType": export_file_type_map[export_file_type]}
        resp = self.connection_manager.post(end_point, data=payload)
        logger.writeDebug(f"GW:create_config_file:resp={resp}")
        return

    def create_config_file_for_add_storage_node(
        self, machine_image_id, template_s3_url=None
    ):
        end_point = CREATE_CONFIG_FILE
        payload = {
            "exportFileType": "AddStorageNodes",
            "machineImageId": machine_image_id,
        }
        if template_s3_url:
            payload["templateS3Url"] = template_s3_url
        resp = self.connection_manager.post(end_point, data=payload)
        logger.writeDebug(f"GW:create_config_file_for_add_storage_node:resp={resp}")
        return

    def create_config_file_to_replace_storage_node(
        self,
        machine_image_id,
        template_s3_url=None,
        node_id=None,
        should_recover_single_node=False,
    ):
        end_point = CREATE_CONFIG_FILE
        payload = {
            "exportFileType": "ReplaceStorageNode",
            "machineImageId": machine_image_id,
        }
        if template_s3_url:
            payload["templateS3Url"] = template_s3_url
        if node_id:
            payload["nodeId"] = node_id
        if should_recover_single_node:
            payload["recoverSingleNode"] = should_recover_single_node
        resp = self.connection_manager.post(end_point, data=payload)
        logger.writeDebug(f"GW:create_config_file_to_replace_storage_node:resp={resp}")
        return

    def create_config_file_for_add_drives(self, no_of_drives):
        end_point = CREATE_CONFIG_FILE
        payload = {
            "exportFileType": "AddDrives",
            "numberOfDrives": no_of_drives,
        }
        resp = self.connection_manager.post(end_point, data=payload)
        logger.writeDebug(f"GW:create_config_file_for_add_drives:resp={resp}")
        return

    @log_entry_exit
    def download_config_file(self, file_name):
        end_point = DOWNLOAD_CONFIG_FILE
        resp = self.connection_manager.download_file(end_point)
        # logger.writeDebug(f"GW:download_config_file:resp={resp}")
        with open(file_name, mode="wb") as file:
            file.write(resp)
        return

    @log_entry_exit
    def add_storage_node(
        self,
        setup_user_password,
        config_file=None,
        exported_config_file=None,
        vm_configuration_file_s3_uri=None,
    ):
        # logger.writeDebug(
        #     f"GW:add_storage_node:config_file={config_file}, setup_user_password={setup_user_password}, exported_config_file={exported_config_file}"
        # )
        end_point = ADD_STORAGE_NODE
        resp = self.connection_manager.add_storage_node(
            end_point,
            setup_user_password,
            config_file,
            exported_config_file,
            vm_configuration_file_s3_uri,
        )

        return resp

    @log_entry_exit
    def remove_storage_node(self, id):
        end_point = DELETE_STORAGE_NODE.format(id)
        resp = self.connection_manager.remove_storage_node(end_point)

        return resp

    @log_entry_exit
    def edit_capacity_management_settings(
        self, is_capacity_balancing_enabled, controller_id=None
    ):
        end_point = EDIT_CAPACITY_SETTING.format(id)
        payload = {}
        if controller_id is None:
            payload["type"] = "StorageCluster"
        else:
            payload["type"] = "StorageController"
            payload["id"] = controller_id

        payload["isEnabled"] = is_capacity_balancing_enabled
        resp = self.connection_manager.patch(end_point, data=payload)
        logger.writeDebug(
            f"GW:edit_capacity_management_settings:capacity_saving={resp}"
        )
        return resp

    @log_entry_exit
    def stop_removing_storage_nodes(self):
        end_point = STOP_REMOVING_STORAGE_NODE
        resp = self.connection_manager.post(end_point, data=None)
        logger.writeDebug(f"GW:stop_removing_storage_nodes:resp={resp}")
        return resp

    @log_entry_exit
    def replace_storage_node_with_config_file_gcp(self, spec):
        end_point = REPLACE_STORAGE_NODE_WITH_CONFIG_FILE.format(spec.node_id)
        header = {"Content-Length": 0}
        resp = self.connection_manager.post(
            end_point, data=None, headers_input=header, long_running=True
        )
        logger.writeDebug(f"GW:replace_storage_node:resp={resp}")
        return resp

    @log_entry_exit
    def replace_storage_node_with_config_file_azure(self, spec):
        end_point = REPLACE_STORAGE_NODE_WITH_CONFIG_FILE.format(spec.node_id)

        resp = self.connection_manager.add_storage_node(
            end_point,
            exported_config_file=spec.exported_config_file,
        )

        return resp

    @log_entry_exit
    def replace_storage_node_with_config_file_aws(self, spec):
        end_point = REPLACE_STORAGE_NODE_WITH_CONFIG_FILE.format(spec.node_id)

        resp = self.connection_manager.add_storage_node(
            end_point,
            vm_configuration_file_s3_uri=spec.vm_configuration_file_s3_uri,
            config_file=spec.configuration_file,
        )

        return resp

    @log_entry_exit
    def replace_storage_node_with_config_file_bare_metal(self, spec):
        end_point = REPLACE_STORAGE_NODE.format(spec.node_id)

        payload = {
            "setupUserPassword": spec.setup_user_password,
        }
        resp = self.connection_manager.post(end_point, data=payload, long_running=True)
        logger.writeDebug(f"GW:replace_storage_node:resp={resp}")
        return resp
