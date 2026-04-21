try:

    from .gateway_manager import VSPConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from ..common.vsp_storage_models import VSPStorageModelsManager
    from ..model.vsp_resource_group_models import (
        VspResourceGroupInfo,
        VspResourceGroupInfoList,
        VirtualStorageMachineInfo,
        VirtualStorageMachineInfoList,
    )
except ImportError:
    from .gateway_manager import VSPConnectionManager
    from common.hv_log import Log
    from common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from common.vsp_storage_models import VSPStorageModelsManager
    from model.vsp_resource_group_models import (
        VspResourceGroupInfo,
        VspResourceGroupInfoList,
        VirtualStorageMachineInfo,
        VirtualStorageMachineInfoList,
    )

GET_RESOURCE_GROUPS_DIRECT = "v1/objects/resource-groups"
GET_RESOURCE_GROUPS_WITH_PARAM_DIRECT = "v1/objects/resource-groups{}"
GET_RESOURCE_GROUP_BY_ID_DIRECT = (
    "v1/objects/resource-groups/{}?detailInfoType=nvmSubsystemIds"
)
GET_RESOURCE_GROUP_BY_ID_NO_DETAIL_DIRECT = "v1/objects/resource-groups/{}"
CREATE_RESOURCE_GROUP_DIRECT = "v1/objects/resource-groups"
ADD_RESOURCE_TO_RESOURCE_GROUP_DIRECT = (
    "v1/objects/resource-groups/{}/actions/add-resource/invoke"
)
REMOVE_RESOURCE_FROM_RESOURCE_GROUP_DIRECT = (
    "v1/objects/resource-groups/{}/actions/remove-resource/invoke"
)
DELETE_RESOURCE_GROUP_DIRECT = "v1/objects/resource-groups/{}"
GET_LDEVS_BY_POOL_ID_DIRECT = "v1/objects/ldevs?poolId={}"
GET_STORAGE_DEVICE_ID_BY_SERIAL_DIRECT = "v1/objects/storages"
GET_VIRTUAL_STORAGE_DEVICE_ID_DIRECT = "v1/objects/storages/{}/virtual-storages"
GET_DP_POOLS_DIRECT = "v1/objects/storages/{}/pools?poolType=DP"
GET_HTI_POOLS_DIRECT = "v1/objects/storages/{}/pools?poolType=HTI"
GET_LDEV_BY_ID_DIRECT = "v1/objects/storages/{}/ldevs/{}"

CREATE_VSM_RESOURCE_GROUP_DIRECT = "v1/objects/virtual-storages"
GET_VSM_BY_ID_DIRECT = "v1/objects/virtual-storages/{}"
GET_VSM_DIRECT = "v1/objects/virtual-storages"

logger = Log()

INPUT_TO_REST_MAP = {
    "ldevs": "ldevIds",
    "host_groups": "hostGroupIds",
    "ports": "portIds",
    "parity_groups": "parityGroupIds",
    "external_parity_groups": "externalParityGroupIds",
    "nvm_subsystem_ids": "nvmSubsystemIds",
}


class VSPResourceGroupDirectGateway:
    def __init__(self, connection_info):

        self.connection_manager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.connection_info = connection_info
        self.serial = None

    @log_entry_exit
    def set_serial(self, serial=None):
        if serial:
            self.serial = serial
            logger.writeError(f"GW:set_serial={self.serial}")

    @log_entry_exit
    def get_resource_groups(self, spec=None, b_refresh=True):
        if spec is None:
            end_point = GET_RESOURCE_GROUPS_DIRECT
            resource_groups_date = self.connection_manager.get(end_point)
            resource_groups = VspResourceGroupInfoList(
                dicts_to_dataclass_list(
                    resource_groups_date["data"], VspResourceGroupInfo
                )
            )
            return resource_groups
        else:
            params = "?"
            if spec.is_locked is not None:
                if spec.is_locked is True:
                    params += "lockStatus=Locked"
                else:
                    params += "lockStatus=Unlocked"
                if spec.query:
                    my_query = []
                    for x in spec.query:
                        key = x.lower()
                        if key in INPUT_TO_REST_MAP:
                            my_query.append(INPUT_TO_REST_MAP[key])
                        else:
                            continue
                    my_query = ",".join(my_query)
                    if len(my_query) > 0:
                        params += "&attributes={}".format(my_query)
            else:
                if spec.query:
                    my_query = []
                    for x in spec.query:
                        key = x.lower()
                        if key in INPUT_TO_REST_MAP:
                            my_query.append(INPUT_TO_REST_MAP[key])
                        else:
                            continue
                    my_query = ",".join(my_query)
                    if len(my_query) > 0:
                        params += "attributes={}".format(my_query)

            if params == "?":
                end_point = GET_RESOURCE_GROUPS_DIRECT
            else:
                end_point = GET_RESOURCE_GROUPS_WITH_PARAM_DIRECT.format(params)
            resource_groups_date = self.connection_manager.get(end_point)
            resource_groups = VspResourceGroupInfoList(
                dicts_to_dataclass_list(
                    resource_groups_date["data"], VspResourceGroupInfo
                )
            )
            return resource_groups

    @log_entry_exit
    def get_remote_resource_groups(self, spec=None):
        if spec is None:
            raise ValueError("spec is required for remote resource groups")

        if spec.secondary_connection_info is None:
            raise ValueError(
                "secondary_connection_info is required for remote resource groups"
            )

        remote_connection_manager = VSPConnectionManager(
            spec.secondary_connection_info.address,
            spec.secondary_connection_info.username,
            spec.secondary_connection_info.password,
            spec.secondary_connection_info.api_token,
        )
        end_point = GET_RESOURCE_GROUPS_DIRECT
        resource_groups_date = remote_connection_manager.get(end_point)
        resource_groups = VspResourceGroupInfoList(
            dicts_to_dataclass_list(resource_groups_date["data"], VspResourceGroupInfo)
        )
        return resource_groups

    @log_entry_exit
    def get_resource_group_by_id(self, id):
        try:
            end_point = GET_RESOURCE_GROUP_BY_ID_DIRECT.format(id)
            resource_group = self.connection_manager.get(end_point)
            return VspResourceGroupInfo(**resource_group)
        except Exception as err:
            # Older storage models do not support nvm subsystem.
            # So catch the exception and try older method without nvmSubsystem.
            logger.writeError(err)
            API_MSG = (
                "The specified value is not supported for the specified storage system"
            )
            if isinstance(err.args[0], str) and API_MSG in err.args[0]:
                end_point = GET_RESOURCE_GROUP_BY_ID_NO_DETAIL_DIRECT.format(id)
                resource_group = self.connection_manager.get(end_point)
                return VspResourceGroupInfo(**resource_group)
            else:
                raise err

    @log_entry_exit
    def create_vsm_resource_group(self, spec):
        end_point = CREATE_VSM_RESOURCE_GROUP_DIRECT

        payload = {}
        payload["resourceGroupName"] = spec.name
        payload["virtualSerialNumber"] = spec.virtual_storage_serial
        virtual_storage_model = VSPStorageModelsManager.get_direct_storage_model(
            spec.virtual_storage_model
        )
        logger.writeDebug(
            "create_vsm_resource_group: virtual_storage_model= {}",
            virtual_storage_model,
        )
        payload["virtualModel"] = virtual_storage_model

        resource_group = self.connection_manager.post(end_point, payload)
        self.connection_info.changed = True
        return resource_group

    @log_entry_exit
    def create_resource_group(self, spec):
        end_point = CREATE_RESOURCE_GROUP_DIRECT

        payload = {}
        payload["resourceGroupName"] = spec.name

        # if spec.virtual_storage_id and spec.virtual_storage_device_id is None:
        #     payload["virtualStorageId"] = spec.virtual_storage_id
        if spec.virtual_storage_serial:
            virtual_storage_device_id = self.get_vitual_storage_device_id(
                spec.virtual_storage_serial
            )
            if virtual_storage_device_id is None:
                if spec.virtual_storage_model:
                    resource_group = self.create_vsm_resource_group(spec)
                    resource_group_id = self.get_rg_id_by_name(spec.name)
                    self.connection_info.changed = True
                    return resource_group_id

                else:
                    raise ValueError("Virtual Model must be specified to create a VSM.")
            else:
                payload["virtualStorageDeviceId"] = virtual_storage_device_id

        resource_group = self.connection_manager.post(end_point, payload)
        self.connection_info.changed = True
        return resource_group

    @log_entry_exit
    def get_rg_id_by_name(self, name):
        resource_groups = self.get_resource_groups()
        for resource_group in resource_groups.data:
            if resource_group.resourceGroupName == name:
                return resource_group.resourceGroupId
        return None

    @log_entry_exit
    def get_storage_device_id(self):
        end_point = GET_STORAGE_DEVICE_ID_BY_SERIAL_DIRECT
        device = self.connection_manager.get(end_point)
        return device["data"][0]["storageDeviceId"]

    @log_entry_exit
    def get_vitual_storage_device_id(self, virtual_storage_serial):
        storage_device_id = self.get_storage_device_id()
        end_point = GET_VIRTUAL_STORAGE_DEVICE_ID_DIRECT.format(storage_device_id)
        virtual_devices = self.connection_manager.get(end_point)
        for device in virtual_devices["data"]:
            if device["virtualSerialNumber"] == virtual_storage_serial:
                return device["virtualStorageDeviceId"]
        return None

    @log_entry_exit
    def get_vsm_by_id(self, vsm_id):
        end_point = GET_VSM_BY_ID_DIRECT.format(vsm_id)
        vsm = self.connection_manager.get(end_point)
        return VirtualStorageMachineInfo(**vsm)

    @log_entry_exit
    def get_vsm_all(self):
        end_point = GET_VSM_DIRECT
        vsm = self.connection_manager.get(end_point)
        return VirtualStorageMachineInfoList(
            dicts_to_dataclass_list(vsm["data"], VirtualStorageMachineInfo)
        )

    @log_entry_exit
    def get_rg_id_from_ldev_id(self, ldev_id):
        storage_device_id = self.get_storage_device_id()
        end_point = GET_LDEV_BY_ID_DIRECT.format(storage_device_id, ldev_id)
        ldev = self.connection_manager.get(end_point)
        return ldev["resourceGroupId"]

    @log_entry_exit
    def get_dp_pools(self):
        storage_device_id = self.get_storage_device_id()
        end_point = GET_DP_POOLS_DIRECT.format(storage_device_id)
        dp_pools = self.connection_manager.get(end_point)
        return dp_pools["data"]

    @log_entry_exit
    def get_hti_pools(self):
        storage_device_id = self.get_storage_device_id()
        end_point = GET_HTI_POOLS_DIRECT.format(storage_device_id)
        hti_pools = self.connection_manager.get(end_point)
        return hti_pools["data"]

    @log_entry_exit
    def add_resource(self, rg_id, spec):
        parameters = {}
        logger.writeDebug("add_resource spec= {}", spec)
        if spec.start_ldev:
            parameters["startLdevId"] = spec.start_ldev
        if spec.end_ldev:
            parameters["endLdevId"] = spec.end_ldev
        if spec.ldevs:
            parameters["ldevIds"] = spec.ldevs
        if spec.parity_groups:
            parameters["parityGroupIds"] = spec.parity_groups
        if spec.external_parity_groups:
            parameters["externalParityGroupIds"] = spec.external_parity_groups
        if spec.ports:
            parameters["portIds"] = spec.ports
        if spec.host_groups or spec.iscsi_targets:
            if spec.host_groups_simple and len(spec.host_groups_simple) > 0:
                parameters["hostGroupIds"] = spec.host_groups_simple
        if spec.nvm_subsystem_ids:
            parameters["nvmSubsystemIds"] = spec.nvm_subsystem_ids

        if len(parameters) == 0:
            return

        payload = {"parameters": parameters}
        end_point = ADD_RESOURCE_TO_RESOURCE_GROUP_DIRECT.format(rg_id)
        timeout = None
        if spec.add_resource_time_out_in_sec:
            timeout = spec.add_resource_time_out_in_sec

        resource_group = self.connection_manager.post(
            end_point, payload, timeout=timeout
        )
        self.connection_info.changed = True
        return resource_group

    @log_entry_exit
    def remove_resource(self, rg_id, spec):
        parameters = {}

        if spec.start_ldev:
            parameters["startLdevId"] = spec.start_ldev
        if spec.end_ldev:
            parameters["endLdevId"] = spec.end_ldev
        if spec.ldevs:
            parameters["ldevIds"] = spec.ldevs
        if spec.parity_groups:
            parameters["parityGroupIds"] = spec.parity_groups
        if spec.external_parity_groups:
            parameters["externalParityGroupIds"] = spec.external_parity_groups
        if spec.ports:
            parameters["portIds"] = spec.ports
        if spec.host_groups:
            parameters["hostGroupIds"] = spec.host_groups_simple
        if spec.iscsi_targets:
            parameters["hostGroupIds"] = (
                spec.iscsi_targets_simple
                if spec.host_groups_simple is None
                else spec.host_groups_simple + spec.iscsi_targets_simple
            )
        if spec.nvm_subsystem_ids:
            parameters["nvmSubsystemIds"] = spec.nvm_subsystem_ids

        if len(parameters) == 0:
            return

        payload = {"parameters": parameters}
        self.remove_resoure_with_payload(rg_id, payload)
        self.connection_info.changed = True

    @log_entry_exit
    def remove_resoure_with_payload(self, rg_id, payload):
        end_point = REMOVE_RESOURCE_FROM_RESOURCE_GROUP_DIRECT.format(rg_id)
        resource_group = self.connection_manager.post(end_point, payload)
        self.connection_info.changed = True
        return resource_group

    @log_entry_exit
    def delete_resource_group(self, rg_id):
        end_point = DELETE_RESOURCE_GROUP_DIRECT.format(rg_id)
        ret_data = self.connection_manager.delete(end_point)
        self.connection_info.changed = True
        return ret_data

    @log_entry_exit
    def get_pool_ldevs(self, pool_ids):
        pool_ldevs = []
        for pool_id in pool_ids:
            ldevs = self.get_ldevs_by_pool_id(pool_id)
            pool_ldevs += ldevs
        return pool_ldevs

    @log_entry_exit
    def get_ldevs_by_pool_id(self, pool_id):
        end_point = GET_LDEVS_BY_POOL_ID_DIRECT.format(pool_id)
        pool = self.connection_manager.get(end_point)
        ldevs = []
        for x in pool["data"]:
            ldevs.append(x["ldevId"])
        logger.writeDebug("LDEVS: {}", ldevs)
        return ldevs

    @log_entry_exit
    def delete_resource_group_force(self, rg):
        parameters = {}

        if hasattr(rg, "ldevIds") and rg.ldevIds:
            parameters["ldevIds"] = rg.ldevIds
        if hasattr(rg, "parityGroupIds") and rg.parityGroupIds:
            parameters["parityGroupIds"] = rg.parityGroupIds
        if hasattr(rg, "externalParityGroupIds") and rg.externalParityGroupIds:
            parameters["externalParityGroupIds"] = rg.externalParityGroupIds
        if hasattr(rg, "portIds") and rg.portIds:
            parameters["portIds"] = rg.portIds
        if hasattr(rg, "hostGroupIds") and rg.hostGroupIds:
            parameters["hostGroupIds"] = rg.hostGroupIds
        if hasattr(rg, "nvmSubsystemIds") and rg.nvmSubsystemIds:
            parameters["nvmSubsystemIds"] = rg.nvmSubsystemIds

        if bool(parameters):
            payload = {"parameters": parameters}
            self.remove_resoure_with_payload(rg.resourceGroupId, payload)

        self.delete_resource_group(rg.resourceGroupId)
        self.connection_info.changed = True
