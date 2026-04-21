from typing import Dict, Any

try:
    from .gateway_manager import VSPConnectionManager
    from ..model.vsp_gad_pairs_models import (
        DirectGadPairInfoList,
        DirectGadPairInfo,
    )
    from ..common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from ..common.hv_log import Log
    from .vsp_replication_pairs_gateway import VSPReplicationPairsDirectGateway
except ImportError:
    from .gateway_manager import VSPConnectionManager
    from model.vsp_gad_pairs_models import (
        DirectGadPairInfoList,
        DirectGadPairInfo,
    )
    from common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from common.hv_log import Log
    from .vsp_replication_pairs_gateway import VSPReplicationPairsDirectGateway

DELETE_GAD_PAIR_DIRECT = "v1/objects/remote-mirror-copypairs/{}"
CREATE_GAD_PAIR_DIRECT = "v1/objects/remote-mirror-copypairs"
SPLIT_GAD_PAIR_DIRECT = "v1/objects/remote-mirror-copypairs/{}/actions/split/invoke"
RESYNC_GAD_PAIR_DIRECT = "v1/objects/remote-mirror-copypairs/{}/actions/resync/invoke"
GET_REMOTE_STORAGES_DIRECT = "v1/objects/remote-storages"
GET_GAD_PAIRS_DIRECT = "v1/objects/remote-copypairs?replicationType=GAD"

logger = Log()


class VSPGadPairDirectGateway(VSPReplicationPairsDirectGateway):
    # def __init__(self, connection_info):

    #     self.connection_manager = VSPConnectionManager(
    #         connection_info.address, connection_info.username, connection_info.password)
    #     # self.end_points = Endpoints
    #     self.connection_info = connection_info
    #     self.rest_api = VSPConnectionManager(
    #         connection_info.address,
    #         connection_info.username,
    #         connection_info.password
    #     )

    #     # sng20241115 VSPReplicationPairsDirectGateway needs this data member
    #     self.remote_connection_manager = None
    #     self.copy_group_gateway = None

    @log_entry_exit
    def swap_split_gad_pair(self, spec, mode=None):
        return super().swap_split_replication_pair(spec, "GAD", mode)

    @log_entry_exit
    def swap_resync_gad_pair(self, spec):
        return super().swap_resync_replication_pair(spec, "GAD")

    @log_entry_exit
    def get_secondary_serial(self, spec):
        # logger.writeDebug("sng20241115 secondary_connection_info ={}", spec.secondary_connection_info)
        secondary_storage_info = self.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        return secondary_storage_info.get("serialNumber")

    # @log_entry_exit
    # def set_storage_serial_number(self, serial: str):
    #     self.storage_serial_number = serial

    # @log_entry_exit
    # def get_storage_device_id(self, serial_number):
    #     end_point = GET_REMOTE_STORAGES_DIRECT
    #     storage_devices = self.connection_manager.get(end_point)
    #     logger.writeDebug("GW:get_local_storage_device_id:storage_devices={}", storage_devices)
    #     for s in storage_devices["data"]:
    #         if str(s.get("serialNumber")) == str(serial_number):
    #             return s.get("storageDeviceId")
    #     raise ValueError("Storage device not found.")

    @log_entry_exit
    def get_all_gad_pairs(self, serial=None):
        # sng1104 - have to use the CG version
        logger.writeDebug("SHOULD USE THE COPY GROUP GET!!")
        end_point = GET_GAD_PAIRS_DIRECT
        tc_data = self.connection_manager.get(end_point)
        logger.writeDebug("GW-Direct:get_all_gad_pairs:data={}", tc_data)

        return DirectGadPairInfoList(
            dicts_to_dataclass_list(tc_data["data"], DirectGadPairInfo)
        )

    @log_entry_exit
    def get_remote_token(self, remote_connection_info):
        remote_connection_manager = VSPConnectionManager(
            remote_connection_info.address,
            remote_connection_info.username,
            remote_connection_info.password,
            remote_connection_info.api_token,
        )
        return remote_connection_manager.getAuthToken()

    # sng20241105 sng1104 create_gad_pair
    @log_entry_exit
    def create_gad_pair(self, spec) -> Dict[str, Any]:

        # secondary_storage_serial_number = spec.secondary_storage_serial_number
        # remote_storage_deviceId = self.get_storage_device_id(
        #     str(secondary_storage_serial_number)
        # )
        secondary_storage_info = self.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        remote_storage_deviceId = secondary_storage_info.get("storageDeviceId")
        logger.writeDebug(
            f"115 spec.is_new_group_creation : {spec.is_new_group_creation}"
        )
        logger.writeDebug(f"115 spec.mu_number : {spec.mu_number}")

        payload = {
            "copyGroupName": spec.copy_group_name,
            "copyPairName": spec.copy_pair_name,
            "replicationType": "GAD",
            "remoteStorageDeviceId": remote_storage_deviceId,
            "pvolLdevId": spec.primary_volume_id,
            "svolLdevId": spec.secondary_volume_id,
            "isNewGroupCreation": (
                spec.is_new_group_creation
                if spec.is_new_group_creation is not None
                else True
            ),
            "fenceLevel": spec.fence_level if spec.fence_level else "NEVER",
            "copyPace": 3,
            "doInitialCopy": True,
            "isDataReductionForceCopy": True,
            "quorumDiskId": spec.quorum_disk_id,
        }

        isConsistencyGroup = None
        if spec.is_consistency_group is not None:
            payload["isConsistencyGroup"] = spec.is_consistency_group
            isConsistencyGroup = spec.is_consistency_group
        if spec.allocate_new_consistency_group is not None:
            payload["isConsistencyGroup"] = spec.allocate_new_consistency_group
            isConsistencyGroup = spec.allocate_new_consistency_group

        if isConsistencyGroup and spec.consistency_group_id:
            payload["consistencyGroupId"] = spec.consistency_group_id

        is_new_group_creation = None
        if spec.is_new_group_creation is not None:
            is_new_group_creation = spec.is_new_group_creation

        # adding GAD to existing copy group,
        # payload cannot include the mu number
        #
        # for new copy group, it is either 0 or user input
        mu_number = 0
        if spec.mu_number:
            mu_number = spec.mu_number
        if is_new_group_creation:
            payload["muNumber"] = mu_number

        if spec.path_group_id is not None:
            payload["pathGroupId"] = spec.path_group_id
        if spec.local_device_group_name:
            payload["localDeviceGroupName"] = spec.local_device_group_name
        if spec.remote_device_group_name:
            payload["remoteDeviceGroupName"] = spec.remote_device_group_name
        if spec.is_consistency_group is not None:
            payload["isConsistencyGroup"] = spec.is_consistency_group
        if spec.is_consistency_group and spec.consistency_group_id:
            payload["consistencyGroupId"] = spec.consistency_group_id
        if spec.copy_pace:
            payload["copyPace"] = self.get_copy_pace_value(spec.copy_pace)
        if spec.do_initial_copy is not None:
            payload["doInitialCopy"] = spec.do_initial_copy
        if spec.is_data_reduction_force_copy is not None:
            payload["isDataReductionForceCopy"] = spec.is_data_reduction_force_copy

        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))
        logger.writeDebug("GW-Direct:create_gad:storage_deviceId={}", storage_deviceId)
        headers = self.get_remote_token(spec.secondary_storage_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        # headers["Remote-Authorization"] = "Session cf68b8ce47fd47e5ad9195466c915d7e"
        # end_point = CREATE_GAD_PAIR_DIRECT.format(storage_deviceId)
        end_point = CREATE_GAD_PAIR_DIRECT
        logger.writeDebug("GW-Direct:create_gad:end_point={}", end_point)
        logger.writeDebug("GW-Direct:create_gad:payload={}", payload)
        return self.connection_manager.post(end_point, payload, headers_input=headers)

    def get_copy_pace_value(self, copy_pace=None):
        copy_pace_value = 1
        if copy_pace:
            copy_pace = copy_pace.strip().upper()
        if copy_pace == "SLOW":
            copy_pace_value = 1
        elif copy_pace == "FAST":
            copy_pace_value = 10
        else:
            copy_pace_value = 3
        return copy_pace_value

    @log_entry_exit
    def split_gad_pair(self, spec):
        return super().split_replication_pair(spec, "GAD")

    @log_entry_exit
    def resync_gad_pair(self, spec):
        return super().resync_replication_pair(spec, "GAD")

    @log_entry_exit
    def resize_gad_pair(self, pair, spec):
        return super().resize_replication_pair(pair, spec)

    @log_entry_exit
    def split_gad_pair_old(self, spec, object_id):
        parameters = {
            "replicationType": "GAD",
        }
        payload = {"parameters": parameters}
        headers = self.get_remote_token(spec.secondary_storage_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        end_point = SPLIT_GAD_PAIR_DIRECT.format(object_id)
        return self.connection_manager.update(end_point, payload, headers_input=headers)

    @log_entry_exit
    def resync_gad_pair_old(self, spec, object_id):
        parameters = {
            "replicationType": "GAD",
        }
        payload = {"parameters": parameters}
        headers = self.get_remote_token(spec.secondary_storage_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        end_point = RESYNC_GAD_PAIR_DIRECT.format(object_id)
        return self.connection_manager.update(end_point, payload, headers_input=headers)

    @log_entry_exit
    def resync_gad_pair_by_spec(self, spec):
        secondary_storage_serial_number = spec.secondary_storage_serial_number
        remote_storage_deviceId = self.get_storage_device_id(
            str(secondary_storage_serial_number)
        )

        self.get_storage_device_id(str(self.storage_serial_number))
        # remoteStorageDeviceId,copyGroupName,localDeviceGroupName,remoteDeviceGroupName, copyPairName
        parameters = {
            "replicationType": "GAD",
        }
        local_device_group_name = (
            spec.local_device_group_name
            if spec.local_device_group_name
            else spec.copy_group_name + "P_"
        )
        remote_device_group_name = (
            spec.remote_device_group_name
            if spec.remote_device_group_name
            else spec.copy_group_name + "S_"
        )
        object_id = f"{remote_storage_deviceId},{spec.copy_group_name},{local_device_group_name},{remote_device_group_name},{spec.copy_pair_name}"
        payload = {"parameters": parameters}
        headers = self.get_remote_token(spec.secondary_storage_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        end_point = RESYNC_GAD_PAIR_DIRECT.format(object_id)
        return self.connection_manager.update(end_point, payload, headers_input=headers)

    @log_entry_exit
    def delete_gad_pair(self, spec, object_id):
        logger.writeDebug("GW:delete_gad_pair:object_id={}", object_id)
        end_point = DELETE_GAD_PAIR_DIRECT.format(object_id)
        headers = self.get_remote_token(spec.secondary_storage_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        # headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        return self.connection_manager.delete_with_headers(end_point, headers=headers)
