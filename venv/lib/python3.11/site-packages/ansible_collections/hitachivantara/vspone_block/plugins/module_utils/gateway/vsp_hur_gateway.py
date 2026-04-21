import time
from typing import Dict, Any

try:
    from .vsp_replication_pairs_gateway import VSPReplicationPairsDirectGateway
    from ..common.hv_log import Log
    from ..common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from ..model.vsp_hur_models import (
        DirectHurPairInfoList,
        DirectHurPairInfo,
    )
except ImportError:
    from .vsp_replication_pairs_gateway import VSPReplicationPairsDirectGateway
    from common.hv_log import Log
    from common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from model.vsp_hur_models import (
        DirectHurPairInfoList,
        DirectHurPairInfo,
    )

CREATE_REMOTE_COPY_PAIR_DIRECT = "v1/objects/remote-mirror-copypairs"
CREATE_HUR_PAIR_DIRECT = "v1/objects/remote-mirror-copypairs"
GET_REMOTE_STORAGES_DIRECT = "v1/objects/remote-storages"
GET_HUR_PAIRS_DIRECT = "v1/objects/remote-copypairs?replicationType=UR"

logger = Log()


class VSPHurDirectGateway(VSPReplicationPairsDirectGateway):
    # def __init__(self, connection_info):

    #     self.connection_manager = VSPConnectionManager(
    #         connection_info.address, connection_info.username, connection_info.password)
    #     self.end_points = Endpoints
    #     self.connection_info = connection_info

    # @log_entry_exit
    # def set_storage_serial_number(self, serial: str):
    #     self.storage_serial_number = serial

    # @log_entry_exit
    # def get_storage_device_id(self, serial_number):
    #     end_point = GET_REMOTE_STORAGES_DIRECT
    #     storage_devices = self.connection_manager.get(end_point)
    #     logger.writeDebug("GW:get_local_storage_device_id:storage_devices={}", storage_devices)
    #     for s in storage_devices["data"]:
    #         if s.get("serialNumber") == serial_number:
    #             return s.get("storageDeviceId")
    #     raise ValueError("Storage device not found.")

    @log_entry_exit
    def get_all_replication_pairs(self, serial=None):
        end_point = GET_HUR_PAIRS_DIRECT
        tc_data = self.connection_manager.get(end_point)
        logger.writeDebug("GW-Direct:get_all_hur_pairs:data={}", tc_data)

        return DirectHurPairInfoList(
            dicts_to_dataclass_list(tc_data["data"], DirectHurPairInfo)
        )

    @log_entry_exit
    def get_secondary_serial(self, spec):
        # logger.writeDebug("sng20241115 65 secondary_connection_info ={}", spec.secondary_connection_info)
        secondary_storage_info = self.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        return secondary_storage_info.get("serialNumber")

    @log_entry_exit
    def create_hur_pair(self, spec) -> Dict[str, Any]:

        # secondary_storage_serial_number = self.get_secondary_serial(spec)
        secondary_storage_info = self.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        remote_storage_deviceId = secondary_storage_info.get("storageDeviceId")

        payload = {
            "copyGroupName": spec.copy_group_name,
            "copyPairName": spec.copy_pair_name,
            "replicationType": "UR",
            "remoteStorageDeviceId": remote_storage_deviceId,
            "pvolLdevId": spec.primary_volume_id,
            "isNewGroupCreation": spec.is_new_group_creation,
            "svolLdevId": int(spec.secondary_volume_id),
            "fenceLevel": spec.fence_level if spec.fence_level else "ASYNC",
        }
        if spec.is_new_group_creation is True:
            payload["muNumber"] = (
                spec.mirror_unit_id if spec.mirror_unit_id is not None else 1
            )
            payload["pvolJournalId"] = spec.primary_volume_journal_id
            payload["svolJournalId"] = spec.secondary_volume_journal_id

        if spec.local_device_group_name:
            payload["localDeviceGroupName"] = spec.local_device_group_name
        if spec.remote_device_group_name:
            payload["remoteDeviceGroupName"] = spec.remote_device_group_name
        if spec.path_group_id:
            payload["pathGroupId"] = spec.path_group_id
        if spec.consistency_group_id:
            payload["consistencyGroupId"] = spec.consistency_group_id
        if spec.do_initial_copy is not None:
            payload["doInitialCopy"] = spec.do_initial_copy
        if spec.is_data_reduction_force_copy is not None:
            payload["isDataReductionForceCopy"] = spec.is_data_reduction_force_copy
        else:
            payload["isDataReductionForceCopy"] = True
        if spec.do_delta_resync_suspend is not None:
            payload["doDeltaResyncSuspend"] = spec.do_delta_resync_suspend

        # storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))
        # logger.writeDebug("GW-Direct:create_hur_copy:storage_deviceId={}", storage_deviceId)
        headers = self.get_remote_token(spec.remote_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        logger.writeDebug("GW-Direct:create_hur_copy:remote_header={}", headers)
        end_point = CREATE_REMOTE_COPY_PAIR_DIRECT  # .format(storage_deviceId)
        logger.writeDebug("GW-Direct:create_hur_copy:end_point={}", end_point)
        start_time = time.time()
        response = self.connection_manager.post(
            end_point, payload, headers_input=headers
        )
        end_time = time.time()
        logger.writeDebug("PF_REST:create_hur_copy:time={:.2f}", end_time - start_time)
        return response

    @log_entry_exit
    def split_hur_pair(self, spec):
        return super().split_replication_pair(spec, "UR")

    @log_entry_exit
    def swap_split_hur_pair(self, spec):
        return super().swap_split_replication_pair(spec, "UR")

    @log_entry_exit
    def resync_hur_pair(self, spec):
        return super().resync_replication_pair(spec, "UR")

    @log_entry_exit
    def swap_resync_hur_pair(self, spec):
        return super().swap_resync_replication_pair(spec, "UR")

    @log_entry_exit
    def delete_hur_pair_by_pair_id(self, spec):
        return super().delete_replication_pair(spec)

    @log_entry_exit
    def get_hur_pair(self, spec):
        return super().get_replication_pair(spec)

    @log_entry_exit
    def resize_hur_pair(self, pair, spec):
        return super().resize_replication_pair(pair, spec)

    @log_entry_exit
    def secondary_takeover_hur_pair(self, spec):
        return super().secondary_takeover_replication_pair(spec, "UR")
