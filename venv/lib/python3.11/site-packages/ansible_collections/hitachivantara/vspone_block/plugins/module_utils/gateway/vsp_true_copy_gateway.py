import time
from typing import Dict, Any

try:
    from .gateway_manager import VSPConnectionManager
    from .vsp_replication_pairs_gateway import VSPReplicationPairsDirectGateway
    from ..common.hv_log import Log
    from ..common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from ..model.vsp_true_copy_models import (
        DirectTrueCopyPairInfo,
        DirectTrueCopyPairInfoList,
    )
except ImportError:
    from .gateway_manager import VSPConnectionManager
    from .vsp_replication_pairs_gateway import VSPReplicationPairsDirectGateway
    from common.hv_log import Log
    from common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from model.vsp_true_copy_models import (
        DirectTrueCopyPairInfo,
        DirectTrueCopyPairInfoList,
    )

CREATE_TRUE_COPY_PAIR_DIRECT = "v1/objects/storages/{}/remote-mirror-copypairs"
SPLIT_TRUE_COPY_PAIR_DIRECT = (
    "v1/objects/storages/{}/remote-mirror-copypairs/{}/actions/split/invoke"
)
RESYNC_TRUE_COPY_PAIR_DIRECT = (
    "v1/objects/storages/{}/remote-mirror-copypairs/{}/actions/resync/invoke"
)
GET_REMOTE_STORAGES_DIRECT = "v1/objects/remote-storages"
GET_STORAGES_DIRECT = "v1/objects/storages"
GET_TRUE_COPY_PAIRS_DIRECT = "v1/objects/remote-copypairs?replicationType=TC"
DELETE_TRUE_COPY_PAIR_DIRECT = "v1/objects/remote-mirror-copypairs/{}"


logger = Log()


class VSPTrueCopyDirectGateway(VSPReplicationPairsDirectGateway):

    @log_entry_exit
    def get_all_true_copy_pairs(self, serial=None):
        end_point = GET_TRUE_COPY_PAIRS_DIRECT
        tc_data = self.connection_manager.get(end_point)
        logger.writeDebug("GW-Direct:get_all_true_copy_pairs:data={}", tc_data)

        return DirectTrueCopyPairInfoList(
            dicts_to_dataclass_list(tc_data["data"], DirectTrueCopyPairInfo)
        )

    @log_entry_exit
    def get_secondary_serial(self, spec):
        secondary_storage_info = self.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        return secondary_storage_info.get("serialNumber")

    @log_entry_exit
    def create_true_copy(self, spec) -> Dict[str, Any]:

        secondary_storage_info = self.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        logger.writeDebug(
            "GW:create_true_copy:secondary_storage_info={}",
            secondary_storage_info,
        )
        remote_storage_device_id = secondary_storage_info.get("storageDeviceId")

        payload = {
            "copyGroupName": spec.copy_group_name,
            "copyPairName": spec.copy_pair_name,
            "replicationType": "TC",
            "remoteStorageDeviceId": remote_storage_device_id,
            "pvolLdevId": spec.primary_volume_id,
            "svolLdevId": spec.secondary_volume_id,
            "isNewGroupCreation": (
                spec.is_new_group_creation
                if spec.is_new_group_creation is not None
                else True
            ),
            "fenceLevel": spec.fence_level if spec.fence_level else "NEVER",
        }
        if spec.path_group_id:
            payload["pathGroupId"] = spec.path_group_id
        if spec.local_device_group_name:
            payload["localDeviceGroupName"] = spec.local_device_group_name
        if spec.remote_device_group_name:
            payload["remoteDeviceGroupName"] = spec.remote_device_group_name

        if spec.is_consistency_group is not None:
            payload["isConsistencyGroup"] = spec.is_consistency_group
        else:
            payload["isConsistencyGroup"] = False

        if spec.consistency_group_id:
            if spec.is_new_group_creation:
                pass
            else:
                payload["consistencyGroupId"] = spec.consistency_group_id

        if spec.copy_pace:
            payload["copyPace"] = self.get_copy_pace_value(spec.copy_pace)
        if spec.do_initial_copy is not None:
            payload["doInitialCopy"] = spec.do_initial_copy
        if spec.is_data_reduction_force_copy is not None:
            payload["isDataReductionForceCopy"] = spec.is_data_reduction_force_copy
        else:
            payload["isDataReductionForceCopy"] = True
        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))
        logger.writeDebug(
            "GW-Direct:create_true_copy:storage_deviceId={}", storage_deviceId
        )
        headers = self.get_remote_token(spec.secondary_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        logger.writeDebug("GW-Direct:create_true_copy:remote_header={}", headers)
        end_point = CREATE_TRUE_COPY_PAIR_DIRECT.format(storage_deviceId)
        logger.writeDebug("GW-Direct:create_true_copy:end_point={}", end_point)
        start_time = time.time()
        response = self.connection_manager.post(
            end_point, payload, headers_input=headers
        )
        end_time = time.time()
        logger.writeDebug("PF_REST:create_true_copy:time={:.2f}", end_time - start_time)
        return response

    @log_entry_exit
    def split_true_copy_pair(self, spec):
        return super().split_replication_pair(spec, "TC")

    @log_entry_exit
    def swap_split_true_copy_pair(self, spec, mode=None):
        return super().swap_split_replication_pair(spec, "TC", mode)

    @log_entry_exit
    def resync_true_copy_pair(self, spec):
        return super().resync_replication_pair(spec, "TC")

    @log_entry_exit
    def swap_resync_true_copy_pair(self, spec):
        return super().swap_resync_replication_pair(spec, "TC")

    @log_entry_exit
    def resize_true_copy_pair(self, pair, spec):
        return super().resize_replication_pair(pair, spec)

    @log_entry_exit
    def split_true_copy_pair_by_object_id(
        self, object_id, sec_conn_info, replication_type, is_svol_readwriteable
    ):
        return super().split_replication_pair_by_object_id(
            object_id, sec_conn_info, replication_type, is_svol_readwriteable
        )

    @log_entry_exit
    def swap_split_true_copy_pair_by_object_id(
        self, object_id, sec_conn_info, replication_type
    ):
        return super().swap_split_replication_pair_by_object_id(
            object_id, sec_conn_info, replication_type
        )

    @log_entry_exit
    def resync_true_copy_pair_by_object_id(
        self, object_id, sec_conn_info, replication_type
    ):
        return super().resync_replication_pair_by_object_id(
            object_id, sec_conn_info, replication_type
        )

    @log_entry_exit
    def swap_resync_true_copy_pair_by_object_id(
        self, object_id, sec_conn_info, replication_type
    ):
        return super().swap_resync_replication_pair_by_object_id(
            object_id, sec_conn_info, replication_type
        )

    @log_entry_exit
    def delete_true_copy_pair_by_object_id(self, object_id, sec_conn_info):
        self.connection_manager = VSPConnectionManager(
            self.connection_info.address,
            self.connection_info.username,
            self.connection_info.password,
            self.connection_info.api_token,
        )
        remote_connection_manager = VSPConnectionManager(
            sec_conn_info.address,
            sec_conn_info.username,
            sec_conn_info.password,
            sec_conn_info.api_token,
        )
        headers = remote_connection_manager.getAuthToken()
        headers["Remote-Authorization"] = headers.pop("Authorization")
        end_point = DELETE_TRUE_COPY_PAIR_DIRECT.format(object_id)
        start_time = time.time()
        response = self.connection_manager.delete(
            end_point, None, headers_input=headers
        )
        end_time = time.time()
        logger.writeDebug("PF_REST:delete_true_copy:time={:.2f}", end_time - start_time)
        return response

    @log_entry_exit
    def delete_true_copy_pair_by_pair_id(self, spec):
        return super().delete_replication_pair(spec)

    @log_entry_exit
    def get_copy_pair_for_primary_volume_id_from_cp_gr(self, cg_gw, spec):
        copy_pairs = cg_gw.get_remote_pairs_for_a_copy_group(spec)
        if copy_pairs is None:
            return None
        for cp in copy_pairs:
            if cp.pvolLdevId == spec.primary_volume_id:
                return cp
        return None

    @log_entry_exit
    def delete_true_copy_pair_by_copy_group_and_pvol_id(self, cg_gw, spec):
        cp = self.get_copy_pair_for_primary_volume_id_from_cp_gr(cg_gw, spec)
        if cp is None:
            return None

        object_id = cp.remoteMirrorCopyPairId
        return self.delete_true_copy_pair_by_object_id(
            object_id, spec.secondary_connection_info
        )

    @log_entry_exit
    def split_true_copy_pair_by_copy_group_and_pvol_id(self, cg_gw, spec):
        cp = self.get_copy_pair_for_primary_volume_id_from_cp_gr(cg_gw, spec)
        if cp is None:
            return None
        object_id = cp.remoteMirrorCopyPairId
        return self.split_true_copy_pair_by_object_id(
            object_id, spec.secondary_connection_info, "TC", spec.is_svol_readwriteable
        )

    @log_entry_exit
    def swap_split_true_copy_pair_by_copy_group_and_pvol_id(self, cg_gw, spec):
        cp = self.get_copy_pair_for_primary_volume_id_from_cp_gr(cg_gw, spec)
        if cp is None:
            return None
        object_id = cp.remoteMirrorCopyPairId
        return self.swap_split_true_copy_pair_by_object_id(
            object_id, spec.secondary_connection_info, "TC"
        )

    @log_entry_exit
    def resync_true_copy_pair_by_copy_group_and_pvol_id(self, cg_gw, spec):
        cp = self.get_copy_pair_for_primary_volume_id_from_cp_gr(cg_gw, spec)
        if cp is None:
            return None
        object_id = cp.remoteMirrorCopyPairId
        return self.resync_true_copy_pair_by_object_id(
            object_id, spec.secondary_connection_info, "TC"
        )

    @log_entry_exit
    def swap_resync_true_copy_pair_by_copy_group_and_pvol_id(self, cg_gw, spec):
        cp = self.get_copy_pair_for_primary_volume_id_from_cp_gr(cg_gw, spec)
        if cp is None:
            return None
        object_id = cp.remoteMirrorCopyPairId
        return self.swap_resync_true_copy_pair_by_object_id(
            object_id, spec.secondary_connection_info, "TC"
        )

    @log_entry_exit
    def delete_true_copy_pair_by_primary_volume_id(self, cg_gw, spec):
        tc_copy_pairs = cg_gw.get_remote_pairs_by_pvol(spec)
        if tc_copy_pairs:
            object_id = tc_copy_pairs[0].remoteMirrorCopyPairId
            return self.delete_true_copy_pair_by_object_id(
                object_id, spec.secondary_connection_info
            )
        return None

    @log_entry_exit
    def split_true_copy_pair_by_primary_volume_id(self, cg_gw, spec):
        tc_copy_pairs = cg_gw.get_remote_pairs_by_pvol(spec)
        if tc_copy_pairs:
            object_id = tc_copy_pairs[0].remoteMirrorCopyPairId
            return self.split_true_copy_pair_by_object_id(
                object_id,
                spec.secondary_connection_info,
                "TC",
                spec.is_svol_readwriteable,
            )
        return None

    @log_entry_exit
    def swap_split_true_copy_pair_by_primary_volume_id(self, cg_gw, spec):
        tc_copy_pairs = cg_gw.get_remote_pairs_by_pvol(spec)
        if tc_copy_pairs:
            object_id = tc_copy_pairs[0].remoteMirrorCopyPairId
            return self.swap_split_true_copy_pair_by_object_id(
                object_id, spec.secondary_connection_info, "TC"
            )
        return None

    @log_entry_exit
    def resync_true_copy_pair_by_primary_volume_id(self, cg_gw, spec):
        tc_copy_pairs = cg_gw.get_remote_pairs_by_pvol(spec)
        if tc_copy_pairs:
            object_id = tc_copy_pairs[0].remoteMirrorCopyPairId
            return self.resync_true_copy_pair_by_object_id(
                object_id, spec.secondary_connection_info, "TC"
            )
        return None

    @log_entry_exit
    def swap_resync_true_copy_pair_by_primary_volume_id(self, cg_gw, spec):
        tc_copy_pairs = cg_gw.get_remote_pairs_by_pvol(spec)
        if tc_copy_pairs:
            object_id = tc_copy_pairs[0].remoteMirrorCopyPairId
            return self.swap_resync_true_copy_pair_by_object_id(
                object_id, spec.secondary_connection_info, "TC"
            )
        return None

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
