import re
import time

try:

    from .gateway_manager import VSPConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        dicts_to_dataclass_list,
        log_entry_exit,
        convert_block_capacity,
        convert_decimal_size_to_bytes,
    )
    from ..message.vsp_true_copy_msgs import VSPTrueCopyValidateMsg
    from ..message.vsp_replication_pair_msgs import VSPReplicationPairValidateMsg
    from .vsp_copy_groups_gateway import VSPCopyGroupsDirectGateway
    from .vsp_volume import VSPVolumeDirectGateway

except ImportError:
    from .gateway_manager import VSPConnectionManager
    from common.hv_log import Log
    from common.ansible_common import (
        dicts_to_dataclass_list,
        log_entry_exit,
        convert_block_capacity,
        convert_decimal_size_to_bytes,
    )
    from message.vsp_true_copy_msgs import VSPTrueCopyValidateMsg
    from message.vsp_replication_pair_msgs import VSPReplicationPairValidateMsg
    from .vsp_copy_groups_gateway import VSPCopyGroupsDirectGateway
    from .vsp_volume import VSPVolumeDirectGateway

CREATE_REMOTE_COPY_PAIR_DIRECT = "v1/objects/storages/{}/remote-mirror-copypairs"
SPLIT_REMOTE_COPY_PAIR_DIRECT = (
    "v1/objects/storages/{}/remote-mirror-copypairs/{}/actions/split/invoke"
)
SECONDARY_TAKEOVER_COPY_PAIR_DIRECT = (
    "v1/objects/storages/{}/remote-mirror-copypairs/{}/actions/takeover/invoke"
)
RESYNC_REMOTE_COPY_PAIR_DIRECT = (
    "v1/objects/storages/{}/remote-mirror-copypairs/{}/actions/resync/invoke"
)
GET_REMOTE_STORAGES_DIRECT = "v1/objects/remote-storages"
GET_STORAGES_DIRECT = "v1/objects/storages"
GET_REMOTE_COPY_PAIRS_DIRECT = "v1/objects/remote-copypairs?replicationType={}"
DELETE_REMOTE_COPY_PAIR_DIRECT = "v1/objects/storages/{}/remote-mirror-copypairs/{}"
GET_ONE_REMOTE_COPY_PAIRS_DIRECT = "v1/objects/storages/{}/remote-mirror-copypairs/{}"

logger = Log()


class VSPReplicationPairsDirectGateway:
    def __init__(self, connection_info):

        self.connection_manager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        # self.end_points = Endpoints
        self.connection_info = connection_info
        self.remote_connection_manager = None
        self.copy_group_gateway = VSPCopyGroupsDirectGateway(connection_info)

    @log_entry_exit
    def set_storage_serial_number(self, serial: str):
        self.storage_serial_number = serial
        if self.storage_serial_number is None:
            primary_storage_info = self.get_secondary_storage_info(self.connection_info)
            self.storage_serial_number = primary_storage_info.get("serialNumber")

    @log_entry_exit
    def get_storage_device_id(self, serial_number):
        end_point = GET_REMOTE_STORAGES_DIRECT
        storage_devices = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_local_storage_device_id:storage_devices={}", storage_devices
        )
        for s in storage_devices["data"]:
            if str(s.get("serialNumber")) == str(serial_number):
                return s.get("storageDeviceId")
        raise ValueError("Storage device not found.")

    @log_entry_exit
    def get_secondary_storage_info(self, remote_connection_info):
        self.init_remote_connection_manager(remote_connection_info)
        secondary_storage = self.remote_connection_manager.get(GET_STORAGES_DIRECT)
        return secondary_storage["data"][0]

    @log_entry_exit
    def get_all_remote_copy_pairs(self, serial):
        end_point = GET_REMOTE_COPY_PAIRS_DIRECT
        remote_copy_data = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW-Direct:get_all_remote_copy_pairs:data={}", remote_copy_data
        )
        return dicts_to_dataclass_list(remote_copy_data["data"])
        # return DirectTrueCopyPairInfoList(
        #    dicts_to_dataclass_list(remote_copy_data["data"], DirectTrueCopyPairInfo)
        # )

    @log_entry_exit
    def init_remote_connection_manager(self, remote_connection_info):
        self.remote_connection_manager = VSPConnectionManager(
            remote_connection_info.address,
            remote_connection_info.username,
            remote_connection_info.password,
            remote_connection_info.api_token,
        )
        return

    def init_connections(self, remote_connection_info):
        self.connection_manager = VSPConnectionManager(
            self.connection_info.address,
            self.connection_info.username,
            self.connection_info.password,
            remote_connection_info.api_token,
        )
        self.remote_connection_manager = VSPConnectionManager(
            remote_connection_info.address,
            remote_connection_info.username,
            remote_connection_info.password,
            remote_connection_info.api_token,
        )
        return

    @log_entry_exit
    def get_remote_token(self, remote_connection_info):
        # if self.remote_connection_manager is None:
        #     self.init_remote_connection_manager(remote_connection_info)
        # logger.writeDebug(f"GW-Direct:create_true_copy:get_remote_token:remote_connection_info={remote_connection_info}")
        # Not sure when the token was generated, got invalid token error, so always generate a new one
        try:
            self.init_remote_connection_manager(remote_connection_info)
            token = self.remote_connection_manager.getAuthToken()
            return token
        except Exception as e:
            if "User authentication failed" in str(e):
                self.init_remote_connection_manager(remote_connection_info)
                return self.remote_connection_manager.getAuthToken()
            else:
                logger.writeDebug("GW:get_remote_token:exception={}", e)
                raise e

    @log_entry_exit
    def get_pair_id_from_swap_pair_id(self, swap_pair_id, remote_connection_info):
        secondary_storage_info = self.get_secondary_storage_info(remote_connection_info)
        remote_storage_deviceId = secondary_storage_info.get("storageDeviceId")
        ss = swap_pair_id.split(",")
        return f"{remote_storage_deviceId},{ss[1]},{ss[3]},{ss[2]},{ss[4]}"

    # Helper function to convert camelCase to snake_case
    def camel_to_snake(self, name: str) -> str:
        # Insert underscores before uppercase letters and convert to lowercase
        return re.sub(r"([a-z])([A-Z])", r"\1_\2", name).lower()

    @log_entry_exit
    def split_replication_pair(self, spec, remote_pair_type):

        secondary_storage_info = self.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        logger.writeDebug(
            "GW:split_replication_pair:secondary_storage_info={}",
            secondary_storage_info,
        )
        remote_storage_deviceId = secondary_storage_info.get("storageDeviceId")

        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))
        # remoteStorageDeviceId,copyGroupName,localDeviceGroupName,remoteDeviceGroupName, copyPairName
        parameters = {
            "replicationType": remote_pair_type,
        }
        if spec.is_svol_readwriteable:
            parameters["svolAccessMode"] = "rw"

        if spec.local_device_group_name and spec.remote_device_group_name:
            object_id = f"{remote_storage_deviceId},{spec.copy_group_name},{spec.local_device_group_name},{spec.remote_device_group_name},{spec.copy_pair_name}"
            logger.writeDebug(
                "GW:split_replication_pair:constructed object_id={}", object_id
            )
        else:
            object_id = (
                self.copy_group_gateway.get_object_id_by_copy_group_and_copy_pair_name(
                    spec
                )
            )
            logger.writeDebug("GW:split_replication_pair:API object_id={}", object_id)

        payload = {"parameters": parameters}
        headers = self.get_remote_token(spec.secondary_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        end_point = SPLIT_REMOTE_COPY_PAIR_DIRECT.format(storage_deviceId, object_id)
        start_time = time.time()
        response = self.connection_manager.update(
            end_point, payload, headers_input=headers
        )
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:split_remote_copy:time={:.2f}", end_time - start_time
        )
        return response

    @log_entry_exit
    def swap_split_replication_pair(self, spec, remote_pair_type, mode=None):

        secondary_storage_info = self.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        logger.writeDebug(
            "GW:swap_split_replication_pair:secondary_storage_info={}",
            secondary_storage_info,
        )
        remote_storage_deviceId = secondary_storage_info.get("storageDeviceId")

        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))
        # remoteStorageDeviceId,copyGroupName,localDeviceGroupName,remoteDeviceGroupName, copyPairName
        parameters = {"replicationType": remote_pair_type, "svolOperationMode": "SSWS"}
        if mode:
            parameters["svolOperationMode"] = mode

        if spec.local_device_group_name and spec.remote_device_group_name:
            object_id = f"{remote_storage_deviceId},{spec.copy_group_name},{spec.local_device_group_name},{spec.remote_device_group_name},{spec.copy_pair_name}"
            logger.writeDebug("GW:sng1119 spec={}", spec.local_device_group_name)
            logger.writeDebug("GW:sng1119 spec={}", spec.remote_device_group_name)
            logger.writeDebug("GW:sng1119 object_id={}", object_id)
        else:
            object_id = (
                self.copy_group_gateway.get_object_id_by_copy_group_and_copy_pair_name(
                    spec
                )
            )
            logger.writeDebug(
                "GW:swap_split_replication_pair:API object_id={}", object_id
            )

        payload = {"parameters": parameters}
        headers = self.get_remote_token(spec.secondary_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        end_point = SPLIT_REMOTE_COPY_PAIR_DIRECT.format(storage_deviceId, object_id)
        start_time = time.time()

        response = self.connection_manager.update(
            end_point, payload, headers_input=headers
        )
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:swap_split_remote_copy:time={:.2f}", end_time - start_time
        )
        return response

    @log_entry_exit
    def resync_replication_pair(self, spec, remote_pair_type):

        secondary_storage_info = self.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        logger.writeDebug(
            "GW:delete_true_copy_pair_by_pair_id:secondary_storage_info={}",
            secondary_storage_info,
        )
        remote_storage_deviceId = secondary_storage_info.get("storageDeviceId")

        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))
        # remoteStorageDeviceId,copyGroupName,localDeviceGroupName,remoteDeviceGroupName, copyPairName
        parameters = {
            "replicationType": remote_pair_type,
        }
        if spec.is_svol_readwriteable:
            parameters["svolAccessMode"] = "rw"

        if spec.local_device_group_name and spec.remote_device_group_name:
            object_id = f"{remote_storage_deviceId},{spec.copy_group_name},{spec.local_device_group_name},{spec.remote_device_group_name},{spec.copy_pair_name}"
            logger.writeDebug(
                "GW:split_replication_pair:constructed object_id={}", object_id
            )
        else:
            object_id = (
                self.copy_group_gateway.get_object_id_by_copy_group_and_copy_pair_name(
                    spec
                )
            )
            logger.writeDebug("GW:split_replication_pair:API object_id={}", object_id)

        payload = {"parameters": parameters}
        headers = self.get_remote_token(spec.secondary_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        end_point = RESYNC_REMOTE_COPY_PAIR_DIRECT.format(storage_deviceId, object_id)
        start_time = time.time()
        response = self.connection_manager.update(
            end_point, payload, headers_input=headers
        )
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:resync_remote_copy:time={:.2f}", end_time - start_time
        )
        return response

    @log_entry_exit
    def swap_resync_replication_pair(self, spec, remote_pair_type):

        secondary_storage_info = self.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        logger.writeDebug(
            "GW:swap_resync_replication_pair:secondary_storage_info={}",
            secondary_storage_info,
        )
        remote_storage_deviceId = secondary_storage_info.get("storageDeviceId")

        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))
        # remoteStorageDeviceId,copyGroupName,localDeviceGroupName,remoteDeviceGroupName, copyPairName
        parameters = {"replicationType": remote_pair_type, "doSwapSvol": True}
        logger.writeDebug("GW:swap_resync_replication_pair:parameters={}", parameters)
        if spec.local_device_group_name and spec.remote_device_group_name:
            object_id = f"{remote_storage_deviceId},{spec.copy_group_name},{spec.local_device_group_name},{spec.remote_device_group_name},{spec.copy_pair_name}"
            logger.writeDebug("sng20241119 object_id={}", object_id)
        else:
            object_id = (
                self.copy_group_gateway.get_object_id_by_copy_group_and_copy_pair_name(
                    spec
                )
            )
            logger.writeDebug(
                "GW:swap_split_replication_pair:API object_id={}", object_id
            )

        payload = {"parameters": parameters}
        headers = self.get_remote_token(spec.secondary_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        end_point = RESYNC_REMOTE_COPY_PAIR_DIRECT.format(storage_deviceId, object_id)
        start_time = time.time()
        if self.remote_connection_manager is None:
            self.init_remote_connection_manager(spec.secondary_connection_info)
        response = self.connection_manager.update(
            end_point, payload, headers_input=headers
        )
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:swap_resync_remote_copy:time={:.2f}", end_time - start_time
        )
        return response

    @log_entry_exit
    def delete_replication_pair(self, spec):
        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))
        secondary_storage_info = self.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        logger.writeDebug(
            "GW:delete_true_copy_pair_by_pair_id:secondary_storage_info={}",
            secondary_storage_info,
        )
        remote_storage_deviceId = secondary_storage_info.get("storageDeviceId")

        # remoteStorageDeviceId,copyGroupName,localDeviceGroupName,remoteDeviceGroupName, copyPairName

        # local_device_group_name = spec.local_device_group_name if spec.local_device_group_name else spec.copy_group_name + "P_"
        # remote_device_group_name = spec.remote_device_group_name if spec.remote_device_group_name else spec.copy_group_name + "S_"
        # object_id = f"{remote_storage_deviceId},{spec.copy_group_name},{local_device_group_name},{remote_device_group_name},{spec.copy_pair_name}"

        if spec.local_device_group_name and spec.remote_device_group_name:
            object_id = f"{remote_storage_deviceId},{spec.copy_group_name},{spec.local_device_group_name},{spec.remote_device_group_name},{spec.copy_pair_name}"
        else:
            object_id = (
                self.copy_group_gateway.get_object_id_by_copy_group_and_copy_pair_name(
                    spec
                )
            )
            if object_id is None:
                raise ValueError(
                    VSPReplicationPairValidateMsg.REPLICATION_PAIR_NOT_FOUND.value.format(
                        spec.copy_group_name, spec.copy_pair_name
                    )
                )
            logger.writeDebug("GW:delete_replication_pair:object_id={}", object_id)

        headers = self.get_remote_token(spec.secondary_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        end_point = DELETE_REMOTE_COPY_PAIR_DIRECT.format(storage_deviceId, object_id)
        start_time = time.time()
        response = self.connection_manager.delete(
            end_point, None, headers_input=headers
        )
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:delete_remote_copy:time={:.2f}", end_time - start_time
        )
        return response

    @log_entry_exit
    def get_replication_pair(self, spec):

        secondary_storage_info = self.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        logger.writeDebug(
            "GW:get_copy_pair_by_pair_id:secondary_storage_info={}",
            secondary_storage_info,
        )
        secondary_storage_info.get("storageDeviceId")

        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))
        # remoteStorageDeviceId,copyGroupName,localDeviceGroupName,remoteDeviceGroupName, copyPairName

        # if spec.local_device_group_name and spec.remote_device_group_name:
        # # local_device_group_name = spec.local_device_group_name if spec.local_device_group_name else spec.copy_group_name + "P_"
        # # remote_device_group_name = spec.remote_device_group_name if spec.remote_device_group_name else spec.copy_group_name + "S_"
        # else:
        object_id = (
            self.copy_group_gateway.get_object_id_by_copy_group_and_copy_pair_name(spec)
        )
        logger.writeDebug("GW:split_replication_pair:object_id={}", object_id)

        if object_id is None:
            return None  # this means hur pair is absent

        copy_group = self.copy_group_gateway.get_copy_group_by_name(spec)
        logger.writeDebug("GW:split_replication_pair:copy_group={}", copy_group)
        headers = self.get_remote_token(spec.secondary_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        end_point = GET_ONE_REMOTE_COPY_PAIRS_DIRECT.format(storage_deviceId, object_id)
        start_time = time.time()
        response = self.connection_manager.get_with_headers(
            end_point, headers_input=headers
        )
        snake_case_journal_pool = {
            self.camel_to_snake(k): v for k, v in response.items()
        }
        if copy_group.muNumber is not None:
            snake_case_journal_pool["mirror_unit_number"] = copy_group.muNumber
        snake_case_journal_pool["pvol_storage_device_id"] = storage_deviceId
        snake_case_journal_pool["pvol_storage_serial_number"] = str(
            self.storage_serial_number
        )
        snake_case_journal_pool["svol_storage_serial_number"] = (
            secondary_storage_info.get("serialNumber")
        )
        if spec.new_volume_size is not None:
            p_volume_data = VSPVolumeDirectGateway(
                self.connection_info
            ).get_volume_by_id(snake_case_journal_pool["pvol_ldev_id"])
            s_volume_data = VSPVolumeDirectGateway(
                spec.secondary_connection_info
            ).get_volume_by_id(snake_case_journal_pool["svol_ldev_id"])
            pvol_size = convert_block_capacity(p_volume_data.blockCapacity)
            svol_size = convert_block_capacity(s_volume_data.blockCapacity)
            snake_case_journal_pool["pvol_ldev_size"] = pvol_size
            snake_case_journal_pool["svol_ldev_size"] = svol_size
            logger.writeDebug("PF_REST:get_remote_copy zm_size = {}", pvol_size)

        if spec.is_svol_readwriteable is not None:
            snake_case_journal_pool["is_svol_readwriteable"] = (
                spec.is_svol_readwriteable
            )

        end_time = time.time()
        logger.writeDebug("PF_REST:get_remote_copy:time={:.2f}", end_time - start_time)
        return snake_case_journal_pool

    @log_entry_exit
    def split_replication_pair_by_object_id(
        self,
        object_id,
        secondary_connection_info,
        remote_pair_type,
        is_svol_readwriteable=None,
    ):

        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))
        parameters = {
            "replicationType": remote_pair_type,
        }
        if is_svol_readwriteable:
            parameters["svolAccessMode"] = "rw"

        payload = {"parameters": parameters}
        headers = self.get_remote_token(secondary_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        end_point = SPLIT_REMOTE_COPY_PAIR_DIRECT.format(storage_deviceId, object_id)
        start_time = time.time()
        response = self.connection_manager.update(
            end_point, payload, headers_input=headers
        )
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:split_remote_copy:time={:.2f}", end_time - start_time
        )
        return response

    @log_entry_exit
    def swap_split_replication_pair_by_object_id(
        self, object_id, secondary_connection_info, remote_pair_type
    ):

        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))

        parameters = {"replicationType": remote_pair_type, "svolOperationMode": "SSWS"}

        payload = {"parameters": parameters}
        headers = self.get_remote_token(secondary_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        end_point = SPLIT_REMOTE_COPY_PAIR_DIRECT.format(storage_deviceId, object_id)
        start_time = time.time()

        response = self.connection_manager.update(
            end_point, payload, headers_input=headers
        )
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:swap_split_remote_copy:time={:.2f}", end_time - start_time
        )
        return response

    @log_entry_exit
    def resync_replication_pair_by_object_id(
        self, object_id, secondary_connection_info, remote_pair_type
    ):

        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))
        parameters = {
            "replicationType": remote_pair_type,
        }

        payload = {"parameters": parameters}
        headers = self.get_remote_token(secondary_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        end_point = RESYNC_REMOTE_COPY_PAIR_DIRECT.format(storage_deviceId, object_id)
        start_time = time.time()
        response = self.connection_manager.update(
            end_point, payload, headers_input=headers
        )
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:resync_remote_copy:time={:.2f}", end_time - start_time
        )
        return response

    @log_entry_exit
    def swap_resync_replication_pair_by_object_id(
        self, object_id, secondary_connection_info, remote_pair_type
    ):

        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))
        parameters = {"replicationType": remote_pair_type, "doSwapSvol": True}

        payload = {"parameters": parameters}
        headers = self.get_remote_token(secondary_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        end_point = RESYNC_REMOTE_COPY_PAIR_DIRECT.format(storage_deviceId, object_id)
        start_time = time.time()

        response = self.connection_manager.update(
            end_point, payload, headers_input=headers
        )
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:swap_resync_remote_copy:time={:.2f}", end_time - start_time
        )
        return response

    @log_entry_exit
    def expand_volume(self, connection, vol_id, spec):
        vol_gateway = VSPVolumeDirectGateway(connection)
        volume_data = vol_gateway.get_volume_by_id(vol_id)
        size_in_bytes = convert_decimal_size_to_bytes(spec.new_volume_size)
        expand_val = size_in_bytes - (
            volume_data.blockCapacity if volume_data.blockCapacity else 0
        )
        # enhanced_expansion = (
        #     True
        #     if volume_data.isDataReductionShareEnabled is not None
        #     else False
        # )
        enhanced_expansion = True
        vol_gateway.expand_volume(volume_data.ldevId, expand_val, enhanced_expansion)

    @log_entry_exit
    def resize_replication_pair(self, pair, spec):
        response = ""
        split_required = True
        if pair.pvolStatus == "PSUS" and pair.svolStatus == "SSUS":
            split_required = False
        pvol_id = pair.pvolLdevId
        svol_id = pair.svolLdevId
        if split_required:
            response = self.split_replication_pair_by_object_id(
                pair.remoteMirrorCopyPairId,
                spec.secondary_connection_info,
                pair.replicationType,
            )
            logger.writeDebug("GW:resize_replication_pair:split:response={}", response)
        try:
            self.expand_volume(spec.secondary_connection_info, svol_id, spec)
            logger.writeDebug("GW:resize_replication_pair:svol_id={}", svol_id)
        except Exception as ex:
            logger.writeDebug(
                "GW:resize_replication_pair:exception in expand volume:ex={}", ex
            )
            # if we split the pair, then we need to resync it before returning
            # pvol_gateway = VSPVolumeDirectGateway(self.connection_info)
            # svol_gateway = VSPVolumeDirectGateway(spec.secondary_connection_info)
            # pvolume_data = pvol_gateway.get_volume_by_id(pvol_id)
            # svolume_data = svol_gateway.get_volume_by_id(svol_id)
            # if split_required and pvolume_data.blockCapacity == svolume_data.blockCapacity:
            #     response = self.resync_replication_pair_by_object_id(
            #         pair.remoteMirrorCopyPairId,
            #         spec.secondary_connection_info,
            #         pair.replicationType,
            #     )
            if "AFA8" in str(ex):
                raise ValueError(VSPTrueCopyValidateMsg.EXPAND_VOLUME_FAILED.value)
            elif "C390" in str(ex):
                raise ValueError(
                    VSPTrueCopyValidateMsg.EXPAND_VOLUME_FAILED_EXISTING_PAIR.value.format(
                        spec.copy_pair_name
                    )
                )
            else:
                raise ValueError(
                    VSPTrueCopyValidateMsg.EXPAND_SVOL_FAILED.value.format(svol_id)
                    + str(ex)
                )

        try:
            self.expand_volume(self.connection_info, pvol_id, spec)
            logger.writeDebug("GW:resize_replication_pair:pvol_id={}", pvol_id)
        except Exception as ex:
            logger.writeDebug(
                "GW:resize_replication_pair:exception in expand volume:ex={}", ex
            )
            if "AFA8" in str(ex):
                raise ValueError(VSPTrueCopyValidateMsg.EXPAND_VOLUME_FAILED.value)
            elif "C390" in str(ex):
                raise ValueError(
                    VSPTrueCopyValidateMsg.EXPAND_VOLUME_FAILED_EXISTING_PAIR.value.format(
                        spec.copy_pair_name
                    )
                )
            else:
                raise ValueError(
                    VSPTrueCopyValidateMsg.EXPAND_PVOL_FAILED.value.format(pvol_id)
                    + str(ex)
                )

        if split_required:
            response = self.resync_replication_pair_by_object_id(
                pair.remoteMirrorCopyPairId,
                spec.secondary_connection_info,
                pair.replicationType,
            )
            logger.writeDebug("GW:resize_replication_pair:resync:response={}", response)
        return response

    @log_entry_exit
    def secondary_takeover_replication_pair(self, spec, remote_pair_type, mode=None):

        # secondary_storage_info = self.get_secondary_storage_info(
        #     spec.secondary_connection_info
        # )
        # logger.writeDebug(
        #     "GW:secondary_takeover_replication_pair:secondary_storage_info={}",
        #     secondary_storage_info,
        # )
        # remote_storage_deviceId = secondary_storage_info.get("storageDeviceId")

        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))
        # remoteStorageDeviceId,copyGroupName,localDeviceGroupName,remoteDeviceGroupName, copyPairName
        parameters = {"mode": "auto"}
        # if mode:
        #     parameters["svolOperationMode"] = mode

        if spec.remote_device_group_name:
            object_id = f"NotSpecified,{spec.copy_group_name},{spec.remote_device_group_name},NotSpecified,{spec.copy_pair_name}"
            logger.writeDebug("GW:sng1119 spec={}", spec.remote_device_group_name)
            logger.writeDebug("GW:sng1119 object_id={}", object_id)
        else:
            raise ValueError(
                "remote_device_group_name is required for takeover operation"
            )
        payload = {"parameters": parameters}
        # headers = self.get_remote_token(spec.secondary_connection_info)
        # headers["Remote-Authorization"] = headers.pop("Authorization")
        # headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        end_point = SECONDARY_TAKEOVER_COPY_PAIR_DIRECT.format(
            storage_deviceId, object_id
        )
        start_time = time.time()

        response = self.connection_manager.post(
            end_point, payload  # , headers_input=headers
        )
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:secondary_takeover_replication_pair:time={:.2f}",
            end_time - start_time,
        )
        response = self.connection_manager.get(
            GET_ONE_REMOTE_COPY_PAIRS_DIRECT.format(storage_deviceId, object_id)
        )
        logger.writeDebug(f"GW:get_storage_device_id:response={response}")
        # Inline code to convert all keys to snake_case
        for key, value in list(response.items()):
            # Convert camelCase to snake_case for top-level keys
            new_key = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower()
            response[new_key] = response.pop(key)

            # Convert keys in nested dictionaries or lists
            if isinstance(value, dict):
                for sub_key, sub_value in list(value.items()):
                    new_sub_key = re.sub(
                        r"([a-z0-9])([A-Z])", r"\1_\2", sub_key
                    ).lower()
                    value[new_sub_key] = value.pop(sub_key)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        for sub_key, sub_value in list(item.items()):
                            new_sub_key = re.sub(
                                r"([a-z0-9])([A-Z])", r"\1_\2", sub_key
                            ).lower()
                            item[new_sub_key] = item.pop(sub_key)
        return response
