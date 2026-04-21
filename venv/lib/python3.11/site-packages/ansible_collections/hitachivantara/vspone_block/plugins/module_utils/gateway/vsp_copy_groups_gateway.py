import time
import re

try:
    from .gateway_manager import VSPConnectionManager
    from ..model.vsp_copy_groups_models import (
        DirectCopyPairInfo,
        DirectCopyPairInfoList,
        CopyGroupInfo,
        CopyGroupInfoList,
        DirectSpecificCopyGroupInfo,
        DirectSpecificCopyGroupInfoList,
    )
    from .vsp_volume import VSPVolumeDirectGateway
    from ..common.ansible_common import dicts_to_dataclass_list
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
except ImportError:
    from .gateway_manager import VSPConnectionManager
    from model.vsp_copy_groups_models import (
        DirectCopyPairInfo,
        DirectCopyPairInfoList,
        CopyGroupInfo,
        CopyGroupInfoList,
        DirectSpecificCopyGroupInfo,
        DirectSpecificCopyGroupInfoList,
    )
    from .vsp_volume import VSPVolumeDirectGateway
    from common.ansible_common import dicts_to_dataclass_list
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

GET_REMOTE_STORAGE_SYSTEMS = "v1/objects/remote-storages"
GET_STORAGES_DIRECT = "v1/objects/storages"
GET_COPY_GROUPS = "v1/objects/remote-mirror-copygroups?remoteStorageDeviceId={}"
GET_ONE_REMOTE_COPY_GROUP = "v1/objects/remote-mirror-copygroups/{}"
GET_ONE_REMOTE_COPY_PAIR = "v1/objects/remote-mirror-copypairs/{}"
GET_STORAGES_DIRECT = "v1/objects/storages"
SPLIT_REMOTE_COPY_GROUP_DIRECT = (
    "v1/objects/storages/{}/remote-mirror-copygroups/{}/actions/split/invoke"
)
RESYNC_REMOTE_COPY_GROUP_DIRECT = (
    "v1/objects/storages/{}/remote-mirror-copygroups/{}/actions/resync/invoke"
)
DELETE_REMOTE_COPY_GROUP_DIRECT = "v1/objects/storages/{}/remote-mirror-copygroups/{}"
TAKEOVER_REMOTE_COPY_GROUP_DIRECT = (
    "v1/objects/storages/{}/remote-mirror-copygroups/{}/actions/takeover/invoke"
)
logger = Log()
gCopyGroupList = None


class VSPCopyGroupsDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.connection_info = connection_info
        self.remote_connection_manager = None
        self.serial = None

    @log_entry_exit
    def set_storage_serial_number(self, serial: str):
        self.storage_serial_number = serial
        if self.storage_serial_number is None:
            primary_storage_info = self.get_secondary_storage_info(self.connection_info)
            self.storage_serial_number = primary_storage_info.get("serialNumber")

    @log_entry_exit
    def get_replication_type(self, replication: str):
        replication_type = {"tc": "TC", "hur": "UR", "gad": "GAD"}
        return replication_type.get(replication, None)

    @log_entry_exit
    def get_all_remote_pairs_from_copy_groups(self, spec):
        all_remote_pairs = []
        start_time = time.time()
        all_copy_groups = self.get_copy_groups(spec)
        logger.writeDebug(f"GW:get_storage_device_id:all_copy_groups={all_copy_groups}")
        for copy_group in all_copy_groups.data:
            all_copy_pairs_for_a_copy_group = self.get_all_copy_pairs_for_a_copy_group(
                copy_group, spec
            )
            if all_copy_pairs_for_a_copy_group is None:
                continue
            all_remote_pairs.extend(all_copy_pairs_for_a_copy_group)
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:get_all_copy_pairs:time={:.2f} no_of_copy_grps = {} no_of_copy_pairs = {}",
            end_time - start_time,
            len(all_copy_groups.data),
            len(all_remote_pairs),
        )
        return all_remote_pairs

    @log_entry_exit
    def get_remote_pairs_for_a_copy_group(self, spec):
        copy_group = self.get_copy_group_by_name(spec)
        if copy_group is None:
            return []
        all_remote_pairs = []
        all_copy_pairs_for_a_copy_group = self.get_all_copy_pairs_for_a_copy_group(
            copy_group, spec
        )
        if all_copy_pairs_for_a_copy_group is not None:
            all_remote_pairs.extend(all_copy_pairs_for_a_copy_group)
        return all_remote_pairs

    @log_entry_exit
    def get_remote_pairs_by_copy_group_and_copy_pair_name(self, spec):
        copy_group = self.get_copy_group_by_name(spec)
        if copy_group is None:
            return []
        all_remote_pairs = []
        all_copy_pairs_for_a_copy_group = self.get_all_copy_pairs_for_a_copy_group(
            copy_group, spec
        )
        if all_copy_pairs_for_a_copy_group is not None:
            for y in all_copy_pairs_for_a_copy_group:
                if y.copyPairName == spec.copy_pair_name:
                    all_remote_pairs.append(y)
        logger.writeDebug(
            f"GW:get_remote_pairs_by_copy_group_and_copy_pair_name:all_remote_pairs={all_remote_pairs}"
        )
        return all_remote_pairs

    @log_entry_exit
    def get_remote_pairs_by_pvol(self, spec):
        all_copy_pairs = self.get_all_remote_pairs_from_copy_groups(spec)
        all_remote_pairs = []
        if all_copy_pairs is not None:
            for y in all_copy_pairs:
                if str(y.pvolLdevId) == str(spec.primary_volume_id):
                    all_remote_pairs.append(y)

        return all_remote_pairs

    @log_entry_exit
    def get_remote_pairs_by_svol(self, spec):
        all_copy_pairs = self.get_all_remote_pairs_from_copy_groups(spec)
        logger.writeDebug(f"GW:92 all_copy_pairs={all_copy_pairs}")
        logger.writeDebug(f"GW:92 spec.secondary_volume_id={spec.secondary_volume_id}")
        all_remote_pairs = []
        if all_copy_pairs is not None:
            for y in all_copy_pairs:
                logger.writeDebug(f"GW:92 y={y}")
                if str(y.svolLdevId) == str(spec.secondary_volume_id):
                    all_remote_pairs.append(y)

        return all_remote_pairs

    def get_remote_copy_pair_by_id(self, spec):

        remote_connection_info = spec.secondary_connection_info
        remote_connection_manager = VSPConnectionManager(
            remote_connection_info.address,
            remote_connection_info.username,
            remote_connection_info.password,
            remote_connection_info.api_token,
        )
        remote_storage_deviceId = self.get_secondary_storage_device_id(
            remote_connection_info
        )
        copy_pair_id = f"{remote_storage_deviceId},{spec.copy_group_name},{spec.local_device_group_name},{spec.remote_device_group_name},{spec.copy_pair_name}"
        all_remote_pairs = []
        headers = remote_connection_manager.getAuthToken()
        headers["Remote-Authorization"] = headers.pop("Authorization")
        response = self.connection_manager.get_with_headers(
            GET_ONE_REMOTE_COPY_PAIR.format(copy_pair_id), headers_input=headers
        )
        if response is not None:
            all_remote_pairs.append(DirectCopyPairInfo(**response))
        return all_remote_pairs

    @log_entry_exit
    def set_serial(self, serial):
        logger.writeError(f"GW:set_serial={self.serial}")
        self.serial = serial

    @log_entry_exit
    def get_copy_group_list(self):
        return gCopyGroupList

    @log_entry_exit
    def get_secondary_storage_device_id(self, secondary_connection_info):
        if self.remote_connection_manager is None:
            self.init_remote_connection_manager(secondary_connection_info)

        secondary_storage_info = self.get_secondary_storage_info(
            secondary_connection_info
        )
        logger.writeDebug(
            "GW:get_secondary_storage_device_id:secondary_storage_info={}",
            secondary_storage_info,
        )
        remote_storage_device_id = secondary_storage_info.get("storageDeviceId")
        return remote_storage_device_id

    @log_entry_exit
    def get_storage_device_id(self, serial):
        response = self.connection_manager.get(GET_REMOTE_STORAGE_SYSTEMS)
        logger.writeDebug(f"GW:get_storage_device_id:response={response}")
        for x in response.get("data"):
            if str(x.get("serialNumber")) == str(serial):

                remote_storage_device_id = x.get("storageDeviceId")
                return remote_storage_device_id

        return None

    @log_entry_exit
    def get_secondary_storage_info(self, remote_connection_info):
        self.init_remote_connection_manager(remote_connection_info)
        secondary_storage = self.remote_connection_manager.get(GET_STORAGES_DIRECT)
        return secondary_storage["data"][0]

    @log_entry_exit
    def get_primary_storage_device_id(self):
        primary_storage = self.connection_manager.get(GET_STORAGES_DIRECT)
        primary_storage_info = primary_storage["data"][0]
        primary_storage_device_id = primary_storage_info.get("serialNumber")
        return primary_storage_device_id

    @log_entry_exit
    def init_remote_connection_manager(self, remote_connection_info):
        self.remote_connection_manager = VSPConnectionManager(
            remote_connection_info.address,
            remote_connection_info.username,
            remote_connection_info.password,
            remote_connection_info.api_token,
        )
        return

    @log_entry_exit
    def get_remote_token(self, remote_connection_info):
        self.remote_connection_manager = VSPConnectionManager(
            remote_connection_info.address,
            remote_connection_info.username,
            remote_connection_info.password,
            remote_connection_info.api_token,
        )

        return self.remote_connection_manager.getAuthToken()

    @log_entry_exit
    def get_copy_groups(self, spec):
        start_time = time.time()
        secondary_storage_info = self.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        logger.writeDebug(
            "GW:get_copy_groups:secondary_storage_info={}", secondary_storage_info
        )
        remote_storage_device_id = secondary_storage_info.get("storageDeviceId")
        logger.writeDebug(f"GW:remote_storage_device_id={remote_storage_device_id}")

        headers = self.get_remote_token(spec.secondary_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        response = self.connection_manager.get_with_headers(
            GET_COPY_GROUPS.format(remote_storage_device_id), headers_input=headers
        )
        logger.writeDebug(f"GW:get_copy_groups:response={response}")
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:get_copy_groups:time={:.2f} no_of_copy_groups = {}",
            end_time - start_time,
            len(response.get("data")),
        )

        global gCopyGroupList
        gCopyGroupList = CopyGroupInfoList(
            dicts_to_dataclass_list(response["data"], CopyGroupInfo)
        )
        return gCopyGroupList

    @log_entry_exit
    def get_copy_group_by_name(self, spec):
        response = self.get_copy_groups(spec)
        for x in response.data:
            if x.copyGroupName == spec.copy_group_name:
                return x
        return None

    @log_entry_exit
    def get_all_copy_pairs_for_a_copy_group(self, copy_group, spec, completeInfo=False):
        try:
            headers = self.get_remote_token(spec.secondary_connection_info)
            headers["Remote-Authorization"] = headers.pop("Authorization")
        except Exception as e:
            logger.writeError(f"GW:get_all_copy_pairs_for_a_copy_group:exception={e}")
            headers = self.get_remote_token(spec.secondary_connection_info)
            headers["Remote-Authorization"] = headers.pop("Authorization")
        try:
            response = self.connection_manager.get_with_headers(
                GET_ONE_REMOTE_COPY_GROUP.format(copy_group.remoteMirrorCopyGroupId),
                headers_input=headers,
            )
            logger.writeDebug(f"GW:get_remote_copy_pairs:response={response}")

            try:
                for p in response["copyPairs"]:
                    if p["replicationType"] == "GAD":
                        pvol = VSPVolumeDirectGateway(
                            self.connection_info
                        ).get_volume_by_id(p["pvolLdevId"])
                        p["isAluaEnabled"] = pvol.isAluaEnabled
            except Exception as e:
                # sng20250111 - includes: Failed to establish a connection
                # just log it so we can still return the pairs
                # should we do the for loop only for single or few items?
                logger.writeDebug(f"GW: 307 Exception={e}")

            one_specific_copy_gr = DirectSpecificCopyGroupInfo(**response)
            logger.writeDebug(
                f"GW:get_copy_pairs:one_specific_copy_gr={one_specific_copy_gr}"
            )
            if completeInfo:
                return one_specific_copy_gr
            else:
                return one_specific_copy_gr.copyPairs

        except Exception as e:
            # if there is an exception, it could be because of the token expiry, so get the token again and retry
            # Refresh the connections
            # For different storage error msg are different, so we can't check error msgs.
            # For pegasus, error msg is "User authentication failed"
            # For VSP 5600H, getting copypair is not working
            if "User authentication failed" in str(e):
                logger.writeDebug(
                    "GW:get_all_copy_pairs:exception:User authentication failed:Refreshing the connections"
                )
                self.connection_manager = VSPConnectionManager(
                    self.connection_info.address,
                    self.connection_info.username,
                    self.connection_info.password,
                    self.connection_info.api_token,
                )

                headers = self.get_remote_token(spec.secondary_connection_info)
                headers["Remote-Authorization"] = headers.pop("Authorization")

                try:
                    response = self.connection_manager.get_with_headers(
                        GET_ONE_REMOTE_COPY_GROUP.format(
                            copy_group.remoteMirrorCopyGroupId
                        ),
                        headers_input=headers,
                    )
                    one_specific_copy_gr = DirectSpecificCopyGroupInfo(**response)
                    logger.writeDebug(f"GW:get_copy_groups:response={response}")
                    logger.writeDebug(
                        f"GW:get_copy_pairs:one_specific_copy_gr={one_specific_copy_gr}"
                    )
                    if completeInfo:
                        return one_specific_copy_gr
                    else:
                        return one_specific_copy_gr.copyPairs
                except Exception as e:
                    # sng20241115 for Operations cannot be performed for the specified object (xxx),
                    # we don't want to throw exception else it breaks the whole operation,
                    # just log it and keep going
                    logger.writeDebug("GW:get_all_copy_pairs:exception={}", e)
                    return None

            else:
                logger.writeDebug("GW:get_all_copy_pairs:exception={}", e)
                return None

    @log_entry_exit
    def get_all_copy_pairs(self, spec):

        if spec.copy_group_name:
            response = self.get_all_copy_pairs_by_copygroup_name(spec)
            return response

        start_time = time.time()
        copy_groups = self.get_copy_groups(spec)

        copy_pairs = []
        copy_groups_details = []

        for x in copy_groups.data:
            one_specific_copy_gr = self.get_all_copy_pairs_for_a_copy_group(x, spec)
            if one_specific_copy_gr is None:
                continue
            copy_groups_details.append(one_specific_copy_gr)
            copy_pairs.append(one_specific_copy_gr.copyPairs)
        end_time = time.time()
        logger.writeDebug(
            f"GW:get_all_copy_pairs:one_specific_copy_gr={one_specific_copy_gr}"
        )
        logger.writeDebug(
            "PF_REST:get_all_copy_pairs:time={:.2f} no_of_copy_grps = {} no_of_copy_pairs = {}",
            end_time - start_time,
            len(copy_groups.data),
            len(copy_pairs),
        )
        # return DirectCopyPairInfoList(data=copy_pairs)
        return DirectSpecificCopyGroupInfoList(data=copy_groups_details)

    @log_entry_exit
    def get_all_copy_pairs_by_type(self, spec, replication_type):

        if spec.copy_group_name:
            response = self.get_all_copy_pairs_by_copygroup_name(spec)
            logger.writeDebug(f"GW:get_all_copy_pairs_by_type response={response}")
            copy_pairs = response.copyPairs
            logger.writeDebug(
                f"GW:get_all_copy_pairs_by_type copy_pairs={copy_pairs} type={type(copy_pairs)}"
            )
            replication_pairs = []
            if copy_pairs is None:
                return replication_pairs
            elif len(copy_pairs) == 1:
                cp = copy_pairs[0]
                if cp.replicationType == replication_type:
                    replication_pairs.append(cp)
                    return DirectCopyPairInfoList(data=replication_pairs)
            else:
                for cp in copy_pairs:
                    if cp.replicationType == replication_type:
                        replication_pairs.append(cp)
                    logger.writeDebug(
                        f"GW:get_all_replication_pairs:replication_pairs={replication_pairs}"
                    )

                return replication_pairs

        start_time = time.time()
        copy_groups = self.get_copy_groups(spec)

        copy_pairs = []
        copy_groups_details = []

        for x in copy_groups.data:
            one_specific_copy_gr = self.get_all_copy_pairs_for_a_copy_group(x, spec)
            if one_specific_copy_gr is None:
                continue
            copy_groups_details.append(one_specific_copy_gr)
            copy_pairs.extend(one_specific_copy_gr.copyPairs)
        end_time = time.time()
        logger.writeDebug(
            f"GW:get_all_copy_pairs:one_specific_copy_gr={one_specific_copy_gr}"
        )
        logger.writeDebug(
            "PF_REST:get_all_copy_pairs:time={:.2f} no_of_copy_grps = {} no_of_copy_pairs = {}",
            end_time - start_time,
            len(copy_groups.data),
            len(copy_pairs),
        )
        logger.writeDebug(f"GW:get_all_replication_pairs:copy_pairs={copy_pairs}")

        replication_pairs = []
        for cp in copy_pairs:
            if cp.replicationType == replication_type:
                replication_pairs.extend(cp)
        logger.writeDebug(
            f"GW:get_all_replication_pairs:replication_pairs={replication_pairs}"
        )
        return replication_pairs

    @log_entry_exit
    def get_all_copy_pairs_by_copygroup_name(self, spec):
        response = self.get_copy_groups(spec)
        copy_pairs = []
        for x in response.data:
            if x.copyGroupName == spec.copy_group_name:
                one_specific_copy_gr = self.get_all_copy_pairs_for_a_copy_group(x, spec)
                logger.writeDebug(
                    f"GW:get_all_copy_pairs_by_copygroup_name:one_specific_copy_gr={one_specific_copy_gr}"
                )
                copy_pairs.append(one_specific_copy_gr)
                # return copy_pairs
                # return DirectSpecificCopyGroupInfoList(data=copy_pairs)
                return one_specific_copy_gr

        return None

    @log_entry_exit
    def get_one_copygroup_info_by_name(self, spec, fact_spec=False):
        response = self.get_copy_groups(spec)
        for x in response.data:
            if x.copyGroupName == spec.copy_group_name:
                one_specific_copy_gr = self.get_all_copy_pairs_for_a_copy_group(
                    x, spec, True
                )
                logger.writeDebug(
                    f"GW:get_one_copygroup_info_by_name:one_specific_copy_gr={one_specific_copy_gr}"
                )

                if one_specific_copy_gr is not None and x.muNumber is not None:
                    one_specific_copy_gr.muNumber = x.muNumber

                return one_specific_copy_gr

        return None

    @log_entry_exit
    def get_one_copy_pair_by_id(self, copy_pair_id, remote_connection_info):
        remote_connection_manager = VSPConnectionManager(
            remote_connection_info.address,
            remote_connection_info.username,
            remote_connection_info.password,
            remote_connection_info.api_token,
        )
        self.connection_manager = VSPConnectionManager(
            self.connection_info.address,
            self.connection_info.username,
            self.connection_info.password,
            self.connection_info.api_token,
        )
        headers = remote_connection_manager.getAuthToken()
        headers["Remote-Authorization"] = headers.pop("Authorization")
        response = self.connection_manager.get_with_headers(
            GET_ONE_REMOTE_COPY_PAIR.format(copy_pair_id), headers_input=headers
        )
        logger.writeDebug(f"GW:get_one_copy_pair_by_id:response={response}")
        return DirectCopyPairInfo(**response)

    @log_entry_exit
    def get_tc_by_cp_group_and_primary_vol_id(self, spec):
        copy_group = self.get_remote_pairs_for_a_copy_group(spec)
        if copy_group is None:
            return None
        for y in copy_group:
            if y.pvolLdevId == spec.primary_volume_id and y.replicationType == "TC":
                return y
        return None

    @log_entry_exit
    def get_tc_pair_by_copy_group_and_copy_pair_name(self, spec):
        copy_pairs = self.get_remote_pairs_for_a_copy_group(spec)
        for y in copy_pairs:
            if y.copyPairName == spec.copy_pair_name and y.replicationType == "TC":
                # tc_pairs.append(y)
                return y

        return None

    @log_entry_exit
    def get_object_id_by_copy_group_and_copy_pair_name(self, spec):
        copy_group = self.get_all_copy_pairs_by_copygroup_name(spec)

        if copy_group is not None:
            for y in copy_group:
                if y.copyPairName == spec.copy_pair_name:
                    return y.remoteMirrorCopyPairId

        return None

    @log_entry_exit
    def get_local_remote_device_names(self, spec, storage_device_id=None):

        copy_group = self.get_copy_group_by_name(spec)
        logger.writeDebug(
            f"GW:get_local_remote_device_names:get_copY-group-by-name={copy_group}"
        )

        if copy_group is None:
            return None

        local_device_name = None
        remote_device_name = None

        if copy_group.remoteStorageDeviceId == storage_device_id:
            local_device_name = copy_group.localDeviceGroupName
            remote_device_name = copy_group.remoteDeviceGroupName
        else:
            local_device_name = copy_group.remoteDeviceGroupName
            remote_device_name = copy_group.localDeviceGroupName

        return (local_device_name, remote_device_name)

    @log_entry_exit
    def get_gad_pair_by_copy_group_and_copy_pair_name(self, spec):
        copy_pairs = self.get_all_copy_pairs_by_copygroup_name(spec)

        logger.writeDebug(f"GW:292 copy_pairs={copy_pairs}")

        if copy_pairs is None:
            return

        data = copy_pairs

        if hasattr(copy_pairs, "data"):
            data = copy_pairs.data

        if not isinstance(data, list):
            data = [data]

        tc_pairs = []
        for x in data:

            if isinstance(x, DirectCopyPairInfo):
                if x.copyPairName == spec.copy_pair_name and x.replicationType == "GAD":
                    #  if there is more than one, return the first one for now
                    tc_pairs.append(x)
                    return x
                else:
                    continue

            for y in x.copyPairs:
                if y.copyPairName == spec.copy_pair_name and y.replicationType == "GAD":
                    #  if there is more than one, return the first one for now
                    tc_pairs.append(y)
                    return y

        return None

    @log_entry_exit
    def split_copy_group(self, spec):
        secondary_storage_info = self.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        logger.writeDebug(
            "GW:split_remote_copy_group:secondary_storage_info={}",
            secondary_storage_info,
        )
        remote_storage_deviceId = secondary_storage_info.get("storageDeviceId")

        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))

        parameters = {
            "replicationType": spec.replication_type,
        }
        if spec.is_svol_writable is not None and spec.is_svol_writable:
            parameters["svolAccessMode"] = "rw"
        elif spec.is_svol_writable is not None and spec.is_svol_writable is False:
            parameters["svolAccessMode"] = "r"
        if spec.do_pvol_write_protect is not None:
            parameters["doPvolWriteProtect"] = spec.do_pvol_write_protect
        if spec.do_data_suspend is not None:
            parameters["doDataSuspend"] = spec.do_data_suspend

        # remoteStorageDeviceId,copyGroupName,localDeviceGroupName,remoteDeviceGroupName
        if spec.local_device_group_name and spec.remote_device_group_name:
            object_id = f"{remote_storage_deviceId},{spec.copy_group_name},{spec.local_device_group_name},{spec.remote_device_group_name}"
            logger.writeDebug("remote copy group object_id={}", object_id)
        else:
            copy_group_info = self.get_one_copygroup_info_by_name(spec)
            object_id = copy_group_info.remoteMirrorCopyGroupId

        payload = {"parameters": parameters}
        headers = self.get_remote_token(spec.secondary_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        end_point = SPLIT_REMOTE_COPY_GROUP_DIRECT.format(storage_deviceId, object_id)
        start_time = time.time()
        response = self.connection_manager.update(
            end_point, payload, headers_input=headers
        )
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:split_remote_copy_group:time={:.2f}", end_time - start_time
        )
        return response

    @log_entry_exit
    def swap_split_copy_group(self, spec):
        secondary_storage_info = self.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        logger.writeDebug(
            "GW:swap_split_remote_copy_group:secondary_storage_info={}",
            secondary_storage_info,
        )
        remote_storage_deviceId = secondary_storage_info.get("storageDeviceId")

        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))

        parameters = {
            "replicationType": spec.replication_type,
            "svolOperationMode": "SSWS",
        }
        if spec.svol_operation_mode:
            parameters["svolOperationMode"] = spec.svol_operation_mode
        # remoteStorageDeviceId,copyGroupName,localDeviceGroupName,remoteDeviceGroupName
        if spec.local_device_group_name and spec.remote_device_group_name:
            object_id = f"{remote_storage_deviceId},{spec.copy_group_name},{spec.local_device_group_name},{spec.remote_device_group_name}"
            logger.writeDebug("remote copy group object_id={}", object_id)
        else:
            copy_group_info = self.get_one_copygroup_info_by_name(spec)
            object_id = copy_group_info.remoteMirrorCopyGroupId

        payload = {"parameters": parameters}
        headers = self.get_remote_token(spec.secondary_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        end_point = SPLIT_REMOTE_COPY_GROUP_DIRECT.format(storage_deviceId, object_id)
        start_time = time.time()

        response = self.connection_manager.update(
            end_point, payload, headers_input=headers
        )
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:swap_split_remote_copy_group:time={:.2f}", end_time - start_time
        )
        return response

    @log_entry_exit
    def resync_copy_group(self, spec):
        secondary_storage_info = self.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        logger.writeDebug(
            "GW:resync_copy_group:secondary_storage_info={}",
            secondary_storage_info,
        )
        remote_storage_deviceId = secondary_storage_info.get("storageDeviceId")

        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))

        parameters = {
            "replicationType": spec.replication_type,
        }
        if spec.do_failback is not None:
            parameters["doFailback"] = spec.do_failback
        if spec.failback_mirror_unit_number is not None:
            parameters["failbackMuNumber"] = spec.failback_mirror_unit_number
        if spec.is_consistency_group is not None:
            parameters["isConsistencyGroup"] = spec.is_consistency_group
        if spec.consistency_group_id is not None:
            parameters["consistencyGroupId"] = spec.consistency_group_id
        if spec.fence_level is not None:
            parameters["fenceLevel"] = spec.fence_level
        if spec.copy_pace is not None:
            parameters["copyPace"] = spec.copy_pace

        if spec.local_device_group_name and spec.remote_device_group_name:
            object_id = f"{remote_storage_deviceId},{spec.copy_group_name},{spec.local_device_group_name},{spec.remote_device_group_name}"
            logger.writeDebug("remote copy group object_id={}", object_id)
        else:
            copy_group_info = self.get_one_copygroup_info_by_name(spec)
            object_id = copy_group_info.remoteMirrorCopyGroupId

        payload = {"parameters": parameters}
        headers = self.get_remote_token(spec.secondary_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        end_point = RESYNC_REMOTE_COPY_GROUP_DIRECT.format(storage_deviceId, object_id)
        start_time = time.time()
        response = self.connection_manager.update(
            end_point, payload, headers_input=headers
        )
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:resync_remote_copy_group:time={:.2f}", end_time - start_time
        )
        return response

    @log_entry_exit
    def swap_resync_copy_group(self, spec):
        secondary_storage_info = self.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        logger.writeDebug(
            "GW:swap_resync_copy_group:secondary_storage_info={}",
            secondary_storage_info,
        )
        remote_storage_deviceId = secondary_storage_info.get("storageDeviceId")

        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))
        # remoteStorageDeviceId,copyGroupName,localDeviceGroupName,remoteDeviceGroupName
        parameters = {"replicationType": spec.replication_type, "doSwapSvol": True}
        if spec.is_consistency_group is not None:
            parameters["isConsistencyGroup"] = spec.is_consistency_group
        if spec.consistency_group_id is not None:
            parameters["consistencyGroupId"] = spec.consistency_group_id
        if spec.copy_pace is not None:
            parameters["copyPace"] = spec.copy_pace
        logger.writeDebug("GW:swap_resync_replication_pair:parameterss={}", parameters)
        if spec.local_device_group_name and spec.remote_device_group_name:
            object_id = f"{remote_storage_deviceId},{spec.copy_group_name},{spec.local_device_group_name},{spec.remote_device_group_name}"
            logger.writeDebug("remote copy group object_id={}", object_id)
        else:
            copy_group_info = self.get_one_copygroup_info_by_name(spec)
            object_id = copy_group_info.remoteMirrorCopyGroupId

        payload = {"parameters": parameters}
        headers = self.get_remote_token(spec.secondary_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        end_point = RESYNC_REMOTE_COPY_GROUP_DIRECT.format(storage_deviceId, object_id)
        start_time = time.time()
        if self.remote_connection_manager is None:
            self.init_remote_connection_manager(spec.secondary_connection_info)
        response = self.connection_manager.update(
            end_point, payload, headers_input=headers
        )
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:swap_resync_remote_copy_group:time={:.2f}", end_time - start_time
        )
        return response

    @log_entry_exit
    def delete_copy_group(self, spec):
        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))
        secondary_storage_info = self.get_secondary_storage_info(
            spec.secondary_connection_info
        )
        logger.writeDebug(
            "GW:delete_remote_copy_group:secondary_storage_info={}",
            secondary_storage_info,
        )
        remote_storage_deviceId = secondary_storage_info.get("storageDeviceId")

        if spec.local_device_group_name and spec.remote_device_group_name:
            object_id = f"{remote_storage_deviceId},{spec.copy_group_name},{spec.local_device_group_name},{spec.remote_device_group_name}"
            logger.writeDebug("remote copy group object_id={}", object_id)
        else:
            copy_group_info = self.get_one_copygroup_info_by_name(spec)
            object_id = copy_group_info.remoteMirrorCopyGroupId

        headers = self.get_remote_token(spec.secondary_connection_info)
        headers["Remote-Authorization"] = headers.pop("Authorization")
        end_point = DELETE_REMOTE_COPY_GROUP_DIRECT.format(storage_deviceId, object_id)
        start_time = time.time()
        response = self.connection_manager.delete(
            end_point, None, headers_input=headers
        )
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:delete_remote_copy_group:time={:.2f}", end_time - start_time
        )
        return response

    @log_entry_exit
    def takeover_copy_group(self, spec):
        # secondary_storage_info = self.get_secondary_storage_info(
        #     spec.secondary_connection_info
        # )
        # logger.writeDebug(
        #     "GW:takeover_copy_group:secondary_storage_info={}",
        #     secondary_storage_info,
        # )
        # remote_storage_deviceId = secondary_storage_info.get("storageDeviceId")

        storage_deviceId = self.get_storage_device_id(str(self.storage_serial_number))

        parameters = {"mode": "auto"}

        # remoteStorageDeviceId,copyGroupName,localDeviceGroupName,remoteDeviceGroupName
        if spec.remote_device_group_name:
            object_id = f"NotSpecified,{spec.copy_group_name},{spec.remote_device_group_name},NotSpecified"
            logger.writeDebug("remote copy group object_id={}", object_id)
        else:
            raise ValueError(
                "remote_device_group_name is required for takeover operation"
            )
            # copy_group_info = self.get_one_copygroup_info_by_name(spec)
            # object_id = copy_group_info.remoteMirrorCopyGroupId
            # parts = object_id.split(',')
            # if len(parts) == 4:
            #     parts[0] = "NotSpecified"
            #     parts[3] = "NotSpecified"
            #     object_id = ','.join(parts)

        payload = {"parameters": parameters}
        # headers = self.get_remote_token(spec.secondary_connection_info)
        # # headers["Remote-Authorization"] = headers.pop("Authorization")
        # headers["Job-Mode-Wait-Configuration-Change"] = "NoWait"
        end_point = TAKEOVER_REMOTE_COPY_GROUP_DIRECT.format(
            storage_deviceId, object_id
        )
        start_time = time.time()
        response = self.connection_manager.post(
            end_point, payload  # , headers_input=None
        )
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:takeover_copy_group:time={:.2f} , response= {}",
            end_time - start_time,
            response,
        )
        response = self.connection_manager.get(
            GET_ONE_REMOTE_COPY_GROUP.format(response)
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
