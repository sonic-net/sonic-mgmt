import time

try:
    from .gateway_manager import VSPConnectionManager
    from ..common.ansible_common import dicts_to_dataclass_list
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..model.vsp_quorum_disk_models import (
        ExtVolumeInfoList,
        ExtVolumeInfo,
        ExternalPathGroupInfoList,
        ExternalPathGroupInfo,
        ExternalPathInfoList,
        ExternalPathInfo,
        QuorumDiskInfoList,
        QuorumDiskInfo,
    )
except ImportError:
    from model.vsp_quorum_disk_models import (
        ExtVolumeInfoList,
        ExtVolumeInfo,
        ExternalPathGroupInfoList,
        ExternalPathGroupInfo,
        ExternalPathInfoList,
        ExternalPathInfo,
        QuorumDiskInfoList,
        QuorumDiskInfo,
    )
    from .gateway_manager import VSPConnectionManager
    from common.ansible_common import dicts_to_dataclass_list
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

GET_REMOTE_STORAGE_SYSTEMS = "v1/objects/remote-storages"
GET_USERGROUPS_DIRECT = "v1/objects/user-groups"
GET_USERS_DIRECT = "v1/objects/users"
QUORUM_DISKS = "v1/objects/quorum-disks"
DELETE_QUORUM_DISK = "v1/objects/quorum-disks/{}"
GET_EXT_VOLUMES = "v1/objects/external-storage-luns"
GET_EXT_PATHS = "v1/objects/external-path-groups"
GET_EXT_PARITY_GROUPS = "v1/objects/external-parity-groups"

logger = Log()


class VSPQuorumDiskDirectGateway:

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
            primary_storage_info = self.get_secondary_storage_info(
                self.connection_info
            )  # Fixed no member issue
            self.storage_serial_number = primary_storage_info.get("serialNumber")

    @log_entry_exit
    def get_secondary_storage_info(self, connection_info):
        pass  # Fixed no member issue

    @log_entry_exit
    def set_serial(self, serial):
        logger.writeError(f"GW:set_serial={self.serial}")
        self.serial = serial

    @log_entry_exit
    def get_quorum_disk_by_id(self, id):
        resp_dict = self.connection_manager.get(QUORUM_DISKS)
        logger.writeDebug(f"GW:20250303 resp_dict =  {resp_dict}")
        # Use a generator to avoid unnecessary looping
        item = next(
            (p for p in resp_dict.get("data", []) if p.get("quorumDiskId") == id),
            None,
        )
        logger.writeDebug(f"GW:20250303 item =  {item}")
        if not item:
            return None

        # Initialize and populate the journal pool object
        data = QuorumDiskInfo(**item)
        return data

    @log_entry_exit
    def get_quorum_disk_by_ldev_id(self, id):
        resp_dict = self.connection_manager.get(QUORUM_DISKS)
        logger.writeDebug(f"GW:20250303 id =  {id}")
        logger.writeDebug(f"GW:20250303 resp_dict =  {resp_dict}")
        # Use a generator to avoid unnecessary looping
        item = next(
            (p for p in resp_dict.get("data", []) if p.get("ldevId") == id),
            None,
        )
        logger.writeDebug(f"GW:20250303 item =  {item}")
        if not item:
            return None

        # Initialize and populate the journal pool object
        data = QuorumDiskInfo(**item)
        return data

    @log_entry_exit
    def get_all_quorum_disks(self):
        start_time = time.time()
        response = self.connection_manager.get(QUORUM_DISKS)
        logger.writeDebug(f"GW:get_all_quorum_disks:response={response}")
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:get_all_quorum_disks:time={:.2f} get_all_quorum_disks.size = {}",
            end_time - start_time,
            len(response.get("data")),
        )
        if response is None:
            return

        rsp = QuorumDiskInfoList(
            dicts_to_dataclass_list(response["data"], QuorumDiskInfo)
        )

        return rsp

    @log_entry_exit
    def get_external_volumes(self):
        start_time = time.time()
        url = GET_EXT_VOLUMES + "?portId=CL3-B&externalWwn=50060e8012277d61"
        response = self.connection_manager.get(url)
        logger.writeDebug(f"GW:response={response}")
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:get_external_volumes:time={:.2f} size = {}",
            end_time - start_time,
            len(response.get("data")),
        )
        if response is None:
            return

        return ExtVolumeInfoList(
            dicts_to_dataclass_list(response["data"], ExtVolumeInfo)
        )

    @log_entry_exit
    def get_external_path_groups(self):
        start_time = time.time()
        response = self.connection_manager.get(GET_EXT_PATHS)
        logger.writeDebug(f"GW:response={response}")
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:get_external_path_groups:time={:.2f} size = {}",
            end_time - start_time,
            len(response.get("data")),
        )
        if response is None:
            return

        epglist = ExternalPathGroupInfoList(
            dicts_to_dataclass_list(response["data"], ExternalPathGroupInfo)
        )

        for epg in epglist.data:
            epg.externalPaths = ExternalPathInfoList(
                dicts_to_dataclass_list(epg.externalPaths, ExternalPathInfo)
            )

        return epglist

    @log_entry_exit
    def create_quorum_disk(
        self,
        quorumDiskId,
        remoteSerialNumber,
        remoteStorageTypeId,
        ldevId,
    ):
        endPoint = QUORUM_DISKS
        payload = {
            "quorumDiskId": quorumDiskId,
            "remoteSerialNumber": remoteSerialNumber,
            "remoteStorageTypeId": remoteStorageTypeId,
            "ldevId": ldevId,
        }
        response = self.connection_manager.post(endPoint, payload)
        return response

    @log_entry_exit
    def delete_quorum_disk(
        self,
        quorumDiskId,
    ):
        endPoint = DELETE_QUORUM_DISK.format(quorumDiskId)
        response = self.connection_manager.delete(endPoint)
        return response
