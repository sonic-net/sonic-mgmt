import time

try:
    from .gateway_manager import VSPConnectionManager
    from ..common.ansible_common import dicts_to_dataclass_list
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..model.vsp_quorum_disk_models import (
        ExtVolumeInfoList,
        ExtVolumeInfo,
        ExtVolumeLocalInfoList,
        ExtVolumeLocalInfo,
        ExternalPathGroupInfoList,
        ExternalPathGroupInfo,
        ExternalPathInfoList,
        ExternalPathInfo,
        SalamanderExternalPathInfoList,
        SalamanderExternalPathInfo,
        SalamanderExternalPathGroupInfo,
    )
except ImportError:
    from model.vsp_quorum_disk_models import (
        ExtVolumeInfoList,
        ExtVolumeInfo,
        ExtVolumeLocalInfoList,
        ExtVolumeLocalInfo,
        ExternalPathGroupInfoList,
        ExternalPathGroupInfo,
        ExternalPathInfoList,
        ExternalPathInfo,
        SalamanderExternalPathInfoList,
        SalamanderExternalPathInfo,
        SalamanderExternalPathGroupInfo,
    )
    from .gateway_manager import VSPConnectionManager
    from common.ansible_common import dicts_to_dataclass_list
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

GET_EXT_VOLUMES = "v1/objects/external-storage-luns?portId={}&externalWwn={}"
GET_EXT_PATHS = "v1/objects/external-path-groups"
GET_EXTERNAL_PATH_GROUPS_ONE = "v1/objects/external-path-groups/{}"
SALAMENDER_GET_EXTERNAL_PATH_GROUPS_ONE = "simple/v1/objects/external-path-groups/{}"
GET_EXT_VOLUMES_LOCAL = "v1/objects/external-volumes"
GET_EXT_PARITY_GROUPS = "v1/objects/external-parity-groups"
GET_EXT_PARITY_GROUP = "v1/objects/external-parity-group/{}"

logger = Log()
gCopyGroupList = None


class VSPExternalVolumeDirectGateway:

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
    def get_external_path_group_by_serial(self, externalSerialNumber):
        start_time = time.time()
        response = self.connection_manager.get(GET_EXT_PATHS)
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:get_external_path_groups:time={:.2f} size = {}",
            end_time - start_time,
            len(response.get("data")),
        )
        if response is None:
            return

        item = next(
            (
                p
                for p in response.get("data", [])
                if p.get("externalSerialNumber") == externalSerialNumber
            ),
            None,
        )
        logger.writeDebug(f"GW:20250303 item =  {item}")
        if not item:
            return

        epglist = ExternalPathGroupInfoList(
            dicts_to_dataclass_list(item, ExternalPathGroupInfo)
        )

        for epg in epglist.data:
            epg.externalPaths = ExternalPathInfoList(
                dicts_to_dataclass_list(epg.externalPaths, ExternalPathInfo)
            )

        return epglist

    @log_entry_exit
    def get_one_external_path_group(self, externa_path_group_id, is_salamander=False):
        start_time = time.time()
        if is_salamander:
            response = self.connection_manager.get(
                SALAMENDER_GET_EXTERNAL_PATH_GROUPS_ONE.format(externa_path_group_id)
            )
        else:
            response = self.connection_manager.get(
                GET_EXTERNAL_PATH_GROUPS_ONE.format(externa_path_group_id)
            )
        end_time = time.time()
        logger.writeDebug(f"response={response}")
        logger.writeDebug(
            "PF_REST:get_one_external_path_group:time={:.2f}",
            end_time - start_time,
        )
        if response is None:
            return

        epg = None
        if is_salamander:
            # Salamander returns a different structure
            epg = SalamanderExternalPathGroupInfo(**response)
            epg.externalPaths = SalamanderExternalPathInfoList(
                dicts_to_dataclass_list(epg.externalPaths, SalamanderExternalPathInfo)
            )
            return epg
        else:
            epg = ExternalPathGroupInfo(**response)
            epg.externalPaths = ExternalPathInfoList(
                dicts_to_dataclass_list(epg.externalPaths, ExternalPathInfo)
            )
        return epg

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
    def get_external_volumes(self):
        start_time = time.time()
        url = GET_EXT_VOLUMES_LOCAL
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

        return ExtVolumeLocalInfoList(
            dicts_to_dataclass_list(response["data"], ExtVolumeLocalInfo)
        )

    @log_entry_exit
    def get_external_volumes_with_extpath(self, portId, externalWwn):
        start_time = time.time()
        url = GET_EXT_VOLUMES.format(portId, externalWwn)
        response = self.connection_manager.get(url)
        logger.writeDebug(f"GW:response={response}")
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:get_external_volumes_with_extpath:time={:.2f} size = {}",
            end_time - start_time,
            len(response.get("data")),
        )
        if response is None:
            return

        return ExtVolumeInfoList(
            dicts_to_dataclass_list(response["data"], ExtVolumeInfo)
        )

    @log_entry_exit
    def get_external_volume_by_id(self, portId, externalWwn, id):
        url = GET_EXT_VOLUMES.format(portId, externalWwn)
        resp_dict = self.connection_manager.get(url)
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
        data = ExtVolumeInfo(**item)
        return data

    @log_entry_exit
    def get_all_external_volumes(self, portId, externalWwn):
        start_time = time.time()
        url = GET_EXT_VOLUMES.format(portId, externalWwn)
        response = self.connection_manager.get(url)
        logger.writeDebug(f"GW:get_all_external_volumes:response={response}")
        end_time = time.time()
        logger.writeDebug(
            "PF_REST:get_all_external_volumes:time={:.2f} get_all_external_volumes.size = {}",
            end_time - start_time,
            len(response.get("data")),
        )
        if response is None:
            return

        rsp = ExtVolumeInfoList(
            dicts_to_dataclass_list(response["data"], ExtVolumeInfo)
        )

        return rsp

    @log_entry_exit
    def get_one_external_parity_group(self, external_parity_group):
        start_time = time.time()
        response = self.connection_manager.get(
            GET_EXT_PARITY_GROUP.format(external_parity_group)
        )
        end_time = time.time()
        logger.writeDebug(f"response={response}")
        logger.writeDebug(
            "PF_REST:get_one_external_parity_group:time={:.2f}",
            end_time - start_time,
        )
        if response is None:
            return
        return response
        # epg = ExternalPathGroupInfo(**response)
        # epg.externalPaths = ExternalPathInfoList(
        #     dicts_to_dataclass_list(epg.externalPaths, ExternalPathInfo)
        # )
        # return epg
