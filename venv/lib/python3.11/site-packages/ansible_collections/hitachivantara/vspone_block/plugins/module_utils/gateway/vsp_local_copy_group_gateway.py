try:
    from .gateway_manager import VSPConnectionManager
    from ..model.vsp_local_copy_group_models import (
        LocalCopyGroupInfo,
        LocalCopyGroupInfoList,
        LocalSpecificCopyGroupInfo,
    )
    from ..common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from ..common.hv_log import Log
    from .vsp_storage_system_gateway import VSPStorageSystemDirectGateway
except ImportError:
    from .gateway_manager import VSPConnectionManager
    from model.vsp_local_copy_group_models import (
        LocalCopyGroupInfo,
        LocalCopyGroupInfoList,
        LocalSpecificCopyGroupInfo,
    )
    from common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from common.hv_log import Log
    from .vsp_storage_system_gateway import VSPStorageSystemDirectGateway

GET_LOCAL_COPY_GROUPS = "v1/objects/local-clone-copygroups"
GET_ONE_COPY_GROUP = "v1/objects/local-clone-copygroups/{}"
GET_STORAGES_DIRECT = "v1/objects/storages"
SPLIT_ONE_COPY_GROUP = "v1/objects/local-clone-copygroups/{}/actions/split/invoke"
MIGRATE_ONE_COPY_GROUP = "v1/objects/local-clone-copygroups/{}/actions/migrate/invoke"
RESYNC_ONE_COPY_GROUP = "v1/objects/local-clone-copygroups/{}/actions/resync/invoke"
RESTORE_ONE_COPY_GROUP = "v1/objects/local-clone-copygroups/{}/actions/restore/invoke"

logger = Log()


class VSPLocalCopyGroupDirectGateway:

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
    def set_storage_serial_number(self, serial: str):
        self.storage_serial_number = serial
        if self.storage_serial_number is None:
            self.storage_serial_number = self.get_storage_serial()

    @log_entry_exit
    def get_storage_serial(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def get_local_copy_groups(self, spec):
        response = self.connection_manager.get(GET_LOCAL_COPY_GROUPS)
        logger.writeDebug(f"GW:get_local_copy_groups:response={response}")
        copy_gr_list = LocalCopyGroupInfoList(
            dicts_to_dataclass_list(response["data"], LocalCopyGroupInfo)
        )
        return copy_gr_list

    @log_entry_exit
    def get_copy_group_by_name(self, spec):
        response = self.get_local_copy_groups(spec)
        for x in response.data:
            if x.copyGroupName == spec.name:
                return x
        return None

    @log_entry_exit
    def get_one_copygroup_info_by_name(self, spec, fact_spec=False):
        response = self.get_local_copy_groups(spec)
        for x in response.data:
            if x.copyGroupName == spec.name:
                one_specific_copy_gr = self.get_one_copygroup_with_copy_pairs_by_id(
                    x.localCloneCopygroupId
                )
                logger.writeDebug(
                    f"GW:get_one_copygroup_info_by_name:one_specific_copy_gr={one_specific_copy_gr}"
                )

                return one_specific_copy_gr

        return None

    @log_entry_exit
    def get_one_copygroup_with_copy_pairs_by_id(self, local_copygroup_id: str):
        end_point = GET_ONE_COPY_GROUP.format(local_copygroup_id)
        logger.writeDebug(
            f"GW:get_one_copygroup_with_copy_pairs_by_id:end_point={end_point}"
        )
        if local_copygroup_id is None:
            return None
        response = self.connection_manager.get(end_point)
        logger.writeDebug(f"GW:get_local_copy_groups:response={response}")

        return LocalSpecificCopyGroupInfo(**response)

    @log_entry_exit
    def split_local_copy_group(self, spec, localCloneCopygroupId):
        funcName = "VSPShadowImagePairDirectGateway: split_local_copy_group"
        if (
            spec.copy_group_name is not None
            and spec.primary_volume_device_group_name is not None
            and spec.secondary_volume_device_group_name is not None
        ):
            shadowImagePairid = (
                spec.copy_group_name
                + ","
                + spec.primary_volume_device_group_name
                + ","
                + spec.secondary_volume_device_group_name
            )
        else:
            shadowImagePairid = localCloneCopygroupId
        end_point = SPLIT_ONE_COPY_GROUP.format(shadowImagePairid)
        # headers = self.populateHeader()
        parameters = {}
        if spec.quick_mode is not None:
            parameters["quickMode"] = spec.quick_mode
        if spec.copy_pace is not None:
            parameters["copyPace"] = spec.copy_pace
        if spec.force_suspend is not None:
            parameters["forceSuspend"] = spec.force_suspend
        if spec.should_force_split is not None:
            parameters["forceSplit"] = spec.should_force_split

        payload = {"parameters": parameters}
        logger.writeDebug(f"GW:split_local_copy_group:payload={payload}")
        response = self.connection_manager.post(end_point, payload)
        logger.writeDebug("{} Response={}", funcName, response)
        return response

    @log_entry_exit
    def resync_local_copy_group(self, spec, localCloneCopygroupId):
        funcName = "VSPShadowImagePairDirectGateway: resync_local_copy_group"
        if (
            spec.copy_group_name is not None
            and spec.primary_volume_device_group_name is not None
            and spec.secondary_volume_device_group_name is not None
        ):
            shadowImagePairid = (
                spec.copy_group_name
                + ","
                + spec.primary_volume_device_group_name
                + ","
                + spec.secondary_volume_device_group_name
            )
        else:
            shadowImagePairid = localCloneCopygroupId
        end_point = RESYNC_ONE_COPY_GROUP.format(shadowImagePairid)
        # headers = self.populateHeader()
        parameters = {}
        if spec.quick_mode is not None:
            parameters["quickMode"] = spec.quick_mode
        if spec.copy_pace is not None:
            parameters["copyPace"] = spec.copy_pace

        payload = {"parameters": parameters}
        logger.writeDebug(f"GW:resync_local_copy_group:payload={payload}")
        response = self.connection_manager.post(end_point, payload)
        logger.writeDebug("{} Response={}", funcName, response)
        return response

    @log_entry_exit
    def restore_local_copy_group(self, spec, localCloneCopygroupId):
        funcName = "VSPShadowImagePairDirectGateway: restore_local_copy_group"
        if (
            spec.copy_group_name is not None
            and spec.primary_volume_device_group_name is not None
            and spec.secondary_volume_device_group_name is not None
        ):
            shadowImagePairid = (
                spec.copy_group_name
                + ","
                + spec.primary_volume_device_group_name
                + ","
                + spec.secondary_volume_device_group_name
            )
        else:
            shadowImagePairid = localCloneCopygroupId
        end_point = RESTORE_ONE_COPY_GROUP.format(shadowImagePairid)
        # headers = self.populateHeader()
        parameters = {}
        if spec.quick_mode is not None:
            parameters["quickMode"] = spec.quick_mode
        if spec.copy_pace is not None:
            parameters["copyPace"] = spec.copy_pace

        payload = {"parameters": parameters}
        logger.writeDebug(f"GW:restore_local_copy_group:payload={payload}")
        response = self.connection_manager.post(end_point, payload)
        logger.writeDebug("{} Response={}", funcName, response)
        return response

    @log_entry_exit
    def delete_local_copy_group(self, spec, localCloneCopygroupId):
        funcName = "VSPShadowImagePairDirectGateway: delete_local_copy_group"
        if (
            spec.copy_group_name is not None
            and spec.primary_volume_device_group_name is not None
            and spec.secondary_volume_device_group_name is not None
        ):
            shadowImagePairid = (
                spec.copy_group_name
                + ","
                + spec.primary_volume_device_group_name
                + ","
                + spec.secondary_volume_device_group_name
            )
        else:
            shadowImagePairid = localCloneCopygroupId
        end_point = GET_ONE_COPY_GROUP.format(shadowImagePairid)
        # headers = self.populateHeader()
        if spec.force_delete is not None:
            # parameters = {}
            # parameters["forceDelete"] = spec.force_delete
            payload = {"forceDelete": spec.force_delete}
            logger.writeDebug(f"GW:delete_local_copy_group:payload={payload}")
            response = self.connection_manager.delete(end_point, payload)
        else:
            response = self.connection_manager.delete(end_point)
        logger.writeDebug("{} Response={}", funcName, response)
        return response

    @log_entry_exit
    def migrate_local_copy_group(self, spec, localCloneCopygroupId):
        funcName = "VSPShadowImagePairDirectGateway: migrate_local_copy_group"
        if (
            spec.copy_group_name is not None
            and spec.primary_volume_device_group_name is not None
            and spec.secondary_volume_device_group_name is not None
        ):
            shadowImagePairid = (
                spec.copy_group_name
                + ","
                + spec.primary_volume_device_group_name
                + ","
                + spec.secondary_volume_device_group_name
            )
        else:
            shadowImagePairid = localCloneCopygroupId
        end_point = MIGRATE_ONE_COPY_GROUP.format(shadowImagePairid)
        # headers = self.populateHeader()
        response = self.connection_manager.post(end_point, data=None)
        logger.writeDebug("{} Response={}", funcName, response)
        return response
