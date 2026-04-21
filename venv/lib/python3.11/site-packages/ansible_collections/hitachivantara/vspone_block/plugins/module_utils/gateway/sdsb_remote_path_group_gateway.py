try:
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..model.sdsb_remote_path_group_models import (
        RemotePathGroupSummaryList,
        RemotePathGroupResponse,
    )

except ImportError:
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from model.sdsb_remote_path_group_models import (
        RemotePathGroupSummaryList,
        RemotePathGroupResponse,
    )

GET_REMOTE_PATH_GROUPS = "v1/objects/remotepath-groups"
GET_REMOTE_PATH_GROUP_BY_ID = "v1/objects/remotepath-groups/{}"
CREATE_REMOTE_PATH_GROUP = "v1/objects/remotepath-groups"
DELETE_REMOTE_PATH_GROUP = "v1/objects/remotepath-groups/{}"
UPDATE_REMOTE_PATH_GROUP = "v1/objects/remotepath-groups/{}"
ADD_REMOTE_PATH = "v1/objects/remotepath-groups/{}/actions/add-remotepath/invoke"
REMOVE_REMOTE_PATH = "v1/objects/remotepath-groups/{}/actions/remove-remotepath/invoke"

logger = Log()


class SDSBRemotePathGroupGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_query_parameters(
        self,
        local_storage_controller_id=None,
        remote_serial=None,
        remote_storage_system_type=None,
        path_group_id=None,
    ):
        params = {}
        if local_storage_controller_id is not None:
            params["localStorageControllerId"] = local_storage_controller_id
        if remote_serial is not None:
            params["remoteSerialNumber"] = remote_serial
        if remote_storage_system_type is not None:
            params["remoteStorageTypeId"] = remote_storage_system_type
        if path_group_id is not None:
            params["pathGroupId"] = path_group_id
        query = ""
        if params:
            query_parts = ["{}={}".format(k, v) for k, v in params.items()]
            query = "?" + "&".join(query_parts)

        return query

    @log_entry_exit
    def get_remote_path_groups(
        self,
        local_storage_controller_id=None,
        remote_serial=None,
        remote_storage_system_type=None,
        path_group_id=None,
    ):
        query = self.get_query_parameters(
            local_storage_controller_id,
            remote_serial,
            remote_storage_system_type,
            path_group_id,
        )
        end_point = GET_REMOTE_PATH_GROUPS + query
        logger.writeDebug("GW:get_remote_path_groups:end_point={}", end_point)

        response = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_remote_path_groups:response={}", response)

        return RemotePathGroupSummaryList().dump_to_object(response)

    @log_entry_exit
    def get_remote_path_group_by_id(self, id):
        end_point = GET_REMOTE_PATH_GROUP_BY_ID.format(id)
        try:
            response = self.connection_manager.get(end_point)
            return RemotePathGroupResponse(**response)
        except Exception as e:
            logger.writeError(f"Error getting remote path group by ID {id}: {e}")
            return None

    @log_entry_exit
    def create_remote_path_group(
        self,
        remote_serial,
        remote_storage_system_type,
        local_port,
        remote_port,
        path_group_id=None,
        timeout_value=None,
    ):
        payload = {
            "localPortNumber": local_port,
            "remoteSerialNumber": remote_serial,
            "remoteStorageTypeId": remote_storage_system_type,
            "remotePortNumber": remote_port,
        }
        if path_group_id:
            payload["pathGroupId"] = path_group_id
        if timeout_value:
            payload["timeoutValueForRemoteIOInSeconds"] = timeout_value

        end_point = CREATE_REMOTE_PATH_GROUP
        response = self.connection_manager.post(end_point, data=payload)
        logger.writeDebug("GW:create_remote_path_group:response={}", response)
        response = self.get_remote_path_group_by_id(response)
        logger.writeDebug("GW:create_remote_path_group:response2={}", response)
        return response

    @log_entry_exit
    def delete_remote_path_group(self, id):
        end_point = DELETE_REMOTE_PATH_GROUP.format(id)
        response = self.connection_manager.delete(end_point)
        return response

    @log_entry_exit
    def update_remote_path_group(self, id, timeout_value):
        end_point = UPDATE_REMOTE_PATH_GROUP.format(id)
        payload = {"timeoutValueForRemoteIOInSeconds": timeout_value}
        response = self.connection_manager.patch(end_point, data=payload)
        logger.writeDebug("GW:update_remote_path_group:response={}", response)
        response = self.get_remote_path_group_by_id(response)
        logger.writeDebug("GW:update_remote_path_group:response2={}", response)
        return response

    @log_entry_exit
    def add_remote_path_to_remote_path_group(self, id, local_port, remote_port):
        end_point = ADD_REMOTE_PATH.format(id)
        payload = {
            "localPortNumber": local_port,
            "remotePortNumber": remote_port,
        }
        response = self.connection_manager.post(end_point, data=payload)
        logger.writeDebug(
            "GW:add_remote_path_to_remote_path_group:response={}", response
        )
        response = self.get_remote_path_group_by_id(response)
        logger.writeDebug(
            "GW:add_remote_path_to_remote_path_group:response2={}", response
        )
        return response

    @log_entry_exit
    def remove_remote_path_from_remote_path_group(self, id, local_port, remote_port):
        end_point = REMOVE_REMOTE_PATH.format(id)
        payload = {
            "localPortNumber": local_port,
            "remotePortNumber": remote_port,
        }
        response = self.connection_manager.post(end_point, data=payload)
        logger.writeDebug(
            "GW:remove_remote_path_from_remote_path_group:response={}", response
        )
        response = self.get_remote_path_group_by_id(response)
        logger.writeDebug(
            "GW:remove_remote_path_from_remote_path_group:response2={}", response
        )
        return response
