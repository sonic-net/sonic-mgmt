try:
    from .gateway_manager import VSPConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.vsp_constants import Endpoints, RemoteConnectionReq
    from ..model.vsp_remote_connection_models import (
        VSPRemoteConnections,
        VSPRemoteConnection,
        RemoteConnectionSpec,
    )

except ImportError:
    from .gateway_manager import VSPConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from common.vsp_constants import Endpoints, RemoteConnectionReq
    from model.vsp_remote_connection_models import (
        VSPRemoteConnections,
        VSPRemoteConnection,
        RemoteConnectionSpec,
    )


logger = Log()


class VSPRemoteConnectionDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.connection_info = connection_info
        self.remote_connection_manager = None

    @log_entry_exit
    def get_all_remote_connections(self, basic=True):
        end_point = Endpoints.GET_ALL_REMOTE_CONNECTIONS
        remote_connections = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_all_remote_connections:remote connections={}", remote_connections
        )
        remote_connections = VSPRemoteConnections().dump_to_object(remote_connections)
        if not basic:
            for remote_connection in remote_connections.data:
                remote_connection.remotePaths = self.get_remote_connection_by_id(
                    remote_connection.remotepathGroupId
                ).remotePaths

        return remote_connections

    @log_entry_exit
    def get_remote_connection_by_id(self, object_id):
        end_point = Endpoints.REMOTE_CONNECTION_SINGLE.format(object_id)
        try:
            remote_connection = self.connection_manager.get(end_point)
            logger.writeDebug(
                "GW:get_remote_connection_by_id:remote connection={}", remote_connection
            )
            remote_connection = VSPRemoteConnection(**remote_connection)
            return remote_connection
        except Exception as e:
            logger.writeError(
                "GW:get_remote_connection_by_id:Error getting remote connection={}", e
            )
            return None

    @log_entry_exit
    def create_remote_connection(self, rc_spec: RemoteConnectionSpec):
        end_point = Endpoints.POST_REMOTE_CONNECTIONS
        first_remote_path = rc_spec.remote_paths[0]
        payload = {
            RemoteConnectionReq.localPortId: first_remote_path.local_port,
            RemoteConnectionReq.remotePortId: first_remote_path.remote_port,
            RemoteConnectionReq.remoteSerialNumber: rc_spec.remote_storage_serial_number,
            RemoteConnectionReq.remoteStorageTypeId: rc_spec.remote_storage_type_id,
            RemoteConnectionReq.pathGroupId: rc_spec.path_group_id,
        }

        response = self.connection_manager.post(end_point, payload)
        logger.writeDebug("GW:create_remote_connection:response={}", response)
        return response

    @log_entry_exit
    def change_remote_connection_settings(self, rc_spec: RemoteConnectionSpec):
        end_point = Endpoints.REMOTE_CONNECTION_SINGLE.format(rc_spec.object_id)
        payload = {}
        if rc_spec.remote_io_timeout_in_sec:
            payload[RemoteConnectionReq.timeoutValueForRemoteIOInSeconds] = (
                rc_spec.remote_io_timeout_in_sec
            )
        if rc_spec.round_trip_in_msec:
            payload[RemoteConnectionReq.roundTripTimeInMilliSeconds] = (
                rc_spec.round_trip_in_msec
            )
        if rc_spec.min_remote_paths:
            payload[RemoteConnectionReq.minNumOfPaths] = rc_spec.min_remote_paths
        if not payload:
            return
        response = self.connection_manager.patch(end_point, payload)
        logger.writeDebug("GW:change_remote_connection_settings:response={}", response)
        return response

    @log_entry_exit
    def add_remote_path_to_remote_connection(self, rc_spec: RemoteConnectionSpec):

        for remote_path in rc_spec.remote_paths:
            response = self.add_remote_path_to_remote_connection_single(
                rc_spec.path_group_id, remote_path.local_port, remote_path.remote_port
            )

        logger.writeDebug(
            "GW:add_remoe_path_to_remote_connection:response={}", response
        )
        return response

    @log_entry_exit
    def add_remote_path_to_remote_connection_single(
        self, object_id, local_port, remote_port
    ):
        end_point = Endpoints.ADD_REMOTE_PATH.format(object_id)

        payload = {
            RemoteConnectionReq.parameters: {
                RemoteConnectionReq.localPortId: local_port,
                RemoteConnectionReq.remotePortId: remote_port,
            }
        }
        response = self.connection_manager.post(end_point, payload)
        logger.writeDebug(
            "GW:add_remote_path_to_remote_connection_single:response={}", response
        )
        return response

    @log_entry_exit
    def remove_remote_path_from_remote_connection(self, rc_spec: RemoteConnectionSpec):

        for remote_path in rc_spec.remote_paths:
            response = self.remove_remote_path_from_remote_connection_single(
                rc_spec.path_group_id, remote_path.local_port, remote_path.remote_port
            )

        logger.writeDebug(
            "GW:remove_remote_path_from_remote_connection:response={}", response
        )
        return response

    @log_entry_exit
    def remove_remote_path_from_remote_connection_single(
        self, object_id, local_port, remote_port
    ):
        end_point = Endpoints.DELETE_REMOTE_PATH.format(object_id)
        payload = {
            RemoteConnectionReq.parameters: {
                RemoteConnectionReq.localPortId: local_port,
                RemoteConnectionReq.remotePortId: remote_port,
            }
        }
        response = self.connection_manager.post(end_point, payload)
        logger.writeDebug(
            "GW:remove_remote_path_from_remote_connection:response={}", response
        )
        return response

    @log_entry_exit
    def delete_remote_connection(self, object_id):
        end_point = Endpoints.REMOTE_CONNECTION_SINGLE.format(object_id)
        response = self.connection_manager.delete(end_point)
        logger.writeDebug("GW:delete_remote_connection:response={}", response)
        return response
