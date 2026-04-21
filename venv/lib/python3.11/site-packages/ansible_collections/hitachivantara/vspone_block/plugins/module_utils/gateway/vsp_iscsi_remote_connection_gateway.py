try:
    from .gateway_manager import VSPConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.vsp_constants import Endpoints, RemoteIscsiConnectionReq
    from ..model.vsp_remote_connection_models import (
        RemoteIscsiConnection,
        RemoteIscsiConnections,
        RemoteIscsiConnectionSpec,
    )

except ImportError:
    from .gateway_manager import VSPConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from common.vsp_constants import Endpoints, RemoteIscsiConnectionReq
    from model.vsp_remote_connection_models import (
        RemoteIscsiConnection,
        RemoteIscsiConnections,
        RemoteIscsiConnectionSpec,
    )


logger = Log()


class VSPIscsiRemoteConnectionDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.connection_info = connection_info

    @log_entry_exit
    def get_all_iscsi_remote_connections(self):
        end_point = Endpoints.GET_ALL_REMOTE_ISCSI_CONNECTIONS
        remote_connections = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_all_iscsi_remote_connections:remote connections={}",
            remote_connections,
        )
        remote_connections = RemoteIscsiConnections().dump_to_object(remote_connections)
        return remote_connections

    @log_entry_exit
    def get_iscsi_remote_connection_by_id(self, object_id):
        end_point = Endpoints.REMOTE_ISCSI_CONNECTION_SINGLE.format(object_id)
        try:
            remote_connection = self.connection_manager.get(end_point)
            logger.writeDebug(
                "GW:get_iscsi_remote_connection_by_id:remote connection={}",
                remote_connection,
            )
            remote_connection = RemoteIscsiConnection(**remote_connection)
            return remote_connection
        except Exception as e:
            logger.writeError(
                "GW:get_iscsi_remote_connection_by_id:Error getting remote connection={}",
                e,
            )
            return None

    @log_entry_exit
    def create_iscsi_remote_connection(self, rc_spec: RemoteIscsiConnectionSpec):
        end_point = Endpoints.POST_REMOTE_ISCSI_CONNECTIONS
        payload = {
            RemoteIscsiConnectionReq.localPortId: rc_spec.local_port,
            RemoteIscsiConnectionReq.remotePortId: rc_spec.remote_port,
            RemoteIscsiConnectionReq.remoteSerialNumber: rc_spec.remote_storage_serial_number,
            RemoteIscsiConnectionReq.remoteStorageTypeId: rc_spec.remote_storage_type_id,
            RemoteIscsiConnectionReq.remoteIpAddress: rc_spec.remote_storage_ip_address,
        }
        if rc_spec.remote_tcp_port:
            payload[RemoteIscsiConnectionReq.remoteTcpPort] = rc_spec.remote_tcp_port

        response = self.connection_manager.post(end_point, payload)
        logger.writeDebug("GW:create_remote_connection:response={}", response)
        return response

    @log_entry_exit
    def delete_iscsi_remote_connection(self, object_id):
        end_point = Endpoints.REMOTE_ISCSI_CONNECTION_SINGLE.format(object_id)
        response = self.connection_manager.delete(end_point)
        logger.writeDebug("GW:delete_remote_connection:response={}", response)
        return response
