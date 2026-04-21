try:
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.sdsb_utils import convert_keys_to_snake_case

except ImportError:
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from common.sdsb_utils import convert_keys_to_snake_case

GET_REMOTE_ISCSI_PORTS = "v1/objects/remote-iscsi-ports"
GET_REMOTE_ISCSI_PORT_BY_ID = "v1/objects/remote-iscsi-ports/{}"
REGISTER_REMOTE_ISCSI_PORT = "v1/objects/remote-iscsi-ports"
DELETE_REMOTE_ISCSI_PORT = "v1/objects/remote-iscsi-ports/{}"


logger = Log()


class SDSBRemoteIscsiPortGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_query_parameters(
        self,
        local_port=None,
        remote_serial=None,
        remote_storage_system_type=None,
        remote_port=None,
    ):
        params = {}
        if local_port is not None:
            params["localPortNumber"] = local_port
        if remote_serial is not None:
            params["remoteSerialNumber"] = remote_serial
        if remote_storage_system_type is not None:
            params["remoteStorageTypeId"] = remote_storage_system_type
        if remote_port is not None:
            params["remotePortNumber"] = remote_port
        query = ""
        if params:
            query_parts = ["{}={}".format(k, v) for k, v in params.items()]
            query = "?" + "&".join(query_parts)

        return query

    @log_entry_exit
    def get_remote_iscsi_ports(
        self,
        local_port=None,
        remote_serial=None,
        remote_storage_system_type=None,
        remote_port=None,
    ):
        query = self.get_query_parameters(
            local_port, remote_serial, remote_storage_system_type, remote_port
        )
        end_point = GET_REMOTE_ISCSI_PORTS + query
        logger.writeDebug("GW:get_remote_iscsi_ports:end_point={}", end_point)

        response = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_remote_iscsi_ports:response={}", response)

        converted = convert_keys_to_snake_case(response)
        logger.writeDebug("GW:get_remote_iscsi_ports:converted={}", converted)
        return converted

    @log_entry_exit
    def get_remote_iscsi_port_by_id(self, id):
        end_point = GET_REMOTE_ISCSI_PORT_BY_ID.format(id)
        response = self.connection_manager.get(end_point)
        converted = convert_keys_to_snake_case(response)
        return converted

    @log_entry_exit
    def register_remote_iscsi_port(
        self,
        local_port,
        remote_serial,
        remote_storage_system_type,
        remote_port,
        remote_ip_address,
        remote_tcp_port=None,
    ):
        payload = {
            "localPortNumber": local_port,
            "remoteSerialNumber": remote_serial,
            "remoteStorageTypeId": remote_storage_system_type,
            "remotePortNumber": remote_port,
            "remoteIpAddress": remote_ip_address,
        }
        if remote_tcp_port:
            payload["remoteTcpPort"] = remote_tcp_port

        end_point = REGISTER_REMOTE_ISCSI_PORT
        response = self.connection_manager.post(end_point, data=payload)
        logger.writeDebug("GW:register_remote_iscsi_port:response={}", response)
        converted = convert_keys_to_snake_case(response)
        logger.writeDebug("GW:register_remote_iscsi_port:converted={}", converted)
        return converted

    @log_entry_exit
    def delete_remote_iscsi_port(self, id):
        end_point = GET_REMOTE_ISCSI_PORT_BY_ID.format(id)
        response = self.connection_manager.delete(end_point)
        return response
