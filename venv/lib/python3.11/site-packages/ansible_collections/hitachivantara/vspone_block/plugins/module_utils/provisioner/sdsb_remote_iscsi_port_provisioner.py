try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_log import Log
except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.ansible_common import log_entry_exit
    from common.hv_log import Log

logger = Log()


class SDSBRemoteIscsiPortProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_REMOTE_ISCSI_PORT
        )

    @log_entry_exit
    def get_remote_iscsi_ports(self, spec=None):

        local_port = None
        remote_serial = None
        remote_storage_system_type = None
        remote_port = None

        if spec:
            if spec.local_port:
                local_port = spec.local_port
            if spec.remote_serial:
                remote_serial = spec.remote_serial
            if spec.remote_storage_system_type:
                remote_storage_system_type = spec.remote_storage_system_type
            if spec.remote_port:
                remote_port = spec.remote_port

        response = self.gateway.get_remote_iscsi_ports(
            local_port, remote_serial, remote_storage_system_type, remote_port
        )
        return response

    @log_entry_exit
    def get_remote_iscsi_port_by_id(self, id):
        try:
            return self.gateway.get_remote_iscsi_port_by_id(id)
        except Exception as e:
            logger.writeException(e)
            return None

    @log_entry_exit
    def register_remote_iscsi_port(self, spec=None):
        response = self.gateway.register_remote_iscsi_port(
            spec.local_port,
            spec.remote_serial,
            spec.remote_storage_system_type,
            spec.remote_port,
            spec.remote_ip_address,
            spec.remote_tcp_port,
        )
        return response

    @log_entry_exit
    def delete_remote_iscsi_port(self, id):
        response = self.gateway.delete_remote_iscsi_port(id)
        return response
