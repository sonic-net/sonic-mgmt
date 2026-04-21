try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.ansible_common import log_entry_exit

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.ansible_common import log_entry_exit


class SDSBControlPortProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_CONTROL_PORT
        )

    @log_entry_exit
    def get_control_ports(self, spec=None):
        control_ports = self.gateway.get_control_ports(spec)
        controllers = None
        controllers = control_ports.get("data", [])
        if spec is not None and spec.storage_node_name:
            control_ports = [
                fd
                for fd in controllers
                if fd.get("storage_node_name") == spec.storage_node_name
            ]
        if spec is not None and spec.storage_node_id:
            control_ports = [
                fd
                for fd in controllers
                if fd.get("storage_node_id") == spec.storage_node_id
            ]
        return control_ports

    @log_entry_exit
    def get_internode_ports(self, spec=None):
        internode_ports = self.gateway.get_internode_ports(spec)
        controllers = None
        controllers = internode_ports.get("data", [])
        if spec is not None and spec.storage_node_name:
            internode_ports = [
                fd
                for fd in controllers
                if fd.get("storage_node_name") == spec.storage_node_name
            ]
        if spec is not None and spec.storage_node_id:
            internode_ports = [
                fd
                for fd in controllers
                if fd.get("storage_node_id") == spec.storage_node_id
            ]
        return internode_ports

    @log_entry_exit
    def get_storage_node_network_settings(self, spec=None):
        settings = self.gateway.get_storage_node_network_settings(spec)
        # controllers = None
        # controllers = settings.get("data", [])
        # if spec is not None and spec.storage_node_name:
        #     settings = [fd for fd in controllers if fd.get("storage_node_name") == spec.storage_node_name]
        # if spec is not None and spec.id:
        #     settings = [fd for fd in controllers if fd.get("id")  == spec.id]
        return settings
