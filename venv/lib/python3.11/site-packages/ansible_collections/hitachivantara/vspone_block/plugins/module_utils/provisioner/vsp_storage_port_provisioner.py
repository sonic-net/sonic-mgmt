try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_log import Log
    from ..model.vsp_storage_port_models import (
        PortInfo,
        PortsInfo,
    )
    from ..message.vsp_storage_port_msgs import StoragePortFailedMsg
    from .vsp_uvm_provisioner import VSPUvmProvisioner

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.ansible_common import log_entry_exit
    from common.hv_log import Log
    from model.vsp_storage_port_models import PortInfo, PortsInfo
    from message.vsp_storage_port_msgs import StoragePortFailedMsg
    from .vsp_uvm_provisioner import VSPUvmProvisioner

logger = Log()


class VSPStoragePortProvisioner:

    def __init__(self, connection_info):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.STORAGE_PORT
        )
        self.connection_info = connection_info
        self.portIdToPortInfoMap = None
        self.all_ports = None

    @log_entry_exit
    def get_single_storage_port(self, port_id: str) -> PortInfo:
        return self.gateway.get_single_storage_port(port_id)

    @log_entry_exit
    def filter_port_using_port_ids(self, port_ids: list) -> PortsInfo:
        # ports = self.get_all_storage_ports()
        # ports.data = [port for port in ports.data if port.portId in port_ids]
        # return ports

        result_ports = []
        for port_id in port_ids:
            port = self.get_single_storage_port(port_id)
            result_ports.append(port)

        return PortsInfo(data=result_ports)

    @log_entry_exit
    def get_all_storage_ports(self) -> PortsInfo:
        if self.portIdToPortInfoMap is None:
            self.portIdToPortInfoMap = {}
            ports = self.gateway.get_all_storage_ports()
            for port in ports.data:
                self.portIdToPortInfoMap[port.portId] = port
            return ports
        else:
            return PortsInfo(data=list(self.portIdToPortInfoMap.values()))

    @log_entry_exit
    def get_port_type(self, port_id):
        if self.portIdToPortInfoMap is None:
            self.portIdToPortInfoMap = {}
            self.all_ports = self.gateway.get_all_storage_ports()
            for port in self.all_ports.data:
                self.portIdToPortInfoMap[port.portId] = port
        port = self.portIdToPortInfoMap[port_id]
        return port.portType

    @log_entry_exit
    def is_change_needed(self, port_details, spec) -> bool:
        change_needed = False
        if spec.port_attribute is not None:
            if spec.port_attribute.upper() == "TAR":
                if len(port_details.portAttributes) != 1:
                    change_needed = True
            if spec.port_attribute.upper() == "ALL":
                if len(port_details.portAttributes) != 4:
                    change_needed = True
        if spec.port_mode is not None:
            if port_details.portMode.upper() != spec.port_mode.upper():
                change_needed = True
        if spec.port_speed is not None:
            if port_details.portSpeed.upper() != spec.port_speed.upper():
                change_needed = True
        if spec.fabric_mode is not None:
            if port_details.fabricMode != spec.fabric_mode:
                change_needed = True
        if spec.port_connection is not None:
            if port_details.portConnection.upper() != spec.port_connection.upper():
                change_needed = True
        if spec.enable_port_security is not None:
            if port_details.portSecuritySetting != spec.enable_port_security:
                change_needed = True
        return change_needed

    @log_entry_exit
    def sending_ping_command_to_host(self, port: str, host_ip: str):
        return self.gateway.sending_ping_command_to_host(port, host_ip)

    @log_entry_exit
    def change_port_settings(self, spec) -> PortInfo:
        port_details = self.get_single_storage_port(spec.port)
        if not self.is_change_needed(port_details, spec):
            return port_details
        try:
            self.gateway.change_port_settings(spec)
            self.connection_info.changed = True
            return self.get_single_storage_port(spec.port)
        except Exception as e:
            err_msg = StoragePortFailedMsg.CHANGE_SETTING_FAILED.value + str(e)
            logger.writeError(err_msg)
            raise ValueError(err_msg)

    @log_entry_exit
    def login_test(self, spec):
        uvm_provisioner = VSPUvmProvisioner(self.connection_info)
        return uvm_provisioner.login_test(spec)

    @log_entry_exit
    def register_external_iscsi_target(self, spec):
        uvm_provisioner = VSPUvmProvisioner(self.connection_info)
        return uvm_provisioner.register_external_iscsi_target(spec)

    @log_entry_exit
    def unregister_external_iscsi_target(self, spec):
        uvm_provisioner = VSPUvmProvisioner(self.connection_info)
        return uvm_provisioner.unregister_external_iscsi_target(spec)

    @log_entry_exit
    def disconnect_from_a_volume_on_external_storag(self, spec):
        uvm_provisioner = VSPUvmProvisioner(self.connection_info)
        return uvm_provisioner.disconnect_from_a_volume_on_external_storage(spec)
