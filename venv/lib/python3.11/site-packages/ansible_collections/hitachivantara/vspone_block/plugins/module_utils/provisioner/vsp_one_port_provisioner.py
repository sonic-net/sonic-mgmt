from ..common.ansible_common import log_entry_exit
from ..common.hv_log import (
    Log,
)
from ..gateway.vsp_one_port_gateway import VspPortSimpleApiGateway
from ..message.vsp_lun_msgs import VSPVolumeMSG
from ..message.vsp_one_port_msgs import VspOnePortMSG
from ..model.vsp_one_port_models import (
    VspOnePortSpec,
    VspOnePortConst,
    VspOnePortResponse,
)
from ..common.ansible_common import is_valid_ip

logger = Log()


class VSPPortSimpleApiProvisioner:
    """
    VSPPortSimpleApiProvisioner
    """

    def __init__(self, connection_info):
        self.gateway = VspPortSimpleApiGateway(connection_info)
        self.connection_info = connection_info

        if not self.gateway.is_pegasus:
            raise Exception(VSPVolumeMSG.ONLY_SUPPORTED_ON_PEGASUS.value)

    @log_entry_exit
    def get_ports_information(self):
        """
        Get port information
        :return: Port information
        """
        return self.gateway.get_ports_information()

    @log_entry_exit
    def get_port_by_id(self, port_id) -> VspOnePortResponse:
        """
        Get port information by ID
        :param port_id: Port ID
        :return: Port information
        """
        return self.gateway.get_port_by_id(port_id)

    @log_entry_exit
    def change_port_settings(self, port_id, spec: VspOnePortSpec):
        """
        Change port settings
        :param port_id: Port ID
        :param spec: VspOnePortSpec
        :return: Updated port information
        """
        port = self.get_port_by_id(port_id)
        if not port:
            raise Exception(VspOnePortMSG.PORT_NOT_FOUND.value.format(port_id=port_id))
        # Validate protocol

        self.__validate_input_data(spec, port)
        try:
            self.gateway.change_vsp_one_port_settings(port_id, spec)
            self.connection_info.changed = True
            spec.comment = VspOnePortMSG.OPERATION_SUCCESSFUL.value.format(
                port_id=port_id
            )
        except Exception as e:
            logger.writeError(
                VspOnePortMSG.ERROR_CHANGING_PORT_SETTINGS.value.format(
                    port_id=port_id, error=e
                )
            )
            spec.comment = (
                VspOnePortMSG.ERROR_CHANGING_PORT_SETTINGS_GENERIC.value.format(error=e)
            )

        return self.get_port_by_id(port_id).camel_to_snake_dict()

    def __validate_input_data(self, spec: VspOnePortSpec, port: VspOnePortResponse):

        if spec.fc_settings and spec.iscsi_settings and spec.nvme_tcp_settings:
            raise Exception(VspOnePortMSG.MULTIPLE_SETTINGS_PROVIDED.value)

        if port.protocol == VspOnePortConst.FC:
            if spec.iscsi_settings or spec.nvme_tcp_settings:
                raise Exception(VspOnePortMSG.FC_SETTINGS_REQUIRED_FOR_FC.value)
        elif port.protocol == VspOnePortConst.ISCSI:
            if spec.fc_settings or spec.nvme_tcp_settings:
                raise Exception(VspOnePortMSG.ISCSI_SETTINGS_REQUIRED_FOR_ISCSI.value)
        elif port.protocol == VspOnePortConst.NVME_TCP:
            if spec.iscsi_settings or spec.fc_settings:
                raise Exception(
                    VspOnePortMSG.NVME_TCP_SETTINGS_REQUIRED_FOR_NVME_TCP.value
                )

        if spec.iscsi_settings:
            if (
                spec.iscsi_settings.ipv4_configuration
                and spec.iscsi_settings.ipv4_configuration.address
                and not is_valid_ip(spec.iscsi_settings.ipv4_configuration.address)
            ):
                raise Exception(
                    VspOnePortMSG.INVALID_IP_ADDRESS.value.format(
                        address=spec.iscsi_settings.ipv4_configuration.address
                    )
                )
            if (
                spec.iscsi_settings.ipv4_configuration
                and spec.iscsi_settings.ipv4_configuration.subnet_mask
                and not is_valid_ip(spec.iscsi_settings.ipv4_configuration.subnet_mask)
            ):
                raise Exception(
                    VspOnePortMSG.INVALID_SUBNET_MASK.value.format(
                        subnet_mask=spec.iscsi_settings.ipv4_configuration.subnet_mask
                    )
                )
            if (
                spec.iscsi_settings.ipv4_configuration
                and spec.iscsi_settings.ipv4_configuration.default_gateway
                and not is_valid_ip(
                    spec.iscsi_settings.ipv4_configuration.default_gateway
                )
            ):
                raise Exception(
                    VspOnePortMSG.INVALID_GATEWAY.value.format(
                        gateway=spec.iscsi_settings.ipv4_configuration.default_gateway
                    )
                )
        if spec.nvme_tcp_settings:
            if (
                spec.nvme_tcp_settings.ipv4_configuration
                and spec.nvme_tcp_settings.ipv4_configuration.address
                and not is_valid_ip(spec.nvme_tcp_settings.ipv4_configuration.address)
            ):
                raise Exception(
                    VspOnePortMSG.INVALID_IP_ADDRESS.value.format(
                        address=spec.nvme_tcp_settings.ipv4_configuration.address
                    )
                )
            if (
                spec.nvme_tcp_settings.ipv4_configuration
                and spec.nvme_tcp_settings.ipv4_configuration.subnet_mask
                and not is_valid_ip(
                    spec.nvme_tcp_settings.ipv4_configuration.subnet_mask
                )
            ):
                raise Exception(
                    VspOnePortMSG.INVALID_SUBNET_MASK.value.format(
                        subnet_mask=spec.nvme_tcp_settings.ipv4_configuration.subnet_mask
                    )
                )
            if (
                spec.nvme_tcp_settings.ipv4_configuration
                and spec.nvme_tcp_settings.ipv4_configuration.default_gateway
                and not is_valid_ip(
                    spec.nvme_tcp_settings.ipv4_configuration.default_gateway
                )
            ):
                raise Exception(
                    VspOnePortMSG.INVALID_GATEWAY.value.format(
                        gateway=spec.nvme_tcp_settings.ipv4_configuration.default_gateway
                    )
                )

    @log_entry_exit
    def vsp_one_port_facts(self, spec):
        """
        Get port facts
        :param port_id: Port ID
        :return: Port facts
        """
        if spec and spec.port_id is not None:
            port_data = self.gateway.get_port_by_id(spec.port_id)
            if port_data:
                return port_data.camel_to_snake_dict()
            else:
                return {}
        return self.gateway.get_ports_information(spec).data_to_snake_case_list()
