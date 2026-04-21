from .gateway_manager import VSPConnectionManager
from ..common.vsp_constants import (
    Endpoints,
)
from ..model.vsp_one_port_models import (
    VspOnePortResponse,
    VspOnePortList,
    VspOnePortSpec,
)
from ..common.hv_log import Log

from ..common.ansible_common import log_entry_exit
from .vsp_storage_system_gateway import VSPStorageSystemDirectGateway

logger = Log()


class VspPortSimpleApiGateway:
    """
    VspPortSimpleApiGateway
    """

    def __init__(self, connection_info):
        self.rest_api = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.storage_gw = VSPStorageSystemDirectGateway(connection_info)
        self.end_points = Endpoints
        self.is_pegasus = self.storage_gw.is_pegasus()

    @log_entry_exit
    def get_ports_information(self, spec):
        """
        Get port information
        :param port_id: Port ID
        :return: Port information
        """
        endpoint = self.end_points.VSP_ONE_GET_PORTS
        if spec and spec.protocol:
            endpoint += f"?protocol={spec.protocol}"
        response = self.rest_api.pegasus_get(endpoint)
        return VspOnePortList().dump_to_object(response)

    @log_entry_exit
    def get_port_by_id(self, port_id):
        """
        Get port information by ID
        :param port_id: Port ID
        :return: Port information
        """
        endpoint = self.end_points.VSP_ONE_SINGLE_PORT.format(port_id)
        try:
            response = self.rest_api.pegasus_get(endpoint)
            return VspOnePortResponse(**response)
        except Exception as e:
            logger.writeError(f"Error getting port by ID {port_id}: {e}")
            return None

    @log_entry_exit
    def change_vsp_one_port_settings(self, port_id, spec: VspOnePortSpec):
        """
        Change VSP one port settings
        :param port_id: Port ID
        :param spec: VspOnePortSpec object with new settings
        :return: Updated port information
        """
        endpoint = self.end_points.VSP_ONE_SINGLE_PORT.format(port_id)
        payload = spec.create_port_setting_payload()
        if payload is None:
            return None
        return self.rest_api.pegasus_patch(endpoint, payload)
