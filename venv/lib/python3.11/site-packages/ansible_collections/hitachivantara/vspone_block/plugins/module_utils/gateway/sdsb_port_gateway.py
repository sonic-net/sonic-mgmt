try:
    from ..common.sdsb_constants import SDSBlockEndpoints
    from ..common.ansible_common import dicts_to_dataclass_list
    from ..model.sdsb_port_models import SDSBComputePortInfo, SDSBComputePortsInfo
    from ..common.ansible_common import log_entry_exit
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log

except ImportError:
    from common.sdsb_constants import SDSBlockEndpoints
    from common.ansible_common import dicts_to_dataclass_list
    from model.sdsb_port_models import SDSBComputePortInfo, SDSBComputePortsInfo
    from common.ansible_common import log_entry_exit
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log

CHANGE_PORT_PROTOCOL = "v1/objects/ports/actions/switch-protocol/invoke"
EDIT_PORT_SETTINGS = "v1/objects/ports/{}"

logger = Log()


class SDSBPortDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_port_by_id(self, id):
        end_point = SDSBlockEndpoints.GET_PORT_BY_ID.format(id)
        data = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_port_by_id:data={}", data)
        return SDSBComputePortInfo(**data)

    @log_entry_exit
    def get_compute_ports(self):
        end_point = SDSBlockEndpoints.GET_PORTS
        compute_ports_data = self.connection_manager.get(end_point)
        logger.writeDebug(
            "GW:get_compute_ports:compute_ports_data={}", compute_ports_data
        )
        return SDSBComputePortsInfo(
            dicts_to_dataclass_list(compute_ports_data["data"], SDSBComputePortInfo)
        )

    @log_entry_exit
    def change_compute_port_protocol(self, protocol):
        protocol_map = {"iscsi": "iSCSI", "nvme_tcp": "NVMe_TCP"}
        payload = {"protocol": protocol_map.get(protocol)}
        end_point = CHANGE_PORT_PROTOCOL
        resp = self.connection_manager.post(end_point, data=payload)
        logger.writeDebug("GW:change_compute_port_protocol:resp={}", resp)
        return resp

    @log_entry_exit
    def edit_compute_port_settings(self, id, nick_name=None, name=None):
        end_point = EDIT_PORT_SETTINGS.format(id)
        payload = {}
        if nick_name:
            payload["nickname"] = nick_name
        if name:
            payload["name"] = name

        resp = self.connection_manager.patch(end_point, data=payload)
        logger.writeDebug("GW:edit_compute_port_settings:resp={}", resp)
        return resp
