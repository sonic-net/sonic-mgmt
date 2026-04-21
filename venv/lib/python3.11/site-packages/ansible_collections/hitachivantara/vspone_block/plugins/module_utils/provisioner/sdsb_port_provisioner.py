try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..model.sdsb_port_models import SDSBComputePortsInfo
    from ..common.ansible_common import log_entry_exit

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from model.sdsb_port_models import SDSBComputePortsInfo
    from common.ansible_common import log_entry_exit


class SDSBPortProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_PORT
        )

    @log_entry_exit
    def get_port_by_id(self, id):
        return self.gateway.get_port_by_id(id)

    @log_entry_exit
    def get_compute_ports(self, spec=None):
        ports = self.gateway.get_compute_ports()
        if spec is None:
            return ports
        else:
            ret_ports = self.apply_filters(ports.data, spec)
            return SDSBComputePortsInfo(data=ret_ports)

    @log_entry_exit
    def apply_filters(self, ports, spec):
        result = ports
        if spec.names:
            result = self.apply_filter_names(result, spec.names)
        if spec.nicknames:
            result = self.apply_filter_nicknames(result, spec.nicknames)

        return result

    @log_entry_exit
    def apply_filter_names(self, ports, filter):
        ret_val = []
        for n in filter:
            for x in ports:
                if x.name == n:
                    ret_val.append(x)

        return ret_val

    @log_entry_exit
    def apply_filter_nicknames(self, ports, filter):
        ret_val = []
        for n in filter:
            for x in ports:
                if x.nickname == n:
                    ret_val.append(x)

        return ret_val

    @log_entry_exit
    def change_compute_port_protocol(self, protocol):
        return self.gateway.change_compute_port_protocol(protocol)

    @log_entry_exit
    def edit_compute_port_settings(self, id, nick_name, name):
        return self.gateway.edit_compute_port_settings(id, nick_name, name)
