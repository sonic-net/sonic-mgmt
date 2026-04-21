try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..model.sdsb_vps_models import SDSBVpsListInfo
    from ..common.ansible_common import log_entry_exit

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from model.sdsb_vps_models import SDSBVpsListInfo
    from common.ansible_common import log_entry_exit


class SDSBVpsProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_VPS
        )

    @log_entry_exit
    def get_vps(self, spec=None):
        vps = self.gateway.get_vps()
        if spec is None:
            return vps
        else:
            ret_vps = self.apply_filters(vps.data, spec)
            return SDSBVpsListInfo(
                data=ret_vps, summaryInformation=vps.summaryInformation
            )

    @log_entry_exit
    def apply_filters(self, vps, spec):
        result = vps
        if spec.id:
            result = self.apply_filter_id(result, spec.id)
        if spec.name:
            result = self.apply_filter_name(result, spec.name)

        return result

    @log_entry_exit
    def apply_filter_id(self, vps, id):
        ret_val = []

        for v in vps:
            if v.id == id:
                ret_val.append(v)
        return ret_val

    @log_entry_exit
    def apply_filter_name(self, vps, name):
        ret_val = []

        for v in vps:
            if v.name == name:
                ret_val.append(v)
        return ret_val

    @log_entry_exit
    def get_vps_by_id(self, id):
        return self.gateway.get_vps_by_id(id)

    @log_entry_exit
    def get_vps_by_name(self, name):
        all_vps = self.get_vps()

        for x in all_vps.data:
            if name == x.name:
                return x

        return None

    @log_entry_exit
    def delete_vps_by_id(self, id):
        return self.gateway.delete_vps_by_id(id)

    @log_entry_exit
    def create_vps(self, spec):
        return self.gateway.create_vps(spec)

    @log_entry_exit
    def update_vps(self, id, spec):
        return self.gateway.update_vps(id, spec)
