try:

    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..model.sdsb_volume_models import SDSBVolumesInfo
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from model.sdsb_volume_models import SDSBVolumesInfo
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit

logger = Log()


class SDSBVolumeProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_VOLUME
        )

    @log_entry_exit
    def create_bulk_volume(
        self,
        pool_id,
        name,
        capacity,
        volume_count=1,
        start_number=1,
        num_of_digits=1,
        savings=None,
        qos_param=None,
        vps_id=None,
    ):

        if not savings:
            savings = "Disabled"

        return self.gateway.create_bulk_volume(
            pool_id,
            name,
            capacity,
            volume_count,
            start_number,
            num_of_digits,
            savings,
            qos_param,
            vps_id,
        )

    @log_entry_exit
    def create_volume(
        self, pool_id, name, capacity, savings=None, qos_param=None, vps_id=None
    ):
        return self.gateway.create_volume(
            pool_id, name, capacity, savings, qos_param, vps_id
        )

    @log_entry_exit
    def get_volume_by_id(self, volume_id):
        return self.gateway.get_volume_by_id(volume_id)

    @log_entry_exit
    def get_volume_by_name(self, volume_name):
        return self.gateway.get_volume_by_name(volume_name)

    @log_entry_exit
    def get_volumes(self, spec=None):
        volumes = self.gateway.get_volumes(spec)
        if spec is None:
            return volumes
        else:
            if spec.nicknames:
                ret_vol = self.apply_filters(volumes.data, spec)
                return SDSBVolumesInfo(ret_vol)
            else:
                return volumes

    @log_entry_exit
    def get_all_volume_names(self):
        volumes = self.get_volumes()
        logger.writeDebug("PV:get_all_volume_names:volumes={}", volumes)
        volume_names = []

        for v in volumes.data:
            volume_names.append(v.name)
        return volume_names

    @log_entry_exit
    def get_volume_name_by_id(self, id):
        logger.writeDebug("PV:get_volume_name_by_id:vol_id={}", id)
        vol = self.gateway.get_volume_by_id(id)
        logger.writeDebug("PV:get_volume_name_by_id:volume={}", vol)
        if vol:
            return vol.name

    @log_entry_exit
    def delete_volume(self, id, vps_id=None):
        logger.writeDebug("PV:delete_volume:vol_id={}", id)
        vol = self.gateway.delete_volume(id, vps_id)
        return vol

    @log_entry_exit
    def update_volume(self, volume_id, name, nickname, qos_param=None, vps_id=None):
        self.gateway.update_volume(volume_id, name, nickname, qos_param, vps_id)

    @log_entry_exit
    def expand_volume_capacity(self, volume_id, capacity, vps_id=None):
        self.gateway.expand_volume_capacity(volume_id, capacity, vps_id)

    @log_entry_exit
    def apply_filters(self, volumes, spec):
        result = volumes
        # if spec.capacity_saving:
        #     result = self.apply_filter_ss(result, spec.capacity_saving)
        # if spec.names:
        #     result = self.apply_filter_names(result, spec.names)
        if spec.nicknames:
            result = self.apply_filter_nicknames(result, spec.nicknames)
        # if spec.count:
        #     result = self.apply_filter_count(result, spec.count)

        return result

    @log_entry_exit
    def apply_filter_ss(self, volumes, filter):
        ret_val = []
        for x in volumes:
            if x.savingSetting == filter:
                ret_val.append(x)

        return ret_val

    @log_entry_exit
    def apply_filter_names(self, volumes, filter):
        ret_val = []
        for n in filter:
            for x in volumes:
                if x.name == n:
                    ret_val.append(x)

        return ret_val

    @log_entry_exit
    def apply_filter_nicknames(self, volumes, filter):
        ret_val = []
        for n in filter:
            for x in volumes:
                if x.nickname == n:
                    ret_val.append(x)

        return ret_val

    @log_entry_exit
    def apply_filter_count(self, volumes, filter):
        if len(volumes) <= filter:
            return volumes
        else:
            return volumes[:filter]
