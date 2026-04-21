try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..model.vsp_external_parity_group_models import CreateExternalParityGroupObject

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit


logger = Log()


class VSPExternalParityGroupProvisioner:

    def __init__(self, connection_info, serial=None):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_EXT_PARITY_GROUP
        )
        self.connection_info = connection_info
        self.serial = serial
        if serial:
            self.gateway.set_serial(serial)

    @log_entry_exit
    def get_one_external_parity_group(self, external_parity_group_id):
        return self.gateway.get_external_parity_group(external_parity_group_id)

    @log_entry_exit
    def get_external_path_group_by_external_parity_group_id(
        self, external_parity_group_id
    ):
        return self.gateway.get_external_path_group_by_external_parity_group_id(
            external_parity_group_id
        )

    @log_entry_exit
    def assign_external_parity_group(self, external_parity_group_id, clpr_id):
        return self.gateway.assign_external_parity_group(
            external_parity_group_id, clpr_id
        )

    @log_entry_exit
    def change_mp_blade(self, external_parity_group_id, mp_blade_id):
        return self.gateway.change_mp_blade(external_parity_group_id, mp_blade_id)

    @log_entry_exit
    def disconnect_from_a_volume_on_external_storage(self, spec):
        result = self.gateway.disconnect_from_a_volume_on_external_storage(
            spec.external_parity_group_id
        )
        return result

    @log_entry_exit
    def delete_external_parity_group(self, spec):
        result = self.gateway.delete_external_parity_group(
            spec.external_parity_group_id, spec.force
        )
        return result

    @log_entry_exit
    def create_external_parity_group(self, spec):
        c_epg = CreateExternalParityGroupObject()
        c_epg.external_parity_group_id = spec.external_parity_group_id
        c_epg.external_path_group_id = spec.external_path_group_id
        c_epg.port_id = spec.port_id
        c_epg.external_wwn = spec.external_wwn
        c_epg.lun_id = spec.lun_id
        c_epg.emulation_type = spec.emulation_type
        c_epg.clpr_id = spec.clpr_id
        c_epg.is_external_attribute_migration = spec.is_external_attribute_migration
        c_epg.command_device_ldev_id = spec.command_device_ldev_id

        result = self.gateway.create_external_parity_group(c_epg)
        return result
