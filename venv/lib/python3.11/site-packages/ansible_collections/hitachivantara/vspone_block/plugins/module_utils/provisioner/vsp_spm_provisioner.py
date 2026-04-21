try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from ..common.hv_log import Log
    from ..common.ansible_common import (
        log_entry_exit,
    )
except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from gateway.vsp_storage_system_gateway import VSPStorageSystemDirectGateway
    from common.hv_log import Log
    from common.ansible_common import (
        log_entry_exit,
    )

logger = Log()


class VSPServerPriorityManagerProvisioner:

    def __init__(self, connection_info, serial):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_SPM
        )
        self.connection_info = connection_info
        self.serial = serial
        if self.serial is None:
            self.serial = self.get_storage_serial_number()
        self.gateway.set_storage_serial_number(serial)

    @log_entry_exit
    def get_storage_serial_number(self):
        storage_gw = VSPStorageSystemDirectGateway(self.connection_info)
        storage_system = storage_gw.get_current_storage_system_info()
        return storage_system.serialNumber

    @log_entry_exit
    def get_all_spms(self):
        resp = self.gateway.get_all_spms()
        return resp

    @log_entry_exit
    def get_one_spm(self, ldev_id, hba):
        try:
            resp = self.gateway.get_one_spm(ldev_id, hba)
            return resp
        except Exception as e:
            logger.writeError(f"An error occurred during get_one_spm call: {str(e)}")
            return None

    @log_entry_exit
    def get_spms_with_query(self, ldev_id=None, host_wwn=None, iscsi_name=None):
        if ldev_id is None and host_wwn is None and iscsi_name is None:
            return self.get_all_spms()
        else:
            return self.gateway.get_spms_with_query(ldev_id, host_wwn, iscsi_name)

    @log_entry_exit
    def set_spm(self, spm_set_object):
        resp = self.gateway.set_spm(spm_set_object)
        return resp

    @log_entry_exit
    def change_spm(self, ldev_id, hba, spm_change_object):
        resp = self.gateway.change_spm(ldev_id, hba, spm_change_object)
        return resp

    @log_entry_exit
    def delete_spm(self, ldev_id, hba):
        resp = self.gateway.delete_spm(ldev_id, hba)
        return resp
