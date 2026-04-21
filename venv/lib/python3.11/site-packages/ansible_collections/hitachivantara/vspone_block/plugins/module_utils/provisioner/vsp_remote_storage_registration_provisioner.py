try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..model.vsp_remote_storage_registration_models import (
        AllRemoteStorageSystemsInfoPfrest,
    )

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from model.vsp_remote_storage_registration_models import (
        AllRemoteStorageSystemsInfoPfrest,
    )


logger = Log()


class VSPRemoteStorageRegistrationProvisioner:

    def __init__(self, connection_info, serial=None):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_REMOTE_STORAGE_REGISTRATION
        )
        self.connection_info = connection_info

        if serial:
            self.serial = serial
            self.gateway.set_serial(serial)
            logger.writeDebug(f"PROV:serial={self.serial}")

    @log_entry_exit
    def register_remote_storage(self, spec):
        response = self.gateway.register_remote_storage(spec)
        return self.get_remote_storage_registration_facts(spec)

    @log_entry_exit
    def delete_remote_storage(self, spec):
        """Delete Remote Storage"""
        response = self.gateway.delete_remote_storage(spec)
        logger.writeDebug(f"PROV:delete_remote_storage:response: {response}")
        return response

    @log_entry_exit
    def get_remote_storage_registration_facts(self, spec):
        """Get Remote Storage Registration Facts"""
        local_remote_storages = self.gateway.get_remote_storages_from_local()
        remote_remote_storages = self.gateway.get_remote_storages_from_remote(
            spec.secondary_connection_info
        )
        return AllRemoteStorageSystemsInfoPfrest(
            local_remote_storages.data, remote_remote_storages.data
        )

    @log_entry_exit
    def get_remote_storages_from_local(self):
        """Get Remote Storages"""
        remote_storages = self.gateway.get_remote_storages_from_local()
        return remote_storages
