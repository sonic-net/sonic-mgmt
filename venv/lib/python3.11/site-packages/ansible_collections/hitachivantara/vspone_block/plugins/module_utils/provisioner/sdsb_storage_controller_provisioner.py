try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_log import Log
except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.ansible_common import log_entry_exit
    from common.hv_log import Log

logger = Log()


class SDSBStorageControllerProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_STORAGE_CONTROLLER
        )

    @log_entry_exit
    def get_storage_controllers(self, spec=None):
        storage_controllers = self.gateway.get_storage_controllers(spec)
        controllers = None
        controllers = storage_controllers.get("data", [])
        if spec is not None and spec.primary_fault_domain_name:
            storage_controllers = [
                fd
                for fd in controllers
                if fd.get("primary_fault_domain_name") == spec.primary_fault_domain_name
            ]
        if spec is not None and spec.primary_fault_domain_id:
            storage_controllers = [
                fd
                for fd in controllers
                if fd.get("primary_fault_domain_id") == spec.primary_fault_domain_id
            ]
        return storage_controllers

    @log_entry_exit
    def get_storage_controller_by_id(self, id=None):
        if id:
            try:
                controller = self.gateway.get_storage_controller_by_id(id)
                return controller
            except Exception as e:
                logger.writeException(e)
                return None
        else:
            return None

    @log_entry_exit
    def update_storage_controller_settings(
        self, id=None, is_detailed_logging_mode=None
    ):
        try:
            resp = self.gateway.update_storage_controller_settings(
                id, is_detailed_logging_mode
            )
            logger.writeDebug("PROV:update_settings_of_controller:resp={}", resp)
        except Exception as e:
            logger.writeException(e)
            raise ValueError(e)
