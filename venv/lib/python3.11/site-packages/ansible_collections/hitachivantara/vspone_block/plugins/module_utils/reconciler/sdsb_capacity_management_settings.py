from typing import Any

try:
    from ..provisioner.sdsb_capacity_mgmt_settings_provisioner import (
        SDSBCapacityManagementSettingsProvisioner,
    )
    from ..common.hv_constants import StateValue
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..message.sdsb_controller_msgs import SDSBControllerValidationMsg
except ImportError:
    from provisioner.sdsb_capacity_mgmt_settings_provisioner import (
        SDSBCapacityManagementSettingsProvisioner,
    )
    from common.hv_constants import StateValue
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from message.sdsb_controller_msgs import SDSBControllerValidationMsg

logger = Log()


class SDSBCapacityManagementSettingsReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBCapacityManagementSettingsProvisioner(
            self.connection_info
        )

    @log_entry_exit
    def get_capacity_management_settings(self, spec=None):
        response = self.provisioner.get_capacity_management_settings(spec)
        return self.display_response(response)

    @log_entry_exit
    def display_response(self, response):
        return {
            "is_storage_cluster_capacity_balancing_enabled": response[
                "storage_cluster"
            ]["is_enabled"],
            "storage_controllers_capacity_balancing_settings": response[
                "storage_controllers"
            ],
        }

    @log_entry_exit
    def reconcile_capacity_management_settings(self, spec: Any, state) -> Any:
        # state = self.state.lower()

        resp_data = None
        if state == StateValue.PRESENT:
            resp_data = self.update_settings_of_controller(spec=spec)
            return resp_data
        else:
            return None

    @log_entry_exit
    def update_settings_of_controller(self, spec):
        logger.writeDebug("RC:update_settings_of_controller:spec= {}", spec)
        if spec.is_empty() is True:
            resp = self.provisioner.update_storage_controller_settings()
            self.connection_info.changed = True
            logger.writeDebug("RC:update_settings_of_controller:resp={}", resp)
            return self.provisioner.get_storage_controllers()

        if spec.id:
            controller = self.provisioner.get_storage_controller_by_id(spec.id)
            logger.writeDebug(
                "RC:update_settings_of_controller:controller={}", controller
            )
            if controller is None:
                raise ValueError(SDSBControllerValidationMsg.CONTROLLER_NOT_FOUND.value)
            input_logging_mode = False
            if spec.is_detailed_logging_mode:
                input_logging_mode = True
            if controller.get("is_detailed_logging_mode") == input_logging_mode:
                return controller

        resp = self.provisioner.update_storage_controller_settings(
            spec.id, spec.is_detailed_logging_mode
        )
        logger.writeDebug("RC:update_settings_of_controller:resp={}", resp)
        self.connection_info.changed = True
        if spec.id:
            return self.provisioner.get_storage_controller_by_id(spec.id)
        else:
            return self.provisioner.get_storage_controllers()
