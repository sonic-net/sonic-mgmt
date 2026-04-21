try:
    from ..provisioner.sdsb_drives_provisioner import SDSBBlockDrivesProvisioner
    from ..common.hv_constants import StateValue
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..message.sdsb_drive_msgs import SDSBDriveValidationMsg
except ImportError:
    from ..provisioner.sdsb_drives_provisioner import SDSBBlockDrivesProvisioner
    from ..common.hv_constants import StateValue
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from ..message.sdsb_drive_msgs import SDSBDriveValidationMsg

logger = Log()


class SDSBBlockDrivesReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBBlockDrivesProvisioner(self.connection_info)

    @log_entry_exit
    def get_drives(self, spec=None):
        if spec and spec.id:
            return self.provisioner.get_drive_by_id(spec.id)
        return self.provisioner.get_drives(spec)

    @log_entry_exit
    def reconcile_drive(self, spec=None, state=None):
        msg = ""
        try:
            if state == StateValue.PRESENT:
                resp_data = self.control_locator_led(spec)
                msg = "Successfully completed the operation."
            elif state == StateValue.ABSENT:
                resp_data = self.remove_drive(spec)
                msg = "Removed drive successfully."
            return resp_data, msg
        except Exception as e:
            if "Could not find the drive with id" in str(e):
                msg = str(e)
                return None, msg
            else:
                raise e

    @log_entry_exit
    def remove_drive(self, spec):
        drive = self.provisioner.get_drive_by_id(spec.id)
        if drive is None:
            raise ValueError(
                SDSBDriveValidationMsg.DRIVE_NOT_FOUND.value.format(spec.id)
            )
        drive_id = self.provisioner.remove_drive(spec.id)
        logger.writeDebug("RC:reconcile_drive:drive={}", drive_id)
        if drive_id:
            self.connection_info.changed = True
            return self.provisioner.get_drive_by_id(drive_id)
        else:
            raise ValueError(SDSBDriveValidationMsg.REMOVE_DRIVE_OPERATION_FAILED.value)

    @log_entry_exit
    def control_locator_led(self, spec):
        drive = self.provisioner.get_drive_by_id(spec.id)
        if drive is None:
            raise ValueError(
                SDSBDriveValidationMsg.DRIVE_NOT_FOUND.value.format(spec.id)
            )
        if not self.is_control_locator_led_operation_needed(
            drive, spec.should_drive_locator_led_on
        ):
            return drive
        drive_id = self.provisioner.control_locator_led(
            spec.id, spec.should_drive_locator_led_on
        )
        logger.writeDebug("RC:reconcile_drive:drive={}", drive_id)
        if drive_id:
            self.connection_info.changed = True
            return self.provisioner.get_drive_by_id(drive_id)
        else:
            raise ValueError(SDSBDriveValidationMsg.LED_DRIVE_OPERATION_FAILED.value)

    @log_entry_exit
    def is_control_locator_led_operation_needed(
        self, drive, should_drive_locator_led_on
    ):
        current_led_status = drive.get("locator_led_status")
        current_led_status_bool = True if current_led_status == "On" else False
        spec_led_status = False
        if should_drive_locator_led_on:
            spec_led_status = should_drive_locator_led_on
        if current_led_status_bool == spec_led_status:
            return False
        else:
            return True
