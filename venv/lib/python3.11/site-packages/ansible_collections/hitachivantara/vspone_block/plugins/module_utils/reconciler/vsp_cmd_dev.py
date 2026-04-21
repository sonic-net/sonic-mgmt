try:
    from ..common.ansible_common import (
        log_entry_exit,
    )
    from ..common.hv_log import Log
    from ..common.hv_constants import StateValue
    from ..provisioner.vsp_cmd_dev_provisioner import VSPCmdDevProvisioner
    from ..message.vsp_cmd_dev_msgs import VSPCmdDevValidateMsg
    from .vsp_volume import VSPVolumeReconciler, VolumeCommonPropertiesExtractor
    from ..model.vsp_volume_models import VolumeFactSpec


except ImportError:
    from common.ansible_common import (
        log_entry_exit,
    )
    from common.hv_log import Log
    from common.hv_constants import StateValue
    from message.vsp_cmd_dev_msgs import VSPCmdDevValidateMsg
    from .vsp_volume import VSPVolumeReconciler, VolumeCommonPropertiesExtractor
    from ..model.vsp_volume_models import VolumeFactSpec

logger = Log()


class VSPCmdDevReconciler:
    def __init__(self, connection_info, serial=None, state=None):

        self.connection_info = connection_info
        self.provisioner = VSPCmdDevProvisioner(connection_info, serial)
        self.storage_serial_number = serial
        if state:
            self.state = state
        self.vol_recon = VSPVolumeReconciler(
            self.connection_info, self.storage_serial_number
        )

    @log_entry_exit
    def reconcile_cmd_dev(self, spec):

        if self.state == StateValue.PRESENT:
            ldev = self.provisioner.get_ldev_by_id(spec.ldev_id)
            if not ldev:
                raise ValueError(
                    VSPCmdDevValidateMsg.LDEV_NOT_FOUND.value.format(spec.ldev_id)
                )
            if ldev.emulationType == "NOT DEFINED":
                raise ValueError(
                    VSPCmdDevValidateMsg.LDEV_NOT_DEFINED.value.format(spec.ldev_id)
                )
            if not self.is_command_device(ldev):
                self.create_command_device(spec)
            else:
                self.update_command_device(ldev, spec)

            vol_spec = VolumeFactSpec()
            vol_spec.query = ["cmd_device_settings"]
            response = self.vol_recon.get_volume_detail_for_spec(ldev, vol_spec)
            logger.writeDebug("RC:reconcile_cmd_dev:vol_detail={}", response)

            comment = "Command Device is enabled successfully."
            if response:
                if self.is_pegasus():
                    comment = (
                        comment
                        + " No command device information is available for VSP One storage system."
                    )

            volume_dict = response.to_dict() if response else {}
            logger.writeDebug("RC:reconcile_cmd_dev:response={}", response)
            extracted_data = VolumeCommonPropertiesExtractor(
                self.storage_serial_number
            ).extract([volume_dict])[0]
            logger.writeDebug("RC:reconcile_cmd_dev:extracted_data={}", extracted_data)
            return extracted_data, comment

        elif self.state == StateValue.ABSENT:
            self.delete_command_device(spec.ldev_id)
            comment = "Command Device is disabled successfully."
            return None, comment

    @log_entry_exit
    def is_pegasus(self):
        return self.provisioner.is_pegasus()

    @log_entry_exit
    def is_command_device(self, ldev):
        if ldev.attributes and "CMD" in ldev.attributes:
            return True
        return False

    @log_entry_exit
    def create_command_device(self, spec):
        self.provisioner.create_command_device(spec)
        # self.connection_info.changed = True

    @log_entry_exit
    def update_command_device(self, ldev, spec):
        vol_detail = self.vol_recon.get_volume_detail_info(ldev)
        logger.writeDebug("RC:reconcile_cmd_dev:vol_detail={}", vol_detail)
        update_needed = False

        if (
            spec.is_security_enabled is not None
            and spec.is_security_enabled != vol_detail.isSecurityEnabled
        ):
            update_needed = True
        if (
            spec.is_user_authentication_enabled is not None
            and spec.is_user_authentication_enabled
            != vol_detail.isUserAuthenticationEnabled
        ):
            update_needed = True
        if (
            spec.is_device_group_definition_enabled is not None
            and spec.is_device_group_definition_enabled
            != vol_detail.isDeviceGroupDefinitionEnabled
        ):
            update_needed = True

        if update_needed:
            self.provisioner.create_command_device(spec)
            # self.connection_info.changed = True

    @log_entry_exit
    def delete_command_device(self, ldev_id):
        ldev = self.provisioner.get_ldev_by_id(ldev_id)
        if not ldev:
            raise ValueError(VSPCmdDevValidateMsg.LDEV_NOT_FOUND.value.format(ldev_id))
        if ldev.attributes and "CMD" not in ldev.attributes:
            return
        self.provisioner.delete_command_device(ldev_id)
        # self.connection_info.changed = True
