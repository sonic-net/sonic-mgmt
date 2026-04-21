import os
from typing import Any

try:
    from ..provisioner.sdsb_software_update_provisioner import (
        SDSBSoftwareUpdateProvisioner,
    )
    from ..common.hv_constants import StateValue
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..message.sdsb_software_update_msgs import SDSBSoftwareUpdateValidationMsg
except ImportError:
    from provisioner.sdsb_software_update_provisioner import (
        SDSBSoftwareUpdateProvisioner,
    )
    from common.hv_constants import StateValue
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from message.sdsb_software_update_msgs import SDSBSoftwareUpdateValidationMsg

logger = Log()


class SDSBSoftwareUpdateReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBSoftwareUpdateProvisioner(self.connection_info)

    @log_entry_exit
    def get_software_update_file(self):
        try:
            return self.provisioner.get_software_update_file()
        except Exception as e:
            if "HTTP Error 404: Not Found" in str(e):
                return (
                    SDSBSoftwareUpdateValidationMsg.SOFTWARE_UPDATE_FILE_NOT_FOUND.value
                )
            else:
                raise Exception(e)

    @log_entry_exit
    def reconcile_software_update(self, spec: Any, state) -> Any:
        # state = self.state.lower()

        if state == StateValue.SOFTWARE_UPDATE_FILE_PRESENT:
            resp_data = self.upload_software_update_file(spec)
            return resp_data

        if spec:
            if spec.should_stop_software_update:
                resp_data = self.stop_updating_storage_software()
                logger.writeDebug(f"RC:reconcile_software_update:resp = {resp_data}")
                return resp_data
            elif spec.is_software_downgrade:
                resp_data = self.downgrade_storage_software()
                return resp_data

        resp_data = self.update_storage_software()
        return resp_data

    @log_entry_exit
    def upload_software_update_file(self, spec):
        self.validate_upload_software_update_file(spec)
        try:
            self.provisioner.upload_software_update_file(spec.software_update_file)
            msg = (
                SDSBSoftwareUpdateValidationMsg.UPLOAD_SOFTWARE_UPDATE_FILE_SUCCESS_MSG.value
            )
            self.connection_info.changed = True
            return msg
        except Exception as e:
            logger.writeException(e)
            msg = (
                SDSBSoftwareUpdateValidationMsg.UPLOAD_SOFTWARE_UPDATE_FILE_FAILURE_MSG.value
            )
            return msg

    @log_entry_exit
    def validate_upload_software_update_file(self, spec):
        logger.writeDebug(f"RC:validate_upload_software_update_file:spec = {spec}")
        if spec is None or spec.software_update_file is None:
            raise ValueError(
                SDSBSoftwareUpdateValidationMsg.SOFTWARE_UPDATE_FILE_REQD.value
            )
        if spec.software_update_file:
            if not os.path.isfile(spec.software_update_file):
                raise ValueError(
                    SDSBSoftwareUpdateValidationMsg.SOFTWARE_UPDATE_FILE_DOES_NOT_EXIST.value.format(
                        spec.software_update_file
                    )
                )
        return

    @log_entry_exit
    def stop_updating_storage_software(self):
        try:
            resp = self.provisioner.stop_updating_storage_software()
            msg = SDSBSoftwareUpdateValidationMsg.STOP_SOFTWARE_UPDATE_SUCCESS_MSG.value
            self.connection_info.changed = True
            return msg
        except Exception as e:
            logger.writeException(e)
            msg = SDSBSoftwareUpdateValidationMsg.STOP_SOFTWARE_UPDATE_FAILURE_MSG.value
            return msg

    @log_entry_exit
    def downgrade_storage_software(self):
        try:
            resp = self.provisioner.downgrade_storage_software()
            msg = SDSBSoftwareUpdateValidationMsg.DOWNGRADE_SOFTWARE_SUCCESS_MSG.value.format(
                resp
            )
            self.connection_info.changed = True
            return msg
        except Exception as e:
            logger.writeException(e)
            msg = SDSBSoftwareUpdateValidationMsg.DOWNGRADE_SOFTWARE_FAILURE_MSG.value
            return msg

    @log_entry_exit
    def update_storage_software(self):
        try:
            resp = self.provisioner.update_storage_software()
            msg = SDSBSoftwareUpdateValidationMsg.UPDATE_SOFTWARE_SUCCESS_MSG.value.format(
                resp
            )
            self.connection_info.changed = True
            return msg
        except Exception as e:
            logger.writeException(e)
            msg = SDSBSoftwareUpdateValidationMsg.UPDATE_SOFTWARE_FAILURE_MSG.value
            return msg
