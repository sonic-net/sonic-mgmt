from typing import Any
import re

try:
    from ..provisioner.sdsb_remote_path_group_provisioner import (
        SDSBRemotePathGroupProvisioner,
    )
    from ..common.hv_constants import StateValue
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..message.sdsb_remote_path_group_msgs import SDSBRemotePathGroupValidationMsg
except ImportError:
    from provisioner.sdsb_remote_iscsi_port_provisioner import (
        SDSBRemotePathGroupProvisioner,
    )
    from common.hv_constants import StateValue
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from message.sdsb_remote_path_group_msgs import SDSBRemotePathGroupValidationMsg

logger = Log()


class SDSBRemotePathGroupReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBRemotePathGroupProvisioner(self.connection_info)

    @log_entry_exit
    def get_remote_path_group_facts(self, spec=None):
        if spec and spec.id:
            return self.provisioner.get_remote_path_group_by_id(spec.id)

        response = self.provisioner.get_remote_path_groups(spec)
        return response

    @log_entry_exit
    def reconcile_remote_path_group(self, spec: Any, state) -> Any:

        resp_data = None
        state_handlers = {
            StateValue.PRESENT: self.create_update_remote_path_group,
            StateValue.ADD_REMOTE_PATH: self.add_remote_path_to_remote_path_group,
            StateValue.REMOVE_REMOTE_PATH: self.remove_remote_path_from_remote_path_group,
            StateValue.ABSENT: self.delete_remote_path_group,
        }
        handler = state_handlers.get(state)
        if handler:
            return handler(spec)
        else:
            spec.comments = f"Unsupported state: {state}"
            return spec

    @log_entry_exit
    def add_remote_path_to_remote_path_group(self, spec):
        self.validate_spec_for_path_operation(spec)
        try:
            response = self.provisioner.get_remote_path_group_by_id(spec.id)
            if response is None:
                spec.comments = f"Did not find remote path group with id = {spec.id}"
                return None
            change_needed = self.is_update_needed_for_add_path(response, spec)
            if not change_needed:
                spec.comments = f"The remote path already exists in the remote path group with id = {spec.id}"
                return response
            response = self.provisioner.add_remote_path_to_remote_path_group(spec)
            self.connection_info.changed = True
            return response
        except Exception as e:
            logger.writeException(e)
            spec.comments = str(e)
            return None

    @log_entry_exit
    def is_update_needed_for_add_path(self, current_rpg, spec):
        current_remote_paths = current_rpg.get("remote_paths", None)
        if current_remote_paths:
            for x in current_remote_paths:
                if (
                    x["local_port_number"] == spec.local_port
                    and x["remote_port_number"] == spec.remote_port
                ):
                    return False
        return True

    @log_entry_exit
    def remove_remote_path_from_remote_path_group(self, spec):
        self.validate_spec_for_path_operation(spec)
        try:
            response = self.provisioner.get_remote_path_group_by_id(spec.id)
            if response is None:
                spec.comments = f"Did not find remote path group with id = {spec.id}"
                return None
            change_needed = self.is_update_needed_for_remove_path(response, spec)
            if not change_needed:
                spec.comments = f"The remote path does not exist in remote path group with id = {spec.id}"
                return response
            response = self.provisioner.remove_remote_path_from_remote_path_group(spec)
            self.connection_info.changed = True
            return response
        except Exception as e:
            logger.writeException(e)
            spec.comments = str(e)
            return None

    @log_entry_exit
    def is_update_needed_for_remove_path(self, current_rpg, spec):
        current_remote_paths = current_rpg.get("remote_paths", None)
        if current_remote_paths:
            for x in current_remote_paths:
                if (
                    x["local_port_number"] == spec.local_port
                    and x["remote_port_number"] == spec.remote_port
                ):
                    return True
        return False

    @log_entry_exit
    def create_update_remote_path_group(self, spec):
        if spec and spec.id:
            return self.update_remote_path_group(spec)
        return self.create_remote_path_group(spec)

    @log_entry_exit
    def create_remote_path_group(self, spec):
        self.validate_spec_for_create(spec)
        try:
            resp = self.provisioner.create_remote_path_group(spec)
            self.connection_info.changed = True
            return resp
        except Exception as e:
            logger.writeException(e)
            spec.comments = str(e)
            return None

    @log_entry_exit
    def update_remote_path_group(self, spec):
        self.validate_spec_for_update(spec)
        try:
            response = self.provisioner.get_remote_path_group_by_id(spec.id)
            if response is None:
                spec.comments = f"Did not find remote path group with id = {spec.id}"
                return None
            current_timeout = response.get("remote_io_timeout_in_sec", None)
            logger.writeDebug(
                f"RC:update_remote_path_group:current_timeout= {current_timeout}"
            )
            if current_timeout == spec.remote_io_timeout_in_sec:
                return response
            resp = self.provisioner.update_remote_path_group(spec)
            self.connection_info.changed = True
            return resp
        except Exception as e:
            logger.writeException(e)
            spec.comments = str(e)
            return None

    @log_entry_exit
    def delete_remote_path_group(self, spec):
        if spec is None or spec.id is None:
            raise ValueError(SDSBRemotePathGroupValidationMsg.ID_REQD.value)
        try:
            self.provisioner.delete_remote_path_group(spec.id)
            self.connection_info.changed = True
            spec.comments = f"Deleted remote path group with id = {spec.id}"
            return
        except Exception as e:
            logger.writeException(e)
            if "not found" in str(e).lower() or "404" in str(e).lower():
                spec.comments = "Remote Path Group not found or deleted."
            else:
                spec.comments = str(e)
            return

    rs_pattern = re.compile(r"^[0-9]{6}$")
    port_pattern = re.compile(r"^CL[1-9A-G]-[A-HJ-NP-R]$")

    @log_entry_exit
    def validate_spec_for_create(self, spec):
        if (
            spec is None
            or spec.local_port is None
            or spec.remote_port is None
            or spec.remote_serial is None
            or spec.remote_storage_system_type is None
            or spec.path_group_id is None
        ):
            raise ValueError(SDSBRemotePathGroupValidationMsg.REQD_INPUT_MISSING.value)

        if spec.remote_serial:
            if not (self.rs_pattern.match(spec.remote_serial)):
                raise ValueError(
                    SDSBRemotePathGroupValidationMsg.INVALID_REMOTE_SERIAL.value
                )

        if spec.local_port:
            if not (self.port_pattern.match(spec.local_port)):
                raise ValueError(
                    SDSBRemotePathGroupValidationMsg.INVALID_PORT.value.format(
                        "local_port"
                    )
                )

        if spec.remote_port:
            if not self.port_pattern.match(spec.remote_port):
                raise ValueError(
                    SDSBRemotePathGroupValidationMsg.INVALID_PORT.value.format(
                        "remote_port"
                    )
                )

        if spec.path_group_id:
            if not (1 <= spec.path_group_id <= 255):
                raise ValueError(
                    SDSBRemotePathGroupValidationMsg.INVALID_PATH_GROUP_ID.value
                )

        if spec.remote_io_timeout_in_sec:
            if not (10 <= spec.remote_io_timeout_in_sec <= 80):
                raise ValueError(
                    SDSBRemotePathGroupValidationMsg.INVALID_TIMEOUT_VALUE.value
                )

    @log_entry_exit
    def validate_spec_for_update(self, spec):
        if spec.remote_io_timeout_in_sec is None:
            raise ValueError(
                SDSBRemotePathGroupValidationMsg.REQD_INPUT_MISSING_FOR_UPDATE.value
            )

    @log_entry_exit
    def validate_spec_for_path_operation(self, spec):
        if spec is None or spec.id is None:
            raise ValueError(SDSBRemotePathGroupValidationMsg.ID_REQD.value)
        if spec.local_port is None or spec.remote_port is None:
            raise ValueError(
                SDSBRemotePathGroupValidationMsg.REQD_INPUT_MISSING_FOR_PATH_OPERATION.value
            )
