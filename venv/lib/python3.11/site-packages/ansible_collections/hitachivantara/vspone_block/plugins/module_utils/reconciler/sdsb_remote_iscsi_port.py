from typing import Any

try:
    from ..provisioner.sdsb_remote_iscsi_port_provisioner import (
        SDSBRemoteIscsiPortProvisioner,
    )
    from ..common.hv_constants import StateValue
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..message.sdsb_remote_iscsi_port_msgs import SDSBRemoteIscsiPortValidationMsg
except ImportError:
    from provisioner.sdsb_remote_iscsi_port_provisioner import (
        SDSBRemoteIscsiPortProvisioner,
    )
    from common.hv_constants import StateValue
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from message.sdsb_remote_iscsi_port_msgs import SDSBRemoteIscsiPortValidationMsg

logger = Log()


class SDSBRemoteIscsiPortReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBRemoteIscsiPortProvisioner(self.connection_info)

    @log_entry_exit
    def get_remote_iscsi_ports(self, spec=None):
        if spec and spec.id:
            return self.provisioner.get_remote_iscsi_port_by_id(spec.id)

        response = self.provisioner.get_remote_iscsi_ports(spec)
        return response

    @log_entry_exit
    def reconcile_remote_iscsi_port(self, spec: Any, state) -> Any:

        resp_data = None
        if state == StateValue.PRESENT:
            resp_data = self.register_remote_iscsi_port(spec)
            return resp_data
        elif state == StateValue.ABSENT:
            resp_data = self.delete_remote_iscsi_port(spec)
            return resp_data
        else:
            return None

    @log_entry_exit
    def register_remote_iscsi_port(self, spec):
        self.validate_spec_for_register(spec)
        logger.writeDebug("RC:register_remote_iscsi_port:spec= {}", spec)
        resp = self.provisioner.register_remote_iscsi_port(spec)
        self.connection_info.changed = True
        return self.provisioner.get_remote_iscsi_port_by_id(resp)

    @log_entry_exit
    def delete_remote_iscsi_port(self, spec):
        if spec is None or spec.id is None:
            raise ValueError(SDSBRemoteIscsiPortValidationMsg.ID_REQD.value)
        try:
            self.provisioner.delete_remote_iscsi_port(spec.id)
            self.connection_info.changed = True
            return None
        except Exception as e:
            logger.writeException(e)
            return -1

    @log_entry_exit
    def validate_spec_for_register(self, spec):
        if (
            spec is None
            or spec.local_port is None
            or spec.remote_ip_address is None
            or spec.remote_port is None
            or spec.remote_serial is None
            or spec.remote_storage_system_type is None
        ):
            raise ValueError(SDSBRemoteIscsiPortValidationMsg.REQD_INPUT_MISSING.value)
