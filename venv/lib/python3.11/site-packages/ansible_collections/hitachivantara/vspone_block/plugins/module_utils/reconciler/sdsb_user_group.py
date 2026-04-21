try:
    from ..provisioner.sdsb_user_group_provisioner import SDSBUserGroupProvisioner
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_constants import StateValue
    from .sdsb_vps_helper import SDSBVpsHelper
    from ..message.sdsb_vps_msgs import SDSBVpsValidationMsg
except ImportError:
    from provisioner.sdsb_user_group_provisioner import SDSBUserGroupProvisioner
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from common.hv_constants import StateValue
    from sdsb_vps_helper import SDSBVpsHelper
    from message.sdsb_vps_msgs import SDSBVpsValidationMsg

logger = Log()


class SDSBUserGroupReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBUserGroupProvisioner(self.connection_info)
        self.vps_helper = SDSBVpsHelper(self.connection_info)

    @log_entry_exit
    def get_user_groups(self, spec=None):
        if spec:
            if (
                spec.vps_id is None
                and spec.vps_name
                and "system" not in spec.vps_name.lower()
            ):
                spec.vps_id = self.vps_helper.get_vps_id_by_vps_name(spec.vps_name)
                if not spec.vps_id:
                    raise ValueError(
                        SDSBVpsValidationMsg.VPS_NAME_ABSENT.value.format(spec.vps_name)
                    )
            elif spec.vps_id and "system" not in spec.vps_id.lower():
                if not self.vps_helper.is_vps_exist(spec.vps_id):
                    raise ValueError(
                        SDSBVpsValidationMsg.VPS_ID_ABSENT.value.format(spec.vps_id)
                    )
        return self.provisioner.get_user_groups(spec)

    @log_entry_exit
    def reconcile_user_group(self, spec, state=None):
        state_handlers = {
            StateValue.PRESENT: self.create_update_user_group,
            StateValue.ABSENT: self.delete_user_group,
        }
        handler = state_handlers.get(state)
        if handler:
            return handler(spec)
        else:
            spec.errors.append(f"Unsupported state: {state}")
            return spec

    @log_entry_exit
    def create_update_user_group(self, spec):
        user_group = self.get_user_groups(spec)
        if user_group is not None:
            return self.update_user_group(user_group, spec)
        else:
            return self.provisioner.create_user_group(spec)

    @log_entry_exit
    def update_user_group(self, current_user_group, spec):
        if spec.role_names is None and spec.scope is None:
            return current_user_group
        else:
            return self.provisioner.update_user_group(spec)

    @log_entry_exit
    def delete_user_group(self, spec):
        response = self.provisioner.delete_user_group(spec)
        if response:
            self.connection_info.changed = True
        return
