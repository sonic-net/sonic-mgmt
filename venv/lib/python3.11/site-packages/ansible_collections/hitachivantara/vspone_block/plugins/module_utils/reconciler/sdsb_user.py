import re

try:
    from ..provisioner.sdsb_users_provisioner import SDSBUsersProvisioner
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_constants import StateValue
    from .sdsb_vps_helper import SDSBVpsHelper
    from ..message.sdsb_vps_msgs import SDSBVpsValidationMsg
    from ..message.sdsb_user_msgs import SDSBUserValidationMsg
except ImportError:
    from provisioner.sdsb_users_provisioner import SDSBUsersProvisioner
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from common.hv_constants import StateValue
    from sdsb_vps_helper import SDSBVpsHelper
    from message.sdsb_vps_msgs import SDSBVpsValidationMsg
    from message.sdsb_user_msgs import SDSBUserValidationMsg

logger = Log()
PASSWORD_REGEX = re.compile(
    r"^[-A-Za-z0-9!#\$%&\"'\(\)\*\+,\.\/:;<>=\?@\[\]\\\^_`\{\}\|~]{1,256}$"
)


class SDSBUsersReconciler:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.provisioner = SDSBUsersProvisioner(self.connection_info)
        self.vps_helper = SDSBVpsHelper(self.connection_info)

    @log_entry_exit
    def get_users(self, spec=None):
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
        return self.provisioner.get_users(spec)

    @log_entry_exit
    def reconcile_user(self, spec, state=None):
        state_handlers = {
            StateValue.PRESENT: self.create_update_user,
            StateValue.ABSENT: self.delete_user,
            StateValue.UPDATE: self.update_user_password,
            StateValue.ADD_USER_GROUP: self.add_user_to_user_groups,
            StateValue.REMOVE_USER_GROUP: self.remove_user_from_user_groups,
        }
        handler = state_handlers.get(state)
        if handler:
            return handler(spec)
        else:
            raise ValueError(f"Unsupported state: {state}")

    @log_entry_exit
    def create_update_user(self, spec=None):
        user = self.get_users(spec)
        if user is not None:
            return self.update_user(user, spec)
        else:
            return self.create_user(spec)

    @log_entry_exit
    def update_user(self, user, spec):
        self.validate_update_user_settings(spec)

        logger.writeDebug("RC:update_user: {}", user)
        change_needed = False
        if spec.password:
            change_needed = True
        else:
            if user.get("is_enabled", None) != spec.is_enabled:
                change_needed = True
        if change_needed:
            self.connection_info.changed = True
            spec.comments = "User information updated successfully."
            return self.provisioner.update_user(spec)
        else:
            spec.comments = "User information update not needed."
            return user

    @log_entry_exit
    def create_user(self, spec=None):
        logger.writeDebug("User not found, creating new user: {}", spec.id)
        self.connection_info.changed = True
        spec.comments = "User created successfully."
        return self.provisioner.create_user(spec)

    @log_entry_exit
    def delete_user(self, spec):
        response = self.provisioner.delete_user(spec)
        if response:
            self.connection_info.changed = True
        return

    @log_entry_exit
    def update_user_password(self, spec):
        self.validate_change_password_spec(spec)
        user = self.get_users(spec)
        if user is not None:
            logger.writeDebug("User found, updating user's: {} password", spec.user_id)
            status = self.provisioner.update_user_password(spec)
            self.connection_info.changed = True
            spec.comments = "User password updated successfully."
            return status
        else:
            logger.writeDebug("User not found, cannot update: {}", spec.user_id)
            # After deploying the cluster first time, admin user is not returned
            # by the get users, but update password rest api call works
            if spec.user_id == "admin":
                status = self.provisioner.update_user_password(spec)
                self.connection_info.changed = True
                spec.comments = "User password updated successfully."
                return status
            else:
                raise ValueError(
                    f"User {spec.user_id} not found for updating password."
                )

    @log_entry_exit
    def add_user_to_user_groups(self, spec):
        if spec.id is None or spec.user_group_ids is None:
            raise ValueError(
                SDSBUserValidationMsg.ID_USER_GROUP_IDS_REQD.value.format(
                    "add_user_group"
                )
            )
        return self.provisioner.add_user_to_user_groups(spec)

    @log_entry_exit
    def remove_user_from_user_groups(self, spec):
        if spec.id is None or spec.user_group_ids is None:
            raise ValueError(
                SDSBUserValidationMsg.ID_USER_GROUP_IDS_REQD.value.format(
                    "remove_user_group"
                )
            )
        return self.provisioner.remove_user_from_user_groups(spec)

    @log_entry_exit
    def validate_change_password_spec(self, spec):
        if spec.current_password is None or spec.new_password is None:
            raise ValueError(
                "For changing password, you must specify current_password or new_password."
            )
        if not PASSWORD_REGEX.fullmatch(spec.new_password):
            raise ValueError("New password does not meet complexity requirements.")
        if spec.new_password == spec.current_password:
            raise ValueError(
                "New password must be different from the current password."
            )
        if len(spec.new_password) < 8:
            raise ValueError("New password must be at least 8 characters long.")
        if len(spec.new_password) > 256:
            raise ValueError("New password must not exceed 256 characters.")

    @log_entry_exit
    def validate_update_user_settings(self, spec):
        if spec.password is None and spec.is_enabled is None:
            raise ValueError(SDSBUserValidationMsg.FIELD_MISSING_FOR_EDIT_USER.value)
