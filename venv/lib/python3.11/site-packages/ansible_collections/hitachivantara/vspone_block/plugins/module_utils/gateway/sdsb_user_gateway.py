import re

try:
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..model.sdsb_user_models import SdsbUserResponse, SdsbUserList

except ImportError:
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from model.sdsb_user_models import SdsbUserResponse, SdsbUserList

GET_USERS = "v1/objects/users"
GET_USER_BY_ID = "v1/objects/users/{}"
CREATE_USER = "v1/objects/users"
DELETE_USER = "v1/objects/users/{}"
UPDATE_USER = "v1/objects/users/{}"
CHANGE_USER_PASSWORD = "v1/objects/users/{}/password"
ADD_USER_TO_USER_GROUPS = "v1/objects/users/{}/actions/add-user-group/invoke"
DELETE_USER_FROM_USER_GROUPS = "v1/objects/users/{}/actions/delete-user-group/invoke"

logger = Log()

PASSWORD_REGEX = re.compile(
    r"^[-A-Za-z0-9!#\$%&\"'\(\)\*\+,\.\/:;<>=\?@\[\]\\\^_`\{\}\|~]{1,256}$"
)


class SDSBUserGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_users(self, spec=None):

        end_point = GET_USERS
        if spec and spec.vps_id:
            end_point = end_point + f"?vpsId={spec.vps_id}"
            logger.writeDebug("GW:get_users:end_point={}", end_point)

        users = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_users:data={}", users)

        return SdsbUserList().dump_to_object(users)

    @log_entry_exit
    def get_user_by_id(self, id):
        end_point = GET_USER_BY_ID.format(id)
        response = self.connection_manager.get(end_point)
        return SdsbUserResponse(**response)

    @log_entry_exit
    def create_user(self, spec=None):

        end_point = CREATE_USER
        payload = {}

        # Validate user ID length
        if len(spec.id) < 6 or len(spec.id) > 28:
            raise ValueError("User ID must be between 6 and 28 characters long.")

        payload["userId"] = spec.id
        if not PASSWORD_REGEX.fullmatch(spec.password):
            raise ValueError("Password does not meet complexity requirements.")
        payload["password"] = spec.password
        if spec.authentication:
            payload["authentication"] = spec.authentication
        else:
            payload["authentication"] = "local"
        if spec.user_group_ids:
            payload["userGroupIds"] = spec.user_group_ids
        if spec.is_enabled_console_login is not None:
            payload["isEnabledConsoleLogin"] = spec.is_enabled_console_login

        response = self.connection_manager.post(end_point, payload)
        logger.writeDebug("GW:create_user:response={}", response)

        return SdsbUserResponse(**response)

    @log_entry_exit
    def delete_user(self, id):
        logger.writeDebug("GW:delete_user:id={}", id)
        end_point = DELETE_USER.format(id)
        response = self.connection_manager.delete(end_point)
        logger.writeDebug("GW:delete_user:response={}", response)
        return response

    @log_entry_exit
    def update_user(self, id, password=None, is_enabled=None):

        end_point = UPDATE_USER.format(id)
        payload = {}
        if password:
            payload["password"] = password
        if is_enabled is not None:
            payload["isEnabled"] = is_enabled

        response = self.connection_manager.patch(end_point, payload)
        logger.writeDebug("GW:update_user:response={}", response)

        return SdsbUserResponse(**response)

    @log_entry_exit
    def change_user_password(self, id, current_password, new_password):
        end_point = CHANGE_USER_PASSWORD.format(id)
        payload = {"currentPassword": current_password, "newPassword": new_password}
        response = self.connection_manager.patch(end_point, payload)
        logger.writeDebug("GW:update_user:response={}", response)

        return SdsbUserResponse(**response)

    @log_entry_exit
    def add_user_to_user_groups(self, id, user_group_ids):

        end_point = ADD_USER_TO_USER_GROUPS.format(id)
        payload = {"userGroupIds": user_group_ids}
        response = self.connection_manager.post(end_point, payload)
        logger.writeDebug("GW:add_user_to_user_groups:response={}", response)

        return SdsbUserResponse(**response)

    @log_entry_exit
    def remove_user_from_user_groups(self, id, user_group_ids):

        end_point = DELETE_USER_FROM_USER_GROUPS.format(id)
        payload = {"userGroupIds": user_group_ids}
        response = self.connection_manager.post(end_point, payload)
        logger.writeDebug("GW:remove_user_from_user_groups:response={}", response)

        return SdsbUserResponse(**response)
