try:
    from .gateway_manager import VSPConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from ..model.vsp_user_models import (
        VspUserInfo,
        VspUserInfoList,
    )
except ImportError:
    from .gateway_manager import VSPConnectionManager
    from common.hv_log import Log
    from common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from model.vsp_user_models import (
        VspUserInfo,
        VspUserInfoList,
    )

GET_USERS_DIRECT = "v1/objects/users"
GET_USER_BY_ID_DIRECT = "v1/objects/users/{}"
CREATE_USER_DIRECT = "v1/objects/users"
UPDATE_USER_PASSWORD_DIRECT = "v1/objects/users/{}"
ADD_USER_TO_USER_GROUP_DIRECT = "v1/objects/users/{}/actions/add-user-group/invoke"
REMOVE_USER_FROM_USER_GROUP_DIRECT = (
    "v1/objects/users/{}/actions/remove-user-group/invoke"
)
DELETE_USER_DIRECT = "v1/objects/users/{}"

logger = Log()


class VSPUserDirectGateway:
    def __init__(self, connection_info):

        self.connection_manager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.connection_info = connection_info
        self.serial = None

    @log_entry_exit
    def set_serial(self, serial=None):
        if serial:
            self.serial = serial
            logger.writeError(f"GW:set_serial={self.serial}")

    @log_entry_exit
    def get_users(self, spec=None):
        if spec is None or spec.is_empty() is True:
            end_point = GET_USERS_DIRECT
            users_date = self.connection_manager.get(end_point)
            logger.writeDebug(f"GW:data={users_date}")
            users = VspUserInfoList(
                dicts_to_dataclass_list(users_date["data"], VspUserInfo)
            )
            return users

    @log_entry_exit
    def get_user_by_id(self, id):
        try:
            end_point = GET_USER_BY_ID_DIRECT.format(id)
            user = self.connection_manager.get(end_point)
            return VspUserInfo(**user)
        except Exception as err:
            logger.writeError(err)
            raise err

    @log_entry_exit
    def create_user(self, spec):
        end_point = CREATE_USER_DIRECT
        payload = {}
        payload["userId"] = spec.name
        payload["authentication"] = spec.authentication
        if spec.authentication == "local":
            payload["userPassword"] = spec.password
        payload["userGroupNames"] = spec.group_names

        user_group = self.connection_manager.post(end_point, payload)
        self.connection_info.changed = True
        return user_group

    @log_entry_exit
    def update_user_password(self, user, spec):
        end_point = UPDATE_USER_PASSWORD_DIRECT.format(user.userObjectId)
        payload = {}
        payload["userPassword"] = spec.password
        user_id = self.connection_manager.patch(end_point, payload)
        self.connection_info.changed = True
        return user_id

    @log_entry_exit
    def add_user_to_user_group(self, user, spec):
        end_point = ADD_USER_TO_USER_GROUP_DIRECT.format(user.userObjectId)
        parameters = {}
        parameters["userGroupNames"] = spec.group_names
        payload = {"parameters": parameters}
        user_id = self.connection_manager.post(end_point, payload)
        self.connection_info.changed = True
        return user_id

    @log_entry_exit
    def remove_user_from_user_group(self, user, spec):
        end_point = REMOVE_USER_FROM_USER_GROUP_DIRECT.format(user.userObjectId)
        parameters = {}
        parameters["userGroupNames"] = spec.group_names
        payload = {"parameters": parameters}
        user_id = self.connection_manager.post(end_point, payload)
        self.connection_info.changed = True
        return user_id

    @log_entry_exit
    def delete_user(self, user, spec):
        end_point = DELETE_USER_DIRECT.format(user.userObjectId)
        ret_data = self.connection_manager.delete(end_point)
        self.connection_info.changed = True
        return ret_data
