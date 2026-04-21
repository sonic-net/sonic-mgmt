import re

try:
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..model.sdsb_user_group_models import SdsbUserGroupList, SdsbUserGroupResponse
except ImportError:
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from model.sdsb_user_group_models import SdsbUserGroupList, SdsbUserGroupResponse

GET_USER_GROUPS = "v1/objects/user-groups"
GET_USER_GROUP_BY_ID = "v1/objects/user-groups/{}"
CREATE_USER_GROUP = "v1/objects/user-groups"
DELETE_USER_GROUP = "v1/objects/user-groups/{}"
UPDATE_USER_GROUP = "v1/objects/user-groups/{}"

logger = Log()

PASSWORD_REGEX = re.compile(
    r"^[-A-Za-z0-9!#\$%&\"'\(\)\*\+,\.\/:;<>=\?@\[\]\\\^_`\{\}\|~]{1,256}$"
)


class SDSBUsersGroupGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_user_groups(self, spec=None):

        end_point = GET_USER_GROUPS
        if spec and spec.vps_id:
            end_point = end_point + f"?vpsId={spec.vps_id}"
            logger.writeDebug("GW:get_user_groups:end_point={}", end_point)

        user_groups = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_user_groups:data={}", user_groups)

        return SdsbUserGroupList().dump_to_object(user_groups)

    @log_entry_exit
    def get_user_group_by_id(self, id):
        end_point = GET_USER_GROUP_BY_ID.format(id)
        response = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_user_group_by_id:response={}", response)
        return SdsbUserGroupResponse(**response)
        # return convert_keys_to_snake_case(response)

    @log_entry_exit
    def create_user_group(
        self, id, role_names, external_group_name=None, vps_id=None, scope=None
    ):

        end_point = CREATE_USER_GROUP
        payload = {}

        payload["userGroupId"] = id
        payload["roleNames"] = role_names

        if external_group_name:
            payload["externalGroupName"] = external_group_name
        if vps_id:
            payload["vpsId"] = vps_id
        if scope:
            payload["scope"] = scope

        response = self.connection_manager.post(end_point, payload)
        logger.writeDebug("GW:create_user_group:response={}", response)

        return SdsbUserGroupResponse(**response)

    @log_entry_exit
    def delete_user_group(self, id):
        end_point = DELETE_USER_GROUP.format(id)
        response = self.connection_manager.delete(end_point)
        logger.writeDebug("GW:delete_user_group:response={}", response)
        return response

    @log_entry_exit
    def update_user_group(self, id, role_names, scope=None):

        # logger.writeDebug("GW:get_chap_users:spec={}", spec)
        end_point = UPDATE_USER_GROUP.format(id)
        payload = {"roleNames": role_names}
        if scope:
            payload["scope"] = scope

        response = self.connection_manager.patch(end_point, payload)
        logger.writeDebug("GW:update_user_group:response={}", response)

        user_grp = self.get_user_group_by_id(id)
        logger.writeDebug("GW:update_user_group:user={}", user_grp)
        return user_grp
