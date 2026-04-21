try:

    from .gateway_manager import VSPConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from ..model.vsp_user_group_models import (
        VspUserGroupInfo,
        VspUserGroupInfoList,
    )
except ImportError:
    from .gateway_manager import VSPConnectionManager
    from common.hv_log import Log
    from common.ansible_common import dicts_to_dataclass_list, log_entry_exit
    from model.vsp_user_group_models import (
        VspUserGroupInfo,
        VspUserGroupInfoList,
    )

GET_USER_GROUPS_DIRECT = "v1/objects/user-groups"
GET_USER_GROUP_BY_ID_DIRECT = "v1/objects/user-groups/{}"
CREATE_USER_GROUP_DIRECT = "v1/objects/user-groups"
UPDATE_USER_GROUP_DIRECT = "v1/objects/user-groups/{}"
ADD_RESOURCE_GROUPS_TO_USER_GROUP_DIRECT = (
    "v1/objects/user-groups/{}/actions/add-resource-group/invoke"
)
REMOVE_RESOURCE_GROUPS_FROM_USER_GROUP_DIRECT = (
    "v1/objects/user-groups/{}/actions/remove-resource-group/invoke"
)
DELETE_USER_GROUP_DIRECT = "v1/objects/user-groups/{}"

logger = Log()


class VSPUserGroupDirectGateway:
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
    def get_user_groups(self, spec=None):
        if spec is None or spec.is_empty() is True:
            end_point = GET_USER_GROUPS_DIRECT
            user_groups_date = self.connection_manager.get(end_point)
            user_groups = VspUserGroupInfoList(
                dicts_to_dataclass_list(user_groups_date["data"], VspUserGroupInfo)
            )
            return user_groups

    @log_entry_exit
    def get_user_group_by_id(self, id):
        try:
            end_point = GET_USER_GROUP_BY_ID_DIRECT.format(id)
            user = self.connection_manager.get(end_point)
            return VspUserGroupInfo(**user)
        except Exception as err:
            logger.writeError(err)
            raise err

    @log_entry_exit
    def create_user_group(self, spec):
        end_point = CREATE_USER_GROUP_DIRECT
        payload = {}
        payload["userGroupId"] = spec.name
        if spec.role_names is None or len(spec.role_names) == 0:
            spec.role_names = ["STORAGE_ADMIN_VIEW_ONLY"]
        payload["roleNames"] = RolesManager.get_role_names(spec.role_names)
        has_all_rgs = RolesManager.get_has_all_resource_groups(spec.role_names)
        logger.writeDebug(f"Has all Resource Group {has_all_rgs}")
        if has_all_rgs is True:
            payload["hasAllResourceGroup"] = has_all_rgs
        else:
            payload["hasAllResourceGroup"] = has_all_rgs
            payload["resourceGroupIds"] = spec.resource_group_ids

        user_group_id = self.connection_manager.post(end_point, payload)
        self.connection_info.changed = True
        return user_group_id

    @log_entry_exit
    def update_user_group_name(self, user_group, spec):
        end_point = UPDATE_USER_GROUP_DIRECT.format(user_group.userGroupObjectId)
        payload = {}
        payload["userGroupId"] = spec.name
        user_group_id = self.connection_manager.patch(end_point, payload)
        self.connection_info.changed = True
        return user_group_id

    @log_entry_exit
    def update_user_group_role_names(self, user_group, spec):

        end_point = UPDATE_USER_GROUP_DIRECT.format(user_group.userGroupObjectId)
        payload = {}
        payload["roleNames"] = spec.role_names
        has_all_rgs = spec.has_all_resource_groups
        if has_all_rgs is True:
            payload["hasAllResourceGroup"] = has_all_rgs
        user_group_id = self.connection_manager.patch(end_point, payload)
        self.connection_info.changed = True
        return user_group_id

    @log_entry_exit
    def add_resource_group_to_user_group(self, user_group, spec):
        end_point = ADD_RESOURCE_GROUPS_TO_USER_GROUP_DIRECT.format(
            user_group.userGroupObjectId
        )
        parameters = {}
        parameters["resourceGroupIds"] = spec.resource_group_ids
        payload = {"parameters": parameters}
        user_group_id = self.connection_manager.post(end_point, payload)
        self.connection_info.changed = True
        return user_group_id

    @log_entry_exit
    def remove_resource_group_from_user_group(self, user_group, spec):
        end_point = REMOVE_RESOURCE_GROUPS_FROM_USER_GROUP_DIRECT.format(
            user_group.userGroupObjectId
        )
        parameters = {}
        parameters["resourceGroupIds"] = spec.resource_group_ids
        payload = {"parameters": parameters}
        user_group_id = self.connection_manager.post(end_point, payload)
        self.connection_info.changed = True
        return user_group_id

    @log_entry_exit
    def delete_user_group(self, user_group, spec):
        end_point = DELETE_USER_GROUP_DIRECT.format(user_group.userGroupObjectId)
        ret_data = self.connection_manager.delete(end_point)
        self.connection_info.changed = True
        return ret_data


class RolesManager:

    # You must specify Storage Administrator (View Only).
    # Audit Log Administrator (View & Modify)#
    # Audit Log Administrator (View Only)#
    # Security Administrator (View & Modify)#
    # Security Administrator (View Only)#
    # Storage Administrator (Initial Configuration)
    # Storage Administrator (Local Copy)
    # Storage Administrator (Performance Management)
    # Storage Administrator (Provisioning)
    # Storage Administrator (Remote Copy)
    # Storage Administrator (System Resource Management)
    # Storage Administrator (View Only)
    # Support Personnel#
    # User Maintenance#
    #: If you specify this role, be sure to specify true for hasAllResourceGroup.

    role_names_mapping = {
        "AUDIT_LOG_ADMIN_VIEW_N_MODIFY": "Audit Log Administrator (View & Modify)",
        "AUDIT_LOG_ADMIN_VIEW_ONLY": "Audit Log Administrator (View Only)",
        "SECURITY_ADMIN_VIEW_N_MODIFY": "Security Administrator (View & Modify)",
        "SECURITY_ADMIN_VIEW_ONLY": "Security Administrator (View Only)",
        "STORAGE_ADMIN_INIT_CONFIG": "Storage Administrator (Initial Configuration)",
        "STORAGE_ADMIN_LOCAL_COPY": "Storage Administrator (Local Copy)",
        "STORAGE_ADMIN_PERF_MGMT": "Storage Administrator (Performance Management)",
        "STORAGE_ADMIN_PROVISION": "Storage Administrator (Provisioning)",
        "STORAGE_ADMIN_REMOTE_COPY": "Storage Administrator (Remote Copy)",
        "STORAGE_ADMIN_SYS_RESOURCE_MGMT": "Storage Administrator (System Resource Management)",
        "STORAGE_ADMIN_VIEW_ONLY": "Storage Administrator (View Only)",
        "SUPPORT_PERSONNEL": "Support Personnel",
        "USER_MAINTENANCE": "User Maintenance",
    }
    has_all_resource_group = [
        "AUDIT_LOG_ADMIN_VIEW_N_MODIFY",
        "AUDIT_LOG_ADMIN_VIEW_ONLY",
        "SECURITY_ADMIN_VIEW_N_MODIFY",
        "SECURITY_ADMIN_VIEW_ONLY",
        "SUPPORT_PERSONNEL",
        "USER_MAINTENANCE",
    ]

    @staticmethod
    def get_role_names(roles):
        roles_list = []

        for role in roles:
            out_role = RolesManager.role_names_mapping.get(role.upper())
            if out_role:
                roles_list.append(out_role)
            else:
                logger.writeDebug(f"Did not find role name for {role}")
        return roles_list

    @staticmethod
    def get_has_all_resource_groups(roles):

        for role in roles:
            if role in RolesManager.has_all_resource_group:
                return True

        return False
