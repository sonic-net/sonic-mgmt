try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..model.vsp_user_group_models import (
        VspUserGroupInfo,
        VspUserGroupInfoList,
    )
    from .vsp_user_provisioner import VSPUserProvisioner
    from ..gateway.vsp_user_group_gateway import RolesManager
    from ..message.vsp_user_group_msgs import VSPUserGroupValidateMsg
except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from model.vsp_user_group_models import (
        VspUserGroupInfo,
        VspUserGroupInfoList,
    )
    from gateway.vsp_user_group_gateway import RolesManager
    from .vsp_user_provisioner import VSPUserProvisioner
    from message.vsp_user_group_msgs import VSPUserGroupValidateMsg


logger = Log()


class VSPUserGroupSubstates:
    """
    Enum class for User Group Substates
    """

    ADD_RESOURCE_GROUP = "add_resource_group"
    REMOVE_RESOURCE_GROUP = "remove_resource_group"
    ADD_ROLE = "add_role"
    REMOVE_ROLE = "remove_role"


class VSPUserGroupProvisioner:

    def __init__(self, connection_info, serial=None):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_USER_GROUP
        )
        self.connection_info = connection_info
        self.serial = serial
        self.users = None

    @log_entry_exit
    def get_user_groups(self, spec):
        if spec.id:
            user_group = self.get_user_group_by_id(spec.id)
            user_group = self.add_users_to_user_group(user_group)
            return VspUserGroupInfoList(data=[user_group])
        elif spec.name:
            user_group = self.get_user_group_by_name(spec.name)
            if user_group is None:
                return None
            else:
                user_group = self.filter_all_resource_group(user_group)
                user_group = self.add_users_to_user_group(user_group)
                return VspUserGroupInfoList(data=[user_group])
        else:
            user_groups = self.gateway.get_user_groups(spec)
            return self.filter_all_resource_groups(user_groups)

    @log_entry_exit
    def add_users_to_user_group(self, user_group):
        if self.users is None:
            user_prov = VSPUserProvisioner(self.connection_info)
            self.users = user_prov.get_users()
        user_group.users = []
        for user in self.users.data:
            if user_group.userGroupId in user.userGroupNames:
                user_group.users.append(user.userId)
            elif user_group.userGroupObjectId in user.userGroupNames:
                user_group.users.append(user.userId)
            else:
                pass
        return user_group

    @log_entry_exit
    def filter_all_resource_groups(self, user_groups):
        filtered_user_groups = []
        for user_group in user_groups.data:
            user_group = self.filter_all_resource_group(user_group)
            user_group = self.add_users_to_user_group(user_group)
            filtered_user_groups.append(user_group)
        return VspUserGroupInfoList(data=filtered_user_groups)

    @log_entry_exit
    def filter_all_resource_group(self, user_group):
        if user_group.hasAllResourceGroup is True:
            new_user_group_dict = {
                "userGroupObjectId": user_group.userGroupObjectId,
                "userGroupId": user_group.userGroupId,
                "roleNames": user_group.roleNames,
                "resourceGroupIds": ["ALL"],
                "isBuiltIn": user_group.isBuiltIn,
                "hasAllResourceGroup": user_group.hasAllResourceGroup,
            }
            return VspUserGroupInfo(**new_user_group_dict)
        return user_group

    @log_entry_exit
    def get_user_group_by_id(self, user_id):
        return self.gateway.get_user_group_by_id(user_id)

    @log_entry_exit
    def get_user_group_by_name(self, user_group_name):
        user_groups = self.gateway.get_user_groups()
        for user_group in user_groups.data:
            if user_group.userGroupId == user_group_name:
                return user_group
        return None

    @log_entry_exit
    def create_user_group(self, spec):
        return self.gateway.create_user_group(spec)

    @log_entry_exit
    def update_user_group(self, user_group, spec):
        user_group_id = None
        if spec.name:
            if user_group.userGroupId != spec.name:
                user_group_id = self.gateway.update_user_group_name(user_group, spec)

        if spec.role_names:
            if spec.state:
                if spec.state.lower() == VSPUserGroupSubstates.ADD_ROLE:
                    has_all_rgs = RolesManager.get_has_all_resource_groups(
                        spec.role_names
                    )
                    spec.has_all_resource_groups = has_all_rgs
                    new_roles = self.get_union_of_roles(
                        user_group.roleNames, spec.role_names
                    )
                    spec.role_names = new_roles
                elif spec.state.lower() == VSPUserGroupSubstates.REMOVE_ROLE:
                    has_all_rgs = RolesManager.get_has_all_resource_groups(
                        spec.role_names
                    )
                    spec.has_all_resource_groups = has_all_rgs
                    new_roles = self.get_subtraction_of_roles(
                        user_group.roleNames, spec.role_names
                    )
                    spec.role_names = new_roles
                if len(spec.role_names) == 0:
                    spec.role_names = ["STORAGE_ADMIN_VIEW_ONLY"]
                user_group_id = self.gateway.update_user_group_role_names(
                    user_group, spec
                )
            else:
                raise ValueError(
                    VSPUserGroupValidateMsg.INVALID_SPEC_STATE_FOR_ROLES.value
                )

        if spec.resource_group_ids:
            if spec.state:
                if spec.state.lower() == VSPUserGroupSubstates.ADD_RESOURCE_GROUP:
                    resource_groups_to_add = self.rgs_to_add(
                        user_group.resourceGroupIds, spec.resource_group_ids
                    )
                    spec.resource_group_ids = resource_groups_to_add
                    user_group_id = self.gateway.add_resource_group_to_user_group(
                        user_group, spec
                    )
                elif spec.state.lower() == VSPUserGroupSubstates.REMOVE_RESOURCE_GROUP:
                    resource_groups_to_remove = self.rgs_to_remove(
                        user_group.resourceGroupIds, spec.resource_group_ids
                    )
                    spec.resource_group_ids = resource_groups_to_remove
                    user_group_id = self.gateway.remove_resource_group_from_user_group(
                        user_group, spec
                    )
                else:
                    raise ValueError(
                        VSPUserGroupValidateMsg.INVALID_SPEC_STATE_FOR_RGS.value
                    )

        return user_group_id

    @log_entry_exit
    def get_union_of_roles(self, existing_roles: list, spec_role_names: list):
        spec_roles = RolesManager.get_role_names(spec_role_names)
        union_roles = set(existing_roles).union(set(spec_roles))
        return list(union_roles)

    @log_entry_exit
    def get_subtraction_of_roles(self, existing_roles: list, spec_role_names: list):
        spec_roles = RolesManager.get_role_names(spec_role_names)
        sub_roles = set(existing_roles) - set(spec_roles)
        return list(sub_roles)

    @log_entry_exit
    def delete_user_group(self, user_group, spec):
        return self.gateway.delete_user_group(user_group, spec)

    @log_entry_exit
    def rgs_to_add(self, ug_rgs: list, spec_rgs: list):
        if ug_rgs is None or len(ug_rgs) == 0:
            return spec_rgs

        if spec_rgs is None or len(spec_rgs) == 0:
            return []

        rgs_to_add = []
        for rg in spec_rgs:
            if rg not in ug_rgs:
                rgs_to_add.append(rg)
        return rgs_to_add

    @log_entry_exit
    def rgs_to_remove(self, ug_rgs: list, spec_rgs: list):
        if ug_rgs is None or len(ug_rgs) == 0:
            return spec_rgs

        if spec_rgs is None or len(spec_rgs) == 0:
            return []

        rgs_to_remove = []
        for rg in spec_rgs:
            if rg in ug_rgs:
                rgs_to_remove.append(rg)
        return rgs_to_remove
