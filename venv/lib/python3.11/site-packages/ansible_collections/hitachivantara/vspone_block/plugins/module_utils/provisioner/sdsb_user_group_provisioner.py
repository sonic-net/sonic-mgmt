try:
    from ..gateway.sdsb_user_group_gateway import SDSBUsersGroupGateway
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_log import Log
except ImportError:
    from gateway.sdsb_user_group_gateway import SDSBUsersGroupGateway
    from common.ansible_common import log_entry_exit
    from common.hv_log import Log

logger = Log()


class SDSBUserGroupProvisioner:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.gateway = SDSBUsersGroupGateway(connection_info)

    @log_entry_exit
    def get_user_groups(self, spec=None):
        if spec and spec.id:
            try:
                response = self.get_user_group_by_id(spec.id)
                return response if response else None
            except Exception as e:
                logger.writeException(e)
                return None
        response = self.gateway.get_user_groups(spec)
        return response.data_to_snake_case_list()

    @log_entry_exit
    def get_user_group_by_id(self, id):
        try:
            response = self.gateway.get_user_group_by_id(id)
            logger.writeDebug("PV:get_user_group_by_id:response={}", response)
            if response is None:
                return None
            else:
                return response.camel_to_snake_dict()
                # return response
        except Exception as e:
            logger.writeException(e)
            return None

    @log_entry_exit
    def create_user_group(self, spec=None):
        try:
            user_group = self.gateway.create_user_group(
                spec.id,
                spec.role_names,
                spec.external_group_name,
                spec.vps_id,
                spec.scope,
            )
            self.connection_info.changed = True
            return user_group.camel_to_snake_dict()
        except Exception as e:
            logger.writeException(e)
            spec.comments = str(e)
            return None

    @log_entry_exit
    def delete_user_group(self, spec=None):
        if spec and spec.id:
            try:
                response = self.gateway.delete_user_group(spec.id)
                spec.comments = f"Successfully deleted user group with id = {spec.id}."
                return True
            except Exception as e:
                logger.writeException(e)
                spec.comments = (
                    f"Not able to delete user group with id = {spec.id}. {str(e)}"
                )
                return False

    @log_entry_exit
    def update_user_group(self, spec=None):
        current_user_group = self.gateway.get_user_group_by_id(spec.id)
        logger.writeDebug(
            f"PV:update_user_group:current_user_group = {current_user_group}"
        )
        change_needed = self.is_update_required(current_user_group, spec)
        logger.writeDebug(f"PV:update_user_group:change_needed = {change_needed}")
        if change_needed:
            self.connection_info.changed = True
            user_group = self.gateway.update_user_group(
                spec.id, spec.role_names, spec.scope
            )
            logger.writeDebug(f"PV:update_user_group:user_group = {current_user_group}")
            return user_group.camel_to_snake_dict()
        else:
            return current_user_group.camel_to_snake_dict()

    @log_entry_exit
    def is_update_required(self, current_user, spec):
        current_role_names = current_user.roleNames
        current_scope = current_user.scope
        if spec.role_names:
            for x in spec.role_names:
                if x not in current_role_names:
                    return True
        if spec.scope:
            for x in spec.scope:
                if x not in current_scope:
                    return True
        return False
