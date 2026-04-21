try:
    from ..gateway.sdsb_user_gateway import SDSBUserGateway
    from ..common.ansible_common import log_entry_exit
    from ..common.hv_log import Log
except ImportError:
    from gateway.sdsb_user_gateway import SDSBUserGateway
    from common.ansible_common import log_entry_exit
    from common.hv_log import Log

logger = Log()


class SDSBUsersProvisioner:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.gateway = SDSBUserGateway(connection_info)

    @log_entry_exit
    def get_users(self, spec=None):
        if spec and spec.id:
            try:
                response = self.get_user_by_id(spec.id)
                return response.camel_to_snake_dict()
            except Exception as e:
                logger.writeException(e)
                return None
        response = self.gateway.get_users(spec)
        return response.data_to_snake_case_list()

        # users = self.gateway.get_users(spec)
        # return users

    @log_entry_exit
    def get_user_by_id(self, id):
        return self.gateway.get_user_by_id(id)

    @log_entry_exit
    def create_user(self, spec=None):
        user = self.gateway.create_user(spec)
        return user.camel_to_snake_dict()

    @log_entry_exit
    def delete_user(self, spec=None):
        if spec and spec.id:
            try:
                response = self.gateway.delete_user(spec.id)
                spec.comments = f"Successfully deleted user with id = {spec.id}."
                return True
            except Exception as e:
                logger.writeException(e)
                spec.comments = f"Not able to delete user with id = {spec.id}. {str(e)}"
                return False

    @log_entry_exit
    def update_user(self, spec=None):
        user = self.gateway.update_user(spec.id, spec.password, spec.is_enabled)
        return user.camel_to_snake_dict()

    @log_entry_exit
    def update_user_password(self, spec=None):
        user = self.gateway.change_user_password(
            spec.id, spec.current_password, spec.new_password
        )
        return user.camel_to_snake_dict()

    @log_entry_exit
    def add_user_to_user_groups(self, spec):
        current_user = self.get_user_by_id(spec.id)
        logger.writeDebug(
            f"PV:is_change_needed_for_add_user:current_user = {current_user}"
        )
        change_needed = self.is_change_needed_for_add_user(
            current_user, spec.user_group_ids
        )
        if change_needed:
            self.connection_info.changed = True
            response = self.gateway.add_user_to_user_groups(
                spec.id, spec.user_group_ids
            )
            logger.writeDebug(f"PV:add_user_to_user_groups:response = {response}")
            return response.camel_to_snake_dict()
        else:
            return current_user.camel_to_snake_dict()

    @log_entry_exit
    def remove_user_from_user_groups(self, spec):
        current_user = self.get_user_by_id(spec.id)
        logger.writeDebug(
            f"PV:is_change_needed_for_remove_user:current_user = {current_user}"
        )
        change_needed = self.is_change_needed_for_remove_user(
            current_user, spec.user_group_ids
        )
        if change_needed:
            self.connection_info.changed = True
            response = self.gateway.remove_user_from_user_groups(
                spec.id, spec.user_group_ids
            )
            logger.writeDebug(f"PV:remove_user_from_user_groups:response = {response}")
            return response.camel_to_snake_dict()
        else:
            return current_user.camel_to_snake_dict()

    @log_entry_exit
    def is_change_needed_for_add_user(self, current_user, user_group_ids):
        current_user_groups = current_user.userGroups
        current_user_group_ids = []
        for x in current_user_groups:
            current_user_group_ids.append(x.userGroupId)
        for x in user_group_ids:
            if x not in current_user_group_ids:
                return True
        return False

    @log_entry_exit
    def is_change_needed_for_remove_user(self, current_user, user_group_ids):
        current_user_groups = current_user.userGroups
        current_user_group_ids = []
        for x in current_user_groups:
            current_user_group_ids.append(x.userGroupId)
        for x in user_group_ids:
            if x in current_user_group_ids:
                return True

        return False
