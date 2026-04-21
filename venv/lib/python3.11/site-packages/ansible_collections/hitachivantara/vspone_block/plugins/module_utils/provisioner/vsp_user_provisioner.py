try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..model.vsp_user_models import (
        VspUserInfoList,
    )
except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from model.vsp_user_models import (
        VspUserInfoList,
    )

logger = Log()


class VSPUserSubstates:
    """
    Enum class for User Group Substates
    """

    ADD_USER_GROUP = "add_user_group"
    REMOVE_USER_GROUP = "remove_user_group"


class VSPUserProvisioner:

    def __init__(self, connection_info, serial=None):
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.VSP_USER
        )
        self.connection_info = connection_info
        self.serial = serial

    @log_entry_exit
    def get_users(self, spec=None):
        if spec is not None and spec.id:
            user = self.get_user_by_id(spec.id)
            if user is None:
                return None
            return VspUserInfoList(data=[user])
        elif spec is not None and spec.name:
            user = self.get_user_by_name(spec.name)
            if user is None:
                return None
            return VspUserInfoList(data=[user])
        else:
            return self.gateway.get_users(spec)

    @log_entry_exit
    def get_user_by_id(self, user_id):
        return self.gateway.get_user_by_id(user_id)

    @log_entry_exit
    def get_user_by_name(self, user_name):
        users = self.gateway.get_users()
        for user in users.data:
            if user.userId == user_name:
                return user
        return None

    @log_entry_exit
    def create_user(self, spec):
        return self.gateway.create_user(spec)

    @log_entry_exit
    def update_user(self, user, spec):
        user_id = user.userObjectId
        if spec.password:
            user_id = self.gateway.update_user_password(user, spec)
        if spec.state:
            if spec.state.lower() == VSPUserSubstates.ADD_USER_GROUP:
                user_id = self.gateway.add_user_to_user_group(user, spec)
            elif spec.state.lower() == VSPUserSubstates.REMOVE_USER_GROUP:
                user_id = self.gateway.remove_user_from_user_group(user, spec)

        return user_id

    @log_entry_exit
    def delete_user(self, user, spec):
        return self.gateway.delete_user(user, spec)
