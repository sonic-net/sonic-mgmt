try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..model.sdsb_chap_user_models import SDSBChapUsersInfo
    from ..common.ansible_common import log_entry_exit

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from model.sdsb_chap_user_models import SDSBChapUsersInfo
    from common.ansible_common import log_entry_exit


class SDSBChapUserProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_CHAP_USER
        )

    @log_entry_exit
    def get_chap_users(self, spec=None):
        chap_users = self.gateway.get_chap_users(spec)
        if spec is not None and spec.id is not None:
            ret_cu = []
            for cu in chap_users.data:
                if cu.id == spec.id:
                    ret_cu.append(cu)
            return SDSBChapUsersInfo(ret_cu)

        return chap_users

    @log_entry_exit
    def get_chap_user_by_id(self, id):
        return self.gateway.get_chap_user_by_id(id)

    @log_entry_exit
    def get_chap_user_by_name(self, name):
        return self.gateway.get_chap_user_by_name(name)

    @log_entry_exit
    def delete_chap_user_by_id(self, id):
        return self.gateway.delete_chap_user_by_id(id)

    @log_entry_exit
    def create_chap_user(self, spec):
        return self.gateway.create_chap_user(spec)

    @log_entry_exit
    def update_chap_user(self, spec):
        return self.gateway.update_chap_user(spec)
