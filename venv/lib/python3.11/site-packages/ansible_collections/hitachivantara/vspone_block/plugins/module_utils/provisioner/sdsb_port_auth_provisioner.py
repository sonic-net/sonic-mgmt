try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.ansible_common import log_entry_exit

except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.ansible_common import log_entry_exit


class SDSBPortAuthProvisioner:

    def __init__(self, connection_info):

        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_PORT_AUTH
        )

    @log_entry_exit
    def get_port_by_name(self, port_name):
        port_data = self.gateway.get_port_by_name(port_name)
        if port_data is not None and len(port_data.data) > 0:
            return port_data.data[0]
        else:
            return None

    @log_entry_exit
    def get_port_auth_settings(self, port_id):
        return self.gateway.get_port_auth_settings(port_id)

    @log_entry_exit
    def get_port_chap_users(self, port_id):
        return self.gateway.get_port_chap_users(port_id)

    @log_entry_exit
    def allow_chap_users_to_access_port(self, port_id, chap_user_id):
        self.gateway.allow_chap_users_to_access_port(port_id, chap_user_id)

    @log_entry_exit
    def remove_chap_user_access_from_port(self, port_id, chap_user_id):
        self.gateway.remove_chap_user_access_from_port(port_id, chap_user_id)

    @log_entry_exit
    def update_port_auth_settings(
        self, port_id, auth_mode, is_discovery_chap_auth, is_mutual_chap_auth
    ):
        return self.gateway.update_port_auth_settings(
            port_id, auth_mode, is_discovery_chap_auth, is_mutual_chap_auth
        )
