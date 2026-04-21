try:
    from ..common.sdsb_constants import SDSBlockEndpoints
    from ..common.ansible_common import dicts_to_dataclass_list
    from ..model.sdsb_port_auth_models import SDSBPortAuthInfo
    from ..model.sdsb_port_models import SDSBComputePortsInfo, SDSBComputePortInfo
    from ..model.sdsb_chap_user_models import SDSBChapUsersInfo, SDSBChapUserInfo
    from ..common.ansible_common import log_entry_exit
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log

except ImportError:
    from common.sdsb_constants import SDSBlockEndpoints
    from common.ansible_common import dicts_to_dataclass_list
    from model.sdsb_port_auth_models import SDSBPortAuthInfo
    from model.sdsb_port_models import SDSBComputePortsInfo, SDSBComputePortInfo
    from model.sdsb_chap_user_models import SDSBChapUsersInfo, SDSBChapUserInfo
    from common.ansible_common import log_entry_exit
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log

logger = Log()


class SDSBPortAuthDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    @log_entry_exit
    def get_port_by_name(self, port_name):
        end_point = SDSBlockEndpoints.GET_PORT_BY_NAME.format(port_name)
        compute_ports_data = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_port_by_name:port_data={}", compute_ports_data)

        return SDSBComputePortsInfo(
            dicts_to_dataclass_list(compute_ports_data["data"], SDSBComputePortInfo)
        )

    @log_entry_exit
    def get_port_auth_settings(self, port_id):
        end_point = SDSBlockEndpoints.GET_PORT_AUTH_SETTINGS.format(port_id)
        data = self.connection_manager.get(end_point)
        return SDSBPortAuthInfo(**data)

    @log_entry_exit
    def get_port_chap_users(self, port_id):
        end_point = SDSBlockEndpoints.GET_PORT_AUTH_SETTINGS_CHAP_USERS.format(port_id)
        chap_user_data = self.connection_manager.get(end_point)
        logger.writeDebug("GW:get_chap_users:data={}", chap_user_data)
        return SDSBChapUsersInfo(
            dicts_to_dataclass_list(chap_user_data["data"], SDSBChapUserInfo)
        )

    @log_entry_exit
    def allow_chap_users_to_access_port(self, port_id, chap_user_id):
        body = {
            "chapUserId": str(chap_user_id),
        }
        end_point = SDSBlockEndpoints.POST_PORT_AUTH_SETTINGS_CHAP_USERS.format(port_id)
        chap_user_data = self.connection_manager.post(end_point, body)
        logger.writeDebug("GW:allow_chap_users_to_access_port:data={}", chap_user_data)
        return chap_user_data

    @log_entry_exit
    def remove_chap_user_access_from_port(self, port_id, chap_user_id):
        end_point = SDSBlockEndpoints.DELETE_PORT_AUTH_SETTINGS_CHAP_USERS.format(
            port_id, chap_user_id
        )
        chap_user_data = self.connection_manager.delete(end_point)
        logger.writeDebug(
            "GW:remove_chap_user_access_from_port:data={}", chap_user_data
        )
        return chap_user_data

    @log_entry_exit
    def update_port_auth_settings(
        self, port_id, auth_mode, is_discovery_chap_auth, is_mutual_chap_auth
    ):
        body = {
            "authMode": str(auth_mode),
            "isDiscoveryChapAuth": is_discovery_chap_auth,
            "isMutualChapAuth": is_mutual_chap_auth,
        }
        logger.writeDebug("GW:update_compute_node:body={}", body)
        end_point = SDSBlockEndpoints.PATCH_PORT_AUTH_SETTINGS.format(port_id)
        data = self.connection_manager.patch(end_point, body)
        logger.writeDebug("GW:update_port_auth_settings:data={}", data)
        return data
