try:
    from ..common.sdsb_constants import SDSBlockEndpoints
    from .gateway_manager import SDSBConnectionManager
    from ..common.hv_log import Log

except ImportError:
    from common.sdsb_constants import SDSBlockEndpoints
    from .gateway_manager import SDSBConnectionManager
    from common.hv_log import Log


logger = Log()


class SDSBBlockLoginMessageDirectGateway:

    def __init__(self, connection_info):
        self.connection_manager = SDSBConnectionManager(
            connection_info.address, connection_info.username, connection_info.password
        )

    def get_login_message(self):
        endpoint = SDSBlockEndpoints.GET_LOGIN_MESSAGE
        logger.writeDebug("GW:get_login_message:endpoint={}", endpoint)
        login_message = self.connection_manager.get(endpoint)
        logger.writeDebug("GW:get_login_message:data={}", login_message)
        return login_message

    def update_login_message(self, message):
        endpoint = SDSBlockEndpoints.GET_LOGIN_MESSAGE
        payload = {"message": message}
        return self.connection_manager.patch(endpoint, payload)
