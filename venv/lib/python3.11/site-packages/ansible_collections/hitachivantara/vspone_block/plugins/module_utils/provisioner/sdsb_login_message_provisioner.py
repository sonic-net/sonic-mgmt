import re

try:
    from ..gateway.gateway_factory import GatewayFactory
    from ..common.hv_constants import GatewayClassTypes
    from ..common.ansible_common import log_entry_exit
    from ..message.sdsb_login_message_msg import SDSBLoginMessageValidationMsg
except ImportError:
    from gateway.gateway_factory import GatewayFactory
    from common.hv_constants import GatewayClassTypes
    from common.ansible_common import log_entry_exit
    from message.sdsb_login_message_msg import SDSBLoginMessageValidationMsg


class SDSBLoginMessageProvisioner:

    def __init__(self, connection_info):
        self.connection_info = connection_info
        self.gateway = GatewayFactory.get_gateway(
            connection_info, GatewayClassTypes.SDSB_LOGIN_MESSAGE
        )

    @log_entry_exit
    def get_login_message(self):
        response = self.gateway.get_login_message()
        return response

    @log_entry_exit
    def validate_login_message(self, message):

        if not isinstance(message, str):
            raise ValueError(SDSBLoginMessageValidationMsg.MESSAGE_STR.value)

        if len(message) > 6144:
            raise ValueError(SDSBLoginMessageValidationMsg.MESSAGE_LIMIT.value)

        # Allowed characters pattern
        pattern = re.compile(
            r'^[a-zA-Z0-9!"#\$%&\'\(\)\*\+,\-\.\/:;<=>\?@\[\]\\\^_`\{\|\}~\t\r\n ]{0,6144}$'
        )
        if not pattern.match(message):
            raise ValueError(
                SDSBLoginMessageValidationMsg.INVALID_CHAR.value.format(message)
            )

    @log_entry_exit
    def update_login_message(self, spec):
        message = spec.message
        if message is None:
            raise ValueError(SDSBLoginMessageValidationMsg.NO_SPEC.value)

        # validate message using helper
        self.validate_login_message(message)

        # get current message from gateway
        current_data = self.gateway.get_login_message()
        current_message = ""

        if isinstance(current_data, dict):
            current_message = current_data.get("message", "")

        # skip if unchanged
        if message == current_message:
            return current_data

        # perform update
        self.gateway.update_login_message(message)
        self.connection_info.changed = True
        return message
