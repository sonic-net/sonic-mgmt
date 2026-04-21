try:
    from ..gateway.vsp_initial_system_settings_gateway import SystemSettingsGateway
    from ..common.ansible_common import log_entry_exit
    from ..message.vsp_initial_settings_msg import VspInitialMsg, ValidationMsg
    from ..model.vsp_initial_system_settings_models import SNMPRequestSpec
    from ..common.ansible_common import is_valid_email, is_valid_ip

except ImportError:
    from gateway.vsp_initial_system_settings_gateway import SystemSettingsGateway
    from common.ansible_common import log_entry_exit
    from message.vsp_initial_settings_msg import VspInitialMsg, ValidationMsg
    from ..model.vsp_initial_system_settings_models import SNMPRequestSpec
    from common.ansible_common import is_valid_email, is_valid_ip


class InitialSystemSettingsProvisioner:
    """
    This class is responsible for provisioning the initial system settings.
    """

    def __init__(self, connection_info):
        """
        Initialize the InitialSystemSettingsProvisioner with connection info and VSP object.
        """
        self.gateway = SystemSettingsGateway(connection_info=connection_info)

    @log_entry_exit
    def specify_transfer_dest_file_for_audit_log(self, spec):
        """
        Upload the transfer destination file to the VSP system.
        """
        self.gateway.specify_transfer_destination_for_audit_log_file(spec)
        self.gateway.connection_info.changed = True
        response = self.get_audit_log_file_transfer_destination()
        return response, VspInitialMsg.TRANSFER_DEST.value

    @log_entry_exit
    def get_audit_log_file_transfer_destination(self):
        """
        Get the audit log file transfer destination.
        """
        return (
            self.gateway.get_audit_log_file_transfer_destination().camel_to_snake_dict()
        )

    @log_entry_exit
    def specify_transfer_destination_for_audit_log_file(self, spec):
        """
        Set the audit log file transfer destination.
        """
        self.gateway.upload_transfer_dest_file_for_audit_log(spec)
        self.gateway.connection_info.changed = True
        return VspInitialMsg.CERT_FILE_UPLOAD.value

    @log_entry_exit
    def send_test_msg_to_transfer_destination(self):
        """
        Send a test message to the transfer destination.
        """
        self.gateway.send_test_msg_to_transfer_destination()
        self.gateway.connection_info.changed = True
        return VspInitialMsg.TRANSFER_DEST_TEST_MSG.value

    @log_entry_exit
    def get_snmp_facts(self):
        """
        Get the SNMP facts from the VSP system.
        """
        return self.gateway.get_snmp_settings()

    @log_entry_exit
    def create_update_snmp(self, spec):
        """
        Create or update the SNMP configuration.
        """
        # Validate the SNMP specification
        self.__validate_snmp_spec(spec)

        unused = self.gateway.specify_snmp_error_notification_destination(spec)
        response = self.get_snmp_facts().camel_to_snake_dict()
        self.gateway.connection_info.changed = True
        return response, VspInitialMsg.SNMP_UPDATE.value

    @log_entry_exit
    def send_test_msg_to_snmp(self):
        """
        Send a test message to the SNMP configuration.
        """
        self.gateway.send_test_snmp_trap()
        self.gateway.connection_info.changed = True
        return None, VspInitialMsg.SNMP_TEST_MSG.value

    def __validate_snmp_spec(self, spec: SNMPRequestSpec):
        """
        Validate the SNMP specification.
        """
        if spec.snmp_v1v2c_trap_destination_settings:
            for trap_dest in spec.snmp_v1v2c_trap_destination_settings:
                if trap_dest.send_trap_to:
                    if any(not is_valid_ip(ip) for ip in trap_dest.send_trap_to):
                        raise ValueError(ValidationMsg.INVALID_IP_ADDRESS_DEST.value)
        if spec.snmp_v1v2c_authentication_settings:
            for auth_setting in spec.snmp_v1v2c_authentication_settings:
                if auth_setting.requests_permitted:
                    if any(
                        not is_valid_ip(ip) for ip in auth_setting.requests_permitted
                    ):
                        raise ValueError(ValidationMsg.INVALID_IP_ADDRESS_AUTH.value)
        if spec.snmp_v3_trap_destination_settings:
            for trap_dest in spec.snmp_v3_trap_destination_settings:
                if trap_dest.send_trap_to:
                    if not is_valid_ip(trap_dest.send_trap_to):
                        raise ValueError(ValidationMsg.INVALID_IP_ADDRESS_DEST_V3.value)
        # if spec.snmp_v3_authentication_settings:
        #     for auth_setting in spec.snmp_v3_authentication_settings:
        #         if auth_setting.requests_permitted:
        #             if any(
        #                 not is_valid_ip(ip) for ip in auth_setting.requests_permitted
        #             ):
        #                 raise ValueError(ValidationMsg.INVALID_IP_ADDRESS_AUTH_V3.value)
        if not is_valid_email(spec.system_group_information.contact):
            raise ValueError(ValidationMsg.INVALID_EMAIL.value)
