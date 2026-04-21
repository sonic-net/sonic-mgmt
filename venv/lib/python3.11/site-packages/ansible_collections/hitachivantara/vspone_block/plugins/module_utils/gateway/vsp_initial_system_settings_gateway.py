import mimetypes
import uuid

try:
    from .gateway_manager import VSPConnectionManager
    from ..common.hv_log import Log
    from ..common.ansible_common import log_entry_exit
    from ..common.vsp_constants import Endpoints, InitialConfig
    from ..model.vsp_initial_system_settings_models import (
        AuditLogFileDestResponse,
        UploadFileSpec,
        SpecifyTransferDestinationFileSpec,
        SyslogServerPfrest,
        SNMPV3,
        SNMPRequestSpec,
    )

except ImportError:
    from .gateway_manager import VSPConnectionManager
    from common.hv_log import Log
    from common.ansible_common import log_entry_exit
    from common.vsp_constants import Endpoints, InitialConfig
    from model.vsp_initial_system_settings_models import (
        AuditLogFileDestResponse,
        UploadFileSpec,
        SpecifyTransferDestinationFileSpec,
        SyslogServerPfrest,
        SNMPV3,
        SNMPRequestSpec,
    )


logger = Log()

CERT_FILE_DICT = {
    "primary_client": "AuditSyslogPrimaryClientCertFile",
    "secondary_client": "AuditSyslogSecondaryClientCertFile",
    "primary_root": "AuditSyslogPrimaryRootCertFile",
    "secondary_root": "AuditSyslogSecondaryRootCertFile",
}


class SystemSettingsGateway:
    """
    Gateway for system settings.
    """

    def __init__(self, connection_info):
        self.connection_manager = VSPConnectionManager(
            connection_info.address,
            connection_info.username,
            connection_info.password,
            connection_info.api_token,
        )
        self.connection_info = connection_info

    @log_entry_exit
    def upload_transfer_dest_file_for_audit_log(self, file_spec: UploadFileSpec):
        """
        Uploads the transfer destination file to the VSP system using multipart/form-data.
        """
        end_point = Endpoints.UPLOAD_TRANSFER_DESTINATION_FILE

        # Build file field details
        file_path = file_spec.file_path
        file_type_value = CERT_FILE_DICT.get(file_spec.file_type)
        filename = file_path.split("/")[-1]
        mimetype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        boundary = uuid.uuid4().hex

        try:
            with open(file_path, "rb") as file:
                file_content = file.read()

            # Construct multipart/form-data body
            delimiter = f"--{boundary}"
            ending = f"--{boundary}--"

            body_parts = [
                delimiter,
                'Content-Disposition: form-data; name="fileType"',
                "",
                file_type_value,
                delimiter,
                f'Content-Disposition: form-data; name="file"; filename="{filename}"',
                f"Content-Type: {mimetype}",
                "",
                file_content.decode("latin1"),
                ending,
                "",
            ]

            # Encode to bytes
            body = "\r\n".join(body_parts).encode("latin1")

            # Set headers
            headers = {
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Accept": "application/json",
            }

            response = self.connection_manager.post_without_job(
                end_point,
                data=body,
                headers_input=headers,
            )
            return response

        except Exception as e:
            logger.writeError(
                "GW:upload_transfer_dest_file:Failed to upload transfer destination file: {}",
                str(e),
            )
            raise e

    @log_entry_exit
    def get_audit_log_file_transfer_destination(self):
        """
        Get the audit log file transfer destination.
        """
        end_point = Endpoints.GET_AUDIT_LOG_FILE_TRANSFER_DESTINATION
        response = self.connection_manager.get(end_point)
        return AuditLogFileDestResponse(**response)

    @log_entry_exit
    def specify_transfer_destination_for_audit_log_file(
        self, spec: SpecifyTransferDestinationFileSpec
    ):
        """
        Specify the transfer destination file.
        """
        end_point = Endpoints.SPECIFY_TRANSFER_DESTINATION_FILE
        payload = {
            InitialConfig.transferProtocol: spec.transfer_protocol,
            InitialConfig.locationName: spec.location_name,
        }
        if spec.retries is not None:
            payload[InitialConfig.retries] = spec.retries

        if spec.retry_interval is not None:
            payload[InitialConfig.retryInterval] = spec.retry_interval

        if spec.is_detailed is not None:
            payload[InitialConfig.isDetailed] = spec.is_detailed

        if spec.primary_syslog_server is not None:
            payload[InitialConfig.primarySyslogServer] = self.set_syslog_server(
                spec.primary_syslog_server
            )
        if spec.secondary_syslog_server is not None:
            payload[InitialConfig.secondarySyslogServer] = self.set_syslog_server(
                spec.secondary_syslog_server
            )

        response = self.connection_manager.patch(end_point, data=payload)
        return response

    def set_syslog_server(self, syslog: SyslogServerPfrest):
        """
        Set the syslog server.
        """
        sys_log_config = {
            InitialConfig.isEnabled: syslog.is_enabled,
        }
        if syslog.ip_address is not None:
            sys_log_config[InitialConfig.ipAddress] = syslog.ip_address
        if syslog.port is not None:
            sys_log_config[InitialConfig.port] = syslog.port
        if syslog.client_cert_file_name is not None:
            sys_log_config[InitialConfig.clientCertFileName] = (
                syslog.client_cert_file_name
            )
        if syslog.client_cert_file_password is not None:
            sys_log_config[InitialConfig.clientCertFilePassword] = (
                syslog.client_cert_file_password
            )
        if syslog.root_cert_file_name is not None:
            sys_log_config[InitialConfig.rootCertFileName] = syslog.root_cert_file_name
        return sys_log_config

    @log_entry_exit
    def send_test_msg_to_transfer_destination(self):
        """
        Send a test message to the transfer destination.
        """
        end_point = Endpoints.SEND_TEST_MESSAGE
        response = None
        try:
            response = self.connection_manager.post(end_point, None)
        except Exception as e:
            if "affectedResources" in str(e):
                return True
            else:
                logger.writeError(
                    "GW:send_test_msg_to_transfer_destination:Failed to send test message: {}",
                    str(e),
                )
                raise e
        return response

    @log_entry_exit
    def get_snmp_settings(self):
        """
        Get the syslog server.
        """
        end_point = Endpoints.GET_SNMP_SETTINGS
        response = self.connection_manager.get(end_point)
        return SNMPV3(**response)

    @log_entry_exit
    def specify_snmp_error_notification_destination(self, spec: SNMPRequestSpec):
        """
        Specify the syslog server.
        """
        payload = {}
        if spec.is_snmp_agent_enabled is not None:
            payload[InitialConfig.isSNMPAgentEnabled] = spec.is_snmp_agent_enabled
        if spec.snmp_version is not None:
            payload[InitialConfig.snmpVersion] = spec.snmp_version

        # Handle trap destination settings
        if (
            spec.snmp_v1v2c_trap_destination_settings
            or spec.snmp_v3_trap_destination_settings
        ):
            payload[InitialConfig.sendingTrapSetting] = {}

        if spec.snmp_v1v2c_trap_destination_settings:
            payload[InitialConfig.sendingTrapSetting][
                InitialConfig.snmpv1v2cSettings
            ] = self.__snmp_v1v2c_trap_destination_settings(
                spec.snmp_v1v2c_trap_destination_settings
            )

        if spec.snmp_v3_trap_destination_settings:
            payload[InitialConfig.sendingTrapSetting][InitialConfig.snmpv3Settings] = (
                self.__get_snmp_v3_trap_destination_settings(
                    spec.snmp_v3_trap_destination_settings
                )
            )

        # Handle authentication settings
        if (
            spec.snmp_v1v2c_authentication_settings
            or spec.snmp_v3_authentication_settings
        ):
            payload[InitialConfig.requestAuthenticationSetting] = {}

        if spec.snmp_v1v2c_authentication_settings:
            payload[InitialConfig.requestAuthenticationSetting][
                InitialConfig.snmpv1v2cSettings
            ] = self.__snmp_v1v2c_authentication_settings(
                spec.snmp_v1v2c_authentication_settings
            )

        if spec.snmp_v3_authentication_settings:
            payload[InitialConfig.requestAuthenticationSetting][
                InitialConfig.snmpv3Settings
            ] = self.__get_snmp_v3_trap_authentication_settings(
                spec.snmp_v3_authentication_settings
            )

        if spec.system_group_information:
            payload[InitialConfig.systemGroupInformation] = {}
            payload[InitialConfig.systemGroupInformation][
                InitialConfig.contact
            ] = spec.system_group_information.contact
            payload[InitialConfig.systemGroupInformation][
                InitialConfig.location
            ] = spec.system_group_information.location
            payload[InitialConfig.systemGroupInformation][
                InitialConfig.storageSystemName
            ] = spec.system_group_information.storage_system_name
        logger.writeDebug(
            "GW:specify_snmp_error_notification_destination:Payload for SNMP settings: {}",
            payload,
        )
        end_point = Endpoints.GET_SNMP_SETTINGS
        response = self.connection_manager.patch(end_point, payload)
        return response

    def __snmp_v1v2c_trap_destination_settings(self, settings):
        """
        Assign SNMP v3 trap destination settings.
        """
        snmpv1v2cSettings = []
        for setting in settings:
            snmpv1v2cSetting = {}
            snmpv1v2cSetting[InitialConfig.community] = setting.community
            snmpv1v2cSetting[InitialConfig.sendTrapTo] = setting.send_trap_to
            snmpv1v2cSettings.append(snmpv1v2cSetting)
        return snmpv1v2cSettings

    def __get_snmp_v3_trap_destination_settings(self, settings):
        """
        Assign SNMP v3 trap destination settings.
        """
        snmpv3Settings = []
        for setting in settings:
            snmpv3Setting = {}
            snmpv3Setting[InitialConfig.userName] = setting.user_name
            snmpv3Setting[InitialConfig.sendTrapTo] = setting.send_trap_to
            snmpv3Setting[InitialConfig.authentication] = {}
            if setting.authentication:
                snmpv3Setting[InitialConfig.authentication][
                    InitialConfig.protocol
                ] = setting.authentication.protocol
                snmpv3Setting[InitialConfig.authentication][
                    InitialConfig.password
                ] = setting.authentication.password
                snmpv3Setting[InitialConfig.authentication][
                    InitialConfig.encryption
                ] = {}
                if setting.authentication.encryption:
                    snmpv3Setting[InitialConfig.authentication][
                        InitialConfig.encryption
                    ][
                        InitialConfig.protocol
                    ] = setting.authentication.encryption.protocol
                    snmpv3Setting[InitialConfig.authentication][
                        InitialConfig.encryption
                    ][InitialConfig.key] = setting.authentication.encryption.key
            snmpv3Settings.append(snmpv3Setting)
        return snmpv3Settings

    def __snmp_v1v2c_authentication_settings(self, settings):
        """
        Assign SNMP v1v2c authentication settings.
        """
        snmpv1v2cAuthenticationSettings = []
        for setting in settings:
            snmpv1v2cAuthenticationSetting = {}
            snmpv1v2cAuthenticationSetting[InitialConfig.community] = setting.community
            snmpv1v2cAuthenticationSetting[InitialConfig.requestsPermitted] = (
                setting.requests_permitted
            )
            snmpv1v2cAuthenticationSettings.append(snmpv1v2cAuthenticationSetting)
        return snmpv1v2cAuthenticationSettings

    def __get_snmp_v3_trap_authentication_settings(self, settings):
        """
        Assign SNMP v3 trap destination settings.
        """
        snmpv3Settings = []
        for setting in settings:
            snmpv3Setting = {}
            snmpv3Setting[InitialConfig.userName] = setting.user_name
            snmpv3Setting[InitialConfig.authentication] = {}
            if setting.authentication:
                snmpv3Setting[InitialConfig.authentication][
                    InitialConfig.protocol
                ] = setting.authentication.protocol
                snmpv3Setting[InitialConfig.authentication][
                    InitialConfig.password
                ] = setting.authentication.password
                snmpv3Setting[InitialConfig.authentication][
                    InitialConfig.encryption
                ] = {}
                if setting.authentication.encryption:
                    snmpv3Setting[InitialConfig.authentication][
                        InitialConfig.encryption
                    ][
                        InitialConfig.protocol
                    ] = setting.authentication.encryption.protocol
                    snmpv3Setting[InitialConfig.authentication][
                        InitialConfig.encryption
                    ][InitialConfig.key] = setting.authentication.encryption.key
            snmpv3Settings.append(snmpv3Setting)
        return snmpv3Settings

    @log_entry_exit
    def send_test_snmp_trap(self):
        """
        Send a test message to the syslog server.
        """
        end_point = Endpoints.SEND_SNMP_TRAP
        response = None
        try:
            response = self.connection_manager.post(end_point, None)
        except Exception as e:
            if "affectedResources" in str(e):
                return True
            else:
                logger.writeError(
                    "GW:send_test_snmp_trap:Failed to send test SNMP trap: {}",
                    str(e),
                )
                raise e
        return response
