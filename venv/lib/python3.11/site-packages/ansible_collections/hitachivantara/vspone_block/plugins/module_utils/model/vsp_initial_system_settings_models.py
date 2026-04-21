from dataclasses import dataclass
from typing import Optional, List

try:
    from .common_base_models import SingleBaseClass
except ImportError:
    from .common_base_models import SingleBaseClass


@dataclass
class UploadFileSpec(SingleBaseClass):
    """
    Class representing the upload file specification.
    """

    file_type: Optional[str] = None
    file_path: Optional[str] = None


@dataclass
class SyslogServer(SingleBaseClass):
    """
    Class representing a syslog server.
    """

    isEnabled: Optional[bool] = None
    ipAddress: Optional[str] = None
    port: Optional[int] = None


@dataclass
class SyslogServerPfrest(SyslogServer):
    """
    Class representing a syslog server for PFREST.
    """

    clientCertFileName: Optional[str] = None
    clientCertFilePassword: Optional[str] = None
    rootCertFileName: Optional[str] = None


@dataclass
class SysLogServerSpec(SingleBaseClass):
    """
    Class representing the specification for a syslog server.
    """

    is_enabled: Optional[bool] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None
    client_cert_file_name: Optional[str] = None
    client_cert_file_password: Optional[str] = None
    root_cert_file_name: Optional[str] = None


@dataclass
class AuditLogFileDestResponse(SingleBaseClass):
    """
    Class representing the response for the audit log file destination.
    """

    transferProtocol: Optional[str] = None
    locationName: Optional[str] = None
    retries: Optional[bool] = None
    retryInterval: Optional[int] = None
    isDetailed: Optional[bool] = None
    primarySyslogServer: Optional[SyslogServer] = None
    secondarySyslogServer: Optional[SyslogServer] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "primarySyslogServer" in kwargs:
            self.primarySyslogServer = SyslogServer(**kwargs["primarySyslogServer"])
        if "secondarySyslogServer" in kwargs:
            self.secondarySyslogServer = SyslogServer(**kwargs["secondarySyslogServer"])


@dataclass
class SpecifyTransferDestinationFileSpec(SingleBaseClass):
    """
    Class representing the specification for the transfer destination file.
    """

    transfer_protocol: Optional[str] = None
    location_name: Optional[str] = None
    retries: Optional[bool] = None
    retry_interval: Optional[int] = None
    is_detailed: Optional[bool] = None
    primary_syslog_server: Optional[SysLogServerSpec] = None
    secondary_syslog_server: Optional[SyslogServer] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if kwargs.get("primary_syslog_server"):
            self.primary_syslog_server = SysLogServerSpec(
                **kwargs["primary_syslog_server"]
            )
        if kwargs.get("secondary_syslog_server"):
            self.secondary_syslog_server = SysLogServerSpec(
                **kwargs["secondary_syslog_server"]
            )


@dataclass
class SNMPEncryption(SingleBaseClass):
    """
    Class representing SNMP encryption settings.
    """

    protocol: Optional[str] = None
    key: Optional[str] = None


@dataclass
class SNMPAuthentication(SingleBaseClass):
    """
    Class representing SNMP authentication settings.
    """

    protocol: Optional[str] = None
    password: Optional[str] = None
    encryption: Optional[SNMPEncryption] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "encryption" in kwargs:
            self.encryption = SNMPEncryption(**kwargs["encryption"])


@dataclass
class SNMPV3Setting(SingleBaseClass):
    """
    Class representing an individual SNMPv3 setting.
    """

    userName: Optional[str] = None
    sendTrapTo: Optional[str] = None
    authentication: Optional[SNMPAuthentication] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "authentication" in kwargs:
            self.authentication = SNMPAuthentication(**kwargs["authentication"])


@dataclass
class SNMPV1V2CSetting(SingleBaseClass):
    """
    Class representing SNMPv1/v2c settings.
    """

    community: Optional[str] = None
    sendTrapTo: Optional[List[str]] = None


@dataclass
class SNMPV1V2CSettingAuth(SingleBaseClass):
    """
    Class representing SNMPv1/v2c settings.
    """

    community: Optional[str] = None
    requestsPermitted: Optional[List[str]] = None


@dataclass
class SNMPSendingTrapSetting(SingleBaseClass):
    """
    Class representing SNMP sending trap settings.
    """

    snmpv3Settings: Optional[List[SNMPV3Setting]] = None
    snmpv1v2cSettings: Optional[List[SNMPV1V2CSetting]] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "snmpv3Settings" in kwargs:
            self.snmpv3Settings = [
                SNMPV3Setting(**setting) for setting in kwargs["snmpv3Settings"]
            ]
        if "snmpv1v2cSettings" in kwargs:
            self.snmpv1v2cSettings = [
                SNMPV1V2CSetting(**setting) for setting in kwargs["snmpv1v2cSettings"]
            ]


@dataclass
class SNMPRequestAuthenticationSetting(SingleBaseClass):
    """
    Class representing SNMP request authentication settings.
    """

    snmpv3Settings: Optional[List[SNMPV3Setting]] = None
    snmpv1v2cSettings: Optional[List[SNMPV1V2CSettingAuth]] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "snmpv3Settings" in kwargs:
            self.snmpv3Settings = [
                SNMPV3Setting(**setting) for setting in kwargs["snmpv3Settings"]
            ]
        if "snmpv1v2cSettings" in kwargs:
            self.snmpv1v2cSettings = [
                SNMPV1V2CSettingAuth(**setting)
                for setting in kwargs["snmpv1v2cSettings"]
            ]


@dataclass
class SNMPSystemGroupInformation(SingleBaseClass):
    """
    Class representing SNMP system group information.
    """

    storageSystemName: Optional[str] = None
    contact: Optional[str] = None
    location: Optional[str] = None


@dataclass
class SNMPV3(SingleBaseClass):
    """
    Class representing SNMPv3 settings.
    """

    isSNMPAgentEnabled: Optional[bool] = None
    snmpVersion: Optional[str] = None
    sendingTrapSetting: Optional[SNMPSendingTrapSetting] = None
    requestAuthenticationSetting: Optional[SNMPRequestAuthenticationSetting] = None
    systemGroupInformation: Optional[SNMPSystemGroupInformation] = None
    snmpEngineID: Optional[str] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "sendingTrapSetting" in kwargs:
            self.sendingTrapSetting = SNMPSendingTrapSetting(
                **kwargs["sendingTrapSetting"]
            )
        if "requestAuthenticationSetting" in kwargs:
            self.requestAuthenticationSetting = SNMPRequestAuthenticationSetting(
                **kwargs["requestAuthenticationSetting"]
            )
        if "systemGroupInformation" in kwargs:
            self.systemGroupInformation = SNMPSystemGroupInformation(
                **kwargs["systemGroupInformation"]
            )


@dataclass
class SNMPEncryptionSpec(SingleBaseClass):
    """
    Class representing SNMP encryption settings.
    """

    protocol: Optional[str] = None
    key: Optional[str] = None


@dataclass
class SNMPAuthenticationSpec(SingleBaseClass):
    """
    Class representing SNMP authentication settings.
    """

    protocol: Optional[str] = None
    password: Optional[str] = None
    encryption: Optional[SNMPEncryption] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "encryption" in kwargs:
            self.encryption = SNMPEncryption(**kwargs["encryption"])


@dataclass
class SNMPV1V2CSettingSpec(SingleBaseClass):
    """
    Class representing SNMPv1/v2c settings.
    """

    community: Optional[str] = None
    send_trap_to: Optional[List[str]] = None


@dataclass
class SNMPV3SettingSpec(SingleBaseClass):
    """
    Class representing SNMPv3 settings.
    """

    user_name: Optional[str] = None
    send_trap_to: Optional[str] = None
    authentication: Optional[SNMPAuthenticationSpec] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if kwargs.get("authentication"):
            self.authentication = SNMPAuthentication(**kwargs["authentication"])


@dataclass
class SNMPV1V2CSettingAuthSpec(SingleBaseClass):
    """
    Class representing SNMPv1/v2c authentication settings.
    """

    community: Optional[str] = None
    requests_permitted: Optional[List[str]] = None


@dataclass
class SNMPV3AuthSetting(SingleBaseClass):
    """
    Class representing SNMPv3 authentication settings.
    """

    user_name: Optional[str] = None
    authentication: Optional[SNMPAuthenticationSpec] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "authentication" in kwargs:
            self.authentication = SNMPAuthentication(**kwargs["authentication"])


@dataclass
class SNMPSystemGroupInformationSpec(SingleBaseClass):
    """
    Class representing SNMP system group information.
    """

    storage_system_name: Optional[str] = None
    contact: Optional[str] = None
    location: Optional[str] = None


@dataclass
class SNMPRequestSpec(SingleBaseClass):
    """
    Class representing SNMP request settings.
    """

    is_snmp_agent_enabled: Optional[bool] = None
    snmp_version: Optional[str] = None
    snmp_v1v2c_trap_destination_settings: Optional[SNMPV1V2CSettingSpec] = None
    snmp_v3_trap_destination_settings: Optional[SNMPV3SettingSpec] = None
    snmp_v1v2c_authentication_settings: Optional[SNMPV1V2CSettingAuthSpec] = None
    snmp_v3_authentication_settings: Optional[SNMPV3AuthSetting] = None
    system_group_information: Optional[SNMPSystemGroupInformationSpec] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if kwargs.get("snmp_v1v2c_trap_destination_settings"):
            self.snmp_v1v2c_trap_destination_settings = [
                SNMPV1V2CSettingSpec(**setting)
                for setting in kwargs["snmp_v1v2c_trap_destination_settings"]
            ]
        if kwargs.get("snmp_v3_trap_destination_settings"):
            self.snmp_v3_trap_destination_settings = [
                SNMPV3SettingSpec(**setting)
                for setting in kwargs["snmp_v3_trap_destination_settings"]
            ]
        if kwargs.get("snmp_v1v2c_authentication_settings"):
            self.snmp_v1v2c_authentication_settings = [
                SNMPV1V2CSettingAuthSpec(**setting)
                for setting in kwargs["snmp_v1v2c_authentication_settings"]
            ]
        if kwargs.get("snmp_v3_authentication_settings"):
            self.snmp_v3_authentication_settings = [
                SNMPV3AuthSetting(**setting)
                for setting in kwargs["snmp_v3_authentication_settings"]
            ]
        if kwargs.get("system_group_information"):
            self.system_group_information = SNMPSystemGroupInformationSpec(
                **kwargs["system_group_information"]
            )
