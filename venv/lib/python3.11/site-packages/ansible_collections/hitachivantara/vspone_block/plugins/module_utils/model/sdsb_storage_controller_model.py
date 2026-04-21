from dataclasses import dataclass
from typing import Optional
from .common_base_models import BaseDataClass, SingleBaseClass
from ..common.ansible_common import match_value_with_case_insensitive


@dataclass
class SDSBStorageControllerFactSpec:

    primary_fault_domain_id: Optional[str] = None
    primary_fault_domain_name: Optional[str] = None
    id: Optional[str] = None


@dataclass
class SDSBStorageControllerSpec:
    id: Optional[str] = None
    is_detailed_logging_mode: Optional[bool] = None

    def is_empty(self):
        if self.id is None and self.is_detailed_logging_mode is None:
            return True
        else:
            return False


# Models for SNMP settings response
@dataclass
class SNMPV2cSetting(SingleBaseClass):
    community: Optional[str] = None
    sendTrapTo: Optional[list[str]] = None


@dataclass
class SNMPV2cSettingReqAuth(SingleBaseClass):
    community: Optional[str] = None
    requestsPermitted: Optional[list[str]] = None


@dataclass
class SendingTrapSetting(SingleBaseClass):
    snmpv2cSettings: Optional[list[SNMPV2cSetting]] = None

    def __post_init__(self):
        if self.snmpv2cSettings is not None:
            self.snmpv2cSettings = [
                SNMPV2cSetting(**item) if not isinstance(item, SNMPV2cSetting) else item
                for item in self.snmpv2cSettings
            ]


@dataclass
class RequestAuthenticationSetting(SingleBaseClass):
    snmpv2cSettings: Optional[list[SNMPV2cSettingReqAuth]] = None

    def __post_init__(self):
        if self.snmpv2cSettings is not None:
            self.snmpv2cSettings = [
                (
                    SNMPV2cSettingReqAuth(**item)
                    if not isinstance(item, SNMPV2cSettingReqAuth)
                    else item
                )
                for item in self.snmpv2cSettings
            ]


@dataclass
class SystemGroupInformation(SingleBaseClass):
    storageSystemName: Optional[str] = None
    contact: Optional[str] = None
    location: Optional[str] = None


@dataclass
class SNMPResponseModel(SingleBaseClass):
    isSNMPAgentEnabled: Optional[bool] = None
    snmpVersion: Optional[str] = None
    sendingTrapSetting: Optional[SendingTrapSetting] = None
    requestAuthenticationSetting: Optional[RequestAuthenticationSetting] = None
    systemGroupInformation: Optional[SystemGroupInformation] = None

    def __post_init__(self):
        if self.sendingTrapSetting is not None:
            self.sendingTrapSetting = SendingTrapSetting(**self.sendingTrapSetting)
        if self.requestAuthenticationSetting is not None:
            self.requestAuthenticationSetting = RequestAuthenticationSetting(
                **self.requestAuthenticationSetting
            )
        if self.systemGroupInformation is not None:
            self.systemGroupInformation = SystemGroupInformation(
                **self.systemGroupInformation
            )


# Models for SNMP settings request spec
@dataclass
class SNMPV2cSettingSpec(SingleBaseClass):
    community: Optional[str] = None
    send_trap_to: Optional[list[str]] = None


@dataclass
class SNMPV2cSettingReqAuthSpec(SingleBaseClass):
    community: Optional[str] = None
    requests_permitted: Optional[list[str]] = None


@dataclass
class SendingTrapSettingSpec(SingleBaseClass):
    snmpv2c_settings: Optional[list[SNMPV2cSettingSpec]] = None

    def __post_init__(self):
        if self.snmpv2c_settings is not None:
            self.snmpv2c_settings = [
                (
                    SNMPV2cSettingSpec(**item)
                    if not isinstance(item, SNMPV2cSettingSpec)
                    else item
                )
                for item in self.snmpv2c_settings
            ]


@dataclass
class RequestAuthenticationSettingSpec(SingleBaseClass):
    snmpv2c_settings: Optional[list[SNMPV2cSettingReqAuthSpec]] = None

    def __post_init__(self):
        if self.snmpv2c_settings is not None:
            self.snmpv2c_settings = [
                (
                    SNMPV2cSettingReqAuthSpec(**item)
                    if not isinstance(item, SNMPV2cSettingReqAuthSpec)
                    else item
                )
                for item in self.snmpv2c_settings
            ]


@dataclass
class SystemGroupInformationSpec(SingleBaseClass):
    storage_system_name: Optional[str] = None
    contact: Optional[str] = None
    location: Optional[str] = None


@dataclass
class SNMPModelSpec(SingleBaseClass):
    is_snmp_agent_enabled: Optional[bool] = None
    snmp_version: Optional[str] = None
    sending_trap_setting: Optional[SendingTrapSettingSpec] = None
    request_authentication_setting: Optional[RequestAuthenticationSettingSpec] = None
    system_group_information: Optional[SystemGroupInformationSpec] = None
    comment: Optional[str] = None

    def __post_init__(self):
        if self.sending_trap_setting is not None:
            self.sending_trap_setting = SendingTrapSettingSpec(
                **self.sending_trap_setting
            )
        if self.request_authentication_setting is not None:
            self.request_authentication_setting = RequestAuthenticationSettingSpec(
                **self.request_authentication_setting
            )
        if self.system_group_information is not None:
            self.system_group_information = SystemGroupInformationSpec(
                **self.system_group_information
            )

    def create_snmp_spec(self):
        spec = {}
        if self.is_snmp_agent_enabled is not None:
            spec["isSNMPAgentEnabled"] = self.is_snmp_agent_enabled
        if self.snmp_version is not None:
            spec["snmpVersion"] = self.snmp_version
        if self.sending_trap_setting is not None:
            sending_trap_spec = {}
            if self.sending_trap_setting.snmpv2c_settings is not None:
                sending_trap_spec["snmpv2cSettings"] = []
                for item in self.sending_trap_setting.snmpv2c_settings:
                    snmpv2c_dict = {}
                    if item.community is not None:
                        snmpv2c_dict["community"] = item.community
                    if item.send_trap_to is not None:
                        snmpv2c_dict["sendTrapTo"] = item.send_trap_to
                    sending_trap_spec["snmpv2cSettings"].append(snmpv2c_dict)
            spec["sendingTrapSetting"] = sending_trap_spec
        if self.request_authentication_setting is not None:
            request_auth_spec = {}
            if self.request_authentication_setting.snmpv2c_settings is not None:
                request_auth_spec["snmpv2cSettings"] = []
                for item in self.request_authentication_setting.snmpv2c_settings:
                    snmpv2c_req_dict = {}
                    if item.community is not None:
                        snmpv2c_req_dict["community"] = item.community
                    if item.requests_permitted is not None:
                        snmpv2c_req_dict["requestsPermitted"] = item.requests_permitted
                    request_auth_spec["snmpv2cSettings"].append(snmpv2c_req_dict)
            spec["requestAuthenticationSetting"] = request_auth_spec
        if self.system_group_information is not None:
            system_group_info_spec = {}
            if self.system_group_information.storage_system_name is not None:
                system_group_info_spec["storageSystemName"] = (
                    self.system_group_information.storage_system_name
                )
            if self.system_group_information.contact is not None:
                system_group_info_spec["contact"] = (
                    self.system_group_information.contact
                )
            if self.system_group_information.location is not None:
                system_group_info_spec["location"] = (
                    self.system_group_information.location
                )
            spec["systemGroupInformation"] = system_group_info_spec
        return spec


@dataclass
class SDSBStorageSpareNodeModel(SingleBaseClass):
    id: Optional[str] = None
    name: Optional[str] = None
    faultDomainId: Optional[str] = None
    faultDomainName: Optional[str] = None
    controlPortIpv4Address: Optional[str] = None
    softwareVersion: Optional[str] = None
    biosUuid: Optional[str] = None
    modelName: Optional[str] = None
    serialNumber: Optional[str] = None
    bmcName: Optional[str] = None
    bmcUser: Optional[str] = None


@dataclass
class SDSBStorageSpareNodeModels(BaseDataClass):
    data: list[SDSBStorageSpareNodeModel] = None


@dataclass
class SDSBSpareNodeSpec(SingleBaseClass):
    fault_domain_id: Optional[str] = None
    control_port_ipv4_address: Optional[str] = None
    setup_user_password: Optional[str] = None
    bmc_name: Optional[str] = None
    bmc_user: Optional[str] = None
    bmc_password: Optional[str] = None
    id: Optional[str] = None
    comment: Optional[str] = None

    def create_spare_node_spec(self):
        spec = {}
        if self.fault_domain_id is not None:
            spec["faultDomainId"] = self.fault_domain_id
        if self.control_port_ipv4_address is not None:
            spec["controlPortIpv4Address"] = self.control_port_ipv4_address
        if self.setup_user_password is not None:
            spec["setupUserPassword"] = self.setup_user_password
        if self.bmc_name is not None:
            spec["bmcName"] = self.bmc_name
        if self.bmc_user is not None:
            spec["bmcUser"] = self.bmc_user
        if self.bmc_password is not None:
            spec["bmcPassword"] = self.bmc_password
        return spec


@dataclass
class ProtectionDomainSettings(SingleBaseClass):
    totalPhysicalCapacity: Optional[int] = None
    isFastRebuildEnabled: Optional[bool] = None
    id: Optional[str] = None
    name: Optional[str] = None
    redundantPolicy: Optional[str] = None
    redundantType: Optional[str] = None
    driveDataRelocationStatus: Optional[str] = None
    driveDataRelocationProgressRate: Optional[int] = None
    rebuildStatus: Optional[str] = None
    rebuildProgressRate: Optional[int] = None
    memoryMode: Optional[str] = None
    asyncProcessingResourceUsageRate: Optional[str] = None
    numberOfFaultSets: Optional[int] = None
    storageControllerClusteringPolicy: Optional[str] = None
    minimumMemorySize: Optional[int] = None
    numberOfFaultDomains: Optional[int] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class ProtectionDomainSettingsList(BaseDataClass):
    data: list[ProtectionDomainSettings] = None


def get_snmp_settings_args() -> dict:

    args = {
        "is_snmp_agent_enabled": {
            "type": "bool",
            "required": False,
        },
        "snmp_version": {
            "type": "str",
            "required": False,
            "choices": ["v2c"],
            "default": "v2c",
        },
        "sending_trap_setting": {
            "type": "dict",
            "options": {
                "snmpv2c_settings": {
                    "type": "list",
                    "elements": "dict",
                    "options": {
                        "community": {
                            "type": "str",
                            "required": False,
                            "default": None,
                        },
                        "send_trap_to": {
                            "type": "list",
                            "elements": "str",
                            "required": False,
                        },
                    },
                    "required": False,
                }
            },
            "required": False,
        },
        "request_authentication_setting": {
            "type": "dict",
            "options": {
                "snmpv2c_settings": {
                    "type": "list",
                    "elements": "dict",
                    "options": {
                        "community": {
                            "type": "str",
                            "required": False,
                            "default": None,
                        },
                        "requests_permitted": {
                            "type": "list",
                            "elements": "str",
                            "required": False,
                        },
                    },
                    "required": False,
                }
            },
            "required": False,
        },
        "system_group_information": {
            "type": "dict",
            "options": {
                "storage_system_name": {
                    "type": "str",
                    "required": False,
                },
                "contact": {
                    "type": "str",
                    "required": False,
                },
                "location": {
                    "type": "str",
                    "required": False,
                },
            },
            "required": False,
        },
    }

    return args


@dataclass
class ProtectionDomainSpec(SingleBaseClass):
    id: Optional[str] = None
    async_processing_resource_usage_rate: Optional[str] = None
    comment: Optional[str] = None

    def __post_init__(self):
        valid_values = ["very_high", "high", "middle", "low"]
        mapped_values = {
            "very_high": "VeryHigh",
            "high": "High",
            "middle": "Middle",
            "low": "Low",
        }
        if self.async_processing_resource_usage_rate is not None:
            if not match_value_with_case_insensitive(
                self.async_processing_resource_usage_rate, valid_values
            ):
                raise ValueError(
                    f"Invalid async_processing_resource_usage_rate valid values are {valid_values} and this is case insensitive"
                )
            self.async_processing_resource_usage_rate = mapped_values.get(
                self.async_processing_resource_usage_rate.lower()
            )

    def create_protection_domain_spec(self):
        spec = {}
        if self.async_processing_resource_usage_rate is not None:
            spec["asyncProcessingResourceUsageRate"] = (
                self.async_processing_resource_usage_rate
            )
        return spec


@dataclass
class SpareNodeFactsSpec(SingleBaseClass):
    id: Optional[str] = None


@dataclass
class StorageSystemSpec(SingleBaseClass):
    root_certificate_file_path: Optional[str] = None
    download_path: Optional[str] = None
    enable_write_back_mode_with_cache_protection: Optional[bool] = None
    force: Optional[bool] = None
    comment: Optional[str] = None


@dataclass
class SDSBPfrestSavingEffectOfStorage(SingleBaseClass):
    efficiencyDataReduction: Optional[int] = None
    totalEfficiency: Optional[int] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class SDSBPStorageClusterInfo(SingleBaseClass):
    storageDeviceId: Optional[str] = None
    id: Optional[str] = None
    modelName: Optional[str] = None
    internalId: Optional[str] = None
    nickname: Optional[str] = None
    numberOfTotalVolumes: Optional[int] = None
    numberOfTotalServers: Optional[int] = None
    numberOfTotalStorageNodes: Optional[int] = None
    numberOfReadyStorageNodes: Optional[int] = None
    numberOfFaultDomains: Optional[int] = None
    totalPoolRawCapacity: Optional[int] = None
    totalPoolRawCapacityInMb: Optional[int] = None
    totalPoolPhysicalCapacity: Optional[int] = None
    totalPoolPhysicalCapacityInMb: Optional[int] = None
    totalPoolCapacity: Optional[int] = None
    totalPoolCapacityInMb: Optional[int] = None
    usedPoolCapacity: Optional[int] = None
    usedPoolCapacityInMb: Optional[int] = None
    freePoolCapacity: Optional[int] = None
    freePoolCapacityInMb: Optional[int] = None
    savingEffects: Optional[SDSBPfrestSavingEffectOfStorage] = None
    softwareVersion: Optional[str] = None
    statusSummary: Optional[str] = None
    status: Optional[str] = None
    writeBackModeWithCacheProtection: Optional[str] = None
    metaDataRedundancyOfCacheProtectionSummary: Optional[str] = None
    systemRequirementsFileVersion: Optional[str] = None
    serviceId: Optional[str] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.__post_init__()

    def __post_init__(self):
        if self.savingEffects is not None:
            self.savingEffects = SDSBPfrestSavingEffectOfStorage(**self.savingEffects)

        if self.freePoolCapacity is not None:
            self.freePoolCapacityInMb = int(self.freePoolCapacity)
        if self.totalPoolCapacity is not None:
            self.totalPoolCapacityInMb = int(self.totalPoolCapacity)
        if self.usedPoolCapacity is not None:
            self.usedPoolCapacityInMb = int(self.usedPoolCapacity)
        if self.totalPoolPhysicalCapacity is not None:
            self.totalPoolPhysicalCapacityInMb = int(self.totalPoolPhysicalCapacity)
        if self.totalPoolRawCapacity is not None:
            self.totalPoolRawCapacityInMb = int(self.totalPoolRawCapacity)


@dataclass
class ServerAllowSettingsSpec(SingleBaseClass):
    is_enabled: Optional[bool] = None
    client_names: Optional[list[str]] = None


@dataclass
class WebServerAccessSettingSpec(SingleBaseClass):
    enable_client_address_allowlist: Optional[bool] = None
    client_address_allowlist: Optional[list[str]] = None
    server_certificate_file_path: Optional[str] = None
    server_certificate_secret_key_file_path: Optional[str] = None
    comment: Optional[str] = None

    def create_server_allow_settings_spec(self):
        spec = {}
        if self.enable_client_address_allowlist is not None:
            spec["isEnabled"] = self.enable_client_address_allowlist
        if self.client_address_allowlist is not None:
            spec["clientNames"] = self.client_address_allowlist
        return spec

    def create_whitelist_settings_spec(self):
        spec = {}
        if self.whitelist_setting.is_enabled is not None:
            spec["isEnabled"] = self.whitelist_setting.is_enabled
        if self.whitelist_setting.client_names is not None:
            spec["clientNames"] = self.whitelist_setting.client_names
        return spec


@dataclass
class ServerAllowSettings(SingleBaseClass):
    isEnabled: Optional[bool] = None
    clientNames: Optional[list[str]] = None


@dataclass
class WebServerAccessSettingResponse(SingleBaseClass):
    allowlistSetting: Optional[dict] = None
    whitelistSetting: Optional[dict] = None

    def __post_init__(self):
        if self.allowlistSetting is not None:
            self.allowlistSetting = ServerAllowSettings(**self.allowlistSetting)
        if self.whitelistSetting is not None:
            self.whitelistSetting = ServerAllowSettings(**self.whitelistSetting)
