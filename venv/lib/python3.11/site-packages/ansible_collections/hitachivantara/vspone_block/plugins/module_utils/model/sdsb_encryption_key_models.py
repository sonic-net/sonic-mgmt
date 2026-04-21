from dataclasses import dataclass
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class EncryptionKeyFactSpec:
    key_id: Optional[str] = None
    id: Optional[str] = None
    count: Optional[int] = None
    key_type: Optional[str] = None
    target_resource_id: Optional[str] = None
    target_resource_name: Optional[str] = None
    start_creation_time: Optional[str] = None
    end_creation_time: Optional[str] = None


@dataclass
class EncryptionKeySpec(SingleBaseClass):
    number_of_keys: Optional[int] = None
    key_type: Optional[str] = None
    target_resource_id: Optional[str] = None
    key_id: Optional[str] = None
    id: Optional[str] = None


@dataclass
class EncryptionEnvironmentSettingsSpec(SingleBaseClass):
    is_encryption_enabled: Optional[bool] = None


@dataclass
class StoragePoolEncryptionSettingsSpec(SingleBaseClass):
    pool_id: Optional[str] = None
    encryption_enabled: Optional[bool] = None
    encryption_key_id: Optional[str] = None


@dataclass
class EncryptionKeyInfo(SingleBaseClass):
    id: str = None
    created_time: str = None
    createdTime: str = None
    key_type: str = None
    keyType: str = None
    target_information: str = None
    targetInformation: str = None
    target_name: str = None
    targetName: str = None
    key_generated_location: str = None
    keyGeneratedLocation: str = None
    number_of_backups: int = None
    numberOfBackups: int = None


@dataclass
class EncryptionKeyInfoList(BaseDataClass):
    data: List[EncryptionKeyInfo] = None


@dataclass
class EncryptionKeyResponse(SingleBaseClass):
    isEnabled: bool = None
    kms: bool = None
    warningThresholdOfFreeKeys: int = None

    def camel_to_snake_dict(self):
        transformed_response = {
            "is_enabled": self.isEnabled,
            "is_encryption_key_management_server_in_use": self.kms,
            "free_keys_warning_threshold": self.warningThresholdOfFreeKeys,
        }
        return transformed_response


@dataclass
class EncryptionKeyInfoSpec(SingleBaseClass):
    key_id: Optional[str] = None
    id: Optional[str] = None
    count: Optional[int] = None
    key_type: Optional[str] = None
    target_resource_id: Optional[str] = None
    target_resource_name: Optional[str] = None
    start_creation_time: Optional[str] = None
    end_creation_time: Optional[str] = None

    def generate_request_params(self):
        params = []
        if self.key_type is not None:
            params.append(f"keyType={self.key_type}")
        if self.count is not None:
            params.append(f"count={self.count}")
        if self.target_resource_id is not None:
            params.append(f"targetResourceId={self.target_resource_id}")
        if self.target_resource_name is not None:
            params.append(f"targetResourceName={self.target_resource_name}")
        if self.start_creation_time is not None:
            params.append(f"startCreationTime={self.start_creation_time}")
        if self.end_creation_time is not None:
            params.append(f"endCreationTime={self.end_creation_time}")
        return "&".join(params) if params else ""
