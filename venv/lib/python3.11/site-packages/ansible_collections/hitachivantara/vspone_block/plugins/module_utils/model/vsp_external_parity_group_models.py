from dataclasses import dataclass
from typing import Optional


@dataclass
class ExternalParityGroupFactSpec:
    external_parity_group: Optional[str] = None


@dataclass
class ExternalParityGroupSpec:
    external_parity_group_id: Optional[str] = None
    mp_blade_id: Optional[int] = None
    clpr_id: Optional[int] = None
    force: Optional[bool] = None
    external_path_group_id: Optional[int] = None
    port_id: Optional[str] = None
    external_wwn: Optional[str] = None
    lun_id: Optional[int] = None
    emulation_type: Optional[str] = None
    is_external_attribute_migration: Optional[bool] = None
    command_device_ldev_id: Optional[int] = None


@dataclass
class CreateExternalParityGroupObject:
    external_parity_group_id: Optional[str] = None
    external_path_group_id: Optional[int] = None
    port_id: Optional[str] = None
    external_wwn: Optional[str] = None
    lun_id: Optional[int] = None
    emulation_type: Optional[str] = None
    clpr_id: Optional[int] = None
    is_external_attribute_migration: Optional[bool] = None
    command_device_ldev_id: Optional[int] = None
