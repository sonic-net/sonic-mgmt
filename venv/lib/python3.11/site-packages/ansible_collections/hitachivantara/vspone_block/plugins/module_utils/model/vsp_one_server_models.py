from dataclasses import dataclass
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from ..common.vsp_constants import (
        ServerPayloadConst,
    )
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class ServerFactsSpec(SingleBaseClass):
    nick_name: Optional[str] = None
    hba_wwn: Optional[str] = None
    iscsi_name: Optional[int] = None
    server_id: Optional[int] = None
    nick_name: Optional[str] = None
    include_details: Optional[bool] = None


@dataclass
class ServerHBAFactsSpec(SingleBaseClass):
    server_id: Optional[int] = None
    nick_name: Optional[str] = None
    hba_wwn: Optional[str] = None
    iscsi_name: Optional[int] = None


@dataclass
class HBASpec(SingleBaseClass):
    hba_wwn: Optional[str] = None
    iscsi_name: Optional[int] = None


@dataclass
class HostGroupSpec(SingleBaseClass):
    host_group_id: Optional[int] = None
    host_group_name: Optional[str] = None
    port_id: Optional[str] = None

    def __post_init__(self):
        if (self.host_group_id is not None and self.host_group_name is not None) or (
            self.host_group_id is None and self.host_group_name is None
        ):
            raise ValueError(
                "Either host_group_id or host_group_name must be provided, but not both"
            )
        if self.port_id is None:
            raise ValueError("port_id must be provided")


@dataclass
class IscsiTargetSpec(SingleBaseClass):
    iscsi_target_id: Optional[int] = None
    iscsi_target_name: Optional[str] = None
    port_id: Optional[str] = None

    def __post_init__(self):
        if (
            self.iscsi_target_id is not None and self.iscsi_target_name is not None
        ) or (self.iscsi_target_id is None and self.iscsi_target_name is None):
            raise ValueError(
                "Either iscsi_target_id or iscsi_target_name must be provided, but not both"
            )
        if self.port_id is None:
            raise ValueError("port_id must be provided")


@dataclass
class VspOneServerPath(SingleBaseClass):
    hbaWwn: Optional[str] = None
    iscsiName: Optional[str] = None
    portIds: Optional[List[str]] = None


@dataclass
class VspOneServerPathSpec(SingleBaseClass):
    hba_wwn: Optional[str] = None
    iscsi_name: Optional[str] = None
    port_ids: Optional[List[str]] = None

    def __post_init__(self):
        if (self.hba_wwn is not None and self.iscsi_name is not None) or (
            self.hba_wwn is None and self.iscsi_name is None
        ):
            raise ValueError(
                "Either hba_wwn or iscsi_name must be provided, but not both"
            )
        if self.port_ids is None or len(self.port_ids) == 0:
            raise ValueError("At least one port_id must be provided")


@dataclass
class IscsiTargetResponse(SingleBaseClass):
    portId: Optional[str] = None
    targetIscsiName: Optional[str] = None


@dataclass
class IscsiTargetList(BaseDataClass):
    data: List[IscsiTargetResponse] = None


@dataclass
class VspOneServerResponse(SingleBaseClass):
    id: Optional[int] = None
    nickname: Optional[str] = None
    protocol: Optional[str] = None
    osType: Optional[str] = None
    totalCapacity: Optional[int] = None
    usedCapacity: Optional[int] = None
    numberOfPaths: Optional[int] = None
    isInconsistent: Optional[bool] = None
    modificationInProgress: Optional[bool] = None
    compatibility: Optional[str] = None
    isReserved: Optional[bool] = None
    hasUnalignedOsTypes: Optional[bool] = None
    osTypeOptions: Optional[List[int]] = None
    numberOfVolumes: Optional[int] = None
    paths: Optional[List[VspOneServerPath]] = None
    hasNonFullmeshLuPaths: Optional[bool] = None
    hasUnalignedOsTypeOptions: Optional[bool] = None
    iscsiTargets: Optional[List[IscsiTargetList]] = None

    def __post_init__(self):
        if self.paths is not None:
            self.paths = [VspOneServerPath(**path) for path in self.paths]

        # if self.iscsiTargets is not None:
        #     self.iscsiTargets = IscsiTargetList(**self.iscsiTargets)


@dataclass
class VspOneServerList(BaseDataClass):
    data: List[VspOneServerResponse] = None


@dataclass
class WwnOfHBA(SingleBaseClass):
    serverId: Optional[int] = None
    hbaWwn: Optional[str] = None
    iscsiName: Optional[str] = None
    portIds: Optional[List[str]] = None


@dataclass
class WwnOfHBAList(BaseDataClass):
    data: List[WwnOfHBA] = None


@dataclass
class ServerPathsResponse(SingleBaseClass):
    id: Optional[str] = None
    serverId: Optional[int] = None
    hbaWwn: Optional[str] = None
    iscsiName: Optional[str] = None
    portId: Optional[str] = None


@dataclass
class ServerPathsList(BaseDataClass):
    data: List[ServerPathsResponse] = None


@dataclass
class ServerIscsiTargetsResponse(SingleBaseClass):
    portId: Optional[int] = None
    targetIscsiName: Optional[bool] = None


@dataclass
class ServerIscsiTargetsList(BaseDataClass):
    data: List[ServerIscsiTargetsResponse] = None


@dataclass
class IscsiTargetNameSpec(SingleBaseClass):
    target_iscsi_name: Optional[str] = None
    port_id: Optional[str] = None


@dataclass
class CreateServerSpec(SingleBaseClass):
    server_id: Optional[int] = None
    nick_name: Optional[int] = None
    protocol: Optional[int] = None
    os_type: Optional[str] = None
    host_hba_wwn: Optional[str] = None
    host_iscsi_name: Optional[str] = None
    port_ids: Optional[List[str]] = None
    is_reserved: Optional[bool] = None
    os_type_options: Optional[List[int]] = None
    hbas: Optional[List[HBASpec]] = None
    keep_lun_config: Optional[bool] = None
    host_groups: Optional[List[str]] = None
    iscsi_targets: Optional[List[str]] = None
    comments: Optional[List[str]] = None
    paths: Optional[List[VspOneServerPathSpec]] = None
    iscsi_target_settings: Optional[List[IscsiTargetNameSpec]] = None
    errors: Optional[List[str]] = None

    def __post_init__(self):
        if self.hbas is not None:
            self.hbas = [HBASpec(**hba) for hba in self.hbas]

        if self.host_groups is not None and self.iscsi_targets is not None:
            raise ValueError(
                "host_groups and iscsi_targets cannot be provided together"
            )

        if self.host_groups is not None:
            self.host_groups = [HostGroupSpec(**hg) for hg in self.host_groups]

        if self.iscsi_targets is not None:
            self.iscsi_targets = [IscsiTargetSpec(**it) for it in self.iscsi_targets]

        if self.paths is not None:
            self.paths = [VspOneServerPathSpec(**path) for path in self.paths]

        if self.iscsi_target_settings is not None:
            self.iscsi_target_settings = [
                IscsiTargetNameSpec(**target) for target in self.iscsi_target_settings
            ]

    def generate_create_payload(self):
        payload = {}
        if self.nick_name is not None:
            payload[ServerPayloadConst.serverNickname] = self.nick_name
        if self.protocol is not None:
            payload[ServerPayloadConst.protocol] = self.protocol
        if self.os_type is not None:
            payload[ServerPayloadConst.osType] = self.os_type
        if self.os_type_options is not None:
            payload[ServerPayloadConst.osTypeOptions] = self.os_type_options
        if self.is_reserved is not None:
            payload[ServerPayloadConst.isReserved] = self.is_reserved
        return payload

    def generate_server_settings_payload(self):
        payload = {}
        if self.nick_name is not None:
            payload[ServerPayloadConst.nickname] = self.nick_name
        if self.os_type is not None:
            payload[ServerPayloadConst.osType] = self.os_type
        if self.os_type_options is not None:
            payload[ServerPayloadConst.osTypeOptions] = self.os_type_options
        return payload


@dataclass
class VspOneServerHBAResponse(SingleBaseClass):
    serverId: Optional[int] = None
    hbaWwn: Optional[str] = None
    iscsiName: Optional[str] = None
    portIds: Optional[List[str]] = None


@dataclass
class VspOneServerHBAList(BaseDataClass):
    data: List[VspOneServerHBAResponse] = None
