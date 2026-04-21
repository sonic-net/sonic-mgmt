from dataclasses import dataclass
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from ..common.ansible_common import (
        dicts_to_dataclass_list,
        normalize_ldev_id,
        volume_id_to_hex_format,
    )
except ImportError:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from common.ansible_common import (
        dicts_to_dataclass_list,
        normalize_ldev_id,
        volume_id_to_hex_format,
    )


@dataclass
class GetHostGroupSpec:
    name: Optional[str] = None
    ports: Optional[List[str]] = None
    lun: Optional[int] = None
    query: Optional[List[str]] = None
    host_group_number: Optional[int] = None


@dataclass
class HostWWN(SingleBaseClass):
    wwn: str = None
    nick_name: str = None


@dataclass
class HostGroupSpec(SingleBaseClass):
    state: Optional[str] = None
    name: Optional[str] = None
    port: Optional[str] = None
    host_mode: Optional[str] = None
    host_mode_options: Optional[List[int]] = None
    ldevs: Optional[List[int]] = None
    wwns: Optional[List[HostWWN]] = None
    delete_all_luns: Optional[bool] = None
    asymmetric_access_priority: Optional[str] = None
    host_group_number: Optional[int] = None
    should_release_host_reserve: Optional[bool] = None
    lun: Optional[int] = None

    def __init__(self, **kwargs):
        for field in self.__dataclass_fields__.keys():
            setattr(self, field, kwargs.get(field, None))
        self.delete_all_luns = kwargs.get("should_delete_all_ldevs", None)
        self.__post_init__()

    def __post_init__(self):
        if self.wwns:
            self.wwns = [HostWWN(**wwn) for wwn in self.wwns]
        if self.ldevs:
            self.ldevs = [normalize_ldev_id(ldev_id) for ldev_id in self.ldevs]


@dataclass
class VSPPortResponse:
    portId: str = None
    portType: str = None

    def __init__(self, **kwargs):
        self.portId = kwargs.get("portId")
        self.portType = kwargs.get("portType")


@dataclass
class VSPWwnResponse:
    portId: str = None
    hostWwn: str = None
    wwnNickname: str = None

    def __init__(self, **kwargs):
        self.portId = kwargs.get("portId")
        self.hostWwn = kwargs.get("hostWwn")
        self.wwnNickname = kwargs.get("wwnNickname")


@dataclass
class LuHostReserve(SingleBaseClass):
    openSystem: bool = None
    persistent: bool = None
    pgrKey: bool = None
    mainframe: bool = None
    acaReserve: bool = None


@dataclass
class VSPLunResponse(SingleBaseClass):
    portId: Optional[str] = None
    lun: Optional[int] = None
    ldevId: Optional[int] = None
    hostGroupNumber: Optional[int] = None
    hostMode: Optional[str] = None
    lunId: Optional[str] = None
    isCommandDevice: Optional[bool] = None
    luHostReserve: Optional[LuHostReserve] = None
    asymmetricAccessState: Optional[str] = None
    isAluaEnabled: Optional[bool] = None
    hostModeOptions: Optional[List[str]] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.luHostReserve = (
            LuHostReserve(**kwargs.get("luHostReserve"))
            if kwargs.get("luHostReserve")
            else None
        )


@dataclass
class VSPLunResponses(BaseDataClass):
    data: List[VSPLunResponse] = None


@dataclass
class VSPHostModeOption(SingleBaseClass):
    hostModeOption: str = None
    hostModeOptionNumber: int = None


@dataclass
class VSPLunPathDetails(SingleBaseClass):
    ldevId: int = None
    ldevIdHex: str = None
    portId: str = None
    hostGroupNumber: int = None
    hostMode: str = None
    isCommandDevice: bool = None
    luHostReserve: Optional[LuHostReserve] = None
    lunId: str = None
    lun: int = None
    asymmetricAccessState: Optional[str] = None
    isAluaEnabled: Optional[bool] = None
    hostModeOptions: Optional[List[str]] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if kwargs.get("luHostReserve"):
            self.luHostReserve = LuHostReserve(**kwargs.get("luHostReserve"))
        self.__post_init__()

    def __post_init__(self):
        if self.ldevId:
            self.ldevIdHex = volume_id_to_hex_format(self.ldevId)


@dataclass
class VSPLunPath(SingleBaseClass):
    # lunId: int = None
    ldevId: int = None
    # portId: str = None
    lun: int = None
    # hostGroupNumber: int = None
    # hostMode: str = None

    # isCommandDevice: bool = None
    # luHostReserve: Optional[LuHostReserve] = None
    # hostModeOptions: List = None

    # def __init__(self, **kwargs):
    # if kwargs.get("luHostReserve"):
    #     self.luHostReserve = LuHostReserve(**kwargs.get("luHostReserve"))


@dataclass
class VSPWwn(SingleBaseClass):
    id: int = None
    nick_name: str = None


@dataclass
class VSPHostGroupInfo(SingleBaseClass):
    hostGroupId: int = None
    hostGroupName: str = None
    hostMode: str = None
    hostModeOptions: List[VSPHostModeOption] = None
    lunPaths: List[VSPLunPathDetails] = None
    wwns: List[VSPWwn] = None
    port: str = None
    resourceGroupId: int = None
    portId: str = None
    hostGroupNumber: int = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.hostGroupId = (
            kwargs.get("hostGroupNumber")
            if kwargs.get("hostGroupNumber") is not None
            else kwargs.get("hostGroupId")
        )
        self.hostGroupName = kwargs.get("hostGroupName")
        self.hostMode = kwargs.get("hostMode")
        if "hostModeOptions" in kwargs:
            self.hostModeOptions = dicts_to_dataclass_list(
                kwargs.get("hostModeOptions"), VSPHostModeOption
            )
        if "lunPaths" in kwargs:
            if (
                kwargs.get("lunPaths")
                and "luHostReserve" in kwargs.get("lunPaths")[0].keys()
            ):
                self.lunPaths = [
                    VSPLunPathDetails(**lunPath) for lunPath in kwargs.get("lunPaths")
                ]
            else:
                self.lunPaths = [
                    VSPLunPath(**lunPath) for lunPath in kwargs.get("lunPaths")
                ]
        if "wwns" in kwargs:
            self.wwns = [VSPWwn(**wwn) for wwn in kwargs.get("wwns")]
        self.port = kwargs.get("port")
        self.resourceGroupId = kwargs.get("resourceGroupId")
        self.__post__init__()

    def __post__init__(self):
        self.hostGroupNumber = self.hostGroupId

    def camel_to_snake_dict(self) -> dict:
        data = super().camel_to_snake_dict()
        data["port_id"] = data.pop("port")
        data.pop("host_group_number", None)
        return data


@dataclass
class VSPHostGroupsInfo(BaseDataClass):
    data: List[VSPHostGroupInfo]


@dataclass
class VSPOneHostGroupInfo(BaseDataClass):
    data: VSPHostGroupInfo


@dataclass
class VSPModifyHostGroupProvResponse(SingleBaseClass):
    changed: bool = None
    host_group: VSPHostGroupInfo = None
    comments: List[str] = None
    comment: str = None
    errors: List[str] = None

    def camel_to_snake_dict(self):
        data = super().camel_to_snake_dict()
        if not data.get("comment"):
            data.pop("comment")
        if not data.get("comments"):
            data.pop("comments")
        if not data.get("errors"):
            data.pop("errors")
        return data


@dataclass
class VSPHostGroupUAIGInfo(SingleBaseClass):
    hostGroupName: str = None
    hostGroupId: int = 0
    resourceGroupId: int = 0
    port: str = None
    hostMode: str = None


@dataclass
class VSPHostGroupUAIG(SingleBaseClass):
    resourceId: str = None
    type: str = None
    storageId: str = None
    entitlementStatus: str = None
    hostGroupInfo: VSPHostGroupUAIGInfo = None
    # 20240830 - without these, the create hur was breaking
    partnerId: str = None
    subscriberId: str = None
    hostGroupName: str = None
    hostGroupId: int = 0
    resourceGroupId: int = 0
    port: str = None
    hostMode: str = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        hg_info = kwargs.get("hostGroupInfo")
        if hg_info:
            for field in hg_info:
                if getattr(self, field) is None:
                    setattr(self, field, hg_info.get(field, None))


@dataclass
class VSPHostGroupsUAIG(BaseDataClass):
    data: List[VSPHostGroupUAIG] = None
