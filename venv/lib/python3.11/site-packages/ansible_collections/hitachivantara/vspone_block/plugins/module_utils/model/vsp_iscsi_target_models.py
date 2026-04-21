from dataclasses import dataclass
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from ..common.ansible_common import (
        dicts_to_dataclass_list,
        normalize_ldev_id,
        volume_id_to_hex_format,
    )
    from .vsp_host_group_models import LuHostReserve
except ImportError:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from common.ansible_common import (
        dicts_to_dataclass_list,
        normalize_ldev_id,
        volume_id_to_hex_format,
    )
    from vsp_host_group_models import LuHostReserve


@dataclass
class IscsiTargetFactSpec:
    subscriber_id: Optional[str] = None
    ports: Optional[List[str]] = None
    name: Optional[str] = None
    iscsi_id: Optional[int] = None
    lun: Optional[int] = None


@dataclass
class IscsiTargetChapUserSpec:
    chap_user_name: str = None
    chap_secret: str = None


@dataclass
class IscsiTarget(SingleBaseClass):
    iqn: str = None
    nick_name: str = None


@dataclass
class IscsiTargetSpec(SingleBaseClass):
    state: Optional[str] = None
    name: Optional[str] = None
    port: Optional[str] = None
    host_mode: Optional[str] = None
    host_mode_options: Optional[List[int]] = None
    ldevs: Optional[List[int]] = None
    iqn_initiators: Optional[List[IscsiTarget]] = None
    chap_users: Optional[List[IscsiTargetChapUserSpec]] = None
    should_delete_all_ldevs: Optional[bool] = None
    lun: Optional[int] = None
    should_release_host_reserve: Optional[bool] = None
    iscsi_id: Optional[int] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "chap_users" in kwargs and kwargs.get("chap_users") is not None:
            self.chap_users = dicts_to_dataclass_list(
                kwargs.get("chap_users"), IscsiTargetChapUserSpec
            )
        if "iqn_initiators" in kwargs and kwargs.get("iqn_initiators") is not None:
            self.iqn_initiators = [
                IscsiTarget(**target) for target in kwargs.get("iqn_initiators")
            ]
        self.__post_init__()

    def __post_init__(self):
        if self.ldevs:
            self.ldevs = [normalize_ldev_id(ldev) for ldev in self.ldevs]


@dataclass
class VSPPortInfo(SingleBaseClass):
    portId: str = None
    portType: str = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "type" in kwargs:
            self.portType = kwargs.get("type")
        elif "portInfo" in kwargs:
            if "portType" in kwargs.get("portInfo"):
                self.portType = kwargs.get("portInfo").get("portType")


@dataclass
class VSPPortsInfo(BaseDataClass):
    data: List[VSPPortInfo]


@dataclass
class VSPPortInfoV3(SingleBaseClass):
    resourceId: str = None
    portType: str = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "portInfo" in kwargs:
            if "portType" in kwargs.get("portInfo"):
                self.portType = kwargs.get("portInfo").get("portType")


@dataclass
class VSPPortsInfoV3(BaseDataClass):
    data: List[VSPPortInfoV3]


@dataclass
class VSPIqnInitiatorDirectGw(SingleBaseClass):
    iscsiName: str = None
    iscsiNickname: str = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class VSPLunDirectGw(SingleBaseClass):
    lun: int = None
    ldevId: int = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class VSPLunDirectGwDetailed(SingleBaseClass):
    lun: int = None
    ldevId: int = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class VSPChapUserDirectGw(SingleBaseClass):
    chapUserName: str = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class VSPHostModeOptionsInfo(SingleBaseClass):
    raidOption: str = None
    raidOptionNumber: int = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class VSPHostModeInfo(SingleBaseClass):
    hostMode: str = None
    hostModeOptions: List[VSPHostModeOptionsInfo] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "hostModeOptions" in kwargs and kwargs.get("hostModeOptions") is not None:
            self.hostModeOptions = dicts_to_dataclass_list(
                kwargs.get("hostModeOptions"), VSPHostModeOptionsInfo
            )


@dataclass
class VSPLogicalUnitInfo(SingleBaseClass):
    hostLun: int = None
    logicalUnitId: int = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class VSPLogicalUnitInfoDetails(SingleBaseClass):
    hostLun: int = None
    logicalUnitId: int = None
    ldevId: int = None
    ldevIdHex: str = None
    portId: Optional[str] = None
    hostGroupNumber: Optional[int] = None
    hostMode: Optional[str] = None
    lunId: Optional[str] = None
    isCommandDevice: Optional[bool] = None
    luHostReserve: Optional[LuHostReserve] = None
    hostModeOptions: Optional[List] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.luHostReserve = (
            LuHostReserve(**kwargs.get("luHostReserve"))
            if kwargs.get("luHostReserve")
            else None
        )
        if self.logicalUnitId:
            self.ldevId = self.logicalUnitId
            self.ldevIdHex = volume_id_to_hex_format(self.ldevId)


@dataclass
class IscsiIqn(SingleBaseClass):
    iqn: str = None
    nick_name: str = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


@dataclass
class VSPAuthParamInfo:
    isChapEnabled: bool = None
    isChapRequired: bool = None
    isMutualAuth: bool = None
    authenticationMode: str = None


@dataclass
class VSPIscsiTargetInfo(SingleBaseClass):
    resourceId: str = None
    portId: str = None
    hostMode: VSPHostModeInfo = None
    resourceGroupId: int = None
    iqn: str = None
    iqnInitiators: List[IscsiIqn] = None
    logicalUnits: List[VSPLogicalUnitInfo] = None
    authParam: VSPAuthParamInfo = None
    subscriberId: str = None
    partnerId: str = None
    storageId: str = None
    chapUsers: List[str] = None
    iscsiName: str = None
    iscsiId: int = None
    entitlementStatus: str = None
    type: str = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "hostMode" in kwargs and kwargs.get("hostMode") is not None:
            self.hostMode = VSPHostModeInfo(**kwargs.get("hostMode"))

        if "logicalUnits" in kwargs and kwargs.get("logicalUnits") is not None:
            if (
                kwargs.get("logicalUnits")
                and "luHostReserve" in kwargs.get("logicalUnits")[0].keys()
            ):
                self.logicalUnits = [
                    VSPLogicalUnitInfoDetails(**lunPath)
                    for lunPath in kwargs.get("logicalUnits")
                ]
            else:
                self.logicalUnits = dicts_to_dataclass_list(
                    kwargs.get("logicalUnits"), VSPLogicalUnitInfo
                )

        if "authParam" in kwargs and kwargs.get("authParam") is not None:
            self.authParam = VSPAuthParamInfo(**kwargs.get("authParam"))

        if "iqnInitiators" in kwargs and kwargs.get("iqnInitiators") is not None:
            self.iqnInitiators = dicts_to_dataclass_list(
                kwargs.get("iqnInitiators"), IscsiIqn
            )

        tg_info = kwargs.get("iscsiTargetInfo")
        if tg_info:
            for key, value in tg_info.items():
                if not hasattr(self, key):
                    if key == "iSCSIName":
                        self.iscsiName = value
                    if key == "iSCSIId":
                        self.iscsiId = value
                    setattr(self, key, value)

        if kwargs.get("iSCSIName"):
            self.iscsiName = kwargs.get("iSCSIName")
        if kwargs.get("iSCSIId"):
            self.iscsiId = kwargs.get("iSCSIId")


@dataclass
class VSPIscsiTargetsInfo(BaseDataClass):
    data: List[VSPIscsiTargetInfo]


@dataclass
class VSPOneIscsiTargetInfo(BaseDataClass):
    data: VSPIscsiTargetInfo


@dataclass
class VSPIscsiTargetModificationInfo(SingleBaseClass):
    changed: bool = None
    iscsiTarget: VSPIscsiTargetInfo = None
    comments: List[str] = None
    comment: str = None
    changed: bool = None


@dataclass
class IscsiTargetPayLoad(SingleBaseClass):
    name: str = None
    port: str = None
    host_mode: str = None
    host_mode_options: List[int] = None
    luns: List[int] = None
    iqn_initiators: List[str] = None
    chap_users: List[IscsiTargetChapUserSpec] = None
    iscsi_id: int = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
