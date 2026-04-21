from dataclasses import dataclass
from typing import List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from ..common.ansible_common import volume_id_to_hex_format
except ImportError:
    from .common_base_models import BaseDataClass, SingleBaseClass
    from common.ansible_common import volume_id_to_hex_format


copy_pace_mapping = {
    "L": "LOW",
    "M": "MEDIUM",
    "H": "HIGH",
}

SMPL = "SMPL"


@dataclass
class VSPMirrorUnit:
    muNumber: int = None
    consistencyGroupId: int = None
    journalStatus: str = None
    pathBlockadeWatchInMinutes: int = None
    copyPace: str = None
    copySpeed: int = None
    isDataCopying: bool = None


@dataclass
class VSPJournalPoolDirect(SingleBaseClass):
    journalId: str = None
    muNumber: int = None
    consistencyGroupId: int = None
    journalStatus: str = None
    numOfActivePaths: int = None
    usageRate: int = None
    qMarker: str = None
    qCount: int = None
    byteFormatCapacity: str = None
    blockCapacity: int = None
    numOfLdevs: int = None
    firstLdevId: int = None
    journalId: str = None
    isMainframe: bool = None
    isCacheModeEnabled: bool = None
    isInflowControlEnabled: bool = None
    dataOverflowWatchInSeconds: int = None
    copySpeed: int = None
    isDataCopying: bool = None
    mpBladeId: int = None
    mirrorUnits: List[VSPMirrorUnit] = None
    journalStatus: str = None

    def __post__init__(self, **kwargs):
        if self.mirrorUnits:
            self.mirrorUnits = [VSPMirrorUnit(**mu) for mu in self.mirrorUnits]


@dataclass
class VSPJournalPoolsDirect(BaseDataClass):
    data: List[VSPJournalPoolDirect]


@dataclass
class MirrorUnit(SingleBaseClass):
    activePathCount: int = None
    activePathWatchSeconds: int = None
    consistencyGroupId: int = None
    isDeltaResyncFailureFullCopy: bool = None
    pathBlockadeWatchSeconds: int = None
    qCount: int = None
    transferSpeedMBPS: bool = None
    status: str = None
    copyPace: str = None
    mirrorUnitId: int = None
    qMarker: int = None


@dataclass
class VSPJournalPool(SingleBaseClass):
    dataOverflowWatchSeconds: int = None
    isCacheModeEnabled: bool = None
    logicalUnitIds: list[int] = None
    ldevIds: list[int] = None
    ldevIdsHex: list[str] = None
    mpBladeId: int = None
    timerType: str = None
    totalCapacity: int = None
    type: str = None
    journalPoolId: int = None
    journalStatus: str = None
    mirrors: list[MirrorUnit] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if kwargs.get("journalId") is not None:
            # Mapping logic from VSPJournalPoolDirect fields to VSPJournalPool fields
            self.dataOverflowWatchSeconds = kwargs.get("dataOverflowWatchInSeconds")
            self.isCacheModeEnabled = kwargs.get("isCacheModeEnabled")
            self.mpBladeId = kwargs.get("mpBladeId")
            self.totalCapacity = (
                kwargs.get("byteFormatCapacity")
                .replace("G", "GB")
                .replace("T", "TB")
                .replace("M", "MB")
            )
            self.journalPoolId = kwargs.get("journalId")
            self.journalStatus = kwargs.get("journalStatus")
            self.numOfLdevs = kwargs.get("numOfLdevs")
            # Convert nested mirror units if present
            mirror_units = kwargs.get("mirrorUnits", [])
            self.mirrors = [
                MirrorUnit(
                    consistencyGroupId=mu.get("consistencyGroupId"),
                    pathBlockadeWatchSeconds=(
                        mu.get("pathBlockadeWatchInMinutes", 0) * 60
                        if mu.get("pathBlockadeWatchInMinutes")
                        else None
                    ),
                    transferSpeedMBPS=mu.get("copySpeed"),
                    status=mu.get("journalStatus"),
                    copyPace=copy_pace_mapping.get(mu.get("copyPace").upper()),
                    mirrorUnitId=mu.get("muNumber"),
                )
                for mu in mirror_units
            ]
        self.__post_init__()

    def __post_init__(self):

        if self.mirrors and not isinstance(self.mirrors[0], MirrorUnit):
            self.mirrors = [MirrorUnit(**mu) for mu in self.mirrors]

        if self.mirrors:
            self.journalStatus = (
                SMPL
                if all(mu.status.upper() == SMPL for mu in self.mirrors)
                else next(
                    (mu.status for mu in self.mirrors if mu.status.upper() != SMPL),
                    None,
                )
            )

    def camel_to_snake_dict(self):
        if self.ldevIdsHex is None:
            self.ldevIdsHex = [
                volume_id_to_hex_format(lun_id) for lun_id in self.logicalUnitIds
            ]
        if self.ldevIds is None:
            self.ldevIds = self.logicalUnitIds
        data = super().camel_to_snake_dict()
        # data.pop("num_of_ldevs", None)
        data.pop("logical_unit_ids", None)
        return data


@dataclass
class VSPJournalPools(BaseDataClass):
    data: List[VSPJournalPool] = None
