from dataclasses import dataclass
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class JournalFactSpec:
    vps_id: Optional[int] = None
    number: Optional[str] = None
    vps_name: Optional[str] = None
    storage_controller_id: Optional[str] = None


@dataclass
class MirrorUnit(SingleBaseClass):
    muNumber: Optional[int] = None
    consistencyGroupId: Optional[int] = None
    journalStatus: Optional[str] = None
    copyPace: Optional[str] = None
    copySpeed: Optional[str] = None
    numberOfActivePaths: Optional[int] = None


@dataclass
class SDSBJournalResponse(SingleBaseClass):
    id: Optional[str] = None
    journalNumber: Optional[int] = None
    storageControllerId: Optional[str] = None
    vpsId: Optional[str] = None
    vpsName: Optional[str] = None
    capacity: Optional[int] = None
    blockCapacity: Optional[int] = None
    volumeIds: Optional[List[str]] = None
    dataOverflowWatchInSeconds: Optional[int] = None
    isInflowControlEnabled: Optional[bool] = None
    isCacheModeEnabled: Optional[bool] = None
    usageRate: Optional[str] = None
    qMarker: Optional[str] = None
    qCount: Optional[str] = None
    status: Optional[str] = None
    mirrorUnits: Optional[List[MirrorUnit]] = None

    def __post_init__(self):
        if self.mirrorUnits is not None:
            self.mirrorUnits = [
                MirrorUnit(**mu) if isinstance(mu, dict) else mu
                for mu in self.mirrorUnits
            ]


@dataclass
class SDSBJournalList(BaseDataClass):
    data: List[SDSBJournalResponse] = None


@dataclass
class SDSBJournalSpec:
    number: Optional[int] = None
    volume_ids: list[str] = None
    data_overflow_watch_in_sec: Optional[int] = None
    enable_inflow_control: Optional[bool] = None
    enable_cache_mode: Optional[bool] = None
    vps_id: Optional[str] = None
    id: Optional[str] = None
    vps_name: Optional[str] = None
    mirror_unit: Optional[dict[str, Optional[str]]] = None
