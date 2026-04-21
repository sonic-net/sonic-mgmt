from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass
except ImportError:
    from common_base_models import BaseDataClass


@dataclass
class ChapUserFactSpec:
    id: Optional[str] = None
    target_chap_user_name: Optional[str] = None


@dataclass
class ChapUserSpec:
    id: Optional[str] = None
    target_chap_user_name: Optional[str] = None
    target_chap_secret: Optional[str] = None
    initiator_chap_user_name: Optional[str] = None
    initiator_chap_secret: Optional[str] = None


@dataclass
class SDSBChapUserInfo:
    id: str
    targetChapUserName: str
    initiatorChapUserName: str

    def to_dict(self):
        return asdict(self)


@dataclass
class SDSBChapUserDetailInfo(SDSBChapUserInfo):
    portIds: List[str]


@dataclass
class SDSBChapUsersInfo(BaseDataClass):
    data: List[SDSBChapUserInfo]
