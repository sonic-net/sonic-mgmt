from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass
except ImportError:
    from common_base_models import BaseDataClass


@dataclass
class SubscriberFactSpec:
    subscriber_id: Optional[str] = None


@dataclass
class SubscriberSpec:
    name: Optional[str] = None
    subscriber_id: Optional[str] = None
    soft_limit: Optional[str] = None
    hard_limit: Optional[str] = None
    quota_limit: Optional[str] = None
    description: Optional[str] = None


@dataclass
class Resource:
    type: Optional[str] = None
    values: Optional[List[str]] = None


@dataclass
class UnsubscribeSpec:
    resources: Optional[List[Resource]] = None


@dataclass
class SubscriberInfo:
    name: str
    subscriberId: str
    partnerId: str
    type: str
    time: int
    softLimit: str
    hardLimit: str
    usedQuota: str
    quotaLimit: str
    usedQuotaInPercent: float
    state: str
    message: str

    def to_dict(self):
        return asdict(self)


@dataclass
class SubscribersInfo(BaseDataClass):
    data: List[SubscriberInfo]
