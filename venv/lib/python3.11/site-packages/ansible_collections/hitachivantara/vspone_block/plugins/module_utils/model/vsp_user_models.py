from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class VSPUserFactSpec(SingleBaseClass):
    id: Optional[str] = None
    name: Optional[str] = None

    def is_empty(self):
        if self.id is None and self.name is None:
            return True
        return False


@dataclass
class VSPUserSpec(SingleBaseClass):
    id: Optional[str] = None
    name: Optional[str] = None
    password: Optional[str] = None
    authentication: Optional[str] = None
    group_names: Optional[List[str]] = None
    state: Optional[str] = None


@dataclass
class VspUserInfo(SingleBaseClass):
    userObjectId: str
    userId: str
    authentication: str
    userGroupNames: List[str]
    isBuiltIn: bool = None
    isAccountStatus: bool = None

    def __init__(self, **kwargs):
        self.userObjectId = kwargs.get("userObjectId")
        self.userId = kwargs.get("userId")
        self.authentication = kwargs.get("authentication")
        self.userGroupNames = kwargs.get("userGroupNames")
        self.isBuiltIn = kwargs.get("isBuiltIn")
        self.isAccountStatus = kwargs.get("isAccountStatus")

    def to_dict(self):
        return asdict(self)


@dataclass
class VspUserInfoList(BaseDataClass):
    data: List[VspUserInfo]
