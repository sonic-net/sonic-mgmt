from dataclasses import dataclass
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
except ImportError:
    from .common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class SDSBSessionFactsSpec(SingleBaseClass):
    id: Optional[str] = None
    vps_id: Optional[str] = None
    user_id: Optional[str] = None


@dataclass
class SDSBSessionSpec(SingleBaseClass):
    id: Optional[str] = None
    alive_time: Optional[int] = None


@dataclass
class UserPrivileges(SingleBaseClass):
    scope: Optional[str] = None
    roleNames: Optional[List[str]] = None


@dataclass
class SessionResponse(SingleBaseClass):
    sessionId: Optional[str] = None
    userId: Optional[str] = None
    userObjectId: Optional[str] = None
    expirationTime: Optional[str] = None
    createdTime: Optional[str] = None
    lastAccessTime: Optional[str] = None
    roleNames: Optional[List[str]] = None
    vpsId: Optional[str] = None
    privileges: Optional[List[UserPrivileges]] = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__post_init__()

    def __post_init__(self):
        if self.privileges:
            self.privileges = [
                UserPrivileges(**usr_priv) for usr_priv in self.privileges
            ]

    def camel_to_snake_dict(self):
        camel_dict = super().camel_to_snake_dict()
        return camel_dict


@dataclass
class SessionResponseList(BaseDataClass):
    data: List[SessionResponse] = None
