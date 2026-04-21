from dataclasses import dataclass
from typing import Optional, List
from .common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class SDSBUserGroupSpec:
    id: Optional[str] = None
    role_names: Optional[List[str]] = None
    external_group_name: Optional[str] = None
    vps_name: Optional[str] = None
    vps_id: Optional[str] = None
    scope: Optional[List[str]] = None
    comments: Optional[str] = None

    def __post_init__(self):
        if self.id is not None and not (1 <= len(self.id) <= 64):
            raise ValueError("id must be between 1-64 characters.")


@dataclass
class SDSBUserGroupFactSpec:
    id: Optional[str] = None
    vps_name: Optional[str] = None
    vps_id: Optional[str] = None


@dataclass
class MemberUser(SingleBaseClass):
    userId: Optional[str] = None
    userObjectId: Optional[str] = None

    def camel_to_snake_dict(self):
        camel_dict = super().camel_to_snake_dict()
        return camel_dict


@dataclass
class SdsbUserGroupResponse(SingleBaseClass):
    memberUsers: Optional[List[MemberUser]] = None
    userGroupId: Optional[str] = None
    userGroupObjectId: Optional[str] = None
    roleNames: Optional[List[str]] = None
    isBuiltIn: Optional[bool] = None
    externalGroupName: Optional[str] = None
    vpsId: Optional[str] = None
    scope: Optional[List[str]] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "memberUsers" in kwargs and kwargs["memberUsers"] is not None:
            self.memberUsers = [
                m_user if isinstance(m_user, MemberUser) else MemberUser(**m_user)
                for m_user in kwargs["memberUsers"]
            ]

    def camel_to_snake_dict(self):
        camel_dict = super().camel_to_snake_dict()

        return camel_dict


@dataclass
class SdsbUserGroupList(BaseDataClass):
    data: List[SdsbUserGroupResponse] = None
