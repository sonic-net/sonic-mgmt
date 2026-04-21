from dataclasses import dataclass
from typing import Optional, List
from .common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class SDSBUserSpec:

    id: Optional[str] = None
    name: Optional[str] = None
    user_id: Optional[str] = None
    password: Optional[str] = None
    user_group_ids: list[str] = None
    authentication: Optional[str] = None
    is_enabled_console_login: Optional[bool] = None
    new_password: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None
    comments: Optional[str] = None
    user_group_ids: Optional[List[str]] = None
    is_enabled: Optional[bool] = None
    vps_id: Optional[str] = None
    vps_name: Optional[str] = None


@dataclass
class SDSBUserFactSpec:
    id: Optional[str] = None
    vps_name: Optional[str] = None
    vps_id: Optional[str] = None


@dataclass
class UserGroup(SingleBaseClass):
    userGroupId: Optional[str] = None
    userGroupObjectId: Optional[str] = None


@dataclass
class UserPrivileges(SingleBaseClass):
    scope: Optional[str] = None
    roleNames: Optional[List[str]] = None


@dataclass
class SdsbUserResponse(SingleBaseClass):
    userId: Optional[str] = None
    userObjectId: Optional[str] = None
    passwordExpirationTime: Optional[str] = None
    isEnabled: Optional[bool] = None
    userGroups: Optional[List[UserGroup]] = None
    isBuiltIn: Optional[bool] = None
    authentication: Optional[str] = None
    roleNames: Optional[List[str]] = None
    isEnabledConsoleLogin: Optional[bool] = None
    vpsId: Optional[str] = None
    privileges: Optional[List[UserPrivileges]] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "userGroups" in kwargs:
            self.userGroups = [UserGroup(**user_gp) for user_gp in self.userGroups]
        if "privileges" in kwargs:
            self.privileges = [
                UserPrivileges(**user_priv) for user_priv in self.privileges
            ]

    def camel_to_snake_dict(self):
        camel_dict = super().camel_to_snake_dict()
        return camel_dict


@dataclass
class SdsbUserList(BaseDataClass):
    data: List[SdsbUserResponse] = None
