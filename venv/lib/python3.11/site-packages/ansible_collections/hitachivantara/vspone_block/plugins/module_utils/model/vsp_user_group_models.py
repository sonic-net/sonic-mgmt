from dataclasses import dataclass, asdict
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class VSPUserGroupFactSpec(SingleBaseClass):
    id: Optional[str] = None
    name: Optional[str] = None

    def is_empty(self):
        if self.id is None and self.name is None:
            return True
        return False


@dataclass
class VSPUserGroupSpec(SingleBaseClass):
    id: Optional[str] = None
    name: Optional[str] = None
    role_names: Optional[List[str]] = None
    resource_group_ids: Optional[List[int]] = None
    state: Optional[str] = None
    has_all_resource_groups: Optional[bool] = False


@dataclass
class VspUserGroupInfo(SingleBaseClass):
    userGroupObjectId: str
    userGroupId: str
    roleNames: List[str]
    resourceGroupIds: List[int]
    isBuiltIn: bool = None
    hasAllResourceGroup: bool = None
    users: List[str] = None

    def __init__(self, **kwargs):
        self.userGroupObjectId = kwargs.get("userGroupObjectId")
        self.userGroupId = kwargs.get("userGroupId")
        self.roleNames = kwargs.get("roleNames")
        self.resourceGroupIds = kwargs.get("resourceGroupIds")
        self.isBuiltIn = kwargs.get("isBuiltIn")
        self.hasAllResourceGroup = kwargs.get("hasAllResourceGroup")

    def to_dict(self):
        return asdict(self)


@dataclass
class VspUserGroupInfoList(BaseDataClass):
    data: List[VspUserGroupInfo]
