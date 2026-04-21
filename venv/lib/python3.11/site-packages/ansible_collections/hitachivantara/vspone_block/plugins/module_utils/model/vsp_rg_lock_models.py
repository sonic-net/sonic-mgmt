from dataclasses import dataclass
from typing import Optional, List

try:
    from .common_base_models import SingleBaseClass
    from ..model.common_base_models import ConnectionInfo

except ImportError:
    from .common_base_models import SingleBaseClass
    from model.common_base_models import ConnectionInfo


@dataclass
class VSPResourceGroupLockSpec(SingleBaseClass):
    # is_resource_group_locked: Optional[bool] = None
    lock_timeout_sec: Optional[int] = None
    secondary_connection_info: Optional[ConnectionInfo] = None
    name: Optional[str] = None
    id: Optional[int] = None
    # lock_token: Optional[str] = None


@dataclass
class VSPResourceGroupNameId(SingleBaseClass):
    name: Optional[str] = None
    id: Optional[str] = None


@dataclass
class VSPResourceGroupLockInfo(SingleBaseClass):
    lock_session_id: Optional[int] = None
    lock_token: Optional[str] = None
    remote_lock_session_id: Optional[int] = None
    remote_lock_token: Optional[str] = None
    locked_resource_groups: Optional[List[str]] = None
    remote_locked_resource_groups: Optional[List[str]] = None
