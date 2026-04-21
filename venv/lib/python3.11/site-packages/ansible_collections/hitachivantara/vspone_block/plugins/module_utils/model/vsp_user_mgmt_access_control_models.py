from dataclasses import dataclass
from typing import List


@dataclass
class VSPResourceGroupInfo:
    resourceGroupId: int
    resourceGroupName: str
    lockStatus: str
    lockOwner: str
    lockHost: str
    virtualStorageId: int
    ldevIds: List[int]
    parityGroupIds: List[str]
