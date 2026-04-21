from dataclasses import dataclass
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class LoginMessageFactSpec:
    message: Optional[str] = None


@dataclass
class SDSBLoginMessageResponse(SingleBaseClass):
    message: Optional[str] = None


@dataclass
class SDSBLoginMessageList(BaseDataClass):
    data: List[SDSBLoginMessageResponse] = None
