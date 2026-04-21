from dataclasses import dataclass
from typing import Optional, List

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class JobFactSpec:
    id: Optional[str] = None
    count: Optional[int] = None


@dataclass
class Request:
    requestUrl: str = None
    requestMethod: str = None
    requestBody: str = None


@dataclass
class ErrorResponse:
    errorSource: str = None
    messageId: str = None
    message: str = None
    cause: str = None
    solution: str = None
    solutionType: str = None
    errorCode: str = None


@dataclass
class SDSBJobInfo(SingleBaseClass):
    jobId: str = None
    self: str = None
    userId: str = None
    status: str = None
    state: str = None
    createdTime: str = None
    updatedTime: str = None
    completedTime: str = None
    request: Request = None
    affectedResources: Optional[List[str]] = None
    error: ErrorResponse = None


@dataclass
class SDSBJobInfoList(BaseDataClass):
    data: List[SDSBJobInfo]
