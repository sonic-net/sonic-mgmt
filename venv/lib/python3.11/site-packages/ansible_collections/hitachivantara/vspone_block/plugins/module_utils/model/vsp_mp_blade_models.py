from dataclasses import dataclass
from typing import Optional

try:
    from .common_base_models import BaseDataClass, SingleBaseClass
except ImportError:
    from common_base_models import BaseDataClass, SingleBaseClass


@dataclass
class MPBladeResponse(SingleBaseClass):
    """
    This class is used to represent the response of a VSP MP Blade.
    """

    mpId: Optional[int] = None
    mpLocationId: Optional[str] = None
    mpUnitId: Optional[str] = None
    ctl: Optional[str] = None
    cbx: Optional[int] = None


@dataclass
class MPBladesResponse(BaseDataClass):
    """
    This class is used to represent the response of VSP MP Blades.
    """

    data: Optional[MPBladeResponse] = None


@dataclass
class MPBladeFactsSpec(SingleBaseClass):
    """
    This class is used to represent the specification for MP Blade facts.
    """

    mp_id: Optional[int] = None
