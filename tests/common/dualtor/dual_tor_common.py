"""DualToR related common utilities for other modules."""
import pytest

__all__ = [
    'cable_type'
]

class CableType(object):
    """Dualtor cable type."""
    active_active = "active-active"
    active_standby = "active-standby"


@pytest.fixture(params=[CableType.active_standby])
def cable_type(request):
    """Dualtor cable type."""
    return request.param
