"""
Test sensor APIs for sensor types that implement SensorBase
"""

import logging
import pytest

from tests.common.helpers.platform_api.sensor import VoltageSensor
from tests.common.helpers.platform_api.sensor import CurrentSensor

from .sensor_api_test_base import SensorApiTestBase

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology("any"),
    pytest.mark.device_type("physical")
]


class TestVoltageSensorApi(SensorApiTestBase):
    """
    Test voltage sensor APIs
    """

    sensor_class = VoltageSensor
    sensor_unit_suffix = "V"
    logger = logging.getLogger(__name__)


class TestCurrentSensorApi(SensorApiTestBase):
    """
    Test current sensor APIs
    """

    sensor_class = CurrentSensor
    sensor_unit_suffix = "A"
    logger = logging.getLogger(__name__)
