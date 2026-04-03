"""
Device-specific metric collections for the SONiC telemetry framework.
"""

from .port_metrics import DevicePortMetrics
from .psu_metrics import DevicePSUMetrics
from .queue_metrics import DeviceQueueMetrics
from .temperature_metrics import DeviceTemperatureMetrics
from .fan_metrics import DeviceFanMetrics

__all__ = [
    'DevicePortMetrics',
    'DevicePSUMetrics',
    'DeviceQueueMetrics',
    'DeviceTemperatureMetrics',
    'DeviceFanMetrics'
]
