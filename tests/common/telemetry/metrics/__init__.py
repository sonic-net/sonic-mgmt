"""
Metric types for the SONiC telemetry framework.
"""

from .gauge import GaugeMetric
from .histogram import HistogramMetric

# Device metric collections are imported in device submodule

__all__ = ['GaugeMetric', 'HistogramMetric']
