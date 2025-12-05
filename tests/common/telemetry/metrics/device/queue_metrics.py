"""
Device queue metrics collection for buffer utilization monitoring.

This module provides metrics for monitoring network queue buffer
utilization and watermark levels across different queue types.
"""

from typing import Optional, Dict, List
from ...base import MetricCollection, Reporter, MetricDefinition
from ...constants import (
    METRIC_NAME_QUEUE_WATERMARK_BYTES,
    UNIT_BYTES
)


class DeviceQueueMetrics(MetricCollection):
    """
    Queue metrics collection for buffer utilization monitoring.

    Provides metrics for monitoring queue buffer watermarks and
    utilization levels across unicast, multicast, and other queue types.
    """

    # Metrics definitions using MetricDefinition for clean, structured definitions
    METRICS_DEFINITIONS: List[MetricDefinition] = [
        MetricDefinition("watermark_bytes", METRIC_NAME_QUEUE_WATERMARK_BYTES, "Queue watermark (Bytes)", UNIT_BYTES),
    ]

    def __init__(self, reporter: Reporter, labels: Optional[Dict[str, str]] = None):
        """
        Initialize device queue metrics collection.

        Args:
            reporter: Reporter instance for all queue metrics
            labels: Common labels (should include device.queue.id and device.queue.cast)
        """
        super().__init__(reporter, labels)
