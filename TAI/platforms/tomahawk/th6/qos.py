"""
TH6 (Tomahawk 6) QoS adapter — inherits TH5, overrides what diverges.
"""

import logging

from TAI.core.factory import AdapterFactory
from TAI.core.qos import QoSAdapter
from TAI.platforms.tomahawk.th5.qos import TH5QoSAdapter

logger = logging.getLogger(__name__)


@AdapterFactory.register(QoSAdapter, 'th6')
class TH6QoSAdapter(TH5QoSAdapter):
    """
    QoS adapter for Broadcom Tomahawk 6 (NH-4020).

    Inherits all TH5 behaviour.  Add overrides here as TH6 diverges.
    """

    platform_name = 'th6'
