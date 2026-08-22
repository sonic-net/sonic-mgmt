"""
TH6 (Tomahawk 6) ThriftAdapter — inherits TH5, overrides what diverges.
"""

import logging

from TAI.core.factory import AdapterFactory
from TAI.core.thrift import ThriftAdapter
from TAI.platforms.tomahawk.th5.thrift import TH5ThriftAdapter

logger = logging.getLogger(__name__)


@AdapterFactory.register(ThriftAdapter, 'th6')
class TH6ThriftAdapter(TH5ThriftAdapter):
    """
    SAI thrift counter adapter for Broadcom Tomahawk 6 (NH-4020).

    Inherits all TH5 behaviour.  Add overrides here as TH6 diverges.
    """

    platform_name = 'th6'
