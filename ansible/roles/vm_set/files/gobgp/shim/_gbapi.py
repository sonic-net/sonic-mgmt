"""Import shim for the gobgp gRPC stubs.

The stubs live in the PTF image at ``/usr/local/lib/gobgp-api``, generated when
the image is built from the same gobgp checkout that produces ``gobgpd``, so the
stubs and the daemon always describe the same gobgp version. ``GOBGP_API_PATH``
overrides the location. Centralising the path setup here gives the rest of the
package a single import surface::

    from ._gbapi import grpc, gb, gbg, attr, nlri, common, extcom

NLRIs come from ``nlri`` (``nlri_pb2``), path attributes from ``attr``/``extcom``,
and the address family from ``common``.
"""
import os
import sys

_GBAPI_DIR = os.environ.get("GOBGP_API_PATH", "/usr/local/lib/gobgp-api")
if _GBAPI_DIR not in sys.path:
    sys.path.insert(0, _GBAPI_DIR)

import grpc  # noqa: E402
from api import gobgp_pb2 as gb  # noqa: E402
from api import gobgp_pb2_grpc as gbg  # noqa: E402
from api import attribute_pb2 as attr  # noqa: E402
from api import nlri_pb2 as nlri  # noqa: E402
from api import common_pb2 as common  # noqa: E402
from api import extcom_pb2 as extcom  # noqa: E402


def family_msg(family):
    """``common.Family`` for ``"v4"``/``"v6"`` (AFI + unicast SAFI)."""
    afi = common.Family.AFI_IP if family == "v4" else common.Family.AFI_IP6
    return common.Family(afi=afi, safi=common.Family.SAFI_UNICAST)


__all__ = ["grpc", "gb", "gbg", "attr", "nlri", "common", "extcom", "family_msg"]
