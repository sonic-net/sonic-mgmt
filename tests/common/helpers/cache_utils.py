import logging

logger = logging.getLogger(__name__)

SINGLE_ASIC_ZONE = "single_asic"


def sonic_asic_zone_getter(function, func_args, func_kargs):
    """
        SonicAsic specific zone getter used for decorator cached.
        example: asic0 of lc1-1,
        zone: lc1-1_asic0
    """

    hostname = getattr(func_args[0], "hostname", None)
    # For the SonicAsic obj of single asic DUT, the namespace is None
    # give SINGLE_ASIC_ZONE as the part of the zone
    namespace = getattr(func_args[0], "namespace", SINGLE_ASIC_ZONE)

    if not hostname:
        raise RuntimeError(f"[Cache] Can't get hostname[{hostname}] for asic[{namespace}]")

    zone = f"{hostname}_{namespace}"
    logger.info(f"[Cache] generate zone[{zone}] for asic[{namespace}]")

    return zone
