def sonic_asic_zone_getter(function, func_args, func_kargs):
    """
        SonicAsic specific zone getter used for decorator cached.
        example: asic0 of lc1-1,
        zone: lc1-1_asic0
    """

    hostname = getattr(func_args[0], "hostname", None)
    namespace = getattr(func_args[0], "namespace", None)

    successfully_get_hostname_namespace = hostname and namespace

    if not successfully_get_hostname_namespace:
        raise RuntimeError(f"Can't extract hostname[{hostname}] or namespace[{namespace}]")

    return f"{hostname}_{namespace}"
