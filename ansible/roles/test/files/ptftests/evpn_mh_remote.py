"""EVPN-MH PTF platform wrapper with the topology backplane enabled."""

import remote


def platform_config_update(config):
    """Delegate to SONiC's remote platform with backplane discovery enabled.

    Keeping the option in the platform hook makes port discovery independent
    of whether a particular PTF release imports tests before or after it loads
    the selected platform module.
    """
    config["need_backplane"] = True
    remote.platform_config_update(config)
