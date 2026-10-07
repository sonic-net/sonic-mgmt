def is_nexthop_device(dut):
    """Return True if the device is a Nexthop platform."""
    return "nexthop" in dut.facts["platform"].lower()


class NexthopPlatform:
    """
    Query Nexthop platform capabilities.

    Capabilities default to supported; a platform opts out by listing the
    capability in _UNSUPPORTED, keyed by hwsku prefix. A SKU absent from the
    table is treated as supporting the capability.
    """

    # hwsku-prefix -> set of capabilities that platform does NOT support
    _UNSUPPORTED = {
        "NH-5010": {"warm_reboot", "fast_reboot"},
    }

    def __init__(self, dut):
        self.dut = dut
        self.hwsku = dut.facts["hwsku"]
        self.platform = dut.facts["platform"]

    @property
    def is_nexthop(self):
        return is_nexthop_device(self.dut)

    def _unsupported(self):
        caps = set()
        for prefix, unsupported in self._UNSUPPORTED.items():
            if self.hwsku.startswith(prefix):
                caps |= unsupported
        return caps

    def supports(self, capability):
        # Non-Nexthop boxes aren't described by this table; report True so a
        # caller that forgot to guard with is_nexthop doesn't wrongly skip.
        if not self.is_nexthop:
            return True
        return capability not in self._unsupported()
