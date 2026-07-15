def is_nokia_device(dut):
    return ('nokia' in dut.facts["hwsku"].lower())


NO_QOS_HWSKUS = ['Nokia-7215-C1']

# Platforms/HwSKUs where the console mux lands on BMC first; use Ctrl+U then "2" for CPU SONiC console.
# Add entries only after BMC-first mux is confirmed on hardware.
BMC_FIRST_CONSOLE_PLATFORMS = (
    "x86_64-nokia_ixr7220_h6_128-r0",
)

BMC_FIRST_CONSOLE_HWSKUS = (
    "Nokia-IXR7220-H6-O256",
)


def _bmc_first_console_hwsku(hwsku):
    if not hwsku:
        return False
    return hwsku in BMC_FIRST_CONSOLE_HWSKUS


def needs_bmc_to_cpu_console_switch(dut, hwsku_hint=None):
    """
    True when serial mux lands on BMC first (Ctrl+U, 2, Enter for CPU console).
    Uses dut facts when present; optional hwsku_hint (e.g. from conn_graph device_info)
    """
    if hwsku_hint and _bmc_first_console_hwsku(hwsku_hint):
        return True
    facts = getattr(dut, "facts", None)
    if facts is None and hasattr(dut, "sonichost"):
        facts = getattr(dut.sonichost, "facts", None)
    facts = facts or {}
    plat = facts.get("platform") or ""
    if plat in BMC_FIRST_CONSOLE_PLATFORMS:
        return True
    return _bmc_first_console_hwsku(facts.get("hwsku"))
