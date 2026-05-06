def is_nokia_device(dut):
    return ('nokia' in dut.facts["hwsku"].lower())


NO_QOS_HWSKUS = ['Nokia-7215-C1']

# Platforms where the console mux lands on BMC first; use Ctrl+U then "2" for CPU SONiC console.
# Add other nokia platforms when needed
BMC_FIRST_CONSOLE_PLATFORMS = (
    "x86_64-nokia_ixr7220_h6_128-r0",
)


def _nokia_ixr7220_h6_hwsku(hwsku):
    if not hwsku:
        return False
    h = hwsku.lower()
    return "nokia" in h and "ixr7220" in h and "-h6-" in h


def needs_bmc_to_cpu_console_switch(dut, hwsku_hint=None):
    """
    True when serial mux lands on BMC first (Ctrl+U, 2, Enter for CPU console).
    Uses dut facts when present; optional hwsku_hint (e.g. from conn_graph device_info)
    """
    if hwsku_hint and _nokia_ixr7220_h6_hwsku(hwsku_hint):
        return True
    facts = getattr(dut, "facts", None)
    if facts is None and hasattr(dut, "sonichost"):
        facts = getattr(dut.sonichost, "facts", None)
    facts = facts or {}
    plat = facts.get("platform") or ""
    if plat in BMC_FIRST_CONSOLE_PLATFORMS:
        return True
    return _nokia_ixr7220_h6_hwsku(facts.get("hwsku"))
