import os

# this file is imported from framework and hence
# we can't import framework API globally here
# import them with in functions
#from spytest import st

def get_vars(dut):
    from spytest import st
    from apis.system.basic import show_version
    retval = dict()
    retval["constants"] = st.get_datastore(dut, "constants")
    retval["vervars"] = st.get_datastore(dut, "vervars")
    version_data = show_version(dut)
    if not version_data and st.is_dry_run(): return retval
    retval["product"] = version_data['product']
    retval["hwsku"] = version_data['hwsku']
    retval["version"] = version_data['version']
    for version in ["3.0.x.0", "3.0.1"]:
        if version in retval["version"]:
            retval["vervars"] = st.get_datastore(dut, "vervars", version)
    if retval["vervars"]:
        for name, val in retval["vervars"].items():
            st.log("VERVARS ({}) - {} = {}".format(dut, name, val))
    return retval

def ensure_upgrade(dut):
    from apis.system.basic import ensure_hwsku_config
    from apis.system.basic import ensure_certificate
    from apis.system.ntp import ensure_ntp_config
    ensure_hwsku_config(dut)
    if os.getenv("SPYTEST_NTP_CONFIG_INIT", "0") != "0":
        ensure_ntp_config(dut)
    if os.getenv("SPYTEST_GENERATE_CERTIFICATE", "0") != "0":
        ensure_certificate(dut)

def api_hooks_init():
    from spytest.dicts import SpyTestDict
    from apis.system.port import shutdown, noshutdown, get_interfaces_all
    from apis.system.port import get_interface_status
    from apis.system.basic import get_swver, get_sysuptime, get_system_status
    from apis.common.checks import verify_topology
    from apis.common.verifiers import get_verifiers
    hooks = SpyTestDict()
    hooks.port_shutdown = shutdown
    hooks.port_noshutdown = noshutdown
    hooks.get_swver = get_swver
    hooks.get_sysuptime = get_sysuptime
    hooks.get_interfaces_all = get_interfaces_all
    hooks.get_interface_status = get_interface_status
    hooks.get_system_status = get_system_status
    hooks.verify_topology = verify_topology
    hooks.get_vars = get_vars
    hooks.verifiers = get_verifiers
    hooks.ensure_upgrade = ensure_upgrade
    return hooks

