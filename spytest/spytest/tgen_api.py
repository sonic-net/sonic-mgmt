
def get_counter_name(mode,tg_type,comp_type,direction):
    from spytest.tgen import tgen_utils
    return tgen_utils.get_counter_name(mode,tg_type,comp_type,direction)
def validate_tgen_traffic(**kwargs):
    from spytest.tgen import tgen_utils
    return tgen_utils.validate_tgen_traffic(**kwargs)
def validate_packet_capture(**kwargs):
    from spytest.tgen import tgen_utils
    return tgen_utils.validate_packet_capture(**kwargs)
def verify_ping(src_obj,port_handle,dev_handle,dst_ip,ping_count=5,exp_count=5):
    from spytest.tgen import tgen_utils
    return tgen_utils.verify_ping(src_obj,port_handle,dev_handle,dst_ip,ping_count=5,exp_count=5)
def tg_bgp_config(**kwargs):
    from spytest.tgen import tgen_utils
    return tgen_utils.tg_bgp_config(**kwargs)
def tg_igmp_config(**kwargs):
    from spytest.tgen import tgen_utils
    return tgen_utils.tg_igmp_config(**kwargs)
def get_traffic_stats(tg_obj, **kwargs):
    from spytest.tgen import tgen_utils
    return tgen_utils.get_traffic_stats(tg_obj, **kwargs)
def port_traffic_control(action, *args, **kwargs):
    from spytest.tgen import tgen_utils
    return tgen_utils.port_traffic_control(action, *args, **kwargs)

def get_handle_byname(name, port=None, tg=None):
    from spytest.framework import get_work_area
    return get_work_area().get_tgen(name, port, tg)

def get_handles_byname(*args):
    rv = dict()
    rv["tg_ph_list"] = []
    for i, name in enumerate(args, start=1):
        tg, tg_ph = get_handle_byname(name)
        rv["tg"] = tg
        rv["tg{}".format(i)] = tg
        rv["tg_ph_{}".format(i)] = tg_ph
        rv["tg_ph_list"].append(tg_ph)
    return rv

def get_chassis(vars=None, index=0):
    if not vars:
        from spytest import st
        tg_names = st.get_tg_names()
    else:
        tg_names = vars['tgen_list']
    from spytest.tgen.tg import get_chassis as tgen_get_chassis
    return tgen_get_chassis(tg_names[index])

def is_soft_tgen(vars=None):
    tg = get_chassis(vars)
    return (tg.tg_type == "scapy")

def get_handles(vars, tg_port_list=list()):
    """
    @author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    This is the common function to get the port handlers based on tg_port_list
    :param vars: This is the framework Spytest vars object.
    :param tg_port_list: List of TG ports for which port handlers to be created.
    :return: Dictionary with tg instance and port handlers
    """
    from spytest import st
    return_val = dict()
    if not tg_port_list:
        st.error("tg Port(s) not provided")
        return None
    tg = get_chassis(vars)
    return_val["tg"] = tg
    return_val["tg_ph_list"] = []
    for i, port in enumerate(tg_port_list, start=1):
        tg_ph = tg.get_port_handle(port)
        return_val["tg{}".format(i)] = tg
        return_val["tg_ph_{}".format(i)] = tg_ph
        return_val["tg_ph_list"].append(tg_ph)
    return return_val


def traffic_action_control(tg_handler, actions=["reset", "clear_stats"]):
    """
    @author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    @author: Chaitanya Vella (chaitanya.vella-kumar@broadcom.com)
    Common function to apply the actions on TG port handlers
    :param tg_handler: List of TG port handlers for which action to be performed.
    :param actions: Default actions are reset and clear_stats, if users wants other this, they have to provided in list.
    :return: Returns TG handler object.
    """
    from spytest import st
    if "tg" not in tg_handler:
        st.error("tg object is not available")
        return None
    tg_port_handler = list()
    for each_item in tg_handler:
        if 'tg_ph_list' in each_item:
            continue
        if 'tg_ph_' in each_item:
            tg_port_handler.append(tg_handler[each_item])
    st.debug("tg_port_handler {}".format(tg_port_handler))
    for action in actions:
        tg_handler["tg"].tg_traffic_control(action=action, port_handle=tg_port_handler)
    return tg_handler

def get_min(v1, v2):
    return v1 if v1 < v2 else v2

def get_max(v1, v2):
    return v1 if v1 > v2 else v2

def normalize_pps(value):
    from spytest import cutils
    if not is_soft_tgen(): return value
    max_value = cutils.get_env_int("SPYTEST_SCAPY_MAX_RATE_PPS", 100)
    return get_min(value, max_value)

def normalize_mtu(value):
    if not is_soft_tgen(): return value
    return get_min(value, 9000)

