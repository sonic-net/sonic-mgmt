
def get_counter_name(mode, tg_type, comp_type, direction):
    from spytest.tgen import tgen_utils
    return tgen_utils.get_counter_name(mode, tg_type, comp_type, direction)


def validate_tgen_traffic(**kwargs):
    from spytest.tgen import tgen_utils
    return tgen_utils.validate_tgen_traffic(**kwargs)


def validate_packet_capture(**kwargs):
    from spytest.tgen import tgen_utils
    return tgen_utils.validate_packet_capture(**kwargs)


def verify_ping(src_obj, port_handle, dev_handle, dst_ip, ping_count=5, exp_count=5):
    from spytest.tgen import tgen_utils
    return tgen_utils.verify_ping(src_obj, port_handle, dev_handle, dst_ip, ping_count=ping_count, exp_count=exp_count)


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


def get_tgen_obj_dict():
    from spytest.tgen.tg import tgen_obj_dict
    return tgen_obj_dict


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


def get_chassis_byname(name):
    from spytest.tgen.tg import get_chassis as tgen_get_chassis
    return tgen_get_chassis(name)


def is_soft_tgen(vars=None):
    tg = get_chassis(vars)
    if not tg: return False
    if tg.tg_type == "scapy": return True
    return tg.tg_virtual


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


def send_traffic(tg, stream, ph_rx=None, ph_tx=None, stop_time=5, run_time=5, clear_stats=False):
    from spytest import st
    if clear_stats or st.is_sonicvs():
        if ph_tx:
            tg.tg_traffic_control(action='clear_stats', port_handle=ph_tx)
        if ph_rx:
            tg.tg_traffic_control(action='clear_stats', port_handle=ph_rx)
    tg.tg_traffic_control(action='run', handle=stream)
    if st.is_sonicvs():
        run_time = run_time + 5
    if run_time > 0:
        st.tg_wait(run_time, "run time")
    tg.tg_traffic_control(action='stop', handle=stream)
    if st.is_sonicvs():
        stop_time = stop_time + 5
    if stop_time > 0:
        st.tg_wait(stop_time, "stop time")
    return None


def send_verify_traffic(tg, stream, ph_rx, ph_tx, tolerance, stop_time=5, run_time=5, clear_stats=False):
    from spytest import st
    err = send_traffic(tg, stream, ph_rx, ph_tx, stop_time, run_time, clear_stats)
    if err:
        return err
    rx_stats = get_traffic_stats(tg, port_handle=ph_rx)
    tx_stats = get_traffic_stats(tg, port_handle=ph_tx)
    tx_pkts = int(tx_stats.tx.total_packets)
    rx_pkts = int(rx_stats.rx.total_packets)
    st.log('rx_pkts : {} tx_pkts : {} tolerance: {}'.format(rx_pkts, tx_pkts, tolerance))
    if not tx_pkts or not rx_pkts:
        return st.error('Recieved ZERO stats.')
    if tolerance > 0:
        if rx_pkts < tx_pkts * tolerance:
            return st.error("Traffic validation failed Rx/TX* {}/{}".format(rx_pkts, tx_pkts * tolerance))
    elif tolerance < 0:
        percent_rx = float(rx_pkts - tx_pkts) / tx_pkts * 100
        st.log('percent_rx : {}'.format(percent_rx))
        if percent_rx > (0 - tolerance):
            return st.error("Unexpected RX {}/{}".format(percent_rx, (0 - tolerance)))
    return None


def get_min(v1, v2):
    return v1 if v1 < v2 else v2


def get_max(v1, v2):
    return v1 if v1 > v2 else v2


def normalize_pps(value):
    from utilities.common import get_env_int
    if not is_soft_tgen(): return value
    max_value = get_env_int("SPYTEST_SCAPY_MAX_RATE_PPS", 100)
    return get_min(int(value), max_value)


def normalize_mtu(value):
    if not is_soft_tgen(): return value
    return get_min(int(value), 9000)


def normalize_hosts(value):
    if not is_soft_tgen(): return value
    return get_min(int(value), 256)


def util_pkt_cap(tg_tx, tg_rx, tx_p_h, rx_p_h, str_h, offset_list=[], value_list=[]):
    tg_rx.tg_packet_control(port_handle=rx_p_h, action='start')
    tg_tx.tg_traffic_control(action='run', handle=str_h)
    tg_rx.tg_packet_control(port_handle=rx_p_h, action='stop')
    tg_tx.tg_traffic_control(action='stop', handle=str_h)
    pkt_cap = tg_rx.tg_packet_stats(port_handle=rx_p_h, format='var', output_type='hex')
    pkt_cap_res = validate_packet_capture(tg_type=tg_rx.tg_type, pkt_dict=pkt_cap,
                                          offset_list=offset_list, value_list=value_list)
    return pkt_cap_res
