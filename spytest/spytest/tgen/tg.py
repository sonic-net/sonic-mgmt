import os
import re
import time
import json
import copy
import inspect
import requests
from netaddr import IPAddress, IPNetwork
from collections import OrderedDict
from spytest.logger import Logger
from spytest.tgen.init import tg_stc_load, tg_scapy_load, tg_ixia_load
from spytest.tgen.tg_stubs import TGStubs
from spytest.tgen.tg_scapy import ScapyClient
from spytest.dicts import SpyTestDict
import utilities.common as utils
import utilities.parallel as putils

workarea = None
logger = None
skip_tgen = False
tg_stc_pkg_loaded = False
tg_ixia_pkg_loaded = False
tg_scapy_pkg_loaded = False
tg_version_list = dict()
tgen_obj_dict = {}


def tgen_profiling_start(msg, max_time=300, skip_report=True):
    return workarea.profiling_start(msg, max_time, skip_report)


def tgen_profiling_stop(pid):
    return workarea.profiling_stop(pid)


def tgen_wait(val, msg=None):
    workarea.tg_wait(val, msg)


def tgen_exception(ex):
    workarea.report_tgen_exception(ex)


def tgen_abort(dbg_msg, msgid, *args):
    msg = "TG API Fatal Abort: {}".format(dbg_msg)
    logger.error(msg)
    workarea.report_tgen_abort(msgid, *args)
    if get_tg_type() in ["scapy"]:
        workarea.set_node_dead(None, msg, False)


def tgen_fail(dbg_msg, msgid, *args):
    logger.error('TG API Fatal Error: %s' % dbg_msg)
    workarea.report_tgen_fail(msgid, *args)


def tgen_script_error(dbg_msg, msgid, *args):
    logger.error('TG API Script Error: %s' % dbg_msg)
    workarea.report_scripterror(msgid, *args)


def tgen_ftrace(*args):
    workarea.tgen_ftrace(*args)


def tgen_log_lvl_is_debug():
    lvl_1 = bool(os.getenv('SPYTEST_LOGS_LEVEL') == 'debug')
    lvl_2 = bool(os.getenv('SPYTEST_TGEN_LOGS_LEVEL') == 'debug')
    return bool(lvl_1 or lvl_2)


def tgen_get_logs_path(for_file=None):
    return workarea.get_logs_path(for_file)


def tgen_get_logs_path_folder(for_file=None):
    tgen_folder = for_file if for_file else 'tgen'
    tgen_folder_path = workarea.get_logs_path(tgen_folder)
    if not os.path.exists(tgen_folder_path):
        os.makedirs(os.path.abspath(tgen_folder_path))
    return tgen_folder_path


def tgen_fwrite(msg):
    file_prefix = os.getenv("SPYTEST_FILE_PREFIX", "results")
    hltApiLog = os.path.join(tgen_get_logs_path_folder(), "{}_{}".format(file_prefix, 'hltApiLog.txt'))
    utils.write_file(hltApiLog, "{}\n".format(msg), "a")
    return msg


def tgen_log_call(fname, **kwargs):
    args_list = []
    for key, value in kwargs.items():
        if isinstance(value, str):
            args_list.append("%s='%s'" % (key, value))
        elif isinstance(value, int):
            args_list.append("%s=%s" % (key, value))
        elif isinstance(value, list):
            args_list.append("%s=%s" % (key, value))
        else:
            args_list.append("%s=%s[%s]" % (key, value, type(value)))
    msg = "REQ: {}({})".format(fname, ",".join(args_list))
    logger.debug(msg)
    return tgen_fwrite(msg)


def tgen_log_resp(fname, text):
    msg = 'RESP: {} {}'.format(fname, text)
    logger.debug(msg)
    return tgen_fwrite(msg)


analyzer_filter = {"ipv4Precedence0": "ip_precedence_tracking",
                   "ipv4DefaultPhb0": "ip_dscp_tracking",
                   "vlanVlanUserPriority0": "vlan_user_priority_tracking",
                   "vlanVlanUserPriority1": "vlan_id_tracking",
                   "vlanVlanId0": "vlan_id_tracking",
                   "vlanVlanId1": "vlan_id_tracking"}


def get_sth():
    return globals().get("sth")


def get_ixiatcl():
    return globals().get("ixiatcl")


def get_ixiangpf():
    return globals().get("ixiangpf")


def get_ixnet():
    return get_ixiangpf().ixnet


def connect_retry(tg):
    if tg.skip_traffic:
        return False

    for i in range(1, 11):
        ret_ds = tg.connect()
        if ret_ds is not None:
            if tg.tgen_config_file and ret_ds.get('status', '0') == '1':
                return ret_ds
            msg = "UNKNOWN" if "log" not in ret_ds else ret_ds.get('log', '')
            if i < 10:
                logger.warning('TG Connect Fail: %s try: %d' % (msg, i))
                tgen_wait(10, "Wait to try reconnecting again")
            else:
                logger.error('TG Connect Error: %s' % (msg))
        else:
            logger.info('TG Connection: Success')
            return True
    return False


class TGBase(TGStubs):
    def __init__(self, tg_type, tg_version, tg_ip=None, tg_port_list=None, tg_virtual=False, **kwargs):
        TGStubs.__init__(self, logger)
        logger.info('TG Base Init skip: {}'.format(skip_tgen))
        self.tg_ns = ""
        self.tg_type = tg_type
        self.tg_virtual = tg_virtual
        self.tg_version = tg_version
        self.tg_ip = tg_ip
        self.tg_port_list = tg_port_list
        self.skip_traffic = skip_tgen
        self.tg_connected = False
        self.in_module_start_cleanup = False
        self.cached_interface_config_handles = OrderedDict()
        self.tg_port_handle = SpyTestDict()
        self.tg_port_analyzer = dict()
        self.ports_fec_disable = list()
        self.topo_handle = dict()
        self.tg_card = kwargs.get('card', '')
        self.tgen_config_file = kwargs.get('config_file', '')
        self.tg_port_speed = kwargs.get('port_speed', '')
        self.auto_neg = kwargs.get('auto_neg', '')
        self.phy_mode = kwargs.get('phy_mode', '')
        self.fec = int(kwargs.get('fec', '0'))
        self.skip_start_protocol = False
        self.tg_link_params = kwargs.get('link_params', dict())

    def manage_interface_config_handles(self, mode, port_handle, handle):
        logger.debug("manage_interface_config_handles: {} {} {}".format(mode, port_handle, handle))
        if port_handle is None or handle is None:
            return
        if port_handle not in self.cached_interface_config_handles:
            self.cached_interface_config_handles[port_handle] = []
        if mode == 'destroy':
            if handle in self.cached_interface_config_handles[port_handle]:
                self.cached_interface_config_handles[port_handle].remove(handle)
        else:
            if handle not in self.cached_interface_config_handles[port_handle]:
                self.cached_interface_config_handles[port_handle].append(handle)

    def manage_traffic_config_handles(self, ret_ds, **kwargs):
        pass

    def ensure_traffic_control(self, timeout=60, skip_fail=False, **kwargs):
        pass

    def ensure_traffic_stats(self, timeout=60, skip_fail=False, **kwargs):
        pass

    def instrument(self, phase, context):
        pass

    def wait(self, msg, val, soft=None):
        if soft is not None and self.tg_type in ["scapy"]:
            val = soft
        if val > 0:
            tgen_wait(val)

    def warn(self, dbg_msg):
        logger.error('TG API Error: %s' % dbg_msg)
        self.ensure_connected(dbg_msg)

    def fail(self, dbg_msg, msgid, *args):
        self.ensure_connected(dbg_msg)
        self.get_session_errors()
        self.collect_diagnosic(msgid, True)
        tgen_fail(dbg_msg, msgid, *args)

    def exception(self, exp):
        logger.error('TG API Fatal Exception: %s' % str(exp))
        self.ensure_connected(str(exp))
        tgen_exception(exp)

    def collect_diagnosic(self, fail_reason, from_fail=False):
        pass

    def get_capture_stats_state(self, port, capture_wait=None):
        pass

    def get_emulation_handle_prefixes(self, ret_ds, **kwargs):
        pass

    def get_port_connected_session(self, **kwargs):
        pass

    def get_session_errors(self, **kwargs):
        return {}

    def ixia_eval(self, func, **kwargs):
        return {}

    def tg_topology_test_control(self, stack=None, skip_wait=False, tg_wait=2, **kwargs):
        pass

    def has_disconnected(self, msg):
        if "Failed to parse stack trace not connected" in msg:
            return True

        if "Ixnetwork error occured" in msg:
            if "Connection reset by peer" in msg or "not connected" in msg:
                return True

        if "SAL is not connected" in msg:
            return True

        return False

    def ensure_connected(self, msg):
        if os.getenv("SPYTEST_ENSURE_CONNECTED", "1") == "0":
            return

        msg = str(msg)

        if self.has_disconnected(msg):
            tgen_abort(msg, "tgen_failed_abort", msg)
            return

        if self.tg_type in ['stc', 'scapy']:
            return

        try:
            # try getting the ixnetwork build number to check connection status
            get_ixnet().getAttribute('::ixNet::OBJ-/globals', '-buildNumber')
        except Exception:
            tgen_abort(msg, "tgen_failed_abort", msg)

    def debug_show(self, ph, msg=""):
        stats = self.tg_traffic_stats(port_handle=ph, mode="aggregate")
        total_tx = stats[ph]['aggregate']['tx']['total_pkts']
        total_rx = stats[ph]['aggregate']['rx']['total_pkts']
        logger.info("{} PORT: {} TX: {} RX: {}".format(msg, ph, total_tx, total_rx))

    def tgen_eval(self, msg, func, **kwargs):

        logger.info('Executing: {}'.format(msg))
        (pid, ret_ds) = (0, dict())
        try:
            pid = tgen_profiling_start(msg)
            # nosemgrep-next-line
            ret_ds = eval(func)(**kwargs)
            tgen_profiling_stop(pid)
        except Exception as exp:
            tgen_profiling_stop(pid)
            logger.info('Error {} executing: {}'.format(msg, func))
            self.collect_diagnosic("tgen_eval_exception")
            if not self.in_module_start_cleanup:
                self.exception(exp)
            self.show_status()

        return ret_ds

    def get_port_handle(self, port):
        return self.tg_port_handle.get(port, None)

    def set_port_handle(self, port, value):
        if port:
            self.tg_port_handle[port] = value
        else:
            self.tg_port_handle.clear()

    def get_port_handle_list(self):
        ph_list = list()
        for _, handle in self.tg_port_handle.items():
            ph_list.append(handle)
        return ph_list

    def get_hltapi_name(self, fname):
        ns = self.tg_ns + '.'
        self.cur_hltapi = re.sub(r'tg_', ns, fname)
        return self.cur_hltapi

    def tgen_check_parallel(self, fname):
        if fname not in ["tg_interface_config", "tg_traffic_config"]:
            return
        if not putils.get_in_parallel():
            tgen_ftrace("{} not called in parallel".format(fname))

    def tg_bgp_routes_control(self, handle, route_handle, mode):
        if mode == 'withdraw':
            return self.tg_withdraw_bgp_routes(route_handle)
        if mode == 'readvertise':
            return self.tg_readvertise_bgp_routes(handle, route_handle)

    def pre_interface_config(self, **kwargs):
        intf_kwrgs = {}
        intf_params = ['port_handle', 'ipv6_intf_addr', 'ipv6_prefix_length', 'ipv6_resolve_gateway_mac',
                       'ipv6_gateway', 'src_mac_addr', 'arp_send_req', 'vlan', 'vlan_id', 'count', 'netmask',
                       'vlan_id_step', 'vlan_id_count', 'intf_ip_addr', 'gateway', 'resolve_gateway_mac']
        for param in intf_params:
            if kwargs.get(param) is not None:
                intf_kwrgs[param] = kwargs.pop(param, '')
        intf_kwrgs['mode'] = 'config'
        intf_kwrgs['vlan'] = '1' if intf_kwrgs.get('vlan_id') else '0'
        intf_kwrgs['skip_start_protocol'] = True
        han = self.tg_interface_config(**intf_kwrgs)
        if han.get('status', '0') != '1':
            logger.error('Host is not created properly')
            return {}, kwargs
        return han, kwargs

    def map_field(self, src, dst, d):
        if d.get(src) is not None:
            if dst:
                d[dst] = d[src]
            else:
                logger.warning("TG API Field Unsupported: {}".format(src))
            d.pop(src)
            return True
        return False

    def modify_tgen_return_params(self, res, actual, modify):
        if modify:
            res[modify] = res[actual] if actual in res else ''
        return res

    def trgen_pre_proc(self, fname, **kwargs):
        if self.skip_traffic:
            return 0
        if fname == 'tg_connect' and self.tg_connected:
            logger.info('TG is already connnected')
            return
        self.tgen_check_parallel(fname)
        tgen_log_call(fname, **kwargs)
        kwargs_port_handle = kwargs.get('port_handle')
        kwargs_handle = kwargs.get('handle')
        kwargs = self.trgen_adjust_mismatch_params(fname, **kwargs)
        self.skip_start_protocol = kwargs.pop('skip_start_protocol', self.skip_start_protocol)
        func = self.get_hltapi_name(fname)

        if self.tg_version == 8.40 and fname == 'tg_traffic_config':
            if kwargs.get('rate_pps') is not None:
                kwargs['rate_pps'] = 5

        # Handling the cleanup here, if mode='destroy' is called.
        # if 'stc', replace interface_config with cleanup_session.
        # if 'ixia', replace handle with protocol_handle (already set).
        if fname == 'tg_interface_config':
            if kwargs.get('mode') == 'modify':
                if self.tg_type == 'stc' and kwargs.get('handle'):
                    func = self.get_hltapi_name('tg_emulation_device_config')
                    self.map_field("port_handle", None, kwargs)
                    self.map_field("arp_send_req", None, kwargs)
                    self.map_field("create_host", None, kwargs)
                    self.map_field("vlan", None, kwargs)
                    self.map_field("interface_handle", "handle", kwargs)
                    self.map_field("src_mac_addr", "mac_addr", kwargs)
                    self.map_field("gateway", "gateway_ip_addr", kwargs)
                    self.map_field("ipv6_intf_addr", "intf_ipv6_addr", kwargs)
                    self.map_field("ipv6_prefix_length", "intf_ipv6_prefix_len", kwargs)
                    self.map_field("ipv6_gateway", "gateway_ipv6_addr", kwargs)
                    self.map_field("gateway_step", "gateway_ip_addr_step", kwargs)
                    self.map_field("ipv6_gateway_step", "gateway_ipv6_addr_step", kwargs)
                    self.map_field("src_mac_addr_step", "mac_addr_step", kwargs)
                    if kwargs.get('netmask') is not None:
                        kwargs['intf_prefix_len'] = IPAddress(kwargs.pop('netmask', '255.255.255.0')).netmask_bits()
            if kwargs.get('mode') == 'destroy':
                if self.tg_type == 'stc':
                    func = self.get_hltapi_name('tg_cleanup_session')
                    kwargs.pop('mode', '')
                    kwargs.pop('handle', '')
                    kwargs['reset'] = '0'
                elif self.tg_type == 'ixia':
                    func = self.get_hltapi_name('tg_topology_config')
                    han = kwargs['handle']
                    han = han[0] if type(han) is list else han
                    han = re.search(r'.*deviceGroup:(\d)+', han).group(0)
                    logger.debug("Starting Destroy ... {}".format(han))
                    self.tg_test_control(handle=han, action='stop_protocol')
                    tgen_wait(10)
                    kwargs['topology_handle'] = han
                    kwargs.pop('handle', '')
                    kwargs.pop('port_handle', '')
        if fname == 'tg_interface_control':
            if kwargs.get('mode') == 'break_link':
                if self.tg_type == 'ixia':
                    func = self.get_hltapi_name('tg_interface_config')
                    kwargs.pop('mode', '')
                    kwargs['op_mode'] = 'sim_disconnect'
            elif kwargs.get('mode') == 'restore_link':
                if self.tg_type == 'ixia':
                    func = self.get_hltapi_name('tg_interface_config')
                    kwargs.pop('mode', '')
                    kwargs['op_mode'] = 'normal'
            elif kwargs.get('mode') == 'check_link':
                if self.tg_type == 'stc':
                    func = self.get_hltapi_name('tg_interface_stats')
                    kwargs.pop('mode', '')
                    desired_status = kwargs.pop('desired_status', '')
                    kwargs["properties"] = "link"
                elif self.tg_type == 'ixia':
                    func = self.get_hltapi_name('tg_test_control')
                    kwargs.pop('mode', '')
                    desired_status = kwargs.pop('desired_status', '')
                    kwargs['action'] = 'check_link_state'
        if fname == 'tg_emulation_bgp_route_config':
            if self.tg_type == 'ixia':
                if kwargs.get('mode') in ['remove', 'delete']:
                    func = self.get_hltapi_name('tg_network_group_config')
                    handle = re.search(r'.*networkGroup:(\d)+', kwargs['handle']).group(0)
                    kwargs = dict()
                    kwargs['mode'] = 'delete'
                    kwargs['protocol_handle'] = handle
        if fname == 'tg_emulation_bgp_control':
            action = kwargs.pop('action', 'enable')
            if self.tg_type == 'ixia':
                if kwargs.get('mode') in ['link_flap', 'full_route_flap']:
                    ret_val = {}
                    if kwargs.get('mode') == 'link_flap':
                        down_time = kwargs.get('link_flap_down_time', '0') if action == 'enable' else '0'
                        up_time = kwargs.get('link_flap_up_time', '0') if action == 'enable' else '0'
                        flap = '1' if action == 'enable' else '0'
                        ret_val = self.ixia_eval('emulation_bgp_config', mode='modify', handle=kwargs['handle'],
                                                 enable_flap=flap, flap_up_time=up_time, flap_down_time=down_time)
                    if kwargs.get('mode') == 'full_route_flap':
                        down_time = kwargs.get('route_flap_down_time', '0')
                        up_time = kwargs.get('route_flap_up_time', '0')
                        flap = '1' if action == 'enable' else '0'
                        handle = re.search(r'.*IPRouteProperty:(\d)+', kwargs['route_handle']).group(0)
                        ret_val = self.ixia_eval('emulation_bgp_route_config', mode='modify', handle=handle,
                                                 enable_route_flap=flap, flap_up_time=up_time, flap_down_time=down_time)
                    self.tg_topology_test_control(action='apply_on_the_fly_changes')
                    return ret_val
                logger.info('Applying changes for IXIA before starting BGP')
                self.tg_topology_test_control(action='apply_on_the_fly_changes', tg_wait=10)
            if self.tg_type == 'stc' and action != 'enable':
                return
        if fname == 'tg_traffic_control':
            if self.tg_type == 'ixia' and kwargs.get('action') == 'reset':
                ret_ds = self.ixia_eval('traffic_control', action='poll')
                if ret_ds.get('stopped') == '0':
                    traffic_items = self.ixia_eval('session_info', mode='get_traffic_items')
                    if traffic_items.get('traffic_config') is not None:
                        logger.debug("stopping streams before reset")
                        ret_ds = self.tg_traffic_control(action='stop', stream_handle=traffic_items['traffic_config'].split())
                        logger.debug(ret_ds)
                        tgen_wait(2)

        if fname == 'tg_packet_stats' and kwargs.get('format') == 'var':
            op_type = kwargs.pop('output_type', None)
            capture_wait = kwargs.pop('capture_wait', 120)
            if self.tg_type == 'ixia':
                self.get_capture_stats_state(kwargs.get('port_handle'), capture_wait)
                if op_type == 'hex':
                    func = self.get_hltapi_name('self.local_get_captured_packets')
                else:
                    kwargs.pop('var_num_frames', '')

        if fname == 'tg_packet_control':
            if self.tg_type == 'stc' and kwargs['action'] in ['start', 'stop', 'cumulative_start']:
                if kwargs.get('action') == 'cumulative_start':
                    kwargs['action'] = 'start'
                port_handle = kwargs.get('port_handle')
                if isinstance(port_handle, list):
                    ret_ds = None
                    kwargs.pop('port_handle', '')
                    for ph in port_handle:
                        ret_ds = self.tg_packet_control(port_handle=ph, **kwargs)
                    return ret_ds

        if fname == 'tg_traffic_stats' and self.tg_type == 'ixia':
            self.ensure_traffic_stats(**kwargs)

        if fname == 'tg_emulation_dhcp_config':
            if self.tg_type == 'ixia':
                if kwargs.get('mode') == 'create':
                    topo_han = self.topo_handle[kwargs.get('port_handle')]
                    if topo_han is None:
                        res = self.ixia_eval('topology_config', port_handle=kwargs.get('port_handle'))
                        topo_han = res['topology_handle']
                        self.topo_handle[kwargs.get('port_handle')] = topo_han
                        logger.info(self.topo_handle)
                    return {'handles': topo_han}
                elif kwargs.get('mode') == 'reset':
                    kwargs.pop('ip_version', '')
                    func = self.get_hltapi_name('tg_topology_config')
                    han = kwargs['handle']
                    han = han[0] if type(han) is list else han
                    logger.debug("Starting Destroy ... {}".format(han))
                    self.tg_test_control(handle=han, action='stop_protocol')
                    tgen_wait(10)
                    out = self.verify_session_status(kwargs['port_handle'])
                    kwargs['topology_handle'] = han
                    kwargs['mode'] = 'destroy'
                    if out:
                        self.topo_handle[kwargs['port_handle']] = None
                    kwargs.pop('handle', '')
                    kwargs.pop('port_handle', '')

        if fname in ['tg_emulation_igmp_control', 'tg_emulation_mld_control']:
            if self.tg_type == 'stc':
                if kwargs.get('mode') in ['start', 'stop']:
                    return

        msg = "{} {}".format(func, kwargs)
        ret_ds = self.tgen_eval(msg, func, **kwargs)
        # logger.info(ret_ds)

        if "status" not in ret_ds and fname == 'tg_traffic_stats':
            for i in range(1, 5):
                logger.warning('Failed to fetch Traffic stats, Executing: {} again, after 3 sec...Try: {}'.format(func, i))
                tgen_wait(3)
                msg = "{} {}".format(func, kwargs)
                ret_ds = self.tgen_eval(msg, func, **kwargs)
                logger.info(ret_ds)
                if ret_ds.get('status') is not None:
                    break
            if ret_ds.get('status') is None:
                logger.error('Traffic stats not collected properly, even after waiting for 15 sec...')

        if "status" not in ret_ds:
            logger.warning(ret_ds)
            msg = "Unknown" if "log" not in ret_ds else ret_ds['log']
            if self.tg_type == 'stc' and not ret_ds:
                tgen_abort("nolog", "tgen_failed_abort", str(msg))
            self.fail("nolog", "tgen_failed_api", msg)
        elif ret_ds['status'] == '1':
            logger.debug('TG API Run Status: Success')
            if ret_ds.get('log', ''):
                logger.warning('TG API ERROR: {}'.format(ret_ds['log']))
            if fname == 'tg_traffic_control' and self.tg_type == 'ixia':
                self.ensure_traffic_control(**kwargs)
            if fname == 'tg_traffic_config':
                stream_id = ret_ds.get('stream_id', '')
                if stream_id:
                    logger.info('STREAM HANDLE: "{}"'.format(stream_id))
                if 'emulation_src_handle' in kwargs or 'emulation_dst_handle' in kwargs:
                    self.get_emulation_handle_prefixes(ret_ds, **kwargs)
            if fname == 'tg_traffic_config' and self.tg_type == 'ixia':
                self.manage_traffic_config_handles(ret_ds, **kwargs)
            if fname == 'tg_connect':
                self.tg_connected = True
                for port in kwargs['port_list']:
                    self.tg_port_handle[port] = ret_ds['port_handle'][self.tg_ip][port]
            if fname == 'tg_interface_config':
                if self.tg_type == 'stc':
                    if kwargs.get('enable_ping_response') is not None and kwargs.get('netmask') is not None:
                        ret_val = self.tg_interface_handle(ret_ds)
                        prefix_len = IPAddress(kwargs.get('netmask', '255.255.255.0')).netmask_bits()
                        for device in utils.make_list(ret_val['handle']):
                            self.local_stc_tapi_call(
                                'stc::config ' + device + ' -enablepingresponse ' + str(kwargs['enable_ping_response']))
                            ipv4if = self.local_stc_tapi_call('stc::get ' + device + ' -children-ipv4if')
                            self.local_stc_tapi_call('stc::config ' + ipv4if + ' -PrefixLength ' + str(prefix_len))
                        get_sth().invoke("stc::apply")
                if re.search('cleanup_session', func):
                    if re.search('sth', func):
                        get_sth().invoke("stc::apply")
                    tgen_wait(1)
                elif kwargs.get('mode') == 'destroy':
                    tgen_wait(10)
                    self.tg_topology_test_control(action='apply_on_the_fly_changes', skip_wait=True)
                    tgen_wait(2)
                    self.manage_interface_config_handles(kwargs.get('mode'), kwargs_port_handle, kwargs_handle)
                elif kwargs.get('mode') == 'config':
                    ret_ds = self.tg_interface_handle(ret_ds)
                    if self.tg_type == 'ixia':
                        if not self.skip_start_protocol:
                            tgen_wait(10)
                            self.tg_topology_test_control(action='apply_on_the_fly_changes', skip_wait=True)
                            logger.info('start the host.')
                        temp = ret_ds['handle'] if not isinstance(ret_ds['handle'], list) else ret_ds['handle'][0]
                        self.tg_topology_test_control(handle=temp, stack='deviceGroup', action='start_protocol')
                    self.manage_interface_config_handles(kwargs.get('mode'), kwargs_port_handle, ret_ds['handle'])
                elif kwargs.get('mode') == 'modify':
                    tgen_wait(2)
                    self.tg_topology_test_control(action='apply_on_the_fly_changes', skip_wait=True)
                else:
                    ret_ds = self.tg_interface_handle(ret_ds)
            if fname == 'tg_emulation_bgp_config':
                if self.tg_type == 'ixia':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'bgp_handle', 'handle')
                if self.tg_type == 'stc':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'handles', 'handle')
            if fname == 'tg_emulation_bgp_route_config':
                logger.info(ret_ds)
                if self.tg_type == 'ixia':
                    if 'bgp_routes' in ret_ds:
                        ret_ds = self.modify_tgen_return_params(ret_ds, 'bgp_routes', 'handle')
                    elif 'ip_routes' in ret_ds:
                        ret_ds = self.modify_tgen_return_params(ret_ds, 'ip_routes', 'handle')
                if self.tg_type == 'stc':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'handles', 'handle')
            if fname == 'tg_emulation_igmp_config':
                if self.tg_type == 'ixia':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'igmp_host_handle', 'host_handle')
                if self.tg_type == 'stc':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'handles', 'host_handle')
            if fname == 'tg_emulation_multicast_group_config':
                if self.tg_type == 'ixia':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'multicast_group_handle', 'mul_group_handle')
                if self.tg_type == 'stc':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'handle', 'mul_group_handle')
            if fname == 'tg_emulation_multicast_source_config':
                if self.tg_type == 'ixia':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'multicast_source_handle', 'mul_source_handle')
                if self.tg_type == 'stc':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'handle', 'mul_source_handle')
            if fname == 'tg_emulation_igmp_group_config':
                if self.tg_type == 'ixia':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'igmp_group_handle', 'group_handle')
                if self.tg_type == 'stc':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'handle', 'group_handle')
            if fname == 'tg_emulation_igmp_querier_config':
                if self.tg_type == 'ixia':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'igmp_querier_handle', 'handle')
            if fname == 'tg_emulation_mld_config':
                if self.tg_type == 'ixia':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'mld_host_handle', 'host_handle')
                if self.tg_type == 'stc':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'handles', 'host_handle')
                ret_ds['ipv6_handle'] = kwargs['handle']
            if fname == 'tg_emulation_mld_group_config':
                if self.tg_type == 'ixia':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'mld_group_handle', 'group_handle')
                if self.tg_type == 'stc':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'handle', 'group_handle')
            if fname == 'tg_emulation_mld_querier_config':
                if self.tg_type == 'ixia':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'mld_querier_handle', 'handle')
                ret_ds['ipv6_handle'] = kwargs['handle']
            if fname == 'tg_emulation_dotonex_config':
                ret_ds = self.modify_tgen_return_params(ret_ds, 'dotonex_device_handle', 'handle')
            if fname == 'tg_emulation_ospf_config':
                if self.tg_type == 'ixia':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'ospfv2_handle', 'handle')
                if self.tg_type == 'stc':
                    if kwargs['mode'] == 'create':
                        ret_ds = self.tg_emulation_ospf_config(handle=ret_ds['handle'], mode='modify',
                                                               router_id=kwargs['router_id'])
            if fname == 'tg_emulation_ospf_topology_route_config':
                prefix_type = {'summary_routes': 'summary', 'ext_routes': 'external', 'nssa_routes': 'nssa',
                               'network': 'net', 'router': 'router'}
                ret_ds['handle'] = ret_ds[prefix_type[kwargs['type']]]['connected_routers']
            if fname == 'tg_emulation_ospf_network_group_config':
                if 'ipv4_prefix_pools_handle' in ret_ds:
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'ipv4_prefix_pools_handle', 'handle')
            if fname == 'tg_emulation_dhcp_server_config':
                if self.tg_type == 'stc':
                    if ret_ds.get('handle') is not None:
                        if ret_ds['handle'].get('dhcp_handle') is not None:
                            ret_ds['dhcp_handle'] = ret_ds['handle']['dhcp_handle']
                        else:
                            ret_ds['dhcp_handle'] = ret_ds['handle']['dhcpv6_handle']
                if self.tg_type == 'ixia':
                    if ret_ds.get('dhcpv4server_handle'):
                        ret_ds = self.modify_tgen_return_params(ret_ds, 'dhcpv4server_handle', 'dhcp_handle')
                    else:
                        ret_ds = self.modify_tgen_return_params(ret_ds, 'dhcpv6server_handle', 'dhcp_handle')
            if fname == 'tg_emulation_dhcp_config':
                if self.tg_type == 'ixia':
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'topology_handle', 'handles')
            if fname == 'tg_emulation_dhcp_group_config':
                if self.tg_type == 'stc':
                    if ret_ds.get('dhcpv6_handle'):
                        ret_ds = self.modify_tgen_return_params(ret_ds, 'dhcpv6_handle', 'handle')
                if self.tg_type == 'ixia':
                    # self.tg_topology_test_control(handle=kwargs['handle'], stack='deviceGroup', action='start_protocol')
                    # self.tg_topology_test_control(handle=kwargs['handle'], stack='deviceGroup', action='stop_protocol')
                    tgen_wait(2)
            if fname == 'tg_emulation_dhcp_stats':
                if self.tg_type == 'ixia':
                    if 'log' in ret_ds and "Couldn't find statistics for" in ret_ds['log']:
                        self.fail(ret_ds['log'], "tgen_failed_statistics")

            if fname == 'tg_cleanup_session':
                self.tg_connected = False
                self.tg_port_handle.clear()
            if fname == 'tg_interface_control':
                if self.tg_type == 'stc':
                    if func == self.get_hltapi_name('tg_interface_stats'):
                        result = ret_ds['link']
                        # Dictionary to compare the result.
                        res_dict = {'up': '1',
                                    'down': '0'
                                    }
                        ret_ds = True if res_dict.get(desired_status.lower(), '') == result else False
                elif self.tg_type == 'ixia':
                    if kwargs.get('op_mode') == 'normal' and kwargs.get('port_handle', '') in self.ports_fec_disable:
                        self.ixia_eval('interface_config', port_handle=kwargs.get('port_handle'), mode="modify", autonegotiation=0,
                                       ieee_media_defaults=0, enable_rs_fec=0)
                        self.ixia_eval('interface_config', port_handle=kwargs.get('port_handle'), mode="modify", autonegotiation=0)
                    if func == self.get_hltapi_name('tg_test_control') and desired_status:
                        ret_ds = bool(ret_ds.get(kwargs['port_handle'], {}).get('state', '').lower() == desired_status.lower())
                    else:
                        ret_ds = bool("log" not in ret_ds)
            if fname == 'tg_traffic_control' and kwargs['action'] == 'stop' and \
                    ret_ds.get('stopped') == '0' and os.getenv("SPYTEST_ENSURE_TRAFFIC_CONTROL", "0") == '0':
                for i in range(1, 10):
                    logger.warning(
                        'Traffic is still running, Executing: {} again, after 3 sec...Try: {}'.format(func, i))
                    tgen_wait(3)
                    msg = "{} {}".format(func, kwargs)
                    ret_ds = self.tgen_eval(msg, func, **kwargs)
                    logger.info(ret_ds)
                    if ret_ds['status'] == '1':
                        logger.debug('TG API Run Status: Success')
                        if ret_ds.get('stopped') == '1':
                            break
                if ret_ds.get('stopped') == '0':
                    logger.error('Traffic is still running, even after waiting for 30 sec...')
            if fname == 'tg_packet_stats' and kwargs.get('format') == 'var':
                if self.tg_type == 'ixia':
                    logger.info('Disabling control and data plane options')
                    self.ixia_eval('packet_config_buffers', port_handle=kwargs['port_handle'],
                                   control_plane_capture_enable='0', data_plane_capture_enable='0')
        else:

            if "not found in mandatory or optional argument list" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_invalid_option")
            if "cannot be executed while other actions are in progress" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_apply_changes")
            if "Protocols cannot be added or removed while protocols are running" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_apply_changes")
            if "Unsupported dynamic traffic operation" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_apply_changes")
            if "Oversubscription detected" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_oversubscription")
            if "RuntimeError in apply" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_runtime_error")
            if "Failed to add endpointsets" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_add_endpoint_sets")
            if "Capture action start failed" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_start_capture")
            if "Possible cause: capture was not stopped" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_stop_capture")
            if "::ixia::test_control: Failed to start Protocols" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_start_protocols")
            if "::ixia::traffic_config: Could not configure stack" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_configure_stack")
            if "::ixia::traffic_config: Could not create traffic item" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_configure_stack")
            if "At least one port must be selected to apply the changes" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_apply_changes")
            if "::ixia::traffic_stats: Could not find Traffic Item Statistics view" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_missing_traffic_item")
            if "parse_dashed_args: Invalid value" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_invalid_value")
            if "Device port_address has invalid Network Stack" in ret_ds['log']:
                tgen_abort(ret_ds['log'], "tgen_failed_abort", ret_ds['log'])
            if "Sorry we could not process this" in ret_ds['log']:
                self.warn(ret_ds['log'])
                try:
                    if self.tg_type == 'ixia':
                        stream_handles = utils.make_list(kwargs.get('handle'))
                        status = self.get_session_errors(stream_handle=stream_handles)[1]

                        msg = ''
                        trafficitems = get_ixnet().getList('/traffic', 'trafficItem')
                        err_msg = ['One or more destination MACs or VPNs are invalid', 'Too Many Flow Groups']
                        for each_ti in trafficitems:
                            ti_name = get_ixnet().getAttribute(each_ti, '-name')
                            if ti_name in kwargs.get('handle'):
                                logger.info('Fetching errors or warnings in Traffic handle: {}'.format(ti_name))
                                for log_type in ['errors', 'warnings']:
                                    log_msg = get_ixnet().getAttribute(each_ti, '-' + log_type)
                                    if log_msg:
                                        logger.error('{} in {}: {}'.format(log_type.upper(), ti_name, log_msg))
                                    else:
                                        logger.info('{} in {}: {}'.format(log_type.upper(), ti_name, log_msg))
                                    if ti_name in stream_handles:
                                        for e_msg in err_msg:
                                            for message in log_msg:
                                                if e_msg in message:
                                                    msg = e_msg
                                                    break
                        if not msg:
                            if status.get('status') == '0':
                                msg = 'One or more TGen connceted ports status showing as down'
                            else:
                                msg = ret_ds['log']
                        if msg in err_msg:
                            self.fail(ret_ds['log'], "tgen_failed_api", msg)
                        self.warn(msg)
                except Exception as ex:
                    self.fail(ex, "tgen_failed_api", ret_ds['log'])

            if "Unable to set attributes" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_set_attrib")
            if "Port already used" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_port_in_used")
            if "Unable to connect to IxNetwork" in ret_ds['log']:
                tgen_abort(ret_ds['log'], "tgen_failed_abort", ret_ds['log'])
            if "Please provide a valid traffic item handle or name" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_api", ret_ds['log'])
            if "Error in" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_api", ret_ds['log'])
            if "started Protocol stack is not permitted" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_configure_stack")
            if "Unable to add" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_configure_stack")
            if "Ixnetwork error occured" in ret_ds['log']:
                tgen_abort(ret_ds['log'], "tgen_failed_abort", ret_ds['log'])
            if "Couldn't find statistics for" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_statistics")

            # warning
            self.warn(ret_ds['log'])

            if fname == 'tg_interface_control':
                if self.tg_type == 'ixia':
                    if func == self.get_hltapi_name('tg_test_control') and desired_status:
                        ret_ds = bool(ret_ds.get(kwargs['port_handle'], {}).get('state', '').lower() == desired_status.lower())
                    else:
                        ret_ds = bool("log" not in ret_ds)
        return ret_ds

    def trgen_post_proc(self, fname, **kwargs):
        pass

    def trgen_adjust_mismatch_params(self, fname, **kwargs):
        return kwargs

    def local_stc_tapi_call(self, param):
        return None

    def verify_session_status(self, port_handle, tg_wait=2, ses_ns=True, retry=10):
        return None


class TGStc(TGBase):
    def __init__(self, tg_type, tg_version, tg_ip=None, tg_port_list=None, **kwargs):
        TGBase.__init__(self, tg_type, tg_version, tg_ip, tg_port_list, **kwargs)
        logger.info('TG STC Init...done')

    def clean_all(self):

        ph_list = self.get_port_handle_list()

        logger.info("TG CLEAN ALL: stop and remove all streams on {}". format(ph_list))
        ret_ds = self.tg_traffic_control(action="reset", port_handle=ph_list)
        logger.debug(ret_ds)

        pre_wait = 2
        for port_handle, handle_list in self.cached_interface_config_handles.items():
            for handle in handle_list:
                if pre_wait:
                    tgen_wait(pre_wait)
                    pre_wait = 0
                logger.info("removing interface handle {} on {}".format(handle, port_handle))
                self.tg_interface_config(port_handle=port_handle, handle=handle, mode='destroy')
        self.cached_interface_config_handles = OrderedDict()

        logger.debug("TG CLEAN ALL FINISHED")

    def get_port_status(self, port_list):
        port_handle_list = []
        for port in port_list:
            port_handle_list.append(self.get_port_handle(port))
        ret_ds = get_sth().interface_stats(port_handle_list=port_handle_list, properties="link")
        retval = {}
        for port, port_handle in zip(port_list, port_handle_list):
            retval[port] = ret_ds[port_handle]["link"]
        return retval

    def show_status(self):
        pass

    def tg_save_config(self, file_name=None, file_path=None):
        file_path = tgen_get_logs_path_folder() if not file_path else file_path
        file_name = 'stc_tgen_config.xml' if not file_name else file_name
        filename = os.path.join(file_path, file_name)
        logger.info('The config file is saved at {}'.format(filename))
        self.tg_save_xml(filename=filename)

    def connect(self):
        self.tg_ns = 'sth'
        self.ports_fec_disable = {}
        logger.info("TGen: Trying to connect")
        msg = "Executing: stc::connect"
        pid = tgen_profiling_start(msg, max_time=900)
        ret_ds = get_sth().connect(device=self.tg_ip, port_list=self.tg_port_list, break_locks=1)
        tgen_profiling_stop(pid)
        logger.info("TGen: connect status: {}".format(ret_ds))
        if ret_ds.get('status') != '1':
            return ret_ds
        port_handle_list = []
        for port in self.tg_port_list:
            self.tg_port_handle[port] = ret_ds['port_handle'][self.tg_ip][port]
            port_handle_list.append(self.tg_port_handle[port])
        port_details_all = self.tg_interface_stats(port_handle=port_handle_list)
        if port_details_all.get('status', '0') == '1' and port_details_all.get('intf_speed', '') != '':
            intf_speed_list = port_details_all['intf_speed'].split()
            for intf_speed, port_handle in zip(intf_speed_list, port_handle_list):
                if not self.ports_fec_disable.get(intf_speed, []):
                    self.ports_fec_disable[intf_speed] = []
                self.ports_fec_disable[intf_speed].append(port_handle)
            for speed in ['100000', '50000', '25000']:
                if speed == '100000' and self.ports_fec_disable.get(speed):
                    logger.info('Disabling FEC on ports {} is of speed {}'.format(self.ports_fec_disable[speed], speed))
                    self.tg_interface_config(port_handle=self.ports_fec_disable[speed],
                                             mode="modify", forward_error_correct="false")
                if speed in ['50000', '25000'] and self.ports_fec_disable.get(speed):
                    fec_opt = 'disable_fec_50g' if speed == '50000' else 'disable_fec'
                    logger.info('Disabling FEC on ports {} is of speed {}'.format(self.ports_fec_disable[speed], speed))
                    self.tg_interface_config(port_handle=self.ports_fec_disable[speed],
                                             mode="modify", fec_option=fec_opt, autonegotiation='1')
                    self.tg_interface_config(port_handle=self.ports_fec_disable[speed],
                                             mode="modify", fec_option=fec_opt, autonegotiation='0')
        return None

    def get_card_type(self, port_list):
        card_type = {}

        chassisHandle = self.local_stc_tapi_call('stc::get ' + 'system1' + ' -children-PhysicalChassisManager')
        mgrChassis = self.local_stc_tapi_call('stc::get ' + chassisHandle + ' -children-PhysicalChassis')
        modHandles = self.local_stc_tapi_call('stc::get ' + mgrChassis + ' -children-PhysicalTestModule')

        port_list = utils.make_list(port_list)
        for modHandle in modHandles.split(' '):
            moduleData = self.local_stc_tapi_call('stc::get ' + modHandle)
            for port in port_list:
                if port.split('/')[0] == re.search(r'-Index\s(\d+)', moduleData).group(1):
                    # logger.info('Card Type for port {} is {}'.format(port, re.search(r'-Model\s([\S]+)',moduleData).group()))
                    card_type[port] = re.search(r'-Model\s([\S]+)', moduleData).group(1)
        logger.info('Card Type: {}'.format(card_type))
        return card_type

    def trgen_adjust_mismatch_params(self, fname, **kwargs):
        if fname == 'tg_traffic_config':
            self.map_field("ethernet_value", "ether_type", kwargs)
            self.map_field("data_pattern", "custom_pattern", kwargs)
            self.map_field("icmp_ndp_nam_o_flag", "icmpv6_oflag", kwargs)
            self.map_field("icmp_ndp_nam_r_flag", "icmpv6_rflag", kwargs)
            self.map_field("icmp_ndp_nam_s_flag", "icmpv6_sflag", kwargs)
            self.map_field("data_pattern_mode", None, kwargs)
            self.map_field("global_stream_control", None, kwargs)
            self.map_field("global_stream_control_iterations", None, kwargs)
            self.map_field("vlan_protocol_tag_id", "vlan_tpid", kwargs)
            if kwargs.get('vlan_tpid') is not None:
                if len(str(kwargs['vlan_tpid'])) == 4:
                    kwargs['vlan_tpid'] = int('0x{}'.format(str(kwargs['vlan_tpid']).lstrip('0x')), 0)
            if kwargs.get('custom_pattern') is not None:
                kwargs['custom_pattern'] = kwargs['custom_pattern'].replace(" ", "")
                kwargs['disable_signature'] = kwargs.get('disable_signature', '1')
            if kwargs.get("l4_protocol") == "icmp" and kwargs.get("l3_protocol") == "ipv6":
                kwargs['l4_protocol'] = 'icmpv6'
                self.map_field("icmp_type", "icmpv6_type", kwargs)
                self.map_field("icmp_code", "icmpv6_code", kwargs)
                self.map_field("icmp_target_addr", "icmpv6_target_address", kwargs)
            if kwargs.get('vlan_id') is not None:
                if kwargs.get('l2_encap') is None:
                    kwargs['l2_encap'] = 'ethernet_ii_vlan'
                if type(kwargs.get('vlan_id')) != list:
                    x = [kwargs.get('vlan_id')]
                else:
                    x = kwargs.get('vlan_id')
                if len(x) > 1:
                    vlan_list = kwargs.get('vlan_id')
                    kwargs['vlan_id'] = vlan_list[0]
                    kwargs['vlan_id_outer'] = vlan_list[1]
                    if len(x) > 2:
                        kwargs['vlan_id_other'] = vlan_list[2:]

            for param in ('enable_time_stamp', 'enable_pgid', 'vlan', 'duration'):
                if kwargs.get(param) is not None:
                    kwargs.pop(param)

            for param in ('udp_src_port_mode', 'udp_dst_port_mode',
                          'tcp_src_port_mode', 'tcp_dst_port_mode'):
                if kwargs.get(param) == 'incr':
                    kwargs[param] = 'increment'
                if kwargs.get(param) == 'decr':
                    kwargs[param] = 'decrement'
            if (kwargs.get('transmit_mode') is not None
                    or kwargs.get('l3_protocol') is not None) and \
                    kwargs.get('length_mode') is None:
                kwargs['length_mode'] = 'fixed'

            if kwargs.get('port_handle2') is not None:
                kwargs['dest_port_list'] = kwargs.pop('port_handle2')

            if kwargs.get('high_speed_result_analysis') is not None and \
               kwargs.get('track_by') is not None:
                attr = kwargs.get('track_by')
                attr = attr.split()[1]
                kwargs.pop('track_by')
                kwargs.pop(analyzer_filter[attr])
            if kwargs.get('circuit_endpoint_type') is not None:
                kwargs.pop('circuit_endpoint_type')

            if re.search(r'ip_delay |ip_throughput | ip_reliability |ip_cost |ip_reserved ', ' '.join(kwargs.keys())):
                delay = kwargs.get('ip_delay', 0)
                throughput = kwargs.get('ip_throughput', 0)
                reliability = kwargs.get('ip_reliability', 0)
                cost = kwargs.get('ip_cost', 0)
                reserved = kwargs.get('ip_reserved', 0)

                bin_val = str(delay) + str(throughput) + str(reliability) + str(cost)
                kwargs['ip_tos_field'] = int(bin_val, 2)
                kwargs['ip_mbz'] = reserved
                # ignore step,mode,count for now
                for param in ('qos_type_ixn', 'ip_delay', 'ip_delay_mode', 'ip_delay_tracking',
                              'ip_throughput', 'ip_throughput_mode', 'ip_throughput_tracking',
                              'ip_reliability', 'ip_reliability_mode', 'ip_reliability_tracking',
                              'ip_cost', 'ip_cost_mode', 'ip_cost_tracking', 'ip_reserved'):

                    kwargs.pop(param, None)

            if kwargs.get('mac_dst_mode') is not None:
                if type(kwargs.get('mac_dst')) == list:
                    kwargs['mac_dst'] = ' '.join(kwargs['mac_dst'])
                    kwargs.pop('mac_dst_mode', '')

            # disabling high_speed_result_analysis by default, as saw few instances where it is needed and not by disabled by scripts.
            if kwargs.get('high_speed_result_analysis') is None:
                kwargs['high_speed_result_analysis'] = 0

        elif fname == 'tg_traffic_stats':
            if kwargs.get('mode') is None:
                kwargs['mode'] = 'aggregate'
            kwargs.pop('csv_path', '')
        elif fname == 'tg_traffic_control':
            self.map_field("max_wait_timer", None, kwargs)
            if kwargs.get('db_file') is None:
                kwargs['db_file'] = 0
            if kwargs.get('handle') is not None:
                kwargs['stream_handle'] = kwargs.pop('handle', '')
            if kwargs.get('stream_handle'):
                kwargs['stream_handle'] = kwargs['stream_handle'] if isinstance(kwargs['stream_handle'], str) else list(kwargs['stream_handle'])
        elif fname == 'tg_interface_config':
            self.map_field("ipv4_resolve_gateway", "resolve_gateway_mac", kwargs)
            self.map_field("ipv6_resolve_gateway", "ipv6_resolve_gateway_mac", kwargs)
            self.map_field("transmit_mode", None, kwargs)
            self.map_field("ignore_link", None, kwargs)
            self.map_field("vlan_custom_config", None, kwargs)
            for param in ['resolve_gateway_mac', 'ipv6_resolve_gateway_mac']:
                if kwargs.get(param) is not None:
                    kwargs[param] = 'false' if str(kwargs[param]) in ['false', '0'] else 'true'
            if "vlan_id_count" in kwargs:
                kwargs['count'] = '1'
            if "count" in kwargs:
                if 'create_host' not in kwargs:
                    kwargs['create_host'] = 'false'
            if kwargs.get('create_host') == 'false':
                if kwargs.get('netmask') is not None:
                    kwargs['intf_prefix_len'] = IPAddress(kwargs.pop('netmask', '255.255.255.0')).netmask_bits()
            if kwargs.get('mode') != 'destroy' and kwargs.get('enable_ping_response') is None:
                kwargs['enable_ping_response'] = 1
        elif fname == 'tg_emulation_bgp_config':
            if kwargs.get('enable_4_byte_as') is not None:
                l_as = int(int(kwargs['local_as']) / 65536)
                l_nn = int(kwargs['local_as']) - (l_as * 65536)
                r_as = int(int(kwargs['remote_as']) / 65536)
                r_nn = int(kwargs['remote_as']) - (r_as * 65536)
                kwargs['local_as4'] = str(l_as) + ":" + str(l_nn)
                kwargs['remote_as4'] = str(r_as) + ":" + str(r_nn)
                # 23456 has to be set due to spirent limiation.
                kwargs['local_as'] = '23456'
                kwargs['remote_as'] = '23456'
                kwargs.pop('enable_4_byte_as')
        elif fname in ['tg_emulation_multicast_group_config', 'tg_emulation_multicast_source_config']:
            self.map_field("active", None, kwargs)
            if kwargs.get('ip_addr_step') is not None:
                kwargs['ip_addr_step'] = kwargs['ip_addr_step_val'] if kwargs.get('ip_addr_step_val') else 1
                kwargs.pop('ip_addr_step_val', '')
        elif fname == 'tg_emulation_igmp_querier_config':
            self.map_field("active", None, kwargs)
        elif fname == 'tg_emulation_igmp_group_config':
            self.map_field("g_filter_mode", "filter_mode", kwargs)
            if kwargs.get('source_pool_handle') is not None:
                kwargs['device_group_mapping'] = 'MANY_TO_MANY'
                kwargs['enable_user_defined_sources'] = '1'
                kwargs['specify_sources_as_list'] = '0'
        elif fname == 'tg_emulation_ospf_config':
            kwargs.pop('validate_received_mtu', '')
            kwargs.pop('max_mtu', '')
        elif fname == 'tg_emulation_dhcp_server_config':
            self.map_field("ipaddress_pool_prefix_length", None, kwargs)
            self.map_field("subnet", None, kwargs)
            self.map_field("pool_count", None, kwargs)
            self.map_field("ipaddress_pool_step", None, kwargs)
            if kwargs.get('mode') == 'reset':
                kwargs.pop('port_handle', '')
        elif fname == 'tg_emulation_dhcp_config':
            if kwargs.get('mode') == 'reset':
                kwargs.pop('port_handle', '')
        elif fname == 'tg_emulation_dhcp_server_relay_agent_config':
            kwargs.pop('assign_strategy', '')
        elif fname == 'tg_emulation_dot1x_config':
            if int(kwargs.get('num_sessions', 1)) > 1:
                for entry in ['username', 'password']:
                    if kwargs.get(entry):
                        kwargs[entry] = str(kwargs[entry]) + '@s'
        elif fname == 'tg_emulation_dot1x_control':
            if kwargs.get('mode') == 'stop':
                kwargs['mode'] = 'logout'
        elif fname == 'tg_emulation_mld_group_config':
            self.map_field("g_filter_mode", None, kwargs)
            if kwargs.get('source_pool_handle') is not None:
                kwargs['device_group_mapping'] = 'MANY_TO_MANY'
                kwargs['user_defined_src'] = 'true'
        elif fname == 'tg_emulation_mld_querier_config':
            self.map_field("active", None, kwargs)
            if kwargs.get('mode') == 'create':
                handles, ret_kwargs = self.pre_interface_config(**kwargs)
                kwargs = ret_kwargs
                kwargs['handle'] = handles['handle']
        elif fname == 'tg_emulation_mld_config':
            self.map_field("active", None, kwargs)
            if kwargs.get('mode') == 'create':
                handles, ret_kwargs = self.pre_interface_config(**kwargs)
                kwargs = ret_kwargs
                kwargs['handle'] = handles['handle']
        elif fname == 'tg_emulation_bgp_route_config':
            if kwargs.get('prefix_from') is not None:
                prefix_len = kwargs.pop('prefix_from', '24')
                kwargs['netmask'] = IPNetwork('0.0.0.0/{}'.format(prefix_len)).netmask.format()
        elif fname == 'tg_emulation_ptp_config':
            self.map_field("vlan_id", "vlan_id1", kwargs)
            self.map_field("profile", "", kwargs)
            self.map_field("arp_send_req", "", kwargs)
            self.map_field("vlan", "", kwargs)
            self.map_field("announce_current_utc_offset_valid", "", kwargs)
            self.map_field("announce_ptp_timescale", "", kwargs)
            self.map_field("path_trace_tlv", "", kwargs)
            kwargs['local_ip_prefix_len'] = IPAddress(kwargs.get('local_ip_prefix_len', '255.255.255.0')).netmask_bits()
            log_intv_map = {'-9': '{"-511"}', '-8': '{"-255"}', '-7': '{"-127"}', '-6': '{"-63"}', '-5': '{"-31"}',
                            '-4': '{"-15"}', '-3': '{"-7"}', '-2': '{"-3"}', '-1': '{"-1"}', '0': '{"0"}', '1': '{"1"}',
                            '2': '{"3"}', '3': '{"7"}', '4': '{"15"}', '5': '{"31"}', '6': '{"63"}', '7': '{"127"}',
                            '8': '{"255"}', '9': '{"511"}'}
            kwargs['log_sync_message_interval'] = log_intv_map.get(kwargs.get('log_sync_message_interval', '-3'))
            kwargs['log_minimum_delay_request_interval'] = log_intv_map.get(kwargs.get('log_minimum_delay_request_interval', '0'))
            kwargs['log_announce_message_interval'] = log_intv_map.get(kwargs.get('log_announce_message_interval', '0'))
            kwargs['time_source'] = kwargs.get('time_source', 'gps')
            kwargs['master_clock_class'] = kwargs.get('master_clock_class', '6')
        return kwargs

    def tg_interface_handle(self, ret_ds):
        temp = '0'
        if "handle_list_pylist" in ret_ds:
            temp = ret_ds['handle_list_pylist']
        elif "handles_pylist" in ret_ds:
            temp = ret_ds['handles_pylist']
        elif "handles" in ret_ds:
            temp = ret_ds['handles']
        if isinstance(temp, list):
            temp = temp[0] if len(temp) == 1 else temp
        ret_ds['handle'] = temp
        return ret_ds

    def tg_withdraw_bgp_routes(self, route_handle):
        result = self.tg_emulation_bgp_route_config(route_handle=route_handle, mode='withdraw')
        logger.info("withdraw action completed: {}".format(result))
        return result if result['status'] == '1' else None

    def tg_readvertise_bgp_routes(self, handle, route_handle):
        result = self.tg_emulation_bgp_config(handle=handle, mode='readvertise')
        logger.info("readvertise action completed: {}".format(result))
        return result if result['status'] == '1' else None

    def tg_igmp_querier_control(self, mode, handle):
        result = self.tg_emulation_igmp_querier_control(mode=mode, handle=handle)
        logger.info("IGMP Querier action completed: {}".format(result))
        return result if result['status'] == '1' else None

    def tg_mld_querier_control(self, mode, handle):
        result = self.tg_emulation_mld_querier_control(mode=mode, handle=handle)
        logger.info("MLD Querier action completed: {}".format(result))
        return result if result['status'] == '1' else None

    def tg_emulation_ospf_route_config(self, **kwargs):
        result = self.tg_emulation_ospf_topology_route_config(**kwargs)
        logger.info('OSPF route config completed: {}'.format(result))
        return result if result['status'] == '1' else None

    def tg_ospf_lsa_config(self, **kwargs):
        result = self.tg_emulation_ospf_lsa_config(**kwargs)
        logger.info('OSPF route config completed: {}'.format(result))
        return result if result['status'] == '1' else None

    def tg_disconnect(self, **kwargs):
        if self.skip_traffic:
            return 0
        logger.info('Executing: {} {}'.format('sth.cleanup_session', kwargs))
        port_handle_list = self.get_port_handle_list()
        ret_ds = get_sth().cleanup_session(port_handle=port_handle_list)
        logger.info(ret_ds)
        if ret_ds.get('status') == '1':
            logger.debug('TGen: API Run Status: Success')
        else:
            logger.warning('TGen: API Error: %s' % ret_ds.get('log', ''))
        self.tg_connected = False
        self.tg_port_handle.clear()

    def local_stc_tapi_call(self, param):
        res = get_sth().invoke(param)
        return res

    def _custom_filter_delete(self, port_handle):

        current_analyzer = self.local_stc_tapi_call('stc::get ' + port_handle + ' -children-Analyzer')
        filter_list_32 = self.local_stc_tapi_call('stc::get ' + current_analyzer + ' -children-Analyzer32BitFilter').split()
        filter_list_16 = self.local_stc_tapi_call('stc::get ' + current_analyzer + ' -children-Analyzer16BitFilter').split()

        for filter in filter_list_32:
            self.local_stc_tapi_call('stc::delete ' + filter)
        for filter in filter_list_16:
            self.local_stc_tapi_call('stc::delete ' + filter)

        self.local_stc_tapi_call('stc::apply')
        self.tg_port_analyzer[port_handle] = {}
        self.tg_port_analyzer[port_handle]['pattern_list'] = list()

    def _custom_filter_config(self, **kwargs):
        ret_dict = dict()
        ret_dict['status'] = '1'

        if not kwargs.get('mode') or not kwargs.get('port_handle'):
            logger.info("Missing Mandatory parameter: mode or port_handle")
            ret_dict['status'] = '0'
            return ret_dict

        port_handle = kwargs['port_handle']
        mode = kwargs['mode'].lower()

        if mode != 'create' and self.tg_port_analyzer[port_handle]['analyzer_handle'] is None:
            logger.error("Custom Filter is not configured for port: {}".format(port_handle))
            ret_dict['status'] = '0'
            return ret_dict

        project_handle = 'Project1'
        # This is the default name/handle. Things might not work if it is different.
        # Need a way to find this.
        res = self.local_stc_tapi_call('stc::get ' + project_handle)
        if not re.search(r'-Name\s+\{Project 1\}', res):
            logger.error('Could not find project handle')
            ret_dict['status'] = '0'
            return ret_dict

        if mode == 'create':
            if not kwargs.get('offset_list') or not kwargs.get('pattern_list'):
                logger.info('Both offset_list and pattern_list are must when mode=create')
                ret_dict['status'] = '0'
                return ret_dict

            if len(kwargs['offset_list']) != len(kwargs['pattern_list']):
                logger.info('offset_list and pattern_list must be of same length')
                ret_dict['status'] = '0'
                return ret_dict

            # Delete existing filters, if any
            self._custom_filter_delete(port_handle)
            self.tg_port_analyzer[port_handle]['pattern_list'].append(kwargs['pattern_list'])

            # subscribe for the result
            self.tg_port_analyzer[port_handle]['stats_handle'] = self.local_stc_tapi_call('stc::subscribe -Parent ' + project_handle + ' -ResultParent ' + port_handle + ' -ConfigType Analyzer -resulttype FilteredStreamResults ')
            self.local_stc_tapi_call('stc::apply')

            current_analyzer = self.local_stc_tapi_call('stc::get ' + port_handle + ' -children-Analyzer')
            self.tg_port_analyzer[port_handle]['analyzer_handle'] = current_analyzer

            f_index = 1
            for offset in kwargs['offset_list']:
                filter_name = 'CustomFilter' + str(f_index)
                custom_filter = self.local_stc_tapi_call('stc::create Analyzer16BitFilter -under ' + current_analyzer)
                self.local_stc_tapi_call('stc::config ' + custom_filter + ' -FilterName ' + filter_name + ' -Offset ' + str(offset))
                f_index += 1

            self.local_stc_tapi_call('stc::apply')

        else:
            current_analyzer = self.tg_port_analyzer[port_handle]['analyzer_handle']
            if mode in ['start', 'stop']:
                self.local_stc_tapi_call('stc::perform Analyzer' + mode.capitalize() + ' -AnalyzerList ' + current_analyzer)
                self.local_stc_tapi_call('stc::apply')
                tgen_wait(2)
            if mode in ['delete']:
                self._custom_filter_delete(port_handle)

            if mode in ['getstats']:
                filter_list_16 = self.local_stc_tapi_call('stc::get ' + current_analyzer + ' -children-Analyzer16BitFilter').split()
                if len(filter_list_16) == 0:
                    logger.error('No filters are configured on this port')
                    ret_dict['status'] = '0'
                    return ret_dict
                if self.tg_port_analyzer[port_handle]['pattern_list'] is not None:
                    pattern_list = self.tg_port_analyzer[port_handle]['pattern_list']
                    exp_filter_pattern_list = list()
                    for p_list in pattern_list:
                        if not isinstance(p_list, list):
                            logger.info('Each pattern must be a list')
                            ret_dict['status'] = '0'
                            return ret_dict
                        if len(p_list) != len(filter_list_16):
                            logger.info('pattern_list and offset_list must be of equal length')
                            ret_dict['status'] = '0'
                            return ret_dict

                        logger.debug('Pattern: {}'.format(p_list))
                        exp_filter_pattern_list.append(':'.join(p_list).lower())
                else:
                    logger.info('pattern_list is mandatory parameter')
                    ret_dict['status'] = '0'
                    return ret_dict

                self.local_stc_tapi_call('stc::perform RefreshResultView -ResultDataSet ' + self.tg_port_analyzer[port_handle]['stats_handle'])
                tgen_wait(3)

                rx_result_handle_list = self.local_stc_tapi_call('stc::get ' + self.tg_port_analyzer[port_handle]['stats_handle'] + ' -resulthandlelist').split()
                logger.debug('rx_result_handle_list: {}'.format(rx_result_handle_list))
                if len(rx_result_handle_list) == 0:
                    logger.error('Filtered result is not received, check the configurations')
                    ret_dict['status'] = '0'
                    return ret_dict

                ret_dict[port_handle] = {}
                ret_dict[port_handle].update({'custom_filter': {}})
                total_rx_count = 0
                ret_dict[port_handle]['custom_filter'].update({'filtered_frame_count': 0})
                ret_dict['status'] = '1'
                for rxresult in rx_result_handle_list:
                    logger.info('rxresult row: {}'.format(rxresult))
                    rx_result_hash = self.local_stc_tapi_call('stc::get ' + rxresult)
                    logger.info('RX Result: {}'.format(rx_result_hash))

                    # Using stc::get we can get info for each key in rx_result_hash, examples below.
                    # We are interested in counts and rate only for now.
                    # hanalyzerPort = get_sth().invoke('stc::get ' + rx_result_hash + " -parent" )
                    # PStreamName  = get_sth().invoke('stc::get ' + hanalyzerPort + " -name")
                    # StreamID = get_sth().invoke('stc::get ' + rxresult + " -Comp32")

                    found_filter_pattern = ''
                    for i in range(1, len(filter_list_16) + 1):
                        filter_pattern = self.local_stc_tapi_call('stc::get ' + rxresult + ' -FilteredValue_' + str(i))
                        if found_filter_pattern == '':
                            found_filter_pattern = ''.join(filter_pattern.split())
                        else:
                            found_filter_pattern = found_filter_pattern + ':' + ''.join(filter_pattern.split())
                    logger.info('exp_filter_pattern_list: {} found_filter_pattern: {}'.format(exp_filter_pattern_list, found_filter_pattern))
                    if found_filter_pattern.lower() in exp_filter_pattern_list:
                        rx_frame_count = self.local_stc_tapi_call('stc::get ' + rxresult + ' -FrameCount')
                        rx_frame_rate = self.local_stc_tapi_call('stc::get ' + rxresult + ' -FrameRate')
                        logger.info('rx_frame_count: {} rx_frame_rate: {}'.format(rx_frame_count, rx_frame_rate))
                        ret_dict[port_handle]['custom_filter']['filtered_frame_count'] = int(ret_dict[port_handle]['custom_filter']['filtered_frame_count']) + int(rx_frame_count)
                        total_rx_count += int(rx_frame_count)
                    else:
                        logger.info('Ignoring filter_pattern: {}'.format(found_filter_pattern.lower()))
                        total_rx_count += int(self.local_stc_tapi_call('stc::get ' + rxresult + ' -FrameCount'))

                ret_dict[port_handle]['custom_filter'].update({'total_rx_count': total_rx_count})

        return ret_dict

    def tg_custom_filter_config(self, **kwargs):
        ret_dict = dict()
        ret_dict['status'] = '1'
        stc_kwargs = dict()

        if not kwargs.get('mode') or not kwargs.get('port_handle'):
            logger.info("Missing Mandatory parameter: port_handle or mode")
            ret_dict['status'] = '0'
            return ret_dict

        mode = kwargs.get('mode').lower()
        port_handle = kwargs.get('port_handle')
        stc_kwargs['port_handle'] = port_handle

        if mode != 'getstats':
            offset_count = 0
            offset_list = list()
            pattern_list = list()
            for offset, pattern in zip(['pattern_offset1'], ['pattern1']):
                if not kwargs.get(offset) or not kwargs.get(pattern) or len(kwargs[pattern]) != 4:
                    logger.info('Missing Mandatory parameter {} or {} and pattern length must be 16 bits'.format(offset, pattern))
                    ret_dict['status'] = '0'
                    return ret_dict
                offset_count += 1
                offset_list.append(kwargs[offset])
                pattern_list.append(kwargs[pattern])

            for offset, pattern in zip(['pattern_offset2'], ['pattern2']):
                if kwargs.get(offset) and kwargs.get(pattern) and len(kwargs[pattern]) == 4:
                    offset_count += 1
                    offset_list.append(kwargs[offset])
                    pattern_list.append(kwargs[pattern])
                elif not kwargs.get(offset) and not kwargs.get(pattern):
                    pass
                else:
                    logger.info('Both parameter {} and {} need to be provided and pattern length must be 16 bits'.format(offset, pattern))
                    ret_dict['status'] = '0'
                    return ret_dict
        if mode == 'create':
            self._custom_filter_config(mode='create', port_handle=port_handle, offset_list=offset_list, pattern_list=pattern_list)
            self._custom_filter_config(mode='start', port_handle=port_handle)
        if mode == 'getstats':
            ret_dict[port_handle] = {}
            ret_dict[port_handle].update({'custom_filter': {}})
            tgen_wait(3)
            result = self._custom_filter_config(mode='getstats', port_handle=port_handle)
            if result['status'] == '0':
                logger.info('No packets matching filter criteria is received')
                ret_dict[port_handle]['custom_filter'].update({'filtered_frame_count': 0})
                ret_dict[port_handle]['custom_filter'].update({'total_rx_count': 0})
                return ret_dict

            filtered_frame_count = result[port_handle]['custom_filter']['filtered_frame_count']
            total_rx_count = result[port_handle]['custom_filter']['total_rx_count']
            ret_dict[port_handle]['custom_filter'].update({'filtered_frame_count': filtered_frame_count})
            ret_dict[port_handle]['custom_filter'].update({'total_rx_count': total_rx_count})

        return ret_dict

    def get_emulation_handle_prefixes(self, ret_ds, **kwargs):
        ip_dict = dict()
        for emu_handle in ['emulation_src_handle', 'emulation_dst_handle']:
            handle_list = utils.make_list(kwargs.get(emu_handle))
            ip_dict[emu_handle] = list()
            for index, handle in enumerate(handle_list):
                try:
                    temp = dict()
                    if handle.startswith('host') or handle.startswith('emulateddevice'):
                        device_obj = self.local_stc_tapi_call('stc::get ' + handle + ' -toplevelif-Targets')
                        if device_obj.startswith('eth') or device_obj.startswith('vlan'):
                            continue
                        temp['start_addr'] = self.local_stc_tapi_call(
                            'stc::get ' + device_obj.split(' ')[0] + ' -Address')
                        temp['handle'] = handle
                    else:
                        if ret_ds.get('stream_id', ''):
                            emu_type = 'src' if emu_handle == 'emulation_src_handle' else 'dst'
                            device_obj = self.local_stc_tapi_call('stc::get ' + ret_ds.get('stream_id') + ' -' + emu_type + 'binding-Targets')
                            device = device_obj.split(' ')[index]
                            temp['start_addr'] = self.local_stc_tapi_call('stc::get ' + device + ' -StartIpList')
                            temp['count'] = self.local_stc_tapi_call('stc::get ' + device + ' -NetworkCount')
                            temp['handle'] = handle
                    ip_dict[emu_handle].append(temp)
                except Exception:
                    logger.error("Couldn't get ip prefix for handle: {}".format(handle))
        logger.info('IP PREFIXES: {}'.format(ip_dict))


class TGIxia(TGBase):
    def __init__(self, tg_type, tg_version, tg_ip=None, tg_port_list=None, tg_ix_server=None, tg_ix_port=8009, tg_virtual=False, **kwargs):
        self.ix_server = tg_ix_server
        self.ix_port = str(tg_ix_port)
        self.topo_handle = {}
        self.traffic_config_handles = {}
        TGBase.__init__(self, tg_type, tg_version, tg_ip, tg_port_list, tg_virtual, **kwargs)
        logger.info('TG Ixia Init...done')

    def clean_all(self):
        if self.skip_traffic:
            return 0
        self.traffic_config_handles.clear()
        ph_list = self.get_port_handle_list()

        traffic_items = self.ixia_eval('session_info', mode='get_traffic_items')
        if traffic_items.get('traffic_config') is not None:
            items = traffic_items['traffic_config'].split()
            logger.info("TG CLEAN ALL: stop and remove all streams on {}".format(items))
            ret_ds = self.ixia_eval('traffic_control', action='poll')
            if ret_ds.get('stopped') == '0':
                logger.debug("stopping streams before reset")
                ret_ds = self.ixia_eval('traffic_control', action='stop', handle=items)
                logger.debug(ret_ds)
                tgen_wait(2)
            ret_ds = self.ixia_eval('traffic_control', action="reset", handle=items)
            logger.debug(ret_ds)
            tgen_wait(2)
        else:
            logger.info("TG CLEAN ALL: No traffic items configured to reset")

        if os.getenv('TGEN_REMOVE_CACHED_INTERFACE_HANDLE'):
            for port_handle, handle_list in self.cached_interface_config_handles.items():
                for handle in handle_list:
                    logger.info("removing interface handle {} on {}".format(handle, port_handle))
                    self.ixia_eval('interface_config', port_handle=port_handle, handle=handle, mode='destroy')
            self.cached_interface_config_handles = dict()
        else:
            topo_handles = []
            for ph in ph_list:
                topo_handle = self.topo_handle[ph]
                if topo_handle:
                    topo_handles.append(topo_handle)
            if topo_handles:
                logger.info("Removing topology handles: {}".format(self.topo_handle))
                self.tg_topology_test_control(action='stop_all_protocols', tg_wait=10)
                self.verify_session_status(ph_list)
                reconnect = False
                for ph in ph_list:
                    topo_handle = self.topo_handle[ph]
                    ret_ds = {}
                    if topo_handle:
                        logger.info("removing cached topology {} on port {}".format(topo_handle, ph))
                        try:
                            ret_ds = self.ixia_eval('topology_config', topology_handle=topo_handle, mode='destroy')
                        except Exception:
                            self.collect_diagnosic("tgen_eval_exception")
                            reconnect = True
                        logger.debug(ret_ds)
                        if 'Unable to delete' in ret_ds.get('log', ''):
                            self.collect_diagnosic("tgen_eval_exception")
                            reconnect = True
                        self.topo_handle[ph] = None
                        if reconnect:
                            break
                        tgen_wait(2)
                if reconnect:
                    self.tg_disconnect()
                    self.tg_connected = False
                    self.topo_handle.clear()
                    tgen_wait(5, 'Wait before reconnect tgen...')
                    connect_tgen()

        logger.info("TG CLEAN ALL FINISHED")

    def ixia_eval(self, func, **kwargs):

        msg = "{} {}".format(func, kwargs)
        logger.info('Executing: {}'.format(msg))
        (pid, ret_ds) = (0, dict())
        try:
            pid = tgen_profiling_start(msg)
            ret_ds = getattr(get_ixiangpf(), func)(**kwargs)
            tgen_profiling_stop(pid)
        except Exception as exp:
            tgen_profiling_stop(pid)
            logger.info('Error {} executing: {}'.format(msg, func))
            self.collect_diagnosic("tgen_eval_exception")
            if not self.in_module_start_cleanup:
                self.exception(exp)
            self.show_status()

        return ret_ds

    def verify_session_status(self, port_handle, tg_wait=2, ses_ns=True, retry=10):
        try:
            ret_list = []
            ph_list = utils.make_list(port_handle)
            res = self.ixia_eval('protocol_info', mode='global_per_port')
            logger.debug(res)
            if res.get('status') == '0' and 'Make sure protocol is started' in res.get('log', ''):
                logger.debug('All device groups were deleted from the configured topologies')
            for ph in ph_list:
                topo_handle = self.topo_handle[ph]
                ret_val = False
                if topo_handle:
                    for loop in range(1, retry + 1):
                        if res.get('status') == '0' and 'Make sure protocol is started' in res.get('log', ''):
                            _ = 'All device groups were deleted from the topologies'
                        elif not res['global_per_port'].get(ph):
                            if loop == retry:
                                logger.debug('No topologies configured on the port {}'.format(ph))
                            logger.debug('Topology {} not found on port {}..try..{}'.format(topo_handle, ph, loop))
                            tgen_wait(tg_wait)
                            res = self.ixia_eval('protocol_info', mode='global_per_port')
                            logger.debug(res)
                            continue
                        else:
                            total = res['global_per_port'][ph]['sessions_total']
                            total_ns = res['global_per_port'][ph]['sessions_not_started']
                            total_s = res['global_per_port'][ph]['sessions_up']
                            if ses_ns and total != total_ns:
                                continue
                            if not ses_ns and total != total_s:
                                continue
                        ret_val = True
                        break
                ret_list.append(ret_val)
            return False if False in ret_list else True
        except Exception as exp:
            logger.debug(exp)

    def tg_topology_test_control(self, stack=None, skip_wait=False, tg_wait=2, **kwargs):
        if kwargs.get('handle') is not None and stack is not None:
            found = re.search(r'.*{}:(\d)+'.format(stack), kwargs['handle'])
            if found:
                kwargs['handle'] = found.group(0)
        kwargs.pop('tg_wait', '')
        skip_start_protocol = kwargs.pop('skip_start_protocol', self.skip_start_protocol)
        if skip_start_protocol:
            tgen_wait(2, 'skipping the start protocol')
            return
        for _ in range(1, 30):
            if kwargs.get('action') == 'apply_on_the_fly_changes':
                res = self.ixia_eval('test_control', action='apply_on_the_fly_changes')
            else:
                res = self.ixia_eval('test_control', **kwargs)
            logger.debug(res)
            if res.get('status', '0') == '1':
                logger.debug('{}: Success'.format(kwargs['action']))
                break
            tgen_wait(tg_wait)
        if not skip_wait:
            tgen_wait(10)

    def get_port_status(self, port_list):
        retval = {}
        for port in port_list:
            ret_ds = self.ixia_eval('test_control', action='check_link_state', port_handle=self.get_port_handle(port))
            retval[port] = bool("log" not in ret_ds)
        return retval

    def get_ixnetwork_status(self, **kwargs):
        ix_server = kwargs.get('ix_server', None)
        ix_rest_port = kwargs.get('ix_port', '8006')
        retries = int(kwargs.get('retries', '1'))
        ret_dict = dict()
        ret_dict['status'] = '0'
        ret_dict['total_session'] = 0
        ret_dict['session_in_use'] = 0
        ret_dict['user_list'] = list()
        ret_dict['user_id'] = list()
        while ret_dict['status'] == '0' and retries > 0:
            try:
                rest_cmd = 'http://' + ix_server.split(':')[0] + ':' + ix_rest_port + '/api/v1/sessions'
                # nosemgrep-next-line
                response = requests.get(rest_cmd, verify=False, allow_redirects=True, timeout=30)
                if response.status_code == 200:
                    ret_dict['status'] = '1'
                    resp_dict = json.loads(response.content)
                    for s_dict in resp_dict:
                        logger.debug('Connection Manager, session info: {}'.format(s_dict))
                        ret_dict['total_session'] += 1
                        if s_dict['state'].lower() == 'active' and re.match(r'IN\s+USE', s_dict['subState']):
                            ret_dict['session_in_use'] += 1
                            m = re.search(r'automation\s+client\s+(.+?)\s', s_dict['subState'])
                            ret_dict['user_list'].append(str(m.group(1)))
                            ret_dict['user_id'].append(str(s_dict['userId']))

                elif response.status_code != 200:
                    logger.debug('Response from Connection Manager: {}'.format(response))
                    retries -= 1

            except requests.ConnectionError as conn_error:
                retries -= 1
                logger.info('Either Connection Manager is not running or REST port 8006 is not enabled')
                logger.info('Error: {}'.format(conn_error))

            except Exception as conn_error:
                retries -= 1
                logger.info('Unknown Exception: {}'.format(conn_error))

        return ret_dict

    def show_status(self):
        if self.ix_port == "443" or os.getenv("SPYTEST_IXIA_CONNMGR_STATUS", "1") == "0":
            return None
        ret_ds = self.get_ixnetwork_status(ix_server=self.ix_server)
        if ret_ds:
            logger.info('Connection Manager Info: {}'.format(ret_ds))
        return ret_ds

    def get_session_errors(self, **kwargs):
        try:
            root = get_ixnet().getRoot()
            globals = get_ixnet().getList(root, 'globals')
            appErrors = get_ixnet().getList(globals[0], 'appErrors')
            errorMsgList = get_ixnet().getList(appErrors[0], 'error')
            logger.error('Global API Errors: {}'.format(errorMsgList))
            errorDesc = dict()
            for errorMsg in errorMsgList:
                errorDesc[errorMsg] = dict()
                errorDesc[errorMsg]['description'] = get_ixnet().getAttribute(errorMsg, '-description')
                errorDesc[errorMsg]['name'] = get_ixnet().getAttribute(errorMsg, '-name')
                if 'Too Many Flow Groups' in errorDesc[errorMsg]['name']:
                    msg = errorDesc[errorMsg]['description']
                    tgen_abort(msg, "tgen_failed_abort", msg)
                if 'Port is Unassigned or Port CPU not ready' in errorDesc[errorMsg]['name']:
                    msg = errorDesc[errorMsg]['description']
                    stream_handle = kwargs.get('stream_handle')
                    self.get_port_connected_session(stream_handle=stream_handle)
                    tgen_abort(msg, "tgen_failed_abort", msg)
            logger.info('Global API Description: {}'.format(errorDesc))
            ret_ds = self.get_port_connected_session(port_handle=list(self.tg_port_handle.values()))
        except Exception as exp:
            self.fail(exp, "tgen_failed_api", str(exp))
        return ret_ds

    def get_port_connected_session(self, **kwargs):
        port_handles = []
        if kwargs.get('stream_handle'):
            stream_handles = utils.make_list(kwargs.get('stream_handle'))
            ports = self.get_port_handle_from_stream_handle(stream_handle=stream_handles)
            if ports:
                for stream in stream_handles:
                    port_handles.extend(ports[stream]['sources'])
                    port_handles.extend(ports[stream]['destinations'])

        if kwargs.get('port_handle'):
            p_handles = utils.make_list(kwargs.get('port_handle'))
            port_handles.extend(p_handles)

        port_handles = list(set(port_handles))
        cur_session = self.ixnet_connect_status['connection']['username']

        if port_handles:
            for port in port_handles:
                ch, card, po = port.split('/')
                tg_ip = utils.make_list(self.tg_ip)
                parent = '::ixNet::OBJ-/availableHardware/chassis:'
                try:
                    s_owner = get_ixnet().getAttribute(parent + '"' + tg_ip[int(ch) - 1] + '"' + '/card:' + card + '/' + 'port:' + po, '-owner')
                    if s_owner != cur_session:
                        logger.info('The port "{}" is connected to IxNetwork session "{}". The current IxNetwork session is "{}"'.format(port, s_owner, cur_session))
                        msg = 'The port ownership is lost. In use by {}'.format(s_owner)
                        tgen_abort(msg, "tgen_failed_abort", msg)
                except Exception as exp:
                    self.fail(exp, "tgen_failed_api", str(exp))
        status = self.ixia_eval('test_control', action='check_link_state', port_handle=list(self.tg_port_handle.values()))
        logger.info('TGen connected Port status: {}'.format(status))
        return port_handles, status

    def get_port_handle_from_stream_handle(self, **kwargs):

        traffic_data = {}
        if not kwargs.get('stream_handle'):
            return traffic_data

        try:
            stream_list = kwargs.get('stream_handle')
            trafficitems = get_ixnet().getList('/traffic', 'trafficItem')

            for each_ti in trafficitems:
                ti_name = get_ixnet().getAttribute(each_ti, '-name')
                traffic_data[ti_name] = {}
                endpointsets = get_ixnet().getList(each_ti, 'endpointSet')

                if ti_name in stream_list:
                    for each_endpoint in endpointsets:
                        vport_source = []
                        vport_destination = []

                        sources = get_ixnet().getAttribute(each_endpoint, '-sources')
                        for each_source in sources:
                            porthandlefetch_status = get_ixiangpf().convert_vport_to_porthandle(
                                vport=each_source.split('/protocols')[0])
                            if porthandlefetch_status['status'] != '1':
                                continue
                            else:
                                vport = porthandlefetch_status['handle']
                                vport_source.append(vport)

                        destinations = get_ixnet().getAttribute(each_endpoint, '-destinations')
                        for each_destination in destinations:
                            porthandlefetch_status = get_ixiangpf().convert_vport_to_porthandle(
                                vport=each_destination.split('/protocols')[0])
                            if porthandlefetch_status['status'] != '1':
                                continue
                            else:
                                vport = porthandlefetch_status['handle']
                                vport_destination.append(vport)

                        traffic_data[ti_name]['sources'] = list(set(vport_source))
                        traffic_data[ti_name]['destinations'] = list(set(vport_destination))
            logger.info('traffic_data: {}'.format(traffic_data))
            return traffic_data
        except Exception:
            return traffic_data

    def connect(self):
        self.tg_ns = 'ixiangpf'
        self.ixnetwork_os = None
        self.ixnet_connect_status = None
        ret_ds = self.show_status()
        if ret_ds and ret_ds['status'] == '1' and ret_ds['session_in_use'] > ret_ds['total_session'] - 1:
            msg = 'Max recommended connection is reached, should abort the run'
            tgen_abort(msg, "tgen_failed_abort", msg)

        params = SpyTestDict(device=self.tg_ip, port_list=self.tg_port_list, connect_timeout=60,
                             ixnetwork_tcl_server=self.ix_server, break_locks=1, reset=1)
        if self.tgen_config_file:
            params.config_file = self.tgen_config_file
            params.pop('reset', '')
        if self.ix_port == "443":
            # ixnetwork linux VM
            params.user_name = "admin"
            params.user_password = "admin"
            if self.tg_virtual:
                params.ixnetwork_license_servers = "10.59.135.10"
                params.ixnetwork_license_type = "subscription_tier1"
        try:
            logger.info("TGen: Trying to connect")
            ret_ds = get_ixiangpf().connect(**params)
        except Exception:
            return {}

        logger.info("TGen: connect status: {}".format(ret_ds))
        if ret_ds.get('status') != '1':
            return ret_ds
        self.ixnet_connect_status = ret_ds
        if 'connection' in ret_ds and ('api_key_file' in ret_ds['connection'] or 'api_key' in ret_ds['connection']):
            self.ixnetwork_os = 'linux'
        else:
            self.ixnetwork_os = 'windows'
        if not ret_ds.get('port_handle') and not self.tg_port_list:
            logger.info('No TGEN ports specificed in the testbed')
            return None
        self.ports_fec_disable = []
        res = dict()
        for _ in range(3):
            res = self.ixia_eval('traffic_stats')
            if res.get('status') == '1':
                break
        if not isinstance(self.tg_ip, list):
            for port in self.tg_port_list:
                # ixia output is different for key 'port_handle': {'10': {'59': {'130': {'4': {'1/5': '1/1/5'}}}}}
                key1, key2, key3, key4 = self.tg_ip.split('.')
                self.tg_port_handle[port] = ret_ds['port_handle'][key1][key2][key3][key4][port]
                if self.tg_port_handle[port] is None:
                    logger.info('Port Handle Info: {}'.format(self.tg_port_handle))
                    logger.info("Port handle for port {} is None...retrying connect again".format(port))
                    self.tg_disconnect()
                    return {}
                # For topology_handle.
                self.topo_handle[self.tg_port_handle[port]] = None
                # To get 100G ports.
                if not res.get(self.tg_port_handle[port]):
                    logger.info('Traffic Stats Info: {}'.format(res))
                    logger.info("Failed to get port {} from the traffic stats info..retrying connect again".format(self.tg_port_handle[port]))
                    self.tg_disconnect()
                    return ret_ds
                if res[self.tg_port_handle[port]]['aggregate']['tx']['line_speed'] in ['100GE', '25GE']:
                    self.ports_fec_disable.append(self.tg_port_handle[port])
        else:
            tg_ip = utils.make_list(self.tg_ip)
            tg_port_list = utils.make_list(self.tg_port_list)
            out = ret_ds['port_handle']
            tg_port_handles = dict()
            for ip in tg_ip:
                key1, key2, key3, key4 = ip.split('.')
                for k1 in out:
                    if k1 != key1:
                        continue
                    for k2 in out[k1]:
                        if k2 != key2:
                            continue
                        for k3 in out[k1][k2]:
                            if k3 != key3:
                                continue
                            for k4 in out[k1][k2][k3]:
                                if k4 != key4:
                                    continue
                                tg_port_handles[ip] = out[k1][k2][k3][k4]
            for index, port_list in enumerate(tg_port_list):
                # ixia output is different for key 'port_handle': {'10': {'59': {'130': {'4': {'1/5': '1/1/5'}}}}}
                for port in port_list:
                    vport = str(index + 1) + '/' + port
                    self.tg_port_handle[vport] = tg_port_handles[tg_ip[index]][port]
                    if self.tg_port_handle[vport] is None:
                        logger.info('Port Handle Info: {}'.format(tg_port_handles))
                        logger.info("Port handle for port {} is None...retrying connect again".format(port))
                        self.tg_disconnect()
                        return {}
                    # For topology_handle.
                    self.topo_handle[self.tg_port_handle[vport]] = None
                    # To get 100G ports.
                    if not res.get(self.tg_port_handle[vport]):
                        logger.info('Traffic Stats Info: {}'.format(ret_ds))
                        logger.info("Failed to get port {} from the traffic stats info..retrying connect again".format(self.tg_port_handle[vport]))
                        self.tg_disconnect()
                        return ret_ds
                    if res[self.tg_port_handle[vport]]['aggregate']['tx']['line_speed'] in ['100GE', '25GE']:
                        self.ports_fec_disable.append(self.tg_port_handle[vport])

        if not params.get('config_file'):
            if self.ports_fec_disable:
                logger.info('Disabling FEC for ports: {}'.format(self.ports_fec_disable))
                res = self.ixia_eval('interface_config', port_handle=list(self.tg_port_handle.values()), mode="modify",
                                     autonegotiation=0, ieee_media_defaults=0, enable_rs_fec=0, force_enable_rs_fec='0',
                                     firecode_force_on='0')
                self.ixia_eval('interface_config', port_handle=self.ports_fec_disable, mode="modify", autonegotiation=0)
                logger.info(res)
            self.auto_neg = 1 if self.auto_neg else 0
            if self.tg_link_params.get('port_speed') and self.tg_link_params.get('auto_neg'):
                if self.tg_link_params.get('port_speed')[0] == self.tg_link_params.get('auto_neg')[0]:
                    self.auto_neg = self.tg_link_params.get('auto_neg')[1]

            def p_han(x):
                return [self.get_port_handle(p) for p in x]
            port_speed = []
            if self.tg_link_params.get('port_speed'):
                port_speed = [p_han(self.tg_link_params['port_speed'][0]), self.tg_link_params['port_speed'][1]]
            elif self.tg_port_speed:
                port_speed = [list(self.tg_port_handle.values()), utils.make_list(self.tg_port_speed)]
            if port_speed:
                logger.info("Changing the TGEN ports speed to '{}' on ports {}".format(port_speed[1], port_speed[0]))
                speed_map = {'ether2500': 'ether2.5Gig', 'ether10000': 'ether10Gig'}
                speeds = [speed_map[i] if speed_map.get(i) else i for i in port_speed[1]]
                res = self.ixia_eval('interface_config', port_handle=port_speed[0], mode="modify", speed=speeds, autonegotiation=self.auto_neg)
                logger.info(res)
                if res.get('status') != '1':
                    logger.info('Example speed options: ether10, ether100, ether1000, ether2500, ether10000, ether5Gig, ether25Gig, ether100Gig, ether40Gig, ether50Gig')
                    logger.info("Failed to change the TGEN port speed to '{}'. Please provide valid supported speed on the ports".format(speeds))
                    self.tg_disconnect()
            if self.auto_neg and not port_speed:
                res = self.ixia_eval('interface_config', port_handle=list(self.tg_port_handle.values()), mode="modify", autonegotiation=self.auto_neg)
            phy_mode = []
            if self.tg_link_params.get('phy_mode'):
                phy_mode = [p_han(self.tg_link_params['phy_mode'][0]), self.tg_link_params['phy_mode'][1]]
            elif self.phy_mode:
                phy_mode = [list(self.tg_port_handle.values()), self.phy_mode]
            if phy_mode:
                res = self.ixia_eval('interface_config', port_handle=phy_mode[0], mode="modify", phy_mode=phy_mode[1])
                logger.info(res)
                if res.get('status') != '1':
                    logger.info("Failed to change the PHY mode of TGEN ports to '{}'".format(phy_mode[0]))
            fec = []
            self.fec = 1 if self.fec else 0
            if self.tg_link_params.get('fec'):
                fec = [p_han(self.tg_link_params['fec'][0]), self.tg_link_params['fec'][1]]
            elif self.fec:
                fec = [list(self.tg_port_handle.values()), self.fec]
            if fec:
                res = self.ixia_eval('interface_config', port_handle=fec[0], mode="modify", ieee_media_defaults=0, enable_rs_fec=fec[1])
                logger.info(res)
                if res.get('status') != '1':
                    logger.info("Failed to change the fec mode of TGEN ports to '{}'".format(fec[0]))
            # Initial setting for ARP/ND.
            if not isinstance(self.tg_ip, list):
                h1 = self.ixia_eval('topology_config', port_handle=self.tg_port_handle[self.tg_port_list[0]], mode='config')
            else:
                port = list(self.tg_port_handle.keys())[0]
                h1 = self.ixia_eval('topology_config', port_handle=port, mode='config')
            logger.info(h1)
            res = self.ixia_eval('interface_config', protocol_handle='/globals', single_arp_per_gateway=0, single_ns_per_gateway=0)
            logger.info(res)
            res = self.ixia_eval('topology_config', topology_handle=h1['topology_handle'], mode='destroy')
            logger.info(res)
            return None
        return ret_ds

    def trgen_adjust_mismatch_params(self, fname, **kwargs):
        if fname == 'tg_traffic_config':
            self.map_field("ether_type", "ethernet_value", kwargs)
            self.map_field("custom_pattern", "data_pattern", kwargs)
            self.map_field("icmpv6_oflag", "icmp_ndp_nam_o_flag", kwargs)
            self.map_field("icmpv6_rflag", "icmp_ndp_nam_r_flag", kwargs)
            self.map_field("icmpv6_sflag", "icmp_ndp_nam_s_flag", kwargs)
            self.map_field("vlan_tpid", "vlan_protocol_tag_id", kwargs)
            self.map_field("icmpv6_code", "icmp_code", kwargs)
            self.map_field("icmpv6_type", "icmp_type", kwargs)
            self.map_field("icmpv6_target_address", "icmp_target_addr", kwargs)
            self.map_field("ipv6_srcprefix", "", kwargs)
            self.map_field("ipv6_dstprefix", "", kwargs)
            self.map_field("disable_signature", "", kwargs)

            if kwargs.get("l4_protocol") == "icmpv6":
                kwargs['l4_protocol'] = 'icmp'

            if kwargs.get('vlan_protocol_tag_id') is not None:
                if len(str(kwargs['vlan_protocol_tag_id'])) != 4:
                    kwargs['vlan_protocol_tag_id'] = hex(int(kwargs['vlan_protocol_tag_id'])).lstrip('0x')

            if type(kwargs.get('vlan_id')) == list:
                # script : [inner vlan id, outer vlan id, other vlan ids]
                # Ixia config: Vlan tag closest to the payload is the INNER tag, and the tag closest to the MAC header
                # is the OUTER tag.
                if len(kwargs['vlan_id']) > 1:
                    kwargs['vlan_id'][0], kwargs['vlan_id'][1] = kwargs['vlan_id'][1], kwargs['vlan_id'][0]

            if kwargs.get('vlan_id_outer') is not None:
                # If vlan_id_outer is present then vlan_id will also be there
                outer_vlan_id = kwargs['vlan_id_outer']
                vlan_id = kwargs['vlan_id']
                kwargs['vlan_id'] = [outer_vlan_id, vlan_id]
                kwargs.pop('vlan_id_outer')
                if kwargs.get('vlan_id_other') is not None:
                    # If vlan_id_other is present then vlan_id_outer will also be there
                    # vlan headers built as following order: vlan_id_other, vlan_id_outer, vlan_id
                    other_vlan_id = utils.make_list(kwargs['vlan_id_other'])
                    other_vlan_id.reverse()
                    other_vlan_id.extend(kwargs['vlan_id'])
                    kwargs['vlan_id'] = other_vlan_id
                    kwargs.pop('vlan_id_other')

            if kwargs.get('vlan_id') is not None and kwargs.get('vlan') is None:
                kwargs['vlan'] = 'enable'

            # for stream level stats, circuit_type and track_by arguments required
            if kwargs.get('port_handle2') is not None:
                if kwargs.get('track_by') is None:
                    kwargs['track_by'] = 'trackingenabled0'
                if kwargs.get('circuit_type') is None:
                    kwargs['circuit_type'] = 'raw'
                if kwargs.get('emulation_src_handle') is not None and kwargs.get('emulation_dst_handle') is not None:
                    kwargs['circuit_type'] = 'none'
                    kwargs.pop('port_handle2')

            for param in ('mac_discovery_gw', 'vlan_priority_mode', 'high_speed_result_analysis',
                          'enable_stream_only_gen', 'enable_stream', 'ipv6_dstprefix_len', 'ipv6_srcprefix_len'):
                if kwargs.get(param) is not None:
                    kwargs.pop(param)

            for param in ('udp_src_port_mode', 'udp_dst_port_mode',
                          'tcp_src_port_mode', 'tcp_dst_port_mode'):
                if kwargs.get(param) == 'increment':
                    kwargs[param] = 'incr'
                if kwargs.get(param) == 'decrement':
                    kwargs[param] = 'decr'

            if kwargs.get('ip_tos_field') is not None:
                bin_tos_val = bin(kwargs['ip_tos_field'])[2:].zfill(4)

                kwargs['qos_type_ixn'] = 'tos'
                kwargs['ip_precedence'] = kwargs.get('ip_precedence', 0)
                # configuring ip_precedence is mandatory if use qos_type_ixn=tos
                kwargs['ip_delay'] = bin_tos_val[0]
                kwargs['ip_throughput'] = bin_tos_val[1]
                kwargs['ip_reliability'] = bin_tos_val[2]
                kwargs['ip_cost'] = bin_tos_val[3]
                kwargs['ip_reserved'] = kwargs.get('ip_mbz', 0)

                kwargs.pop('ip_tos_field')
                kwargs.pop('ip_mbz', None)

            if kwargs.get('emulation_dst_handle') is not None:
                foundIgmp = 1
                if isinstance(kwargs['emulation_dst_handle'], list):
                    for ele in kwargs['emulation_dst_handle']:
                        if not re.search(r'.*igmpMcastIPv4GroupList.*', ele):
                            foundIgmp = 0
                            break
                else:
                    if not re.search(r'.*igmpMcastIPv4GroupList.*', kwargs['emulation_dst_handle']):
                        foundIgmp = 0
                if foundIgmp == 1:
                    kwargs['emulation_multicast_dst_handle'] = 'all_multicast_ranges'
                    kwargs['emulation_multicast_dst_handle_type'] = [['0']]
                    kwargs['emulation_multicast_rcvr_handle'] = [[kwargs['emulation_dst_handle']]]
                    kwargs['emulation_multicast_rcvr_port_index'] = [['0']]
                    kwargs['emulation_multicast_rcvr_host_index'] = [['0']]
                    kwargs['emulation_multicast_rcvr_mcast_index'] = [['0']]
                    kwargs['emulation_dst_handle'] = [['0']]

        if fname == 'tg_traffic_control':
            if kwargs.get('stream_handle') is not None:
                kwargs['handle'] = kwargs.pop('stream_handle', '')
            if kwargs.get('handle'):
                kwargs['handle'] = kwargs['handle'] if isinstance(kwargs['handle'], str) else list(kwargs['handle'])
            for param in ('get', 'enable_arp', 'duration'):
                if kwargs.get(param) is not None:
                    kwargs.pop(param)
            if kwargs.get('action') in ['run', 'stop'] and kwargs.get('port_handle') is None:
                # kwargs['max_wait_timer'] = 120
                # temp change to roll back the HF from ixia
                if os.getenv("SPYTEST_ENSURE_TRAFFIC_CONTROL", "0") == "0":
                    kwargs['max_wait_timer'] = 30
                else:
                    kwargs['max_wait_timer'] = 180

        if fname == 'tg_interface_config':
            self.map_field("resolve_gateway_mac", "ipv4_resolve_gateway", kwargs)
            self.map_field("ipv6_resolve_gateway_mac", "ipv6_resolve_gateway", kwargs)
            self.map_field("control_plane_mtu", "mtu", kwargs)
            self.map_field("flow_control", "enable_flow_control", kwargs)
            self.map_field("arp_target", None, kwargs)
            wait = 5 if self.skip_start_protocol else 10
            for param in ['ipv4_resolve_gateway', 'ipv6_resolve_gateway']:
                if kwargs.get(param) is not None:
                    kwargs[param] = '0' if str(kwargs[param]) in ['false', '0'] else '1'
            if kwargs.get('mode') == 'modify':
                self.map_field("handle", "interface_handle", kwargs)
            if kwargs.get('mode') == 'config':
                topo_han = self.topo_handle[kwargs.get('port_handle')]
                if topo_han is None:
                    res = self.ixia_eval('topology_config', port_handle=kwargs.get('port_handle'))
                    logger.info(res)
                    if res.get('status') == '0':
                        self.fail(res.get('log'), "tgen_failed_api", res.get('log'))
                    topo_han = res['topology_handle']
                    self.topo_handle[kwargs.get('port_handle')] = topo_han
                    logger.info(self.topo_handle)
                    tgen_wait(wait)
                mul = kwargs.get('count', '1')
                if 'vlan_id_count' in kwargs:
                    mul = kwargs.get('vlan_id_count', '1')
                res = self.ixia_eval('topology_config', topology_handle=topo_han, device_group_multiplier=mul)
                logger.info(res)
                if res.get('status') == '0':
                    self.fail(res.get('log'), "tgen_failed_api", res.get('log'))
                tgen_wait(wait)
                kwargs['protocol_handle'] = res['device_group_handle']
                kwargs.pop('port_handle')
                if kwargs.get('vlan_custom_config') is not None:
                    # vlan_custom_config = ['vlan_id', 'vlan_id_step', 'repeat_each' 'sequence']
                    cust_val = kwargs.get('vlan_custom_config')
                    mul_status = self.tg_multivalue_config(pattern='custom', nest_step='1', nest_owner=topo_han, nest_enabled='0')
                    cust_status = self.tg_multivalue_config(multivalue_handle=mul_status['multivalue_handle'], custom_start=cust_val[0], custom_step='0')
                    incr_status = self.tg_multivalue_config(custom_handle=cust_status['custom_handle'], custom_increment_value=cust_val[1], custom_increment_count=cust_val[2])
                    self.tg_multivalue_config(increment_handle=incr_status['increment_handle'], custom_increment_value='0', custom_increment_count=cust_val[3])
                    kwargs['vlan_id'] = mul_status['multivalue_handle']
                    kwargs['vlan_id_count'] = '1'
                    kwargs['vlan_id_step'] = '0'
                    kwargs.pop('vlan_custom_config', None)
            if kwargs.get('enable_flow_control') is not None:
                kwargs['enable_flow_control'] = 1 if kwargs['enable_flow_control'] == 'true' else 0
            for param in ('count', 'block_mode', 'enable_ping_response'):
                if kwargs.get(param) is not None:
                    kwargs.pop(param)

        if fname == 'tg_packet_control':
            if kwargs['action'] in ['start', 'cumulative_start']:
                self.ixia_eval('traffic_control', action='apply')
                # suggested by Ixia for more accurate results
                logger.info('Enabling control and data plane options')
                self.ixia_eval('packet_config_buffers', port_handle=kwargs['port_handle'],
                               control_plane_capture_enable='1',
                               data_plane_capture_enable='1')

        if fname == 'tg_traffic_stats':
            if kwargs.get('csv_path') is None:
                kwargs['csv_path'] = tgen_get_logs_path_folder()

        if fname == 'tg_emulation_bgp_route_config':
            if kwargs.get('mode') not in ['remove', 'delete']:
                if 'ipv6_prefix_length' in kwargs:
                    kwargs['prefix_from'] = kwargs['ipv6_prefix_length']
                    kwargs.pop('ipv6_prefix_length')
                if 'netmask' in kwargs:
                    kwargs['prefix_from'] = IPAddress(kwargs.pop('netmask', '255.255.255.0')).netmask_bits()
                logger.info('Disabling protocol before adding the route')
                # self.tg_topology_test_control(handle=kwargs['handle'], stack='deviceGroup', action='stop_protocol')
                self.tg_topology_test_control(action='stop_all_protocols', tg_wait=10)
                topo = re.search(r'.*topology:(\d)+', kwargs['handle']).group(0)
                logger.debug('Topology: {}'.format(topo))
                topo_index = list(self.topo_handle.values()).index(topo)
                tg_port = list(self.topo_handle.keys())[topo_index]
                logger.debug('port_handle: {}'.format(tg_port))
                flag = 0
                for _ in range(1, 30):
                    res = self.ixia_eval('protocol_info', mode='global_per_port')
                    logger.info(res)
                    if not res['global_per_port'].get(tg_port):
                        self.tg_topology_test_control(action='apply_on_the_fly_changes', tg_wait=2)
                        continue
                    total = res['global_per_port'][tg_port]['sessions_total']
                    total_ns = res['global_per_port'][tg_port]['sessions_not_started']
                    logger.debug("sessions_total = {}".format(total))
                    logger.debug("sessions_not_started = {}".format(total_ns))
                    if total == total_ns:
                        flag = 1
                        break
                    tgen_wait(2)
                if not flag:
                    msg = "Failed to get port {} from the protocol info".format(tg_port)
                    self.fail(msg, "tgen_failed_api", msg)
                tgen_wait(10)

        if fname == 'tg_emulation_bgp_config':
            if kwargs.get('local_as') is not None and kwargs.get('remote_as') is not None:
                if int(kwargs['local_as']) != int(kwargs['remote_as']):
                    kwargs['neighbor_type'] = 'external'
                else:
                    kwargs['neighbor_type'] = 'internal'
                kwargs.pop('remote_as')

        if fname == 'tg_emulation_igmp_config':
            kwargs['handle'] = kwargs['handle'][0] if type(kwargs['handle']) is list else kwargs['handle']
            self.tg_topology_test_control(handle=kwargs['handle'], stack='deviceGroup', action='stop_protocol')
            if kwargs.get('mode') == 'create':
                kwargs['handle'] = re.search(r'.*ipv4:(\d)+', kwargs['handle']).group(0)

        if fname in ['tg_emulation_igmp_control', 'tg_emulation_mld_control']:
            if kwargs.get('mode') in ['join', 'leave']:
                kwargs['group_member_handle'] = kwargs['handle']
                kwargs.pop('handle', None)

        if fname == 'tg_emulation_multicast_group_config':
            if kwargs.get('active') is None:
                kwargs['active'] = '1'
            kwargs.pop('ip_addr_step_val', '')

        if fname == 'tg_emulation_multicast_source_config':
            if kwargs.get('active') is None:
                kwargs['active'] = '1'
            kwargs.pop('ip_addr_step_val', '')

        if fname == 'tg_emulation_igmp_group_config':
            if kwargs.get('source_pool_handle') is None and kwargs.get('mode') == 'create':
                res = self.tg_emulation_multicast_source_config(mode='create', ip_addr_start='21.1.1.100',
                                                                num_sources=1, active=0)
                kwargs['source_pool_handle'] = res['multicast_source_handle']
            if kwargs.get('mode') == 'clear_all':
                self.map_field("handle", "session_handle", kwargs)

        if fname == 'tg_emulation_igmp_querier_config':
            if kwargs.get('active') is None and kwargs.get('mode') == 'create':
                kwargs['active'] = '1'
            if kwargs.get('mode') == 'create':
                kwargs['handle'] = re.search(r'.*ipv4:(\d)+', kwargs['handle']).group(0)
                self.tg_topology_test_control(handle=kwargs['handle'], stack='topology', action='stop_protocol')

        if fname == 'tg_emulation_mld_group_config':
            if kwargs.get('source_pool_handle') is None and kwargs.get('mode') == 'create':
                res = self.tg_emulation_multicast_source_config(mode='create', ip_addr_start='3000::1', num_sources=1,
                                                                active=0)
                kwargs['source_pool_handle'] = res['multicast_source_handle']
            if kwargs.get('mode') == 'clear_all':
                self.map_field("handle", "session_handle", kwargs)

        if fname == 'tg_emulation_mld_querier_config':
            if kwargs.get('mode') == 'create':
                handles, ret_kwargs = self.pre_interface_config(**kwargs)
                kwargs = ret_kwargs
                kwargs['handle'] = handles['handle']
                ver_map = {'MLD_V1': 'version1', 'MLD_V2': 'version2'}
                kwargs['version'] = ver_map[kwargs.pop('mld_version', '')]
            elif kwargs.get('mode') == 'delete':
                han = kwargs['handle']
                han = han[0] if type(han) is list else han
                self.tg_topology_test_control(handle=han, stack='deviceGroup', action='stop_protocol')

        if fname == 'tg_emulation_mld_config':
            if kwargs.get('mode') == 'create':
                handles, ret_kwargs = self.pre_interface_config(**kwargs)
                kwargs = ret_kwargs
                kwargs['handle'] = handles['ipv6_handle']
            elif kwargs.get('mode') == 'delete':
                han = kwargs['handle']
                han = han[0] if type(han) is list else han
                self.tg_topology_test_control(handle=han, stack='deviceGroup', action='stop_protocol')

        if fname == 'tg_emulation_ospf_config':
            kwargs['handle'] = kwargs['handle'][0] if isinstance(kwargs['handle'], list) else kwargs['handle']
            self.tg_topology_test_control(handle=kwargs['handle'], stack='ethernet', action='stop_protocol')
            if kwargs.get('mode') == 'create':
                kwargs['handle'] = re.search(r'.*ipv(4|6):(\d)+', kwargs['handle']).group(0)
                kwargs['area_id_type'] = 'ip'
                kwargs.pop('gateway_ip_addr', '')

        if fname == 'tg_emulation_dhcp_group_config':
            self.map_field("ipv4_gateway_address", "dhcp4_gateway_address", kwargs)
            self.map_field("gateway_ipv6_addr", "dhcp6_gateway_address", kwargs)
            self.map_field("vlan_ether_type", None, kwargs)
            self.map_field("gateway_addresses", None, kwargs)
            self.map_field("retry_attempts", None, kwargs)
            self.map_field("enable_auto_retry", None, kwargs)
            topo = kwargs.get('handle')
            topo_index = list(self.topo_handle.values()).index(topo)
            tg_port = list(self.topo_handle.keys())[topo_index]
            logger.debug('port_handle: {}'.format(tg_port))

            intf_kwrgs = dict()
            key_dict = {'count': 'num_sessions', 'src_mac_addr': 'mac_addr', 'vlan_id': 'vlan_id',
                        'vlan_custom_config': 'vlan_custom_config', 'vlan_id_step': 'vlan_id_step',
                        'vlan_id_count': 'vlan_id_count'}
            for key, val in key_dict.items():
                if kwargs.get(val):
                    intf_kwrgs[key] = kwargs.pop(val, None)
            if intf_kwrgs.get('count') is not None and intf_kwrgs.get('vlan_id_count') is not None:
                if int(intf_kwrgs.get('count')) != int(intf_kwrgs.get('vlan_id_count')):
                    intf_kwrgs.pop('vlan_id_count', '')
            if int(intf_kwrgs.get('count', 1)) > 1:
                intf_kwrgs.pop('vlan_id_count', '')
            intf_kwrgs['vlan'] = '1' if intf_kwrgs.get('vlan_id') else '0'
            intf_kwrgs['mode'] = 'config'
            intf_kwrgs['port_handle'] = tg_port
            intf_kwrgs['skip_start_protocol'] = True
            han = self.tg_interface_config(**intf_kwrgs)
            group_kwargs = dict()
            group_kwargs['handle'] = han['ethernet_handle']
            if str(kwargs.get("dhcp_range_ip_type")) == '4':
                group_kwargs['dhcp_range_ip_type'] = 'ipv4'
                group_kwargs['dhcp4_gateway_address'] = kwargs.get('dhcp4_gateway_address', '0.0.0.0')
            else:
                group_kwargs['dhcp_range_ip_type'] = 'ipv6'
                group_kwargs['dhcp6_gateway_address'] = kwargs.get('dhcp6_gateway_address', '::')
            kwargs = group_kwargs
            kwargs['skip_start_protocol'] = True
            del group_kwargs

        if fname == 'tg_emulation_dhcp_server_config':
            kwargs['handle'] = kwargs['handle'][0] if isinstance(kwargs['handle'], list) else kwargs['handle']
            self.tg_topology_test_control(handle=kwargs['handle'], stack='ethernet', action='stop_protocol')
            self.map_field("gateway_ipv6_addr", "ipv6_gateway", kwargs)
            self.map_field("remote_mac", "manual_gateway_mac", kwargs)
            self.map_field("encapsulation", "", kwargs)
            self.map_field("assign_strategy", "", kwargs)
            self.map_field("mac_addr", "", kwargs)
            if str(kwargs.get('ip_version')) == '6':
                self.map_field("addr_pool_addresses_per_server", "ipaddress_count", kwargs)
                self.map_field("prefix_pool_step", "", kwargs)
                self.map_field("prefix_pool_start_addr", "", kwargs)
                self.map_field("prefix_pool_per_server", "", kwargs)
                self.map_field("prefix_pool_prefix_length", "", kwargs)
                self.map_field("addr_pool_start_addr", "ipaddress_pool", kwargs)
                self.map_field("addr_pool_prefix_length", "ipaddress_pool_prefix_length", kwargs)
                self.map_field("addr_pool_step_per_server", "", kwargs)
                self.map_field("addr_pool_host_step", "pool_address_increment", kwargs)
                self.map_field("add_prefix_pool_start_addr", "ipaddress_pool", kwargs)
                self.map_field("add_prefix_pool_prefix_length", "ipaddress_pool_prefix_length", kwargs)
                self.map_field("add_prefix_pool_step_per_server", "ipaddress_pool_inside_step", kwargs)
                self.map_field("add_prefix_pool_step", "pool_address_increment", kwargs)
                self.map_field("server_emulation_mode", "", kwargs)
                self.map_field("local_ipv6_prefix_len", "", kwargs)
                self.map_field("local_ipv6_addr", "", kwargs)

                if kwargs.get('ipaddress_pool_inside_step') is None:
                    kwargs['ipaddress_pool_inside_step'] = '0:0:0:1::'
            kwargs['skip_start_protocol'] = True

        if fname == 'tg_emulation_dhcp_server_control':
            self.map_field("ip_version", "", kwargs)
            if kwargs.get('action') == 'connect':
                kwargs['action'] = 'collect'

        if fname == 'tg_emulation_dhcp_config':
            ip_version = kwargs.get('ip_version', '4')
            if 'retry_count' in kwargs or 'request_rate' in kwargs:
                self.ixia_eval('emulation_dhcp_config', handle='/globals', retry_count=kwargs.get('retry_count', 3),
                               request_rate=kwargs.get('request_rate', 200), ip_version=ip_version)

        if fname == 'tg_emulation_dhcp_stats':
            self.map_field("ip_version", "dhcp_version", kwargs)
            if kwargs.get('dhcp_version') is not None:
                kwargs['dhcp_version'] = 'dhcp4' if int(kwargs.get('dhcp_version')) == 4 else 'dhcp6'
            if kwargs.get('mode') == 'aggregate':
                kwargs['mode'] = 'aggregate_stats'
            if kwargs.get('mode') == 'detailed_session':
                kwargs['mode'] = 'session'

        if fname == 'tg_emulation_dhcp_control':
            self.map_field("ip_version", "", kwargs)
            self.map_field("port_handle", "", kwargs)
        return kwargs

    def tg_emulation_ipv6_autoconfig(self, **kwargs):
        self.map_field("mac_addr", "src_mac_addr", kwargs)
        self.map_field("mac_addr_step", "src_mac_addr_step", kwargs)
        self.map_field("router_solicit_retransmit_delay", "ipv6_autoconfiguration_send_rs_interval", kwargs)
        self.map_field("router_solicit_retry", None, kwargs)
        dict1 = {}
        for param in ['ipv6_autoconfiguration_send_rs_interval']:
            if param in kwargs:
                dict1[param] = kwargs.pop(param, '')
            self.tg_interface_config(protocol_handle='/globals', **dict1)
        if kwargs.get('mode') == 'create':
            handles, _ = self.pre_interface_config(**kwargs)
            addr_mode = kwargs.get('ipv6_addr_mode', 'autoconfig')
            handles = self.tg_interface_config(ipv6_addr_mode=addr_mode, protocol_handle=handles['ethernet_handle'])

            handles['handle'] = handles['ipv6autoconfiguration_handle']
        elif kwargs.get('mode') == 'reset':
            kwargs['mode'] = 'destroy'
            handles = self.tg_interface_config(**kwargs)
        return handles if handles['status'] == '1' else None

    def tg_emulation_ipv6_autoconfig_control(self, **kwargs):
        han = kwargs['handle']
        kwargs.get('port_handle', '')
        if kwargs.get('action') == 'start':
            self.tg_topology_test_control(handle=han, stack='ipv6Autoconfiguration', action='start_protocol', skip_wait=True)
        if kwargs.get('action') == 'stop':
            self.tg_topology_test_control(handle=han, stack='ipv6Autoconfiguration', action='stop_protocol', skip_wait=True)

    def tg_emulation_dot1x_config(self, **kwargs):
        if int(kwargs.get('num_sessions', 1)) > 1:
            for entry in ['username', 'password']:
                if kwargs.get(entry):
                    pattern = str(kwargs[entry]) + '{Inc:0,1}'
                    ret_val = self.tg_multivalue_config(pattern="string", string_pattern=pattern)
                    kwargs[entry] = ret_val['multivalue_handle']
        self.map_field("username", "user_name", kwargs)
        self.map_field("password", "user_pwd", kwargs)
        self.map_field("eap_auth_method", "protocol_type", kwargs)
        self.map_field("username_wildcard", "", kwargs)
        self.map_field("password_wildcard", "", kwargs)
        self.map_field("wildcard_pound_start", "", kwargs)
        self.map_field("wildcard_question_start", "", kwargs)
        self.map_field("encapsulation", "", kwargs)
        self.map_field("local_ip_addr", "", kwargs)
        self.map_field("ip_version", "", kwargs)
        self.map_field("gateway_ip_addr", "", kwargs)
        self.map_field("auth_retry_interval", "", kwargs)
        self.map_field("auth_retry_count", "", kwargs)
        self.map_field("retransmit_count", "", kwargs)
        self.map_field("retransmit_interval", "", kwargs)

        if kwargs.get('mode') == 'create':
            port_han = kwargs.pop('port_handle', '')
            intf_kwrgs = dict()
            key_dict = {'count': 'num_sessions', 'src_mac_addr': 'mac_addr', 'vlan_id': 'vlan_id',
                        'vlan_id_step': 'vlan_id_step',
                        'vlan_id_count': 'vlan_id_count', 'src_mac_address_step': 'mac_addr_step'}
            for key, val in key_dict.items():
                if kwargs.get(val):
                    intf_kwrgs[key] = kwargs.pop(val, None)
            intf_kwrgs['vlan'] = '1' if intf_kwrgs.get('vlan_id') else '0'
            intf_kwrgs['mode'] = 'config'
            intf_kwrgs['port_handle'] = port_han
            intf_kwrgs['skip_start_protocol'] = True
            han = self.tg_interface_config(**intf_kwrgs)
            kwargs['handle'] = han['ethernet_handle']
        elif kwargs.get('mode') == 'delete':
            han = kwargs['handle']
            han = han[0] if type(han) is list else han
            self.tg_topology_test_control(handle=han, stack='deviceGroup', action='stop_protocol')
        kwargs['skip_start_protocol'] = True
        result = self.tg_emulation_dotonex_config(**kwargs)
        return result if result['status'] == '1' else None

    def tg_emulation_dot1x_control(self, **kwargs):
        if kwargs.get('mode') == 'logout':
            kwargs['mode'] = 'stop'
        result = self.tg_emulation_dotonex_control(**kwargs)
        return result if result['status'] == '1' else None

    def emulation_dot1x_stats(self, **kwargs):
        if kwargs.get('mode') == 'aggregate':
            kwargs['mode'] = 'per_port_stats'
        if kwargs.get('mode') == 'sessions':
            kwargs['mode'] = 'per_session_stats'
        result = self.tg_emulation_dotonex_info(**kwargs)
        return result if result['status'] == '1' else None

    def tg_emulation_ptp_control(self, **kwargs):
        if re.search(r'.*ipv(4|6):(\d)+', kwargs.get('handle')):
            result = self.tg_ptp_over_ip_control(**kwargs)
        else:
            result = self.tg_ptp_over_mac_control(**kwargs)
        return result if result['status'] == '1' else None

    def tg_emulation_ptp_stats(self, **kwargs):
        kwargs.pop('port_handle', '')
        if not kwargs.get('handle'):
            logger.info('Provide argument handle to fetch the stats')
            return {}
        if re.search(r'.*ipv(4|6):(\d)+', kwargs.get('handle')):
            result = self.tg_ptp_over_ip_stats(**kwargs)
        else:
            result = self.tg_ptp_over_mac_stats(**kwargs)
        return result if result['status'] == '1' else None

    def tg_emulation_ptp_config(self, **kwargs):
        self.map_field("master_clock_priority1", "priority1", kwargs)
        self.map_field("master_clock_priority2", "priority2", kwargs)
        self.map_field("log_sync_message_interval", "log_sync_interval", kwargs)
        self.map_field("path_delay_mechanism", "delay_mechanism", kwargs)
        self.map_field("device_type", "role", kwargs)
        self.map_field("log_minimum_delay_request_interval", "log_delay_req_interval", kwargs)
        self.map_field("log_announce_message_interval", "log_announce_interval", kwargs)
        self.map_field("ptp_port_number", "port_number", kwargs)
        self.map_field("ptp_session_mode", "communication_mode", kwargs)
        self.map_field("master_clock_class", "clock_class", kwargs)
        self.map_field("ptp_domain_number", "domain", kwargs)
        self.map_field("local_mac_addr", "src_mac_addr", kwargs)
        self.map_field("vlan_id1", "vlan_id", kwargs)
        self.map_field("local_ip_addr", "intf_ip_addr", kwargs)
        self.map_field("local_ip_prefix_len", "netmask", kwargs)
        self.map_field("remote_ip_addr", "gateway", kwargs)
        self.map_field("frequency_traceable", "announce_frequency_traceable", kwargs)
        self.map_field("custom_clock_accuracy", "clock_accuracy", kwargs)
        self.map_field("utc_offset", "current_utc_offset", kwargs)
        self.map_field("time_traceable", "announce_time_traceable", kwargs)
        self.map_field("local_ipv6_addr", "ipv6_intf_addr", kwargs)
        self.map_field("local_ipv6_prefix_len", "ipv6_prefix_length", kwargs)
        self.map_field("remote_ipv6_addr", "ipv6_gateway", kwargs)

        transport_type = kwargs.pop('transport_type', '')
        time_source_map = {'atomic-clock': '0X10', 'gps': '0X20', 'terrestrial-radio': '0X30', 'ptp': '0X40',
                           'ntp': '0X50', 'handset': '0X60', 'other': '0X90', 'internal-oscillator': '0XA0'}
        if kwargs.get('time_source') in ['ptp-profile', 'reserved']:
            logger.info('Provided invalid value for time sorce')
            return False
        if kwargs.get('time_source'):
            kwargs['time_source'] = time_source_map.get(kwargs.get('time_source', 'gps'))
        log_intv_map = {'-9': '247', '-8': '248', '-7': '249', '-6': '250', '-5': '251', '-4': '252', '-3': '253',
                        '-2': '254', '-1': '255', '0': '0', '1': '1', '2': '2', '3': '3', '4': '4', '5': '5', '6': '6',
                        '7': '7', '8': '8', '9': '9'}
        for param in ['log_sync_interval', 'log_delay_req_interval', 'log_announce_interval']:
            if kwargs.get(param):
                kwargs[param] = log_intv_map.get(kwargs.get(param, '0'))
        if kwargs.get('delay_mechanism') == 'end-to-end':
            kwargs['delay_mechanism'] = 'E2E'
        if kwargs.get('delay_mechanism') == 'peer-to-peer':
            kwargs['delay_mechanism'] = 'P2P'
        sync_two_step_flag = kwargs.pop('sync_two_step_flag', '')
        if sync_two_step_flag == 'on':
            kwargs['step_mode'] = 'two-step'
        if sync_two_step_flag == 'off':
            kwargs['step_mode'] = 'one-step'
        if kwargs.get('role') == 'ptpMaster':
            kwargs['role'] = 'master'
        if kwargs.get('role') == 'ptpSlave':
            kwargs['role'] = 'slave'
        leap_flag = kwargs.pop('leap_flag', '')
        if leap_flag == 'leap59':
            kwargs['announce_leap59'] = '1'
        if leap_flag == 'leap61':
            kwargs['announce_leap61'] = '1'
        clock_acc_map = {'less_025_0ns': '32', 'less_100_0ns': '33', 'less_250_0ns': '34', 'less_001_0us': '35',
                         'less_002_5us': '36', 'less_010_0us': '37', 'less_025_0us': '38', 'less_100_0us': '39',
                         'less_250_0us': '40', 'less_001_0ms': '41', 'less_002_5ms': '42', 'less_010_0ms': '43',
                         'less_025_0ms': '44', 'less_100_0ms': '45', 'less_250_0ms': '46', 'less_001_0s': '47',
                         'less_010_0s': '48', 'greater_010_0s': '49'}
        if kwargs.get('clock_accuracy'):
            kwargs['clock_accuracy'] = clock_acc_map.get(kwargs.get('clock_accuracy', 'less_001_0us'))
        res_dict = {'true': '1', 'false': '0', '1': '1', '0': '0'}
        for param in ['announce_frequency_traceable', 'announce_time_traceable', 'announce_current_utc_offset_valid', 'announce_ptp_timescale', 'path_trace_tlv']:
            if kwargs.get(param):
                kwargs[param] = res_dict.get(kwargs.get(param, '0'))
        if kwargs.get('mode') == 'create':
            if not transport_type:
                logger.info('Mandatory argument transport_type not provided')
                return False
            handles, ret_kwargs = self.pre_interface_config(**kwargs)
            kwargs = ret_kwargs
            if transport_type == 'ethernet_ii':
                kwargs['parent_handle'] = handles['ethernet_handle']
            if transport_type == 'ipv4':
                kwargs['parent_handle'] = handles['ipv4_handle']
            if transport_type == 'ipv6':
                kwargs['parent_handle'] = handles['ipv6_handle']
        elif kwargs.get('mode') == 'delete':
            han = kwargs['handle']
            han = han[0] if type(han) is list else han
            self.tg_topology_test_control(handle=han, stack='deviceGroup', action='stop_protocol')
            if not transport_type:
                ret_val = re.search(r'.*ipv(4|6):(\d)+', han)
                if ret_val:
                    if ret_val.group(1) == '4':
                        transport_type = 'ipv4'
                    if ret_val.group(1) == '6':
                        transport_type = 'ipv6'
                else:
                    transport_type = 'ethernet_ii'
        if transport_type == 'ethernet_ii':
            result = self.tg_ptp_over_mac_config(**kwargs)
        elif transport_type in ['ipv4', 'ipv6']:
            result = self.tg_ptp_over_ip_config(**kwargs)
        else:
            logger.info('Invlaid transport_tye provided')
            return {}
        return result if result['status'] == '1' else None

    def tg_emulation_dhcp_server_relay_agent_config(self, **kwargs):
        self.map_field("relay_agent_pool_count", "pool_count", kwargs)
        self.map_field("relay_agent_ipaddress_pool", "ipaddress_pool", kwargs)
        self.map_field("prefix_length", "ipaddress_pool_prefix_length", kwargs)
        self.map_field("relay_agent_pool_step", "ipaddress_pool_inside_step", kwargs)
        self.map_field("relay_agent_ipaddress_step", "pool_address_increment", kwargs)
        self.map_field("relay_agent_ipaddress_count", "ipaddress_count", kwargs)
        self.map_field("vpn_id_type", "", kwargs)
        kwargs.pop('vpn_id', None)
        assign_strategy = kwargs.pop('assign_strategy', None)
        if assign_strategy == 'link_selection':
            kwargs['subnet_addr_assign'] = 1
            kwargs['subnet'] = "relay link_selection"
        kwargs['mode'] = 'modify'
        if kwargs.get('ipaddress_pool_prefix_length') is not None and kwargs.get('ipaddress_count') is None:
            kwargs['ipaddress_count'] = 2**(32 - int(kwargs['ipaddress_pool_prefix_length'])) - 3

        self.tg_emulation_dhcp_server_config(**kwargs)

    def tg_interface_handle(self, ret_ds):
        if "interface_handle" in ret_ds:
            if "ipv4_handle" in ret_ds or "ipv6_handle" in ret_ds:
                temp = ret_ds['interface_handle'].split()
                # Removing extra ethernet handles.
                temp = temp[:int(len(temp) / 2)]
                ret_ds['handle'] = temp[0] if len(temp) == 1 else temp
            else:
                ret_ds['handle'] = ret_ds['interface_handle']
        return ret_ds

    def tg_igmp_querier_control(self, mode, handle):
        result = self.tg_emulation_igmp_control(mode=mode, handle=handle)
        tgen_wait(10)
        logger.info("IGMP Querier action completed: {}".format(result))
        return result if result['status'] == '1' else None

    def tg_mld_querier_control(self, mode, handle):
        result = self.tg_emulation_mld_control(mode=mode, handle=handle)
        tgen_wait(10)
        logger.info("MLD Querier action completed: {}".format(result))
        return result if result['status'] == '1' else None

    def tg_withdraw_bgp_routes(self, route_handle):
        result = self.tg_emulation_bgp_control(handle=route_handle, mode='stop')
        logger.info('withdraw action completed: {}'.format(result))
        return result if result['status'] == '1' else None

    def tg_readvertise_bgp_routes(self, handle, route_handle):
        result = self.tg_emulation_bgp_control(handle=route_handle, mode='start')
        logger.info('readvertise action completed: {}'.format(result))
        return result if result['status'] == '1' else None

    def tg_ospf_lsa_config(self, **kwargs):
        prefix_type = {'summary_pool': 'summary', 'ext_pool': 'external', 'nssa_ext_pool': 'nssa'}
        for type, prefix in prefix_type.items():
            if kwargs['type'] == type:
                prefix_ret = prefix
                if type == 'ext_pool':
                    prefix_ret = 'external1' if str(kwargs['external_prefix_type']) == '1' else 'external2'
                self.map_field('{}_prefix_start'.format(prefix), '{}_network_address'.format(prefix_ret), kwargs)
                self.map_field('{}_number_of_prefix'.format(prefix), '{}_number_of_routes'.format(prefix_ret), kwargs)
                self.map_field('{}_prefix_length'.format(prefix), '{}_prefix'.format(prefix_ret), kwargs)
                self.map_field('{}_prefix_metric'.format(prefix), '{}_metric'.format(prefix_ret), kwargs)
                kwargs.pop('{}_prefix_type'.format(prefix), '')
                kwargs['{}_active'.format(prefix_ret)] = '1'
        kwargs['type'] = 'linear'
        kwargs['linear_nodes'] = '1'
        kwargs['from_ip'] = '1.0.0.1'
        kwargs['to_ip'] = '1.0.0.2'
        result = self.tg_emulation_ospf_network_group_config(**kwargs)
        logger.info('OSPF route config completed: {}'.format(result))
        return result if result['status'] == '1' else None

    def tg_emulation_ospf_route_config(self, **kwargs):
        if kwargs.get('mode') == 'delete':
            kwargs['handle'] = re.search(r'.*networkGroup:(\d)+', kwargs['handle']).group(0)
        elif kwargs.get('mode') == 'create':
            ret = re.search(r'.*ospfv(\d):*', kwargs['handle']).group(1)
            ver = '4' if str(ret) == '2' else '6'
            if kwargs['type'] == 'summary_routes':
                kwargs['ipv{}_prefix_route_origin'.format(ver)] = 'another_area'
            if kwargs['type'] == 'ext_routes':
                route_origin = 'external_type_1' if str(kwargs['external_prefix_type']) == '1' else 'external_type_2'
                kwargs['ipv{}_prefix_route_origin'.format(ver)] = route_origin
                kwargs.pop('external_prefix_type', '')
            if kwargs['type'] == 'network':
                # TODO: Code need to implenented for network type route prefixes
                pass
            if kwargs['type'] == 'nssa_routes':
                kwargs['ipv{}_prefix_route_origin'.format(ver)] = 'nssa'
                kwargs.pop('nssa_prefix_type', '')

            prefix_type = {'summary_routes': 'summary', 'ext_routes': 'external', 'nssa_routes': 'nssa',
                           'network': 'net', 'router': 'router'}
            for type, prefix in prefix_type.items():
                if kwargs['type'] == type and kwargs['type'] not in ['network', 'router']:
                    self.map_field('{}_prefix_start'.format(prefix), 'ipv{}_prefix_network_address'.format(ver), kwargs)
                    self.map_field('{}_number_of_prefix'.format(prefix), 'ipv{}_prefix_number_of_addresses'.format(ver),
                                   kwargs)
                    self.map_field('{}_prefix_length'.format(prefix), 'ipv{}_prefix_length'.format(ver), kwargs)
                    self.map_field('{}_prefix_metric'.format(prefix), 'ipv{}_prefix_metric'.format(ver), kwargs)
                    kwargs['type'] = 'ipv4-prefix' if ver == '4' else 'ipv6-prefix'
                elif kwargs['type'] == 'router':
                    # TODO: Code need to implenented for router prefixes
                    kwargs['type'] = 'linear'
                    kwargs['linear_nodes'] = '100'  # Prefix count
                    kwargs['from_ip'] = '1.0.0.1'
                    kwargs['to_ip'] = '1.0.0.2'
                else:
                    # TODO: Code need to implenented for network prefixes
                    pass
        result = self.tg_emulation_ospf_network_group_config(**kwargs)
        self.tg_topology_test_control(action='apply_on_the_fly_changes')
        logger.info('OSPF route config completed: {}'.format(result))
        return result if result['status'] == '1' else None

    def trgen_post_proc(self, fname, **kwargs):
        if fname == 'tg_emulation_bgp_route_config':
            if kwargs.get('mode') in ['remove', 'delete']:
                self.tg_topology_test_control(action='apply_on_the_fly_changes')
            else:
                logger.info('Enabling protocol after adding the route')
                self.tg_topology_test_control(handle=kwargs['handle'], stack='ipv(4|6)', action='start_all_protocols')

        if fname == 'tg_emulation_igmp_group_config':
            if kwargs.get('mode') == 'create':
                logger.info('Enabling protocol after adding the igmp host')
                kwargs['handle'] = kwargs['session_handle'][0] if type(kwargs['session_handle']) is list else kwargs['session_handle']
                self.tg_topology_test_control(handle=kwargs['handle'], stack='deviceGroup', action='start_protocol')
                logger.info('Disabling IGMP Host after starting the devicegroup ...')
                res = self.tg_emulation_igmp_control(handle=kwargs['session_handle'], mode='stop')
                logger.debug('{}'.format(res))
                tgen_wait(5)

        if fname == 'tg_emulation_igmp_querier_config':
            if kwargs.get('mode') == 'create':
                logger.info('Enabling protocol after adding the igmp host')
                self.tg_topology_test_control(handle=kwargs['handle'], stack='topology', action='start_protocol')

        if fname == 'tg_emulation_ospf_config':
            kwargs['handle'] = kwargs['handle'][0] if isinstance(kwargs['handle'], list) else kwargs['handle']
            self.tg_topology_test_control(handle=kwargs['handle'], stack='ipv(4|6)', action='start_protocol')

        if fname == 'tg_emulation_dotonex_config':
            tgen_wait(2)
        self.skip_start_protocol = False

    def tg_arp_control(self, **kwargs):
        if 'handle' in kwargs:
            han = kwargs['handle']
            if type(han) is list:
                han = re.search(r'.*ipv(4|6):(\d)+', han[0]).group(0)
            result = self.tg_interface_config(protocol_handle=han, arp_send_req='1')
        elif 'port_handle' in kwargs:
            result = self.tg_interface_config(port_handle=kwargs['port_handle'], arp_send_req='1')
        else:
            result = None
        logger.info('Sending ARP completed: {}'.format(result))
        return result

    def tg_disconnect(self, **kwargs):
        if self.skip_traffic:
            return 0
        logger.info('Executing: {} {}'.format('ixiangpf.cleanup_session', kwargs))
        port_handle_list = self.get_port_handle_list()
        ret_ds = self.ixia_eval('cleanup_session', maintain_lock=0, port_handle=port_handle_list, reset=1)
        logger.info(ret_ds)
        if ret_ds['status'] == '1':
            logger.debug('TGen: API Run Status: Success')
        else:
            logger.warning('TGen: API Error: %s' % ret_ds['log'])
        self.tg_connected = False
        self.tg_port_handle.clear()

    def tg_save_config(self, file_name=None, file_path=None, fail_reason=''):
        datetime = utils.get_current_datetime(fmt='%Y_%m_%d_%H_%M_%S')
        config_file = 'ixNetconfig_' + fail_reason + '_' + datetime + '.ixncfg'
        file_name = config_file if not file_name else file_name
        # file_path = tgen_get_logs_path_folder() if not file_path else file_path
        # filename = os.path.join(file_path, file_name)
        _, config_path = self._ixnet_config_file_location()
        logger.info('Saving Ixia session configuration....')
        logger.info('Config File Path: API server {}@{}'.format(self.ix_server.split(':')[0], config_path))
        logger.info('Configuration File: {}'.format(file_name))
        get_ixnet().execute('saveConfig', get_ixnet().writeTo(file_name, '-ixNetRelative'))

    def _ixnet_config_file_location(self):
        if self.ixnetwork_os == 'linux':
            file_path = '/opt/ixia/IxNetwork/9.10.2007.7/aptixia/api/logcollector'
            config_path = '/opt/ixia/IxNetwork/9.10.2007.7/'
        else:
            file_path = r'C:\Program Files (x86)\Ixia\IxNetwork\9.10.2007.7\diagnostic'
            config_path = r'C:\Program Files (x86)\Ixia\IxNetwork\9.10.2007.7'
        return file_path, config_path

    def collect_diagnosic(self, fail_reason, from_fail=False):
        # Default Location of collected diags for Windows :: C:\Program Files (x86)\Ixia\IxNetwork\9.10.2007.7\diagnostic
        # Default Location of collected diags for Linux:: /opt/ixia/IxNetwork/9.10.2007.7/aptixia/api/logcollector
        if os.getenv("SPYTEST_TGEN_COLLECT_DIAGNOSTICS", "0") == "0":
            return
        try:
            file_location = ''
            if self.tg_version in ["7.4", "7.40"]:
                return
            if self.tg_version in ["8.4", "8.40", "8.42", "8.42"]:
                file_location = get_ixnet().getAttribute('::ixNet::OBJ-/globals', '-persistencePath') + '\\'
            file_path, _ = self._ixnet_config_file_location()
            datetime = utils.get_current_datetime(fmt='%Y_%m_%d_%H_%M_%S')
            self.tg_save_config(fail_reason=fail_reason)
            logger.info('Collecting Ixia diagnostics....started')
            logger.info('Diagnostics File Path: API server {}@{}'.format(self.ix_server.split(':')[0], file_path))
            diags_file = file_location + 'ixNetDiag_' + fail_reason + '_' + datetime + '_Collect.zip'
            logger.info('Diagnostics File: {}'.format(diags_file))
            get_ixnet().execute('collectLogs', get_ixnet().writeTo(diags_file, '-ixNetRelative'), 'currentInstance')
            logger.info('Collecting Ixia diagnostics....completed')
        except Exception as ex:
            if not from_fail:
                self.fail(ex, "tgen_failed_api", str(ex))
            else:
                logger.error(str(ex))

    def local_ixnet_call(self, method, *args):
        # ::ixNet::OK'
        # IxNetError:
        func_call = 'ixiangpf.ixnet.' + method
        # nosemgrep-next-line
        res = eval(func_call)(*args)
        if re.search(r'Error', res):
            logger.info('Error in ixNet call {}: {}'.format(func_call, res))
        return res

    def local_get_captured_packets(self, **kwargs):
        packet_type = kwargs.get('packet_type', 'data')
        if packet_type.lower() == 'control':
            packet_type = 'control'

        ret_dict = dict()
        # get vport info
        res = self.tg_convert_porthandle_to_vport(port_handle=kwargs['port_handle'])
        vport_handle = res['handle']
        var_num_frames = kwargs.get('var_num_frames', 20)
        for i in range(3):
            try:
                captured_packets = dict()
                cap_pkt_count = self.local_ixnet_call('getAttribute', vport_handle + '/capture', '-' + packet_type + 'PacketCounter')
                logger.debug('Capture packet count on wire: {}'.format(cap_pkt_count))
                pkts_in_buffer = int(cap_pkt_count) if int(cap_pkt_count) <= int(var_num_frames) else int(var_num_frames)
                captured_packets.update({'aggregate': {'num_frames': pkts_in_buffer}})
                captured_packets['frame'] = dict()
                for pkt_count in range(0, pkts_in_buffer):
                    sub_method = 'getPacketFrom' + packet_type.title() + 'Capture'
                    self.local_ixnet_call('execute', sub_method, vport_handle + '/capture/currentPacket', pkt_count)
                    hp = self.local_ixnet_call('getAttribute', vport_handle + '/capture/currentPacket', '-packetHex')
                    frame_in_hex = hp.encode('ascii', 'ignore').split()[2:]
                    frame_in_hex_upper = [byte.upper() for byte in frame_in_hex]
                    captured_packets['frame'].update({str(pkt_count): {'frame_pylist': frame_in_hex_upper}})
                ret_dict[kwargs['port_handle']] = captured_packets
                ret_dict['status'] = '1'
                ret_dict.pop('log', '')
                break
            except Exception as exp:
                if captured_packets.get('frame') and len(captured_packets['frame']) > 0:
                    logger.debug('No. of capture packets fetched: {}'.format(len(captured_packets['frame'])))
                    ret_dict[kwargs['port_handle']] = captured_packets
                    ret_dict['status'] = '1'
                    break
                else:
                    ret_dict['log'] = str(exp)
                logger.error('Capture packet get failed:: {}: Trying again....{}'.format(str(exp), i))
        return ret_dict

    def tg_custom_filter_config(self, **kwargs):
        ret_dict = dict()
        ret_dict['status'] = '1'
        ixia_kwargs = dict()

        if not kwargs.get('mode') or not kwargs.get('port_handle'):
            logger.info("Missing Mandatory parameter: port_handle or mode")
            ret_dict['status'] = '0'
            return ret_dict

        mode = kwargs.get('mode').lower()
        action = kwargs.get('action', 'cumulative_start')
        port_handle = kwargs.get('port_handle')
        ixia_kwargs['port_handle'] = port_handle
        offset_count = 0
        if mode != 'getstats':
            for offset, pattern in zip(['pattern_offset1'], ['pattern1']):
                if not kwargs.get(offset) or not kwargs.get(pattern):
                    logger.info('Missing Mandatory parameter {} or {}'.format(offset, pattern))
                    ret_dict['status'] = '0'
                    return ret_dict
                offset_count += 1
                ixia_kwargs['pattern_offset1'] = kwargs['pattern_offset1']
                ixia_kwargs['pattern1'] = kwargs['pattern1']
                capture_filter_pattern = 'pattern1'

            for offset, pattern in zip(['pattern_offset2'], ['pattern2']):
                if kwargs.get(offset) and kwargs.get(pattern):
                    offset_count += 1
                    ixia_kwargs['pattern_offset2'] = kwargs['pattern_offset2']
                    ixia_kwargs['pattern2'] = kwargs['pattern2']
                    capture_filter_pattern = 'pattern1and2'

                elif not kwargs.get(offset) and not kwargs.get(pattern):
                    pass
                else:
                    logger.info('Both parameter {} and {} need to be provided'.format(offset, pattern))
                    ret_dict['status'] = '0'
                    return ret_dict

        # capture_filter_pattern = kwargs.get('capture_filter_pattern','pattern1and2')
        if mode == 'create':
            self.tg_packet_control(port_handle=port_handle, action='reset')
            self.tg_packet_config_buffers(port_handle=port_handle, capture_mode='trigger',
                                          before_trigger_filter='all', after_trigger_filter='filter')
            self.tg_packet_config_filter(**ixia_kwargs)
            self.tg_packet_config_triggers(port_handle=port_handle, capture_trigger=1,
                                           capture_filter=1, capture_filter_pattern=capture_filter_pattern)
            self.tg_packet_control(port_handle=port_handle, action=action)

        if mode == 'getstats':
            self.tg_packet_control(port_handle=port_handle, action='stop')
            ret_dict[port_handle] = {}
            ret_dict[port_handle].update({'custom_filter': {}})
            filtered_frame_count = 0
            total_rx_count = 0
            self.get_capture_stats_state(port_handle, capture_wait=kwargs.get('capture_wait', 120))
            result = self.tg_packet_stats(port_handle=port_handle)
            if result['status'] != '1':
                for i in range(1, 5):
                    logger.info('Get Filtered Stats Failed, Trying again, after 5 sec...Try: {}'.format(i))
                    tgen_wait(5)
                    result = self.tg_packet_stats(port_handle=port_handle)
                    if result['status'] == '1':
                        break

            logger.info(result)
            if result['status'] == '1':
                filtered_frame_count = result[port_handle]['aggregate']['uds4_frame_count']
                total_rx_count = result[port_handle]['aggregate']['uds3_frame_count']

            ret_dict[port_handle]['custom_filter'].update({'filtered_frame_count': filtered_frame_count})
            ret_dict[port_handle]['custom_filter'].update({'total_rx_count': total_rx_count})

        return ret_dict

    def ensure_traffic_stats(self, timeout=60, skip_fail=False, **kwargs):
        if os.getenv("SPYTEST_ENSURE_TRAFFIC_STATS", "0") == "0":
            return
        logger.debug("Waiting to stabilize the traffic stats...")
        mode = kwargs.get('mode')
        traffic_mode = {'traffic_item': 'Traffic Item Statistics', 'flow': 'Flow Statistics',
                        'aggregate': 'Port Statistics'}
        if traffic_mode.get(mode) is not None:
            if mode == 'all':
                view_traffic_page = get_ixnet().getList('/statistics', 'view')
            else:
                view_traffic_page = r'::ixNet::OBJ-/statistics/view:"{}"/page'.format(traffic_mode[mode])
            for page in utils.make_list(view_traffic_page):
                # logger.debug("Traffic Mode: {}, Traffic View: {}".format(mode, page))
                tgen_wait(3 * self._get_pooling_interval(page, timeout, skip_fail))

    def _get_pooling_interval(self, view_page, timeout, skip_fail):
        ts1 = int(get_ixnet().getAttribute(view_page, '-timestamp'))
        count = 0
        while (ts1 >= int(get_ixnet().getAttribute(view_page, '-timestamp'))):
            time.sleep(1)
            count += 1
            if count > timeout:
                msg = 'no stats refresh happened for more than {} sec'.format(timeout)
                logger.error(msg)
                if not skip_fail:
                    self.fail(msg, "tgen_failed_api", msg)
        ts2 = int(get_ixnet().getAttribute(view_page, '-timestamp'))
        return (ts2 - ts1) / 1000

    def ensure_traffic_control(self, timeout=180, skip_fail=False, **kwargs):
        if os.getenv("SPYTEST_ENSURE_TRAFFIC_CONTROL", "0") == "0":
            return
        action = kwargs.get('action')
        handle = kwargs.get('handle')
        port_handle = kwargs.get('port_handle')
        duration = utils.integer_parse(kwargs.get('duration', 0))
        traffic_elems = []
        if handle:
            for h in utils.make_list(handle):
                traffic_elems.extend(self._get_traffic_elem_from_stream_id(h))
        elif port_handle:
            for ph in utils.make_list(port_handle):
                traffic_elems.extend(self._get_traffic_elem_from_port_handle(ph))
        else:
            logger.error("neither handle nor port_handle specified")
            return
        for traffic_elem in traffic_elems:
            if action == "run":
                self._ensure_traffic_elem_start(traffic_elem, duration, timeout, skip_fail)
            elif action == "stop":
                self._ensure_traffic_elem_stop(traffic_elem, duration, timeout, skip_fail)
        if action == 'reset':
            if not port_handle:
                return
            port_handle = utils.make_list(port_handle)
            for han in port_handle:
                if han in self.traffic_config_handles:
                    self.traffic_config_handles.pop(han)

    def _get_traffic_elem_from_stream_id(self, stream_id):
        retval = []
        for port_handle in self.traffic_config_handles:
            for ent in self.traffic_config_handles[port_handle]:
                if ent["res"]["stream_id"] == stream_id:
                    retval.append(ent)
        return retval

    def _get_traffic_elem_from_port_handle(self, port_handle):
        if port_handle not in self.traffic_config_handles:
            # logger.error("port_handle {} not found in cache".format(port_handle))
            return [None]
        return self.traffic_config_handles[port_handle]

    def _read_traffic_elem_duration_and_mode(self, traffic_elem, duration):
        kws = traffic_elem["kwargs"]
        config_duration = utils.integer_parse(kws.get("duration", 0))
        if config_duration > duration:
            duration = config_duration
        return duration, kws.get("transmit_mode")

    def _ensure_traffic_elem_start(self, traffic_elem, duration, timeout=180, skip_fail=False):
        if traffic_elem is None:
            logger.info("skip checking for start traffic elem")
            return True
        duration, transmit_mode = self._read_traffic_elem_duration_and_mode(traffic_elem, duration)
        if duration > 0 or transmit_mode in ['single_burst']:
            # need to wait for completion of traffic when duration is specified
            # Stopping traffic in fixed duration and single_burst scenarios
            tgen_wait(duration)
            res = self.ixia_eval('traffic_control', action='stop', handle=traffic_elem["res"]['stream_id'])
            logger.info('Traffic Stop: {}'.format(res))
            return self._ensure_traffic_elem_stop(traffic_elem, duration, timeout, skip_fail)
        timeout = timeout if timeout > duration else duration + 10
        end_time = time.time() + timeout
        msg = "Verifying stream_id start: {}, trafficItem: {}".format(traffic_elem["res"]['stream_id'],
                                                                      traffic_elem['traffic_item'])
        logger.debug(msg)
        while True:
            try:
                state = get_ixnet().getAttribute(traffic_elem["traffic_item"], '-state')
            except Exception as exp:
                msg = "Traffic item not found for stream_id: {}, Exception: {}".format(traffic_elem["res"]['stream_id'], exp)
                logger.error(msg)
                return False
            if state == "started":
                return True
            if "unapplied" in state:
                for errr_type in ['errors', 'warnings']:
                    err_logs = get_ixnet().getAttribute(traffic_elem["traffic_item"], '-' + errr_type)
                    logger.error("Unapplied {}: {}".format(errr_type.upper(), err_logs))
                # msg = "traffic is not configured"
                # self.fail(msg, "tgen_failed_api", msg)
                return False
            time.sleep(1)
            if time.time() > end_time:
                break
        if not skip_fail:
            logger.debug("Verifying stream_id: {}, State: {}".format(traffic_elem["res"]['stream_id'], state))
            msg = "Failed to start the traffic in {} seconds".format(timeout)
            self.fail(msg, "tgen_failed_api", msg)
        return False

    def _ensure_traffic_elem_stop(self, traffic_elem, duration, timeout=180, skip_fail=False):
        if traffic_elem is None:
            logger.info("skip checking for stop traffic elem")
            return True
        timeout = timeout if timeout > duration else duration + 10
        end_time = time.time() + timeout
        msg = "Verifying stream_id stop: {}, trafficItem: {}".format(traffic_elem["res"]['stream_id'], traffic_elem['traffic_item'])
        logger.debug(msg)
        while True:
            try:
                state = get_ixnet().getAttribute(traffic_elem["traffic_item"], '-state')
            except Exception as exp:
                msg = "Traffic item not found for stream_id: {}, Exception: {}".format(traffic_elem["res"]['stream_id'], exp)
                logger.debug(msg)
                return False
            if state == "stopped":
                return True
            if "unapplied" in state:
                for errr_type in ['errors', 'warnings']:
                    err_logs = get_ixnet().getAttribute(traffic_elem["traffic_item"], '-' + errr_type)
                    logger.error("Unapplied {}: {}".format(errr_type.upper(), err_logs))
                # msg = "traffic is not configured"
                # self.fail(msg, "tgen_failed_api", msg)
                return False
            time.sleep(1)
            if time.time() > end_time:
                break
        if not skip_fail:
            logger.debug("Verifying stream_id: {}, State: {}".format(traffic_elem["res"]['stream_id'], state))
            msg = "Failed to stop the traffic in {} seconds".format(timeout)
            self.fail(msg, "tgen_failed_api", msg)
        return False

    def manage_traffic_config_handles(self, ret_ds, **kwargs):
        if os.getenv("SPYTEST_ENSURE_TRAFFIC_CONTROL", "0") == "0":
            return
        port_handle = kwargs.get('port_handle')
        mode = kwargs.get('mode')
        if mode == "create":
            if not port_handle:
                return
            if port_handle not in self.traffic_config_handles:
                self.traffic_config_handles[port_handle] = []
            ent = {"res": copy.deepcopy(ret_ds), "kwargs": copy.deepcopy(kwargs)}
            ent["traffic_item"] = "/".join(ret_ds["traffic_item"].split("/")[:-1])
            self.traffic_config_handles[port_handle].append(ent)
        elif mode == "remove":
            for port_handle, port_values in self.traffic_config_handles.items():
                for val in port_values:
                    if kwargs.get('stream_id') in val['res']['stream_id']:
                        port_values.remove(val)
                if not port_values:
                    self.traffic_config_handles.pop(port_handle)

    def get_capture_stats_state(self, port, capture_wait=120):
        res = self.tg_convert_porthandle_to_vport(port_handle=port)
        try:
            capture = get_ixnet().getList(res['handle'], 'capture')[0]
            count = 0
            start = time.time()
            for cap_type in ['-dataCaptureState', '-controlCaptureState']:

                state = get_ixnet().getAttribute(capture, cap_type)
                while state != 'ready':
                    time.sleep(1)
                    count = count + 1
                    if count > int(capture_wait):
                        diff = time.time() - start
                        logger.error('Capture did not become ready even after {} sec'.format(diff))
                        break
                    state = get_ixnet().getAttribute(capture, cap_type)
        except Exception as exp:
            self.fail(exp, "tgen_failed_api", str(exp))

        logger.info("Total time taken to capture ready {} sec".format(time.time() - start))
        if self.ix_port == '443':
            tgen_wait(5, 'waiting to stabilize the captured packets')

    def get_emulation_handle_prefixes(self, ret_ds, **kwargs):
        ip_dict = dict()
        for emu_handle in ['emulation_src_handle', 'emulation_dst_handle']:
            handle_list = utils.make_list(kwargs.get(emu_handle))
            ip_dict[emu_handle] = list()
            for handle in handle_list:
                try:
                    temp = dict()
                    if 'PrefixPools' in handle:
                        hand = re.search(r'.*ipv(4|6)PrefixPools:(\d)+', handle).group(0)
                        addr_han = get_ixnet().getAttribute(hand, '-networkAddress')
                        values = get_ixnet().getAttribute(addr_han, '-values')
                    else:
                        values = get_ixnet().getAttribute(handle, '-address')
                    temp['start_addr'] = values
                    temp['handle'] = handle
                    ip_dict[emu_handle].append(temp)
                except Exception:
                    logger.error("Couldn't get ip prefix for handle: {}".format(handle))
        logger.info('IP PREFIXES: {}'.format(ip_dict))


class TGScapy(TGBase):
    def __init__(self, tg_type, tg_version, tg_ip=None, tg_port=8009, tg_port_list=None):
        logger.info('TG Scapy Init')
        TGBase.__init__(self, tg_type, tg_version, tg_ip, tg_port_list, True)
        self.sc = ScapyClient(logger, tg_ip, tg_port, tg_port_list, self)

    def __getattribute__(self, name):
        try:
            return object.__getattribute__(self.sc, name)
        except Exception:
            return object.__getattribute__(self, name)

    def clean_all(self):
        self.server_control("clean-all", "")

    def show_status(self):
        pass

    def instrument(self, phase, context):
        self.server_control(phase, context)

    def alert(self, msg):
        workarea.alert(msg)

    def log_call(self, fname, **kwargs):
        msg = tgen_log_call(fname, **kwargs)
        if not tgen_log_lvl_is_debug():
            logger.info(msg)

    def log_resp(self, fname, text):
        msg = tgen_log_resp(fname, text)
        if not tgen_log_lvl_is_debug():
            logger.info(msg)

    def api_fail(self, msg):
        tgen_fail("", "tgen_failed_api", msg)

    def save_log(self, name, data):
        try:
            logs_path = tgen_get_logs_path()
            lfile = os.path.join(logs_path, name)
            utils.write_file(lfile, data)
        except Exception as exp:
            logger.error('TG: Failed to save log: %s' % str(exp))

    def connect(self):
        logger.info('TG Scapy Connect {}:{}'.format(self.tg_ip, self.tg_port))
        return self.scapy_connect()

    def tg_arp_control(self, **kwargs):
        if 'handle' in kwargs:
            result = self.tg_interface_config(protocol_handle=kwargs['handle'], arp_send_req='1')
        elif 'port_handle' in kwargs:
            result = self.tg_interface_config(port_handle=kwargs['port_handle'], arp_send_req='1')
        else:
            result = None
        logger.info('Sending ARP completed: {}'.format(result))
        return result

    def tg_withdraw_bgp_routes(self, route_handle):
        result = self.tg_emulation_bgp_control(handle=route_handle, mode='stop')
        logger.info('withdraw action completed: {}'.format(result))
        return result if result['status'] == '1' else None

    def tg_readvertise_bgp_routes(self, handle, route_handle):
        result = self.tg_emulation_bgp_control(handle=route_handle, mode='start')
        logger.info('readvertise action completed: {}'.format(result))
        return result if result['status'] == '1' else None

    def tg_igmp_querier_control(self, mode, handle):
        result = self.tg_emulation_igmp_querier_control(mode=mode, handle=handle)
        tgen_wait(10)
        logger.info("IGMP Querier action completed: {}".format(result))
        return result if result['status'] == '1' else None


def generate_tg_methods(tg_type, afnl):
    for func in afnl:
        # logger.info("creating wrapper for {}".format(func))
        dummy_func_name = 'tg_' + func[0]
        if tg_type == 'ixia':
            real_func_name = 'ixiangpf.' + func[0]
        elif tg_type == 'stc':
            real_func_name = 'sth.' + func[0]
        tg_wrapper_func = \
            "def dummy_func_name(self,**kwargs):\n" + \
            "   #logger.info('Calling TG Wrapper: ')\n" + \
            "   res=self.trgen_pre_proc('dummy_func_name',**kwargs)\n" + \
            "   self.trgen_post_proc('dummy_func_name',**kwargs)\n" + \
            "   return res\n"

        tg_wrapper_func = re.sub(
            r'dummy_func_name', dummy_func_name, tg_wrapper_func)
        tg_wrapper_func = re.sub(
            r'real_func_name', real_func_name, tg_wrapper_func)

        # nosemgrep-next-line
        exec(tg_wrapper_func, globals())
        if tg_type == 'ixia':
            # nosemgrep-next-line
            setattr(TGIxia, dummy_func_name, eval(dummy_func_name))
        else:
            # nosemgrep-next-line
            setattr(TGStc, dummy_func_name, eval(dummy_func_name))


def close_tgen():
    for _, tg in tgen_obj_dict.items():
        tg.tg_disconnect()
    return True


def init_tgen(workarea_in, logger_in, skip_tgen_in):
    global workarea, logger, skip_tgen
    workarea = workarea_in
    logger = logger_in or Logger()
    skip_tgen = skip_tgen_in
    hltApiLog = tgen_get_logs_path('hltApiLog.txt')
    utils.delete_file(hltApiLog)


def instrument_tgen(phase, context):
    for _, tg in tgen_obj_dict.items():
        tg.instrument(phase, context)


def connect_tgen():
    tg = get_chassis()
    tg.tg_connected = connect_retry(tg)
    logger.info('TG Connect...done')
    return tg.tg_connected


def get_tgen_link_params(dut, port, param, default=None):
    port_list = utils.make_list(port)
    param_list = utils.make_list(param)
    param_dict = dict()
    for ent in param_list:
        p, v = [], []
        for intf in port_list:
            ret = workarea.get_link_param(dut, intf, ent, default)
            if ret:
                p.append(intf)
                v.append(ret)
        if p and v:
            param_dict[ent] = [p, v]
    return param_dict


def load_tgen(tgen_dict, phase):

    dconnect = int(os.getenv("SPYTEST_TGEN_DELAYED_CONNECT", "0"))

    do_init, do_connect = False, False
    if dconnect == 1:
        # load during session create and connect during session init
        if phase != 1:
            do_init = True
        if phase != 0:
            do_connect = True
    elif dconnect == 2:
        # load and connect during session init
        if phase != 0:
            do_init = True
            do_connect = True
    else:
        # load and connect during session create
        if phase != 1:
            do_init = True
            do_connect = True

    if do_init:
        rv = load_tgen_int(tgen_dict)
        if not rv:
            return rv
    if do_connect:
        return connect_tgen()

    return True


def load_tgen_int(tgen_dict):
    global tg_stc_pkg_loaded, tg_ixia_pkg_loaded, tg_scapy_pkg_loaded, skip_tgen
    file_prefix = os.getenv("SPYTEST_FILE_PREFIX", "results")
    config_file = tgen_dict.get('config_file', '')
    config_file = os.getenv("SPYTEST_TGEN_CONFIG_FILE", config_file)

    # Abort if same TG type are having different version
    tg_type = tgen_dict['type']
    tg_version = tgen_dict['version']
    tg_virtual = bool(tgen_dict.get('virtual', 0))
    if tg_type in ['ixia']:
        tgen_dict['config_file'] = config_file
    if tg_type not in ["stc", "ixia", "scapy"]:
        logger.error("Unknown TGen Type {}".format(tg_type))
        return False

    if tg_version_list.get(tg_type, None) is None:
        tg_version_list[tg_type] = tg_version
    elif tg_version_list.get(tg_type, None) != tg_version:
        logger.error("Only one version per TG type is supported: %s %s %s"
                     % (tg_type, tg_version_list.get(tg_type, None), tg_version))
        return False

    tg_ip = tgen_dict['ip']
    tg_port_list = tgen_dict['ports']
    logger.info("Loading {}:{} {} Ports: {} skip: {}".format(
        tg_type, tg_version, tg_ip, tg_port_list, skip_tgen))
    if config_file:
        logger.info("Loading config file: {}".format(config_file))
    link_params = get_tgen_link_params(tgen_dict['name'], tg_port_list, ['phy_mode', 'port_speed', 'auto_neg', 'fec'])
    if link_params:
        tgen_dict['link_params'] = link_params

    dryrun_force_scapy = bool(os.getenv("SPYTEST_DRYRUN_FORCE_SCAPY", "0") != "0")

    if isinstance(tg_ip, list):
        chassis_ports = {}
        for port in tg_port_list:
            parts = port.split("/")
            if len(parts) != 3:
                logger.error("Invalid port {}".format(port))
                return False
            chassis = int(parts[0])
            if chassis not in chassis_ports:
                chassis_ports[chassis] = []
            chassis_ports[chassis].append("/".join(parts[1:]))
        new_port_list = []
        for index, _ in enumerate(tg_ip):
            port_list = chassis_ports.get(index + 1, list())
            new_port_list.append(port_list)
        tg_port_list = new_port_list
    elif not skip_tgen and not dryrun_force_scapy:
        reachable = bool(os.getenv("SPYTEST_TGEN_SKIP_REACHABLE_CHECK", "0") != "0")
        if not reachable:
            if utils.ipcheck(tg_ip, 10, logger.warning, "TGEN "):
                reachable = True
        if not reachable:
            return False

    if skip_tgen and dryrun_force_scapy:
        tg_type = 'scapy'
        tg_version = '1.0'
        skip_tgen = False

    if tg_type == 'stc':
        os.environ['STC_LOG_OUTPUT_DIRECTORY'] = tgen_get_logs_path_folder()
        logger.debug("STC_TGEN_LOGS_PATH: {}".format(os.getenv('STC_LOG_OUTPUT_DIRECTORY')))
        if not tg_stc_pkg_loaded:
            if not tg_stc_load(tg_version, logger, tgen_get_logs_path()):
                return False
            code = "import sth \n"
            # nosemgrep-next-line
            exec(code, globals(), globals())
            if tgen_log_lvl_is_debug():
                logger.info("Setting Stc Debugs...")
                hltExportLog = os.path.join(tgen_get_logs_path_folder(), "{}_{}".format(file_prefix, 'hltExportLog'))
                hltDbgLog = os.path.join(tgen_get_logs_path_folder(), "{}_{}".format(file_prefix, 'hltDbgLog'))
                stcExportLog = os.path.join(tgen_get_logs_path_folder(), "{}_{}".format(file_prefix, 'stcExportLog'))
                hltMapLog = os.path.join(tgen_get_logs_path_folder(), "{}_{}".format(file_prefix, 'hltMapLog'))
                logger.info('STC Cmd Log File: {}*'.format(hltExportLog))
                logger.info('STC Dbg Log File: {}*'.format(hltDbgLog))
                logger.info('STC Vendor Log File: {}*'.format(stcExportLog))
                logger.info('STC Map Log File: {}*'.format(hltMapLog))
                get_sth().test_config(log=1, log_level=7, logfile=hltDbgLog,
                                      vendorlog=1, vendorlogfile=stcExportLog,
                                      hltlog=1, hltlogfile=hltExportLog,
                                      hlt2stcmapping=1, hlt2stcmappingfile=hltMapLog,
                                      custom_path=tgen_get_logs_path_folder())
            all_func_name_list = inspect.getmembers(get_sth(), inspect.isfunction)
            generate_tg_methods(tg_type, all_func_name_list)

            # work around for isEOTResults
            if os.getenv('SPYTEST_STC_IS_EOT_FIXUP', "0") == '1':
                ResultOptions1 = get_sth().invoke('stc::get project1 -children-ResultOptions')
                get_sth().invoke('stc::config ' + ResultOptions1 + ' -TimedRefreshResultViewMode CONTINUOUS')
                get_sth().invoke('stc::subscribe -parent project1 -configType StreamBlock -resultType RxStreamBlockResults ')
                get_sth().invoke('stc::subscribe -parent project1 -configType StreamBlock -resultType TxStreamBlockResults ')

            tg_stc_pkg_loaded = True
        tg_obj = TGStc(tg_type, tg_version, tg_ip, tg_port_list, **tgen_dict)

    if tg_type == 'ixia':
        for ix_server in utils.make_list(tgen_dict['ix_server']):
            if not utils.ipcheck(ix_server):
                logger.error("IxNetWork IP Address: {} is not reachable".format(ix_server))
                return False
            tg_ix_port = tgen_dict.get('ix_port', 8009)
            tg_ix_server = "{}:{}".format(ix_server, tg_ix_port)
            if not tg_ixia_pkg_loaded:
                if not tg_ixia_load(tg_version, logger, tgen_get_logs_path()):
                    return False
                code = \
                    "from ixiatcl import IxiaTcl \n" + \
                    "from ixiahlt import IxiaHlt \n" + \
                    "from ixiangpf import IxiaNgpf \n" + \
                    "from ixiaerror import IxiaError \n" + \
                    "ixiatcl = IxiaTcl() \n" + \
                    "ixiahlt = IxiaHlt(ixiatcl) \n" + \
                    "ixiangpf = IxiaNgpf(ixiahlt) \n"

                # nosemgrep-next-line
                exec(code, globals(), globals())
                if tgen_log_lvl_is_debug():
                    logger.info("Setting Ixia Debugs...")
                    hltCmdLog = os.path.join(tgen_get_logs_path_folder(), "{}_{}".format(file_prefix, 'hltCmdLog.txt'))
                    hltDebugLog = os.path.join(tgen_get_logs_path_folder(),
                                               "{}_{}".format(file_prefix, 'hltDebugLog.txt'))
                    logger.info('Ixia Cmd Log File: {}*'.format(hltCmdLog))
                    logger.info('Ixia Dbg Log File: {}*'.format(hltDebugLog))
                    get_ixiatcl().set('::ixia::logHltapiCommandsFlag', '1')
                    get_ixiatcl().set('::ixia::logHltapiCommandsFileName', hltCmdLog)
                    get_ixiatcl().set('::ixia::debug', '3')
                    get_ixiatcl().set('::ixia::debug_file_name', hltDebugLog)

                all_func_name_list = inspect.getmembers(get_ixiangpf(), inspect.ismethod)
                generate_tg_methods(tg_type, all_func_name_list)
                tg_ixia_pkg_loaded = True
            tg_obj = TGIxia(tg_type, tg_version, tg_ip, tg_port_list, tg_ix_server, tg_ix_port, tg_virtual, **tgen_dict)
            if tg_obj.tg_connected:
                break

    if tg_type == 'scapy':
        if not tg_scapy_pkg_loaded:
            if not tg_scapy_load(tg_version, logger, tgen_get_logs_path()):
                return False
            tg_scapy_pkg_loaded = True
        tg_ix_port = tgen_dict.get('ix_port', 8009)
        tg_obj = TGScapy(tg_type, tg_version, tg_ip, tg_ix_port, tg_port_list)

    tgen_obj_dict[tgen_dict['name']] = tg_obj
    return True


def module_init():
    retval = True
    for _, tg in tgen_obj_dict.items():
        tg.in_module_start_cleanup = True
        try:
            tg.clean_all()
        except Exception:
            retval = False
        tg.in_module_start_cleanup = False
    return retval


def get_tgen_handler():
    return {
        'ixia_handler': get_ixiangpf() if 'ixiangpf' in globals() else None,
        'stc_handler': get_sth() if 'sth' in globals() else None
    }


def get_chassis(name=None):
    try:
        if name is None:
            name = list(tgen_obj_dict.keys())[0]
        return tgen_obj_dict[name]
    except Exception:
        return None


def get_tgen(port, name=None):
    tg = get_chassis(name)
    if not tg:
        return (None, None)
    ph = tg.get_port_handle(port)
    return (tg, ph)


def is_soft_tgen(name=None):
    tg = get_chassis(name)
    if not tg:
        return False
    if tg.tg_type == "scapy":
        return True
    return tg.tg_virtual


def get_tg_type(name=None):
    tg = get_chassis(name)
    return tg.tg_type if tg else "ixia"


if __name__ == "__main__":
    tg_stc_load("4.91", None, None)
    # tg_ixia_load("8.42", None, None)
    tg_ixia_load("9.10", None, None)
    code = \
        "from ixiatcl import IxiaTcl \n" + \
        "from ixiahlt import IxiaHlt \n" + \
        "from ixiangpf import IxiaNgpf \n" + \
        "from ixiaerror import IxiaError \n" + \
        "ixiatcl = IxiaTcl() \n" + \
        "ixiahlt = IxiaHlt(ixiatcl) \n" + \
        "ixiangpf = IxiaNgpf(ixiahlt) \n"

    # nosemgrep-next-line
    exec(code, globals(), globals())
