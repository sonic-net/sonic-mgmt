import os
import re
import time
import json
import copy
import inspect
import requests
from collections import OrderedDict
import utilities.common as utils
import utilities.parallel as putils
from spytest.logger import Logger
from spytest.tgen.init import tg_stc_load,tg_scapy_load,tg_ixia_load
from spytest.tgen.tg_scapy import ScapyClient
from spytest.dicts import SpyTestDict
from netaddr import IPAddress

workarea = None
logger = None
skip_tgen = False
tg_stc_pkg_loaded = False
tg_ixia_pkg_loaded = False
tg_scapy_pkg_loaded = False
tg_version_list = dict()
tgen_obj_dict = {}

def tgen_profiling_start(msg, max_time=300):
    return workarea.profiling_start(msg, max_time)

def tgen_profiling_stop(pid):
    return workarea.profiling_stop(pid)

def tgen_wait(val):
    workarea.tg_wait(val)

def tgen_exception(ex):
    workarea.report_tgen_exception(ex)

def tgen_abort(dbg_msg, msgid, *args):
    logger.error('TG API Fatal Error: %s' % dbg_msg)
    workarea.report_tgen_abort(msgid, *args)

def tgen_fail(dbg_msg, msgid, *args):
    logger.error('TG API Fatal Error: %s' % dbg_msg)
    workarea.report_tgen_fail(msgid, *args)

def tgen_script_error(dbg_msg, msgid, *args):
    logger.error('TG API Script Error: %s' % dbg_msg)
    workarea.report_scripterror(msgid, *args)

def tgen_ftrace(*args):
    workarea.tgen_ftrace(*args)

def tgen_get_logs_path(for_file=None):
    return workarea.get_logs_path(for_file)

def tgen_get_logs_path_folder(for_file=None):
    tgen_folder = for_file if for_file else 'tgen'
    tgen_folder_path = workarea.get_logs_path(tgen_folder)
    if not os.path.exists(tgen_folder_path):
        os.makedirs(os.path.abspath(tgen_folder_path))
    return tgen_folder_path

def tgen_log_call(fname, **kwargs):
    args_list=[]
    for key, value in kwargs.items():
        if isinstance(value, str):
            args_list.append("%s='%s'" %(key, value))
        elif isinstance(value, int):
            args_list.append("%s=%s" %(key, value))
        elif isinstance(value, list):
            args_list.append("%s=%s" %(key, value))
        else:
            args_list.append("%s=%s[%s]" %(key, value, type(value)))
    text = "{}({})\n".format(fname, ",".join(args_list))
    logger.debug('REQ: {}'.format(text.strip()))
    file_prefix = os.getenv("SPYTEST_FILE_PREFIX", "results")
    hltApiLog = os.path.join(tgen_get_logs_path_folder(), "{}_{}".format(file_prefix, 'hltApiLog.txt'))
    utils.write_file(hltApiLog, text, "a")

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

class TGBase(object):
    def __init__(self, tg_type, tg_version, tg_ip=None, tg_port_list=None):
        logger.info('TG Base Init...start')
        self.tg_ns = ""
        self.tg_type = tg_type
        self.tg_version = tg_version
        self.tg_ip = tg_ip
        self.tg_port_list = tg_port_list
        self.skip_traffic = skip_tgen
        self.tg_connected = False
        self.in_module_start_cleanup = False
        self.cached_interface_config_handles = OrderedDict()
        self.tg_port_handle = dict()
        self.tg_port_analyzer = dict()
        if self.tg_ip == None or self.tg_port_list == None:
            return
        if self.skip_traffic:
            return

        for i in range(0, 10):
            ret_ds = self.connect()
            if ret_ds:
                msg = "UNKNOWN" if "log" not in ret_ds else ret_ds['log']
                logger.warning('TG Connect Error: %s try: %d' % (msg, i))
                tgen_wait(10)
            else:
                logger.info('TG Connection: Success')
                self.tg_connected = True
                break

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

    def clean_all(self):
        logger.error("should be overriden")
        return None

    def connect(self):
        logger.error("should be overriden")
        return None

    def show_status(self):
        logger.error("should be overriden")
        return None

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
        tgen_fail(dbg_msg, msgid, *args)

    def exception(self, exp):
        logger.error('TG API Fatal Exception: %s' % str(exp))
        self.ensure_connected(str(exp))
        tgen_exception(exp)

    def has_disconnected(self, msg):
        if "Failed to parse stack trace not connected" in msg:
            return True

        if "Ixnetwork error occured" in msg:
            if "Connection reset by peer" in msg or "not connected" in msg:
                return True

        return False

    def ensure_connected(self, msg):
        if os.getenv("SPYTEST_ENSURE_CONNECTED", "1") == "0":
            return

        if self.has_disconnected(msg):
            tgen_abort(msg, "tgen_failed_abort", msg)
            return

        if self.tg_type in ['stc', 'scapy']:
            return

        try:
            # try getting the ixnetwork build number to check connection status
            get_ixiangpf().ixnet.getAttribute('::ixNet::OBJ-/globals', '-buildNumber')
        except Exception as exp:
            tgen_abort(msg, "tgen_failed_abort", str(msg))

    def debug_show(self, ph, msg=""):
        stats = self.tg_traffic_stats(port_handle=ph,mode="aggregate")
        total_tx = stats[ph]['aggregate']['tx']['total_pkts']
        total_rx = stats[ph]['aggregate']['rx']['total_pkts']
        logger.info("{} PORT: {} TX: {} RX: {}".format(msg, ph, total_tx, total_rx))

    def tgen_eval(self, msg, func, **kwargs):

        logger.info('Executing: {}'.format(msg))
        (pid, ret_ds) = (0, dict())
        try:
            pid = tgen_profiling_start(msg)
            ret_ds = eval(func)(**kwargs)
            tgen_profiling_stop(pid)
        except Exception as exp:
            tgen_profiling_stop(pid)
            logger.info('Error {} executing: {}'.format(msg, func))
            if not self.in_module_start_cleanup:
                self.exception(exp)
            self.show_status()

        return ret_ds

    def get_port_handle(self, port):
        return self.tg_port_handle.get(port, None)

    def get_port_handle_list(self):
        ph_list = list()
        for port, handle in self.tg_port_handle.items():
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
            return self.tg_readvertise_bgp_routes(handle,route_handle)

    def map_field(self, src, dst, d):
        if d.get(src) != None:
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

    def tg_topology_test_control(self, stack=None, skip_wait=False, tg_wait=2, **kwargs):
        if kwargs.get('handle') != None and stack != None:
            kwargs['handle'] = re.search(r'.*{}:(\d)+'.format(stack), kwargs['handle']).group(0)
        kwargs.pop('tg_wait', '')
        for i in range(1, 30):
            if kwargs.get('action') == 'apply_on_the_fly_changes':
                res = get_ixiangpf().test_control(action='apply_on_the_fly_changes')
            else:
                res = self.tg_test_control(**kwargs)
            logger.debug(res)
            if res.get('status', '0') == '1':
                logger.debug('{}: Success'.format(kwargs['action']))
                break
            tgen_wait(tg_wait)
        if not skip_wait:
            tgen_wait(10)

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
        func = self.get_hltapi_name(fname)

        if self.tg_version == 8.40 and fname == 'tg_traffic_config':
            if kwargs.get('rate_pps') != None:
                kwargs['rate_pps'] = 5

        # Handling the cleanup here, if mode='destroy' is called.
        # if 'stc', replace interface_config with cleanup_session.
        # if 'ixia', replace handle with protocol_handle (already set).
        if fname == 'tg_interface_config':
            if kwargs.get('mode') == 'destroy':
                if self.tg_type == 'stc':
                    func = self.get_hltapi_name('tg_cleanup_session')
                    kwargs.pop('mode','')
                    kwargs.pop('handle','')
                    kwargs['reset']='0'
                elif self.tg_type == 'ixia':
                    func = self.get_hltapi_name('tg_topology_config')
                    han = kwargs['handle']
                    han = han[0] if type(han) is list else han
                    han = re.search(r'.*deviceGroup:(\d)+',han).group(0)
                    logger.debug("Starting Destroy...")
                    logger.debug(han)
                    self.tg_test_control(handle=han, action='stop_protocol')
                    tgen_wait(10)
                    kwargs['topology_handle'] = han
                    kwargs.pop('handle','')
                    kwargs.pop('port_handle','')
        if fname == 'tg_interface_control':
            if kwargs.get('mode') == 'break_link':
                if self.tg_type == 'ixia':
                    func = self.get_hltapi_name('tg_interface_config')
                    kwargs.pop('mode','')
                    kwargs['op_mode']='sim_disconnect'
            elif kwargs.get('mode') == 'restore_link':
                if self.tg_type == 'ixia':
                    func = self.get_hltapi_name('tg_interface_config')
                    kwargs.pop('mode','')
                    kwargs['op_mode']='normal'
            elif kwargs.get('mode') == 'check_link':
                if self.tg_type == 'stc':
                    func = self.get_hltapi_name('tg_interface_stats')
                    kwargs.pop('mode','')
                    desired_status=kwargs.pop('desired_status','')
                    kwargs["properties"] = "link"
                elif self.tg_type == 'ixia':
                    func = self.get_hltapi_name('tg_test_control')
                    kwargs.pop('mode','')
                    kwargs['action']='check_link_state'

        if fname == 'tg_traffic_control':
            if self.tg_type == 'ixia' and kwargs.get('action') == 'reset':
                traffic_items = get_ixiangpf().session_info(mode='get_traffic_items')
                if traffic_items.get('traffic_config') != None:
                    logger.debug("stopping streams before reset")
                    ret_ds = self.tg_traffic_control(action='stop', stream_handle=traffic_items['traffic_config'].split())
                    logger.debug(ret_ds)
                    tgen_wait(2)

        if fname == 'tg_packet_stats' and kwargs.get('format') == 'var':
            op_type = kwargs.pop('output_type',None)
            if self.tg_type == 'ixia' and op_type == 'hex':
                    func = self.get_hltapi_name('self.local_get_captured_packets')

        if fname == 'tg_packet_control':
            if self.tg_type == 'stc' and kwargs['action'] == 'start':
                port_handle=kwargs.get('port_handle')
                if isinstance(port_handle,list):
                    ret_ds = None
                    kwargs.pop('port_handle','')
                    for ph in port_handle:
                        ret_ds = self.tg_packet_control(port_handle=ph, **kwargs)
                    return ret_ds

        if fname == 'tg_traffic_stats' and self.tg_type == 'ixia':
            self.ensure_traffic_stats(**kwargs)

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
                if ret_ds.get('status') != None:
                    break
            if ret_ds.get('status') == None:
                logger.error('Traffic stats not collected properly, even after waiting for 15 sec...')
        if "status" not in ret_ds:
            logger.warning(ret_ds)
            msg = "Unknown" if "log" not in ret_ds else ret_ds['log']
            self.fail("nolog", "tgen_failed_api", msg)
        elif ret_ds['status'] == '1':
            logger.debug('TG API Run Status: Success')
            if fname == 'tg_traffic_control' and self.tg_type == 'ixia':
                self.ensure_traffic_control(**kwargs)
            if fname == 'tg_traffic_config' and self.tg_type == 'ixia':
                self.manage_traffic_config_handles(ret_ds, **kwargs)
            if fname == 'tg_connect':
                self.tg_connected = True
                for port in kwargs['port_list']:
                    self.tg_port_handle[port] = ret_ds['port_handle'][self.tg_ip][port]
            if fname == 'tg_interface_config':
                if self.tg_type == 'stc':
                    if kwargs.get('enable_ping_response') != None and kwargs.get('netmask') != None:
                        ret_val = self.tg_interface_handle(ret_ds)
                        prefix_len = IPAddress(kwargs.get('netmask', '255.255.255.0')).netmask_bits()
                        for device in utils.make_list(ret_val['handle']):
                            self.local_stc_tapi_call(
                                'stc::config ' + device + ' -enablepingresponse ' + str(kwargs['enable_ping_response']))
                            ipv4if = self.local_stc_tapi_call('stc::get ' + device + ' -children-ipv4if')
                            self.local_stc_tapi_call('stc::config ' + ipv4if + ' -PrefixLength ' + str(prefix_len))
                        get_sth().invoke("stc::apply")
                if re.search('cleanup_session',func):
                    if re.search('sth',func):
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
                        tgen_wait(10)
                        self.tg_topology_test_control(action='apply_on_the_fly_changes', skip_wait=True)
                        logger.info('start the host.')
                        temp = ret_ds['handle'] if type(ret_ds['handle'])!=list else ret_ds['handle'][0]
                        self.tg_topology_test_control(handle=temp, stack='deviceGroup', action='start_protocol')
                    self.manage_interface_config_handles(kwargs.get('mode'), kwargs_port_handle, ret_ds['handle'])
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
                    if ret_ds.get('handle') != None:
                        if ret_ds['handle'].get('dhcp_handle') != None:
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
                    ret_ds = self.modify_tgen_return_params(ret_ds, 'handle', 'handles')
            if fname == 'tg_emulation_dhcp_group_config':
                if self.tg_type == 'ixia':
                    if ret_ds.get('dhcpv4client_handle'):
                        ret_ds = self.modify_tgen_return_params(ret_ds, 'dhcpv4client_handle', 'handles')
                    else:
                        ret_ds = self.modify_tgen_return_params(ret_ds, 'dhcpv6client_handle', 'handles')
            if fname == 'tg_cleanup_session':
                self.tg_connected = False
                self.tg_port_handle.clear()
            if fname == 'tg_interface_control':
                if self.tg_type == 'stc':
                    if func == self.get_hltapi_name('tg_interface_stats'):
                        result = ret_ds['link']
                        # Dictionary to compare the result.
                        res_dict = { 'up'   : '1',
                                     'down' : '0'
                                   }
                        ret_ds = True if res_dict.get(desired_status.lower(),'') == result else False
                elif self.tg_type == 'ixia':
                    if func == self.get_hltapi_name('tg_test_control'):
                        ret_ds = bool("log" not in ret_ds)
            if fname == 'tg_traffic_control' and  kwargs['action'] == 'stop' and \
                 ret_ds.get('stopped') == '0' and os.getenv("SPYTEST_ENSURE_TRAFFIC_CONTROL", "0") =='0':
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
                    self.tg_packet_config_buffers(port_handle=kwargs['port_handle'],
                                                  control_plane_capture_enable='0', data_plane_capture_enable='0')
        else:

            if "not found in mandatory or optional argument list" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_invalid_option")
            if "cannot be executed while other actions are in progress" in ret_ds['log']:
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
            if "::ixia::test_control: Failed to start Protocols" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_start_protocols")
            if "::ixia::traffic_config: Could not configure stack" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_configure_stack")
            if "At least one port must be selected to apply the changes" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_apply_changes")
            if "::ixia::traffic_stats: Could not find Traffic Item Statistics view" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_missing_traffic_item")
            if "parse_dashed_args: Invalid value" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_invalid_value")

            # warning
            self.warn(ret_ds['log'])

            if fname == 'tg_interface_control':
                if self.tg_type == 'ixia':
                    if func == self.get_hltapi_name('tg_test_control'):
                        ret_ds = bool("log" not in ret_ds)
        return ret_ds

    def trgen_post_proc(self, fname, **kwargs):
        pass

class TGStc(TGBase):
    def __init__(self, tg_type, tg_version, tg_ip=None, tg_port_list=None):
        TGBase.__init__(self, tg_type, tg_version, tg_ip, tg_port_list)
        logger.info('TG STC Init...done')

    def clean_all(self):

        ph_list = self.get_port_handle_list()

        logger.info("TG CLEAN ALL: stop and remove all streams on {}". format(ph_list))
        ret_ds = self.tg_traffic_control(action="reset", port_handle=ph_list)
        logger.debug(ret_ds)
        tgen_wait(2)

        for port_handle, handle_list in self.cached_interface_config_handles.items():
            for handle in handle_list:
                logger.info("removing interface handle {} on {}".format(handle, port_handle))
                self.tg_interface_config(port_handle=port_handle, handle=handle, mode='destroy')
        self.cached_interface_config_handles = OrderedDict()

        logger.debug("TG CLEAN ALL FINISHED")

    def get_port_status(self, port_list):
        port_handle_list=[]
        for port in port_list:
            port_handle_list.append(self.get_port_handle(port))
        ret_ds = get_sth().interface_stats(port_handle_list=port_handle_list, properties="link")
        retval = {}
        for port,port_handle in zip(port_list, port_handle_list):
            retval[port] = ret_ds[port_handle]["link"]
        return retval

    def show_status(self):
        pass

    def connect(self):
        self.tg_ns = 'sth'
        ret_ds = get_sth().connect(device=self.tg_ip, port_list=self.tg_port_list,
                             break_locks=1)
        logger.info(ret_ds)
        if ret_ds['status'] != '1':
            return ret_ds
        port_handle_list=[]
        for port in self.tg_port_list:
            self.tg_port_handle[port] = ret_ds['port_handle'][self.tg_ip][port]
            port_handle_list.append(self.tg_port_handle[port])
        port_details_all = self.tg_interface_stats(port_handle=port_handle_list)
        intf_speed_list = port_details_all['intf_speed'].split()
        for intf_speed,port,port_handle in zip(intf_speed_list, self.tg_port_list, port_handle_list):
            if intf_speed == '100000':
                logger.info('disabling FEC as spirent port {} is of 100G'.format(port))
                self.tg_interface_config(port_handle=port_handle, \
                                         mode="modify",forward_error_correct="false")
        return None

    def trgen_adjust_mismatch_params(self, fname, **kwargs):
        if fname == 'tg_traffic_config':
            self.map_field("ethernet_value", "ether_type", kwargs)
            self.map_field("data_pattern", "custom_pattern", kwargs)
            self.map_field("icmp_ndp_nam_o_flag", "icmpv6_oflag", kwargs)
            self.map_field("icmp_ndp_nam_r_flag", "icmpv6_rflag", kwargs)
            self.map_field("icmp_ndp_nam_s_flag", "icmpv6_sflag", kwargs)
            self.map_field("data_pattern_mode", None, kwargs)
            self.map_field("icmp_target_addr", None, kwargs)
            if kwargs.get('custom_pattern') != None:
                kwargs['custom_pattern'] = kwargs['custom_pattern'].replace(" ","")
                kwargs['disable_signature'] = '1'
            if kwargs.get("l4_protocol") == "icmp" and kwargs.get("l3_protocol") == "ipv6":
                kwargs['l4_protocol'] = 'icmpv6'
                self.map_field("icmp_type", "icmpv6_type", kwargs)
            if kwargs.get('vlan_id') != None:
                if kwargs.get('l2_encap') == None:
                    kwargs['l2_encap'] = 'ethernet_ii_vlan'
                if type(kwargs.get('vlan_id')) != list:
                    x = [kwargs.get('vlan_id')]
                else:
                    x = kwargs.get('vlan_id')
                if len(x) > 1:
                    vlan_list = kwargs.get('vlan_id')
                    kwargs['vlan_id'] = vlan_list[0]
                    kwargs['vlan_id_outer'] = vlan_list[1]

            for param in ('enable_time_stamp', 'enable_pgid', 'vlan', 'duration'):
                if kwargs.get(param) != None:
                    kwargs.pop(param)

            for param in ('udp_src_port_mode', 'udp_dst_port_mode',
                          'tcp_src_port_mode', 'tcp_dst_port_mode'):
                if kwargs.get(param) == 'incr':
                    kwargs[param] = 'increment'
                if kwargs.get(param) == 'decr':
                    kwargs[param] = 'decrement'
            if (kwargs.get('transmit_mode') != None or
                kwargs.get('l3_protocol') != None) and \
                kwargs.get('length_mode') == None:
                kwargs['length_mode'] = 'fixed'

            if kwargs.get('port_handle2') != None:
                kwargs['dest_port_list'] = kwargs.pop('port_handle2')

            if kwargs.get('high_speed_result_analysis') != None and \
               kwargs.get('track_by') != None:
                attr = kwargs.get('track_by')
                attr = attr.split()[1]
                kwargs.pop('track_by')
                kwargs.pop(analyzer_filter[attr])
            if kwargs.get('circuit_endpoint_type') != None:
                kwargs.pop('circuit_endpoint_type')

            if re.search(r'ip_delay |ip_throughput | ip_reliability |ip_cost |ip_reserved ',' '.join(kwargs.keys())):
                delay = kwargs.get('ip_delay',0)
                throughput = kwargs.get('ip_throughput',0)
                reliability = kwargs.get('ip_reliability',0)
                cost = kwargs.get('ip_cost',0)
                reserved = kwargs.get('ip_reserved',0)

                bin_val = str(delay) + str(throughput) + str(reliability) + str(cost)
                kwargs['ip_tos_field'] = int(bin_val,2)
                kwargs['ip_mbz'] = reserved
                # ignore step,mode,count for now
                for param in ('qos_type_ixn', 'ip_delay', 'ip_delay_mode', 'ip_delay_tracking',
                        'ip_throughput', 'ip_throughput_mode', 'ip_throughput_tracking',
                        'ip_reliability', 'ip_reliability_mode', 'ip_reliability_tracking',
                        'ip_cost', 'ip_cost_mode', 'ip_cost_tracking','ip_reserved'):

                    kwargs.pop(param,None)

            if kwargs.get('mac_dst_mode') != None:
                if type(kwargs.get('mac_dst')) == list:
                    kwargs['mac_dst'] = ' '.join(kwargs['mac_dst'])
                    kwargs.pop('mac_dst_mode', '')

            #disabling high_speed_result_analysis by default, as saw few instances where it is needed and not by disabled by scripts.
            if kwargs.get('high_speed_result_analysis') == None:
                kwargs['high_speed_result_analysis'] = 0

        elif fname == 'tg_traffic_stats':
            if kwargs.get('mode') == None:
                kwargs['mode'] = 'aggregate'
            kwargs.pop('csv_path', '')
        elif fname == 'tg_traffic_control':
            self.map_field("max_wait_timer", None, kwargs)
            if kwargs.get('db_file') == None:
                kwargs['db_file'] = 0
            if kwargs.get('handle') != None:
                kwargs['stream_handle'] = kwargs['handle']
                kwargs.pop('handle')
        elif fname == 'tg_interface_config':
            self.map_field("ipv4_resolve_gateway", "resolve_gateway_mac", kwargs)
            if kwargs.get("resolve_gateway_mac") != None:
                kwargs['resolve_gateway_mac'] = 'false' if kwargs['resolve_gateway_mac'] == 0 else 'true'
            if "vlan_id_count" in kwargs:
                kwargs['count'] = '1'
            if "count" in kwargs:
                if 'create_host' not in kwargs:
                    kwargs['create_host'] = 'false'
        elif fname == 'tg_emulation_bgp_config':
            if kwargs.get('enable_4_byte_as') != None:
                l_as = int(kwargs['local_as']) / 65536
                l_nn = int(kwargs['local_as']) - (l_as * 65536)
                r_as = int(kwargs['remote_as']) / 65536
                r_nn = int(kwargs['remote_as']) - (r_as * 65536)
                kwargs['local_as4'] = str(l_as)+":"+str(l_nn)
                kwargs['remote_as4'] = str(r_as)+":"+str(r_nn)
                # 23456 has to be set due to spirent limiation.
                kwargs['local_as'] = '23456'
                kwargs['remote_as'] = '23456'
                kwargs.pop('enable_4_byte_as')
        elif fname in ['tg_emulation_multicast_group_config', 'tg_emulation_multicast_source_config']:
            self.map_field("active", None, kwargs)
            if kwargs.get('ip_addr_step') != None:
                kwargs['ip_addr_step'] = kwargs['ip_addr_step_val'] if kwargs.get('ip_addr_step_val') else 1
                kwargs.pop('ip_addr_step_val', '')
        elif fname == 'tg_emulation_igmp_querier_config':
            self.map_field("active", None, kwargs)
        elif fname == 'tg_emulation_igmp_group_config':
            self.map_field("g_filter_mode", "filter_mode", kwargs)
            if kwargs.get('source_pool_handle') != None:
                kwargs['device_group_mapping'] = 'MANY_TO_MANY'
                kwargs['enable_user_defined_sources'] = '1'
                kwargs['specify_sources_as_list'] = '0'
        elif fname == 'tg_emulation_igmp_control':
            if kwargs.get('mode') == 'start':
                kwargs['mode'] = 'join'
            if kwargs.get('mode') == 'stop':
                kwargs['mode'] = 'leave'
        elif fname == 'tg_emulation_ospf_config':
            kwargs.pop('validate_received_mtu', '')
            kwargs.pop('max_mtu', '')
        return kwargs

    def tg_interface_handle(self, ret_ds):
        temp = '0'
        if "handle_list_pylist" in ret_ds:
            temp = ret_ds['handle_list_pylist']
        elif "handles_pylist" in ret_ds:
            temp = ret_ds['handles_pylist']
        elif "handles" in ret_ds:
            temp = ret_ds['handles']
        if type(temp) == list:
            temp = temp[0] if len(temp)==1 else temp
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

    def tg_emulation_ospf_route_config(self, **kwargs):
        result = self.tg_emulation_ospf_topology_route_config(**kwargs)
        logger.info('OSPF route config completed: {}'.format(result))
        return result if result['status'] == '1' else None

    def tg_ospf_lsa_config(self, **kwargs):
        result = self.tg_emulation_ospf_lsa_config(**kwargs)
        logger.info('OSPF route config completed: {}'.format(result))
        return result if result['status'] == '1' else None

    def tg_disconnect(self,**kwargs):
        if self.skip_traffic: return 0
        logger.info('Executing: {} {}'.format('sth.cleanup_session',kwargs))
        port_handle_list = self.get_port_handle_list()
        ret_ds = get_sth().cleanup_session(port_handle=port_handle_list)
        logger.info(ret_ds)
        if ret_ds['status'] == '1':
            logger.debug('TG API Run Status: Success')
        else:
            logger.warning('TG API Error: %s' % ret_ds['log'])
        self.tg_connected = False
        self.tg_port_handle.clear()

    def local_stc_tapi_call(self,param):
        res = get_sth().invoke(param)
        return res

    def _custom_filter_delete(self,port_handle):

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


    def _custom_filter_config(self,**kwargs):
        ret_dict = dict()
        ret_dict['status'] = '1'

        if not kwargs.get('mode') or not kwargs.get('port_handle'):
            logger.info("Missing Mandatory parameter: mode or port_handle")
            ret_dict['status'] = '0'
            return ret_dict

        port_handle = kwargs['port_handle']
        mode = kwargs['mode'].lower()

        if mode != 'create' and self.tg_port_analyzer[port_handle]['analyzer_handle'] == None:
            logger.error("Custom Filter is not configured for port: {}".format(port_handle))
            ret_dict['status'] = '0'
            return ret_dict

        project_handle = 'Project1'
        #This is the default name/handle. Things might not work if it is different.
        # Need a way to find this.
        res = self.local_stc_tapi_call('stc::get ' + project_handle)
        if not re.search(r'-Name\s+\{Project 1\}',res):
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

            #Delete existing filters, if any
            self._custom_filter_delete(port_handle)
            self.tg_port_analyzer[port_handle]['pattern_list'].append(kwargs['pattern_list'])

            #subscribe for the result
            self.tg_port_analyzer[port_handle]['stats_handle'] = self.local_stc_tapi_call('stc::subscribe -Parent ' + project_handle + ' -ResultParent ' + port_handle + ' -ConfigType Analyzer -resulttype FilteredStreamResults ')
            self.local_stc_tapi_call('stc::apply')

            current_analyzer = self.local_stc_tapi_call('stc::get ' + port_handle + ' -children-Analyzer')
            self.tg_port_analyzer[port_handle]['analyzer_handle'] = current_analyzer

            f_index = 1
            for offset in kwargs['offset_list']:
                filter_name = 'CustomFilter'+str(f_index)
                custom_filter = self.local_stc_tapi_call('stc::create Analyzer16BitFilter -under ' + current_analyzer)
                self.local_stc_tapi_call('stc::config ' + custom_filter + ' -FilterName ' + filter_name + ' -Offset ' + str(offset))
                f_index += 1

            self.local_stc_tapi_call('stc::apply')

        else:
            current_analyzer = self.tg_port_analyzer[port_handle]['analyzer_handle']
            if mode in ['start','stop']:
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
                if self.tg_port_analyzer[port_handle]['pattern_list'] != None:
                    pattern_list = self.tg_port_analyzer[port_handle]['pattern_list']
                    exp_filter_pattern_list = list()
                    for p_list in pattern_list:
                        if not isinstance(p_list,list):
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
                for rxresult in rx_result_handle_list:
                    logger.debug('rxresult row: {}'.format(rxresult))
                    rx_result_hash = self.local_stc_tapi_call('stc::get ' + rxresult)
                    logger.debug('RX Result: {}'.format(rx_result_hash))

                    # Using stc::get we can get info for each key in rx_result_hash, examples below.
                    # We are interested in counts and rate only for now.
                    #hanalyzerPort = get_sth().invoke('stc::get ' + rx_result_hash + " -parent" )
                    #PStreamName  = get_sth().invoke('stc::get ' + hanalyzerPort + " -name")
                    #StreamID = get_sth().invoke('stc::get ' + rxresult + " -Comp32")

                    found_filter_pattern = ''
                    for i in range(1,len(filter_list_16)+1):
                        filter_pattern = self.local_stc_tapi_call('stc::get ' + rxresult + ' -FilteredValue_' + str(i))
                        if found_filter_pattern == '':
                            found_filter_pattern = ''.join(filter_pattern.split())
                        else:
                            found_filter_pattern = found_filter_pattern + ':' + ''.join(filter_pattern.split())
                    logger.info('exp_filter_pattern_list: {} found_filter_pattern: {}'.format(exp_filter_pattern_list,found_filter_pattern))
                    if found_filter_pattern.lower() in exp_filter_pattern_list:
                        rx_frame_count = self.local_stc_tapi_call('stc::get ' + rxresult + ' -FrameCount')
                        rx_frame_rate = self.local_stc_tapi_call('stc::get ' + rxresult + ' -FrameRate')
                        logger.info('rx_frame_count: {} rx_frame_rate: {}'.format(rx_frame_count,rx_frame_rate))
                        ret_dict[port_handle]['custom_filter']['filtered_frame_count'] = int(ret_dict[port_handle]['custom_filter']['filtered_frame_count']) + int(rx_frame_count)
                        total_rx_count += int(rx_frame_count)
                    else:
                        logger.info('Ignoring filter_pattern: {}'.format(found_filter_pattern.lower()))
                        total_rx_count += int(self.local_stc_tapi_call('stc::get ' + rxresult + ' -FrameCount'))

                ret_dict[port_handle]['custom_filter'].update({'total_rx_count': total_rx_count})

        return ret_dict


    def tg_custom_filter_config(self,**kwargs):
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
            for offset,pattern in zip(['pattern_offset1'],['pattern1']):
                if not kwargs.get(offset) or not kwargs.get(pattern) or len(kwargs[pattern]) != 4:
                    logger.info('Missing Mandatory parameter {} or {} and pattern length must be 16 bits'.format(offset,pattern))
                    ret_dict['status'] = '0'
                    return ret_dict
                offset_count += 1
                offset_list.append(kwargs[offset])
                pattern_list.append(kwargs[pattern])

            for offset,pattern in zip(['pattern_offset2'],['pattern2']):
                if kwargs.get(offset) and kwargs.get(pattern) and len(kwargs[pattern]) == 4:
                    offset_count += 1
                    offset_list.append(kwargs[offset])
                    pattern_list.append(kwargs[pattern])
                elif not kwargs.get(offset) and not kwargs.get(pattern):
                    pass
                else:
                    logger.info('Both parameter {} and {} need to be provided and pattern length must be 16 bits'.format(offset,pattern))
                    ret_dict['status'] = '0'
                    return ret_dict
        if mode == 'create':
            self._custom_filter_config(mode='create',port_handle=port_handle,offset_list=offset_list,pattern_list=pattern_list)
            self._custom_filter_config(mode='start',port_handle=port_handle)
        if mode == 'getstats':
            ret_dict[port_handle] = {}
            ret_dict[port_handle].update({'custom_filter': {}})
            tgen_wait(3)
            result = self._custom_filter_config(mode='getstats',port_handle=port_handle)
            filtered_frame_count = result[port_handle]['custom_filter']['filtered_frame_count']
            total_rx_count = result[port_handle]['custom_filter']['total_rx_count']
            ret_dict[port_handle]['custom_filter'].update({'filtered_frame_count': filtered_frame_count})
            ret_dict[port_handle]['custom_filter'].update({'total_rx_count': total_rx_count})

        return ret_dict

class TGIxia(TGBase):
    def __init__(self, tg_type, tg_version, tg_ip=None, tg_port_list=None, ix_server=None, ix_port=8009):
        self.ix_server = ix_server
        self.ix_port = str(ix_port)
        self.topo_handle = {}
        self.traffic_config_handles = {}
        TGBase.__init__(self, tg_type, tg_version, tg_ip, tg_port_list)
        logger.info('TG Ixia Init...done')

    def clean_all(self):
        self.traffic_config_handles.clear()
        ph_list = self.get_port_handle_list()

        traffic_items = get_ixiangpf().session_info(mode='get_traffic_items')
        if traffic_items.get('traffic_config') != None:
            items = traffic_items['traffic_config'].split()
            logger.info("TG CLEAN ALL: stop and remove all streams on {}". format(items))
            ret_ds = self.tg_traffic_control(action="reset", stream_handle=items)
            logger.debug(ret_ds)
            tgen_wait(2)
        else:
            logger.info("TG CLEAN ALL: No traffic items configured to reset")

        if os.getenv('TGEN_REMOVE_CACHED_INTERFACE_HANDLE'):
            for port_handle, handle_list in self.cached_interface_config_handles.items():
                for handle in handle_list:
                    logger.info("removing interface handle {} on {}".format(handle, port_handle))
                    self.tg_interface_config(port_handle=port_handle, handle=handle, mode='destroy')
            self.cached_interface_config_handles = dict()
        else:
            topo_handles = []
            for ph in ph_list:
                topo_handle=self.topo_handle[ph]
                if topo_handle:
                    topo_handles.append(topo_handle)
                    self.topo_handle[ph] = None

            if topo_handles:
                logger.info("remove all topology handles")
                ret_ds = self.tg_test_control(action='stop_all_protocols')
                logger.info(ret_ds)
                tgen_wait(10)
                for topo_handle in topo_handles:
                    logger.info("removing cached {}".format(topo_handle))
                    ret_ds=self.tg_topology_config(topology_handle=topo_handle, mode='destroy')
                    logger.info(ret_ds)
                    tgen_wait(2)

        logger.debug("TG CLEAN ALL FINISHED")

    def get_port_status(self, port_list):
        retval = {}
        for port in port_list:
            ret_ds = get_ixiangpf().test_control(action='check_link_state', port_handle=self.get_port_handle(port))
            retval[port] = bool("log" not in ret_ds)
        return retval

    def get_ixnetwork_status(self,**kwargs):
        ix_server = kwargs.get('ix_server',None)
        ix_rest_port = kwargs.get('ix_port','8006')
        retries = int(kwargs.get('retries','1'))
        ret_dict = dict()
        ret_dict['status'] = '0'
        ret_dict['total_session'] = 0
        ret_dict['session_in_use'] = 0
        ret_dict['user_list'] = list()
        ret_dict['user_id'] = list()
        while ret_dict['status'] == '0' and retries > 0:
            try:
                rest_cmd = 'http://' + ix_server.split(':')[0] + ':' + ix_rest_port + '/api/v1/sessions'
                response = requests.get(rest_cmd,verify=False, allow_redirects=True,  timeout=30)
                if response.status_code == 200:
                    ret_dict['status'] = '1'
                    resp_dict = json.loads(response.content)
                    for s_dict in resp_dict:
                        logger.debug('Connection Manager, session info: {}'.format(s_dict))
                        ret_dict['total_session'] += 1
                        if s_dict['state'].lower() == 'active' and re.match(r'IN\s+USE',s_dict['subState']):
                            ret_dict['session_in_use'] += 1
                            m =  re.search(r'automation\s+client\s+(.+?)\s',s_dict['subState'])
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
        logger.info('Connection Manager Info: {}'.format(ret_ds))
        return ret_ds

    def connect(self):
        self.tg_ns = 'ixiangpf'
        ret_ds = self.show_status()
        if ret_ds and ret_ds['status'] == '1' and ret_ds['session_in_use'] > 1:
            logger.error('Max recommended connection is reached, should abort the run')

        params = SpyTestDict(device=self.tg_ip, port_list=self.tg_port_list,
                      ixnetwork_tcl_server=self.ix_server, break_locks=1, reset=1)
        if self.ix_port == "443":
            # ixnetwork linux VM
            params.user_name = "admin"
            params.user_password = "admin"
        ret_ds = get_ixiangpf().connect(**params)

        logger.info(ret_ds)
        if ret_ds['status'] != '1':
            return ret_ds
        ports_100g=[]
        res=get_ixiangpf().traffic_stats()
        for port in self.tg_port_list:
            # ixia output is different for key 'port_handle': {'10': {'59': {'130': {'4': {'1/5': '1/1/5'}}}}}
            key1, key2, key3, key4 = self.tg_ip.split('.')
            self.tg_port_handle[port] = \
                ret_ds['port_handle'][key1][key2][key3][key4][port]
            # For topology_handle.
            self.topo_handle[self.tg_port_handle[port]]=None
            # To get 100G ports.
            if res[self.tg_port_handle[port]]['aggregate']['tx']['line_speed'] == '100GE':
                ports_100g.append(self.tg_port_handle[port])
        if ports_100g != []:
            logger.info('Disabling FEC for 100G ports: {}'.format(ports_100g))
            res=get_ixiangpf().interface_config(port_handle=ports_100g, mode="modify", autonegotiation=0, ieee_media_defaults=0, enable_rs_fec=0)
            logger.info(res)
        # Initial setting for ARP/ND.
        h1=get_ixiangpf().topology_config(port_handle=self.tg_port_handle[self.tg_port_list[0]], mode='config')
        logger.info(h1)
        res=get_ixiangpf().interface_config(protocol_handle='/globals', single_arp_per_gateway=0, single_ns_per_gateway=0)
        logger.info(res)
        res=get_ixiangpf().topology_config(topology_handle=h1['topology_handle'], mode='destroy')
        logger.info(res)
        return None

    def trgen_adjust_mismatch_params(self, fname, **kwargs):
        if fname == 'tg_traffic_config':
            self.map_field("ether_type", "ethernet_value", kwargs)
            self.map_field("custom_pattern", "data_pattern", kwargs)
            self.map_field("icmpv6_oflag", "icmp_ndp_nam_o_flag", kwargs)
            self.map_field("icmpv6_rflag", "icmp_ndp_nam_r_flag", kwargs)
            self.map_field("icmpv6_sflag", "icmp_ndp_nam_s_flag", kwargs)
            self.map_field("vlan_tpid", "vlan_protocol_tag_id", kwargs)

            if kwargs.get('vlan_protocol_tag_id') != None:
                eth_type = kwargs.pop('ethernet_value', None)
                kwargs['ethernet_value'] = hex(int(kwargs.pop('vlan_protocol_tag_id'))).lstrip('0x')
                if eth_type != None:
                    kwargs['vlan_protocol_tag_id'] = eth_type

            if kwargs.get('vlan_id_outer') != None:
                # If vlan-id_outer is present then vlan_id will also be there
                outer_vlan_id = kwargs['vlan_id_outer']
                vlan_id = kwargs['vlan_id']
                kwargs['vlan_id'] = [vlan_id, outer_vlan_id]
                kwargs.pop('vlan_id_outer')

            if kwargs.get('vlan_id') != None and kwargs.get('vlan') == None:
                kwargs['vlan'] = 'enable'

            # for stream level stats, circuit_type and track_by arguments required
            if kwargs.get('port_handle2') != None:
                if kwargs.get('track_by') == None:
                    kwargs['track_by'] = 'trackingenabled0'
                if kwargs.get('circuit_type') == None:
                    kwargs['circuit_type'] = 'raw'
                if kwargs.get('emulation_src_handle') != None and kwargs.get('emulation_dst_handle') != None:
                    kwargs['circuit_type'] = 'none'
                    kwargs.pop('port_handle2')

            for param in ('mac_discovery_gw', 'vlan_priority_mode', 'high_speed_result_analysis',
                          'enable_stream_only_gen', 'enable_stream', 'ipv6_dstprefix_len', 'ipv6_srcprefix_len'):
                if kwargs.get(param) != None:
                    kwargs.pop(param)

            for param in ('udp_src_port_mode', 'udp_dst_port_mode',
                          'tcp_src_port_mode', 'tcp_dst_port_mode'):
                if kwargs.get(param) == 'increment':
                    kwargs[param] = 'incr'
                if kwargs.get(param) == 'decrement':
                    kwargs[param] = 'decr'

            if kwargs.get('ip_tos_field') != None:
                bin_tos_val = bin(kwargs['ip_tos_field'])[2:].zfill(4)

                kwargs['qos_type_ixn'] = 'tos'
                kwargs['ip_precedence'] = kwargs.get('ip_precedence',0)
                # configuring ip_precedence is mandatory if use qos_type_ixn=tos
                kwargs['ip_delay'] = bin_tos_val[0]
                kwargs['ip_throughput'] = bin_tos_val[1]
                kwargs['ip_reliability'] = bin_tos_val[2]
                kwargs['ip_cost'] = bin_tos_val[3]
                kwargs['ip_reserved'] = kwargs.get('ip_mbz',0)

                kwargs.pop('ip_tos_field')
                kwargs.pop('ip_mbz',None)

            if kwargs.get('emulation_dst_handle') != None:
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
            if kwargs.get('stream_handle') != None:
                kwargs['handle'] = kwargs['stream_handle']
                kwargs.pop('stream_handle')
            for param in ('get', 'enable_arp'):
                if kwargs.get(param) != None:
                    kwargs.pop(param)
            if kwargs.get('action') in ['run', 'stop'] and kwargs.get('port_handle') == None:
                #kwargs['max_wait_timer'] = 120
                #temp change to roll back the HF from ixia
                if os.getenv("SPYTEST_ENSURE_TRAFFIC_CONTROL", "0") == "0":
                    kwargs['max_wait_timer'] = 30
                else:
                    kwargs['max_wait_timer'] = 180

        if fname == 'tg_interface_config':
            self.map_field("resolve_gateway_mac", "ipv4_resolve_gateway", kwargs)
            self.map_field("control_plane_mtu", "mtu", kwargs)
            self.map_field("flow_control", "enable_flow_control", kwargs)
            if kwargs.get('mode') == 'config':
                topo_han=self.topo_handle[kwargs.get('port_handle')]
                if topo_han == None:
                    res=self.tg_topology_config(port_handle=kwargs.get('port_handle'))
                    logger.info(res)
                    topo_han = res['topology_handle']
                    self.topo_handle[kwargs.get('port_handle')] = topo_han
                    logger.info(self.topo_handle)
                    tgen_wait(10)
                mul=kwargs.get('count','1')
                if 'vlan_id_count' in kwargs:
                    mul=kwargs.get('vlan_id_count','1')
                res=self.tg_topology_config(topology_handle=topo_han, device_group_multiplier=mul)
                logger.info(res)
                tgen_wait(10)
                kwargs['protocol_handle'] = res['device_group_handle']
                kwargs.pop('port_handle')
            if kwargs.get('enable_flow_control') != None:
                kwargs['enable_flow_control'] = 1 if kwargs['enable_flow_control'] == 'true' else 0
            for param in ('count', 'block_mode', 'enable_ping_response'):
                if kwargs.get(param) != None:
                    kwargs.pop(param)

        if fname == 'tg_packet_control':
                if kwargs['action'] == 'start':
                    self.tg_traffic_control(action='apply')
                    # suggested by Ixia for more accurate results
                    logger.info('Enabling control and data plane options')
                    self.tg_packet_config_buffers(port_handle=kwargs['port_handle'],
                                                  control_plane_capture_enable='1',
                                                  data_plane_capture_enable='1')

        if fname == 'tg_traffic_stats':
            if kwargs.get('csv_path') == None:
                kwargs['csv_path'] = tgen_get_logs_path_folder()

        if fname == 'tg_emulation_bgp_route_config':
            if 'ipv6_prefix_length' in kwargs:
                kwargs['prefix_from'] = kwargs['ipv6_prefix_length']
                kwargs.pop('ipv6_prefix_length')
            logger.info('Disabling protocol before adding the route')
            self.tg_topology_test_control(handle=kwargs['handle'], stack='ethernet', action='stop_all_protocols',
                                          tg_wait=10)
            topo = re.search(r'.*topology:(\d)+', kwargs['handle']).group(0)
            logger.debug('Topology: {}'.format(topo))
            tg_port = self.topo_handle.keys()[self.topo_handle.values().index(topo)]
            logger.debug('port_handle: {}'.format(tg_port))
            for i in range(1,30):
                res = self.tg_protocol_info(mode='global_per_port')
                total=res['global_per_port'][tg_port]['sessions_total']
                total_ns=res['global_per_port'][tg_port]['sessions_not_started']
                logger.debug(total)
                logger.debug(total_ns)
                if total == total_ns:
                    break
                tgen_wait(2)
            tgen_wait(10)

        if fname == 'tg_emulation_bgp_control':
            logger.info('Applying changes for IXIA before starting BGP')
            self.tg_topology_test_control(action='apply_on_the_fly_changes', tg_wait=10)

        if fname == 'tg_emulation_bgp_config':
            if kwargs.get('local_as') != None and kwargs.get('remote_as') != None:
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

        if fname == 'tg_emulation_igmp_control':
            if kwargs.get('mode') in ['join', 'leave'] :
                kwargs['group_member_handle'] = kwargs['handle']
                kwargs.pop('handle', None)

        if fname == 'tg_emulation_multicast_group_config':
            if kwargs.get('active') == None:
                kwargs['active'] = '1'
            kwargs.pop('ip_addr_step_val', '')

        if fname == 'tg_emulation_multicast_source_config':
            if kwargs.get('active') == None:
                kwargs['active'] = '1'
            kwargs.pop('ip_addr_step_val', '')

        if fname == 'tg_emulation_igmp_group_config':
            if kwargs.get('source_pool_handle') == None and kwargs.get('mode') == 'create':
                res = self.tg_emulation_multicast_source_config(mode='create', ip_addr_start='21.1.1.100',
                                                                num_sources=1, active=0)
                kwargs['source_pool_handle'] = res['multicast_source_handle']
            if kwargs.get('mode') == 'clear_all':
                self.map_field("handle", "session_handle", kwargs)

        if fname == 'tg_emulation_igmp_querier_config':
            if kwargs.get('active') == None and kwargs.get('mode') == 'create':
                kwargs['active'] = '1'
            if kwargs.get('mode') == 'create':
                kwargs['handle'] = re.search(r'.*ipv4:(\d)+', kwargs['handle']).group(0)
                self.tg_topology_test_control(handle=kwargs['handle'], stack='topology', action='stop_protocol')

        if fname =='tg_emulation_ospf_config':
            kwargs['handle'] = kwargs['handle'][0] if isinstance(kwargs['handle'], list) else kwargs['handle']
            self.tg_topology_test_control(handle=kwargs['handle'], stack='ethernet', action='stop_protocol')
            if kwargs.get('mode') == 'create':
                kwargs['handle'] = re.search(r'.*ipv(4|6):(\d)+', kwargs['handle']).group(0)
                kwargs['area_id_type'] = 'ip'
                kwargs.pop('gateway_ip_addr', '')
        if fname == 'tg_emulation_dhcp_group_config':
            self.map_field("ipv4_gateway_address", "dhcp4_gateway_address", kwargs)
            self.map_field("gateway_ipv6_addr", "dhcp6_gateway_address", kwargs)
            if str(kwargs.get("dhcp_range_ip_type")) == '4':
                kwargs['dhcp_range_ip_type'] = 'ipv4'
            else:
                kwargs['dhcp_range_ip_type'] = 'ipv6'
        if fname == 'tg_emulation_dhcp_server_config':
            self.map_field("gateway_ipv6_addr", "ipv6_gateway", kwargs)
            self.map_field("remote_mac", "manual_gateway_mac", kwargs)
            self.map_field("encapsulation", "", kwargs)
        return kwargs

    def tg_interface_handle(self, ret_ds):
        if "interface_handle" in ret_ds:
            if "ipv4_handle" in ret_ds or "ipv6_handle" in ret_ds:
                temp = ret_ds['interface_handle'].split()
                # Removing extra ethernet handles.
                temp = temp[:len(temp)/2]
                ret_ds['handle'] = temp[0] if len(temp)==1 else temp
            else:
                ret_ds['handle'] = ret_ds['interface_handle']
        return ret_ds

    def tg_igmp_querier_control(self, mode, handle):
        result = self.tg_emulation_igmp_control(mode=mode, handle=handle)
        tgen_wait(10)
        logger.info("IGMP Querier action completed: {}".format(result))
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

    def tg_arp_control(self, **kwargs):
        if 'handle' in kwargs:
            han = kwargs['handle']
            if type(han) is list:
                han = re.search(r'.*ipv(4|6):(\d)+',han[0]).group(0)
            result = self.tg_interface_config(protocol_handle=han, arp_send_req='1')
        elif 'port_handle' in kwargs:
            result = self.tg_interface_config(port_handle=kwargs['port_handle'], arp_send_req='1')
        logger.info ('Sending ARP completed: {}'.format(result))
        return result

    def tg_disconnect(self,**kwargs):
        if self.skip_traffic: return 0
        logger.info('Executing: {} {}'.format('ixiangpf.cleanup_session',kwargs))
        port_handle_list = self.get_port_handle_list()
        ret_ds = get_ixiangpf().cleanup_session(
            maintain_lock=0, port_handle=port_handle_list, reset=1)
        logger.info(ret_ds)
        if ret_ds['status'] == '1':
            logger.debug('TG API Run Status: Success')
        else:
            logger.warning('TG API Error: %s' % ret_ds['log'])
        self.tg_connected = False
        self.tg_port_handle.clear()

    def local_ixnet_call(self,method,*args):
        #::ixNet::OK'
        #IxNetError:
        func_call = 'ixiangpf.ixnet.'+method
        res = eval(func_call)(*args)
        if re.search(r'Error',res):
            logger.info('Error in ixNet call {}: {}'.format(func_call,res))
        return res

    def local_get_captured_packets(self,**kwargs):
        packet_type = kwargs.get('packet_type','data')
        if packet_type.lower() == 'control':
            packet_type = 'control'

        ret_dict = dict()
        captured_packets = dict()
        #Add code to check if any packets are captured and return 0 if none
        ret_dict['status'] = '1'

        #get vport info
        res = self.tg_convert_porthandle_to_vport(port_handle=kwargs['port_handle'])
        vport_handle = res['handle']
        cap_pkt_count = self.local_ixnet_call('getAttribute',vport_handle+'/capture','-'+packet_type+'PacketCounter')
        pkts_in_buffer = int(cap_pkt_count) if int(cap_pkt_count) <= 20 else 20
        captured_packets.update({'aggregate': {'num_frames': pkts_in_buffer}})
        captured_packets['frame'] = dict()
        for pkt_count in range(0,pkts_in_buffer):
            sub_method = 'getPacketFrom'+packet_type.title()+'Capture'
            self.local_ixnet_call('execute', sub_method, vport_handle+'/capture/currentPacket', pkt_count)
            hp = self.local_ixnet_call('getAttribute',vport_handle+'/capture/currentPacket', '-packetHex')
            frame_in_hex = hp.encode('ascii','ignore').split()[2:]
            frame_in_hex_upper = [byte.upper() for byte in frame_in_hex]
            captured_packets['frame'].update({str(pkt_count): {'frame_pylist': frame_in_hex_upper}})

        ret_dict[kwargs['port_handle']] = captured_packets
        return ret_dict

    def tg_custom_filter_config(self,**kwargs):
        ret_dict = dict()
        ret_dict['status'] = '1'
        ixia_kwargs = dict()

        if not kwargs.get('mode') or not kwargs.get('port_handle'):
            logger.info("Missing Mandatory parameter: port_handle or mode")
            ret_dict['status'] = '0'
            return ret_dict

        mode = kwargs.get('mode').lower()
        port_handle = kwargs.get('port_handle')
        ixia_kwargs['port_handle'] = port_handle
        offset_count = 0
        if mode != 'getstats':
            for offset,pattern in zip(['pattern_offset1'],['pattern1']):
                if not kwargs.get(offset) or not kwargs.get(pattern):
                    logger.info('Missing Mandatory parameter {} or {}'.format(offset,pattern))
                    ret_dict['status'] = '0'
                    return ret_dict
                offset_count += 1
                ixia_kwargs['pattern_offset1'] = kwargs['pattern_offset1']
                ixia_kwargs['pattern1'] = kwargs['pattern1']
                capture_filter_pattern = 'pattern1'

            for offset,pattern in zip(['pattern_offset2'],['pattern2']):
                if kwargs.get(offset) and kwargs.get(pattern):
                    offset_count += 1
                    ixia_kwargs['pattern_offset2'] = kwargs['pattern_offset2']
                    ixia_kwargs['pattern2'] = kwargs['pattern2']
                    capture_filter_pattern = 'pattern1and2'

                elif not kwargs.get(offset) and not kwargs.get(pattern):
                    pass
                else:
                    logger.info('Both parameter {} and {} need to be provided'.format(offset,pattern))
                    ret_dict['status'] = '0'
                    return ret_dict

        #capture_filter_pattern = kwargs.get('capture_filter_pattern','pattern1and2')
        if mode == 'create':
            self.tg_packet_config_buffers(port_handle=port_handle,capture_mode = 'trigger',
                    before_trigger_filter = 'all', after_trigger_filter = 'filter')
            self.tg_packet_config_filter(**ixia_kwargs)
            self.tg_packet_config_triggers(port_handle=port_handle,capture_trigger=1,
                    capture_filter=1,capture_filter_pattern=capture_filter_pattern)
            self.tg_packet_control(port_handle=port_handle,action='start')

        if mode == 'getstats':
            self.tg_packet_control(port_handle=port_handle,action='stop')
            ret_dict[port_handle] = {}
            ret_dict[port_handle].update({'custom_filter': {}})
            filtered_frame_count = 0
            total_rx_count = 0
            tgen_wait(5)
            result = self.tg_packet_stats(port_handle=port_handle)
            if result['status'] != '1':
                for i in range(1,5):
                    logger.info('Get Filtered Stats Failed, Trying again, after 5 sec...Try: {}'.format(i))
                    tgen_wait(5)
                    result = self.tg_packet_stats(port_handle=port_handle)
                    if result['status'] == '1':
                        break

            logger.debug(result)
            if result['status'] == '1':
                filtered_frame_count = result[port_handle]['aggregate']['num_frames']
                total_rx_count = result[port_handle]['aggregate']['uds5_frame_count']

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
        if traffic_mode.get(mode) != None:
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
        handle=kwargs.get('handle')
        port_handle=kwargs.get('port_handle')
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
            if not port_handle: return
            port_handle = utils.make_list(port_handle)
            for han in port_handle:
                if han in self.traffic_config_handles: self.traffic_config_handles.pop(han)

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
            res = get_ixiangpf().traffic_control(action='stop', handle=traffic_elem["res"]['stream_id'])
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
                #msg = "traffic is not configured"
                #self.fail(msg, "tgen_failed_api", msg)
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
            if not port_handle: return
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
                if not self.traffic_config_handles[port_handle]: self.traffic_config_handles.pop(port_handle)

class TGScapy(TGBase, ScapyClient):
    def __init__(self, tg_type, tg_version, tg_ip=None, tg_port=8009, tg_port_list=None):
        logger.info('TG Scapy Init')
        ScapyClient.__init__(self, logger, tg_port)
        TGBase.__init__(self, tg_type, tg_version, tg_ip, tg_port_list)

    def clean_all(self):
        self.server_control("clean-all", "")

    def show_status(self):
        pass

    def instrument(self, phase, context):
        self.server_control(phase, context)

    def log_call(self, fname, **kwargs):
        tgen_log_call(fname, **kwargs)

    def api_fail(self, msg):
        tgen_fail("", "tgen_failed_api", msg)

    def save_log(self, name, data):
        lfile = tgen_get_logs_path(name)
        utils.write_file(lfile, data)

    def connect(self):
        logger.info('TG Scapy Connect {}:{}'.format(self.tg_ip, self.tg_port))
        return self.scapy_connect()

    def tg_arp_control(self, **kwargs):
        if 'handle' in kwargs:
            result = self.tg_interface_config(protocol_handle=kwargs['handle'], arp_send_req='1')
        elif 'port_handle' in kwargs:
            result = self.tg_interface_config(port_handle=kwargs['port_handle'], arp_send_req='1')
        logger.info ('Sending ARP completed: {}'.format(result))
        return result

    def tg_withdraw_bgp_routes(self, route_handle):
        result = self.tg_emulation_bgp_control(handle=route_handle, mode='stop')
        logger.info('withdraw action completed: {}'.format(result))
        return result if result['status'] == '1' else None

    def tg_readvertise_bgp_routes(self, handle, route_handle):
        result = self.tg_emulation_bgp_control(handle=route_handle, mode='start')
        logger.info('readvertise action completed: {}'.format(result))
        return result if result['status'] == '1' else None

def generate_tg_methods(tg_type, afnl):
    for func in afnl:
        #logger.info("creating wrapper for {}".format(func))
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

        #exec tg_wrapper_func in globals()
        exec(tg_wrapper_func, globals())
        if tg_type == 'ixia':
            setattr(TGIxia, dummy_func_name, eval(dummy_func_name))
        else:
            setattr(TGStc, dummy_func_name, eval(dummy_func_name))

def close_tgen(tgen_dict):
    try:
        tg_obj = tgen_obj_dict[tgen_dict['name']]
        tg_obj.tg_disconnect()
    except:
        pass

def init_tgen(workarea_in, logger_in, skip_tgen_in):
    global workarea, logger, skip_tgen
    workarea = workarea_in
    logger = logger_in or Logger()
    skip_tgen = skip_tgen_in
    hltApiLog = tgen_get_logs_path('hltApiLog.txt')
    utils.delete_file(hltApiLog)

def instrument_tgen(tgen_dict, phase, context):
    tg = tgen_obj_dict[tgen_dict["name"]]
    tg.instrument(phase, context)

def load_tgen(tgen_dict):
    global tg_stc_pkg_loaded, tg_ixia_pkg_loaded, tg_scapy_pkg_loaded, tg_version_list
    file_prefix = os.getenv("SPYTEST_FILE_PREFIX", "results")
    # Abort if same TG type are having different version
    tg_type = tgen_dict['type']
    tg_version = tgen_dict['version']

    if tg_version_list.get(tg_type, None) == None:
        tg_version_list[tg_type] = tg_version
    elif tg_version_list.get(tg_type, None) != tg_version:
        logger.error("Only one version per TG type is supported: %s %s %s"
                     % (tg_type, tg_version_list.get(tg_type, None), tg_version))
        return False

    tg_ip = tgen_dict['ip']
    tg_port_list = tgen_dict['ports']
    logger.info("Loading {}:{} {} Ports: {}".format(
        tg_type, tg_version, tg_ip, tg_port_list))

    if not utils.ipcheck(tg_ip):
        logger.error("TGEN IP Address: {} is not reachable".format(tg_ip))
        return False

    if tg_type == 'stc':
        os.environ['STC_LOG_OUTPUT_DIRECTORY'] = tgen_get_logs_path_folder()
        logger.debug("STC_TGEN_LOGS_PATH: {}".format(os.getenv('STC_LOG_OUTPUT_DIRECTORY')))
        if not tg_stc_pkg_loaded:
            if not tg_stc_load(tg_version, logger, tgen_get_logs_path()):
                return False
            code = "import sth \n"
            exec (code, globals(), globals())
            if os.getenv('SPYTEST_LOGS_LEVEL') == 'debug':
                logger.info("Setting Stc Debugs...")
                hltExportLog = os.path.join(tgen_get_logs_path_folder(), "{}_{}".format(file_prefix, 'hltExportLog'))
                hltDbgLog = os.path.join(tgen_get_logs_path_folder(), "{}_{}".format(file_prefix, 'hltDbgLog'))
                stcExportLog = os.path.join(tgen_get_logs_path_folder(), "{}_{}".format(file_prefix, 'stcExportLog'))
                hltMapLog = os.path.join(tgen_get_logs_path_folder(), "{}_{}".format(file_prefix,'hltMapLog'))
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
        tg_obj = TGStc(tg_type, tg_version, tg_ip, tg_port_list)

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

                exec(code, globals(), globals())
                if os.getenv('SPYTEST_LOGS_LEVEL') == 'debug':
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
            tg_obj = TGIxia(tg_type, tg_version, tg_ip, tg_port_list, tg_ix_server, tg_ix_port)
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
    return tg_obj.tg_connected

def module_init(tgen_dict):
    tg_type = tgen_dict['type']
    tg_version = tgen_dict['version']
    tg_ip = tgen_dict['ip']
    tg_port_list = tgen_dict['ports']

    # add any thing to be done before start of user module
    # like clear streams or port reset etc.
    logger.info("TG Module init {}:{} {} Ports: {}".format(
        tg_type, tg_version, tg_ip, tg_port_list))

    tg = None
    try:
        tg = tgen_obj_dict[tgen_dict["name"]]
        tg.in_module_start_cleanup = True
        tg.clean_all()
        tg.in_module_start_cleanup = False
        return True
    except Exception as exp:
        if tg: tg.in_module_start_cleanup = False
        msg = "Failed to reset port list {} : {}".format(",".join(tg_port_list), exp)
        logger.exception(msg)
        return False

def get_tgen_handler():
    return {
        'ixia_handler': get_ixiangpf() if 'ixiangpf' in globals() else None,
        'stc_handler': get_sth() if 'sth' in globals() else None
    }

def get_tgen(port, name=None):
    if name is None:
        try: name = tgen_obj_dict.keys()[0]
        except: pass
    elif name not in tgen_obj_dict:
        return (None, None)
    tg = tgen_obj_dict[name]
    ph = tg.get_port_handle(port)
    return (tg, ph)

if __name__ == "__main__":
    tg_ixia_load("8.42", None, None)
    code = \
        "from ixiatcl import IxiaTcl \n" + \
        "from ixiahlt import IxiaHlt \n" + \
        "from ixiangpf import IxiaNgpf \n" + \
        "from ixiaerror import IxiaError \n" + \
        "ixiatcl = IxiaTcl() \n" + \
        "ixiahlt = IxiaHlt(ixiatcl) \n" + \
        "ixiangpf = IxiaNgpf(ixiahlt) \n"

    exec(code, globals(), globals())

