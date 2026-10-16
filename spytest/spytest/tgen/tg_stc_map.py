import os
import re
import copy
import inspect
import traceback
import utilities.common as utils

from spytest.logger import Logger
from netaddr import IPAddress

from spytest.tgen.tg import TGStc, tgen_abort, get_sth, tgen_wait, analyzer_filter
from typing import Dict, List

logger = None
ports_offline = False

TitleBeforeMapping="Before Mapping"
TitleAfterMapping="After Mapping"
TitleIxiangpfAdapter="Ixiangpf Adapter"
TitleDhcpPollEnableCustomer="DhcpPool.EnableCustomer"
TitleDhcpPoolServerRelay="DhcpPool.ServerRelay"
TitleDhcpClientCreate="DhcpClient.Create"
device_groups_index=0

def get_myfname():
    return inspect.stack()[1].function

def log_func(title, fname, **kwargs):
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
    msg = "====== {}: {}({})".format(title, fname, ",".join(args_list))
    logger.info(msg)

def deep_vars(obj):
    if isinstance(obj, dict):
        return {k: deep_vars(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [deep_vars(item) for item in obj]
    elif hasattr(obj, "__dict__"):
        return {k: deep_vars(v) for k, v in vars(obj).items()}
    else:
        return obj

def pick_field(dst_kwargs: Dict, dst_field: str, src_kwargs: Dict, src_field: str, default=None ):
    if src_kwargs.get(src_field) is not None:
        dst_kwargs[dst_field] = src_kwargs[src_field]
        return True
    if default is not None:
        dst_kwargs[dst_field] = default
    logger.warning("Cannot pick dst_field value for - {}".format(dst_field))
    return False

def is_list_of_lists(obj):
    return isinstance(obj, list) and obj and all(isinstance(i, list) for i in obj)
class _ListKeyDict(dict):
    """
    A dict subclass whose __getitem__ accepts a list key by aggregating
    numeric stat values across all matching stream entries.
    This allows tgen_utils._fetch_stats / get_traffic_stats to index
    the 'stream' sub-dict with a list of stream handles without crashing
    with 'TypeError: unhashable type: list'.
    """
    def __getitem__(self, key):
        if not isinstance(key, list):
            return super().__getitem__(key)
        result = {}
        for k in key:
            if k not in self:
                continue
            for direction, d_val in super().__getitem__(k).items():
                if not isinstance(d_val, dict):
                    continue
                if direction not in result:
                    result[direction] = {}
                for counter, val in d_val.items():
                    try:
                        result[direction][counter] = str(
                            int(float(result[direction].get(counter, 0))) +
                            int(float(val or 0))
                        )
                    except (TypeError, ValueError):
                        result[direction][counter] = val
        return result
class device_group:
    def __init__(self, **kwargs):
        self.kwargs = copy.deepcopy(kwargs)
        # mapping device_group_handleX->hostY, 1:N map
        global device_groups_index
        device_groups_index+=1
        device_group_handle="{}_{}".format("device_group_handle", device_groups_index)
        self.device_group_handle = device_group_handle
        self.host_kwargs_map: Dict = {} # host as key, and kwargs as value

    def add_host(self, host: str, kwargs):
        self.host_kwargs_map[host] = copy.deepcopy(kwargs)

    def delete_host(self, host: str):
        self.host_kwargs_map.pop(host, "")

    def get_host(self):
        for host, args in self.host_kwargs_map.items():
            if args.get("mapto") is None:
                return host
        return None

    def get_host_kwargs(self, host):
        return self.host_kwargs_map.get(host)

    def destroy(self):
        port_handle = ""
        for host, args in self.host_kwargs_map.items():
            if args.get("port_handle") is not None:
                port_handle=args.get("port_handle")

        if port_handle == "":
            logger.warning("cannot find any interface to destroy")
            return

        for host, args in self.host_kwargs_map.items():
            if args.get("mapto") is not None:
                get_mapfuncs().stc.manage_interface_config_handles('destroy', port_handle, host)
            else:
                get_mapfuncs().tg_interface_config(port_handle=port_handle, handle=host, mode='destroy')

        self.host_kwargs_map.clear()

class Stream_id():
    def __init__(self, index, prefix:str = "", streamblocks:List = []):
        stream_id="{}{}_{}".format(prefix,"stream_id", index)
        self.stream_id = stream_id
        self.streamblocks = streamblocks

    def get_streamblocks(self):
        return self.streamblocks

    def add_streamblock(self, streamblock:str):
        self.streamblocks.append(streamblock)
        return

    def set_streamblocks(self, streamblocks:List):
        self.streamblocks = streamblocks

class topology():
    #  kwargs includes: topology_name, lag_handle/port_handle, dhcp_group_handle
    def __init__(self, index, **kwargs):
        self.kwargs = copy.deepcopy(kwargs)

        topology_handle="{}_{}".format("topology_handle", index)
        self.topology_handle = topology_handle

        # device_group_handle as mapping key.
        self.device_groups:Dict[str, device_group]={}

    def device_group_create(self, **kwargs):
        devgrp=device_group(**kwargs)
        self.device_groups[devgrp.device_group_handle]=devgrp
        return devgrp

    def device_group_destroy(self, device_group_handle):
        dg = self.device_groups.get(device_group_handle, None)
        if dg:
            dg.destroy()
            self.device_groups.pop(device_group_handle, None)
            logger.info("device_group destroyed - {} ".format(device_group_handle))

    def destroy(self):
        for device_group_handle in list(self.device_groups):
            self.device_group_destroy(device_group_handle)

class Ixnet_Adapter():
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def getAttribute(self, *args):
        logger.info("{}, args={}".format(get_myfname(), args))
        ret = 'aresOne-M'
        return ret


class Ixiangpf_Adapter():
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.mapfuncs: TGStcMapFuncs = kwargs['stcmap']
        self.ixnet = Ixnet_Adapter(**kwargs)
        pass

    def override(self, **kwargs):
        caller = inspect.stack()[1].function
        log_func(TitleIxiangpfAdapter, caller, **kwargs)
        fname = caller if "tg_" in caller else "tg_{}".format(caller)
        logger.info("override {}->{}".format(caller, fname))

        ret_ds = {}

        if hasattr(self.mapfuncs, fname):
            method=getattr(self.mapfuncs, fname)
            if callable(method):
                ret_ds=method(**kwargs)
                return ret_ds
        elif hasattr(self.mapfuncs.stc, fname):
            method=getattr(self.mapfuncs.stc, fname)
            if callable(method):
                ret_ds=method(**kwargs)
                return ret_ds

        ret_ds['status']=0
        logger.error("{} should be overriden".format(fname))
        return ret_ds

    def tg_save_config(self, **kwargs):
        return self.override(**kwargs)

    def test_control(self, **kwargs):
        return self.override(**kwargs)

    def convert_porthandle_to_vport(self, **kwargs):
        return self.override(**kwargs)

    def convert_vport_to_porthandle(self, **kwargs):
        return self.override(**kwargs)

    def emulation_dhcp_server_config(self, **kwargs):
        return self.override(**kwargs)

    def emulation_dhcp_group_config(self, **kwargs):
        return self.override(**kwargs)

    def emulation_dhcp_control(self, **kwargs):
        return self.override(**kwargs)

    def emulation_dhcp_server_control(self, **kwargs):
        return self.override(**kwargs)

    def emulation_dhcp_stats(self, **kwargs):
        return self.override(**kwargs)

    def set_dhcp_server(self, **kwargs):
        return self.override(**kwargs)

    def arp_dhcp_server(self, **kwargs):
        return self.override(**kwargs)

class TGStcMapFuncs():
    def __init__(self, stc: TGStc, logger_in):
        self.stc = stc
        self.map_field = stc.map_field
        self.topology_index = 0
        self.topologies:Dict[str, topology] = {}
        self.stream_id_index = 0
        self.stream_ids: Dict[str, Stream_id] = {}
        self.ixiangpf_adapter = Ixiangpf_Adapter(stcmap=self)
        self.fail = self.stc.fail
        self.warn = self.stc.warn
        ####################
        # override functions
        ####################
        self.stc.ixia_eval = self._ixia_eval

        self.stc.tg_topology_config = self.tg_topology_config
        self.stc.tg_protocol_info = self.tg_protocol_info
        self.stc.tg_convert_porthandle_to_vport = self.tg_convert_porthandle_to_vport
        self.stc.tg_convert_vport_to_porthandle = self.tg_convert_vport_to_porthandle
        # dhcp
        # self.stc.tg_emulation_dhcp_server_config = self.ixiangpf_adapter.emulation_dhcp_server_config
        # self.stc.tg_emulation_dhcp_group_config = self.ixiangpf_adapter.emulation_dhcp_group_config
        # self.stc.tg_emulation_dhcp_control = self.ixiangpf_adapter.emulation_dhcp_control
        # self.stc.tg_emulation_dhcp_server_control = self.ixiangpf_adapter.emulation_dhcp_server_control
        # self.stc.tg_emulation_dhcp_stats = self.ixiangpf_adapter.emulation_dhcp_stats
        global logger, mapfuncs
        logger = logger_in or Logger()
        mapfuncs = self

    def _ixia_eval(self, func, **kwargs):
        # return self.stc.tgen_eval("", func, **kwargs)
        log_func(TitleIxiangpfAdapter, func, **kwargs)
        fname = func if "tg_" in func else "tg_{}".format(func)
        logger.info("override {}->{}".format(func, fname))

        ret_ds = {}

        if hasattr(self, fname):
            method=getattr(self, fname)
            if callable(method):
                ret_ds=method(**kwargs)
                return ret_ds
        elif hasattr(self.stc, fname):
            method=getattr(self.stc, fname)
            if callable(method):
                ret_ds=method(**kwargs)
                return ret_ds

        ret_ds['status']=0
        logger.error("{} should be overriden".format(fname))
        return ret_ds

    def _check_return_status(self, ret_ds: Dict):
        if not ret_ds and os.getenv("SPYTEST_FILE_MOVE", 0) != "0":
            logger.warning("tg_stc_map: empty ret_ds in filemote - treating as no-op")
            return

        if "status" not in ret_ds or ret_ds['status'] != '1':
            stack_info = traceback.format_stack(limit=10)
            outs = "------------------------------------------------\r\n"
            outs += "".join(stack_info)
            outs += "------------------------------------------------\r\n"
            logger.error(outs)

        if "status" not in ret_ds:
            logger.error(ret_ds)
            msg = "Unknown" if "log" not in ret_ds else ret_ds['log']
            tgen_abort("nolog", "tgen_failed_abort", str(msg))
            self.fail("nolog", "tgen_failed_api", msg)
        elif ret_ds['status'] == '1':
            pass
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
            if "Unable to set attributes" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_set_attrib")
            if "Port already used" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_port_in_used")
            if "Unable to connect to IxNetwork" in ret_ds['log']:
                tgen_abort(ret_ds['log'], "tgen_failed_abort", ret_ds['log'])
            if "Please provide a valid traffic item handle or name" in ret_ds['log']:
                self.fail(ret_ds['log'], "tgen_failed_api", ret_ds['log'])
            if "invalid handle" in ret_ds['log'] and "should have been obtained using create or get" in ret_ds['log']:
                logger.warning("Skipping already-deleted or unregistered Viavi TestCenter handle during cleanup: {}".format(ret_ds['log']))
                return
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

            self.warn("{} status error: ret_ds {}".format(inspect.stack()[1].function, ret_ds))

    def _stream_id_create(self, prefix:str, streamblocks:List)->Stream_id:
        self.stream_id_index+=1
        stream_id=Stream_id(self.stream_id_index, prefix, streamblocks)
        self.stream_ids[self.stream_id_index] = stream_id
        return self.stream_ids[self.stream_id_index]

    def _dump_topologies(self):
        # TODO: change info to trace
        # logger.info("----------------dump topologies start-----------------------\n{}".
        #             format(pprint.pformat(deep_vars(self.topologies))))
        # logger.info("----------------dump topologies end ------------------------")
        pass

    def _topology_create(self, **kwargs)->topology:
        self.topology_index+=1
        topo=topology(self.topology_index, **kwargs)
        self.topologies[topo.topology_handle]=topo
        return self.topologies[topo.topology_handle]

    def _get_port_handle_from_cache(self, handle):
        for port_handle, handle_list in self.stc.cached_interface_config_handles.items():
            if handle in handle_list:
                return port_handle
        return None

    def _get_port_handle_by_device_group_handle(self, device_group_handle):
        for topo in self.topologies.values():
            for grp in topo.device_groups.values():
                if grp.device_group_handle == device_group_handle:
                    if topo.kwargs.get('port_handle') is not None:
                        return topo.kwargs.get('port_handle')
                    else:
                        return topo.kwargs.get('lag_handle')
        logger.warning("cannot find the port_handle by device_group_handle - {}".format(device_group_handle))
        return None

    def _get_port_handle_by_topology_handle(self, topology_handle):
        for topo in self.topologies.values():
            if topo.topology_handle == topology_handle:
                if topo.kwargs.get('port_handle') is not None:
                    return topo.kwargs.get('port_handle')
                else:
                    return topo.kwargs.get('lag_handle')
        logger.warning("cannot find the port_handle by topology_handle - {}".format(topology_handle))
        return None

    def _get_dhcp_group_handle_by_topology_handle(self, topology_handle):
        for topo in self.topologies.values():
            if topo.topology_handle == topology_handle:
                if topo.kwargs.get('dhcp_group_handle') is not None:
                    return topo.kwargs.get('dhcp_group_handle')
        logger.warning("cannot find the dhcp_group_handle by topology_handle - {}".format(topology_handle))
        return None

    def _set_dhcp_group_handle(self, topology_handle, dhcp_group_handle):
        for topo in self.topologies.values():
            if topo.topology_handle == topology_handle:
                topo.kwargs['dhcp_group_handle'] = dhcp_group_handle
        return None

    def _topology_destroy(self, topology_handle):
        topo = self.topologies.get(topology_handle, None)
        if topo:
            topo.destroy()
            self.topologies.pop(topology_handle, None)
            logger.info("topology destroyed - {} ".format(topology_handle))

    def _device_group_destroy(self, device_group_handle):
        for topo in self.topologies.values():
            topo.device_group_destroy(device_group_handle)

    def _add_device_group_host(self, device_group_handle, host, kwargs):
        for topo in self.topologies.values():
            for grp in topo.device_groups.values():
                if grp.device_group_handle == device_group_handle:
                    grp.add_host(host, kwargs)
                    return None
        logger.warning("cannot find the device_group by device_group_handle - {}".format(device_group_handle))
        return None

    def _delete_device_group_host(self, host):
        logger.info("delete the host - {}".format(host))
        for topo in self.topologies.values():
            for grp in topo.device_groups.values():
                if host in grp.host_kwargs_map.keys():
                    grp.delete_host(host)
                    return None
        logger.warning("cannot find the host - {}".format(host))
        return None

    def _get_device_group_host(self, device_group_handle):
        for topo in self.topologies.values():
            for grp in topo.device_groups.values():
                if grp.device_group_handle == device_group_handle:
                    return grp.get_host()
        logger.warning("cannot find the device_group by device_group_handle - {}".format(device_group_handle))
        return None

    def _get_device_group_multiplier(self, device_group_handle):
        """Return device_group_multiplier stored in device_group kwargs, or 1 if not set."""
        for topo in self.topologies.values():
            for grp in topo.device_groups.values():
                if grp.device_group_handle == device_group_handle:
                    return grp.kwargs.get('device_group_multiplier', 1)
        return 1

    def _get_host_kwargs(self, host):
        for topo in self.topologies.values():
            for grp in topo.device_groups.values():
                if grp.host_kwargs_map.get(host) is not None:
                    return grp.host_kwargs_map.get(host)
        logger.warning("cannot find the host kwargs by host - {}".format(host))
        return None

    def _update_host_kwargs(self, host, **kwargs):
        for topo in self.topologies.values():
            for grp in topo.device_groups.values():
                if grp.host_kwargs_map.get(host) is not None:
                    grp.host_kwargs_map[host] = copy.deepcopy(kwargs)
                    return
        logger.warning("cannot find the host kwargs by host - {}".format(host))
        return None

    def _convert_traffic_stats_ret(self, input_dict, streams):

        output_dict = {
                "traffic_item": {}
                }

        for key, value in input_dict.items():
            # Process only streamblocks
            if key.startswith("streamblock") and isinstance(value, dict):
                tx = value.get("tx", {})
                rx = value.get("rx", {})
                output_dict["traffic_item"][key] = {
                    "tx": tx,
                    "rx": rx
                }
            # keep it as it is other keys like port1, status, etc.
            else:
                output_dict["traffic_item"][key] = value

            if is_list_of_lists(streams):
                for idx, sublist in enumerate(streams, start=1):
                    key = f"TI-streamblock_{idx}"

                    output_dict["traffic_item"][key] = {
                        "tx": {"total_pkts": 0},
                        "rx": {"total_pkts": 0}
                    }
                    for sb in sublist:
                        if sb not in input_dict:
                            continue
                        tx = input_dict[sb]["tx"]
                        rx = input_dict[sb]["rx"]

                        output_dict["traffic_item"][key]["tx"]["total_pkts"] += int(tx.get("total_pkts", 0))
                        output_dict["traffic_item"][key]["rx"]["total_pkts"] += int(rx.get("total_pkts", 0))
            else:
                if key.startswith("streamblock") and isinstance(value, dict):
                    traffic_key = f"TI-{key}"
                    output_dict["traffic_item"][traffic_key] = {
                        "tx": {"total_pkts": 0},
                        "rx": {"total_pkts": 0}
                        }
                    tx = input_dict[key]["tx"]
                    rx = input_dict[key]["rx"]
                    output_dict["traffic_item"][traffic_key]["tx"]["total_pkts"] = int(tx.get("total_pkts", 0))
                    output_dict["traffic_item"][traffic_key]["rx"]["total_pkts"] = int(rx.get("total_pkts", 0))
        return output_dict

    def _convert_dhcp_stats(self, stats):
        ret_ds = {
            "status": stats['status'],
            "session": {}
        }

        for key in stats.get('group'):
            dhcp_info = stats['group'].get(key)
            for key2, value in dhcp_info.items():
                if type(value) is dict:
                    entry="/{}.item:{}".format(key, key2)
                    ret_ds['session'][entry] = {}
                    ret_ds['session'][entry] = {}
                    if value['ipv4_addr'] == "0.0.0.0":
                        ret_ds['session'][entry]['Address'] = "reserveSlot[Unresolved]"
                        ret_ds['session'][entry]['address'] = "reserveSlot[Unresolved]"
                    else:
                        ret_ds['session'][entry]['Address'] = value['ipv4_addr']
                        ret_ds['session'][entry]['address'] = value['ipv4_addr']
        return ret_ds

    def _convert_flow_traffic_stat(self, input_dict):
        output_dict = {'flow': {}}
        flow_index = 1

        for key, val in input_dict.items():
            # Top-level streamblock
            if key.startswith('streamblock') and isinstance(val, dict):
                stream_name = key
                rx_info = val.get('rx', {}).get('0', {})
                tx_info = val.get('tx', {}).get('0', {})

                # pick first rx port
                port_list = rx_info.get('rx_port_handle_list_pylist', [])
                port = port_list[0] if port_list else 'unknown'

                output_dict['flow'][str(flow_index)] = {
                    'flow_name': f"{port} {stream_name}",
                    'rx': rx_info,
                    'tx': tx_info
                }
                flow_index += 1

            # Nested under port -> stream, will change it later if needed after veriffing at customer side
            # elif isinstance(val, dict) and 'stream' in val:
            #     for stream_name, stream_val in val['stream'].items():
            #         rx_info = stream_val.get('rx', {}).get('0', {})
            #         tx_info = stream_val.get('tx', {}).get('0', {})

            #         port_list = rx_info.get('rx_port_handle_list_pylist', [])
            #         port = port_list[0] if port_list else 'unknown'

            #         output_dict['flow'][str(flow_index)] = {
            #             'flow_name': f"{port} {stream_name}",
            #             'rx': rx_info,
            #             'tx': tx_info
            #         }
            #         flow_index += 1
            # keep it as it is other keys like port1, status, etc.
            # else:
            #     output_dict["flow"][key] = val

        return output_dict

    def _convert_traffic_stats_aggregate(self, input_dict):
        logger.info(get_myfname)

        ret_ds = {
            'status': input_dict['status']
        }

        for location, port_handle in self.stc.tg_port_handle.items():
            if port_handle not in input_dict:
                continue

            ret_ds[location] = input_dict[port_handle]
            func = self.stc.get_hltapi_name("tg_interface_stats")

            kwargs = {
                "port_handle": port_handle,
                "properties": 'intf_speed'
            }

            msg = "{} {}".format(func, kwargs)
            interface_stats = self.stc.tgen_eval(msg, func, **kwargs)
            logger.info("{}: interface_stats = {}".format(func, interface_stats))

            intf_speed = int(interface_stats['intf_speed'])
            intf_speeds = "{}GE".format(intf_speed//1000)
            ret_ds[location]['aggregate']['tx']['line_speed'] = intf_speeds

            # liu debug
            TEST_STC_INTF_SPEED = os.environ.get('TEST_STC_INTF_SPEED', '0GE')
            if TEST_STC_INTF_SPEED != '0GE':
                ret_ds[location]['aggregate']['tx']['line_speed'] = TEST_STC_INTF_SPEED

            # also include port handle as index
            ret_ds[port_handle] = ret_ds[location]

        return ret_ds


    def _traffic_config_mapping(self, **kwargs):
        log_func(TitleBeforeMapping, get_myfname(), **kwargs)
        kwargs2 = copy.deepcopy(kwargs)

        ##########################################
        #  Mapping function name and parameters
        ##########################################

        fname = 'tg_traffic_config'
        ##########################################
        #  Run Mapped function
        ##########################################
        func = self.stc.get_hltapi_name(fname)
        msg = "{} {}".format(func, kwargs2)
        log_func(TitleAfterMapping, func, **kwargs2)
        ret_ds = self.stc.tgen_eval(msg, func, **kwargs2)
        logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))

        ##########################################
        #  Post Running processing
        ##########################################
        self._check_return_status(ret_ds)

        stream_id = ret_ds.get('stream_id', '')
        if stream_id:
            logger.info('STREAM HANDLE: "{}"'.format(stream_id))
        return ret_ds

    def _merge_list(self, args):
        retval = []
        morecheck = True
        if type(args) != list:
            retval.append(args)
            return retval

        while morecheck:
            morecheck = False
            for arg in args:
                if arg is None:
                    retval.append(arg)
                elif isinstance(arg, list):
                    retval.extend(arg)
                    morecheck = True
                elif isinstance(arg, dict):
                    retval.append(arg)
                    morecheck = True
                else:
                    retval.append(arg)
            if morecheck == True:
                args = retval
                retval = []

        return retval

    def get_is_macmove(self):
        class_path = os.environ.get("PYTEST_CURRENT_TEST", "")
        class_name = ''
        if class_path:
            try:
                class_name = class_path.split("::")[0] + "::" + class_path.split("::")[1]
            except Exception:
                logger.warning("Fail to get class_name from class_path:{}".format(class_path))
        is_mh_macmove = 'test_vxlan_multi_homing' in class_name and 'TestVxlanMacMoveTriggers' in class_name
        return is_mh_macmove

    def get_is_dhcp_relay(self):
        class_path = os.environ.get("PYTEST_CURRENT_TEST", "")
        class_name = ''
        if class_path:
            try:
                class_name = class_path.split("::")[0] + "::" + class_path.split("::")[1]
            except Exception:
                logger.warning("Fail to get class_name from class_path:{}".format(class_path))
        return 'test_vxlan_multi_homing' in class_name and 'TestVxlanDhcpRelay' in class_name

    def toggle_macmove_arp(self, host=None, flag='true', type='all'):
        # In MAC-move scenarios, enable/disable a host's gateway-MAC (ARP/ND)
        # resolution on its IPv4/IPv6 interfaces; otherwise trigger a global ARP
        # refresh. 'flag' turns resolution on ('true') or off ('false').
        is_mh_macmove = self.get_is_macmove()

        if is_mh_macmove and host is not None:
            ipv4if = get_sth().invoke("stc::get %s -children-Ipv4If" % host)
            if ipv4if:
                get_sth().emulation_device_config(mode='modify', handle=host, resolve_gateway_mac=flag)
            ipv6ifs = get_sth().invoke("stc::get %s -children-Ipv6If" % host)
            if ipv6ifs:
                for ipv6if in ipv6ifs.split():
                    get_sth().invoke("stc::config %s -ResolveGatewayMac %s" % (ipv6if, flag))
                    get_sth().invoke("stc::config %s -EnableGatewayLearning %s" % (ipv6if, flag))

        if type == 'all' and not host and not is_mh_macmove and not self.get_is_dhcp_relay():
            # added for these script which needs arp
            try:
                get_sth().arp_control(arp_target='all')
            except Exception as e:
                logger.warning("tge_test_control: ARP failed : {}".format(e))

    def tg_test_control(self, **kwargs):
        log_func(TitleBeforeMapping, get_myfname(), **kwargs)

        ##########################################
        #  Mapping function name and parameters
        ##########################################
        fname = ''
        kwargs2={}
        ret_ds = {}

        action = kwargs.pop('action', 'novalue')
        logger.info("action is {}".format(action))

        if action == 'stop_all_protocols':
            fname =  'tg_stop_devices'
        elif action == 'stop_protocol':
            device_handle = kwargs.get("handle")
            if device_handle:
                host = self._get_device_group_host(device_handle)
                if host != None:
                    self.toggle_macmove_arp(host=host, flag='false')
                    get_sth().invoke("stc::perform ArpNdStopCommand -HandleList %s" % host)
                    ret_ds['status']=1
                    return ret_ds
        elif action == 'start_all_protocols':
            fname = 'tg_start_devices'
            func = self.stc.get_hltapi_name(fname)
            msg = "{} {}".format(func, kwargs2)
            log_func(TitleAfterMapping, func, **kwargs2)
            ret_ds = self.stc.tgen_eval(msg, func, **kwargs2)
            logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))

            # Poll LACP state before sending ARP — no fixed pre-wait.
            # ARP must come after LACP is UP; sending ARP while PortChannel
            # is still down causes the switch to drop frames and miss MAC learning.
            lacp_timeout = 30
            lacp_interval = 5
            elapsed = 0
            # lacp_converged = False
            while elapsed < lacp_timeout:
                lacp_result = self.tg_protocol_info(handle='', mode='aggregate')
                down_handles = [h for h, v in lacp_result.items()
                                if isinstance(v, dict) and v.get('aggregate', {}).get('sessions_down', '0') != '0']
                if not down_handles:
                    # lacp_converged = True
                    break
                tgen_wait(lacp_interval)
                elapsed += lacp_interval
            self.toggle_macmove_arp(host=None, type='all')
            return ret_ds
        elif action == 'start_protocol':
            device_handle = kwargs.get("handle")
            if device_handle:
                fname = 'tg_arp_control'
                host = self._get_device_group_host(device_handle)
                if host != None:
                    self.toggle_macmove_arp(host=host, flag='true')
                    kwargs2['handle']=host
                    kwargs2['arp_target']="device"
            else:
                fname = 'tg_start_devices'
        elif action == 'apply_on_the_fly_changes':
            self.stc.local_stc_tapi_call('stc::apply')
            ret_ds['status']=1
            return ret_ds
        else:
            ret_ds['status']=0
            logger.error("Map error for action - {}".format(action))
            return

        ##########################################
        #  Run Mapped function
        ##########################################
        func = self.stc.get_hltapi_name(fname)
        msg = "{} {}".format(func, kwargs2)
        log_func(TitleAfterMapping, func, **kwargs2)
        ret_ds = self.stc.tgen_eval(msg, func, **kwargs2)
        logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))

        ##########################################
        #  Post Running processing
        ##########################################
        self._check_return_status(ret_ds)

        return ret_ds

    def _traffic_config_create_raw(self, **kwargs):
        log_func(TitleBeforeMapping, get_myfname(), **kwargs)
        kwargs2=copy.deepcopy(kwargs)

        ##########################################
        #  Mapping function name and parameters
        ##########################################
        emulation_src_handle = kwargs2.get("emulation_src_handle")
        emulation_dst_handle = kwargs2.get("emulation_dst_handle")

        if emulation_src_handle is not None:
            kwargs2['port_handle'] = emulation_src_handle
        if emulation_dst_handle is not None:
            kwargs2['dest_port_list'] = emulation_dst_handle

        # for raw stream ignore bidirectional
        bidirectional = kwargs2.get("bidirectional", 0)
        if bidirectional == 1:
            logger.warning("for raw stream, ignore bidirectional option")
            kwargs2['bidirectional']=0

        kwargs2.pop('emulation_src_handle', '')
        kwargs2.pop('emulation_dst_handle', '')
        kwargs2.pop('src_dest_mesh', '')
        kwargs2.pop('circuit_endpoint_type', '')
        kwargs2.pop('track_by', '')
        kwargs2.pop('circuit_type', '')

        ret = self._traffic_config_mapping(**kwargs2)
        # ret ex. {'stream_id': 'streamblock3', 'status': '1', 'stream_id_pylist': ['streamblock3'] }

        return ret

    def _traffic_config_create_bound(self, **kwargs):
        log_func(TitleBeforeMapping, get_myfname(), **kwargs)
        kwargs2=copy.deepcopy(kwargs)

        ##########################################
        #  Mapping function name and parameters
        ##########################################
        emulation_src_handle = kwargs2.get("emulation_src_handle")
        emulation_dst_handle = kwargs2.get("emulation_dst_handle")

        # src
        port_handle = self._get_port_handle_by_device_group_handle(emulation_src_handle)
        if port_handle is not None:
            kwargs2['port_handle'] = port_handle
        # else: keep the existing port_handle already present in kwargs2 (e.g. passed directly by caller)
        srchost = self._get_device_group_host(emulation_src_handle)
        if  srchost != None:
            kwargs2['emulation_src_handle']=srchost

        if kwargs2.get('circuit_endpoint_type') is not None:
            circuit_endpoint_type = kwargs2.pop('circuit_endpoint_type')
            if circuit_endpoint_type in ['ipv4', 'ipv6', 'arp', 'gre']:
                kwargs2['l3_protocol'] = circuit_endpoint_type
            else:
                logger.warning("cannot decide l3_protocol by circuit_endpoint_type - {}".format(circuit_endpoint_type))

        kwargs2.pop('src_dest_mesh', '')
        kwargs2.pop('track_by', '')
        kwargs2.pop('circuit_type', '')

        ret_ds = {}
        ret_ds["stream_id"] = []

        bidirectional = kwargs2.get("bidirectional", 0)

        # will create unidirectional streamblock
        kwargs2["bidirectional"] = 0

        # Clamp rate to Spirent minimum before creating any streamblock (forward or backward)
        if kwargs2.get('rate_percent') is not None:
            rate = float(kwargs2.get('rate_percent'))
            if rate < 0.001:
                logger.warning("rate_percent {:.6f} below Spirent minimum, clamping to 0.001".format(rate))
                kwargs2['rate_percent'] = 0.001
        if kwargs2.get('rate_bps') is not None:
            rate = int(kwargs2.get('rate_bps'))
            if rate < 1:
                logger.warning("rate_bps {} below minimum, clamping to 1".format(rate))
                kwargs2['rate_bps'] = 1

        dst_hosts = []
        for dst_grphandle in utils.make_list(emulation_dst_handle):
            host = self._get_device_group_host(dst_grphandle)
            if host is not None:
                dst_hosts.append(host)
            else:
                logger.warning("skipping None dst host for dst_grphandle={}".format(dst_grphandle))

        # direction: forward
        logger.info("---- Direction: src --> dst")
        if dst_hosts:
            kwargs2['emulation_dst_handle'] = dst_hosts
        else:
            kwargs2.pop('emulation_dst_handle', None)
        ret = self._traffic_config_mapping(**kwargs2)
        if type(ret['stream_id']) == dict:
            for key, value in ret['stream_id'].items():
                if type(value) == list:
                    ret_ds['stream_id'].extend(value)
        else:
            ret_ds['stream_id'].append(ret['stream_id'])

        # direction: backward only when bidirectional is 1
        if bidirectional == 1:
            dst_count = len(utils.make_list(emulation_dst_handle))
            if kwargs2.get('rate_percent') is not None:
                rate = float(kwargs2.get('rate_percent')) / dst_count
                if rate < 0.001:
                    logger.warning("rate_percent {:.6f} below Spirent minimum after dividing by dst_count {}, clamping to 0.001".format(rate, dst_count))
                    rate = 0.001
                kwargs2['rate_percent'] = rate
            if kwargs2.get('rate_bps') is not None:
                rate = kwargs2.get('rate_bps') // dst_count
                if rate < 1:
                    logger.warning("rate_bps {} below minimum after dividing by dst_count {}, clamping to 1".format(rate, dst_count))
                    rate = 1
                kwargs2['rate_bps'] = rate

            for index, dst_grphandle in enumerate(utils.make_list(emulation_dst_handle), start=1):
                logger.info("---- Direction: src <-- dst  No.{}/{}".format(index, dst_count))
                dsthost = self._get_device_group_host(dst_grphandle)
                kwargs2['emulation_src_handle'] = dsthost
                kwargs2['emulation_dst_handle'] = srchost

                port_handle = self._get_port_handle_by_device_group_handle(dst_grphandle)
                if port_handle is not None:
                    kwargs2['port_handle'] = port_handle

                ret = self._traffic_config_mapping(**kwargs2)
                if type(ret['stream_id']) == dict:
                    for key, value in ret['stream_id'].items():
                        if type(value) == list:
                            ret_ds['stream_id'].extend(value)
                else:
                    ret_ds['stream_id'].append(ret['stream_id'])

        ret_ds['status'] = '1'
        return ret_ds

    def _remove_host(self, host: str):
        port_handle = self._get_port_handle_from_cache(host)
        fname = 'tg_emulation_device_config'
        kwargs = {
            "mode": "delete",
            "port_handle": port_handle,
            "handle": host,
        }

        func = self.stc.get_hltapi_name(fname)
        msg = "{} {}".format(func, kwargs)
        log_func("remove host", func, **kwargs)
        ret_ds = self.stc.tgen_eval(msg, func, **kwargs)
        logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))

        self._check_return_status(ret_ds)

        # self._delete_device_group_host(host)
        # self._dump_topologies()

        return ret_ds

    def tg_traffic_config(self, **kwargs):
        global ports_offline
        log_func(TitleBeforeMapping, get_myfname(), **kwargs)
        kwargs2=copy.deepcopy(kwargs)

        ##########################################
        #  Mapping function name and parameters
        ##########################################
        if kwargs2['mode'] is None:
            return

        if self.stc.tg_version == 8.40:
            if kwargs2.get('rate_pps') is not None:
                kwargs2['rate_pps'] = 5

        self.map_field("ethernet_value", "ether_type", kwargs2)
        self.map_field("data_pattern", "custom_pattern", kwargs2)
        self.map_field("icmp_ndp_nam_o_flag", "icmpv6_oflag", kwargs2)
        self.map_field("icmp_ndp_nam_r_flag", "icmpv6_rflag", kwargs2)
        self.map_field("icmp_ndp_nam_s_flag", "icmpv6_sflag", kwargs2)
        self.map_field("data_pattern_mode", None, kwargs2)
        self.map_field("global_stream_control", None, kwargs2)
        self.map_field("global_stream_control_iterations", None, kwargs2)
        self.map_field("vlan_protocol_tag_id", "vlan_tpid", kwargs2)
        if kwargs2.get('vlan_tpid') is not None:
            if len(str(kwargs2['vlan_tpid'])) == 4:
                kwargs2['vlan_tpid'] = int('0x{}'.format(str(kwargs2['vlan_tpid']).lstrip('0x')), 0)
        if kwargs2.get('custom_pattern') is not None:
            kwargs2['custom_pattern'] = kwargs2['custom_pattern'].replace(" ", "")
            kwargs2['disable_signature'] = kwargs2.get('disable_signature', '1')
        if kwargs2.get("l4_protocol") == "icmp" and kwargs2.get("l3_protocol") == "ipv6":
            kwargs2['l4_protocol'] = 'icmpv6'
            self.map_field("icmp_type", "icmpv6_type", kwargs2)
            self.map_field("icmp_code", "icmpv6_code", kwargs2)
            self.map_field("icmp_target_addr", "icmpv6_target_address", kwargs2)
        if kwargs2.get('vlan_id') is not None:
            if kwargs2.get('l2_encap') is None:
                kwargs2['l2_encap'] = 'ethernet_ii_vlan'
            if type(kwargs2.get('vlan_id')) != list:
                x = [kwargs2.get('vlan_id')]
            else:
                x = kwargs2.get('vlan_id')
            if len(x) > 1:
                vlan_list = kwargs2.get('vlan_id')
                kwargs2['vlan_id'] = vlan_list[0]
                kwargs2['vlan_id_outer'] = vlan_list[1]
                if len(x) > 2:
                    kwargs2['vlan_id_other'] = vlan_list[2:]

        for param in ('enable_time_stamp', 'enable_pgid', 'vlan', 'duration'):
            if kwargs2.get(param) is not None:
                kwargs2.pop(param)

        for param in ('udp_src_port_mode', 'udp_dst_port_mode',
                        'tcp_src_port_mode', 'tcp_dst_port_mode'):
            if kwargs2.get(param) == 'incr':
                kwargs2[param] = 'increment'
            if kwargs2.get(param) == 'decr':
                kwargs2[param] = 'decrement'
        if (kwargs2.get('transmit_mode') is not None
                or kwargs2.get('l3_protocol') is not None) and \
                kwargs2.get('length_mode') is None:
            kwargs2['length_mode'] = 'fixed'

        if kwargs2.get('transmit_mode') is not None:
            transmit_mode = kwargs2['transmit_mode']
            if transmit_mode == 'continuous':
                pass
            elif transmit_mode == 'single_burst' or transmit_mode == 'multi_burst':
                kwargs2['burst_loop_count'] = kwargs2.get('pkts_per_burst')
                kwargs2['transmit_mode'] = 'multi_burst'
                kwargs2['pkts_per_burst'] = 1

        if kwargs2.get('port_handle2') is not None and kwargs2.get('bidirectional') is None:
            kwargs2['dest_port_list'] = kwargs2.pop('port_handle2')
        #Disable default ARP on raw streamblocks for macmove case
        if kwargs2.get('track_by') == "endpoint_pair" and kwargs2.get('vlan_id') in [920, 910]:
            kwargs2['resolved_dst_mac_address'] = 0

        if kwargs2.get('high_speed_result_analysis') is not None and \
            kwargs2.get('track_by') is not None:
            attr = kwargs2.get('track_by')
            # TODO: just avoid broken when only 1 track_by parameter comes in.
            #       analyzer_filter to be study.
            if len(utils.make_list(attr)) > 1:
                attr = attr.split()[1]
                kwargs2.pop('track_by')
                kwargs2.pop(analyzer_filter[attr])
        if kwargs2.get('track_by') is not None:
            attr = kwargs2.get('track_by')
            kwargs2.pop('track_by')

        if re.search(r'ip_delay |ip_throughput | ip_reliability |ip_cost |ip_reserved ', ' '.join(kwargs2.keys())):
            delay = kwargs2.get('ip_delay', 0)
            throughput = kwargs2.get('ip_throughput', 0)
            reliability = kwargs2.get('ip_reliability', 0)
            cost = kwargs2.get('ip_cost', 0)
            reserved = kwargs2.get('ip_reserved', 0)

            bin_val = str(delay) + str(throughput) + str(reliability) + str(cost)
            kwargs2['ip_tos_field'] = int(bin_val, 2)
            kwargs2['ip_mbz'] = reserved
            # ignore step,mode,count for now
            for param in ('qos_type_ixn', 'ip_delay', 'ip_delay_mode', 'ip_delay_tracking',
                            'ip_throughput', 'ip_throughput_mode', 'ip_throughput_tracking',
                            'ip_reliability', 'ip_reliability_mode', 'ip_reliability_tracking',
                            'ip_cost', 'ip_cost_mode', 'ip_cost_tracking', 'ip_reserved'):

                kwargs2.pop(param, None)

        if kwargs2.get('mac_dst_mode') is not None:
            if type(kwargs2.get('mac_dst')) == list:
                kwargs2['mac_dst'] = ' '.join(kwargs2['mac_dst'])
                kwargs2.pop('mac_dst_mode', '')

        #disabling high_speed_result_analysis by environment variable: HIGH_SPEED_RESULT_ANALYSIS_DEFAULT=0
        if kwargs2.get('high_speed_result_analysis') is None:
            HIGH_SPEED_RESULT_ANALYSIS_DEFAULT = os.environ.get('HIGH_SPEED_RESULT_ANALYSIS_DEFAULT', '1')
            if HIGH_SPEED_RESULT_ANALYSIS_DEFAULT in ['0', '1']:
                kwargs2['high_speed_result_analysis'] = int(HIGH_SPEED_RESULT_ANALYSIS_DEFAULT)

        #Dependency for ip_src_addr/ipv6_src_addr,setting l3_protocol to ipv4/ipv6 if ip_src_addr/ipv6_src_addr is provided
        if kwargs2.get('ip_src_addr') is not None:
            kwargs2['l3_protocol'] = "ipv4"
        if kwargs2.get('ipv6_src_addr') is not None:
            kwargs2['l3_protocol'] = "ipv6"

        #############################################################################

        ### rate_bps: int value required.
        if kwargs2.get('rate_bps') is not None:
            kwargs2['rate_bps'] = int(kwargs2['rate_bps'])

        mode = kwargs2["mode"]
        if mode == 'create':
            logger.info("Map for mode - {}".format(mode))
            circuit_type = kwargs2.get('circuit_type', 'default')
            if circuit_type == 'raw' or not kwargs2.get('emulation_dst_handle'):
                ret = self._traffic_config_create_raw(**kwargs2)
            else:
                ret = self._traffic_config_create_bound(**kwargs2)

            if ret['status'] != '1':
                return ret

            # TODO: stream_id mapping
            # ret_ds = {
            #     "status" : ret['status'],
            #     "stream_id": self._stream_id_create("", ret['stream_id']).stream_id
            # }

            ret_ds = ret
            logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))

            # disable the streamblocks after creating them.
            self.tg_traffic_config(mode = 'disable', stream_id = ret_ds['stream_id'])

            return ret_ds
        elif mode == 'disable' or mode == 'remove' or mode == 'enable' or mode == 'modify':
            logger.info("Map for mode - {}".format(mode))
            stream_id = kwargs2.get('stream_id', '')
            if type(stream_id) == list:
                stream_id = self._merge_list(stream_id)
                kwargs2['stream_id'] = stream_id
        else:
            logger.error("Map error for mode - {}".format(mode))
            return

        fname = 'tg_traffic_config'

        ##########################################
        #  Run Mapped function
        ##########################################
        func = self.stc.get_hltapi_name(fname)
        msg = "{} {}".format(func, kwargs2)
        log_func(TitleAfterMapping, func, **kwargs2)
        ret_ds = self.stc.tgen_eval(msg, func, **kwargs2)
        logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))

        ##########################################
        #  Post Running processing
        ##########################################
        self._check_return_status(ret_ds)


        stream_id = ret_ds.get('stream_id', '')
        if stream_id:
            logger.info('STREAM HANDLE: "{}"'.format(stream_id))
        # TODO
        # if kwargs.get("emulation_src_handle") is not None or kwargs.get("emulation_dst_handle") is not None:
        #     self.stc.get_emulation_handle_prefixes(ret_ds, **kwargs)

        return ret_ds

    def tg_protocol_info(self, **kwargs):
        log_func(TitleBeforeMapping, get_myfname(), **kwargs)
        ret_ds = {"status": 1}

        # Check LACP state for all member ports that have LACP configured.
        # Uses emulation_lacp_info(action='collect', mode='state') to trigger an explicit
        # state refresh via the HLTAPI abstraction layer.
        # State semantics:
        #   UP       - port is Collecting+Distributing — all STC LAG ports should reach this
        #   EXCHG    - PDU exchange ongoing but not yet selected — transient or failed state
        #   DOWN     - link or LACP session is down — failure
        #   NO_STATE - LACP not yet started or port disabled — failure
        try:
            port_list = get_sth().invoke("stc::get project1 -children-port").split()
            for port in port_list:
                try:
                    port_state = get_sth().invoke("stc::get %s -Online" % port)
                    has_lacp = get_sth().invoke("stc::get %s -children-lacpportconfig" % port)
                    if port_state.lower() != 'true' or not has_lacp:
                        continue
                    attrs = (get_sth().invoke("stc::get %s -Active -LacpState" % has_lacp).split() + ['', ''])[:2]
                    lacp_active, lacp_state_cfg = attrs
                    # Active=FALSE: LAG disabled (mode='delete' maps to 'disable', BLL workaround)
                    # LacpState='': LACP not yet initialized — both cause stcattr error in HLTAPI
                    if lacp_active.lower() != 'true' or not lacp_state_cfg:
                        continue
                    lacp_info = get_sth().emulation_lacp_info(port_handle=port, action='collect', mode='state')
                    if not isinstance(lacp_info, dict) or lacp_info.get('status') == '0':
                        # logger.warning("LACP collect failed on port {} (status=0 / DOWN): {}".format(port, lacp_info))
                        ret_ds[port] = {'aggregate': {'sessions_down': '1'}}
                        continue
                    lacp_state = lacp_info.get('lacp_state', 'NO_STATE')
                    sessions_down = '0' if lacp_state == 'UP' else '1'
                    if sessions_down != '0':
                        logger.warning("LACP abnormal on port {}: LacpState={}".format(port, lacp_state))
                    else:
                        logger.info("LACP on port {}: LacpState={}".format(port, lacp_state))
                    ret_ds[port] = {'aggregate': {'sessions_down': sessions_down}}
                except Exception as e:
                    logger.warning("Failed to check LACP state on port {}: {}".format(port, e))
                    ret_ds[port] = {'aggregate': {'sessions_down': '1'}}
        except Exception as e:
            logger.warning("Failed to check LACP state: {}".format(e))

        logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))

        # this is designed for iteritems() of python2 mapping to items() of python3
        class _Result():
            def __init__(self, value: Dict):
                self.value = value
                return

            def iteritems(self):
                return self.value.items()

            def items(self):
                return self.value.items()

        return _Result(ret_ds)

    def tg_topology_config(self, **kwargs):
        log_func(TitleBeforeMapping, get_myfname(), **kwargs)
        ret_ds = {}

        mode = kwargs.pop('mode', 'create')
        if mode == 'create':
            if kwargs.get("topology_name") is not None:
                topo = self._topology_create(**kwargs)
                ret_ds = copy.deepcopy(topo.kwargs)
                ret_ds["topology_handle"]= topo.topology_handle
                ret_ds["status"]='1'
            elif kwargs.get("topology_handle") is not None:
                topology_handle=kwargs.get("topology_handle")
                topo=self.topologies.get(topology_handle)
                if kwargs.get("device_group_name") is not None:
                    grp=topo.device_group_create(**kwargs)
                    ret_ds = copy.deepcopy(grp.kwargs)
                    ret_ds["device_group_handle"]= grp.device_group_handle
                    ret_ds["status"]='1'
        elif mode == 'destroy':
            if kwargs.get("device_group_handle") is not None:
                device_group_handle=kwargs.get("device_group_handle")
                self._device_group_destroy(device_group_handle)
            elif kwargs.get("topology_handle") is not None:
                topology_handle=kwargs.get("topology_handle")
                self._topology_destroy(topology_handle)

            ret_ds["status"]='1'

        logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))

        # debug only
        self._dump_topologies()

        return ret_ds

    def tg_interface_config(self, **kwargs):
        log_func(TitleBeforeMapping, get_myfname(), **kwargs)

        ##########################################
        #  Mapping function name and parameters
        ##########################################
        kwargs_protocol_handle = kwargs.get('protocol_handle')
        port_handle:str
        ret_handle:str

        mode = kwargs.get('mode', 'config')

        if mode == 'destroy':
            # called from TGStc's clean_all
            func = self.stc.get_hltapi_name('tg_emulation_device_config')
            kwargs2 = copy.deepcopy(kwargs)
            kwargs2['mode']='delete'
            host = kwargs2.get('handle')
            if host is not None:
                args = self._get_host_kwargs(host)
                if type(args) == dict and args.get('mapto') is not None:
                    kwargs2['handle'] = args['mapto']

        elif mode == 'modify':
            # default
            kwargs2 = copy.deepcopy(kwargs)
            func = self.stc.get_hltapi_name('tg_emulation_device_config')

            if kwargs2.get('port_handle') is not None:
                port_handle = kwargs2['port_handle']

                # might provide port list than port_hanlde list
                real_port_handle = []
                for port in port_handle:
                    ph = self.stc.get_port_handle(port)
                    if ph is not None:
                        real_port_handle.append(ph)
                if len(real_port_handle) > 0:
                    kwargs2['port_handle'] = real_port_handle

                func = self.stc.get_hltapi_name('tg_interface_config')

            if kwargs2.get('fcoe_priority_groups') is not None:
                fcoe_priority_groups = kwargs2['fcoe_priority_groups']
                #kwargs2['pfc_priority_pause_quanta'] = fcoe_priority_groups.split()
                #kwargs2['pfc_priority_enable'] = ['true','true','true','true','true','true','true','true']
                kwargs3 = {}
                fcoe_priority_groups = kwargs2['fcoe_priority_groups']
                pfc_list = fcoe_priority_groups.split()
                for index in range(0,len(pfc_list)):
                    if pfc_list[index] != '0':
                        kwargs3['priority' + str(index)] = 1
                # if enable priority must configure pfc_negotiate_by_dcbx =0 firstly
                kwargs2['pfc_negotiate_by_dcbx'] = 0

                kwargs2.pop('fcoe_priority_groups', '')
                kwargs2.pop('fcoe_priority_group_size', '')
                kwargs2.pop('fcoe_flow_control_type', '')
                kwargs2.pop('intf_mode', '')
                kwargs2.pop('fcoe_support_data_center_mode', '')

                # pfc priority must be configured after pfc_negotiate_by_dcbx=0 is configured, so these steps twice.
                msg = "{} {}".format(func, kwargs2)
                log_func(TitleAfterMapping, func, **kwargs2)
                ret_ds2 = self.stc.tgen_eval(msg, func, **kwargs2)
                logger.info("{}: ret_ds2 = {}".format(get_myfname(), ret_ds2))
                self._check_return_status(ret_ds2)
                for k in kwargs3.keys():
                    kwargs2[k] = kwargs3[k]

            op_mode = kwargs.get('op_mode')
            if op_mode is not None:
                func3 = self.stc.get_hltapi_name('tg_interface_control')
                kwargs3 = {
                        "port_handle": kwargs2['port_handle'],
                        "mode": "restore_link"
                    }
                kwargs2.pop('op_mode', None)
                if op_mode == 'normal':
                    kwargs2['data_path_mode'] = 'normal'
                elif op_mode == 'loopback':
                    kwargs2['data_path_mode'] = 'local_loopback'
                elif op_mode == 'monitor':
                    kwargs2['data_path_mode'] = 'line_monitor'
                elif op_mode == 'sim_disconnect':
                    kwargs3['mode'] = 'break_link'
                else:
                    logger.warning("not support op_mode - {}".format(op_mode))

                msg = "{} {}".format(func3, kwargs3)
                log_func(TitleAfterMapping, func3, **kwargs3)
                ret_ds = self.stc.tgen_eval(msg, func3, **kwargs3)
                logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))
                self._check_return_status(ret_ds)
                return ret_ds

            # other simple mappings
            # self.map_field('ignore_link', 'ignore_link_status', kwargs2)
            kwargs2.pop('ignore_link', '')

        else:
            logger.info("processing mode: {} as config".format(mode))
            kwargs["mode"] = "config"

            #
            # protocol_handle is a factor to decide create or modify
            #
            if kwargs_protocol_handle is None:
                # No protocol_handle: this is a direct port interface config
                config_action = 'port'
                func = self.stc.get_hltapi_name('tg_interface_config')
                kwargs2 = copy.deepcopy(kwargs)
            elif "device_group_handle" in kwargs_protocol_handle:
                config_action = 'create'

                port_handle = self._get_port_handle_by_device_group_handle(kwargs_protocol_handle)
                func = self.stc.get_hltapi_name('tg_emulation_device_config')
                kwargs2 = {
                    "mode": "create",
                    "port_handle": port_handle,
                    "encapsulation": "ethernet_ii"
                }
                # Map device_group_multiplier to STC count so the correct number of
                # Ethernet devices (handles) are created (e.g. 1000 for scaled MAC test).
                multiplier = self._get_device_group_multiplier(kwargs_protocol_handle)
                if multiplier and int(multiplier) > 1:
                    kwargs2['count'] = int(multiplier)
                    logger.info("device_group_multiplier={} -> count={} for device_group_handle={}".format(
                        multiplier, kwargs2['count'], kwargs_protocol_handle))
                pick_field(kwargs2, "mac_addr", kwargs, "src_mac_addr")
                pick_field(kwargs2, "mac_addr_step", kwargs, "src_mac_addr_step")
                pick_field(kwargs2, "vlan_id", kwargs, "vlan_id")
                pick_field(kwargs2, "vlan_id_step", kwargs, "vlan_id_step")
                pick_field(kwargs2, "vlan_id_count", kwargs, "vlan_id_count")
                if kwargs2.get("vlan_id") is not None:
                    kwargs2["encapsulation"]="ethernet_ii_vlan"

                ret_handle = "ethernet_handle"

            else:
                config_action = 'modify'
                # recreate the host
                # now the kwargs_protocol_handle is like hostX, for example host35
                host_kwargs = self._get_host_kwargs(kwargs_protocol_handle)
                logger.info("host={}, kwargs = {}".format(kwargs_protocol_handle, host_kwargs))
                kwargs2 = copy.deepcopy(host_kwargs)

                # Remove the hostX first
                self._remove_host(kwargs_protocol_handle)
                kwargs2.pop('handle', '')
                device_group_handle = kwargs2.pop('device_group_handle', '')

                func = self.stc.get_hltapi_name('tg_emulation_device_config')

                if kwargs.get("ipv6_gateway") is not None:
                    kwargs2["ip_version"] = "ipv6"
                    pick_field(kwargs2, "gateway_ipv6_addr", kwargs, "ipv6_gateway")
                    pick_field(kwargs2, "gateway_ipv6_addr_step", kwargs, "ipv6_gateway_step")
                    pick_field(kwargs2, "intf_ipv6_addr", kwargs, "ipv6_intf_addr")
                    pick_field(kwargs2, "intf_ipv6_addr_step", kwargs, "ipv6_intf_addr_step")
                    ret_handle = "ipv6_handle"
                else:
                    kwargs2["ip_version"] = "ipv4"
                    pick_field(kwargs2, "gateway_ip_addr", kwargs, "gateway")
                    pick_field(kwargs2, "gateway_ip_addr_step", kwargs, "gateway_step")
                    pick_field(kwargs2, "intf_ip_addr", kwargs, "intf_ip_addr")
                    pick_field(kwargs2, "intf_ip_addr_step", kwargs, "intf_ip_addr_step")
                    ret_handle = "ipv4_handle"


        ##########################################
        #  Run Mapped function
        ##########################################
        msg = "{} {}".format(func, kwargs2)
        log_func(TitleAfterMapping, func, **kwargs2)
        ret_ds = self.stc.tgen_eval(msg, func, **kwargs2)
        logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))

        ##########################################
        #  Post Running processing
        ##########################################
        self._check_return_status(ret_ds)


        if kwargs.get('enable_ping_response') is not None and kwargs.get('netmask') is not None:
            ret_val = self.stc.tg_interface_handle(ret_ds)
            prefix_len = IPAddress(kwargs.get('netmask', '255.255.255.0')).netmask_bits()
            for device in utils.make_list(ret_val['handle']):
                self.stc.local_stc_tapi_call(
                    'stc::config ' + device + ' -enablepingresponse ' + str(kwargs['enable_ping_response']))
                ipv4if = self.stc.local_stc_tapi_call('stc::get ' + device + ' -children-ipv4if')
                self.stc.local_stc_tapi_call('stc::config ' + ipv4if + ' -PrefixLength ' + str(prefix_len))
            get_sth().invoke("stc::apply")

        if re.search('cleanup_session', func):
            if re.search('sth', func):
                get_sth().invoke("stc::apply")
            tgen_wait(1)
        elif kwargs.get('mode') == 'destroy':
            tgen_wait(2)
            kwargs_port_handle = kwargs.get('port_handle')
            kwargs_handle = kwargs.get('handle')
            self.stc.manage_interface_config_handles(kwargs.get('mode'), kwargs_port_handle, kwargs_handle)
            mapped_handle = kwargs2.get('handle')
            if mapped_handle and mapped_handle != kwargs_handle:
                self.stc.manage_interface_config_handles(kwargs.get('mode'), kwargs_port_handle, mapped_handle)
        elif kwargs.get('mode') == 'config':
            ret_ds = self.stc.tg_interface_handle(ret_ds)
            # handle protocol_hanlde is None
            if config_action == 'port':
                # direct port-handle interface config: just track the handle
                self.stc.manage_interface_config_handles(
                    kwargs.get('mode'), kwargs2.get('port_handle'), ret_ds['handle'])
            elif config_action == 'create':
                ret_ds[ret_handle]=ret_ds['handle']
                self.stc.manage_interface_config_handles(kwargs.get('mode'), kwargs2['port_handle'], ret_ds['handle'])
                kwargs2['device_group_handle'] = kwargs_protocol_handle
                self._add_device_group_host(kwargs_protocol_handle, ret_ds[ret_handle], kwargs2)
            else:
                ret_ds[ret_handle]=ret_ds['handle']
                self.stc.manage_interface_config_handles(kwargs.get('mode'), kwargs2['port_handle'], ret_ds['handle'])
                kwargs2['device_group_handle'] = device_group_handle
                self._add_device_group_host(device_group_handle, ret_ds[ret_handle], kwargs2)
                self._update_host_kwargs(kwargs_protocol_handle, mapto=ret_ds[ret_handle])
                logger.info("{} mapto ==> {}".format(kwargs_protocol_handle, ret_handle))
                self._dump_topologies()

        elif kwargs.get('mode') == 'modify':
            tgen_wait(2)
            self.stc.tg_topology_test_control(action='apply_on_the_fly_changes', skip_wait=True)
        else:
            ret_ds = self.stc.tg_interface_handle(ret_ds)

        logger.info("ret_ds adjust = {}".format(ret_ds))
        return ret_ds

    def tg_convert_porthandle_to_vport(self, **kwargs):
        log_func(TitleBeforeMapping, get_myfname(), **kwargs)

        ##########################################
        #  Mapping function name and parameters
        ##########################################
        ret_ds = {}
        port_handle = kwargs.get('port_handle')
        if port_handle is not None:
            ret_ds = {'handle': port_handle}
        return ret_ds

    def tg_convert_vport_to_porthandle(self, **kwargs):
        log_func(TitleBeforeMapping, get_myfname(), **kwargs)

        ##########################################
        #  Mapping function name and parameters
        ##########################################
        ret_ds = {'status': '0'}
        vport = kwargs.get('vport')
        if vport is not None:
            last_part = vport.split('-')[-1]
            ret_ds['handle'] = last_part
            ret_ds['status'] = '1'

        logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))
        return ret_ds

    def tg_emulation_lag_config(self, **kwargs):
        log_func(TitleBeforeMapping, get_myfname(), **kwargs)
        self.map_field('lacp_actor_system_id', 'actor_system_id', kwargs)
        self.map_field('lacp_send_marker_req_on_lag_change', None, kwargs)
        ##########################################
        #  Mapping function name and parameters
        ##########################################
        fname = ''

        kwargs.pop('active', '')
        if kwargs.get('protocol_type') is not None:
            kwargs['protocol'] = kwargs.pop('protocol_type')
            kwargs['protocol'] = 'lacp'

        # mode: stc support create | enable | disable | modify | delete
        mode = kwargs.get('mode', 'aggregate')
        if mode == 'delete':
            # workaround: bll issue -
            #  RuntimeError in perform: Lost network connection to the server; please reconnect again.
            kwargs['mode'] = 'disable'
        else:
            pass
        actor_key = None
        if mode == 'create':
            actor_key = kwargs.get('lacp_actor_key', 1)
        fname = 'tg_emulation_lag_config'

        ##########################################
        #  Run Mapped function
        ##########################################
        func = self.stc.get_hltapi_name(fname)
        msg = "{} {}".format(func, kwargs)
        log_func(TitleAfterMapping, func, **kwargs)
        ret_ds = self.stc.tgen_eval(msg, func, **kwargs)
        logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))

        ##########################################
        #  Post Running processing
        ##########################################
        self._check_return_status(ret_ds)
        # config lag port to use rate_based
        lag_handle = ret_ds.get('lag_handle')
        if lag_handle:
            logger.info("Change Lag port to use rate_based")
            self.tg_interface_config(mode='modify', port_handle=lag_handle, scheduling_mode = 'rate_based')
            lag_obj = get_sth().invoke("stc::get %s -children-lag" % lag_handle)
            if lag_obj:
                get_sth().invoke("stc::config %s -L2HashOption 0" % lag_obj)
                get_sth().invoke("stc::config %s -L3HashOption 0" % lag_obj)
                # Set LACP actor key after LAG port creation.
                # ActorKey lives on LacpPortConfig (per member port).
                # Get member ports via PortSetMember-targets, then config each LacpPortConfig.
                if actor_key is not None:
                    member_ports = get_sth().invoke("stc::get %s -PortSetMember-targets" % lag_obj).split()
                    for port in member_ports:
                        lacp_port_cfg = get_sth().invoke("stc::get %s -children-lacpportconfig" % port)
                        if lacp_port_cfg:
                            logger.info("Setting LACP actor key to {} on port {} config {}".format(actor_key, port, lacp_port_cfg))
                            get_sth().invoke("stc::config %s -ActorKey %s" % (lacp_port_cfg, actor_key))
        else:
            logger.error("Fail to create lag port.")

        return ret_ds

    def tg_traffic_control(self, **kwargs):
        log_func(TitleBeforeMapping, get_myfname(), **kwargs)

        ##########################################
        #  Mapping function name and parameters
        ##########################################
        fname = ''
        ret_ds={}

        self.map_field("max_wait_timer", None, kwargs)
        if kwargs.get('db_file') is None:
            kwargs['db_file'] = 0

        # stc support: run|stop|reset|destroy|clear_stats|poll

        if kwargs.get('stream_handle') is not None:
            stream_handle = kwargs['stream_handle']
            if type(stream_handle) == list:
                kwargs['stream_handle'] = self._merge_list(stream_handle)

        action = kwargs.get('action', 'config')
        if action == 'regenerate':
            kwargs['action'] = 'clear_stats'
        elif action == 'apply':
            try:
                self.stc.local_stc_tapi_call('stc::apply')
            except Exception as err:
                # TODO: workaround for issue: Oversubscription detected
                # The reason is that we cannot get string like "Oversubscription detected" here
                logger.warning("{}: apply failed - {}".format(get_myfname(), str(err)))

            ret_ds['status']=1
            return ret_ds
        elif action == 'stop':
            kwargs.pop('stream_handle', '')
            kwargs['port_handle'] = 'all'
        elif action == 'run':
            # Auto-enable stream handles that are disabled before running
            stream_handle = kwargs.get('stream_handle')
            if stream_handle is not None:
                handles = self._merge_list(utils.make_list(stream_handle))
                for handle in handles:
                    try:
                        if get_sth().invoke("stc::get {} -Active".format(handle)).lower() == 'false':
                            logger.info("Auto-enabling disabled stream before run: {}".format(handle))
                            get_sth().traffic_config(mode='enable', stream_id=handle)
                    except Exception as e:
                        logger.warning("Failed to check/enable stream {}: {}".format(handle, str(e)))
        else:
            # stop or reset, keep the same
            pass

        fname = 'tg_traffic_control'

        ##########################################
        #  Run Mapped function
        ##########################################
        func = self.stc.get_hltapi_name(fname)
        msg = "{} {}".format(func, kwargs)
        log_func(TitleAfterMapping, func, **kwargs)
        ret_ds = self.stc.tgen_eval(msg, func, **kwargs)
        logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))

        ##########################################
        #  Post Running processing
        ##########################################
        self._check_return_status(ret_ds)

        return ret_ds

    def tg_traffic_stats(self, **kwargs):
        log_func(TitleBeforeMapping, get_myfname(), **kwargs)
        #time.sleep(30)
        ##########################################
        #  Mapping function name and parameters
        ##########################################
        fname = ''
        ret_ds={}
        conv_dict={}
        streams = kwargs.get('streams')
        if streams is not None:
            if type(streams) == list:
                kwargs['streams'] = self._merge_list(streams)

        mode = kwargs.get('mode', 'aggregate')
        if mode == 'traffic_item':
            kwargs['mode'] = 'streams'
        elif mode == 'streams':
            pass  # pass mode='streams' directly to STC
        elif mode == 'flow':
            kwargs['mode'] = 'detailed_streams'
        elif mode == 'aggregate':
            kwargs['mode'] = 'aggregate'
            # kwargs['properties'] = 'intf_speed'
            if kwargs.get('port_handle') is None:
                kwargs['port_handle'] = self.stc.get_port_handle_list()
        else:
            ret_ds['status'] = 0
            return ret_ds

        kwargs.pop('csv_path', '')
        kwargs['scale_mode'] = '1'

        fname = 'tg_traffic_stats'

        ##########################################
        #  Run Mapped function
        ##########################################
        func = self.stc.get_hltapi_name(fname)
        msg = "{} {}".format(func, kwargs)
        log_func(TitleAfterMapping, func, **kwargs)
        ret_ds = self.stc.tgen_eval(msg, func, **kwargs)
        # debug info not summited
        logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))
        self._check_return_status(ret_ds)
        ##########################################
        #  Post Running processing
        ##########################################
        if mode == 'traffic_item':
            conv_dict = self._convert_traffic_stats_ret(ret_ds, streams)
        elif mode == 'streams':
            # Wrap each port's 'stream' sub-dict in _ListKeyDict so that callers
            # (tgen_utils._fetch_stats / get_traffic_stats) can index it with a
            # list of stream handles and get aggregated counts instead of crashing
            # with 'TypeError: unhashable type: list'.
            conv_dict = ret_ds
            for port_val in conv_dict.values():
                if isinstance(port_val, dict) and 'stream' in port_val:
                    port_val['stream'] = _ListKeyDict(port_val['stream'])
        elif mode == 'flow':
            conv_dict = self._convert_flow_traffic_stat(ret_ds)
        elif mode == 'aggregate':
            conv_dict = self._convert_traffic_stats_aggregate(ret_ds)
        else:
            ret_ds['status']=0
            return ret_ds

        return conv_dict

    def tg_emulation_dhcp_server_config(self, **kwargs0):
        log_func(TitleBeforeMapping, get_myfname(), **kwargs0)
        kwargs = copy.deepcopy(kwargs0)

        ##########################################
        #  Mapping function name and parameters
        ##########################################
        fname = ''
        ret_ds={}

        self.map_field('pool_count', None, kwargs)
        self.map_field("ipaddress_pool_prefix_length", 'prefix_pool_length', kwargs)
        self.map_field('ipaddress_pool_step', 'addr_pool_step', kwargs)
        self.map_field('subnet_addr_assign', None, kwargs)
        self.map_field("subnet", "assign_strategy", kwargs)
        self.map_field('protocol_name', 'host_name', kwargs)
        self.map_field('dhcp_range_renew_timer', None, kwargs)
        self.map_field('mac_mtu', None, kwargs)

        # stc: create|enable|modify|activate|reset
        mode = kwargs.get('mode', 'novalue')
        logger.info("mode = {}".format(mode))
        if mode == 'reset':
            kwargs.pop('port_handle', '')
        elif mode == 'create':
            kwargs_handle = kwargs.get('handle')
            port_handle = self._get_port_handle_by_topology_handle(kwargs_handle)
            if port_handle is None:
                ret_ds['status'] = 0
                return ret_ds

            if kwargs.get('encapsulation') is None and kwargs.get('vlan_id') is not None:
                kwargs['encapsulation'] = 'ETHERNET_II_VLAN'

            kwargs['port_handle'] = port_handle
            kwargs.pop('handle')
        elif mode == 'enable':
            pass
        elif mode == 'modify':
            pass
        elif mode == 'activate':
            pass
        else:
            logger.error("not support mode - {}".format(mode))
            ret_ds['status']=0
            return ret_ds
        host_name = kwargs.get('host_name')
        #workaround for l2 dhcp server, will remove it after confirm with cusomter.
        if host_name and "l2" in host_name:
            kwargs['assign_strategy'] = "gateway"
        fname = 'tg_emulation_dhcp_server_config'

        ##########################################
        #  Run Mapped function
        ##########################################
        func = self.stc.get_hltapi_name(fname)
        msg = "{} {}".format(func, kwargs)
        log_func(TitleAfterMapping, func, **kwargs)
        ret_ds = self.stc.tgen_eval(msg, func, **kwargs)
        logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))

        ##########################################
        #  Post Running processing
        ##########################################
        self._check_return_status(ret_ds)

        if ret_ds.get('handle') is None:
            ret_ds['status'] = 0
            return ret_ds

        if ret_ds['handle'].get('dhcp_handle') is None:
            ret_ds['status'] = 0
            return ret_ds

        ip_version = kwargs.get('ip_version', '4')
        if ip_version == '4':
            ret_ds['dhcpv4server_handle'] = ret_ds['handle']['dhcp_handle']
        else:
            ret_ds['dhcpv6server_handle'] = ret_ds['handle']['dhcp_handle']

        pool_count = int(kwargs0.get('pool_count', 1))
        ipaddress_pool = kwargs0.get('ipaddress_pool')
        # Normalize a single ipaddress_pool string into a list so callers can pass
        # either form (e.g. ipaddress_pool='1.1.1.3' vs ['1.1.1.3', ...]).
        if isinstance(ipaddress_pool, str):
            ipaddress_pool = [ipaddress_pool]
        if not isinstance(ipaddress_pool, list):
            logger.error("pool_count ={} while ipaddress_pool is not a list".format(pool_count))
            ret_ds['status'] = 0
            return ret_ds
        if len(ipaddress_pool) != pool_count:
            logger.warning("pool_count ={} while size of ipaddress_pool is {}".format(pool_count, len(ipaddress_pool)))
            pool_count = len(ipaddress_pool)

        if pool_count > 1:
            ipaddress_count = kwargs0.get('ipaddress_count', 65536)

            ##########################################
            #  Enable custom poll
            ##########################################
            args = {
                "mode": 'modify',
                "handle": ret_ds['handle']['dhcp_handle'],
                "enable_custom_pool": 'true',
            }
            msg = "{} {}".format(func, args)
            log_func(TitleDhcpPollEnableCustomer, func, **args)
            ret_ds2 = self.stc.tgen_eval(msg, func, **args)
            logger.info("ret_ds2 = {}".format(ret_ds2))
            self._check_return_status(ret_ds2)

            ##########################################
            #  Create Relay Agent One by One
            ##########################################
            func = self.stc.get_hltapi_name("tg_emulation_dhcp_server_relay_agent_config")
            for i in range (0, pool_count):
                args = {
                    "mode":'create',
                    "handle": ret_ds['handle']['dhcp_handle'],
                    "relay_agent_ipaddress_pool":ipaddress_pool[i],
                    "relay_agent_pool_count":1,
                    "relay_agent_ipaddress_count": ipaddress_count
                }
                msg = "{} {}".format(func, args)
                log_func(TitleDhcpPoolServerRelay, func, **args)
                ret_ds3 = self.stc.tgen_eval(msg, func, **args)
                logger.info("ret_ds3 = {}".format(ret_ds3))
                self._check_return_status(ret_ds3)
        # For TestVxlanDhcpRelay: force ResolveGatewayMac=FALSE on every created server.
        # set it explicitly here so no server proactively ARPs/seeds the DUT for its (shared) IP at device start.
        if mode == 'create' and self.get_is_dhcp_relay() and ret_ds.get('handle', {}).get('dhcp_handle'):
            try:
                host = ret_ds['handle']['dhcp_handle']
                for ipv4if in (get_sth().invoke("stc::get %s -children-Ipv4If" % host) or "").split():
                    get_sth().invoke("stc::config %s -ResolveGatewayMac FALSE" % ipv4if)
            except Exception as e:
                logger.warning("force ResolveGatewayMac FALSE failed for {}: {}".format(host, e))
        return ret_ds

    def tg_emulation_dhcp_group_config(self, **kwargs0):
        log_func(TitleBeforeMapping, get_myfname(), **kwargs0)
        kwargs = copy.deepcopy(kwargs0)

        ##########################################
        #  Mapping function name and parameters
        ##########################################
        fname = ''
        ret_ds={}

        self.map_field('protocol_name', 'host_name', kwargs)
        self.map_field('dhcp_range_renew_timer', None, kwargs)
        self.map_field('mac_mtu', None, kwargs)
        if kwargs.get('dhcp_range_ip_type') == 'ipv4':
            kwargs['dhcp_range_ip_type'] = '4'
        elif kwargs.get('dhcp_range_ip_type') == 'ipv6':
            kwargs['dhcp_range_ip_type'] = '6'
        else:
            kwargs['dhcp_range_ip_type'] = '4'

        # stc: create|modify|enable|activate|reset
        mode = kwargs.get('mode', 'novalue')
        logger.info("mode = {}".format(mode))
        if mode == 'reset':
            kwargs.pop('port_handle', '')
        elif mode == 'create':
            kwargs_handle = kwargs.get('handle')

            port_handle = self._get_port_handle_by_topology_handle(kwargs_handle)
            if port_handle is None:
                ret_ds['status'] = 0
                return ret_ds

            ##########################################
            #  Create DHCP Client
            ##########################################
            dhcp_group_handle = self._get_dhcp_group_handle_by_topology_handle(kwargs_handle)
            if dhcp_group_handle is None:
                func_dhcp_config = self.stc.get_hltapi_name("tg_emulation_dhcp_config")
                args = {
                    "mode": 'create',
                    "port_handle": port_handle,
                    "ip_version": kwargs['dhcp_range_ip_type'],
                }
                msg = "{} {}".format(func_dhcp_config, args)
                log_func(TitleDhcpClientCreate, func_dhcp_config, **args)
                ret_ds2 = self.stc.tgen_eval(msg, func_dhcp_config, **args)
                logger.info("ret_ds2 = {}".format(ret_ds2))
                self._check_return_status(ret_ds2)

                dhcp_group_handle = ret_ds2.get('handles')
                self._set_dhcp_group_handle(kwargs_handle, dhcp_group_handle)

            if kwargs.get('encap') is None and kwargs.get('vlan_id') is not None:
                kwargs['encap'] = 'ethernet_ii_vlan'

            kwargs['handle'] = dhcp_group_handle
        elif mode == 'enable':
            pass
        elif mode == 'modify':
            pass
        elif mode == 'activate':
            pass
        else:
            logger.error("not support mode - {}".format(mode))
            ret_ds['status']=0
            return ret_ds


        fname = 'tg_emulation_dhcp_group_config'

        ##########################################
        #  Run Mapped function
        ##########################################
        func = self.stc.get_hltapi_name(fname)
        msg = "{} {}".format(func, kwargs)
        log_func(TitleAfterMapping, func, **kwargs)
        ret_ds = self.stc.tgen_eval(msg, func, **kwargs)
        logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))

        ##########################################
        #  Post Running processing
        ##########################################
        self._check_return_status(ret_ds)

        dhcp_range_ip_type = kwargs.get('dhcp_range_ip_type', '4')
        if dhcp_range_ip_type == '4':
            # ex. {'status': '1', 'handles': 'dhcpv4blockconfig1', 'handle': 'host2'}
            ret_ds['dhcpv4client_handle'] = ret_ds['handles']
        else:
            # ex. {'status': '1', 'port_handle': 'port1', 'dhcpv6_handle': 'host2'}
            ret_ds['dhcpv6client_handle'] = ret_ds['dhcpv6_handle']

        return ret_ds

    def tg_emulation_dhcp_control(self, **kwargs0):
        log_func(TitleBeforeMapping, get_myfname(), **kwargs0)
        kwargs = copy.deepcopy(kwargs0)

        ##########################################
        #  Mapping function name and parameters
        ##########################################
        fname = ''
        ret_ds={}

        action = kwargs.get('action', 'novalue')
        logger.info("action = {}".format(action))

        fname = 'tg_emulation_dhcp_control'

        ##########################################
        #  Run Mapped function
        ##########################################
        func = self.stc.get_hltapi_name(fname)
        msg = "{} {}".format(func, kwargs)
        log_func(TitleAfterMapping, func, **kwargs)
        ret_ds = self.stc.tgen_eval(msg, func, **kwargs)
        logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))

        ##########################################
        #  Post Running processing
        ##########################################
        self._check_return_status(ret_ds)

        return ret_ds

    def tg_arp_dhcp_server(self, **kwargs0):
        # native/routed only. The tested server sits on an interface With ResolveGatewayMac FALSE
        # Turn resolve back ON for THIS, SONIC DUT does not send arp actively
        log_func(TitleBeforeMapping, get_myfname(), **kwargs0)
        kwargs = copy.deepcopy(kwargs0)
        ret_ds = {'status': '1'}

        dhcp_handle = kwargs.get('dhcp_handle') or kwargs.get('handle')
        if not dhcp_handle:
            logger.warning("tg_arp_dhcp_server: need dhcp_handle")
            ret_ds['status'] = '0'
            return ret_ds

        try:
            ipv4ifs = get_sth().invoke("stc::get %s -children-Ipv4If" % dhcp_handle)
            for ipv4if in (ipv4ifs or "").split():
                get_sth().invoke("stc::config %s -ResolveGatewayMac TRUE" % ipv4if)
            get_sth().invoke("stc::apply")
            get_sth().invoke("stc::perform ArpNdStart -HandleList %s" % dhcp_handle)
        except Exception as e:
            logger.warning("tg_arp_dhcp_server({}) failed: {}".format(dhcp_handle, e))
            ret_ds['status'] = '0'
        return ret_ds

    def tg_set_dhcp_server(self, **kwargs0):
        # Change a DHCP server host's interface IP (Ipv4If.Address). Used by
        # TestVxlanDhcpRelay to move standby servers off the shared IP so a single
        # owner is on the wire, avoiding EVPN MAC-moves that misdeliver the relayed REQUEST
        log_func(TitleBeforeMapping, get_myfname(), **kwargs0)
        kwargs = copy.deepcopy(kwargs0)
        ret_ds = {'status': '1'}

        dhcp_handle = kwargs.get('dhcp_handle') or kwargs.get('handle')
        ip_address = kwargs.get('ip_address')

        if not dhcp_handle or not ip_address:
            logger.warning("tg_set_dhcp_server: need both dhcp_handle and ip_address")
            ret_ds['status'] = '0'
            return ret_ds

        try:
            ipv4ifs = get_sth().invoke("stc::get %s -children-Ipv4If" % dhcp_handle)
            for ipv4if in (ipv4ifs or "").split():
                # keep ResolveGatewayMac FALSE: changing -Address otherwise resets it to
                # the default TRUE, which would let the (shifted) standby ARP/seed again
                get_sth().invoke("stc::config %s -Address %s -ResolveGatewayMac FALSE" % (ipv4if, ip_address))
            get_sth().invoke("stc::apply")
        except Exception as e:
            logger.warning("tg_set_dhcp_server({}, ip_address={}) failed: {}".format(dhcp_handle, ip_address, e))
            ret_ds['status'] = '0'
        return ret_ds

    def tg_emulation_dhcp_server_control(self, **kwargs0):
        log_func(TitleBeforeMapping, get_myfname(), **kwargs0)
        kwargs = copy.deepcopy(kwargs0)

        ##########################################
        #  Mapping function name and parameters
        ##########################################
        fname = ''
        ret_ds={}

        action = kwargs.get('action', 'novalue')
        logger.info("action = {}".format(action))

        if action == 'collect':
            kwargs['action'] = 'connect'

        fname = 'tg_emulation_dhcp_server_control'

        ##########################################
        #  Run Mapped function
        ##########################################
        func = self.stc.get_hltapi_name(fname)
        msg = "{} {}".format(func, kwargs)
        log_func(TitleAfterMapping, func, **kwargs)
        ret_ds = self.stc.tgen_eval(msg, func, **kwargs)
        logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))

        ##########################################
        #  Post Running processing
        ##########################################
        self._check_return_status(ret_ds)

        return ret_ds

    def tg_emulation_dhcp_stats(self, **kwargs0):
        log_func(TitleBeforeMapping, get_myfname(), **kwargs0)
        kwargs = copy.deepcopy(kwargs0)

        ##########################################
        #  Mapping function name and parameters
        ##########################################
        fname = ''
        ret_ds={}

        mode = kwargs.get('mode', 'novalue')
        logger.info("mode = {}".format(mode))
        if mode == 'session':
            kwargs['mode'] = 'detailed_session'

        fname = 'tg_emulation_dhcp_stats'

        ##########################################
        #  Run Mapped function
        ##########################################
        func = self.stc.get_hltapi_name(fname)
        msg = "{} {}".format(func, kwargs)
        log_func(TitleAfterMapping, func, **kwargs)
        ret_ds = self.stc.tgen_eval(msg, func, **kwargs)
        logger.info("{}: ret_ds = {}".format(get_myfname(), ret_ds))

        ##########################################
        #  Post Running processing
        ##########################################
        self._check_return_status(ret_ds)

        ret_ds = self._convert_dhcp_stats(ret_ds)
        logger.info("after convert ret_ds = {}".format(ret_ds))

        return ret_ds

def get_mapfuncs() -> TGStcMapFuncs:
    global mapfuncs
    return mapfuncs
