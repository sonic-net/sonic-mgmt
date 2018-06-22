from infra import *


class DTelWatchlistEntry(object):
    def __init__(self,
                 watchlist=None,
                 priority=10,
                 ether_type=None,
                 ether_type_mask=None,
                 src_ip=None,
                 src_ip_mask=None,
                 dst_ip=None,
                 dst_ip_mask=None,
                 ip_proto=None,
                 ip_proto_mask=None,
                 dscp=None,
                 dscp_mask=None,
                 l4_src_port=None,
                 l4_src_port_mask=None,
                 l4_src_port_range=None,
                 l4_dst_port=None,
                 l4_dst_port_mask=None,
                 l4_dst_port_range=None,
                 tunnel_vni=None,
                 tunnel_vni_mask=None,
                 inner_ether_type=None,
                 inner_ether_type_mask=None,
                 inner_src_ip=None,
                 inner_src_ip_mask=None,
                 inner_dst_ip=None,
                 inner_dst_ip_mask=None,
                 inner_ip_proto=None,
                 inner_ip_proto_mask=None,
                 inner_l4_src_port=None,
                 inner_l4_src_port_mask=None,
                 inner_l4_src_port_range=None,
                 inner_l4_dst_port=None,
                 inner_l4_dst_port_mask=None,
                 inner_l4_dst_port_range=None,
                 dtel_int_enable=None,
                 dtel_int_session=None,
                 dtel_postcard_enable=None,
                 dtel_sample_percent=None,
                 dtel_report_all=None,
                 dtel_drop_report_enable=None):

        if watchlist is None:
            raise ValueError('Need to provide watchlist')
        if watchlist.watchlist_type == 'flow':
            if watchlist.switch.dtel_monitoring_type == 'postcard':
                if dtel_postcard_enable is None:
                    dtel_postcard_enable = True
            else:
                if dtel_int_enable is None:
                    dtel_int_enable = True
                if dtel_int_session is None:
                    if len(watchlist.switch.dtel_int_sessions) == 1:
                        # If no INT session is specified and there is only one configured, use it
                        dtel_int_session = watchlist.switch.dtel_int_sessions[0]
                    else:
                        raise ValueError('Need to specify INT session')
        elif watchlist.watchlist_type == 'drop':
            if dtel_drop_report_enable is None:
                dtel_drop_report_enable = True
        # Attributes
        self.switch = watchlist.switch
        self._watchlist = None
        self._priority = None
        self._ether_type = None
        self._ether_type_mask = None
        self._src_ip = None
        self._src_ip_mask = None
        self._dst_ip = None
        self._dst_ip_mask = None
        self._ip_proto = None
        self._ip_proto_mask = None
        self._dscp = None
        self._dscp_mask = None
        self._l4_src_port = None
        self._l4_src_port_mask = None
        self._l4_src_port_range = None
        self._l4_dst_port = None
        self._l4_dst_port_mask = None
        self._l4_dst_port_range = None
        self._tunnel_vni = None
        self._tunnel_vni_mask = None
        self._inner_ether_type = None
        self._inner_ether_type_mask = None
        self._inner_src_ip = None
        self._inner_src_ip_mask = None
        self._inner_dst_ip = None
        self._inner_dst_ip_mask = None
        self._inner_ip_proto = None
        self._inner_ip_proto_mask = None
        self._inner_l4_src_port = None
        self._inner_l4_src_port_mask = None
        self._inner_l4_src_port_range = None
        self._inner_l4_dst_port = None
        self._inner_l4_dst_port_mask = None
        self._inner_l4_dst_port_range = None
        self._dtel_int_enable = None
        self._dtel_int_session = None
        self._dtel_postcard_enable = None
        self._dtel_sample_percent = None
        self._dtel_report_all = None
        self._dtel_drop_report_enable = None
        # Properties
        DTelWatchlistEntry.watchlist.fset(self, watchlist)
        DTelWatchlistEntry.priority.fset(self, priority)
        DTelWatchlistEntry.ether_type.fset(self, ether_type)
        DTelWatchlistEntry.ether_type_mask.fset(self, ether_type_mask)
        DTelWatchlistEntry.src_ip.fset(self, src_ip)
        if self._src_ip:
            # Mask needs to be set only if address is set
            DTelWatchlistEntry.src_ip_mask.fset(self, src_ip_mask)
        DTelWatchlistEntry.dst_ip.fset(self, dst_ip)
        if self._dst_ip:
            # Mask needs to be set only if address is set
            DTelWatchlistEntry.dst_ip_mask.fset(self, dst_ip_mask)
        DTelWatchlistEntry.ip_proto.fset(self, ip_proto)
        DTelWatchlistEntry.ip_proto_mask.fset(self, ip_proto_mask)
        DTelWatchlistEntry.dscp.fset(self, dscp)
        DTelWatchlistEntry.dscp_mask.fset(self, dscp_mask)
        DTelWatchlistEntry.l4_src_port.fset(self, l4_src_port)
        DTelWatchlistEntry.l4_src_port_mask.fset(self, l4_src_port_mask)
        DTelWatchlistEntry.l4_src_port_range.fset(self, l4_src_port_range)
        DTelWatchlistEntry.l4_dst_port.fset(self, l4_dst_port)
        DTelWatchlistEntry.l4_dst_port_mask.fset(self, l4_dst_port_mask)
        DTelWatchlistEntry.l4_dst_port_range.fset(self, l4_dst_port_range)
        DTelWatchlistEntry.tunnel_vni.fset(self, tunnel_vni)
        DTelWatchlistEntry.tunnel_vni_mask.fset(self, tunnel_vni_mask)
        DTelWatchlistEntry.inner_ether_type.fset(self, inner_ether_type)
        DTelWatchlistEntry.inner_ether_type_mask.fset(self, inner_ether_type_mask)
        DTelWatchlistEntry.inner_src_ip.fset(self, inner_src_ip)
        DTelWatchlistEntry.inner_src_ip_mask.fset(self, inner_src_ip_mask)
        DTelWatchlistEntry.inner_dst_ip.fset(self, inner_dst_ip)
        DTelWatchlistEntry.inner_dst_ip_mask.fset(self, inner_dst_ip_mask)
        DTelWatchlistEntry.inner_ip_proto.fset(self, inner_ip_proto)
        DTelWatchlistEntry.inner_ip_proto_mask.fset(self, inner_ip_proto_mask)
        DTelWatchlistEntry.inner_l4_src_port.fset(self, inner_l4_src_port)
        DTelWatchlistEntry.inner_l4_src_port_mask.fset(self, inner_l4_src_port_mask)
        DTelWatchlistEntry.inner_l4_src_port_range.fset(self, inner_l4_src_port_range)
        DTelWatchlistEntry.inner_l4_dst_port.fset(self, inner_l4_dst_port)
        DTelWatchlistEntry.inner_l4_dst_port_mask.fset(self, inner_l4_dst_port_mask)
        DTelWatchlistEntry.inner_l4_dst_port_range.fset(self, inner_l4_dst_port_range)
        DTelWatchlistEntry.dtel_int_enable.fset(self, dtel_int_enable)
        DTelWatchlistEntry.dtel_int_session.fset(self, dtel_int_session)
        DTelWatchlistEntry.dtel_postcard_enable.fset(self, dtel_postcard_enable)
        DTelWatchlistEntry.dtel_sample_percent.fset(self, dtel_sample_percent)
        DTelWatchlistEntry.dtel_report_all.fset(self, dtel_report_all)
        DTelWatchlistEntry.dtel_drop_report_enable.fset(self, dtel_drop_report_enable)
        # Append
        self.watchlist.entries.append(self)

    def delete(self):
        self.watchlist.entries.remove(self)

    @property
    def watchlist(self):
        return self._watchlist

    @watchlist.setter
    def watchlist(self, value):
        if self._watchlist is not None:
            raise ValueError('Changing watchlists is not allowed')
        if value not in self.switch.dtel_watchlists:
            raise ValueError('Unrecognized watchlist')
        self._watchlist = value

    @property
    def priority(self):
        return self._priority

    @priority.setter
    def priority(self, value):
        if value <= 0 or value >= 2**32:
            raise ValueError('Invalid priority value')
        self._priority = int(value)

    @property
    def ether_type(self):
        return self._ether_type

    @ether_type.setter
    def ether_type(self, value):
        if value is not None:
            if value < 0 or value >= 2**16:
                raise ValueError('ether_type must be a uint16')
        self._ether_type = value

    @property
    def ether_type_mask(self):
        return self._ether_type_mask

    @ether_type_mask.setter
    def ether_type_mask(self, value):
        if value is not None:
            if value < 0 or value >= 2**16:
                raise ValueError('ether_type_mask must be a uint16')
        self._ether_type_mask = value

    @property
    def src_ip(self):
        return self._src_ip

    @src_ip.setter
    def src_ip(self, value):
        self._src_ip = check_ip_address(value, allow_none=True)

    @property
    def src_ip_mask(self):
        return self._src_ip_mask

    @src_ip_mask.setter
    def src_ip_mask(self, value):
        if value is not None:
            if value < 0 or value > 32:
                raise ValueError('src_ip_mask is a integer between 0 and 32')
            self._src_ip_mask = value

    @property
    def dst_ip(self):
        return self._dst_ip

    @dst_ip.setter
    def dst_ip(self, value):
        self._dst_ip = check_ip_address(value, allow_none=True)

    @property
    def dst_ip_mask(self):
        return self._dst_ip_mask

    @dst_ip_mask.setter
    def dst_ip_mask(self, value):
        if value is not None:
            if value < 0 or value > 32:
                raise ValueError('dst_ip_mask is an integer between 0 and 32')
            self._dst_ip_mask = value

    @property
    def ip_proto(self):
        return self._ip_proto

    @ip_proto.setter
    def ip_proto(self, value):
        if value is not None:
            if value < 0 or value >= 2**8:
                raise ValueError('ip_proto must be a uint8')
        self._ip_proto = value

    @property
    def ip_proto_mask(self):
        return self._ip_proto_mask

    @ip_proto_mask.setter
    def ip_proto_mask(self, value):
        if value is not None:
            if value < 0 or value >= 2**8:
                raise ValueError('ip_proto_mask must be a uint8')
        self._ip_proto_mask = value

    @property
    def dscp(self):
        return self._dscp

    @dscp.setter
    def dscp(self, value):
        if value is not None:
            if value < 0 or value >= 2 ** 8:
                raise ValueError('dscp must be a uint8')
        self._dscp = value

    @property
    def dscp_mask(self):
        return self._dscp_mask

    @dscp_mask.setter
    def dscp_mask(self, value):
        if value is not None:
            if value < 0 or value >= 2 ** 8:
                raise ValueError('dscp_mask must be a uint8')
        self._dscp_mask = value

    @property
    def l4_src_port(self):
        return self._l4_src_port

    @l4_src_port.setter
    def l4_src_port(self, value):
        if value is not None:
            if self._l4_src_port_range is not None:
                raise ValueError('Cannot set both l4_src_port and l4_src_port_range')
            if value < 0 or value >= 2**16:
                raise ValueError('l4_src_port must be a uint16')
        self._l4_src_port = value

    @property
    def l4_src_port_mask(self):
        return self._l4_src_port_mask

    @l4_src_port_mask.setter
    def l4_src_port_mask(self, value):
        if value is not None:
            if self._l4_src_port_range is not None:
                raise ValueError('Cannot set both l4_src_port_mask and l4_src_port_range')
            if value < 0 or value >= 2**16:
                raise ValueError('l4_src_port_mask must be a uint16')
        self._l4_src_port_mask = value

    @property
    def l4_src_port_range(self):
        return self._l4_src_port_range

    @l4_src_port_range.setter
    def l4_src_port_range(self, value):
        if value is not None:
            if self._l4_src_port is not None:
                raise ValueError('Cannot set both l4_src_port_range and l4_src_port')
            if self._l4_src_port_mask is not None:
                raise ValueError('Cannot set both l4_src_port_range and l4_src_port_mask')
            if not isinstance(value, str):
                raise ValueError('l4_src_port_range must be a string')
            fields = value.split('-')
            if len(fields) != 2:
                raise ValueError('l4_src_port_range must be in the form of \'MIN-MAX\'')
            if int(fields[0]) < 0 or int(fields[0]) >= 2**16:
                raise ValueError('l4_src_port_range MIN must be between 0 and 2**16')
            if int(fields[1]) < 0 or int(fields[1]) >= 2**16:
                raise ValueError('l4_src_port_range MAX must be between 0 and 2**16')
            if int(fields[0]) > int(fields[1]):
                raise ValueError('l4_src_port_range MAX must be greater than MIN')
        self._l4_src_port_range = value

    @property
    def l4_dst_port(self):
        return self._l4_dst_port

    @l4_dst_port.setter
    def l4_dst_port(self, value):
        if value is not None:
            if self._l4_dst_port_range is not None:
                raise ValueError('Cannot set both l4_dst_port and l4_dst_port_range')
            if value < 0 or value >= 2**16:
                raise ValueError('l4_dst_port must be a uint16')
        self._l4_dst_port = value

    @property
    def l4_dst_port_mask(self):
        return self._l4_dst_port_mask

    @l4_dst_port_mask.setter
    def l4_dst_port_mask(self, value):
        if value is not None:
            if self._l4_dst_port_range is not None:
                raise ValueError('Cannot set both l4_dst_port_mask and l4_dst_port_range')
            if value < 0 or value >= 2**16:
                raise ValueError('l4_dst_port_mask must be a uint16')
        self._l4_dst_port_mask = value

    @property
    def l4_dst_port_range(self):
        return self._l4_dst_port_range

    @l4_dst_port_range.setter
    def l4_dst_port_range(self, value):
        if value is not None:
            if self._l4_dst_port is not None:
                raise ValueError('Cannot set both l4_dst_port_range and l4_dst_port')
            if self._l4_dst_port_mask is not None:
                raise ValueError('Cannot set both l4_dst_port_range and l4_dst_port_mask')
            if not isinstance(value, str):
                raise ValueError('l4_dst_port_range must be a string')
            fields = value.split('-')
            if len(fields) != 2:
                raise ValueError('l4_dst_port_range must be in the form of \'MIN-MAX\'')
            if int(fields[0]) < 0 or int(fields[0]) >= 2 ** 16:
                raise ValueError('l4_dst_port_range MIN must be between 0 and 2**16')
            if int(fields[1]) < 0 or int(fields[1]) >= 2 ** 16:
                raise ValueError('l4_dst_port_range MAX must be between 0 and 2**16')
            if int(fields[0]) > int(fields[1]):
                raise ValueError('l4_dst_port_range MAX must be greater than MIN')
        self._l4_dst_port_range = value

    @property
    def tunnel_vni(self):
        return self._tunnel_vni

    @tunnel_vni.setter
    def tunnel_vni(self, value):
        if value is not None:
            raise ValueError('tunnel_vni not supported')
        self._tunnel_vni = value

    @property
    def tunnel_vni_mask(self):
        return self._tunnel_vni_mask

    @tunnel_vni_mask.setter
    def tunnel_vni_mask(self, value):
        if value is not None:
            raise ValueError('tunnel_vni_mask not supported')
        self._tunnel_vni_mask = value

    @property
    def inner_ether_type(self):
        return self._inner_ether_type

    @inner_ether_type.setter
    def inner_ether_type(self, value):
        if value is not None:
            if value < 0 or value >= 2**16:
                raise ValueError('inner_ether_type must be a uint16')
        self._inner_ether_type = value

    @property
    def inner_ether_type_mask(self):
        return self._inner_ether_type_mask

    @inner_ether_type_mask.setter
    def inner_ether_type_mask(self, value):
        if value is not None:
            if value < 0 or value >= 2**16:
                raise ValueError('inner_ether_type_mask must be a uint16')
        self._inner_ether_type_mask = value

    @property
    def inner_src_ip(self):
        return self._inner_src_ip

    @inner_src_ip.setter
    def inner_src_ip(self, value):
        self._inner_src_ip = check_ip_address(value, allow_none=True)

    @property
    def inner_src_ip_mask(self):
        return self._inner_src_ip_mask

    @inner_src_ip_mask.setter
    def inner_src_ip_mask(self, value):
        self._inner_src_ip_mask = check_ip_address(value, allow_none=True)

    @property
    def inner_dst_ip(self):
        return self._inner_dst_ip

    @inner_dst_ip.setter
    def inner_dst_ip(self, value):
        self._inner_dst_ip = check_ip_address(value, allow_none=True)

    @property
    def inner_dst_ip_mask(self):
        return self._inner_dst_ip_mask

    @inner_dst_ip_mask.setter
    def inner_dst_ip_mask(self, value):
        self._inner_dst_ip_mask = check_ip_address(value, allow_none=True)

    @property
    def inner_ip_proto(self):
        return self._inner_ip_proto

    @inner_ip_proto.setter
    def inner_ip_proto(self, value):
        if value is not None:
            if value < 0 or value >= 2**8:
                raise ValueError('inner_ip_proto must be a uint8')
        self._inner_ip_proto = value

    @property
    def inner_ip_proto_mask(self):
        return self._inner_ip_proto_mask

    @inner_ip_proto_mask.setter
    def inner_ip_proto_mask(self, value):
        if value is not None:
            if value < 0 or value >= 2**8:
                raise ValueError('inner_ip_proto_mask must be a uint8')
        self._inner_ip_proto_mask = value

    @property
    def inner_l4_src_port(self):
        return self._inner_l4_src_port

    @inner_l4_src_port.setter
    def inner_l4_src_port(self, value):
        if value is not None:
            if self._inner_l4_src_port_range is not None:
                raise ValueError('Cannot set both inner_l4_src_port and inner_l4_src_port_range')
            if value < 0 or value >= 2**16:
                raise ValueError('inner_l4_src_port must be a uint16')
        self._inner_l4_src_port = value

    @property
    def inner_l4_src_port_mask(self):
        return self._inner_l4_src_port_mask

    @inner_l4_src_port_mask.setter
    def inner_l4_src_port_mask(self, value):
        if value is not None:
            if value < 0 or value >= 2**16:
                raise ValueError('inner_l4_src_port_mask must be a uint16')
        self._inner_l4_src_port_mask = value

    @property
    def inner_l4_src_port_range(self):
        return self._inner_l4_src_port_range

    @inner_l4_src_port_range.setter
    def inner_l4_src_port_range(self, value):
        if value is not None:
            if self._inner_l4_src_port is not None:
                raise ValueError('Cannot set both inner_l4_src_port_range and inner_l4_src_port')
            if self._inner_l4_src_port_mask is not None:
                raise ValueError('Cannot set both inner_l4_src_port_range and inner_l4_src_port_mask')
            if not isinstance(value, str):
                raise ValueError('inner_l4_src_port_range must be a string')
            fields = value.split('-')
            if len(fields) != 2:
                raise ValueError('inner_l4_src_port_range must be in the form of \'MIN-MAX\'')
            if int(fields[0]) < 0 or int(fields[0]) >= 2 ** 16:
                raise ValueError('inner_l4_src_port_range MIN must be between 0 and 2**16')
            if int(fields[1]) < 0 or int(fields[1]) >= 2 ** 16:
                raise ValueError('inner_l4_src_port_range MAX must be between 0 and 2**16')
            if int(fields[0]) > int(fields[1]):
                raise ValueError('inner_l4_src_port_range MAX must be greater than MIN')
        self._inner_l4_src_port_range = value

    @property
    def inner_l4_dst_port(self):
        return self._inner_l4_dst_port

    @inner_l4_dst_port.setter
    def inner_l4_dst_port(self, value):
        if value is not None:
            if self._inner_l4_dst_port_range is not None:
                raise ValueError('Cannot set both inner_l4_dst_port and inner_l4_dst_port_range')
            if value < 0 or value >= 2**16:
                raise ValueError('inner_l4_dst_port must be a uint16')
        self._inner_l4_dst_port = value

    @property
    def inner_l4_dst_port_mask(self):
        return self._inner_l4_src_port_mask

    @inner_l4_dst_port_mask.setter
    def inner_l4_dst_port_mask(self, value):
        if value is not None:
            if self._inner_l4_dst_port_range is not None:
                raise ValueError('Cannot set both inner_l4_dst_port_mask and inner_l4_dst_port_range')
            if value < 0 or value >= 2**16:
                raise ValueError('inner_l4_dst_port_mask must be a uint16')
        self._inner_l4_dst_port_mask = value

    @property
    def inner_l4_dst_port_range(self):
        return self._inner_l4_dst_port_range

    @inner_l4_dst_port_range.setter
    def inner_l4_dst_port_range(self, value):
        if value is not None:
            if self._inner_l4_dst_port is not None:
                raise ValueError('Cannot set both inner_l4_dst_port_range and inner_l4_dst_port')
            if self._inner_l4_dst_port_mask is not None:
                raise ValueError('Cannot set both inner_l4_dst_port_range and inner_l4_dst_port_mask')
            if not isinstance(value, str):
                raise ValueError('inner_l4_dst_port_range must be a string')
            fields = value.split('-')
            if len(fields) != 2:
                raise ValueError('inner_l4_dst_port_range must be in the form of \'MIN-MAX\'')
            if int(fields[0]) < 0 or int(fields[0]) >= 2 ** 16:
                raise ValueError('inner_l4_dst_port_range MIN must be between 0 and 2**16')
            if int(fields[1]) < 0 or int(fields[1]) >= 2 ** 16:
                raise ValueError('inner_l4_dst_port_range MAX must be between 0 and 2**16')
            if int(fields[0]) > int(fields[1]):
                raise ValueError('inner_l4_dst_port_range MAX must be greater than MIN')
        self._inner_l4_dst_port_range = value

    @property
    def dtel_int_enable(self):
        return self._dtel_int_enable

    @dtel_int_enable.setter
    def dtel_int_enable(self, value):
        if value is not None and not isinstance(value, bool):
            raise ValueError('dtel_int_enable must be a boolean')
        if value is True and self.watchlist.watchlist_type == 'drop':
            raise ValueError('Cannot add a flow entry to a drop watchlist')
        self._dtel_int_enable = value

    @property
    def dtel_int_session(self):
        return self._dtel_int_session

    @dtel_int_session.setter
    def dtel_int_session(self, value):
        if value is not None and (value not in self.switch.dtel_int_sessions):
            raise ValueError('Invalid INT session')
        self._dtel_int_session = value

    @property
    def dtel_postcard_enable(self):
        return self._dtel_postcard_enable

    @dtel_postcard_enable.setter
    def dtel_postcard_enable(self, value):
        if value is not None and not isinstance(value, bool):
            raise ValueError('dtel_postcard_enable must be a boolean')
        if value is True and self.watchlist.watchlist_type == 'drop':
            raise ValueError('Cannot add a flow entry to a drop watchlist')
        self._dtel_postcard_enable = value

    @property
    def dtel_sample_percent(self):
        return self._dtel_sample_percent

    @dtel_sample_percent.setter
    def dtel_sample_percent(self, value):
        if value is not None and (value < 0 or value > 100):
            raise ValueError('dtel_sample_percent must be a value between 0 and 100')
        self._dtel_sample_percent = value

    @property
    def dtel_report_all(self):
        return self._dtel_report_all

    @dtel_report_all.setter
    def dtel_report_all(self, value):
        if value is not None and not isinstance(value, bool):
            raise ValueError('dtel_report_all must be a boolean')
        self._dtel_report_all = value

    @property
    def dtel_drop_report_enable(self):
        return self._dtel_drop_report_enable

    @dtel_drop_report_enable.setter
    def dtel_drop_report_enable(self, value):
        if value is not None and not isinstance(value, bool):
            raise ValueError('dtel_drop_report_enable must be a boolean')
        if value is True and self.watchlist.watchlist_type == 'flow':
            raise ValueError('Cannot add a drop entry to a flow watchlist')
        self._dtel_drop_report_enable = value
