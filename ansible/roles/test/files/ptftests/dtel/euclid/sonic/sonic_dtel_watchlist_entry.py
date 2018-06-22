from dtel import dtel_watchlist_entry
from dtel.infra import *


class SONiCDTelWatchlistEntry(dtel_watchlist_entry.DTelWatchlistEntry, FrozenClass):
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
        super(SONiCDTelWatchlistEntry, self).__init__(
            watchlist,
            priority=priority,
            ether_type=ether_type,
            ether_type_mask=ether_type_mask,
            src_ip=src_ip,
            src_ip_mask=src_ip_mask,
            dst_ip=dst_ip,
            dst_ip_mask=dst_ip_mask,
            ip_proto=ip_proto,
            ip_proto_mask=ip_proto_mask,
            dscp=dscp,
            dscp_mask=dscp_mask,
            l4_src_port=l4_src_port,
            l4_src_port_mask=l4_src_port_mask,
            l4_src_port_range=l4_src_port_range,
            l4_dst_port=l4_dst_port,
            l4_dst_port_mask=l4_dst_port_mask,
            l4_dst_port_range=l4_dst_port_range,
            tunnel_vni=tunnel_vni,
            tunnel_vni_mask=tunnel_vni_mask,
            inner_ether_type=inner_ether_type,
            inner_ether_type_mask=inner_ether_type_mask,
            inner_src_ip=inner_src_ip,
            inner_src_ip_mask=inner_src_ip_mask,
            inner_dst_ip=inner_dst_ip,
            inner_dst_ip_mask=inner_dst_ip_mask,
            inner_ip_proto=inner_ip_proto,
            inner_ip_proto_mask=inner_ip_proto_mask,
            inner_l4_src_port=inner_l4_src_port,
            inner_l4_src_port_mask=inner_l4_src_port_mask,
            inner_l4_src_port_range=inner_l4_src_port_range,
            inner_l4_dst_port=inner_l4_dst_port,
            inner_l4_dst_port_mask=inner_l4_dst_port_mask,
            inner_l4_dst_port_range=inner_l4_dst_port_range,
            dtel_int_enable=dtel_int_enable,
            dtel_int_session=dtel_int_session,
            dtel_postcard_enable=dtel_postcard_enable,
            dtel_sample_percent=dtel_sample_percent,
            dtel_report_all=dtel_report_all,
            dtel_drop_report_enable=dtel_drop_report_enable)

        # These four values can be changed by the superclass contructor, so they should be re-set here
        dtel_int_enable = dtel_watchlist_entry.DTelWatchlistEntry.dtel_int_enable.fget(self)
        dtel_int_session = dtel_watchlist_entry.DTelWatchlistEntry.dtel_int_session.fget(self)
        dtel_postcard_enable = dtel_watchlist_entry.DTelWatchlistEntry.dtel_postcard_enable.fget(self)
        dtel_drop_report_enable = dtel_watchlist_entry.DTelWatchlistEntry.dtel_drop_report_enable.fget(self)

        if watchlist is None:
            raise ValueError('Need to provide watchlist')
        self.table_name = 'ACL_RULE'
        if self.watchlist.watchlist_type == 'flow':
            self.hashname = 'DTEL_FLOW_WATCHLIST|RULE'
        else:
            self.hashname = 'DTEL_DROP_WATCHLIST|RULE'

        rule_id = self.watchlist.switch.generate_id(self.table_name + '|' + self.hashname)
        self.hashname += str(rule_id)
        keys = []
        values = []
        keys.append('PRIORITY')
        values.append(priority)
        if ether_type is not None:
            keys.append('ETHER_TYPE')
            values.append(ether_type)
        if ether_type_mask is not None:
            keys.append('ETHER_TYPE_MASK')
            values.append(ether_type_mask)
        if src_ip is not None:
            keys.append('SRC_IP')
            values.append(src_ip + '/' + str(src_ip_mask))
        if dst_ip is not None:
            keys.append('DST_IP')
            values.append(dst_ip + '/' + str(dst_ip_mask))
        if ip_proto is not None:
            keys.append('IP_PROTOCOL')
            values.append(ip_proto)
        if ip_proto_mask is not None:
            keys.append('IP_PROTOCOL_MASK')
            values.append(ip_proto_mask)
        if dscp is not None:
            keys.append('DSCP')
            values.append(dscp)
        if dscp_mask is not None:
            keys.append('DSCP_MASK')
            values.append(dscp_mask)
        if l4_src_port is not None:
            keys.append('L4_SRC_PORT')
            values.append(l4_src_port)
        if l4_src_port_mask is not None:
            keys.append('L4_SRC_PORT_MASK')
            values.append(l4_src_port_mask)
        if l4_src_port_range is not None:
            keys.append('L4_SRC_PORT_RANGE')
            values.append(l4_src_port_range)
        if l4_dst_port is not None:
            keys.append('L4_DST_PORT')
            values.append(l4_dst_port)
        if l4_dst_port_mask is not None:
            keys.append('L4_DST_PORT_MASK')
            values.append(l4_dst_port_mask)
        if l4_dst_port_range is not None:
            keys.append('L4_DST_PORT_RANGE')
            values.append(l4_dst_port_range)
        if tunnel_vni is not None:
            keys.append('TUNNEL_VNI')
            values.append(tunnel_vni)
        if tunnel_vni_mask is not None:
            keys.append('TUNNEL_VNI_MASK')
            values.append(tunnel_vni_mask)
        if inner_ether_type is not None:
            keys.append('INNER_ETHER_TYPE')
            values.append(inner_ether_type)
        if inner_ether_type_mask is not None:
            keys.append('INNER_ETHER_TYPE_MASK')
            values.append(inner_ether_type_mask)
        if inner_src_ip is not None:
            keys.append('INNER_SRC_IP')
            values.append(inner_src_ip)
        if inner_src_ip_mask is not None:
            keys.append('INNER_SRC_IP_MASK')
            values.append(inner_src_ip_mask)
        if inner_dst_ip is not None:
            keys.append('INNER_DST_IP')
            values.append(inner_dst_ip)
        if inner_dst_ip_mask is not None:
            keys.append('INNER_DST_IP_MASK')
            values.append(inner_dst_ip_mask)
        if inner_ip_proto is not None:
            keys.append('INNER_IP_PROTO')
            values.append(inner_ip_proto)
        if inner_ip_proto_mask is not None:
            keys.append('INNER_IP_PROTO_MASK')
            values.append(inner_ip_proto_mask)
        if inner_l4_src_port is not None:
            keys.append('INNER_L4_SRC_PORT')
            values.append(inner_l4_src_port)
        if inner_l4_src_port_mask is not None:
            keys.append('INNER_L4_SRC_PORT_MASK')
            values.append(inner_l4_src_port_mask)
        if inner_l4_src_port_range is not None:
            keys.append('INNER_L4_SRC_PORT_RANGE')
            values.append(inner_l4_src_port_range)
        if inner_l4_dst_port is not None:
            keys.append('INNER_L4_DST_PORT')
            values.append(inner_l4_dst_port)
        if inner_l4_dst_port_mask is not None:
            keys.append('INNER_L4_DST_PORT_MASK')
            values.append(inner_l4_dst_port_mask)
        if inner_l4_dst_port_range is not None:
            keys.append('INNER_L4_DST_PORT_RANGE')
            values.append(inner_l4_dst_port_range)
        if dtel_int_enable is not None:
            keys.append('FLOW_OP')
            values.append('INT')
        if dtel_int_session is not None:
            keys.append('INT_SESSION')
            values.append(self.dtel_int_session.hashname)
        if dtel_postcard_enable is not None:
            keys.append('FLOW_OP')
            values.append('POSTCARD')
        if dtel_sample_percent is not None:
            keys.append('FLOW_SAMPLE_PERCENT')
            values.append(dtel_sample_percent)
        if dtel_report_all is not None:
            keys.append('REPORT_ALL_PACKETS')
            values.append(dtel_report_all)
        if dtel_drop_report_enable is not None:
            keys.append('DROP_REPORT_ENABLE')
            values.append(dtel_drop_report_enable)
        self.watchlist.switch.redis_write(self.table_name,
                                          self.hashname,
                                          keys,
                                          values)
        self._freeze()

    def delete(self):
        self.switch.redis_delete('ACL_RULE', self.hashname)
        super(SONiCDTelWatchlistEntry, self).delete()

    @property
    def priority(self):
        value = int(self.switch.redis_read(self.table_name, self.hashname, 'PRIORITY'))
        dtel_watchlist_entry.DTelWatchlistEntry.priority.fset(self, value)
        return dtel_watchlist_entry.DTelWatchlistEntry.priority.fget(self)

    @priority.setter
    def priority(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.priority.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'PRIORITY', value)

    @property
    def ether_type(self):
        value = int(self.switch.redis_read(self.table_name, self.hashname, 'ETHER_TYPE'))
        dtel_watchlist_entry.DTelWatchlistEntry.ether_type.fset(self, value)
        return dtel_watchlist_entry.DTelWatchlistEntry.priority.fget(self)

    @ether_type.setter
    def ether_type(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.ether_type.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'ETHER_TYPE', value)

    @property
    def ether_type_mask(self):
        raise ValueError('ether_type_mask not supported in SONiC')

    @ether_type_mask.setter
    def ether_type_mask(self, value):
        raise ValueError('ether_type_mask not supported in SONiC')

    @property
    def src_ip(self):
        value = self.switch.redis_read(self.table_name, self.hashname, 'SRC_IP')
        value = value.split('/')
        dtel_watchlist_entry.DTelWatchlistEntry.src_ip.fset(self, value[0])
        dtel_watchlist_entry.DTelWatchlistEntry.src_ip_mask.fset(self, int(value[1]))
        return dtel_watchlist_entry.DTelWatchlistEntry.src_ip.fget(self)

    @src_ip.setter
    def src_ip(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.src_ip.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'SRC_IP', value + '/' + str(self._src_ip_mask))

    @property
    def src_ip_mask(self):
        value = self.switch.redis_read(self.table_name, self.hashname, 'SRC_IP')
        value = value.split('/')
        dtel_watchlist_entry.DTelWatchlistEntry.src_ip_mask.fset(self, int(value[1]))
        dtel_watchlist_entry.DTelWatchlistEntry.src_ip.fset(self, value[0])
        return dtel_watchlist_entry.DTelWatchlistEntry.src_ip_mask.fget(self)

    @src_ip_mask.setter
    def src_ip_mask(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.src_ip_mask.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'SRC_IP', self._src_ip + '/' + str(value))

    @property
    def dst_ip(self):
        value = self.switch.redis_read(self.table_name, self.hashname, 'DST_IP')
        value = value.split('/')
        dtel_watchlist_entry.DTelWatchlistEntry.dst_ip.fset(self, value[0])
        dtel_watchlist_entry.DTelWatchlistEntry.dst_ip_mask.fset(self, int(value[1]))
        return dtel_watchlist_entry.DTelWatchlistEntry.dst_ip.fget(self)

    @dst_ip.setter
    def dst_ip(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.dst_ip.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'DST_IP', value + '/' + str(self._dst_ip_mask))

    @property
    def dst_ip_mask(self):
        value = self.switch.redis_read(self.table_name, self.hashname, 'DST_IP')
        value = value.split('/')
        dtel_watchlist_entry.DTelWatchlistEntry.dst_ip_mask.fset(self, int(value[1]))
        dtel_watchlist_entry.DTelWatchlistEntry.dst_ip.fset(self, value[0])
        return dtel_watchlist_entry.DTelWatchlistEntry.dst_ip_mask.fget(self)

    @dst_ip_mask.setter
    def dst_ip_mask(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.dst_ip_mask.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'DST_IP', self._dst_ip + '/' + str(value))

    @property
    def ip_proto(self):
        value = int(self.switch.redis_read(self.table_name, self.hashname, 'IP_PROTO'))
        dtel_watchlist_entry.DTelWatchlistEntry.ip_proto.fset(self, value)
        return dtel_watchlist_entry.DTelWatchlistEntry.ip_proto.fget(self)

    @ip_proto.setter
    def ip_proto(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.ip_proto.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'IP_PROTO', value)

    @property
    def ip_proto_mask(self):
        raise ValueError('ip_proto_mask not supported in SONiC')

    @ip_proto_mask.setter
    def ip_proto_mask(self, value):
        raise ValueError('ip_proto_mask not supported in SONiC')

    @property
    def dscp(self):
        value = int(self.switch.redis_read(self.table_name, self.hashname, 'DSCP'))
        dtel_watchlist_entry.DTelWatchlistEntry.dscp.fset(self, value)
        return dtel_watchlist_entry.DTelWatchlistEntry.dscp.fget(self)

    @dscp.setter
    def dscp(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.dscp.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'DSCP', value)

    @property
    def dscp_mask(self):
        raise ValueError('dscp_mask not supported in SONiC')

    @dscp_mask.setter
    def dscp_mask(self, value):
        raise ValueError('dscp_mask not supported in SONiC')

    @property
    def l4_src_port(self):
        value = int(self.switch.redis_read(self.table_name, self.hashname, 'L4_SRC_PORT'))
        dtel_watchlist_entry.DTelWatchlistEntry.l4_src_port.fset(self, value)
        return dtel_watchlist_entry.DTelWatchlistEntry.l4_src_port.fget(self)

    @l4_src_port.setter
    def l4_src_port(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.l4_src_port.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'L4_SRC_PORT', value)

    @property
    def l4_src_port_mask(self):
        value = int(self.switch.redis_read(self.table_name, self.hashname, 'L4_SRC_PORT_MASK'))
        dtel_watchlist_entry.DTelWatchlistEntry.l4_src_port_mask.fset(self, value)
        return dtel_watchlist_entry.DTelWatchlistEntry.l4_src_port_mask.fget(self)

    @l4_src_port_mask.setter
    def l4_src_port_mask(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.l4_dst_port_mask.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'L4_SRC_PORT_MASK', value)

    @property
    def l4_src_port_range(self):
        value = int(self.switch.redis_read(self.table_name, self.hashname, 'L4_SRC_PORT_RANGE'))
        dtel_watchlist_entry.DTelWatchlistEntry.l4_src_port_range.fset(self, value)
        return dtel_watchlist_entry.DTelWatchlistEntry.l4_src_port_range.fget(self)

    @l4_src_port_range.setter
    def l4_src_port_range(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.l4_src_port_range.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'L4_SRC_PORT_RANGE', value)

    @property
    def l4_dst_port(self):
        value = int(self.switch.redis_read(self.table_name, self.hashname, 'L4_DST_PORT'))
        dtel_watchlist_entry.DTelWatchlistEntry.l4_dst_port.fset(self, value)
        return dtel_watchlist_entry.DTelWatchlistEntry.l4_dst_port.fget(self)

    @l4_dst_port.setter
    def l4_dst_port(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.l4_dst_port.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'L4_DST_PORT', value)

    @property
    def l4_dst_port_mask(self):
        value = int(self.switch.redis_read(self.table_name, self.hashname, 'L4_DST_PORT_MASK'))
        dtel_watchlist_entry.DTelWatchlistEntry.l4_dst_port_mask.fset(self, value)
        return dtel_watchlist_entry.DTelWatchlistEntry.l4_dst_port_mask.fget(self)

    @l4_dst_port_mask.setter
    def l4_dst_port_mask(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.l4_dst_port_mask.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'L4_DST_PORT_MASK', value)

    @property
    def l4_dst_port_range(self):
        value = int(self.switch.redis_read(self.table_name, self.hashname, 'L4_DST_PORT_RANGE'))
        dtel_watchlist_entry.DTelWatchlistEntry.l4_dst_port_range.fset(self, value)
        return dtel_watchlist_entry.DTelWatchlistEntry.l4_dst_port_range.fget(self)

    @l4_dst_port_range.setter
    def l4_dst_port_range(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.l4_dst_port_range.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'L4_DST_PORT_RANGE', value)

    @property
    def tunnel_vni(self):
        value = int(self.switch.redis_read(self.table_name, self.hashname, 'TUNNEL_VNI'))
        dtel_watchlist_entry.DTelWatchlistEntry.tunnel_vni.fset(self, value)
        return dtel_watchlist_entry.DTelWatchlistEntry.tunnel_vni.fget(self)

    @tunnel_vni.setter
    def tunnel_vni(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.tunnel_vni.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'TUNNEL_VNI', value)

    @property
    def tunnel_vni_mask(self):
        raise ValueError('tunnel_vni_mask not supported in SONiC')

    @tunnel_vni_mask.setter
    def tunnel_vni_mask(self, value):
        raise ValueError('tunnel_vni_mask not supported in SONiC')

    @property
    def inner_ether_type(self):
        raise ValueError('inner_ether_type not supported in SONiC')

    @inner_ether_type.setter
    def inner_ether_type(self, value):
        raise ValueError('inner_ether_type not supported in SONiC')

    @property
    def inner_ether_type_mask(self):
        raise ValueError('inner_ether_type_mask not supported in SONiC')

    @inner_ether_type_mask.setter
    def inner_ether_type_mask(self, value):
        raise ValueError('inner_ether_type_mask not supported in SONiC')

    @property
    def inner_src_ip(self):
        raise ValueError('inner_src_ip not supported in SONiC')

    @inner_src_ip.setter
    def inner_src_ip(self, value):
        raise ValueError('inner_src_ip not supported in SONiC')

    @property
    def inner_src_ip_mask(self):
        raise ValueError('inner_src_ip_mask not supported in SONiC')

    @inner_src_ip_mask.setter
    def inner_src_ip_mask(self, value):
        raise ValueError('inner_src_ip_mask not supported in SONiC')

    @property
    def inner_dst_ip(self):
        raise ValueError('inner_dst_ip not supported in SONiC')

    @inner_dst_ip.setter
    def inner_dst_ip(self, value):
        raise ValueError('inner_dst_ip not supported in SONiC')

    @property
    def inner_dst_ip_mask(self):
        raise ValueError('inner_dst_ip_mask not supported in SONiC')

    @inner_dst_ip_mask.setter
    def inner_dst_ip_mask(self, value):
        raise ValueError('inner_dst_ip_mask not supported in SONiC')

    @property
    def inner_ip_proto(self):
        raise ValueError('inner_ip_proto not supported in SONiC')

    @inner_ip_proto.setter
    def inner_ip_proto(self, value):
        raise ValueError('inner_ip_proto not supported in SONiC')

    @property
    def inner_ip_proto_mask(self):
        raise ValueError('inner_ip_proto_mask not supported in SONiC')

    @inner_ip_proto_mask.setter
    def inner_ip_proto_mask(self, value):
        raise ValueError('inner_ip_proto_mask not supported in SONiC')

    @property
    def inner_l4_src_port(self):
        raise ValueError('inner_l4_src_port not supported in SONiC')

    @inner_l4_src_port.setter
    def inner_l4_src_port(self, value):
        raise ValueError('inner_l4_src_port not supported in SONiC')

    @property
    def inner_l4_src_port_mask(self):
        raise ValueError('inner_l4_src_port_mask not supported in SONiC')

    @inner_l4_src_port_mask.setter
    def inner_l4_src_port_mask(self, value):
        raise ValueError('inner_l4_src_port_mask not supported in SONiC')

    @property
    def inner_l4_src_port_range(self):
        raise ValueError('inner_l4_src_port_range not supported in SONiC')

    @inner_l4_src_port_range.setter
    def inner_l4_src_port_range(self, value):
        raise ValueError('inner_l4_src_port_range not supported in SONiC')

    @property
    def inner_l4_dst_port(self):
        raise ValueError('inner_l4_dst_port not supported in SONiC')

    @inner_l4_dst_port.setter
    def inner_l4_dst_port(self, value):
        raise ValueError('inner_l4_dst_port not supported in SONiC')

    @property
    def inner_l4_dst_port_mask(self):
        raise ValueError('inner_l4_dst_port_mask not supported in SONiC')

    @inner_l4_dst_port_mask.setter
    def inner_l4_dst_port_mask(self, value):
        raise ValueError('inner_l4_dst_port_mask not supported in SONiC')

    @property
    def inner_l4_dst_port_range(self):
        raise ValueError('inner_l4_dst_port_range not supported in SONiC')

    @inner_l4_dst_port_range.setter
    def inner_l4_dst_port_range(self, value):
        raise ValueError('inner_l4_dst_port_range not supported in SONiC')

    @property
    def dtel_int_enable(self):
        value = self.switch.redis_read(self.table_name, self.hashname, 'INT')
        dtel_watchlist_entry.DTelWatchlistEntry.dtel_int_enable.fset(self, value)
        return dtel_watchlist_entry.DTelWatchlistEntry.dtel_int_enable.fget(self)

    @dtel_int_enable.setter
    def dtel_int_enable(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.dtel_int_enable.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'INT', value)

    @property
    def dtel_postcard_enable(self):
        value = self.switch.redis_read(self.table_name, self.hashname, 'POSTCARD')
        dtel_watchlist_entry.DTelWatchlistEntry.dtel_postcard_enable.fset(self, value)
        return dtel_watchlist_entry.DTelWatchlistEntry.dtel_postcard_enable.fget(self)

    @dtel_postcard_enable.setter
    def dtel_postcard_enable(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.dtel_postcard_enable.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'POSTCARD', value)

    @property
    def dtel_sample_percent(self):
        value = int(self.switch.redis_read(self.table_name, self.hashname, 'FLOW_SAMPLE_PERCENT'))
        dtel_watchlist_entry.DTelWatchlistEntry.dtel_sample_percent.fset(self, value)
        return dtel_watchlist_entry.DTelWatchlistEntry.dtel_sample_percent.fget(self)

    @dtel_sample_percent.setter
    def dtel_sample_percent(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.dtel_sample_percent.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'FLOW_SAMPLE_PERCENT', value)

    @property
    def dtel_report_all(self):
        value = self.switch.redis_read(self.table_name, self.hashname, 'REPORT_ALL_PACKETS')
        dtel_watchlist_entry.DTelWatchlistEntry.dtel_report_all.fset(self, value)
        return dtel_watchlist_entry.DTelWatchlistEntry.dtel_report_all.fget(self)

    @dtel_report_all.setter
    def dtel_report_all(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.dtel_report_all.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'REPORT_ALL_PACKETS', value)

    @property
    def dtel_drop_report_enable(self):
        value = self.switch.redis_read(self.table_name, self.hashname, 'DROP_REPORT_ENABLE')
        dtel_watchlist_entry.DTelWatchlistEntry.dtel_drop_report_enable.fset(self, value)
        return dtel_watchlist_entry.DTelWatchlistEntry.dtel_drop_report_enable.fget(self)

    @dtel_drop_report_enable.setter
    def dtel_drop_report_enable(self, value):
        dtel_watchlist_entry.DTelWatchlistEntry.dtel_drop_report_enable.fset(self, value)
        self.switch.redis_write(self.table_name, self.hashname, 'DROP_REPORT_ENABLE', value)
