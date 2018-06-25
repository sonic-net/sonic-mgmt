from dtel import dtel_watchlist
import sonic_dtel_watchlist_entry
from dtel.infra import *


class SONiCDTelWatchlist(dtel_watchlist.DTelWatchlist, FrozenClass):
    def __init__(self, switch, watchlist_type=None):
        if watchlist_type is None:
            raise ValueError('Need to provide watchllist_type')
        super(SONiCDTelWatchlist, self).__init__(switch, watchlist_type)
        if self.watchlist_type == 'flow':
            self.hashname = 'DTEL_FLOW_WATCHLIST'
        elif self.watchlist_type == 'drop':
            self.hashname = 'DTEL_DROP_WATCHLIST'
        else:
            raise ValueError('Unexpected watchlist type: %s' % self.watchlist_type)
        self._freeze()

    def delete(self):
        for entry in self.entries:
            entry.delete()
        super(SONiCDTelWatchlist, self).delete()

    def create_entry(self,
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
                     dtel_int_session=None,
                     dtel_sample_percent=None,
                     dtel_report_all=None,
                     dtel_int_enable=None,
                     dtel_postcard_enable=None,
                     dtel_drop_report_enable=None):

        if src_ip and not src_ip_mask:
            src_ip_mask = 32
        if dst_ip and not dst_ip_mask:
            dst_ip_mask = 32

        if ether_type_mask is not None:
            raise ValueError('SONiC does not support ether_type_mask in watchlists')
        if ip_proto_mask is not None:
            raise ValueError('SONiC does not support ip_proto_mask in watchlists')
        if dscp_mask is not None:
            raise ValueError('SONiC does not support dscp_mask in watchlists')
        if l4_src_port_mask is not None:
            raise ValueError('SONiC does not support l4_src_port_mask in watchlists')
        if l4_dst_port_mask is not None:
            raise ValueError('SONiC does not support l4_dst_port_mask in watchlists')
        if tunnel_vni_mask is not None:
            raise ValueError('SONiC does not support tunnel_vni_mask in watchlists')
        if inner_ether_type is not None:
            raise ValueError('SONiC does not support inner_ether_type in watchlists')
        if inner_ether_type is not None:
            raise ValueError('SONiC does not support inner_ether_type in watchlists')
        if inner_ether_type is not None:
            raise ValueError('SONiC does not support inner_ether_type in watchlists')
        if inner_ether_type_mask is not None:
            raise ValueError('SONiC does not support inner_ether_type_mask in watchlists')
        if inner_src_ip is not None:
            raise ValueError('SONiC does not support inner_src_ip in watchlists')
        if inner_src_ip_mask is not None:
            raise ValueError('SONiC does not support inner_src_ip_mask in watchlists')
        if inner_dst_ip is not None:
            raise ValueError('SONiC does not support inner_dst_ip in watchlists')
        if inner_dst_ip_mask is not None:
            raise ValueError('SONiC does not support inner_dst_ip_mask in watchlists')
        if inner_ip_proto is not None:
            raise ValueError('SONiC does not support inner_ip_proto in watchlists')
        if inner_ip_proto_mask is not None:
            raise ValueError('SONiC does not support inner_ip_proto_mask in watchlists')
        if inner_l4_src_port is not None:
            raise ValueError('SONiC does not support inner_l4_src_port in watchlists')
        if inner_l4_src_port_mask is not None:
            raise ValueError('SONiC does not support inner_l4_src_port_mask in watchlists')
        if inner_l4_src_port_range is not None:
            raise ValueError('SONiC does not support inner_l4_src_port_range in watchlists')
        if inner_l4_dst_port is not None:
            raise ValueError('SONiC does not support inner_l4_dst_port in watchlists')
        if inner_l4_dst_port_mask is not None:
            raise ValueError('SONiC does not support inner_l4_dst_port_mask in watchlists')
        if inner_l4_dst_port_range is not None:
            raise ValueError('SONiC does not support inner_l4_dst_port_range in watchlists')

        return sonic_dtel_watchlist_entry.SONiCDTelWatchlistEntry(self,
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

