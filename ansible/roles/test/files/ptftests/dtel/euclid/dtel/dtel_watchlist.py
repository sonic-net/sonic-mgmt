import dtel_watchlist_entry


class DTelWatchlist(object):
    def __init__(self, switch=None, watchlist_type=None):
        if switch is None:
            raise ValueError('Need to provide switch')
        if watchlist_type is None:
            raise ValueError('Need to provide watchlist_type')
        # Attributes
        self.switch = switch
        self._watchlist_type = None
        self.entries = []
        # Properties
        DTelWatchlist.watchlist_type.fset(self, watchlist_type)
        self.switch.dtel_watchlists.append(self)

    def delete(self):
        for entry in list(self.entries):
            entry.delete()
        self.switch.dtel_watchlists.remove(self)

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

        if self.watchlist_type == 'flow':
            if self.switch.dtel_monitoring_type == 'postcard':
                dtel_postcard_enable = True
                dtel_int_session = None
            elif self.switch.dtel_monitoring_type == 'int_endpoint':
                dtel_int_enable = True
                if dtel_int_session is None:
                    raise ValueError('Need to provide dtel_int_session')
            elif self.switch.dtel_monitoring_type == 'int_transit':
                raise ValueError('INT transit switches do not need flow watchlists')
        elif self.watchlist_type == 'drop':
            dtel_drop_report_enable = False
            if dtel_sample_percent is not None:
                raise ValueError('dtel_sample_percent is not applicable to drop watchlists')
            if dtel_report_all is not None:
                raise ValueError('dtel_report_all is not applicable to drop watchlists')
        return dtel_watchlist_entry.DTelWatchlistEntry(self,
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

    @property
    def watchlist_type(self):
        return self._watchlist_type

    @watchlist_type.setter
    def watchlist_type(self, value):
        if not value == 'flow' and not value == 'drop':
            raise ValueError('Invalid watchlist type, has to be either \'flow\' or \'drop\'')
        for watchlist in self.switch.dtel_watchlists:
            if watchlist != self:
                if watchlist.watchlist_type == value:
                    # In this case there is another watchlist with the same type
                    raise ValueError('%s watchlist already configured' % value)
            else:
                if watchlist.watchlist_type != value:
                    raise ValueError('Changing the watchlist type is not allowed')
        self._watchlist_type = value
