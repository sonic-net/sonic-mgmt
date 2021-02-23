import sys

class TGStubs(object):
    def __init__(self, logger):
        self.logger = logger
    def override(self, name=None):
        name = name or sys._getframe(1).f_code.co_name
        self.logger.error("{} should be overriden".format(name))
        return {}
    def clean_all(self):
        return self.override()
    def show_status(self):
        return self.override()
    def tg_interface_handle(self, ret_ds):
        return self.override()
    def tg_interface_config(self, *args, **kwargs):
        return self.override()
    def tg_test_control(self, **kwargs):
        return self.override()
    def tg_packet_control(self, *args, **kwargs):
        return self.override()
    def tg_traffic_control(self, *args, **kwargs):
        return self.override()
    def tg_topology_config(self, **kwargs):
        return self.override()
    def tg_packet_stats(self, *args, **kwargs):
        return self.override()
    def tg_traffic_stats(self, *args, **kwargs):
        return self.override()
    def tg_interface_stats(self, **kwargs):
        return self.override()
    def tg_packet_config_buffers(self, **kwargs):
        return self.override()
    def tg_packet_config_filter(self, **kwargs):
        return self.override()
    def tg_packet_config_triggers(self, **kwargs):
        return self.override()
    def tg_convert_porthandle_to_vport(self, **kwargs):
        return self.override()
    def tg_protocol_info(self, **kwargs):
        return self.override()
    def tg_withdraw_bgp_routes(self, route_handle):
        return self.override()
    def tg_readvertise_bgp_routes(self, handle, route_handle):
        return self.override()
    def tg_emulation_bgp_config(self, **kwargs):
        return self.override()
    def tg_emulation_bgp_control(self, **kwargs):
        return self.override()
    def tg_emulation_bgp_route_config(self, **kwargs):
        return self.override()
    def tg_emulation_ospf_config(self, **kwargs):
        return self.override()
    def tg_emulation_ospf_lsa_config(self, **kwargs):
        return self.override()
    def tg_emulation_ospf_network_group_config(self, **kwargs):
        return self.override()
    def tg_emulation_ospf_topology_route_config(self, **kwargs):
        return self.override()
    def tg_emulation_igmp_control(self, **kwargs):
        return self.override()
    def tg_emulation_igmp_querier_control(self, **kwargs):
        return self.override()
    def tg_emulation_multicast_source_config(self, **kwargs):
        return self.override()

