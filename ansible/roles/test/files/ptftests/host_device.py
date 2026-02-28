class HostDevice(object):

    @staticmethod
    def getHostDeviceInstance(neighbor_type, *args, **kwargs):
        import arista
        import sonic
        if "eos" in neighbor_type:
            return arista.Arista(*args, **kwargs)
        elif "sonic" in neighbor_type:
            return sonic.Sonic(*args, **kwargs)
        else:
            raise NotImplementedError

    def connect(self):
        raise NotImplementedError

    def disconect(self):
        raise NotImplementedError

    def run(self):
        raise NotImplementedError

    def verify_neigh_lag_no_flap(self):
        raise NotImplementedError

    def change_bgp_neigh_state(self, bgp_info, is_up=True):
        raise NotImplementedError

    def change_bgp_route(self, cfg_map):
        raise NotImplementedError

    def verify_bgp_neigh_state(self, dut=None, state="Active"):
        raise NotImplementedError
