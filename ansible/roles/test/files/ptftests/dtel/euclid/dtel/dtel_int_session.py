class DTelINTSession(object):
    def __init__(self,
                 switch,
                 max_hop_count=8,
                 collect_switch_id=True,
                 collect_switch_ports=True,
                 collect_ig_timestamp=True,
                 collect_eg_timestamp=True,
                 collect_queue_info=True):

        # Set attributes
        self.switch = switch
        self._max_hop_count = None
        self._collect_switch_id = None
        self._collect_switch_ports = None
        self._collect_ig_timestamp = None
        self._collect_eg_timestamp = None
        self._collect_queue_info = None
        # Set properties
        DTelINTSession.max_hop_count.fset(self, max_hop_count)
        DTelINTSession.collect_switch_id.fset(self, collect_switch_id)
        DTelINTSession.collect_switch_ports.fset(self, collect_switch_ports)
        DTelINTSession.collect_ig_timestamp.fset(self, collect_ig_timestamp)
        DTelINTSession.collect_eg_timestamp.fset(self, collect_eg_timestamp)
        DTelINTSession.collect_queue_info.fset(self, collect_queue_info)
        # Append
        self.switch.dtel_int_sessions.append(self)

    def delete(self):
        int_watchlist_entries = [x for watchlist in self.switch.dtel_watchlists
                                 for x in watchlist.entries if x.dtel_int_enable is not None
                                 and x.dtel_int_session == self]
        if int_watchlist_entries:
            raise RuntimeError("Cannot delete INT session because flow watchlist entries still "
                               "reference it")
        else:
            self.switch.dtel_int_sessions.remove(self)

    @property
    def max_hop_count(self):
        return self._max_hop_count

    @max_hop_count.setter
    def max_hop_count(self, value):
        if value is not None:
            if value < 1:
                raise ValueError('max_hop_count must be greater than 1')
            self._max_hop_count = int(value)

    @property
    def collect_switch_id(self):
        return self._collect_switch_id

    @collect_switch_id.setter
    def collect_switch_id(self, value):
        if value is not None:
            if not isinstance(value, bool):
                raise ValueError('collect_switch_id must be boolean')
            self._collect_switch_id = value

    @property
    def collect_switch_ports(self):
        return self._collect_switch_ports

    @collect_switch_ports.setter
    def collect_switch_ports(self, value):
        if value is not None:
            if not isinstance(value, bool):
                raise ValueError('collect_switch_ports must be boolean')
            self._collect_switch_ports = value

    @property
    def collect_ig_timestamp(self):
        return self._collect_ig_timestamp

    @collect_ig_timestamp.setter
    def collect_ig_timestamp(self, value):
        if value is not None:
            if not isinstance(value, bool):
                raise ValueError('collect_ig_timestamp must be boolean')
            self._collect_ig_timestamp = value

    @property
    def collect_eg_timestamp(self):
        return self._collect_eg_timestamp

    @collect_eg_timestamp.setter
    def collect_eg_timestamp(self, value):
        if value is not None:
            if not isinstance(value, bool):
                raise ValueError('collect_eg_timestamp must be boolean')
            self._collect_eg_timestamp = value

    @property
    def collect_queue_info(self):
        return self._collect_queue_info

    @collect_queue_info.setter
    def collect_queue_info(self, value):
        if value is not None:
            if not isinstance(value, bool):
                raise ValueError('collect_queue_info must be boolean')
            self._collect_queue_info = value
