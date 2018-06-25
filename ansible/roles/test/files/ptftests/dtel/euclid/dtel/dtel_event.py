class DTelEvent(object):
    def __init__(self, report_session=None, event_type=None, dscp_value=None):
        if report_session is None:
            raise ValueError('Need to provide report_session')
        if event_type is None:
            raise ValueError('Need to provide event_type')
        if dscp_value is None:
            raise ValueError('Need to provide dscp_value')
        # Attributes
        self.switch = report_session.switch
        self._report_session = None
        self._event_type = None
        self._dscp_value = None
        # Properties
        DTelEvent.report_session.fset(self, report_session)
        DTelEvent.event_type.fset(self, event_type)
        DTelEvent.dscp_value.fset(self, dscp_value)
        # Append
        self._report_session.dtel_events.append(self)

    def delete(self):
        self._report_session.dtel_events.remove(self)

    @property
    def report_session(self):
        return self._report_session

    @report_session.setter
    def report_session(self, value):
        if value not in self.switch.dtel_report_sessions:
            raise ValueError('Unknown report_session')
        self._report_session = value

    @property
    def event_type(self):
        return self._event_type

    @event_type.setter
    def event_type(self, value):
        event_types = ['flow_state', 'flow_report_all_packets', 'flow_tcp_flag',
                       'queue_report_threshold_breach', 'queue_report_tail_drop',
                       'drop_report']
        if value not in event_types:
            raise ValueError('event_type should be one of %s' % ', '.join(event_types))
        for event in self._report_session.dtel_events:
            if event != self:
                if event.event_type == value:
                    raise ValueError("event_type already defined")
        self._event_type = value

    @property
    def dscp_value(self):
        return self._dscp_value

    @dscp_value.setter
    def dscp_value(self, value):
        if value < 0 or value >= 2**8:
            raise ValueError('dscp_value must be a uint8')
        for event in self._report_session.dtel_events:
            if event != self:
                if event.dscp_value == value:
                    raise ValueError('dscp_value already used')
        self._dscp_value = value
