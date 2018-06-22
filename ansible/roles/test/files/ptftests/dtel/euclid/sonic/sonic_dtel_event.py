from dtel import dtel_event
from dtel.infra import *


class SONiCDTelEvent(dtel_event.DTelEvent, FrozenClass):
    def __init__(self, report_session=None, event_type=None, dscp_value=None):
        if report_session is None:
            raise ValueError('Need to provide report_session')
        if event_type is None:
            raise ValueError('Need to provide event_type')
        if dscp_value is None:
            raise ValueError('Need to provide dscp_value')
        event_strings = {'flow_state': 'EVENT_TYPE_FLOW_STATE',
                         'flow_report_all_packets': 'EVENT_TYPE_FLOW_REPORT_ALL_PACKETS',
                         'flow_tcp_flag': 'EVENT_TYPE_FLOW_TCPFLAG',
                         'queue_report_threshold_breach': 'EVENT_TYPE_QUEUE_REPORT_THRESHOLD_BREACH',
                         'queue_report_tail_drop': 'EVENT_TYPE_QUEUE_REPORT_TAIL_DROP',
                         'drop_report': 'EVENT_TYPE_DROP_REPORT'}
        self.hashname = event_strings[event_type]
        session_hashname = report_session.hashname
        super(SONiCDTelEvent, self).__init__(report_session, event_type, dscp_value)
        keys = ['EVENT_REPORT_SESSION', 'EVENT_DSCP_VALUE']
        values = [session_hashname, str(dtel_event.DTelEvent.dscp_value.fget(self))]
        self.switch.redis_write('DTEL_EVENT',
                                self.hashname,
                                keys,
                                values)
        self._freeze()

    def delete(self):
        self.switch.redis_delete('DTEL_EVENT', self.hashname)
        super(SONiCDTelEvent, self).delete()

    @property
    def report_session(self):
        value = self.switch.redis_read('DTEL_EVENT', self.hashname, 'EVENT_REPORT_SESSION')
        for report_session in self.switch.dtel_report_sessions:
            if report_session.hashname == value:
                break
        else:
            report_session = None
        dtel_event.DTelEvent.report_session.fset(self, report_session)
        return dtel_event.DTelEvent.report_session.fget(self)

    @report_session.setter
    def report_session(self, value):
        dtel_event.DTelEvent.report_session.fset(self, value)
        session_name = value.hashname
        self.switch.redis_write('DTEL_EVENT', self.hashname, 'EVENT_REPORT_SESSION', session_name)

    @property
    def dscp_value(self):
        value = int(self.switch.redis_read('DTEL_EVENT', self.hashname, 'EVENT_DSCP_VALUE'))
        dtel_event.DTelEvent.dscp_value.fset(self, value)
        return dtel_event.DTelEvent.dscp_value.fget(self)

    @dscp_value.setter
    def dscp_value(self, value):
        dtel_event.DTelEvent.dscp_value.fset(self, value)
        self.switch.redis_write('DTEL_EVENT', self.hashname, 'EVENT_DSCP_VALUE', value)
