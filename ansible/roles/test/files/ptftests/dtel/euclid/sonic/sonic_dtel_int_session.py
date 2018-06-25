from dtel import dtel_int_session
from dtel.infra import *


class SONiCDTelINTSession(dtel_int_session.DTelINTSession, FrozenClass):
    def __init__(self,
                 switch,
                 max_hop_count=8,
                 collect_switch_id=True,
                 collect_switch_ports=True,
                 collect_ig_timestamp=True,
                 collect_eg_timestamp=True,
                 collect_queue_info=True):
        super(SONiCDTelINTSession, self).__init__(
                 switch=switch,
                 max_hop_count=max_hop_count,
                 collect_switch_id=collect_switch_id,
                 collect_switch_ports=collect_switch_ports,
                 collect_ig_timestamp=collect_ig_timestamp,
                 collect_eg_timestamp=collect_eg_timestamp,
                 collect_queue_info=collect_queue_info)
        session_id = self.switch.generate_id('DTEL_INT_SESSION|INT_SESSION')
        self.hashname = 'INT_SESSION' + session_id
        keys = ['MAX_HOP_COUNT', 'COLLECT_SWITCH_ID', 'COLLECT_SWITCH_PORTS',
                'COLLECT_INGRESS_TIMESTAMP', 'COLLECT_EGRESS_TIMESTAMP', 'COLLECT_QUEUE_INFO']
        values = [max_hop_count, collect_switch_id, collect_switch_ports,
                  collect_ig_timestamp, collect_eg_timestamp, collect_queue_info]
        self.switch.redis_write('DTEL_INT_SESSION',
                                self.hashname,
                                keys,
                                values)
        self._freeze()

    def delete(self):
        self.switch.redis_delete('DTEL_INT_SESSION', self.hashname)
        super(SONiCDTelINTSession, self).delete()

    @property
    def max_hop_count(self):
        value = int(self.switch.redis_read('DTEL_INT_SESSION', self.hashname, 'MAX_HOP_COUNT'))
        dtel_int_session.DTelINTSession.max_hop_count.fset(self, value)
        return dtel_int_session.DTelINTSession.max_hop_count.fget(self)

    @max_hop_count.setter
    def max_hop_count(self, value):
        dtel_int_session.DTelINTSession.max_hop_count.fset(self, value)
        self.switch.redis_write('DTEL_INT_SESSION', self.hashname, 'MAX_HOP_COUNT', value)

    @property
    def collect_switch_id(self):
        value = self.switch.redis_read('DTEL_INT_SESSION', self.hashname, 'COLLECT_SWITCH_ID')
        dtel_int_session.DTelINTSession.collect_switch_id.fset(self, value)
        return dtel_int_session.DTelINTSession.collect_switch_id.fget(self)

    @collect_switch_id.setter
    def collect_switch_id(self, value):
        dtel_int_session.DTelINTSession.collect_switch_id.fset(self, value)
        self.switch.redis_write('DTEL_INT_SESSION', self.hashname, 'COLLECT_SWITCH_ID', value)

    @property
    def collect_switch_ports(self):
        value = self.switch.redis_read('DTEL_INT_SESSION', self.hashname, 'COLLECT_SWITCH_PORTS')
        dtel_int_session.DTelINTSession.collect_switch_ports.fset(self, value)
        return dtel_int_session.DTelINTSession.collect_switch_ports.fget(self)

    @collect_switch_ports.setter
    def collect_switch_ports(self, value):
        dtel_int_session.DTelINTSession.collect_switch_ports.fset(self, value)
        self.switch.redis_write('DTEL_INT_SESSION', self.hashname, 'COLLECT_SWITCH_PORTS', value)

    @property
    def collect_ig_timestamp(self):
        value = self.switch.redis_read('DTEL_INT_SESSION', self.hashname, 'COLLECT_INGRESS_TIMESTAMP')
        dtel_int_session.DTelINTSession.collect_ig_timestamp.fset(self, value)
        return dtel_int_session.DTelINTSession.collect_ig_timestamp.fget(self)

    @collect_ig_timestamp.setter
    def collect_ig_timestamp(self, value):
        dtel_int_session.DTelINTSession.collect_ig_timestamp.fset(self, value)
        self.switch.redis_write('DTEL_INT_SESSION', self.hashname, 'COLLECT_INGRESS_TIMESTAMP', value)

    @property
    def collect_eg_timestamp(self):
        value = self.switch.redis_read('DTEL_INT_SESSION', self.hashname, 'COLLECT_EGRESS_TIMESTAMP')
        dtel_int_session.DTelINTSession.collect_eg_timestamp.fset(self, value)
        return dtel_int_session.DTelINTSession.collect_eg_timestamp.fget(self)

    @collect_eg_timestamp.setter
    def collect_eg_timestamp(self, value):
        dtel_int_session.DTelINTSession.collect_eg_timestamp.fset(self, value)
        self.switch.redis_write('DTEL_INT_SESSION', self.hashname, 'COLLECT_EGRESS_TIMESTAMP', value)

    @property
    def collect_queue_info(self):
        value = self.switch.redis_read('DTEL_INT_SESSION', self.hashname, 'COLLECT_QUEUE_INFO')
        dtel_int_session.DTelINTSession.collect_queue_info.fset(self, value)
        return dtel_int_session.DTelINTSession.collect_queue_info.fget(self)

    @collect_queue_info.setter
    def collect_queue_info(self, value):
        dtel_int_session.DTelINTSession.collect_queue_info.fset(self, value)
        self.switch.redis_write('DTEL_INT_SESSION', self.hashname, 'COLLECT_QUEUE_INFO', value)

