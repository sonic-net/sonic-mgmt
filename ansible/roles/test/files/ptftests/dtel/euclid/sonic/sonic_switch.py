from dtel import switch
import redis
import time
import sonic_dtel_report_session
import sonic_dtel_int_session
import sonic_dtel_queue_report
import sonic_dtel_watchlist
from dtel.infra import *


class SONiCSwitch(switch.Switch, FrozenClass):
    def __init__(self, dtel_monitoring_type=None, dtel_switch_id=None, management_ip=None, purge=True):
        if dtel_switch_id is None:
            raise ValueError('Need to provide dtel_switch_id')
        if management_ip is None:
            raise ValueError('Need to provide management_ip')
        self.redis_client = redis.StrictRedis(host=management_ip, port=6379, db=4)
        super(SONiCSwitch, self).__init__(dtel_monitoring_type=dtel_monitoring_type,
                                          dtel_switch_id=dtel_switch_id,
                                          management_ip=management_ip)
        if purge is True:
            # cleanup any previous telemetry configuration
            self.cleanup(purge=True)
        SONiCSwitch.dtel_switch_id.fset(self, dtel_switch_id)
        self._freeze()

    def redis_write(self, table, hashname, keys, values):
        if not isinstance(keys, list):
            keys = [keys]
            values = [values]
        if len(keys) != len(values):
            raise ValueError("Each key needs a value")
        mapping = {}
        for key, value in zip(keys, values):
            if isinstance(value, bool):
                if value:
                    value = 'TRUE'
                else:
                    value = 'FALSE'
            elif isinstance(value, int):
                value = str(value)
            mapping[key] = value
        self.redis_client.hmset(table + '|' + hashname, mapping)
        time.sleep(0.01)

    def redis_delete(self, table, hashname, keys=None):
        if keys is None:
            self.redis_client.delete(table + '|' + hashname)
        else:
            if not isinstance(keys, list):
                keys = [keys]
            for key in keys:
                self.redis_client.hdel(table + '|' + hashname, key)

    def redis_read(self, table, hashname, key=None):
        if key is not None:
            redis_value = self.redis_client.hget(table + '|' + hashname, key)
        else:
            redis_value = self.redis_client.hgetall(table + '|' + hashname)
        if redis_value == 'TRUE':
            return True
        elif redis_value == 'FALSE':
            return False
        elif redis_value is None:
            return False
        else:
            return redis_value

    def generate_id(self, key_string):
        all_keys = self.redis_client.keys('*')
        ids = [0]
        for key in all_keys:
            if key_string in key:
                used_id = key.split(key_string)[1]
                if used_id:
                    ids.append(int(used_id))
        key_range = range(max(ids) + 2)
        return str(min(set(key_range) - set(ids)))

    @property
    def dtel_int_endpoint_enable(self):
        value = self.redis_read('DTEL', 'INT_ENDPOINT', 'INT_ENDPOINT')
        switch.Switch.dtel_int_endpoint_enable.fset(self, value)
        return switch.Switch.dtel_int_endpoint_enable.fget(self)

    @dtel_int_endpoint_enable.setter
    def dtel_int_endpoint_enable(self, value):
        switch.Switch.dtel_int_endpoint_enable.fset(self, value)
        if value:
            self.redis_write('DTEL', 'INT_ENDPOINT', 'INT_ENDPOINT', 'TRUE')
        else:
            self.redis_delete('DTEL', 'INT_ENDPOINT', 'INT_ENDPOINT')

    @property
    def dtel_int_transit_enable(self):
        value = self.redis_read('DTEL', 'INT_TRANSIT', 'INT_TRANSIT')
        switch.Switch.dtel_int_transit_enable.fset(self, value)
        return switch.Switch.dtel_int_transit_enable.fget(self)

    @dtel_int_transit_enable.setter
    def dtel_int_transit_enable(self, value):
        switch.Switch.dtel_int_transit_enable.fset(self, value)
        if value:
            self.redis_write('DTEL', 'INT_TRANSIT', 'INT_TRANSIT', 'TRUE')
        else:
            self.redis_delete('DTEL', 'INT_TRANSIT', 'INT_TRANSIT')

    @property
    def dtel_postcard_enable(self):
        value = self.redis_read('DTEL', 'POSTCARD', 'POSTCARD')
        switch.Switch.dtel_postcard_enable.fset(self, value)
        return switch.Switch.dtel_postcard_enable.fget(self)

    @dtel_postcard_enable.setter
    def dtel_postcard_enable(self, value):
        switch.Switch.dtel_postcard_enable.fset(self, value)
        if value:
            self.redis_write('DTEL', 'POSTCARD', 'POSTCARD', 'TRUE')
        else:
            self.redis_delete('DTEL', 'POSTCARD', 'POSTCARD')

    @property
    def dtel_drop_report_enable(self):
        value = self.redis_read('DTEL', 'DROP_REPORT', 'DROP_REPORT')
        switch.Switch.dtel_drop_report_enable.fset(self, value)
        return switch.Switch.dtel_drop_report_enable.fget(self)

    @dtel_drop_report_enable.setter
    def dtel_drop_report_enable(self, value):
        switch.Switch.dtel_drop_report_enable.fset(self, value)
        if value:
            self.redis_write('DTEL', 'DROP_REPORT', 'DROP_REPORT', 'TRUE')
        else:
            self.redis_delete('DTEL', 'DROP_REPORT', 'DROP_REPORT')

    @property
    def dtel_queue_report_enable(self):
        value = self.redis_read('DTEL', 'QUEUE_REPORT', 'QUEUE_REPORT')
        switch.Switch.dtel_queue_report_enable.fset(self, value)
        return switch.Switch.dtel_queue_report_enable.fget(self)

    @dtel_queue_report_enable.setter
    def dtel_queue_report_enable(self, value):
        switch.Switch.dtel_queue_report_enable.fset(self, value)
        if value:
            self.redis_write('DTEL', 'QUEUE_REPORT', 'QUEUE_REPORT', 'TRUE')
        else:
            self.redis_delete('DTEL', 'QUEUE_REPORT', 'QUEUE_REPORT')

    @property
    def dtel_switch_id(self):
        value = int(self.redis_read('DTEL', 'SWITCH_ID', 'SWITCH_ID'))
        switch.Switch.dtel_switch_id.fset(self, value)
        return switch.Switch.dtel_switch_id.fget(self)

    @dtel_switch_id.setter
    def dtel_switch_id(self, value):
        switch.Switch.dtel_switch_id.fset(self, value)
        self.redis_write('DTEL', 'SWITCH_ID', 'SWITCH_ID', str(value))

    @property
    def dtel_flow_state_clear_cycle(self):
        value = int(self.redis_read('DTEL', 'FLOW_STATE_CLEAR_CYCLE', 'FLOW_STATE_CLEAR_CYCLE'))
        switch.Switch.dtel_flow_state_clear_cycle.fset(self, value)
        return switch.Switch.dtel_flow_state_clear_cycle.fget(self)

    @dtel_flow_state_clear_cycle.setter
    def dtel_flow_state_clear_cycle(self, value):
        switch.Switch.dtel_flow_state_clear_cycle.fset(self, value)
        self.redis_write('DTEL', 'FLOW_STATE_CLEAR_CYCLE', 'FLOW_STATE_CLEAR_CYCLE', value)

    @property
    def dtel_latency_sensitivity(self):
        value = int(self.redis_read('DTEL', 'LATENCY_SENSITIVITY', 'LATENCY_SENSITIVITY'))
        switch.Switch.dtel_latency_sensitivity.fset(self, value)
        return switch.Switch.dtel_latency_sensitivity.fget(self)

    @dtel_latency_sensitivity.setter
    def dtel_latency_sensitivity(self, value):
        switch.Switch.dtel_latency_sensitivity.fset(self, value)
        self.redis_write('DTEL', 'LATENCY_SENSITIVITY', 'LATENCY_SENSITIVITY', value)

    @property
    def dtel_int_sink_port_list(self):
        redis_port_list = self.redis_read('DTEL', 'SINK_PORT_LIST')
        port_list = []
        for port in redis_port_list:
            port_fields = port.split('Ethernet')
            port_list.append(int(port_fields[1]))
        switch.Switch.dtel_int_sink_port_list.fset(self, swport_to_fpport(port_list))
        return switch.Switch.dtel_int_sink_port_list.fget(self)

    @dtel_int_sink_port_list.setter
    def dtel_int_sink_port_list(self, value):
        switch.Switch.dtel_int_sink_port_list.fset(self, value)
        redis_ports = []
        for port in fpport_to_swport(switch.Switch.dtel_int_sink_port_list.fget(self)):
            redis_ports.append('Ethernet' + str(port))
        if redis_ports:
            self.redis_write('DTEL', 'SINK_PORT_LIST', redis_ports, redis_ports)
        else:
            # In this case we just want to delete all ports
            self.redis_delete('DTEL', 'SINK_PORT_LIST')

    @property
    def dtel_int_l4_dscp(self):
        value = self.redis_read('DTEL', 'INT_L4_DSCP', 'INT_L4_DSCP_VALUE')
        if value is False:
            value = None
        else:
            value = int(value)
        mask = self.redis_read('DTEL', 'INT_L4_DSCP', 'INT_L4_DSCP_MASK')
        if mask is False:
            mask = None
        else:
            mask = int(mask)
        switch.Switch.dtel_int_l4_dscp.fset(self, {'value': value, 'mask': mask})
        return switch.Switch.dtel_int_l4_dscp.fget(self)

    @dtel_int_l4_dscp.setter
    def dtel_int_l4_dscp(self, value):
        if value['value'] is not None and value['value'] is not None:
            switch.Switch.dtel_int_l4_dscp.fset(self, value)
            self.redis_write('DTEL',
                             'INT_L4_DSCP',
                             ['INT_L4_DSCP_VALUE', 'INT_L4_DSCP_MASK'],
                             [str(value['value']), str(value['mask'])])

    def create_dtel_report_session(self, dst_ip_list=None, src_ip=None, udp_port=REPORT_UDP_PORT,
                                   truncate_size=REPORT_TRUNCATE_SIZE):
        if dst_ip_list is None:
            raise ValueError('Need to provide report_dst')
        if src_ip is None:
            src_ip = self.management_ip
        return sonic_dtel_report_session.SONiCDTelReportSession(self, dst_ip_list, src_ip=src_ip,
                                                                udp_port=udp_port,
                                                                truncate_size=truncate_size)

    def create_dtel_int_session(self, max_hop_count=8, collect_switch_id=True,
                                collect_switch_ports=True, collect_ig_timestamp=True,
                                collect_eg_timestamp=True, collect_queue_info=True):
        return sonic_dtel_int_session.SONiCDTelINTSession(self,
                                                          max_hop_count=max_hop_count,
                                                          collect_switch_id=collect_switch_id,
                                                          collect_switch_ports=collect_switch_ports,
                                                          collect_ig_timestamp=collect_ig_timestamp,
                                                          collect_eg_timestamp=collect_eg_timestamp,
                                                          collect_queue_info=collect_queue_info)

    def create_dtel_queue_report(self,
                                 port=None,
                                 queue_id=None,
                                 depth_threshold=None,
                                 latency_threshold=None,
                                 breach_quota=None,
                                 report_tail_drop=None):
        if port is None:
            raise ValueError('Need to provide port')
        if queue_id is None:
            raise ValueError('Need to provide queue_id')

        return sonic_dtel_queue_report.SONiCDTelQueueReport(switch=self,
                                                            port=port,
                                                            queue_id=queue_id,
                                                            depth_threshold=depth_threshold,
                                                            latency_threshold=latency_threshold,
                                                            breach_quota=breach_quota,
                                                            report_tail_drop=report_tail_drop)

    def create_dtel_watchlist(self, watchlist_type=None):
        if watchlist_type is None:
            raise ValueError('Need to provide watchlist_type')
        return sonic_dtel_watchlist.SONiCDTelWatchlist(self, watchlist_type)

    def cleanup_dtel_watchlist_entries(self, purge=False):
        if purge is True:
            entries = self.redis_client.keys('ACL_RULE|*WATCHLIST|RULE*')
            for entry in entries:
                entry_hashname = entry.split('ACL_RULE|')[1]
                table_name = 'ACL_RULE'
                self.redis_delete(table_name, entry_hashname)
        super(SONiCSwitch, self).cleanup_dtel_watchlist_entries(purge)

    def cleanup_dtel_watchlists(self, purge=False):
        if purge is True:
            self.cleanup_dtel_watchlist_entries()
        super(SONiCSwitch, self).cleanup_dtel_watchlists(purge)

    def cleanup_dtel_events(self, purge=False):
        if purge is True:
            events = self.redis_client.keys('DTEL_EVENT|EVENT*')
            for event in events:
                table_name = 'DTEL_EVENT'
                event_hashname = event.split('DTEL_EVENT|')[1]
                self.redis_delete(table_name, event_hashname)
        super(SONiCSwitch, self).cleanup_dtel_events(purge)

    def cleanup_dtel_report_sessions(self, purge=False):
        if purge is True:
            report_sessions = self.redis_client.keys('DTEL_REPORT_SESSION|REPORT_SESSION*')
            for report_session in report_sessions:
                table_name = 'DTEL_REPORT_SESSION'
                report_session_hashname = report_session.split('DTEL_REPORT_SESSION|')[1]
                self.redis_delete(table_name, report_session_hashname)
        super(SONiCSwitch, self).cleanup_dtel_report_sessions(purge)

    def cleanup_dtel_int_sessions(self, purge=False):
        if purge is True:
            int_sessions = self.redis_client.keys('DTEL_INT_SESSION|INT_SESSION*')
            for int_session in int_sessions:
                table_name = 'DTEL_INT_SESSION'
                int_session_hashname = int_session.split('DTEL_INT_SESSION|')[1]
                self.redis_delete(table_name, int_session_hashname)
        super(SONiCSwitch, self).cleanup_dtel_int_sessions(purge)

    def cleanup_dtel_queue_reports(self, purge=False):
        if purge is True:
            queue_reports = self.redis_client.keys('DTEL_QUEUE_REPORT|Ethernet*')
            for queue_report in queue_reports:
                table_name = 'DTEL_QUEUE_REPORT'
                queue_report_hashname = queue_report.split('DTEL_QUEUE_REPORT|')[1]
                self.redis_delete(table_name, queue_report_hashname)
        super(SONiCSwitch, self).cleanup_dtel_queue_reports(purge)

    def cleanup_dtel_switch_attributes(self, purge=False):
        if purge is True:
            self.dtel_int_endpoint_enable = False
            self.dtel_int_transit_enable = False
            self.dtel_postcard_enable = False
            self.dtel_drop_report_enable = False
            self.dtel_queue_report_enable = False
            self.dtel_switch_id = 0xffffffff
            self.dtel_flow_state_clear_cycle = 0
            self.dtel_latency_sensitivity = 16
            self.dtel_int_sink_port_list = []
            self._dtel_int_l4_dscp = {'value': None, 'mask': None}
