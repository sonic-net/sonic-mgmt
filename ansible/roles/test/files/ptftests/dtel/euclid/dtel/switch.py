from infra import *
import dtel_report_session
import dtel_int_session
import dtel_queue_report
import dtel_watchlist


class Switch(object):
    def __init__(self, dtel_monitoring_type=None, dtel_switch_id=None, management_ip=None):

        if dtel_switch_id is None:
            raise ValueError('Need to provide dtel_switch_id')
        if management_ip is None:
            raise ValueError('Need to provide management_ip')
        self.management_ip = check_ip_address(management_ip)
        self.mac_self = None
        self.ipaddr_inf = None
        self.ipaddr_nbr = None

        self.dtel_report_sessions = []
        self.dtel_int_sessions = []
        self.dtel_queue_reports = []
        self.dtel_watchlists = []

        self._dtel_monitoring_type = None
        self._dtel_int_endpoint_enable = None
        self._dtel_int_transit_enable = None
        self._dtel_postcard_enable = None
        self._dtel_drop_report_enable = None
        self._dtel_queue_report_enable = None
        self._dtel_switch_id = None # 0xffffffff
        self._dtel_flow_state_clear_cycle = None #0
        self._dtel_latency_sensitivity = None #16
        self._dtel_int_sink_port_list = [] # []
        self._dtel_int_l4_dscp = {'value': None, 'mask': None}

        Switch.dtel_switch_id.fset(self, dtel_switch_id)
        Switch.dtel_monitoring_type.fset(self, dtel_monitoring_type)

    @property
    def dtel_monitoring_type(self):
        return self._dtel_monitoring_type

    @dtel_monitoring_type.setter
    def dtel_monitoring_type(self, value):
        if self._dtel_monitoring_type is not None:
            raise ValueError('Cannot change flow monitoring type')
        if value not in ['int_endpoint', 'int_transit', 'postcard']:
            raise ValueError('Need to provide a valid flow monitoring type: \'int_endpoint\', '
                             '\'int_transit\', or \'postcard\'')
        self._dtel_monitoring_type = value

    @property
    def dtel_int_endpoint_enable(self):
        return self._dtel_int_endpoint_enable

    @dtel_int_endpoint_enable.setter
    def dtel_int_endpoint_enable(self, value):
        if self.dtel_monitoring_type != 'int_endpoint' and value is True:
            raise ValueError('Cannot enable int_endpoint on a non-INT-Endpoint switch')
        if not isinstance(value, bool):
            raise TypeError("INT endpoint should be True or False")
        if self._dtel_int_l4_dscp['value'] is None or self._dtel_int_l4_dscp['mask'] is None:
            if value is True:
                raise ValueError('dtel_int_l4_dscp must be set before enabling INT EP')
        self._dtel_int_endpoint_enable = value

    @property
    def dtel_int_transit_enable(self):
        return self._dtel_int_transit_enable

    @dtel_int_transit_enable.setter
    def dtel_int_transit_enable(self, value):
        if self.dtel_monitoring_type != 'int_transit' and value is True:
            raise ValueError('Cannot enable int_transit on a non-INT-Transit switch')
        if not isinstance(value, bool):
            raise TypeError("INT transit should be True or False")
        if self._dtel_int_l4_dscp['value'] is None or self._dtel_int_l4_dscp['mask'] is None:
            if value is True:
                raise ValueError('dtel_int_l4_dscp must be set before enabling INT Transit')
        self._dtel_int_transit_enable = value

    @property
    def dtel_postcard_enable(self):
        return self._dtel_postcard_enable

    @dtel_postcard_enable.setter
    def dtel_postcard_enable(self, value):
        if self.dtel_monitoring_type != 'postcard' and value is True:
            raise ValueError('Cannot enable postcard on a non-Postcard switch')
        if not isinstance(value, bool):
            raise TypeError("Postcard should be True or False")
        self._dtel_postcard_enable = value

    @property
    def dtel_drop_report_enable(self):
        return self._dtel_drop_report_enable

    @dtel_drop_report_enable.setter
    def dtel_drop_report_enable(self, value):
        if not isinstance(value, bool):
            raise TypeError("Drop Report should be True or False")
        self._dtel_drop_report_enable = value

    @property
    def dtel_queue_report_enable(self):
        return self._dtel_queue_report_enable

    @dtel_queue_report_enable.setter
    def dtel_queue_report_enable(self, value):
        if not isinstance(value, bool):
            raise TypeError("Queue Report should be True or False")
        self._dtel_queue_report_enable = value

    @property
    def dtel_switch_id(self):
        return self._dtel_switch_id

    @dtel_switch_id.setter
    def dtel_switch_id(self, value):
        if int(value) < 0 or int(value) >= 2**32:
            raise ValueError("Switch ID must be a uint32")
        self._dtel_switch_id = value

    @property
    def dtel_flow_state_clear_cycle(self):
        return self._dtel_flow_state_clear_cycle

    @dtel_flow_state_clear_cycle.setter
    def dtel_flow_state_clear_cycle(self, value):
        if int(value) < 0 or int(value) >= 2**16:
            raise ValueError("Flow State Clear Cycle must be a uint16")
        self._dtel_flow_state_clear_cycle = value

    @property
    def dtel_latency_sensitivity(self):
        return self._dtel_latency_sensitivity

    @dtel_latency_sensitivity.setter
    def dtel_latency_sensitivity(self, value):
        if int(value) < 0 or int(value) >= 2**16:
            raise ValueError("Latency Sensitivity must be a uint16")
        self._dtel_latency_sensitivity = value

    @property
    def dtel_int_sink_port_list(self):
        return swport_to_fpport(self._dtel_int_sink_port_list)

    @dtel_int_sink_port_list.setter
    def dtel_int_sink_port_list(self, value):
        self._dtel_int_sink_port_list = fpport_to_swport(value)

    @property
    def dtel_int_l4_dscp(self):
        return self._dtel_int_l4_dscp

    @dtel_int_l4_dscp.setter
    def dtel_int_l4_dscp(self, value):
        if value['value'] < 0 or value['value'] > 2**8 or not isinstance(value['value'], int):
            if value['value'] is not None:
                raise ValueError('INT DSCP value should be a uint8')
        if value['mask'] < 0 or value['mask'] > 2**8 or not isinstance(value['mask'], int):
            if value['mask'] is not None:
                raise ValueError('INT DSCP mask should be a uint8')
        self._dtel_int_l4_dscp['value'] = value['value']
        self._dtel_int_l4_dscp['mask'] = value['mask']

    def create_dtel_report_session(self, dst_ip_list=None, src_ip=None, udp_port=REPORT_UDP_PORT,
                                   truncate_size=REPORT_TRUNCATE_SIZE):
        if dst_ip_list is None:
            raise ValueError('Need to provide report_dst')
        if src_ip is None:
            src_ip = self.management_ip
        return dtel_report_session.DTelReportSession(self, dst_ip_list, src_ip=src_ip, udp_port=udp_port,
                                                     truncate_size=truncate_size)

    def create_dtel_int_session(self, max_hop_count=8, collect_switch_id=True,
                                collect_switch_ports=True, collect_ig_timestamp=True,
                                collect_eg_timestamp=True, collect_queue_info=True):
        return dtel_int_session.DTelINTSession(self,
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
        return dtel_queue_report.DTelQueueReport(switch=self,
                                                 port=port,
                                                 queue_id=queue_id,
                                                 depth_threshold=depth_threshold,
                                                 latency_threshold=latency_threshold,
                                                 breach_quota=breach_quota,
                                                 report_tail_drop=report_tail_drop)

    def create_dtel_watchlist(self, watchlist_type=None):
        if watchlist_type is None:
            raise ValueError('Need to provide watchlist_type')
        return dtel_watchlist.DTelWatchlist(self, watchlist_type)

    def cleanup_dtel_watchlist_entries(self, purge=False):
        if purge is True:
            for watchlist in self.dtel_watchlists:
                watchlist.entries = []
        else:
            for watchlist in self.dtel_watchlists:
                for entry in list(watchlist.entries):
                    entry.delete()

    def cleanup_dtel_watchlists(self, purge=False):
        if purge is True:
            self.dtel_watchlists = []
        else:
            for watchlist in list(self.dtel_watchlists):
                watchlist.delete()

    def cleanup_dtel_events(self, purge=False):
        if purge is True:
            for report_session in self.dtel_report_sessions:
                report_session.dtel_events = []
        else:
            for report_session in self.dtel_report_sessions:
                for event in list(report_session.dtel_events):
                    event.delete()

    def cleanup_dtel_report_sessions(self, purge=False):
        if purge is True:
            self.dtel_report_sessions = []
        else:
            for report_session in list(self.dtel_report_sessions):
                report_session.delete()

    def cleanup_dtel_int_sessions(self, purge=False):
        if purge is True:
            self.dtel_int_sessions = []
        else:
            for int_session in list(self.dtel_int_sessions):
                int_session.delete()

    def cleanup_dtel_queue_reports(self, purge=False):
        if purge is True:
            self.dtel_queue_reports = []
        else:
            for queue_report in list(self.dtel_queue_reports):
                queue_report.delete()

    def cleanup_dtel_switch_attributes(self, purge=False):
        if purge:
            self._dtel_int_endpoint_enable = False
            self._dtel_int_transit_enable = False
            self._dtel_postcard_enable = False
            self._dtel_drop_report_enable = False
            self._dtel_queue_report_enable = False
            self._dtel_switch_id = 0xffffffff
            self._dtel_flow_state_clear_cycle = 0
            self._dtel_latency_sensitivity = 30
            self._dtel_int_sink_port_list = []
            self._dtel_int_l4_dscp = {'value': None, 'mask': None}

    def cleanup(self, purge=False):
        self.cleanup_dtel_watchlist_entries(purge=purge)
        self.cleanup_dtel_watchlists(purge=purge)
        self.cleanup_dtel_events(purge=purge)
        self.cleanup_dtel_report_sessions(purge=purge)
        self.cleanup_dtel_int_sessions(purge=purge)
        self.cleanup_dtel_queue_reports(purge=purge)
        self.cleanup_dtel_switch_attributes(purge=purge)
