"""
The TrafficFlowConfig module allows for modular pass through of traffic params for all Snappi based tests.
"""


class TrafficFlowConfig():
    def __init__(self):
        """
        Initialize the TrafficFlowConfig class

        Params:
            data_flow_config (dict): data traffic flow configuration
                Dict values:
                    flow_name: data flow name
                    flow_dur_sec: data flow duration in seconds if applicable
                    flow_rate_percent: data flow rate in percentage if applicable
                    flow_rate_pps: data flow rate in packets per second if applicable
                    flow_rate_bps: data flow rate in bytes per second if applicable
                    flow_pkt_size: data flow packet size in bytes if applicable
                    flow_pkt_count: data flow packet count if applicable
                    flow_delay_sec: data flow delay in seconds if applicable
                    flow_traffic_type: data flow traffic type if applicable ex. data_traffic_flow.CONTINUOUS
            background_flow_config (dict): background traffic flow configuration
                Dict values:
                    flow_name: background flow name
                    flow_dur_sec: data flow duration in seconds if applicable
                    flow_rate_percent: data flow rate in percentage if applicable
                    flow_rate_pps: data flow rate in packets per second if applicable
                    flow_rate_bps: data flow rate in bytes per second if applicable
                    flow_pkt_size: data flow packet size in bytes if applicable
                    flow_pkt_count: data flow packet count if applicable
                    flow_delay_sec: data flow delay in seconds if applicable
                    flow_traffic_type: background flow traffic type if applicable ex.
                                                  background_traffic_flow.CONTINUOUS
            pause_flow_config (dict): pause traffic flow configuration
                Dict values:
                    flow_name: pause flow name
                    flow_dur_sec: data flow duration in seconds if applicable
                    flow_rate_percent: data flow rate in percentage if applicable
                    flow_rate_pps: data flow rate in packets per second if applicable
                    flow_rate_bps: data flow rate in bytes per second if applicable
                    flow_pkt_size: data flow packet size in bytes if applicable
                    flow_pkt_count: data flow packet count if applicable
                    flow_delay_sec: data flow delay in seconds if applicable
                    flow_traffic_type: pause flow traffic type if applicable ex. pause_traffic_flow.CONTINUOUS
        """
        self.data_flow_config = None
        self.background_flow_config = None
        self.pause_flow_config = None
