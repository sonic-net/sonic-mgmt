"""
The MultiDUTParams module allows for modular pass through of multi params for all multidut snappi_tests cases
"""


class MultiDUTParams():
    def __init__(self):
        """
        Initializes the MultiDUTParams class

        Params:
            duthost1 (obj): Duthost1 object
            duthost2 (obj): Duthost2 object
            duthost3 (obj): Duthost3 object (Supervisor for chassis topology)
            multidut_port (dict): Contains details of snappi and its peer ports
        """
        self.duthost1 = None
        self.duthost2 = None
        self.duthost3 = None
        self.multi_dut_ports = None
        self.hw_platform = None
        self.vendor = None
        self.t1_hostname = None
        self.host_name = None
        self.ingress_duthosts = []
        self.egress_duthosts = []
        self.flap_details = None
        self.BLACKOUT_PERCENTAGES = []
        self.process_names = {}
