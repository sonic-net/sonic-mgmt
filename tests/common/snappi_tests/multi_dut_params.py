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
            multidut_port (dict): Contains details of snappi and its peer ports
        """
        self.duthost1 = None
        self.duthost2 = None
        self.multi_dut_ports = None
        self.ingress_duthosts = []
        self.egress_duthosts = []
