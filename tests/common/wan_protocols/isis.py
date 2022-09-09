from tests.common.wan_utilities.utilities import compare_dictionaries


class LACPProtocol:
    def __init__(self, dut_handler, neighbor_device_handler):
        self.device_a = dut_handler
        self.device_b = neighbor_device_handler

    def validate_isis_adjacency(self, neighbor, expected_adjacency_ports):
        adj_result, adj_message = self.device_a.check_isis_adjacency(neighbor, expected_adjacency_ports)
        return adj_result, adj_message

    def compare_isis_database(self):
        isis_database_a = self.device_a.get_isis_database()
        isis_database_b = self.device_b.get_isis_database()
        compout = compare_dictionaries(isis_database_a, isis_database_b, "isis database dut 1", "isis database dut 2")
        if compout == "":
            return True, "ISIS Databases match between DUT 1 and DUT 2"
        else:
            return False, compout
