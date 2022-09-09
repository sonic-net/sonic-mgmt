class LDPProtocol:
    def __init__(self, dut_handler):
        self.dut_handler = dut_handler

    def verify_remote_ldp_sessions(self, dut):
        result, remote_ldp = self.dut_handler.check_remote_ldp_sessions(dut)
        return result, remote_ldp
