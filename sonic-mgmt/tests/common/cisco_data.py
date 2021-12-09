def is_cisco_device(dut):
    return dut.facts["asic_type"] == "cisco-8000"
