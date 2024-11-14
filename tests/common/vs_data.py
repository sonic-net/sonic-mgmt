def is_vs_device(dut):
    return dut.facts["asic_type"] == "vs"
