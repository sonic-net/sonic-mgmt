def is_barefoot_device(dut):
    return dut.facts["asic_type"] == "barefoot"
