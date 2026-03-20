def is_vpp_device(dut):
    return dut.facts["asic_type"] == "vpp"
