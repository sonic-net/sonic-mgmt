def is_marvell_device(dut):
    return dut.facts["asic_type"] == "marvell"
