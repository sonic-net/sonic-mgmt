def is_broadcom_device(dut):
    return dut.facts["asic_type"] == "broadcom"


LOSSY_ONLY_HWSKUS = ['Arista-7060X6-64PE-C256S2', 'Arista-7060X6-64PE-C224O8',
                     'Arista-7060X6-64PE-B-C512S2', 'Arista-7060X6-64PE-B-C448O16']
