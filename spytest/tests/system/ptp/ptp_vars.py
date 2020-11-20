from spytest.dicts import SpyTestDict

data = SpyTestDict()

#Calnex Controller 
data.clx_config_file_path = 'C:/calnex/paragon-x/config/'
data.s2_filename = 'calnex-ms-bc-ieee-l2-mc.cst'

data.parent_clock_id = '000000.0000.000001'
data.gm_clock_id = '000000.0000.000001'
data.gm_priority1 = 128
data.gm_priority2 = 128

data.mode_bc = 'boundary-clock'
data.mode_tc_e2e = 'end-to-end-transparent-clock'
data.domain_1 = 24
data.domain_profile_1588 = 'ieee1588'
data.priority1 = 255
data.priority2 = 255

data.mode_bc_show = 'BC'
data.mode_tc_e2e_show = 'E2E_TC'

data.role_master = 'master'
data.role_slave = 'slave'
data.role_none = 'none'
data.role_faulty = 'faulty'







