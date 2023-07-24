
skip_testbeds_list = [
    'azd',
    '3164',
    '8101',
    '8102',
    'ec9516',
    '-t2-',
    'testbed-bjw-can-720dt-3',
    'testbed-bjw-can-7050qx-2',
    'vms61-dual-mixed-8102'
]

curr_convert_to_trusty_images_dict = {
    '$(BJW_IMAGE_BFN_INTERNAL)'              :  {'trusty_image' : '$(BJW_TRUSTY_IMAGE_BFN_INTERNAL)'             , 'image' : 'sonic-barefoot.bin',            'vendor' : 'barefoot'},   
    '$(BJW_IMAGE_BRCM_ABOOT_202205)'         :  {'trusty_image' : '$(BJW_TRUSTY_IMAGE_BRCM_ABOOT_202205)'        , 'image' : 'sonic-aboot-broadcom.swi',      'vendor' : 'broadcom'},
    '$(BJW_IMAGE_BRCM_ABOOT_202205_SLIM)'    :  {'trusty_image' : '$(BJW_TRUSTY_IMAGE_BRCM_ABOOT_202205_SLIM)'   , 'image' : 'sonic-aboot-broadcom-slim.swi', 'vendor' : 'broadcom'},
    '$(BJW_IMAGE_MARVELL_202205)'            :  {'trusty_image' : '$(BJW_TRUSTY_IMAGE_MARVELL_202205)'           , 'image' : 'sonic-marvell-armhf.bin',       'vendor' : 'marvell-armhf'},
    '$(BJW_IMAGE_MLNX_202012)'               :  {'trusty_image' : '$(BJW_TRUSTY_IMAGE_MLNX_202012)'              , 'image' : 'sonic-mellanox.bin',            'vendor' : 'mellanox'},
    '$(IMAGE_BRCM_201911)'                   :  {'trusty_image' : '$(TRUSTY_IMAGE_BRCM_201911)'                  , 'image' : 'sonic-broadcom.bin',            'vendor' : 'broadcom'},
    '$(IMAGE_BRCM_202012)'                   :  {'trusty_image' : '$(TRUSTY_IMAGE_BRCM_202012)'                  , 'image' : 'sonic-broadcom.bin',            'vendor' : 'broadcom'},
    '$(IMAGE_BRCM_202012_SLIM)'              :  {'trusty_image' : '$(TRUSTY_IMAGE_BRCM_202012_SLIM)'             , 'image' : 'sonic-broadcom-slim.bin',       'vendor' : 'broadcom'},
    '$(IMAGE_BRCM_202205)'                   :  {'trusty_image' : '$(TRUSTY_IMAGE_BRCM_202205)'                  , 'image' : 'sonic-broadcom.bin',            'vendor' : 'broadcom'},
    '$(IMAGE_BRCM_ABOOT_201911)'             :  {'trusty_image' : '$(TRUSTY_IMAGE_BRCM_ABOOT_201911)'            , 'image' : 'sonic-aboot-broadcom.swi',      'vendor' : 'broadcom'},
    '$(IMAGE_BRCM_ABOOT_202012)'             :  {'trusty_image' : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012)'            , 'image' : 'sonic-aboot-broadcom.swi',      'vendor' : 'broadcom'},
    '$(IMAGE_BRCM_ABOOT_202012_SLIM)'        :  {'trusty_image' : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012_SLIM)'       , 'image' : 'sonic-aboot-broadcom-slim.swi', 'vendor' : 'broadcom'},
    '$(IMAGE_BRCM_ABOOT_202205)'             :  {'trusty_image' : '$(TRUSTY_IMAGE_BRCM_ABOOT_202205)'            , 'image' : 'sonic-aboot-broadcom.swi',      'vendor' : 'broadcom'},
    '$(IMAGE_BRCM_ABOOT_202205_SLIM)'        :  {'trusty_image' : '$(TRUSTY_IMAGE_BRCM_ABOOT_202205_SLIM)'       , 'image' : 'sonic-aboot-broadcom-slim.swi', 'vendor' : 'broadcom'},
    '$(IMAGE_BRCM_ABOOT_DNX_CHASSIS_202205)' :  {'trusty_image' : '$(TRUSTY_IMAGE_BRCM_ABOOT_DNX_CHASSIS_202205)', 'image' : 'sonic-aboot-broadcom-dnx.swi',  'vendor' : 'broadcom'},
    '$(IMAGE_BRCM_DNX_ABOOT_PUBLIC)'         :  {'trusty_image' : '$(TRUSTY_IMAGE_BRCM_DNX_ABOOT_PUBLIC)'        , 'image' : 'sonic-aboot-broadcom-dnx.swi',  'vendor' : 'broadcom'},
    '$(IMAGE_CISCO_ABOOT_202012)'            :  {'trusty_image' : '$(TRUSTY_IMAGE_CISCO_ABOOT_202012)'           , 'image' : 'sonic-cisco-8000.bin',          'vendor' : 'cisco-8000'},
    '$(IMAGE_CISCO_ABOOT_202205)'            :  {'trusty_image' : '$(TRUSTY_IMAGE_CISCO_ABOOT_202205)'           , 'image' : 'sonic-cisco-8000-nosec.bin',    'vendor' : 'cisco-8000'},
    '$(IMAGE_MARVELL_202012)'                :  {'trusty_image' : '$(TRUSTY_IMAGE_MARVELL_202012)'               , 'image' : 'sonic-marvell-armhf.bin',       'vendor' : 'marvell-armhf'},
    '$(IMAGE_MARVELL_202205)'                :  {'trusty_image' : '$(TRUSTY_IMAGE_MARVELL_202205)'               , 'image' : 'sonic-marvell-armhf.bin',       'vendor' : 'marvell-armhf'},
    '$(IMAGE_MLNX_201911)'                   :  {'trusty_image' : '$(TRUSTY_IMAGE_MLNX_201911)'                  , 'image' : 'sonic-mellanox.bin',            'vendor' : 'mellanox'},
    '$(IMAGE_MLNX_202012)'                   :  {'trusty_image' : '$(TRUSTY_IMAGE_MLNX_202012)'                  , 'image' : 'sonic-mellanox.bin',            'vendor' : 'mellanox'},
    '$(IMAGE_MLNX_202205)'                   :  {'trusty_image' : '$(TRUSTY_IMAGE_MLNX_202205)'                  , 'image' : 'sonic-mellanox.bin',            'vendor' : 'mellanox'},
}


trusty_images_url = {
    'testbed-bjw-can-2700-1'   : '$(BJW_TRUSTY_IMAGE_MLNX_202012)',
    'testbed-bjw-can-7050qx-1' : '$(BJW_TRUSTY_IMAGE_BRCM_ABOOT_202205_SLIM)',
    'testbed-bjw-can-720dt-1'  : '$(BJW_TRUSTY_IMAGE_BRCM_ABOOT_202205)',
    'testbed-bjw-can-720dt-2'  : '$(BJW_TRUSTY_IMAGE_BRCM_ABOOT_202205)',
    'testbed-bjw-can-720dt-3'  : '$(BJW_TRUSTY_IMAGE_BRCM_ABOOT_202205)',
    'testbed-bjw-can-7215-1'   : '$(BJW_TRUSTY_IMAGE_MARVELL_202205)',
    'testbed-bjw-can-7215-11'  : '$(BJW_TRUSTY_IMAGE_MARVELL_202205)',
    'testbed-bjw-can-7215-6'   : '$(BJW_TRUSTY_IMAGE_MARVELL_202205)',
    'testbed-str-e1031-acs-1'  : '$(TRUSTY_IMAGE_BRCM_202012_SLIM)',
    'testbed-str-e1031-acs-3'  : '$(TRUSTY_IMAGE_BRCM_202012_SLIM)',
    'testbed-str2-7215-acs-1'  : '$(TRUSTY_IMAGE_MARVELL_202012)',
    'testbed-str2-7215-acs-3'  : '$(TRUSTY_IMAGE_MARVELL_202205)',
    'vms1-8'                   : '$(TRUSTY_IMAGE_MLNX_201911)',
    'vms1-t1-2700'             : '$(TRUSTY_IMAGE_MLNX_202205)',
    'vms11-2-t0'               : '$(TRUSTY_IMAGE_MLNX_202012)',
    'vms11-t0-on-4'            : '$(TRUSTY_IMAGE_BRCM_202012)',
    'vms12-t0-3800'            : '$(TRUSTY_IMAGE_MLNX_202012)',
    'vms13-4-t0'               : '$(TRUSTY_IMAGE_BRCM_202012)',
    'vms13-5-t1-lag'           : '$(TRUSTY_IMAGE_BRCM_202012)',
    'vms18-t0-7050qx-acs-02'   : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012_SLIM)',
    'vms18-t1-7050qx-acs-03'   : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012_SLIM)',
    'vms18-t1-msn4600c-acs-1'  : '$(TRUSTY_IMAGE_MLNX_202205)',
    'vms2-2-t0-2700'           : '$(TRUSTY_IMAGE_MLNX_201911)',
    'vms2-4-t0-2700'           : '$(TRUSTY_IMAGE_MLNX_201911)',
    'vms2-t1-7260-7'           : '$(TRUSTY_IMAGE_BRCM_ABOOT_202205)',
    'vms20-t0-7050cx3-1'       : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012)',
    'vms20-t0-7050cx3-2'       : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012)',
    'vms20-t0-ixia-2'          : '$(TRUSTY_IMAGE_BRCM_ABOOT_201911)',
    'vms20-t0-sn3800-2'        : '$(TRUSTY_IMAGE_MLNX_201911)',
    'vms20-t1-7050cx3-3'       : '$(TRUSTY_IMAGE_BRCM_ABOOT_202205)',
    'vms20-t1-dx010-6'         : '$(TRUSTY_IMAGE_BRCM_202205)',
    'vms21-dual-t0-7050-3'     : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012)',
    'vms21-dual-t0-7260'       : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012)',
    'vms21-t0-2700'            : '$(TRUSTY_IMAGE_MLNX_202012)',
    'vms21-t0-z9332f-02'       : '$(TRUSTY_IMAGE_BRCM_202012)',
    'vms21-t1-2700-2'          : '$(TRUSTY_IMAGE_MLNX_202205)',
    'vms21-t1-8101-02'         : '$(TRUSTY_IMAGE_CISCO_ABOOT_202205)',
    'vms21-t1-8102-01'         : '$(TRUSTY_IMAGE_CISCO_ABOOT_202012)',
    'vms24-dual-t0-7050-1'     : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012)',
    'vms24-dual-t0-7050-2'     : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012)',
    'vms24-t0-7260-2'          : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012)',
    'vms24-t1-7050qx-acs-01'   : '$(TRUSTY_IMAGE_BRCM_ABOOT_202205_SLIM)',
    'vms28-dual-t0-7260'       : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012)',
    'vms28-dual-t0-8102'       : '$(TRUSTY_IMAGE_CISCO_ABOOT_202012)',
    'vms28-t0-4600c-03'        : '$(TRUSTY_IMAGE_MLNX_202012)',
    'vms28-t0-4600c-04'        : '$(TRUSTY_IMAGE_MLNX_202012)',
    'vms28-t0-7280-4'          : '$(TRUSTY_IMAGE_BRCM_DNX_ABOOT_PUBLIC)',
    'vms28-t1-8102-02'         : '$(TRUSTY_IMAGE_CISCO_ABOOT_202012)',
    'vms3-t1-7280'             : '$(TRUSTY_IMAGE_BRCM_ABOOT_DNX_CHASSIS_202205)',
    'vms3-t1-dx010-1'          : '$(TRUSTY_IMAGE_BRCM_202205)',
    'vms6-t0-7060'             : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012_SLIM)',
    'vms6-t1-7060'             : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012_SLIM)',
    'vms63-t0-7060-1'          : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012_SLIM)',
    'vms63-t0-7060-2'          : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012_SLIM)',
    'vms63-t1-7060-3'          : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012_SLIM)',
    'vms7-t0-4600c-2'          : '$(TRUSTY_IMAGE_MLNX_202205)',
    'vms7-t0-7260-1'           : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012)',
    'vms7-t0-7260-2'           : '$(TRUSTY_IMAGE_BRCM_ABOOT_202012)',
    'vms7-t0-dx010-4'          : '$(TRUSTY_IMAGE_BRCM_202012)',
    'vms7-t0-dx010-5'          : '$(TRUSTY_IMAGE_BRCM_202012)',
    'vms7-t0-s6100'            : '$(TRUSTY_IMAGE_BRCM_202012)',
    'vms7-t0-s6100-4'          : '$(TRUSTY_IMAGE_BRCM_202012)',
    'vms7-t1-s6100'            : '$(TRUSTY_IMAGE_BRCM_202205)',
    'vmsvc1-dual-t0-7050-1'    : '$(TRUSTY_IMAGE_BRCM_ABOOT_202205)',
    'vmsvc1-dual-t0-7050-2'    : '$(TRUSTY_IMAGE_BRCM_ABOOT_202205)'
}

pipeline_testbeds = ['testbed-bjw-can-2700-1','testbed-bjw-can-7050qx-1','testbed-bjw-can-720dt-1','testbed-bjw-can-720dt-2','testbed-bjw-can-720dt-3',
                     'testbed-bjw-can-7215-1','testbed-bjw-can-7215-11','testbed-bjw-can-7215-6','testbed-str-e1031-acs-1','testbed-str-e1031-acs-3',
                     'testbed-str2-7215-acs-1','testbed-str2-7215-acs-3','vms1-8','vms1-t1-2700','vms11-2-t0','vms11-t0-on-4','vms12-t0-3800',
                     'vms13-4-t0','vms13-5-t1-lag','vms18-t0-7050qx-acs-02','vms18-t1-7050qx-acs-03','vms18-t1-msn4600c-acs-1','vms2-2-t0-2700',
                     'vms2-4-t0-2700','vms2-t1-7260-7','vms20-t0-7050cx3-1','vms20-t0-7050cx3-2','vms20-t0-ixia-2','vms20-t0-sn3800-2','vms20-t1-7050cx3-3',
                     'vms20-t1-dx010-6','vms21-dual-t0-7050-3','vms21-dual-t0-7260','vms21-t0-2700','vms21-t0-z9332f-02','vms21-t1-2700-2','vms21-t1-8101-02',
                     'vms21-t1-8102-01','vms24-dual-t0-7050-1','vms24-dual-t0-7050-2','vms24-t0-7260-2','vms24-t1-7050qx-acs-01','vms28-dual-t0-7260',
                     'vms28-dual-t0-8102','vms28-t0-4600c-03','vms28-t0-4600c-04','vms28-t0-7280-4','vms28-t1-8102-02','vms3-t1-7280','vms3-t1-dx010-1',
                     'vms6-t0-7060','vms6-t1-7060','vms63-t0-7060-1','vms63-t0-7060-2','vms63-t1-7060-3','vms7-t0-4600c-2','vms7-t0-7260-1','vms7-t0-7260-2',
                     'vms7-t0-dx010-4','vms7-t0-dx010-5','vms7-t0-s6100','vms7-t0-s6100-4','vms7-t1-s6100','vmsvc1-dual-t0-7050-1','vmsvc1-dual-t0-7050-2']


'''
# get latest pipeline config 
    pipeline_analyzer.create_branch_pipeline_list('internal')
    pipeline_analyzer.create_branch_pipeline_list('master')
    pipeline_analyzer.create_branch_pipeline_list('internal-202205')
    pipeline_analyzer.create_branch_pipeline_list('internal-202012')
'''
nightly_pipeline_202012 = {
    1 : 'vms6-t0-7060.1.202012',
    2 : 'vms7-t0-7260-2.202012',
    3 : 'vms24-t0-7260-2.202012',
    4 : 'vms20-t0-7050cx3-1.202012',
    5 : 'vms18-t0-7050qx-acs-02.202012',
    6 : 'vms18-t1-7050qx-acs-03.202012',
    7 : 'vms21-dual-t0-7050-3.202012',
    8 : 'vms20-t0-7050cx3-2.202012',
    9 : 'vms6-t0-7060.2.202012',
    10 : 'vms24-dual-t0-7050-2.202012',
    11 : 'vms21-dual-t0-7260.202012',
    12 : 'vms28-dual-t0-7260.202012',
    13 : 'testbed-bjw-can-7050qx-2.1.202012',
    14 : 'testbed-bjw-can-7050qx-2.2.202012',
    15 : 'vms63-t0-7060-1-non-platform.202012',
    16 : 'vms63-t0-7060-2-platform.202012',
    17 : 'vms3-t1-dx010-1.202012',
    18 : 'vms7-t0-dx010-4.202012',
    19 : 'vms7-t0-dx010-5.202012',
    20 : 'vms20-t1-dx010-6-platform.202012',
    21 : 'vms20-t1-dx010-6-non-platform.202012',
    22 : '8102-t1-vms21-1.202012',
    23 : '8102-t1-vms61-01.202012',
    24 : 'vms20-t0-sn3800-2-metadata_tests.201911',
    25 : 'vms2-2-t0-2700',
    26 : 'vms12-t0-3800-platform_tests.201911',
    27 : 'vms20-t0-sn3800-2.201911',
}

nightly_pipeline_202205 = {
    1 : 'vms24-t1-7050qx-acs-01-copp-qos.202205',
    2 : 'vms20-t1-7050cx3-3-platform.202205',
    3 : 'vms21-dual-t0-7260.202205',
    4 : 'vms6-t1-7060-full.202205',
    5 : 'vms28-dual-t0-7260.202205',
    6 : 'vms24-t1-7050qx-acs-0-full.202205',
    7 : 'vms2-t1-7260-7-non-platform.202205',
    8 : 'vms21-dual-t0-7050-3.202205',
    9 : 'vms24-dual-t0-7050-2.202205',
    10 : 'vmsvc1-dual-t0-7050-1',
    11 : 'vmsvc1-dual-t0-7050-2',
    12 : 'vmsvc1-dual-t0-7050-2-regular',
    13 : 'testbed-bjw-can-720dt-1',
    14 : 'vms24-dual-t0-7050-1.202205',
    15 : 'testbed-bjw-can-720dt-2',
    16 : 'vms20-t1-7050cx3-3-non-platform.202205',
    17 : 'vms6-t1-7060-copp-qos.202205',
    18 : 'testbed-bjw-can-7050qx-1-full.202205',
    19 : 'testbed-bjw-can-7050qx-1-copp-qos.202205',
    20 : 'testbed-bjw-can-720dt-3.202205',
    21 : 'testbed-bjw-can-720dt-4.202205',
    22 : 'vms63-t1-7060-3-copp-qos.202205',
    23 : 'vms63-t1-7060-3-full.202205',
    24 : 'vms2-t1-7260-7-platform.202205',
    25 : 'vms24-dual-t0-7050-1-regular.202205',
    26 : '8102-t1-vms28-1.202205',
    27 : '8102-dual-vms28-1.SKIP-dualIO',
    28 : 'vms21-t1-8101-02.202205',
    29 : '8102-t0-vms61-01.202205',
    30 : 'vms61-t1-8101-02-O8C48-202205',
    31 : 'vms61-t1-8101-8x400G+48x100G-202205',
    32 : '8102-mixed-vms61-1.SKIP-dualio',
    33 : '8102-dual-vms28-2.dualio',
    34 : '8102-mixed-vms61-2.dualio',
    35 : 'vms63-t1-8111-02.202205',
    36 : '8102-t1-bjw-01',
    37 : 'vms63-t1-8111-01.202205',
    38 : 'vms7-t1-s6100-non-platform.202205',
    39 : 'vms7-t1-s6100-platform.202205',
    40 : 'vms7-t0-4600c-2.202205',
    41 : 'vms20-t0-sn3800-2.202205',
    42 : 'vms21-t0-2700-non-platform_tests.202205',
    43 : 'vms1-t1-2700-platform_tests.202205',
    44 : 'vms1-8-t1-2700.202205',
    45 : 'vms12-t0-3800-platform_tests.202205',
    46 : 'vms18-t1-msn4600c-acs-1.202205',
    47 : 'vms21-t1-2700-2-non-platform_tests.202205',
    48 : 'vms11-2-t0-2700-2-platform_tests.202205',
    49 : 'vms12-t0-8-lag-2700-non-platform_tests.202205',
    50 : 'vms12-t0-8-lag-2700-platform_tests.202205',
    51 : 'vms63-t1-4600-5.202205',
    52 : 'testbed-bjw-can-t0-4600c-1.202205',
    53 : 'testbed-bjw-can-t0-4600c-1-platform_tests.202205',
    54 : 'bjw-can-2700-2-non-platform_cq_tests.202205',
    55 : 'bjw-can-2700-2-platform_cq_tests.202205',
    56 : 'testbed-str2-7215-acs-3.202205',
    57 : 'testbed-bjw-can-7215-1.202205',
    58 : 'testbed-bjw-can-7215-6.202205',
    59 : 'testbed-bjw-can-7215-11.202205',
}

nightly_pipeline_internal = {
    1 : 'vms7-t0-7260-2.internal',
    2 : 'vms24-t0-7260-2.internal',
    3 : 'vms2-t1-7260-7.internal',
    4 : 'vms21-dual-t0-7050-3.internal',
    5 : 'vms20-t0-7050cx3-1.internal',
    6 : 'vms20-t0-7050cx3-2.internal',
    7 : 'vms20-t1-7050cx3-3-platform.internal',
    8 : 'vms21-dual-t0-7260.internal',
    9 : 'vms24-dual-t0-7050-2.internal',
    10 : 'vms28-dual-t0-7260.internal',
    11 : 'vms20-t1-7050cx3-3-non-platform.internal',
    12 : 'vms7-t0-dx010-4.internal',
    13 : 'vms7-t0-dx010-5.internal',
    14 : 'vms3-t1-dx010-1.internal',
    15 : 'vms7-t1-s6100-platform.internal',
    16 : 'vms7-t1-s6100-non-platform.internal',
    17 : 'vms12-t0-3800-platform_tests.internal',
    18 : 'vms18-t1-msn4600c-acs-1.internal',
}

nightly_pipeline_master = {
    1 : 'vms20-t0-7050cx3-1.master',
    2 : 'vms20-t1-7050cx3-3-platform.master',
    3 : 'vms2-t1-7260-7.master',
    4 : 'vms20-t0-7050cx3-2.master',
    5 : 'vms20-t1-7050cx3-3-non-platform.master',
    6 : 'vms21-dual-t0-7050-3.master',
    7 : 'vms24-dual-t0-7050-2.master',
    8 : 'vms7-t0-7260-2.master',
    9 : 'vms24-t0-7260-2.master',
    10 : 'vms7-t0-dx010-4.master',
    11 : 'vms7-t0-dx010-5.master',
    12 : 'vms20-t1-dx010-6.master',
    13 : 'vms3-t1-dx010-1.master',
    14 : 'vms7-t1-s6100-platform.master',
    15 : 'vms7-t1-s6100-non-platform.master',
    16 : 'vms12-t0-3800-platform_tests.master', 
}

# fixme:
# it would be covered in testbedV2
branch_verify_cfg={
  'internal-202205': {
    't0': {
        
    },
    't1': {
      'Arista-7050QX32S-Q32':[
          'testbed-bjw-can-7050qx-1',   # 949   # 950
          'vms24-t1-7050qx-acs-01'      # 951   # 952
      ],
      'Arista-7060CX-32S-C32':[
          'vms63-t1-7060-3',
          'vms6-t1-7060'
      ],
      'Arista-7260CX3-C64':[
          'vms2-t1-7260-7'
      ]
    }
  },
  'master': {
    
  },
  'internal-202012': {
    
  },
  'internal': {
    
  },
  
}