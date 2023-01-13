
skip_testbeds_list = [
    'azd',
    '3164',
    'testbed-bjw-can-7215-1',
    'testbed-str2-7215-acs-3',
    '-t2-'
]


golden_image_url = {
    'vms2-t1-7260-7'         : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012)',            # Arista
    'vms3-t1-7280'           : '$(GOLDEN_IMAGE_BRCM_DNX_ABOOT_PUBLIC)',        # Arista
    'vms6-t0-7060'           : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012_SLIM)',       # Arista
    'vms6-t1-7060'           : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012_SLIM)',       # Arista
    'vms7-t0-7260-1'         : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012)',            # Arista
    'vms7-t0-7260-2'         : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012)',            # Arista
    'vms18-t0-7050qx-acs-02' : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012_SLIM)',       # Arista
    'vms18-t1-7050qx-acs-03' : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012_SLIM)',       # Arista
    'vms20-t0-7050cx3-1'     : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012)',            # Arista
    'vms20-t0-7050cx3-2'     : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012)',            # Arista
    'vms20-t1-7050cx3-3'     : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012)',            # Arista
    'vms21-dual-t0-7050-3'   : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012)',            # Arista
    'vms21-dual-t0-7260'     : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012)',            # Arista
    'vms24-dual-t0-7050-1'   : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012)',            # Arista
    'vms24-dual-t0-7050-2'   : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012)',            # Arista
    'vms24-t0-7260-2'        : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012)',            # Arista
    'vms24-t1-7050qx-acs-01' : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012_SLIM)',       # Arista
    'vms26-t2-7800-1'        :  None,                                          # Arista
    'vms28-dual-t0-7260'     : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012)',            # Arista
    'vms3-t1-dx010-1'        : '$(GOLDEN_IMAGE_BRCM_202012)',                  # Celestica
    'vms7-t0-dx010-4'        : '$(GOLDEN_IMAGE_BRCM_202012)',                  # Celestica
    'vms7-t0-dx010-5'        : '$(GOLDEN_IMAGE_BRCM_202012)',                  # Celestica
    'vms12-3-t0-e1031'       : '$(GOLDEN_IMAGE_BRCM_202012_SLIM)',             # Celestica
    'vms12-9-t0-e1031'       : '$(GOLDEN_IMAGE_BRCM_202012_SLIM)',             # Celestica
    'vms20-t1-dx010-6'       : '$(GOLDEN_IMAGE_BRCM_202012)',                  # Celestica
    'vms13-t1-n3164-2'       : '$(GOLDEN_IMAGE_BRCM_202012)',                  # Cisco   #fixme
    'vms20-t1-n3164-acs-4'   : '$(GOLDEN_IMAGE_BRCM_202012)',                  # Cisco   #fixme
    'vmsvc1-t1-n3164-acs-1'  : '$(GOLDEN_IMAGE_BRCM_202012)',                  # Cisco   #fixme
    'vms7-t0-s6100'          : '$(GOLDEN_IMAGE_BRCM_202012)',                  # Dell
    'vms7-t0-s6100-4'        : '$(GOLDEN_IMAGE_BRCM_202012)',                  # Dell
    'vms7-t1-s6100'          : '$(GOLDEN_IMAGE_BRCM_202012)',                  # Dell
    'vms11-t0-on-4'          : '$(GOLDEN_IMAGE_BRCM_202012)',                  # Dell
    'vms13-5-t1-lag'         : '$(GOLDEN_IMAGE_BRCM_202012)',                  # Dell
    'vms21-t0-z9332f-02'     : '$(GOLDEN_IMAGE_BRCM_202012)',                  # Dell
    'vms1-8'                 : '$(GOLDEN_IMAGE_MLNX_202012)',                  # Mellanox
    'vms1-t1-2700'           : '$(GOLDEN_IMAGE_MLNX_202012)',                  # Mellanox
    'vms2-2-t0-2700'         : '$(GOLDEN_IMAGE_MLNX_202012)',                  # Mellanox
    'vms2-4-t0-2700'         : '$(GOLDEN_IMAGE_MLNX_202012)',                  # Mellanox
    'vms7-t0-4600c-2'        : '$(GOLDEN_IMAGE_MLNX_202012)',                  # Mellanox
    'vms12-t0-3800'          : '$(GOLDEN_IMAGE_MLNX_202012)',                  # Mellanox
    'vms18-t1-msn4600c-acs-1': '$(GOLDEN_IMAGE_MLNX_202012)',                  # Mellanox
    'vms20-t0-sn3800-2'      : '$(GOLDEN_IMAGE_MLNX_202012)',                  # Mellanox
    'vms21-t0-2700'          : '$(GOLDEN_IMAGE_MLNX_202012)',                  # Mellanox
    'vms21-t1-2700-2'        : '$(GOLDEN_IMAGE_MLNX_202012)',                  # Mellanox
    'vms24-t0-3800-azd'      : '$(GOLDEN_IMAGE_MLNX_202012)',                  # Mellanox
    'vms28-t0-4600c-03'      : '$(GOLDEN_IMAGE_MLNX_202012)',                  # Mellanox
    'vms28-t0-4600c-04'      : '$(GOLDEN_IMAGE_MLNX_202012)',                  # Mellanox
    'vms11-2-t0'             : '$(GOLDEN_IMAGE_MLNX_202012)',                  # Mellanox
    'vms18-t0-7215-acs-1'    : '$(GOLDEN_IMAGE_MARVELL_202012)',               # Nokia
    'vms21-t0-7215-acs-3'    : '$(GOLDEN_IMAGE_MARVELL_202012)',               # Nokia
    'vms29-t2-7250-1'        : None,                                           # Nokia
    'vms29-t2-7250-2'        : None,                                           # Nokia 
    'vms20-t0-ixia-2'        : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012_SLIM)',       # Rdma
    'vmsvc1-dual-t0-7050-1'  : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012)',            # Arista
    'vmsvc1-dual-t0-7050-2'  : '$(GOLDEN_IMAGE_BRCM_ABOOT_202012)'             # Arista
}
