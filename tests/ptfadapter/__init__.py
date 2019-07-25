import ptf

# config ptf with basic parameters before any other ptf module import
ptf.config = {
    'relax': True,
    'disable_ipv6': False,
    'disable_vxlan': False,
    'disable_erspan': False,
    'disable_geneve': False,
    'disable_mpls': False,
    'disable_nvgre': False,
    'qlen': 100000,
}

from ptfadapter import PtfTestAdapter

__all__ = ['PtfTestAdapter']