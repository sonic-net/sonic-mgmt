#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from platform_qos_base import PlatformQosBase
from platform_qos_broadcom import PlatformQosBroadcom


class PlatformQosTomhawk(PlatformQosBroadcom):

    hwsku_name = []

    #
    # PD functions
    #

    def build_param(self):
        pass

    def handle_leakout(self):
        pass

    def build_packet(self):
        pass
