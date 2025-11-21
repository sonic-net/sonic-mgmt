#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from platform_qos_base import PlatformQosBase


class PlatformQosKvm(PlatformQosBase):

    platform_name = "kvm"

    #
    # PD functions
    #

    def build_param(self):
        pass

    def disable_port_transmit(self):
        pass

    def build_packet(self):
        pass

    def handle_leakout(self):
        pass

    def read_port_counter(self):
        pass

    def enable_port_transmit(self):
        pass

    def qos_test_assert(self):
        pass
