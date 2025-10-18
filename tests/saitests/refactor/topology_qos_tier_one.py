#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from topology_qos_base import TopologyQosBase


class TopologyQosTierOne(TopologyQosBase):

    topology_name = ["t1"]

    #
    # topology specific functions
    #

    def populate_arp(self):
        pass

    def detect_rx_port(self):
        pass
