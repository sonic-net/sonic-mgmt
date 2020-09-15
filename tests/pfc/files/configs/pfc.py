"""
Contains configurations for pfc lossy and pfc global pause
"""
import json
import sys

from abstract_open_traffic_generator.port import Port
from abstract_open_traffic_generator.result import PortRequest
from abstract_open_traffic_generator.config import Options
from abstract_open_traffic_generator.config import Config

from abstract_open_traffic_generator.layer1 import\
    Layer1, OneHundredGbe, FlowControl, Ieee8021qbb

from abstract_open_traffic_generator.device import\
    DeviceGroup, Device, Ethernet, Vlan, Ipv4, Pattern

from abstract_open_traffic_generator.flow import\
    DeviceEndpoint, Endpoint, Flow, Header, Size, Rate,\
    Duration, Fixed, PortEndpoint, PfcPause, Counter, Random

from abstract_open_traffic_generator.flow_ipv4 import\
    Priority, Dscp

from abstract_open_traffic_generator.flow import Pattern as PATTERN
from abstract_open_traffic_generator.flow import Ipv4 as IPV4
from abstract_open_traffic_generator.flow import Vlan as VLAN
from abstract_open_traffic_generator.flow import Ethernet as ETHERNET
from abstract_open_traffic_generator.port import Options as PortOptions


def configure_pfc_lossy (api,
                         phy_tx_port,
                         phy_rx_port,
                         port_speed,
                         tx_port_ip='0.0.0.0',
                         rx_port_ip='0.0.0.0',
                         tx_gateway_ip='0.0.0.0',
                         rx_gateway_ip='0.0.0.',
                         tx_ip_incr='0.0.0.0',
                         rx_ip_incr='0.0.0.0',
                         tx_gateway_incr='0.0.0.0',
                         rx_gateway_incr='0.0.0.0',
                         test_data_priority=[0, 1, 2, 5, 6, 7],
                         background_data_priority=[3, 4],
                         test_flow_name='Test Data',
                         background_flow_name='Background Data',
                         test_line_rate=50,
                         background_line_rate=50,
                         pause_line_rate=100, 
                         start_delay=1,
                         configure_pause_frame=True) :
    """
    Create the configuration of the PFC lossy.
    """
    start_delay = start_delay * 1000000000

    api.set_config(None)

    tx = Port(name='Tx', location=phy_tx_port)
    rx = Port(name='Rx', location=phy_rx_port)

    #########################################################################
    # common L1 configuration
    #########################################################################
    pfc = Ieee8021qbb(pfc_delay=1,
                pfc_class_0=0,
                pfc_class_1=1,
                pfc_class_2=2,
                pfc_class_3=3,
                pfc_class_4=4,
                pfc_class_5=5,
                pfc_class_6=6,
                pfc_class_7=7)

    flow_ctl = FlowControl(choice=pfc)


    l1_oneHundredGbe = OneHundredGbe(link_training=True,
                                     ieee_media_defaults=False,
                                     auto_negotiate=False,
                                     speed='one_hundred_gbps',
                                     flow_control=flow_ctl,
                                     rs_fec=True)

    common_l1_config = Layer1(name='common L1 config',
                              choice=l1_oneHundredGbe,
                              port_names=[tx.name, rx.name])

    ###########################################################################
    # Create TX stack configuration
    ###########################################################################
    tx_ipv4 = Ipv4(name='Tx Ipv4',
                   address=Pattern(tx_port_ip),
                   prefix=Pattern('24'),
                   gateway=Pattern(tx_gateway_ip))

    tx_ethernet = Ethernet(name='Tx Ethernet', ipv4=tx_ipv4)

    tx_device = Device(name='Tx Device',
                       devices_per_port=1,
                       ethernets=[tx_ethernet])

    tx_device_group = DeviceGroup(name='Tx Device Group',
                                  port_names=[tx.name],
                                  devices=[tx_device])


    ###########################################################################
    # Create RX stack configuration
    ###########################################################################
    rx_ipv4 = Ipv4(name='Rx Ipv4',
                   address=Pattern(rx_port_ip),
                   prefix=Pattern('24'),
                   gateway=Pattern(rx_gateway_ip))

    rx_ethernet = Ethernet(name='Rx Ethernet', ipv4=rx_ipv4)

    rx_device = Device(name='Rx Device',
                       devices_per_port=1,
                       ethernets=[rx_ethernet])

    rx_device_group = DeviceGroup(name='Rx Device Group',
                                  port_names=[rx.name],
                                  devices=[rx_device])


    ###########################################################################
    # Traffic configuration Test data
    ###########################################################################
    data_endpoint = DeviceEndpoint(
        tx_device_names=[tx_device.name],
        rx_device_names=[rx_device.name],
        packet_encap='ipv4',
        src_dst_mesh='',
        route_host_mesh='',
        bi_directional=False,
        allow_self_destined=False
    )

    test_dscp = Priority(Dscp(phb=PATTERN(choice=test_data_priority)))

    test_flow = Flow(
        name=test_flow_name,
        endpoint=Endpoint(data_endpoint),
        packet=[
            Header(choice=ETHERNET()),
            Header(choice=IPV4(priority=test_dscp))
        ],
        size=Size(1024),
        rate=Rate('line', test_line_rate),
        duration=Duration(Fixed(packets=0, delay=start_delay, delay_unit='nanoseconds'))
    )

    ###########################################################################
    # Traffic configuration Background data
    ###########################################################################
    background_dscp = Priority(Dscp(phb=PATTERN(choice=background_data_priority)))
    background_flow = Flow(
        name=background_flow_name,
        endpoint=Endpoint(data_endpoint),
        packet=[
            Header(choice=ETHERNET()),
            Header(choice=IPV4(priority=background_dscp))
        ],
        size=Size(1024),
        rate=Rate('line', background_line_rate),
        duration=Duration(Fixed(packets=0, delay=start_delay, delay_unit='nanoseconds'))
    )

    ###########################################################################
    # Traffic configuration Pause
    ###########################################################################
    if (configure_pause_frame) :
        pause_endpoint = PortEndpoint(tx_port_name=rx.name, rx_port_names=[rx.name])
        pause = Header(PfcPause(
            dst=PATTERN(choice='01:80:C2:00:00:01'),
            src=PATTERN(choice='00:00:fa:ce:fa:ce'),
            class_enable_vector=PATTERN(choice='E7'),
            pause_class_0=PATTERN(choice='ffff'),
            pause_class_1=PATTERN(choice='ffff'),
            pause_class_2=PATTERN(choice='ffff'),
            pause_class_3=PATTERN(choice='0'),
            pause_class_4=PATTERN(choice='0'),
            pause_class_5=PATTERN(choice='ffff'),
            pause_class_6=PATTERN(choice='ffff'),
            pause_class_7=PATTERN(choice='ffff'),
        ))

        pause_flow = Flow(
            name='Pause Storm',
            endpoint=Endpoint(pause_endpoint),
            packet=[pause],
            size=Size(64),
            rate=Rate('line', value=pause_line_rate),
            duration=Duration(Fixed(packets=0, delay=0, delay_unit='nanoseconds'))
        )
        flows = [test_flow, background_flow, pause_flow]
    else :
        flows = [test_flow, background_flow]

    ###########################################################################
    # Set config
    ###########################################################################
    config = Config(
        ports=[
            tx,
            rx
        ],
        layer1=[common_l1_config],
        device_groups=[tx_device_group, rx_device_group],
        flows=flows,
        options=Options(PortOptions(location_preemption=True))
    )

    api.set_config(config)
    return config

