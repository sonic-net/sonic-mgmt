from __future__ import absolute_import, division, print_function
__metaclass__ = type


class Ospfv3_interfacesArgs(object):
    """The arg spec for the sonic_ospfv3_interfaces module"""

    def __init__(self, **kwargs):
        pass

    argument_spec = {
        'config': {
            'elements': 'dict',
            'options': {
                'bfd': {
                    'options': {
                        'bfd_profile': {'type': 'str'},
                        'enable': {'required': True, 'type': 'bool'}
                    },
                    'type': 'dict'
                },
                'name': {'required': True, 'type': 'str'},
                'network': {
                    'choices': ['broadcast', 'point_to_point'],
                    'type': 'str'
                },
                'area_id': {'type': 'str'},
                'cost': {'type': 'int'},
                'dead_interval': {'type': 'int'},
                'hello_interval': {'type': 'int'},
                'mtu_ignore': {'type': 'bool'},
                'priority': {'type': 'int'},
                'retransmit_interval': {'type': 'int'},
                'transmit_delay': {'type': 'int'},
                'passive': {'type': 'bool'},
                'advertise': {'type': 'str'},
            },
            'type': 'list'
        },

        'state': {
            'choices': ['merged', 'deleted', 'replaced', 'overridden'],
            'default': 'merged',
            'type': 'str'
        }
    }  # pylint: disable=C0301
