#
# -*- coding: utf-8 -*-
# Copyright 2024 Dell Inc. or its subsidiaries. All Rights Reserved
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The sonic qos_scheduler fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from copy import deepcopy

from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.utils.utils import (
    remove_empties_from_list
)
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.qos_scheduler.qos_scheduler import Qos_schedulerArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)


class Qos_schedulerFacts(object):
    """ The sonic qos_scheduler fact class
    """

    def __init__(self, module, subspec='config', options='options'):
        self._module = module
        self.argument_spec = Qos_schedulerArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for qos_scheduler
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []

        if not data:
            cfg = self.get_config(self._module)
            data = self.update_qos_scheduler(cfg)
        objs = self.render_config(self.generated_spec, data)
        facts = {}
        if objs:
            params = utils.validate_config(self.argument_spec, {'config': objs})
            facts['qos_scheduler'] = remove_empties_from_list(params['config'])
        ansible_facts['ansible_network_resources'].update(facts)
        return ansible_facts

    def render_config(self, spec, conf):
        """
        Render config as dictionary structure and delete keys
          from spec for null values

        :param spec: The facts tree, generated from the argspec
        :param conf: The configuration
        :rtype: dictionary
        :returns: The generated config
        """
        return conf

    def get_config(self, module):
        cfg = None
        get_path = '/data/openconfig-qos:qos/scheduler-policies'
        request = {'path': get_path, 'method': 'get'}

        try:
            response = edit_config(module, to_request(module, request))
            if 'openconfig-qos:scheduler-policies' in response[0][1]:
                cfg = response[0][1].get('openconfig-qos:scheduler-policies')
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)

        return cfg

    def update_qos_scheduler(self, cfg):

        config_list = []
        if cfg:
            scheduler_policy = cfg.get('scheduler-policy')
            if scheduler_policy:
                for policy in scheduler_policy:
                    config_dict = {}
                    name = policy.get('name')
                    if name:
                        config_dict['name'] = name
                    schedulers = policy.get('schedulers')
                    if schedulers:
                        scheduler = schedulers.get('scheduler')
                        if scheduler:
                            schedulers_list = []
                            for schedule in scheduler:
                                schedulers_dict = {}
                                sequence = schedule.get('sequence')
                                if sequence is not None:
                                    schedulers_dict['sequence'] = sequence
                                config = schedule.get('config')
                                if config:
                                    scheduler_type = config.get('priority')
                                    weight = config.get('weight')
                                    meter_type = config.get('meter-type')

                                    if scheduler_type:
                                        schedulers_dict['scheduler_type'] = scheduler_type.lower()
                                    if weight:
                                        schedulers_dict['weight'] = weight
                                    if meter_type:
                                        schedulers_dict['meter_type'] = meter_type.lower()

                                two_rate_three_color = schedule.get('two-rate-three-color')
                                if two_rate_three_color:
                                    trtc_config = two_rate_three_color.get('config')
                                    if trtc_config:
                                        cir = trtc_config.get('cir')
                                        pir = trtc_config.get('pir')
                                        cbs = trtc_config.get('bc')
                                        pbs = trtc_config.get('be')

                                        if cir:
                                            schedulers_dict['cir'] = cir
                                        if pir:
                                            schedulers_dict['pir'] = pir
                                        if cbs:
                                            schedulers_dict['cbs'] = cbs
                                        if pbs:
                                            schedulers_dict['pbs'] = pbs

                                if schedulers_dict:
                                    schedulers_list.append(schedulers_dict)
                            if schedulers_list:
                                config_dict['schedulers'] = schedulers_list

                    if config_dict:
                        config_list.append(config_dict)

        return config_list
