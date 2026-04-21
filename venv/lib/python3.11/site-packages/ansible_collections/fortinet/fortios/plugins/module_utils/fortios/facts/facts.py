from __future__ import (absolute_import, division, print_function)
# Copyright (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

"""
The facts class for fortios
this file validates each subset of monitor and selectively
calls the appropriate facts gathering and monitoring function
"""

try:
    from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.argspec.system.system import SystemArgs
    from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.facts.facts import FactsBase
    from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.facts.system.system import SystemFacts
except ImportError as err:
    IMPORT_ERROR = err
else:
    IMPORT_ERROR = None

if not IMPORT_ERROR:
    class Facts(FactsBase):
        """ The facts class for fortios
        """

        FACT_SUBSETS = {
            "system": SystemFacts
        }

        def __init__(self, module, fos=None, subset=None):
            if IMPORT_ERROR:
                module.fail_json(IMPORT_ERROR)
            super(Facts, self).__init__(module)
            self._fos = fos
            self._subset = subset

        def gen_runable(self, subsets, valid_subsets):
            """ Generate the runable subset

            :param module: The module instance
            :param subsets: The provided subsets
            :param valid_subsets: The valid subsets
            :rtype: list
            :returns: The runable subsets
            """
            runable_subsets = []
            FACT_DETAIL_SUBSETS = []
            FACT_DETAIL_SUBSETS.extend(SystemArgs.FACT_SYSTEM_SUBSETS)
            subset_str = ', '.join(sorted(FACT_DETAIL_SUBSETS))
            for subset in subsets:
                if subset['fact'] not in FACT_DETAIL_SUBSETS:
                    self._module.fail_json(
                        msg='Subset must be one of [%s], got %s' % (subset_str, subset['fact']))

                for valid_subset in frozenset(self.FACT_SUBSETS.keys()):
                    if subset['fact'].startswith(valid_subset):
                        runable_subsets.append((subset, valid_subset))

            return runable_subsets

        def get_network_legacy_facts(self, fact_legacy_obj_map, legacy_facts_type=None):
            if not legacy_facts_type:
                legacy_facts_type = self._gather_subset

            runable_subsets = self.gen_runable(legacy_facts_type, frozenset(fact_legacy_obj_map.keys()))
            if runable_subsets:
                self.ansible_facts['ansible_net_gather_subset'] = []

                instances = list()
                for (subset, valid_subset) in runable_subsets:
                    instances.append(fact_legacy_obj_map[valid_subset](self._module, self._fos, subset))

                for inst in instances:
                    inst.populate_facts(self._connection, self.ansible_facts)

        def get_facts(self, facts_type=None, data=None):
            """ Collect the facts for fortios
            :param facts_type: List of facts types
            :param data: previously collected conf
            :rtype: dict
            :return: the facts gathered
            """
            self.get_network_legacy_facts(self.FACT_SUBSETS, facts_type)

            return self.ansible_facts, self._warnings
