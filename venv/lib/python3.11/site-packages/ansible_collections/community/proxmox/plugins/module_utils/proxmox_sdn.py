# -*- coding: utf-8 -*-
#
# Copyright (c) 2025, Jana Hoch <janahoch91@proton.me>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import List, Dict

from ansible_collections.community.proxmox.plugins.module_utils.proxmox import (
    ansible_to_proxmox_bool,
    proxmox_to_ansible_bool,
    ProxmoxAnsible
)


class ProxmoxSdnAnsible(ProxmoxAnsible):
    """Base Class for All Proxmox SDN Classes"""

    def __init__(self, module):
        super(ProxmoxSdnAnsible, self).__init__(module)
        self.module = module

    def get_global_sdn_lock(self) -> str:
        """Acquire global SDN lock. Needed for any changes under SDN.

        :return: lock-token
        """
        try:
            return self.proxmox_api.cluster().sdn().lock().post()
        except Exception as e:
            self.module.fail_json(
                msg=f'Failed to acquire global sdn lock {e}'
            )

    def apply_sdn_changes_and_release_lock(self, lock: str, release_lock: bool = True) -> None:
        """Apply all SDN changes done under a lock token.

        :param lock: Global SDN lock token
        :param release_lock: if True release lock after successfully applying changes
        """
        lock_params = {
            'lock-token': lock,
            'release-lock': ansible_to_proxmox_bool(release_lock)
        }
        try:
            self.proxmox_api.cluster().sdn().put(**lock_params)
        except Exception as e:
            self.rollback_sdn_changes_and_release_lock(lock)
            self.module.fail_json(
                msg=f'Failed to apply sdn changes {e}. Rolling back all pending changes.'
            )

    def rollback_sdn_changes_and_release_lock(self, lock: str, release_lock: bool = True) -> None:
        """Rollback all changes  done under a lock token.

        :param lock: Global SDN lock token
        :param release_lock: if True release lock after successfully rolling back changes
        """
        lock_params = {
            'lock-token': lock,
            'release-lock': ansible_to_proxmox_bool(release_lock)
        }
        try:
            self.proxmox_api.cluster().sdn().rollback().post(**lock_params)
        except Exception as e:
            self.module.fail_json(
                msg=f'Rollback attempt failed - {e}. Manually clear lock by deleting /etc/pve/sdn/.lock'
            )

    def release_lock(self, lock: str, force: bool = False) -> None:
        """Release Global SDN lock

        :param lock: Global SDN lock token
        :param force: if true, allow releasing lock without providing the token
        """
        lock_params = {
            'lock-token': lock,
            'force': ansible_to_proxmox_bool(force)
        }
        try:
            self.proxmox_api.cluster().sdn().lock().delete(**lock_params)
        except Exception as e:
            self.module.fail_json(
                msg=f'Failed to release lock - {e}. Manually clear lock by deleting /etc/pve/sdn/.lock'
            )

    def get_zones(self, zone_type: str = None) -> List[Dict]:
        """Get Proxmox SDN zones

        :param zone_type: Filter zones based on type.
        :return: list of all zones and their properties.
        """
        try:
            return self.proxmox_api.cluster().sdn().zones().get(type=zone_type)
        except Exception as e:
            self.module.fail_json(
                msg=f'Failed to retrieve zone information from cluster: {e}'
            )

    def get_aliases(self, firewall_obj):
        """Get aliases for IP/CIDR at given firewall endpoint level

        :param firewall_obj: Firewall endpoint as a ProxmoxResource e.g. self.proxmox_api.cluster().firewall
                            If it is None it'll return an empty list
        :return: List of aliases and corresponding IP/CIDR
        """
        if firewall_obj is None:
            return list()
        try:
            return firewall_obj().aliases().get()
        except Exception as e:
            self.module.fail_json(
                msg=f'Failed to retrieve aliases - {e}'
            )

    def get_fw_rules(self, rules_obj, pos=None):
        """Get firewall rules at given rules endpoint level

        :param rules_obj: Firewall Rules endpoint as a ProxmoxResource e.g. self.proxmox_api.cluster().firewall().rules
        :param pos: Rule position if it is None it'll return all rules
        :return: Firewall rules as a list of dict
        """
        if pos is not None:
            pos = str(pos)
        try:
            return rules_obj(pos).get()
        except Exception as e:
            self.module.fail_json(
                msg=f'Failed to retrieve firewall rules: {e}'
            )

    def get_groups(self):
        """Get firewall security groups

        :return: list of groups
        """
        try:
            return [x['group'] for x in self.proxmox_api.cluster().firewall().groups().get()]
        except Exception as e:
            self.module.fail_json(
                msg=f'Failed to retrieve firewall security groups: {e}'
            )

    def get_ip_sets(self):
        """Get ipsets for firewall.

        :return: dict of ip_set name and cidr
        """
        try:
            ip_sets = self.proxmox_api.cluster().firewall().ipset().get()
            for ip_set in ip_sets:
                ip_set_obj = getattr(self.proxmox_api.cluster().firewall().ipset(), ip_set['name'])
                cidrs = ip_set_obj.get()
                for cidr in cidrs:
                    cidr['nomatch'] = proxmox_to_ansible_bool(cidr.get('nomatch'))
                ip_set['cidrs'] = cidrs
            return ip_sets
        except Exception as e:
            self.module.fail_json(
                msg=f'Failed to retrieve firewall ipsets: {e}'
            )
