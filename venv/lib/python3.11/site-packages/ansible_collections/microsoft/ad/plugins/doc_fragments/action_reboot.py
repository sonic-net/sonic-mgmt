# -*- coding: utf-8 -*-

# Copyright (c) 2024 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


class ModuleDocFragment:

    # Common options for ansible_collections.microsoft.ad.plugins.plugin_utils._module_with_reboot
    DOCUMENTATION = r"""
options:
  reboot:
    description:
    - If C(true), this will reboot the host if a reboot was required by the
      module.
    - If C(false), this will not reboot the host if a reboot was required and
      instead sets the I(reboot_required) return value to C(true).
    - This cannot be used with async mode.
    type: bool
    default: false
  reboot_timeout:
    description:
    - Maximum seconds to wait for machine to re-appear after a reboot and respond to a test command.
    - This timeout is evaluated separately for both the reboot verification and test command success so
      the total timeout can be twice this value.
    default: 600
    type: int
    version_added: 1.7.0
"""
