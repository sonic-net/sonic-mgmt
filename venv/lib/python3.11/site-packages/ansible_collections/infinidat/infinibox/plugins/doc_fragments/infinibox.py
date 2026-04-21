# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


class ModuleDocFragment(object):
    """
    Standard Infinibox documentation fragment
    """
    DOCUMENTATION = r'''
options:
  system:
    description:
      - Infinibox Hostname or IPv4 Address.
    type: str
    required: true
  user:
    description:
      - Infinibox User username with sufficient priveledges ( see notes ).
    type: str
    required: true
  password:
    description:
      - Infinibox User password.
    type: str
    required: true
  stay_logged_in:
    description:
      - If True, persist API session to disk.
      - Load the session on subsequent module calls.
      - Persisted sessions are only usable for stay_logged_in_minutes.
    type: bool
    required: false
    default: false
  stay_logged_in_minutes:
    description:
      - Number of minutes for which a persisted session may be reused.
      - After this time, the session data will be deleted.
      - The time should be shorter than the IBOX session timeout time.
    type: int
    required: false
    default: 5

notes:
  - This module requires infinisdk python library
  - You must set INFINIBOX_USER and INFINIBOX_PASSWORD environment variables
    if user and password arguments are not passed to the module directly
  - Ansible uses the infinisdk configuration file C(~/.infinidat/infinisdk.ini) if no credentials are provided.
    See U(http://infinisdk.readthedocs.io/en/latest/getting_started.html)
  - All Infinidat modules support check mode (--check). However, a dryrun that creates
    resources may fail if the resource dependencies are not met for a task.
    For example, consider a task that creates a volume in a pool.
    If the pool does not exist, the volume creation task will fail.
    It will fail even if there was a previous task in the playbook that would have created the pool but
    did not because the pool creation was also part of the dry run.
requirements:
  - python2 >= 2.7 or python3 >= 3.6
  - infinisdk (https://infinisdk.readthedocs.io/en/latest/)
'''
