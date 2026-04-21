from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):
    # Standard documentation
    DOCUMENTATION = r'''
options:
  login_user:
    description:
      - The MongoDB user to login with.
      - Required when I(login_password) is specified.
    required: no
    type: str
  login_password:
    description:
      - The password used to authenticate with.
      - Required when I(login_user) is specified.
    required: no
    type: str
  login_database:
    description:
      - The database where login credentials are stored.
    required: no
    type: str
    default: 'admin'
  login_host:
    description:
      - The host running MongoDB instance to login to.
    required: no
    type: str
    default: 'localhost'
  login_port:
    description:
      - The MongoDB server port to login to.
    required: no
    type: int
    default: 27017
  strict_compatibility:
    description:
      - Enforce strict requirements for pymongo and MongoDB software versions
    type: bool
    default: True
  atlas_auth:
    description:
      - Authentication path intended for MongoDB Atlas Instances
    type: bool
    default: False
'''
