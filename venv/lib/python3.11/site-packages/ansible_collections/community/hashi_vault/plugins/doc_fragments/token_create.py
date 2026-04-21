# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = r'''
options:
  orphan:
    description:
      - When C(true), uses the C(/create-orphan) API endpoint, which requires C(sudo) (but not C(root)) to create an orphan.
      - With C(hvac>=1.0.0), requires collection version C(>=3.3.0).
    type: bool
    default: false
  no_parent:
    description:
      - This option only has effect if used by a C(root) or C(sudo) caller and only when I(orphan=false).
      - When C(true), the token created will not have a parent.
    type: bool
  no_default_policy:
    description:
      - If C(true) the default policy will not be contained in this token's policy set.
      - If the token will be used with this collection, set I(token_validate=false).
    type: bool
  policies:
    description:
      - A list of policies for the token. This must be a subset of the policies belonging to the token making the request, unless root.
      - If not specified, defaults to all the policies of the calling token.
    type: list
    elements: str
  id:
    description:
      - The ID of the client token. Can only be specified by a root token.
      - The ID provided may not contain a C(.) character.
      - Otherwise, the token ID is a randomly generated value.
    type: str
  role_name:
    description:
      - The name of the token role. If used, the token will be created against the specified role name which may override options set during this call.
    type: str
  meta:
    description: A dict of string to string valued metadata. This is passed through to the audit devices.
    type: dict
  renewable:
    description:
      - Set to C(false) to disable the ability of the token to be renewed past its initial TTL.
      - Setting the value to C(true) will allow the token to be renewable up to the system/mount maximum TTL.
    type: bool
  ttl:
    description:
      - The TTL period of the token, provided as C(1h) for example, where hour is the largest suffix.
      - If not provided, the token is valid for the default lease TTL, or indefinitely if the root policy is used.
    type: str
  type:
    description: The token type. The default is determined by the role configuration specified by I(role_name).
    type: str
    choices:
      - batch
      - service
  explicit_max_ttl:
    description:
      - If set, the token will have an explicit max TTL set upon it.
      - This maximum token TTL cannot be changed later,
        and unlike with normal tokens, updates to the system/mount max TTL value will have no effect at renewal time.
      - The token will never be able to be renewed or used past the value set at issue time.
    type: str
  display_name:
    description: The display name of the token.
    type: str
  num_uses:
    description:
      - The maximum uses for the given token. This can be used to create a one-time-token or limited use token.
      - The value of C(0) has no limit to the number of uses.
    type: int
  period:
    description:
      - If specified, the token will be periodic.
      - It will have no maximum TTL (unless an I(explicit_max_ttl) is also set) but every renewal will use the given period.
      - Requires a root token or one with the C(sudo) capability.
    type: str
  entity_alias:
    description:
      - Name of the entity alias to associate with during token creation.
      - Only works in combination with I(role_name) option and used entity alias must be listed in C(allowed_entity_aliases).
      - If this has been specified, the entity will not be inherited from the parent.
    type: str
'''
