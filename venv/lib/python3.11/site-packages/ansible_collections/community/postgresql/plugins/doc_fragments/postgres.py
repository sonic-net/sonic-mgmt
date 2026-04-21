# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    # Postgres documentation fragment
    DOCUMENTATION = r'''
options:
  login_user:
    description:
      - The username this module should use to establish its PostgreSQL session.
    type: str
    default: postgres
    aliases: [ login ]
  login_password:
    description:
      - The password this module should use to establish its PostgreSQL session.
    type: str
    default: ''
  login_host:
    description:
      - Host running the database.
      - If you have connection issues when using C(localhost), try to use C(127.0.0.1) instead.
    default: ''
    type: str
    aliases: [ host ]
  login_unix_socket:
    description:
      - Path to a Unix domain socket for local connections.
    type: str
    default: ''
    aliases: [ unix_socket ]
  login_port:
    description:
      - Database port to connect to.
      - The C(port) alias is deprecated and will be removed in the next major release. Use C(login_port) instead.
    type: int
    default: 5432
    aliases: [ port ]
  ssl_mode:
    description:
      - Determines whether or with what priority a secure SSL TCP/IP connection will be negotiated with the server.
      - See U(https://www.postgresql.org/docs/current/static/libpq-ssl.html) for more information on the modes.
      - Default of C(prefer) matches libpq default.
    type: str
    default: prefer
    choices: [ allow, disable, prefer, require, verify-ca, verify-full ]
  ca_cert:
    description:
      - Specifies the name of a file containing SSL certificate authority (CA) certificate(s).
      - If the file exists, the server's certificate will be verified to be signed by one of these authorities.
    type: str
    aliases: [ ssl_rootcert ]
  ssl_cert:
    description:
      - Specifies the file name of the client SSL certificate.
    type: path
    version_added: '2.4.0'
  ssl_key:
    description:
      - Specifies the location for the secret key used for the client certificate.
    type: path
    version_added: '2.4.0'
  connect_params:
    description:
      - Any additional parameters to be passed to libpg.
      - These parameters take precedence.
    type: dict
    default: {}
    version_added: '2.3.0'

attributes:
  check_mode:
    description: Can run in check_mode and return changed status prediction without modifying target.

notes:
- The default authentication assumes that you are either logging in as or sudo'ing to the C(postgres) account on the host.
- To avoid "Peer authentication failed for user postgres" error,
  use postgres user as a I(become_user).
- This module uses C(psycopg), a Python PostgreSQL database adapter. You must
  ensure that C(psycopg2 >= 2.5.1) or C(psycopg3 >= 3.1.8) is installed on the host before using this module.
- If the remote host is the PostgreSQL server (which is the default case), then
  PostgreSQL must also be installed on the remote host.
- For Ubuntu-based systems, install the C(postgresql), C(libpq-dev), and C(python3-psycopg2) packages
  on the remote host before using this module.

requirements: [ 'psycopg2 >= 2.5.1' ]
'''
