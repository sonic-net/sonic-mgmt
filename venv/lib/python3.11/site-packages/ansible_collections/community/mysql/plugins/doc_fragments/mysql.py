# -*- coding: utf-8 -*-

# Copyright: (c) 2015, Jonathan Mainguy <jon@soh.re>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    # Standard mysql documentation fragment
    DOCUMENTATION = r'''
options:
  login_user:
    description:
      - The username used to authenticate with.
    type: str
  login_password:
    description:
      - The password used to authenticate with.
    type: str
  login_host:
    description:
      - Host running the database.
      - In some cases for local connections the I(login_unix_socket=/path/to/mysqld/socket),
        that is usually C(/var/run/mysqld/mysqld.sock), needs to be used instead of I(login_host=localhost).
    type: str
    default: localhost
  login_port:
    description:
      - Port of the MySQL server. Requires I(login_host) be defined as other than localhost if login_port is used.
    type: int
    default: 3306
  login_unix_socket:
    description:
      - The path to a Unix domain socket for local connections.
      - Use this parameter to avoid the C(Please explicitly state intended protocol) error.
    type: str
  connect_timeout:
    description:
      - The connection timeout when connecting to the MySQL server.
    type: int
    default: 30
  config_file:
    description:
      - Specify a config file from which user and password are to be read.
      - The default config file, C(~/.my.cnf), if it exists, will be read, even if I(config_file) is not specified.
      - The default config file, C(~/.my.cnf), if it exists, must contain a C([client]) section as a MySQL connector requirement.
      - To prevent the default config file from being read, set I(config_file) to be an empty string.
    type: path
    default: '~/.my.cnf'
  ca_cert:
    description:
      - The path to a Certificate Authority (CA) certificate. This option, if used, must specify the same certificate
        as used by the server.
    type: path
    aliases: [ ssl_ca ]
  client_cert:
    description:
      - The path to a client public key certificate.
    type: path
    aliases: [ ssl_cert ]
  client_key:
    description:
      - The path to the client private key.
    type: path
    aliases: [ ssl_key ]
  check_hostname:
    description:
      - Whether to validate the server host name when an SSL connection is required. Corresponds to MySQL CLIs C(--ssl) switch.
      - Setting this to C(false) disables hostname verification. Use with caution.
      - Requires pymysql >= 0.7.11.
    type: bool
    version_added: '1.1.0'
requirements:
   - PyMySQL (Python 2.7 and Python 3.x)
notes:
   - Requires the PyMySQL (Python 2.7 and Python 3.X) package installed on the remote host.
     The Python package may be installed with apt-get install python-pymysql (Ubuntu; see M(ansible.builtin.apt)) or
     yum install python2-PyMySQL (RHEL/CentOS/Fedora; see M(ansible.builtin.yum)). You can also use dnf install python2-PyMySQL
     for newer versions of Fedora; see M(ansible.builtin.dnf).
   - Be sure you have PyMySQL library installed on the target machine
     for the Python interpreter Ansible discovers. For example if ansible discovers and uses Python 3, you need to install
     the Python 3 version of PyMySQL. If ansible discovers and uses Python 2, you need to install the Python 2
     version of PyMySQL.
   - If you have trouble, it may help to force Ansible to use the Python interpreter you need by specifying
     C(ansible_python_interpreter). For more information, see
     U(https://docs.ansible.com/ansible/latest/reference_appendices/interpreter_discovery.html).
   - Both C(login_password) and C(login_user) are required when you are
     passing credentials. If none are present, the module will attempt to read
     the credentials from C(~/.my.cnf), and finally fall back to using the MySQL
     default login of 'root' with no password.
   - If there are problems with local connections, using I(login_unix_socket=/path/to/mysqld/socket)
     instead of I(login_host=localhost) might help. As an example, the default MariaDB installation of version 10.4
     and later uses the unix_socket authentication plugin by default that
     without using I(login_unix_socket=/var/run/mysqld/mysqld.sock) (the default path)
     causes the error ``Host '127.0.0.1' is not allowed to connect to this MariaDB server``.
   - "If credentials from the config file (for example, C(/root/.my.cnf)) are not needed to connect to a database server, but
     the file exists and does not contain a C([client]) section, before any other valid directives, it will be read and this
     will cause the connection to fail, to prevent this set it to an empty string, (for example C(config_file: ''))."
   - "To avoid the C(Please explicitly state intended protocol) error, use the I(login_unix_socket) argument,
     for example, C(login_unix_socket: /run/mysqld/mysqld.sock)."
   - Alternatively, to avoid using I(login_unix_socket) argument on each invocation you can specify the socket path
     using the `socket` option in your MySQL config file (usually C(~/.my.cnf)) on the destination host, for
     example C(socket=/var/lib/mysql/mysql.sock).
attributes:
  check_mode:
    description: Can run in check_mode and return changed status prediction without modifying target.
'''
