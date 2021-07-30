# This file contains the list of API's which performs User operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
import re
from spytest import st
from utilities.common import filter_and_select, make_list
from apis.security.rbac import add_user
from apis.system.rest import config_rest, delete_rest
import os, base64
from crypt import crypt


def config_user(dut, username, mode='add', cli_type=""):
    """
    Add/Delete the user name to the device.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param username:
    :param mode: add|del
    :return:
    """
    #cli_type = st.get_ui_type(dut, cli_type=cli_type)
    username = username.strip()
    if mode == 'add':
        command = "useradd {}".format(username)
        rv = st.config(dut, command)
        if "already exists" in rv:
            st.error("User '{}' already exists".format(username))
            return False
    else:
        command = "userdel {}".format(username)
        rv = st.config(dut, command)
        if "does not exist" in rv:
            st.log("User '{}' does not exist".format(username))
            return False
    return True

def show(dut, *argv, **kwargs):
    """
    Generic show API.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param argv:
    :param kwargs:
    :Usage:
        show(vars.D1, 'logged_users')
        show(vars.D1, 'user_list')
        show(vars.D1, 'group_list')
        show(vars.D1, user_group='admin')
    """
    cli_type = kwargs.get("cli_type", "click")
    if 'logged_users' in argv:
        return st.show(dut, "show users", type=cli_type)
    if 'user_list' in argv:
        command = "cat /etc/passwd | awk -F: '{ print $1}'"
        return st.show(dut, command, skip_tmpl=True, skip_error_check=True, faster_cli=False).split('\n')[:-1]
    if 'group_list' in argv:
        command = "getent group | awk -F: '{ print $1}'"
        return st.show(dut, command, skip_tmpl=True, skip_error_check=True, faster_cli=False).split('\n')[:-1]
    if kwargs.get('user_group'):
        return st.show(dut, "id {}".format(kwargs['user_group']), type=cli_type)


def verify(dut, *argv, **kwargs):
    """
    Generic verify API.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param argv:
    :param kwargs:
    :Usage:
        verify(vars.D1, 'logged_users', verify_list=[{'user':'admin'}, {'user':'test1}])
        verify(vars.D1, 'user_list', verify_list=['admin', 'test1'])
        verify(vars.D1, 'group_list', verify_list=['admin','operator'])
        verify(vars.D1, user_group='admin', verify_list=[{'group':'admin'}])
    """
    cli_type = kwargs.get("cli_type","")
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    result = True
    if not kwargs.get('verify_list'):
        st.error("Mandatory parameter -verify_list is missing")
        return False
    out = show(dut, *argv, **kwargs)
    if 'logged_users' in argv or kwargs.get('user_group'):
        for each in make_list(kwargs.get('verify_list')):
            if cli_type == "click":
                if not filter_and_select(out, None, each):
                    st.log("{} - {} is not match".format(each, out))
                    result = False
            else:
                out[0]['secondary_group'] = re.findall(r'\(([^)]+)', out[0]['secondary_group'])
                if each['group'] == 'sudo':
                    each['group'] = 'operator'
                if each['group'] not in out[0]['secondary_group']:
                    st.log("{} - {} is not match".format(each, out))
                    result = False
    if 'user_list' in argv or 'group_list' in argv:
        for each in make_list(kwargs.get('verify_list')):
            if each not in out:
                st.log("{} - is not found in {}".format(each, out))
                result = False

    return result


def config(dut, **kwargs):
    """
    Add/Delete  username with password and role to the device.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param :dut:
    :param :username:
    :param :password:
    :param :role:   admin | operator
    :param :group:
    :param :cli_type:  click | klish
    :param :no_form: 0[False] | 1[True]

    :Usage:
    config(vars.D1, username='test', password='test123', role='operator', cli_type='kilsh')
    config(vars.D1, username='test', cli_type='kilsh', no_form=True)
    config(vars.D1, username='test', password='test123', role='admin', cli_type='click', no_form=0)
    config(vars.D1, username='test', password_update='test1234', cli_type='click', no_form=0)
    config(vars.D1, group='admin_test', cli_type='click', no_form=0)
    config(vars.D1, group='admin_test', cli_type='click', no_form=1)
    config(vars.D1, username='test', password='test123', role='admin', cli_type='click', no_form=1)
    """
    cli_type = kwargs.get("cli_type", "")
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    no_form = kwargs.get("no_form", False)

    if cli_type == "click":
        if not no_form:
            if kwargs.get('group'):
                st.config(dut, "groupadd {}".format(kwargs['group']))
            if kwargs.get('username'):
                command = "useradd {} -m".format(kwargs['username'])
                if kwargs.get('role'):
                    command += " -g {}".format(kwargs['role'])
                st.config(dut, command)
            if kwargs.get('username') and kwargs.get('password'):
                st.change_passwd(dut, kwargs['username'], kwargs['password'])
            if kwargs.get('username') and kwargs.get('append_role'):
                st.config(dut, "usermod -aG {} {}".format(kwargs['append_role'], kwargs['username']))
        else:
            if kwargs.get('username') and kwargs.get('role'):
                st.config(dut, "gpasswd -d {} {}".format(kwargs['username'], kwargs['role']))
            if kwargs.get('group'):
                st.config(dut, "groupdel {}".format(kwargs['group']))
            if kwargs.get('username'):
                st.config(dut, "userdel {} -r".format(kwargs['username']))

    elif cli_type == "klish":
        if not kwargs.get('username'):
            st.error("Mandatory parameter 'username' is missing")
            return False
        if not no_form:
            if not kwargs.get("password") and not kwargs.get('role'):
                st.error("Mandatory parameter 'password' and 'role' is missing")
                return False
            if kwargs['role'] == 'sudo':
                kwargs['role'] = 'operator'
        command = "username {} password {} role {}".format(kwargs['username'], kwargs['password'], kwargs['role'])
        if no_form:
            command = "no username {} ".format(kwargs['username'])
        st.config(dut, command, type=cli_type, skip_error_check=True)
        add_user(dut, kwargs['username'])
    elif cli_type in ['rest-patch', 'rest-put']:
        if not no_form:
            if kwargs['role'] == 'sudo':
                kwargs['role'] = 'operator'
            data={
                 "openconfig-system:user": [
                 {
                 "username": str(kwargs['username']),
                 "config": {
                 "username": str(kwargs['username']),
                 "password": "",
                 "password-hashed": hashed_pwd(kwargs['password']),
                 "ssh-key": "",
                 "role": str(kwargs['role'])
                 }
               }
             ]
            }
            rest_urls = st.get_datastore(dut, "rest_urls")
            url1 = rest_urls['user_creation_del'].format(kwargs['username'])
            if not config_rest(dut, http_method=cli_type, rest_url=url1, json_data=data):
                st.error("Failed to configure user {} ".format(kwargs['username']))
                return False
        if no_form:
            rest_urls = st.get_datastore(dut, "rest_urls")
            url1 = rest_urls['user_creation_del'].format(kwargs['username'])
            if not delete_rest(dut, http_method=cli_type, rest_url=url1):
                st.error("Failed to delete user {} ".format(kwargs['username']))
    else:
        st.log("UNSUPPORTED CLI TYPE -- {}".format(cli_type))
        return False
    return True


def hashed_pwd(pwd):
    pwd = pwd.replace("\\","")
    if pwd[:3] == '$6$':
        return pwd
    salt = base64.b64encode(os.urandom(6), './')
    return crypt(pwd, '$6$' + salt)
