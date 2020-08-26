# This file contains the list of API's which performs User operations.
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

from spytest import st
from utilities.common import filter_and_select, make_list


def config_user(dut, username, mode='add'):
    """
    Add/Delete the user name to the device.
    Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param username:
    :param mode: add|del
    :return:
    """
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
    result = True
    if not kwargs.get('verify_list'):
        st.error("Mandatory parameter -verify_list is missing")
        return False
    out = show(dut, *argv, **kwargs)
    if 'logged_users' in argv or kwargs.get('user_group'):
        for each in make_list(kwargs.get('verify_list')):
            if not filter_and_select(out, None, each):
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
    cli_type = kwargs.get("cli_type", "klish")
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
            if not no_form:
                if not kwargs.get("password") and not kwargs.get('role'):
                    st.error("Mandatory parameter 'password' and 'role' is missing")
            return False
        command = "username {} password {} role {}".format(kwargs['username'], kwargs['password'], kwargs['role'])
        if no_form:
            command = "no username {} ".format(kwargs['username'])
        st.config(dut, command, type=cli_type, skip_error_check=True)

    else:
        return False

    return True
