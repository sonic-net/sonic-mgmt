# This file contains the list of API's which performs TACSCS operations.
# @author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

from spytest.utils import filter_and_select
from spytest import st

def set_aaa_authentication_properties(dut,property,value):
        '''
        Configuring aaa authentication properties.
        '''
        command = "config aaa  authentication {} {}".format(property,value)
        rv = st.config(dut,command)
        return True


def set_tacacs_properties(dut,property,value):
        '''
        Configuring tacacs properties.
        '''
        command = "config tacacs {} {}".format(property,value)
        rv = st.config(dut,command)
        return True


def set_tacacs_server(dut,mode,address,tcp_port=None,timeout=None,passkey=None,auth_type=None,priority=None,use_mgmt_vrf= False):
        '''
        Configuring tacacs server properties.
        '''
        sub_opts = []
        if mode.lower() == 'add':
                command = "config tacacs {} {} ".format('add',address)
                if tcp_port:
                        sub_opts.append('{} {}'.format('-o',tcp_port))
                if timeout:
                        sub_opts.append('{} {}'.format('-t',timeout))
                if passkey:
                        sub_opts.append('{} {}'.format('-k',passkey))
                if auth_type:
                        sub_opts.append('{} {}'.format('-a',auth_type))
                if priority:
                        sub_opts.append('{} {}'.format('-p',priority))
                if use_mgmt_vrf:
                        sub_opts.append('{}'.format('-m'))
                command = command + ' '.join(sub_opts)

        elif mode.lower() == 'delete':
                command = "config tacacs {} {} ".format('delete',address)

        rv = st.config(dut,command)
        return True

def show_aaa(dut):
        '''
        To get the show aaa command output as list of dict
        '''
        command = "show aaa"
        return st.show(dut,command)

def show_tacacs(dut):
        '''
        To get the show tacacs command output as list of dict
        '''
        command = "show tacacs"
        out =  st.show(dut,command)
        ## Dividing show tacacs output as global and server
        rv ={'global':[],'servers':[]}
        rv['global']= [{'auth_type':out[0]['global_auth_type']\
                                        ,'passkey':out[0]['global_passkey']\
                                        ,'timeout':out[0]['global_timeout']}]
        for each_dict in out:
                if each_dict['address'] != '' and  each_dict['priority'] != '':
                        temp_dic = {
                                'address':each_dict['address']\
                                ,'priority':each_dict['priority']\
                                ,'tcp_port':each_dict['tcp_port'] \
                                ,'passkey': each_dict['passkey']\
                                ,'auth_type':each_dict['auth_type']\
                                ,'timeout':each_dict['timeout']
                                                }

                        rv['servers'].append(temp_dic)
        return rv

def verify_aaa(dut,login=None,failthrough=None,fallback=None):
        '''
        To verify the 'show aaa' parameters
        '''
        output = show_aaa(dut)
        if login and not filter_and_select(output, ['login'], {"login": login}):
                st.error("Provided and Configured login  values are not match.")
                return False
        if failthrough and not filter_and_select(output, ['failthrough'], {"failthrough": failthrough}):
                st.error("Provided and Configured failthrough  values are not match.")
                return False
        if fallback and not filter_and_select(output, ['fallback'], {"fallback": fallback}):
                st.error("Provided and Configured fallback values are not match.")
                return False
        return True


def verify_tacacs_global(dut,auth_type=None,timeout=None,passkey=None):
        '''
        To verify the 'show tacacs' global parameters
        '''
        output = show_tacacs(dut)
        output = output['global']
        if auth_type and not filter_and_select(output, ['auth_type'], {"auth_type": auth_type}):
                st.error("Global:Provided and Configured auth_type values are not match.")
                return False
        if timeout and not filter_and_select(output, ['timeout'], {"timeout": timeout}):
                st.error("Global:Provided and Configured timeout values are not match.")
                return False
        if passkey and not filter_and_select(output, ['passkey'], {"passkey": passkey}):
                st.error("Global:Provided and Configured passkey values are not match.")
                return False
        return True


def verify_tacacs_server(dut,address,tcp_port=None,timeout=None,passkey=None,auth_type=None,priority=None):
        '''
        To verify the 'show tacacs' server parameters
        '''
        output = show_tacacs(dut)
        output = output['servers']
        if address and not filter_and_select(output, ['address'], {"address": address}):
                st.error("Provided and configured address values are not matching.")
                return False
        if tcp_port and not filter_and_select(output, ['tcp_port'], {"tcp_port": tcp_port}):
                st.error("Provided and configured tcp_port values are not matching.")
                return False
        if priority and not filter_and_select(output, ['priority'], {"priority": priority}):
                st.error("Provided and configured priority values are not matching.")
                return False
        if timeout and not filter_and_select(output, ['timeout'], {"timeout": timeout}):
                st.error("Provided and configured timeout values are not matching.")
                return False
        if passkey and not filter_and_select(output, ['passkey'], {"passkey": passkey}):
                st.error("Provided and configured passkey values are not matching.")
                return False
        if auth_type and not filter_and_select(output, ['auth_type'], {"auth_type": auth_type}):
                st.error("Provided and configured auth_type values are not matching.")
                return False
        return True


def verify_tacacs_details(dut, tacacs_params):
    """
    API to verify the tacacs details
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param tacacs_params:
    :return:
    """
    if tacacs_params:
        output = show_tacacs(dut)
        if output and "servers" in output:
            output = output['servers']
            for params in tacacs_params:
                if params["ip"] and not filter_and_select(output, ['address'], {"address": params["ip"]}):
                    st.error("Provided and configured address values are not matching.")
                    return False
                if params["tcp_port"] and not filter_and_select(output, ['tcp_port'], {"tcp_port": params["tcp_port"]}):
                    st.error("Provided and configured tcp_port values are not matching.")
                    return False
                if params["priority"] and not filter_and_select(output, ['priority'], {"priority": params["priority"]}):
                    st.error("Provided and configured priority values are not matching.")
                    return False
                if params["timeout"] and not filter_and_select(output, ['timeout'], {"timeout": params["timeout"]}):
                    st.error("Provided and configured timeout values are not matching.")
                    return False
                if params["passkey"] and not filter_and_select(output, ['passkey'], {"passkey": params["passkey"]}):
                    st.error("Provided and configured passkey values are not matching.")
                    return False
                if params["auth_type"] and not filter_and_select(output, ['auth_type'], {"auth_type": params["auth_type"]}):
                    st.error("Provided and configured auth_type values are not matching.")
                    return False
            return True
        else:
            st.log("servers index not found in output ...")
            return False
    else:
        st.log("tacacs params not provided ...")
        return False