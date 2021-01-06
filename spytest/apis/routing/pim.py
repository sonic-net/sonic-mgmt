from __future__ import division
from spytest.utils import filter_and_select
from spytest import st
import re
from apis.common import redis

def config_pim_global(dut, **kwargs):
    """
    config_pim_global(dut=data.dut1,pim_enable='yes',config='yes',hello_intv= 50)

    Configure interface with pim configurations
    :param dut:
    :param ecmp_rebalance:
    :param ecmp:
    :param join_prune_interval:
    :param packets:
    :param ssm_prefix_list:
    :return:
    """
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    if 'vrf' in kwargs:
        vrf = kwargs['vrf']
    else:
        vrf = 'default'

    maxtime = kwargs['maxtime'] if 'maxtime' in kwargs else 0

    if vrf == 'default':
        my_cmd = ''
    else:
        my_cmd = 'vrf {}\n'.format(vrf)

    if 'ecmp_rebalance' in kwargs:
        my_cmd += '{} ip pim ecmp rebalance \n'.format(config_cmd)

    if 'ecmp' in kwargs:
        my_cmd += '{} ip pim ecmp \n'.format(config_cmd)

    if 'join_prune_interval' in kwargs:
        my_cmd += '{} ip pim join-prune-interval {} \n'.format(config_cmd, kwargs['join_prune_interval'])

    if 'keep_alive' in kwargs:
        my_cmd += '{} ip pim keep-alive-timer {} \n'.format(config_cmd, kwargs['keep_alive'])

    if 'packets' in kwargs:
        my_cmd += '{} ip pim packets {} \n'.format(config_cmd, kwargs['packets'])

    if 'ssm_prefix_list' in kwargs:
        my_cmd += '{} ip pim ssm prefix-list {} \n'.format(config_cmd, kwargs['ssm_prefix_list'])

    if vrf != 'default':
        my_cmd += 'exit-vrf\n'

    skip_error = bool(kwargs.get('skip_error', False))
    return st.config(dut, my_cmd, type='vtysh', skip_error_check=skip_error,max_time=maxtime)

def config_intf_pim(dut, **kwargs):
    """
    config_intf_pim(dut=data.dut1,intf ='Ethernet10',pim_enable='yes',config='yes',hello_intv= 50)

    Configure interface with pim configurations
    :param dut:
    :param intf:
    :param pim_enable:
    :param hello_intv:
    :param drpriority:
    :param use_source:
    :param bfd_enable:
    :return:
    """

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    maxtime = kwargs['maxtime'] if 'maxtime' in kwargs else 0

    if 'intf' in kwargs:
        if type(kwargs['intf']) is list:
            kwargs['intf'] = list(kwargs['intf'])
        else:
            kwargs['intf'] = [kwargs['intf']]
    else:
        return ""

    my_cmd= ''
    output = ''
    use_batch = bool(kwargs.get('use_batch', True))
    skip_error = bool(kwargs.get('skip_error', False))
    for intf in kwargs['intf']:
        my_cmd += 'interface {}\n'.format(intf)

        if 'pim_enable' in kwargs:
            my_cmd += '{} ip pim \n'.format(config_cmd)

        if 'hello_intv' in kwargs:
            if 'hold_time' in kwargs:
                my_cmd += '{} ip pim hello {} {}\n'.format(config_cmd, kwargs['hello_intv'], kwargs['hold_time'])
            else:
                my_cmd += '{} ip pim hello {} \n'.format(config_cmd, kwargs['hello_intv'])

        if 'drpriority' in kwargs:
            my_cmd += '{} ip pim drpriority {} \n'.format(config_cmd, kwargs['drpriority'])

        if 'use_source' in kwargs:
            my_cmd += '{} ip pim use-source {} \n'.format(config_cmd, kwargs['use_source'])

        if 'bfd_enable' in kwargs:
            my_cmd += '{} ip pim bfd\n'.format(config_cmd)

        if not use_batch:
            my_cmd += "exit\n"
            output = output + st.config(dut, my_cmd, type='vtysh', skip_error_check=skip_error)
            my_cmd = ''

    if use_batch:
        #my_cmd += "exit\n"
        output = st.config(dut, my_cmd, type='vtysh', skip_error_check=skip_error,max_time=maxtime)

    return output

def config_ip_mroute(dut, **kwargs):
    """
    Configure global or interface mroute configurations
    :param dut:
    :param dest_ip:
    :param dest_ip_mask:
    :param next_hop:
    :param distance: (OPTIONAL Parameter)
    :return:
    config_ip_mroute('dut1',dest_ip='232.1.1.1',dest_ip_mask='8',next_hop='Ethernet24',distance=10) - global
    config_ip_mroute('dut1',intf='Etherent24',oif='Ethernet32',group='232.1.1.1',source='10.1.1.2') - interface scope
    """
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    if 'intf' in kwargs:
        my_cmd = 'interface {}\n'.format(kwargs['intf'])
        my_cmd += '{} ip mroute {} {} {}\n'.format(config_cmd,kwargs['oif'],kwargs['group'],kwargs['source'])
    else:
        my_cmd = ''
        if 'distance' in kwargs:
            my_cmd += '{} ip mroute {}/{} {} {}\n'.format(config_cmd,kwargs['dest_ip'],kwargs['dest_ip_mask'],kwargs['next_hop'],kwargs['distance'])
        else:
            my_cmd += '{} ip mroute {}/{} {}\n'.format(config_cmd,kwargs['dest_ip'], kwargs['dest_ip_mask'], kwargs['next_hop'])

    #if kwargs.has_key('intf'):
    #    my_cmd += 'exit\n'

    skip_error = bool(kwargs.get('skip_error', False))
    return st.config(dut, my_cmd, type='vtysh', skip_error_check=skip_error)


def config_ip_multicast_rpf_lookup(dut, **kwargs):
    """
    config_ip_multicast_rpf_lookup(dut=data.dut1,rpf_lookup_mode ='longer-prefix'config='yes')

    Configure multicast RPF lookup mode
    :param dut:
    :param rpf_lookup_mode:
    :return:
    """
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    if 'rpf_lookup_mode' in kwargs:
        my_cmd = '{} ip multicast rpf-lookup-mode {}\n'.format(config_cmd,kwargs['rpf_lookup_mode'])

    skip_error = bool(kwargs.get('skip_error', False))
    return st.config(dut, my_cmd, type='vtysh', skip_error_check=skip_error)


def config_intf_multicast(dut, **kwargs):
    """
    config_intf_multicast(dut=data.dut1,intf ='Ethernet10',config='yes')

    Configure interface with pim configurations
    :param dut:
    :param intf:
    :return:
    """

    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    if 'intf' in kwargs:
        my_cmd = 'interface {}\n'.format(kwargs['intf'])
        my_cmd += '{} multicast \n'.format(config_cmd)
        my_cmd += 'exit\n'

    skip_error = bool(kwargs.get('skip_error', False))
    return st.config(dut, my_cmd, type='vtysh', skip_error_check=skip_error)

def config_ip_multicast_boundary(dut, **kwargs):
    """
    config_ip_multicast_boundary(dut=data.dut1,rpf_lookup_mode ='longer-prefix'config='yes')

    Configure multicast RPF lookup mode
    :param dut:
    :param intf:
    :param oil_prefix_list:
    :return:
    """
    if 'config' in kwargs:
        config = kwargs['config']
    else:
        config = 'yes'

    if config.lower() == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'

    my_cmd = 'interface {}\n'.format(kwargs['intf'])
    my_cmd += '{} ip multicast boundary oil {}\n'.format(config_cmd,kwargs['oil_prefix_list'])
    my_cmd += 'exit\n'

    skip_error = bool(kwargs.get('skip_error', False))
    return st.config(dut, my_cmd, type='vtysh', skip_error_check=skip_error)


def verify_ip_mroute(dut,**kwargs):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param source:
    :type string or list
    :param group:
    :type string or list
    :param proto:
    :type protocol type in string or list
    :param iif:
    :type incoming interface as string or list
    :param oif:
    :type outgoing interface as list or string
    :param ttl:
    :type ttl value as list or string
    :param uptime
    :type uptime in list or string
    :param vrf
    :type vrfname as list or string
    :return:

    Usage
    pim.verify_ip_mroute(data.dut1,source='10.10.10.1',group='225.1.1.1',proto='STATIC',iif='Ethernet10',
                                       oif='Ethernet12',ttl='1',vrf='default')
    pim.verify_ip_mroute(data.dut1,source=['10.10.10.1','20.20.20.1'],group=['225.1.1.1','232.0.0.1'],proto=['STATIC','STATIC']
                                    ,iif=['Ethernet10','Ethernet5'] , oif=['Ethernet12','Ethernet12'],ttl=['1','1'],vrf=['default','RED'])
    """

    ret_val = True
    if 'vrf' in kwargs:
        vrf = kwargs['vrf']
        del kwargs['vrf']
    else:
        vrf = 'default'

    if vrf != 'default':
        cmd = 'show ip mroute vrf {}'.format(vrf)
    else:
        cmd = 'show ip mroute'

    skip_tmpl = kwargs.pop('skip_tmpl',False)

    if 'skip_error' in kwargs:
        skip_error = kwargs['skip_error']
        del kwargs['skip_error']
    else:
        skip_error = False
    output = st.show(dut,cmd,skip_error_check=skip_error,skip_tmpl=skip_tmpl, type='vtysh')

    if 'return_output' in kwargs:
        return output

    if len(output) == 0:
        st.error("Output is Empty")
        return False

    #Converting all kwargs to list type to handle single or list of mroute instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    #convert kwargs into list of dictionary
    input_dict_list =[]
    for i in range(len(kwargs[kwargs.keys()[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    for input_dict in input_dict_list:
        entries = filter_and_select(output,None,match=input_dict)
        if not entries:
            st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
            ret_val = False
    return ret_val


def verify_pim_show(dut,**kwargs):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut
    :type string
    :param cmd_type
    :type string (CLI type)


    :API type: "show ip pim neighbor"
    :arg_list: interface,neighbor,dr_priority,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,interface=['Ethernet24','Ethernet10'],neighbor=['10.10.10.2','10.10.10.3'],dr_priority=['10','20'],vrf='RED',cmd_type='neighbor')
    pim.verify_pim_show(dut1,interface='Ethernet24',neighbor='10.10.10.2',dr_priority='10',vrf='RED',cmd_type='neighbor')



    :API type: "show ip pim interface"
    :arg_list: interface,state,address,nbr_count,dr,fhrif_channels,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='interface',interface=['Ethernet24','pimreg'],state=['up']*2,address=['10.10.10.1','0.0.0.0'],
                                nbr_count=[1,0],dr=['10.10.10.2','local'],fhr=[0,0],if_channels=[0,0],vrf='default')
    pim.verify_pim_show(dut1,cmd_type='interface',interface='Ethernet24',state='up',address='10.10.10.1',nbr_count=1,dr='10.10.10.2',fhr=0,if_channels=0)



    :API type: "show ip pim state "
    :arg_list:source,group,iif,flag,installed'
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,type='state',source='10.10.10.2',group='232.1.1.2',iif='Ethernet24',oif=[['Ethernet10','Vlan100']],flag=[['IJ'],['J']])



    :API type: "show ip pim interface traffic "
    :arg_list:interface,vrf,hello_rx,hello_tx,join_rx,join_tx,prune_rx,prune_tx,register_rx,register_tx,register_stop_tx,register_stop_rxassert_rxassert_tx,vrf
    :arg_type: String or list
    :Usage:
     pim.verify_pim_show(dut1,cmd_type='interface traffic',interface='Ethernet24',vrf='default',hello_rx=32,hello_tx=32,join_rx=0,join_tx=0,
                                      prune_rx=0,prune_tx=0,register_rx=0,register_tx=0,register_stop_tx=0,
                                      register_stop_rx=0,assert_rx=0,assert_tx=0)


    :API type: "show ip pim nexthop"
    :arg_list: source,interface,nexthop,registered_count,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='nexthop',source=['10.10.10.2'],interface=['Ethernet24'],nexthop=['10.10.10.2'],registered_count=1)



    :API type: "show ip pim assert "
    :arg_list: interface,address,source,group,state,winner,uptime,timer,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='assert',interface=[],address=[],source=[],group=[],state=[],winner=[],uptime=[],timer=[])
    pim.verify_pim_show(dut1,cmd_type='assert',interface='',address='',source='',group='',state='',winner='',uptime='',timer='')


    :API type: "show ip pim assert-internal "
    :arg_list: interface,address,source,group,ca,eca,atd,eatd,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='assert-internal',interface=[],address=[],source=[],group=[],ca=[],eca=[],atd=[],eatd=[],vrf='RED')
    pim.verify_pim_show(dut1,cmd_type='assert-internal',interface='',address='',source='',group='',ca='',eca='',atd='',eatd='')


    :API type: "show ip pim assert-metric "
    :arg_list: interface,address,source,group,rpt,pref,metric,address2,vrf
    :arg_type:
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='assert-metric',interface='',address='',source='',group='',rpt='',pref='',metric='',address2='',vrf='RED')
    pim.verify_pim_show(dut1,cmd_type='assert-metric',interface=[],address=[],source=[],group=[],rpt=[],pref=[],metric=[],address2=[],vrf='RED')



    :API type: "show ip pim assert-winner-metric "
    :arg_list: interface,address,source,group,rpt,pref,metric,address2,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='assert-winner-metric',interface='',address='',source='',group='',rpt='',pref='',metric='',address2='',vrf='RED')
    pim.verify_pim_show(dut1,cmd_type='assert-winner-metric',interface=[],address=[],source=[],group=[],rpt=[],pref=[],metric=[],address2=[],vrf='RED')


    :API type: "show ip pim upstream "
    :arg_list: iif,source,group,state,uptime,jointimer,rstimer,katimer,refcnt,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='upstream',source=[],group=[],state=[],uptime=[],jointimer=[],rstimer=[],katimer=[],refcnt=[],vrf='default')
    pim.verify_pim_show(dut1,cmd_type='upstream',source='',group='',state='',uptime='',jointimer='',rstimer='',katimer='',refcnt='',vrf='RED')


    :API type: "show ip pim upstream-join-desired "
    :arg_list: interface,source,group,lostassert,joins,piminclude,joindesired,evaljd,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='upstream-join-desired',interface=[],source=[],group=[],lostassert=[],joins=[],piminclude=[],joindesired=[],evaljd=[],vrf='default')
    pim.verify_pim_show(dut1,cmd_type='upstream-join-desired',interface='',source='',group='',lostassert='',joins='',piminclude='',joindesired='',evaljd='',vrf='RED')


    :API type: "show ip pim upstream-rpf "
    :arg_list: source,group,rpfiface,ribnexthop,rpfaddress,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='upstream-rpf',source=[],group=[],rpfiface=[],ribnexthop=[],rpfaddress=[],vrf='RED')
    pim.verify_pim_show(dut1,cmd_type='upstream-rpf',source='',group='',rpfiface='',ribnexthop='',rpfaddress='',vrf='default')

    :API type: "show ip pim join "
    :arg_list: interface,address,source,group,state,uptime,expire,prune,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='join',interface=[],address=[],source=[],group=[],state=[],uptime=[],expire=[],prune=[],vrf='RED')
    pim.verify_pim_show(dut1,cmd_type='join',interface='',address='',source='',group='',state='',uptime='',expire='',prune='',vrf='RED')

    :API type: "show ip pim secondary "
    :arg_list: interface,address,neighbor,secondary,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='secondary',interface=[],address=[],neighbor=[],secondary=[],vrf='RED')
    pim.verify_pim_show(dut1,cmd_type='secondary',interface='',address='',neighbor='',secondary='',vrf='RED')

    :API type: "show ip pim local-membership "
    :arg_list: interface,address,source,group,membership,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='local-membership',interface=[],address=[],source=[],group=[],membership=[],vrf='RED')
    pim.verify_pim_show(dut1,cmd_type='local-membership',interface='',address='',source='',group='',membership='',vrf='RED')

    :API type: "show ip pim rpf"
    :arg_list: cache_ref_delay,cache_ref_timer,cache_ref_reqs,cache_ref_events,cache_ref_last,nexthop_lookup,nexthop_lookup_avoid,
                source,group,rpfiface,ribnexthop,rpfaddress,metric,pref,vrf
    :arg_type: String or list
    :Usage:
    pim.verify_pim_show(dut1,cmd_type='rpf',cache_ref_delay='',cache_ref_timer='',cache_ref_reqs=''
                        ,cache_ref_events='',cache_ref_last='',nexthop_lookup='',nexthop_lookup_avoid=''
                         source=[],group=[],rpfiface=[],ribnexthop=[],rpfaddress=[],metric=[],pref=[],vrf='RED')

    """

    ret_val = True
    if 'cmd_type' in kwargs:
        cmd_type = kwargs['cmd_type']
        del kwargs['cmd_type']
    else:
        cmd_type = 'neighbor'

    if 'vrf' in kwargs:
        vrf_name = kwargs['vrf']
        del kwargs['vrf']
    else:
        vrf_name = 'default'

    if vrf_name != 'default':
        cmd = 'show ip pim vrf {} {}'.format(vrf_name,cmd_type)
    else:
        cmd = "show ip pim {}".format(cmd_type)

    skip_tmpl = kwargs.pop('skip_tmpl', False)
    if 'skip_error' in kwargs:
        skip_error = kwargs['skip_error']
        del kwargs['skip_error']
    else:
        skip_error = False
    output = st.show(dut,cmd,skip_error_check=skip_error,skip_tmpl=skip_tmpl, type='vtysh')

    if 'return_output' in kwargs:
        return output

    if len(output) == 0:
        st.error("Output is Empty")
        return False

    common_param = ['registered_count','cache_ref_delay','cache_ref_timer','cache_ref_reqs','cache_ref_events',\
                    'cache_ref_last','nexthop_lookup','nexthop_lookup_avoid']
    for key in common_param:
        if key in kwargs:
            if str(kwargs[key]) != str(output[0][key]):
                st.error("Match not Found for {}: Expected - {} Actual- {}".format(key,kwargs[key],output[0][key]))
                ret_val = False
            else:
                st.log("Match Found for {}: Expected - {} Actual- {}".format(key,kwargs[key],output[0][key]))
            del kwargs[key]

    if cmd_type == 'state':
        for entry in output:
            entry_index = output.index(entry)
            if entry['oif'] != '':
                pattern = re.compile(r'\w+')
                result = pattern.findall(entry['oif'])
                res = result[::2] + result[1::2]
                res_by_2 = int(len(res)/2)
                oif_list = [str(oif) for oif in res[:res_by_2]]
                flag_list = [str(flag) for flag  in res[res_by_2:]]
                output[entry_index]['oif'] = oif_list
                output[entry_index]['flag'] = flag_list
    #Converting all kwargs to list type to handle single or list of mroute instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    #convert kwargs into list of dictionary
    input_dict_list =[]
    for i in range(len(kwargs[kwargs.keys()[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    for input_dict in input_dict_list:
        entries = filter_and_select(output,None,match=input_dict)
        if not entries:
            st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
            ret_val = False

    return ret_val

def verify_pim_neighbor_detail(dut,**kwargs):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param interface:
    :type string or list of PIM interfaces
    :param neighbor
    :type string or list of neighbors
    :param:uptime
    :type string or list
    :param holdtime
    :type string or list
    :param dr_priority
    :type string or list
    :param gen_id
    :type string or list
    :param override_interval
    :type string or list
    :param propogation delay
    :type string or list
    :param hello_addr_list
    :type string or list
    :param hello_dr_priority
    :type string or list
    :param hello_gen_id
    :type string or list
    :param hello_holdtime
    :type string or list
    :param hello_lan_prune_delay
    :type string or list
    :param hello_t_bit
    :type string or list
    :param vrf
    :type string
    :return:

    Usage
    pim.verify_pim_neighbor_detail(dut1,neighbor=['10.10.10.2','20.20.20.2'],interface=['Ethernet24','Ethernet32'])
    pim.verify_pim_neighbor_detail(dut1,neighbor='10.10.10.2',interface='Ethernet24')
    """

    ret_val = True
    if 'vrf' in kwargs:
        vrf_name = kwargs['vrf']
        del kwargs['vrf']
    else:
        vrf_name = 'default'

    #Converting all kwargs to list type to handle single or list of mroute instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    if len(kwargs['neighbor']) > 1:
        if vrf_name == 'default':
            cmd = "show ip pim neighbor detail"
        else:
            cmd = "show ip pim vrf {} neighbor detail".format(vrf_name)
    else:
        if vrf_name == 'default':
            cmd = "show ip pim neighbor {}".format(kwargs['neighbor'][0])
        else:
            cmd = "show ip pim vrf {} neighbor {}".format(vrf_name,kwargs['neighbor'][0])

    skip_tmpl = kwargs.pop('skip_tmpl', False)
    if 'skip_error' in kwargs:
        skip_error = kwargs['skip_error']
    else:
        skip_error = False

    output = st.show(dut,cmd,skip_error_check=skip_error,skip_tmpl=skip_tmpl ,type='vtysh')

    if 'return_output' in kwargs:
        return output
    if len(output) == 0:
        st.error("Output is Empty")
        return False
    for i in range(len(kwargs['neighbor'])):
        nbr_index = None
        st.log("Validation for PIM neighbor : {}".format(kwargs['neighbor'][i]))
        for peer_info in output:
            if str(peer_info['neighbor']) == str(kwargs['neighbor'][i]):
                nbr_index = output.index(peer_info)
        if nbr_index is not None:
            #Iterate through the user parameters
            for k in kwargs.keys():
                if str(output[nbr_index][k]) == str(kwargs[k][i]):
                    st.log('Match Found for {} :: Expected: {}  Actual : {}'.format(k,kwargs[k][i],output[nbr_index][k]))
                    ret_val=True
                else:
                    st.error('Match Not Found for {} :: Expected: {}  Actual : {}'.format(k,kwargs[k][i],output[nbr_index][k]))
                    return False
        else:
            st.error(" PIM neighbor {} not in output".format(kwargs['neighbor'][i]))
            return False

    return ret_val


def verify_pim_interface_detail(dut,**kwargs):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param interface:
    :type  String or list
    :param state
    :type String or list
    :param primary_addr
    :type String or list
    :param secondary_addr
    :type list of list
    :param pim_nbr
    :type String or list
    :param nbr_state
    :type String or list
    :param nbr_uptime
    :type String or list
    :param nbr_expiry_timer
    :type String or list
    :param dr_addr
    :type String or list
    :param dr_priority
    :type String or list
    :param dr_priority_local
    :type String or list
    :param dr_changes
    :type String or list
    :param period
    :type String or list
    :param timer
    :type String or list
    :param stat_start
    :type String or list
    :param receive
    :type String or list
    :param receive_failed
    :type String or list
    :param send
    :type String or list
    :param send_failed
    :type String or list
    :param gen_id
    :type String or list
    :param all_multicast
    :type String or list
    :param broadcast
    :type String or list
    :param deleted
    :type String or list
    :param ifindex
    :type String or list
    :param multicast
    :type String or list
    :param multicast_loop
    :type String or list
    :param promiscuous
    :type String or list
    :param lan_delay
    :type String or list
    :param eff_propogation_delay
    :type String or list
    :param eff_override_interval
    :type String or list
    :param join_prune_override_interval
    :type String or list
    :param propogation_delay
    :type String or list
    :param propogation_delay_high
    :type String or list
    :param override_interval
    :type String or list
    :param override_interval_high
    :type String or list
    :param vrf
    :type String
    :return:

    Usage
    pim.verify_pim_interface_detail(dut1,interface=['Ethernet24','Ethernet32'],state=['up','up'],primar_addr=['10.10.10.1','20.20.20.1'],
                                    secondary_addr=[['fe80::3e2c:99ff:fea6:fba0/64'],['fe80::3e2c:99ff:fea6:fba0/64']])
    pim.verify_pim_interface_detail(dut1,interface='Ethernet24',primary_addr='10.10.10.1',secondary_addr=[['fe80::3e2c:99ff:fea6:fba0/64']])
    """

    ret_val = True
    if 'vrf' in kwargs:
        vrf_name = kwargs['vrf']
        del kwargs['vrf']
    else:
        vrf_name = 'default'

    #Converting all kwargs to list type to handle single or list of mroute instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    if len(kwargs['interface']) > 1:
        if vrf_name == 'default':
            cmd = "show ip pim interface detail"
        else:
            cmd = "show ip pim vrf {} interface detail".format(vrf_name)
    else:
        if vrf_name == 'default':
            cmd = "show ip pim interface {}".format(kwargs['interface'][0])
        else:
            cmd = "show ip pim vrf {} interface {}".format(vrf_name,kwargs['interface'][0])

    if 'skip_error' in kwargs:
        skip_error = kwargs['skip_error']
        del kwargs['skip_error']
    else:
        skip_error = False

    skip_tmpl = kwargs.pop('skip_tmpl', False)
    output = st.show(dut, cmd, skip_error_check=skip_error,skip_tmpl=skip_tmpl,type='vtysh')

    if 'return_output' in kwargs:
        return output
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    for i in range(len(kwargs['interface'])):
        nbr_index = None
        st.log("Validation for PIM interface : {}".format(kwargs['interface'][i]))
        for peer_info in output:
            if str(peer_info['interface']) == str(kwargs['interface'][i]):
                nbr_index = output.index(peer_info)
        if nbr_index is not None:
            #Iterate through the user parameters
            for k in kwargs.keys():
                if str(output[nbr_index][k]) == str(kwargs[k][i]):
                    st.log('Match Found for {} :: Expected: {}  Actual : {}'.format(k,kwargs[k][i],output[nbr_index][k]))
                    ret_val=True
                else:
                    st.error('Match Not Found for {} :: Expected: {}  Actual : {}'.format(k,kwargs[k][i],output[nbr_index][k]))
                    return False
        else:
            st.error(" PIM Interface {} not in output".format(kwargs['interface'][i]))
            return False

    return ret_val


def verify_pim_nexthop_lookup(dut,**kwargs):
    """

    :param dut:
    :param source
    :type string
    :param group
    :type string
    :param interface
    :type string
    :param vrf
    :type string
    :return:
    """
    ret_val = True
    if 'vrf' in kwargs:
        vrf_name = kwargs['vrf']
        del kwargs['vrf']
    else:
        vrf_name = 'default'

    if 'source' not in kwargs or 'group' not in kwargs:
        st.error("Mandatory arguments -source or -group Missing")
        return False

    if vrf_name != 'default':
        cmd = 'show ip pim vrf {} nexthop-lookup {} {}'.format(vrf_name,kwargs['source'],kwargs['group'])
    else:
        cmd = "show ip pim nexthop-lookup {} {}".format(kwargs['source'],kwargs['group'])

    output = st.show(dut,cmd, type='vtysh')
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if 'return_output' in kwargs:
        return output

    for key in kwargs:
        if str(kwargs[key]) != str(output[0][key]):
            st.error("Match not found for {} : Expected- {} Actual - {}".format(key,kwargs[key],output[0][key]))
            ret_val = False
        else:
            st.log("Match found for {} : Expected- {} Actual - {}".format(key, kwargs[key], output[0][key]))
    return ret_val

def verify_pim_ssm_range(dut,group_range='232.0.0.0/8',vrf='default',return_output='no'):
    """
    :param dut:
    :param group_range:
    :param vrf:
    :return:

    Usage:
    pim.verify_pim_ssm_range(dut1,group_range='224.0.0.0/8')
    """

    if vrf == 'default':
        cmd = 'show ip pim group-type'
    else:
        cmd = 'show ip pim vrf {} group-type'.format(vrf)

    output = st.show(dut,cmd, type='vtysh')
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if return_output == 'yes':
        return output

    if str(output[0]['ssm_group_range']) == group_range:
        st.log("Match Found for SSM group range :Expected- {} Actual-{}".format(group_range,output[0]['ssm_group_range']))
    else:
        st.error("Match Not Found for SSM group range: Expected- {} Actual-{}".format(group_range,output[0]['ssm_group_range']))
        return False

def verify_pim_group_type(dut,group,group_type,vrf='default',return_output='no'):
    """
    :param dut:
    :param group_id:
    :param vrf_name:
    :param return_output:
    :return:

    Usage:
    pim.verify_pim_group_type(dut1,group='224.1.1.1',group_type='ASM')
    """

    if vrf == 'default':
        cmd = 'show ip pim group-type {}'.format(group)
    else:
        cmd = 'show ip pim vrf {} group-type {}'.format(vrf,group)

    output = st.show(dut,cmd, type='vtysh')
    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if return_output == 'yes':
        return output

    if output[0]['group_type'] == group_type:
        st.log("Match Found for Group Type for {} :Expected- {} Actual-{}".format(group,group_type,output[0]['group_type']))
    else:
        st.error("Match Not Found for Group Type for {} :Expected- {} Actual-{}".format(group,group_type,output[0]['group_type']))
        return False


def clear_mroute(dut,vrf='default'):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param vrf:
    :return:
    """
    if vrf == 'default':
        cmd = "clear ip mroute"
    else:
        cmd = "clear ip mroute vrf {}".format(vrf)

    st.config(dut,cmd, type='vtysh', conf=False)


def clear_pim_traffic(dut,vrf='default'):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param vrf:
    :return:
    """

    if vrf == 'default':
        cmd = "clear ip pim interface traffic"
    else:
        cmd = "clear ip pim vrf {} interface traffic".format(vrf)

    st.config(dut, cmd, type='vtysh', conf=False)

def clear_pim_interfaces(dut,vrf='default'):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param vrf:
    :return:
    """

    if vrf == 'default':
        cmd = "clear ip pim interfaces"
    else:
        cmd = "clear ip pim vrf {} interfaces".format(vrf)

    st.config(dut, cmd, type='vtysh', conf=False)


def clear_pim_oil(dut,vrf='default'):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param vrf:
    :return:
    """

    if vrf == 'default':
        cmd = "clear ip pim oil"
    else:
        cmd = "clear ip pim vrf {} oil".format(vrf)

    st.config(dut, cmd, type='vtysh', conf=False)


def debug_pim(dut,**kwargs):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :return:

    Usage:
    +++++
    debug_pim('dut1',type_list=['events','nht','packet_dump','packets','trace','trace_detail','zebra'],direction='both',pkt_type='all')
    debug_pim(dut1)
    """


    if 'config' in kwargs:
        config= kwargs['config']
    else:
        config = 'yes'

    if config == 'yes':
        config_cmd = ''
    else:
        config_cmd = 'no'
    cmd = ''

    if 'type_list' in kwargs:
        for type in kwargs['type_list']:
            if type == 'events':
                cmd +='{} debug pim events\n'.format(config_cmd)
            elif type == 'nht':
                cmd += '{} debug pim nht\n'.format(config_cmd)
            elif type == 'packet_dump':
                if 'direction' in kwargs:
                    direction = kwargs['direction']
                else:
                    direction = 'both'
                if direction != 'both':
                    cmd += '{} debug pim packet-dump {}\n'.format(config_cmd,direction)
                else:
                    cmd += '{} debug pim packet-dump send\n{} debug pim packet-dump receive\n'.format(config_cmd,config_cmd)
            elif type == 'packets':
                if 'pkt_type' in kwargs:
                    pkt_type = kwargs['pkt_type']
                else:
                    pkt_type = 'all'
                if pkt_type != 'all':
                    cmd += '{} debug pim packets {}\n'.format(config_cmd,pkt_type)
                else:
                    cmd += '{} debug pim packets hello\n{} debug pim packets joins\n{} debug pim packets register\n'.format(config_cmd,config_cmd,config_cmd)
            elif type == 'trace':
                cmd += '{} debug pim trace\n'.format(config_cmd)
            elif type == 'trace_detail':
                cmd += '{} debug pim trace detail\n'.format(config_cmd)
            elif type == 'zebra':
                cmd += '{} debug pim zebra\n'.format(config_cmd)
    else:
        cmd += '{} debug pim'.format(config_cmd)
    st.config(dut,cmd, type='vtysh',conf=False)


def debug_mroute(dut,type=None):
    """
    Author: Sooriya G
    email : sooriya.gajendrababu@broadcom.com
    :param dut:
    :param type:
    :return:
    """
    if type is None:
        cmd = 'debug mroute'
    else:
        cmd = 'debug mroute detail'

    st.config(dut,cmd, type='vtysh', conf=False)

def verify_ip_mroute_appdb(dut, source, group, **kwargs):
    """
    Author : Kiran Kumar K
    :param : source:
    :type : address
    :param : group:
    :type : address
    :type : interface name
    :return:
    :type: bool
    """
    if 'vrf' in kwargs:
        vrf_name = kwargs['vrf']
        del kwargs['vrf']
    else:
        vrf_name = 'default'

    if vrf_name != 'default':
        key = "IPMC_ROUTE_TABLE:{}|{}|{}".format(vrf_name, source, group)
    else:
        key = "IPMC_ROUTE_TABLE:{}|{}".format(source, group)
    print(key)
    command = redis.build(dut, redis.APPL_DB, "hgetall \"{}\"".format(key))
    print(command)
    output = st.show(dut, command)
    print(output)
    st.debug(output)

    if len(output) == 0:
        return False

    for each in kwargs.keys():
        print(each)
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True

def verify_intf_mcast_mode_in_appdb(dut, in_intf, **kwargs):
    """
    Author : Kiran Kumar K
    :param : in_intf:
    :type : interface name
    :return:
    :type: bool
    """

    key = "INTF_TABLE:{}".format(in_intf)
    print(key)
    command = redis.build(dut, redis.APPL_DB, "hgetall {}".format(key))
    print(command)
    output = st.show(dut, command)
    print(output)
    st.debug(output)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True

def verify_mroute_bcmcmd(dut, **kwargs):
    """
    Author :Priyanka Gupta
    :return:
    :type: bool
    """
    command = "bcmcmd 'ipmc table show'"
    output = st.show(dut, command)
    st.debug(output)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True

def verify_mroute_debugcommand(dut, **kwargs):
    """
    Author :Priyanka Gupta
    :return:
    :type: bool
    """
    command = "show debug ipmcorch all"
    output = st.show(dut, command)
    st.debug(output)
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True

def mtrace(dut,**kwargs):
    """
    Author : Sooriya G
    :param dut:
    :param source:
    :param group
    :return:
    """

    if 'source' not in kwargs or 'group' not in kwargs:
        st.error("Mandatory argument -source or -group is missing")
        return False
    source = kwargs['source']
    group = kwargs['group']
    cmd = 'mtrace {} {}'.format(source,group)
    output = st.show(dut,cmd,skip_tmpl=True,skip_error_check=True, type='vtysh')
    return output

def verify_ip_multicast(dut,**kwargs):
    """
    Author: Nagappa
    email : nagappa.chincholi@broadcom.com
    :param dut:
    :param source:
    :param vrf
    :type vrfname as list or string
    :return:

    Usage
    pim.verify_ip_multicast(data.dut1,tot_dyn_mcast_routes='10',join_prune_holdtime='150',upstream_join_timer='70',vrf='default')
    """

    ret_val = True
    if 'vrf' in kwargs:
        vrf = kwargs['vrf']
        del kwargs['vrf']
    else:
        vrf = 'default'

    if vrf != 'default':
        cmd = 'show ip multicast vrf {}'.format(vrf)
    else:
        cmd = 'show ip multicast'

    if 'skip_error' in kwargs:
        skip_error = kwargs['skip_error']
        del kwargs['skip_error']
    else:
        skip_error = False

    output = st.show(dut, cmd, skip_error_check=skip_error, type='vtysh')

    if 'return_output' in kwargs:
        return output

    if len(output) == 0:
        st.error("Output is Empty")
        return False

    #Converting all kwargs to list type to handle single or list of mroute instances
    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    #convert kwargs into list of dictionary
    input_dict_list =[]
    for i in range(len(kwargs[kwargs.keys()[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)

    for input_dict in input_dict_list:
        entries = filter_and_select(output,None,match=input_dict)
        if entries:
            st.log("DUT {} -> Match Found {} ".format(dut,input_dict))
        else:
            st.error("DUT {} -> Match Not Found {}".format(dut,input_dict))
            ret_val = False

    return ret_val


def grep_total_count(dut,**kwargs):
    """
    :param dut:
    :param kwargs:
    :return:
    """
    ret_val = True
    grep_val = kwargs['grep']
    cmd = kwargs['cmd']
    output = st.show(dut,"sudo vtysh -c '{}' | grep {} | wc -l".format(cmd,grep_val),skip_tmpl=True)
    actual_count = int(output.split('\n')[0])
    exp_count = int(kwargs['exp_count'])

    if actual_count != exp_count:
        st.error("Count Mismatch:  Expected-{} Actual-{}".format(exp_count,actual_count))
        ret_val = False
    return ret_val



