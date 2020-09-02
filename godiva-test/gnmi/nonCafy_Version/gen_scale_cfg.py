#!/usr/bin/env python3

import argparse
import json
import logging
import os

def _create_parser():
    parser = argparse.ArgumentParser(description='Scale CLI utility.')
    parser.add_argument('-n', '--num_of_intfs', type=int, help='Number of interfaces',
                      required=True)
    parser.add_argument('-d', '--description', type=str, help='Description tag',
                      required=False)
    return parser

def main():
    argparser = _create_parser()
    args = vars(argparser.parse_args())
    num_of_intfs = args['num_of_intfs']
    descr = args.get('description')
    if descr is None:
        descr = "simple"
    main_dict = dict()
    
    for i in range(1,num_of_intfs):
        intf_dict = dict()
        cfg_dict = dict()
        oci_dict = dict()
        intfs_dict = dict()
        verify_dict = dict()
        verify_dict["prefix"] = "/oc-if:interfaces"
        verify_dict["path"] = "/oc-if:interface[name=Loopback{}]".format(i)
        verify_cfg_list = list()
        verify_cfg_dict = dict()
        sub_main_dict = dict()
        intf_list = list()
        set_key_list = ['openconfig-interfaces:interfaces','interface',0,'config']
        check_var_list = ['name','type','description','mtu']

        cfg_dict["name"] = "Loopback{}".format(i)
        cfg_dict["description"] = "For {} oper TC :{}".format(descr,i)
        cfg_dict["type"] = "iana-if-type:softwareLoopback"
        cfg_dict["mtu"] = "1500"

        intf_dict["name"] = "Loopback{}".format(i)
        intf_dict["config"] = cfg_dict

        intf_list.append(intf_dict)

        verify_cfg_dict['name'] = "Loopback{}".format(i)
        verify_cfg_dict['section'] = "SCALE_INTF_{}".format(i)
        verify_cfg_dict['set_key'] = set_key_list
        verify_cfg_dict['get_key'] = "interfaces,interface,config"
        verify_cfg_dict["set_list_index"] = 0
        verify_cfg_dict['check_var_list'] = check_var_list
        verify_cfg_list.append(verify_cfg_dict)
        verify_dict["config"] = verify_cfg_list

        intfs_dict["interface"] = intf_list
        oci_dict["openconfig-interfaces:interfaces"] = intfs_dict
        sub_main_dict["config"] = oci_dict
        sub_main_dict["verify"] = verify_dict
        main_dict["SCALE_INTF_{}".format(i)] = sub_main_dict
        #main_dict["GET_VERIFY_{}".format(i)] = verify_dict

    j = json.dumps(main_dict, indent=4)
    f = open('scale.json', 'w')
    print(j, file=f)

if __name__ == '__main__':
  main()