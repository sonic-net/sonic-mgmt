#!/usr/bin/env python3
import argparse
import grpc
import os
import sys
import json
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
# sys.path.append(
#    os.path.join(os.path.dirname(os.path.abspath(__file__)),
#                 '../../utils/'))

# Add 3rd party python packages' paths (instead of setting PYTHONPATH)
TP_DIR = "./../../godiva-test/lib"
tp_dirs = os.listdir(TP_DIR)
for tp_dir in tp_dirs:
    sys.path.append(os.path.join(TP_DIR,tp_dir))

import p4_switch
from p4_error_utils import printGrpcError
import p4_info_helper
import p4_test_lib as p4TestLib

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

def main():
    parser = argparse.ArgumentParser(description='P4Runtime Client')

    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='../../thirdparty/google/p4/b4-gen.txt')
    parser.add_argument('--p4json', help='JSON file from p4c',
                        type=str, action="store", required=False,
                        # default='../../thirdparty/google/p4/b4-gen.json'
                        default = None)
    parser.add_argument("-i", '--input_conf_file',
                        help="path to input runtime configuration file (JSON)",
                        type=str, action="store", required=True)

    args = parser.parse_args()

    if args.p4info and not os.path.exists(args.p4info):
        parser.print_help()
        print(("p4info file not found: {}".format(args.p4info)))
        parser.exit(1)
    if args.p4json and not os.path.exists(args.p4json):
        parser.print_help()
        print(("JSON file not found: {}".format(args.p4json)))
        parser.exit(1)
    if not os.path.exists(args.input_conf_file):
        parser.print_help()
        print(("Input Config file not found: {}".format(args.input_conf_file)))
        parser.exit(1)

    #workdir = os.path.dirname(os.path.abspath(args.input_conf_file))
    with open(args.input_conf_file, 'r') as ip_conf_file:
        input_conf = p4TestLib.json_load_byteified(ip_conf_file)

    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4_info_helper.P4InfoHelper(args.p4info) \
                    if args.p4info!=None else None

    try:
        # Create a switch connection object for s1 (switch 1)
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4_switch.SwitchConnection(
            name='s1',
            address='172.17.0.2:50051',
            device_id=0,
            proto_dump_file='s1-p4runtime-requests-log.txt')

        # XXX Does not look like this is setting the role field in
        # message MasterArbitrationUpdate proto/p4/v1/p4runtime.proto

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()

        # XXX We need to test several messages simulatenously. Python
        # can only invoke one RPC from one thread (GIL Lock).
        #
        # For example simulatenous stream + Config/Read/Write/etc.
        #
        # Investigate IterableQueue? Also used in p4_switch.py
        #

        if p4info_helper != None: 
            # Install the P4 program on the switches
            s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                           p4_json_file_path=args.p4json)
            print("Installed P4 Program using SetForwardingPipelineConfig on s1")

            print("Getting ForwardingPipelineConfig on s1")
            response = s1.GetForwardingPipelineConfig(resp_typ=0)
            print (response)
            sleep(2)

            if 'table_entries' in input_conf:
                print (input_conf)
                table_entries = input_conf['table_entries']
                print("Inserting %d table entries..." % len(table_entries))
                for entry in table_entries:
                    print(p4TestLib.tableEntryToString(entry))
                    #insertTableEntry(s1, entry, p4info_helper)
                    print ("INSERTING TABLE ENTRIES")
                    p4TestLib.tableEntryActions(s1, entry, p4info_helper, 'INSERT')
                    sleep(1)
                    #removeTableEntry(s1, entry, p4info_helper)
                    print ("REMOVING TABLE ENTRIES")
                    p4TestLib.tableEntryActions(s1, entry, p4info_helper, 'DELETE')
                    sleep(1)
                    print ("RE-INSERTING TABLE ENTRIES")
                    p4TestLib.tableEntryActions(s1, entry, p4info_helper, 'INSERT')
                    sleep(1)
                    print ("READING TABLE ENTRIES")
                    #readTableRules(p4info_helper, s1)
                    sleep(1)

            if 'table_entries' in input_conf:
                print (input_conf)
                table_entries = input_conf['table_entries']
                print("Inserting %d table entries..." % len(table_entries))
                for entry in table_entries:
                    print(p4TestLib.tableEntryToString(entry))
                    #insertTableEntry(s1, entry, p4info_helper)
                    #removeTableEntry(s1, entry, p4info_helper)
                    print ("REMOVING TABLE ENTRIES")
                    p4TestLib.tableEntryActions(s1, entry, p4info_helper, 'DELETE')
                    sleep(1)

            # Write the rules that tunnel traffic from h1 to h2
            #writeTunnelRules(p4info_helper, ingress_sw=s1, egress_sw=s1, tunnel_id=100,
            #                 dst_eth_addr="00:00:00:00:02:02", dst_ip_addr="10.0.2.2")

            # TODO Read table entries
            # readTableRules(p4info_helper, s1)

            # Print the tunnel counters every 2 seconds
            #while True:
            #    sleep(2)
            #    print ('\n----- Reading tunnel counters -----')
            #    printCounter(p4info_helper, s1, "MyIngress.ingressTunnelCounter", 100)
            #    printCounter(p4info_helper, s1, "MyIngress.egressTunnelCounter", 200)

    except KeyboardInterrupt:
        print("Shutting down.")
    except grpc.RpcError as e:
        print(e)
        printGrpcError(e)

    p4_switch.ShutdownAllSwitchConnections()

if __name__ == '__main__':
    main()
