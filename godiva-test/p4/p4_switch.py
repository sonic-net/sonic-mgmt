# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import sys
from queue import Queue
from datetime import datetime
from time import sleep
from pathlib import Path
from logger.cafylog import CafyLog

import grpc
from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc
#from p4.tmp import p4config_pb2
#import p4config_pb2
from p4_error_utils import printGrpcError
import p4_test_lib as p4TestLib
from p4_base_ap import ApData

# XXX This is in PI proto/p4/tmp/p4config.proto
# from p4.tmp import p4config_pb2

MSG_LOG_MAX_LEN = 1024
log = CafyLog(name='P4 Switch')

# List of all active connections
connections = []

def ShutdownAllSwitchConnections():
    for c in connections:
        log.info("Shutting down connection: {}".format(c))
        c.shutdown()

class SwitchConnection(object):

    def __init__(self, name=None, address='127.0.0.1:50051', device_id=ApData.device_id,
                 proto_dump_file=None):
        self.name = name
        self.address = address
        self.device_id = device_id
        self.p4info = None
        self.channel = grpc.insecure_channel(self.address)
        if proto_dump_file is not None:
            interceptor = GrpcRequestLogger(proto_dump_file)
            self.channel = grpc.intercept_channel(self.channel, interceptor)
        self.client_stub = p4runtime_pb2_grpc.P4RuntimeStub(self.channel)
        self.requests_stream = IterableQueue()
        self.stream_msg_resp = self.client_stub.StreamChannel(iter(self.requests_stream))
        self.proto_dump_file = proto_dump_file
        connections.append(self)

    def buildDeviceConfig(self, p4_json_file_path=None):
        pass
        # XXX, cleanup including caller and import
        #"Builds the device specific config for passed JSON"
        #device_config = p4config_pb2.P4DeviceConfig()
        #device_config.reassign = True
        #print(p4_json_file_path)
        #device_config.device_data = p4_json_file_path
        #with open(p4_json_file_path, 'r') as f:
        #    device_config.device_data = p4TestLib.json_load_byteified(f)
        #return device_config

    def shutdown(self):
        self.requests_stream.close()
        self.stream_msg_resp.cancel()
        self.channel.close()

    def listen(self):
        for item in self.stream_msg_resp:
            log.info("P4Runtime Answer: {item}".format(item=item))
            return item # just one

    def MasterArbitrationUpdate(self, dry_run=False, device_id = None, **kwargs):
        request = p4runtime_pb2.StreamMessageRequest()
        if device_id == None:
            request.arbitration.device_id = self.device_id
        else:
            request.arbitration.device_id = device_id

        request.arbitration.election_id.high = kwargs.pop('election_id_high', 0)
        request.arbitration.election_id.low = kwargs.pop('election_id_low', 1)

        log.info("using the following ELECTION-ID for MasterArbitration - {high} and {low}".\
            format(high = request.arbitration.election_id.high, low =request.arbitration.election_id.low))
        sleep(5)
        #request.arbitration.role.id = 333

        log.info("P4Runtime MasterArbitrationUpdate: {resp}".format(resp = request))
        if dry_run:
            log.info("P4Runtime MasterArbitrationUpdate: {resp}".format(resp = request))
        else:
            self.requests_stream.put(request)
            log.info("Sent")
            for item in self.stream_msg_resp:
                log.info("P4Runtime Answer: {item}".format(item=item))
                return item # just one

    def SetForwardingPipelineConfig(self, p4info, dry_run=False, **kwargs):
        #device_config = self.buildDeviceConfig(**kwargs)
        request = p4runtime_pb2.SetForwardingPipelineConfigRequest()
        try:
            request.election_id.low = kwargs["election_id_low"]
        except KeyError:
            request.election_id.low = 1
        try:
            request.election_id.high = kwargs["election_id_high"]
        except KeyError:
            request.election_id.high = 0
        try:
            request.device_id = kwargs["device_id"]
        except KeyError:
            request.device_id = self.device_id
        try:
            cfg_reqd = kwargs["config"]
        except KeyError:
            cfg_reqd = True
        try:
            ckie = kwargs["cookie"]
        except KeyError:
            ckie = False
        try:
            pjson = kwargs["p4_json_file_path"]
        except KeyError:
            pjson = None

        #device_config = self.buildDeviceConfig(pjson)


        log.info(request.election_id.low)
        #request.device_id = self.device_id
        #request.role_id = 333
        if cfg_reqd:
            config = request.config
            config.p4info.CopyFrom(p4info)
            tgt_bin = Path(pjson)
            if tgt_bin.is_file():
                with open(pjson, 'rb') as f2:
                    request.config.p4_device_config = f2.read()
            if ckie:
                config.cookie.cookie = ckie
            print("Sending Config: ")
        else:
            print("Sending NO Config: ", request.config)
        #config.p4_device_config = device_config.SerializeToString()

        try:
            req_act = kwargs["action"]
        except KeyError:
            #Using default Action for 'SetForwardingPipeline' as VERIFY_AND_COMMIT(3)
            req_act = "VERIFY_AND_COMMIT"

        #request.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_SAVE
        req_nam = request.Action.Value(req_act)
        setattr(request, 'action', req_nam)
        if dry_run:
            log.info("P4Runtime SetForwardingPipelineConfig:", request)
        else:
            self.client_stub.SetForwardingPipelineConfig(request)


    def GetForwardingPipelineConfig(self, dry_run=False, **kwargs):
        request = p4runtime_pb2.GetForwardingPipelineConfigRequest()
        try:
            request.device_id = kwargs["device_id"]
        except KeyError:
            request.device_id = self.device_id

        try:
            req_type = kwargs["resp_typ"]
        except KeyError:
            req_type = "ALL"

        req_nam = request.ResponseType.Value(req_type)
        setattr(request, 'response_type', req_nam)

        #if request.response_type == 0:
        #    request.response_type = p4runtime_pb2.GetForwardingPipelineConfigRequest.ALL
        if dry_run:
            print ("P4Runtime GetForwardingPipelineConfig:", request)
        else:
            response = self.client_stub.GetForwardingPipelineConfig(request)
            return response


    def WriteTableEntry(self, table_entry, dry_run=False, **kwargs):
        request = p4runtime_pb2.WriteRequest()
        #request.device_id = self.device_id
        try:
            request.election_id.low = kwargs["election_id_low"]
        except KeyError:
            request.election_id.low = 1
        try:
            request.election_id.high = kwargs["election_id_high"]
        except KeyError:
            request.election_id.high = 0
        try:
            upd_type = kwargs["oper"]
        except KeyError:
            upd_type = "INSERT"
        try:
            request.device_id = kwargs["device_id"]
        except KeyError:
            request.device_id = self.device_id
        try:
            request.role_id = kwargs["role_id"]
        except KeyError:
            request.role_id = 555

        #request.role_id = 555
        update = request.updates.add()
        if upd_type.upper() == "MODIFY":
            update.type = p4runtime_pb2.Update.MODIFY
        else:
            update.type = p4runtime_pb2.Update.INSERT
        update.entity.table_entry.CopyFrom(table_entry)

        if dry_run:
            log.info("P4Runtime Write:", request)
        else:
            self.client_stub.Write(request)
        
        return
    
    def ProcessBatchedTableEntries(self, table_entries, dry_run=False, **kwargs):
        request = p4runtime_pb2.WriteRequest()
        try:
            request.device_id = kwargs["device_id"]
        except KeyError:
            request.device_id = self.device_id
        try:
            request.election_id.low = kwargs["election_id_low"]
        except KeyError:
            request.election_id.low = 1
        try:
            request.election_id.high = kwargs["election_id_high"]
        except KeyError:
            request.election_id.high = 0

        request.role_id = 555
        for tbl_entry in table_entries:
            update = request.updates.add()
            upd_type = tbl_entry['op']
            if upd_type.upper() == "MODIFY":
                update.type = p4runtime_pb2.Update.MODIFY
            elif upd_type.upper() == "INSERT":
                update.type = p4runtime_pb2.Update.INSERT
            else:
                update.type = p4runtime_pb2.Update.DELETE
            update.entity.table_entry.CopyFrom(tbl_entry['te'])

        if dry_run:
            log.info("P4Runtime Write:", request)
        else:
            self.client_stub.Write(request)

        return

    def WriteActionProfileGroup(self, group_entry, dry_run=False, **kwargs):
        
        request = p4runtime_pb2.WriteRequest()
        try:
            request.device_id = kwargs["device_id"]
        except KeyError:
            request.device_id = self.device_id
        try:
            request.election_id.low = kwargs["election_id_low"]
        except KeyError:
            request.election_id.low = 1
        try:
            request.election_id.high = kwargs["election_id_high"]
        except KeyError:
            request.election_id.high = 0
        try:
            update_type = kwargs["update_type"]
        except KeyError:
            update_type = "INSERT"

        request.role_id = 555
        update = request.updates.add()

        if "INSERT" in update_type:
            update.type = p4runtime_pb2.Update.INSERT
        elif "MODIFY" in update_type:
            update.type = p4runtime_pb2.Update.MODIFY
        elif "DELETE" in update_type:
            update.type = p4runtime_pb2.Update.DELETE

        update.entity.action_profile_group.CopyFrom(group_entry)
        log.info("After CopyFrom : {req}".format(req=request))

        if dry_run:
            log.info("P4Runtime Write - Action Profile Group:", request)
        else:
            #log.info("P4Runtime Write - Action Profile Group:", request)
            self.client_stub.Write(request)
        
        return

    def ReadActionProfileGroup(self, group_id=None, dry_run=False, **kwargs):
        request = p4runtime_pb2.ReadRequest()
        try:
            request.device_id = kwargs["device_id"]
        except KeyError:
            request.device_id = self.device_id
        entity = request.entities.add()
        group = entity.action_profile_group
        if group_id is not None:
            group.group_id = group_id
        else:
            group.group_id = 0
        if dry_run:
            log.info("P4Runtime Read:", request)
        else:
            log.info("P4Runtime Read for Group ID: %d" % group_id)
            for response in self.client_stub.Read(request):
                yield response

    def WriteActionProfileMember(self, member_entry, dry_run=False, **kwargs):
        
        request = p4runtime_pb2.WriteRequest()
        try:
            request.device_id = kwargs["device_id"]
        except KeyError:
            request.device_id = self.device_id
        try:
            request.election_id.low = kwargs["election_id_low"]
        except KeyError:
            request.election_id.low = 1
        try:
            request.election_id.high = kwargs["election_id_high"]
        except KeyError:
            request.election_id.high = 0
        try:
            update_type = kwargs["update_type"]
        except KeyError:
            request.update_type = "INSERT"

        request.role_id = 555
        update = request.updates.add()

        if "INSERT" in update_type:
            update.type = p4runtime_pb2.Update.INSERT
        elif "MODIFY" in update_type:
            update.type = p4runtime_pb2.Update.MODIFY
        elif "DELETE" in update_type:
            update_type = p4runtime_pb2.Update.DELETE

        update.entity.action_profile_member.CopyFrom(member_entry)
        log.info("After CopyFrom : {req}".format(req=request))

        if dry_run:
            log.info("P4Runtime Write - Action Profile Member:", request)
        else:
            self.client_stub.Write(request)
        return

    def ReadActionProfileMember(self, member_id=None, dry_run=False, **kwargs):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        member = entity.action_profile_member
        if member_id is not None:
            member.member_id = member_id
        else:
            member.member_id = 0
        
        if dry_run:
            log.info("P4Runtime Read:", request)
        else:
            log.info("P4Runtime Read for Member ID: %d" % member_id)
            for response in self.client_stub.Read(request):
                yield response

    def BatchedReadMemberGroup(self,member_id=None, group_id=None, dry_run=False, **kwargs):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity1 = request.entities.add()
        member = entity1.action_profile_member
        if member_id is not None:
            member.member_id = member_id
        else:
            member.member_id = 0
        
        entity2 = request.entities.add()
        group = entity2.action_profile_group
        if group_id is not None:
            group.group_id = group_id
        else:
            group.group_id = 0
    
        if dry_run:
            log.info("P4Runtime Read:", request)
        else:
            log.info("P4Runtime BatchedRead for Member ID: {} and Group ID: {}".format(member_id,group_id))
            for response in self.client_stub.Read(request):
                yield response
            
    def InvlBatchedReadMemberGroup(self,member_id=None, group_id=None, dry_run=False, **kwargs):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity1 = request.entities.add()
        member = entity1.action_profile_member
        if member_id is not None:
            member.member_id = member_id
        else:
            member.member_id = 0
        
        entity2 = request.entities.add()
        group = entity2.action_profile_group
        if group_id is not None:
            group.group_id = group_id
        else:
            group.group_id = 0

        entity3 = request.entities.add()
    
        if dry_run:
            log.info("P4Runtime Read:", request)
        else:
            log.info("P4Runtime BatchedRead for Member ID: {} and Group ID: {}".format(member_id,group_id))
            for response in self.client_stub.Read(request):
                yield response

    def DeleteActionProfileMember(self, member_entry, dry_run=False, **kwargs):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        try:
            request.election_id.low = kwargs["election_id_low"]
        except KeyError:
            request.election_id.low = 1
        try:
            request.election_id.high = kwargs["election_id_high"]
        except KeyError:
            request.election_id.high = 0
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.DELETE
        update.entity.action_profile_member.CopyFrom(member_entry)
        if dry_run:
            print ("P4Runtime Write:", request)
        else:
            self.client_stub.Write(request)
        return


    def DeleteTableEntry(self, table_entry, dry_run=False, **kwargs):
        request = p4runtime_pb2.WriteRequest()
        try:
            request.device_id = kwargs["device_id"]
        except KeyError:
            request.device_id = self.device_id
        try:
            request.election_id.low = kwargs["election_id_low"]
        except KeyError:
            request.election_id.low = 1
        try:
            request.election_id.high = kwargs["election_id_high"]
        except KeyError:
            request.election_id.high = 0
        try:
            request.role_id = kwargs["role_id"]
        except KeyError:
            request.role_id = 555
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.DELETE
        update.entity.table_entry.CopyFrom(table_entry)
        if dry_run:
            print ("P4Runtime Write:", request)
        else:
            self.client_stub.Write(request)
        return


    def ReadTableEntries(self, table_id=None, dry_run=False, **kwargs):
        request = p4runtime_pb2.ReadRequest()
        try:
            request.device_id = kwargs["device_id"]
        except KeyError:
            request.device_id = self.device_id        

        entity = request.entities.add()
        table_entry = entity.table_entry
        if table_id is not None:
            table_entry.table_id = table_id
        else:
            table_entry.table_id = 0
        if dry_run:
            log.info("P4Runtime Read:", request)
        else:
            log.info("P4Runtime Read for Table ID: %d" % table_id)
            for response in self.client_stub.Read(request):
                yield response

    def ReadTableEntriesWc(self, table_id, tbl_entry, dry_run=False, **kwargs):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        if table_id is not None:
            entity.table_entry.CopyFrom(tbl_entry)
            entity.table_entry.table_id = table_id
        else:
            entity.table_entry.table_id = 0
        if dry_run:
            log.info("P4Runtime Read:", request)
        else:
            for response in self.client_stub.Read(request):
                yield response

    def ReadCounters(self, counter_id=None, index=None, dry_run=False, **kwargs):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        counter_entry = entity.counter_entry
        if counter_id is not None:
            counter_entry.counter_id = counter_id
        else:
            counter_entry.counter_id = 0
        if index is not None:
            counter_entry.index.index = index
        if dry_run:
            log.info("P4Runtime Read:", request)
        else:
            for response in self.client_stub.Read(request):
                yield response


class GrpcRequestLogger(grpc.UnaryUnaryClientInterceptor,
                        grpc.UnaryStreamClientInterceptor):
    """Implementation of a gRPC interceptor that logs request to a file"""

    def __init__(self, log_file):
        self.log_file = log_file
        with open(self.log_file, 'w') as f:
            # Clear content if it exists.
            f.write("")

    def log_message(self, method_name, body):
        with open(self.log_file, 'a') as f:
            ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            msg = str(body)
            f.write("\n[%s] %s\n---\n" % (ts, method_name))
            if len(msg) < MSG_LOG_MAX_LEN:
                f.write(str(body))
            else:
                f.write("Message too long (%d bytes)! Skipping log...\n" % len(msg))
            f.write('---\n')

    def intercept_unary_unary(self, continuation, client_call_details, request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)

    def intercept_unary_stream(self, continuation, client_call_details, request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)

class IterableQueue(Queue):
    _sentinel = object()

    def __iter__(self):
        return iter(self.get, self._sentinel)

    def close(self):
        self.put(self._sentinel)
