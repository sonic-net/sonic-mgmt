from topology.topo_mgr.topo_mgr import Topology
from framework.pytest.cafy import Cafy
import pytest
from logger.cafylog import CafyLog
from topology.zap.zap import Zap
from utils.helper import Helper
from utils.cafyexception import CafyException
import os
from cmal_base_ap import ApData, CMALApBase
import grpc
import marshal
import json

# Python bindings from Proto files
import mal_pb2
import mal_pb2_grpc
import cmal_local_config_pb2
import cmal_local_config_pb2_grpc

from google.protobuf import json_format

log = CafyLog(name='CMAL Sanity script')

@pytest.fixture(scope="session", autouse=True)
def stub():
    channel = grpc.insecure_channel(ApData.svr_addr+":"+ApData.port_addr)
    stub = mal_pb2_grpc.MalConfigServiceStub(channel)
    return stub

class TestCMAL(CMALApBase):

    def add_port(self, cmal_local_config, intf_name):
        zap = ApData.zap
        cmal_port_dict = zap.get_interface_configuration(intf_name)
        system_config = cmal_local_config.system_config
        system_config.chassis_id.name = ApData.chassis_id_name

        ports_config = cmal_local_config.ports_config

        ports_config.default_port_params_profile = ApData.default_port_params_profile

        port = ports_config.ports.add()
        port.port_id.name = cmal_port_dict["name"]
        port.port_type =  cmal_local_config_pb2.Port.TRUNK
        port.of_port_name = cmal_port_dict["of_port_name"]
        port.of_port_no = cmal_port_dict["of_port_no"]
        port.admin_state = cmal_local_config_pb2.Port.DISABLED
        port.description = cmal_port_dict["description"]
        port.local_index = cmal_port_dict["port_number"]
        port.port_params_profile_name = cmal_port_dict["port_params_profile_name"]

        for pname in cmal_port_dict["port_set_profile_name"]:
            port.port_set_profile_name.append(pname)

        port.link_event_damp_control_profile_name = cmal_port_dict["link_event_damp_control_profile_name"]
        port.card_slot_number = cmal_port_dict["card_slot_number"]
        port.port_number = cmal_port_dict["port_number"]
        port.channel_number = cmal_port_dict["channel_number"]
        port.node_id.name = ApData.node_id

    @pytest.mark.parametrize("lock_status", ["NEW_LOCK", "LOCK_EXISTS", "FORCE_TAKE_LOCK"])
    def test_ConfigLock(self,stub,lock_status):
        
        if lock_status == "FORCE_TAKE_LOCK":
            take_lock = True
        else:
            take_lock = False
        
        # Get Lock ID
        try:
            response = stub.ConfigLock(mal_pb2.ConfigLockRequest(force_take_lock=take_lock))
            log.info("Response:%sresp" % response)
        except grpc.RpcError as rpc_error_call:
            ApData.lock_id = None
            log.info(rpc_error_call.code())
            log.info(rpc_error_call.details())
        else:
            if lock_status == "NEW_LOCK":

                if not response.took_lock_away:
                    log.info('Lock id is : {lock_id}'.format(lock_id=response.local_config_lock_id))
                else:
                    assert False, "Lock is held by another user : {lock_status}"\
                    .format(lock_status=mal_pb2.ConfigLockResponse.Status.Name(response.status))

            elif lock_status == "LOCK_EXISTS":

                if not response.took_lock_away:
                    log.info("Lock response for lock already held : " + mal_pb2.ConfigLockResponse.Status.Name(response.status))
                else:
                    assert False, "Expected lock to be held by another user, instead got the lock id : {id}"\
                    .format(id=response.local_config_lock_id)

            elif lock_status == "FORCE_TAKE_LOCK":
                if response.took_lock_away:
                    log.info('Lock id is : {lock_id}'.format(lock_id=response.local_config_lock_id))
                else:
                    assert False, "Either lock was never held by another user, or we are unable to forcefully \
                    take the lock. status from server : {status}".format(status=mal_pb2.ConfigLockResponse.Status.Name(response.status))
            
            ApData.lock_id = response.local_config_lock_id
        
    def test_ConfigLockInfo(self,stub):
        try:
            response = stub.ConfigLockInfo(mal_pb2.ConfigLockSubscribeRequest())
            log.info(response)
        except grpc.RpcError as rpc_error_call:
            log.info(rpc_error_call.code())
            log.info(rpc_error_call.details())

    def test_ConfigUnlock(self,stub):

        try:
            response = stub.ConfigUnlock(mal_pb2.ConfigUnlockRequest(local_config_lock_id=ApData.lock_id))
            log.info(response)
        except grpc.RpcError as rpc_error_call:
            log.info(rpc_error_call.code())
            log.info(rpc_error_call.details())

    def test_ConfigVerify(self,stub):
        
        with open('config.txt', 'r') as file:
            data = file.read()
        config = marshal.dumps(data)
        
        cv_request = mal_pb2.ConfigVerifyRequest(push_request=mal_pb2.ConfigPushRequest(is_append=True,local_config=config))
        
        try:
            response = stub.ConfigVerify(cv_request)
            status = mal_pb2.ConfigVerifyResponse.Status.Name(response.status)
            log.info("Mal client received: " + status)
            if status == "APPEND_NOT_SUPPORTED":
                log.error("CMAL does not implement append, Detail from CMAL Server: %s" % response.error_detail)
            elif status == "VERIFICATION_REJECTED":
                log.error("The contents of the config did not pass verification, \
                Detail from CMAL Server: %s" % response.config_verify_failed_description)
            if response.reboot_required:
                log.info("Config is verified but the config will be applied only on reboot")
                log.info("Reason is : %s" % response.reboot_required_reasons)

        except grpc.RpcError as rpc_error_call:
            log.info(rpc_error_call.code())
            log.info(rpc_error_call.details())

        
    def test_ConfigVerifyAndCommit(self,stub):
        
        cmal_local_config = cmal_local_config_pb2.CmalLocalConfig()

        self.add_port(cmal_local_config, "R1_EX1_1.R1")
        self.add_port(cmal_local_config, "R1_EX1_2.R1")

        json_string = json_format.MessageToJson(cmal_local_config, False, True)
        log.info(json_string)

        config_verify_and_commit_req = mal_pb2.ConfigVerifyAndCommitRequest()

        config_verify_and_commit_req.push_request.is_append = False
        config_verify_and_commit_req.push_request.skip_verification = False
        config_verify_and_commit_req.push_request.local_config = cmal_local_config.SerializeToString()
        
        try:
            response = stub.ConfigVerifyAndCommit(config_verify_and_commit_req)
            log.info("Mal client received: " + str(response.config_verify_response.status))
        except grpc.RpcError as rpc_error_call:
            log.info(rpc_error_call.code())
            log.info(rpc_error_call.details())
        else:
            if response.config_verify_response.status != 0:
                verify_status = mal_pb2.ConfigVerifyResponse.Status.Name(response.config_verify_response.status)
                log.info("Mal client Verify status -- received: " + verify_status)
                if verify_status == "APPEND_NOT_SUPPORTED":
                    log.error("CMAL does not implement append, Detail from CMAL Server: %s" % response.error_detail)
                elif verify_status == "VERIFICATION_REJECTED":
                    log.error("The contents of the config did not pass verification, \
                    Detail from CMAL Server: %s" % response.config_verify_failed_description)
                if response.config_verify_response.reboot_required:
                    log.info("Config is verified but the config will be applied only on reboot")
                    log.info("Reason is : %s" % response.reboot_required_reasons)

                commit_status = mal_pb2.ConfigCommitResponse.Status.Name(response.config_commit_response.status)
                log.info("Mal client Verify status -- received: " + commit_status)
                if commit_status == "LOCK_NOT_HELD":
                    log.error("According to the CMAL server, we never acquired the lock.")
                elif commit_status == "LOCK_TAKEN_AWAY":
                    log.error("Looks like some other user has taken our lock")
                elif commit_status == "COMMIT_NOT_APPLIED":
                    log.error("A serious error occurred. Either there is something wrong with the config \
                    which the ConfigVerify stage could not detect or there was an internal error. CMAL server is in an inconsistent state \
                    if this happens: only _part_ of the config may have been applied. Error reason from server: \
                    %s " % response.config_commit_response.error_detail)
                elif commit_status == "REQUEST_INCOMPLETE":
                    log.error("Request is incomplete - Most probable reason : ConfigVerifyAndCommit requests must contain \
                    both a local_config and local_config_metadata field. Error reason from server: \
                    %s " % response.config_commit_response.error_detail)

                if response.config_commit_response.reboot_required:
                    log.info("Server is asking for a reboot to fully apply the config")
                    log.info("Reason is : %s" % response.reboot_required_reasons)
                if response.config_commit_response.traffic_disruption_required:
                    log.info("config is accepted, but could not be fully applied immediately, as it requires traffic disruption")
                    log.info("Reason is : %s" % response.traffic_disruption_required_reasons)
            else:
                log.info("Config is accepted.")

        
    def test_ConfigGet(self,stub):
        try:
            response = stub.ConfigGet(mal_pb2.ConfigGetRequest(config_name=ApData.config_name))
            message = mal_pb2.ConfigGetResponse.Status.Name(response.status)
            if message == "NO_SUCH_CONFIG":
                log.error("No such config_name: %s exists on the server" % ApData.config_name)
            elif message == "CORRUPTED_CONFIG":
                log.error("According to the server, %s is present, but has been corrupted or is otherwise\
                unreadable. It will need to be pushed again.")
             
            lc_metadata = response.local_config_metadata
            lc_commit_md = response.local_config_commit_metadata
            local_config = response.local_config
            if response.reboot_required:
                log.info("Server is asking for a reboot to fully apply the config")
                log.info("Reason is : %s" % response.reboot_required_reasons)
            if response.traffic_disruption_required:
                log.info("config is accepted, but could not be fully applied immediately, as it requires traffic disruption")
                log.info("Reason is : %s" % response.traffic_disruption_required_reasons)
        except grpc.RpcError as rpc_error_call:
            log.info(rpc_error_call.code())
            log.info(rpc_error_call.details())
    
    def test_ConfigCopy(self,stub):
        try:
            response = stub.ConfigGet(mal_pb2.ConfigCopyRequest(local_config_lock_id=ApData.lock_id,dst_config_name="cp_name"))
            message = mal_pb2.ConfigCopyResponse.Status.Name(response.status)
            if message == "NO_SUCH_CONFIG" or message == "CANNOT_OVERWRITE_EXISTING_CONFIG":
                log.error("Unexpected error message - %s" % message)
            elif message == "LOCK_NOT_HELD":
                log.error("According to the CMAL server, we never acquired the lock.")
            elif message == "LOCK_TAKEN_AWAY":
                log.error("Looks like some other user has taken our lock")
            else:
                log.info("Config was successfully copied")
                
        except grpc.RpcError as rpc_error_call:
            log.info(rpc_error_call.code())
            log.info(rpc_error_call.details())
    
    def test_ConfigMove(self,stub):
        try:
            response = stub.ConfigMove(mal_pb2.ConfigMoveRequest(local_config_lock_id = ApData.lock_id,\
            src_config_name = ApData.config_name, dst_config_name = "move_name"))
            message = mal_pb2.ConfigMoveResponse.Status.Name(response.status)
            if message == "NO_SUCH_CONFIG":
                log.error("Unexpected error message - %s" % message)
            elif message == "CANNOT_OVERWRITE_EXISTING_CONFIG":
                log.error("Looks like a config with the same name already exists, one can use do_overwrite=true and a config \
                is actually overwritten, CMAL should log that fact.")
            elif message == "LOCK_NOT_HELD":
                log.error("According to the CMAL server, we never acquired the lock.")
            elif message == "LOCK_TAKEN_AWAY":
                log.error("Looks like some other user has taken our lock")
            else:
                log.info("Config was successfully moved")

            if ApData.copy_overwrite and message == "CANNOT_OVERWRITE_EXISTING_CONFIG":
                response = stub.ConfigMove(mal_pb2.ConfigMoveRequest(local_config_lock_id = ApData.lock_id,\
                src_config_name = ApData.config_name, dst_config_name = "move_name", do_overwrite=True))
                if message == "CANNOT_OVERWRITE_EXISTING_CONFIG":
                    log.error("Request fails with do_overwrite=True options, raise a CMAL bug")
                elif message == "LOCK_NOT_HELD":
                    log.error("According to the CMAL server, we never acquired the lock.")
                elif message == "LOCK_TAKEN_AWAY":
                    log.error("Looks like some other user has taken our lock")
                elif response.config_overwritten:
                    log.info("Config was successfully moved")
                else:
                    log.error("Confirm from CMAL server using ConfigGet if config was really overwritten or not\
                    Raise an error that config_overwritten was not set")

            #### Todo -- Try the same test with local config metadata ###
        except grpc.RpcError as rpc_error_call:
            log.info(rpc_error_call.code())
            log.info(rpc_error_call.details())

    def test_ConfigDel(self,stub):
        try:
            response = stub.ConfigDel(mal_pb2.ConfigDelRequest(local_config_lock_id=ApData.lock_id,config_name="cp_name"))
            message = mal_pb2.ConfigDelResponse.Status.Name(response.status)
            if message == "NO_SUCH_CONFIG":
                log.error("Unexpected error message - %s" % message)
            elif message == "LOCK_NOT_HELD":
                log.error("According to the CMAL server, we never acquired the lock.")
            elif message == "LOCK_TAKEN_AWAY":
                log.error("Looks like some other user has taken our lock")
            else:
                log.info("Config was successfully deleted")
                
        except grpc.RpcError as rpc_error_call:
            log.info(rpc_error_call.code())
            log.info(rpc_error_call.details())
    



