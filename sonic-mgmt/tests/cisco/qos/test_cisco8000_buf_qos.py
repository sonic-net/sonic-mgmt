import pytest
import logging

#
# list of pid and sku that cisco-8000 supports
# update when new pid/sku is enabled for RDMA
#
pid_sku = [{"x86_64-8102_64h_o-r0" : ["Cisco-8102-C64"]},
           {"x86_64-8101_32h_o-r0" : ["32x100Gb"]},
           {"x86_64-8111_32eh_o-r0": ["Cisco-8111-O32", "Cisco-8111-O64", "Cisco-8111-O62C2"]},
           {"x86_64-88_lc0_36fh_mo-r0" : [{"Cisco-88-LC0-36FH-M-O36": [0,1,2]}]},
           {"x86_64-88_lc0_36fh_m-r0" : [{"Cisco-88-LC0-36FH-M-O36": [0,1,2]}]},
           {"x86_64-88_lc0_36fh_o-r0" : [{"Cisco-88-LC0-36FH-O36": [0,1,2]}]},
           {"x86_64-88_lc0_36fh-r0" : [{"Cisco-88-LC0-36FH-O36": [0,1,2]}]},
           {"x86_64-8101_32fh_o-r0" : ["32x400Gb", "Cisco-8101-C64", "Cisco-8101-O32", "Cisco-8101-O8C48", "Cisco-DSF-8101-32FH"]},
           {"x86_64-8800_rp_o-r0" : [""]}
           ]

def print_rc(cmd, rc):
    if rc.is_successful:
        logging.info("Success :{}".format(cmd))
    else:
        logging.error("Failed :{}".format(cmd))


def run_mmu_config(duthost, raw_pid_sku, mmucommand):
    def get_pid_sku(pid_sku):
        for pid in (pid_sku):
            v =  pid_sku[pid]
            if list(v):
                for sku in v:
                    if isinstance(sku, dict):
                        t2_sku, t2_asic = next(iter(sku.items()))
                        for asic in t2_asic:
                            path="{}/{}/{}".format(pid, t2_sku, str(asic))
                            logging.info("path {} sku {} asic {}".format(path, t2_sku, asic))
                            yield path, t2_sku
                    else:
                        path="{}/{}".format(pid, str(sku))
                        logging.info("path {} sku {}".format(path, sku))
                        yield path, sku
    #
    prefix='/usr/share/sonic/device'
    output_file='/tmp/_cfggen_'
    for item in get_pid_sku(raw_pid_sku):
        pidpath = item[0]
        sku = item[1]
        if sku:
            cfggen = 'sonic-cfggen -t {}/{}/{} -k {} > {}'.format(prefix, pidpath, mmucommand, sku, output_file)
        else:
            cfggen = 'sonic-cfggen -t {}/{}/{} -k {} > {}'.format(prefix, pidpath, mmucommand, '""', output_file)
        #
        logging.info("executing {} for pid/sku {}".format(cfggen, pidpath))
        try:
            rc = duthost.shell(cfggen)
            print_rc(cfggen, rc)
        except:
            pytest.fail("{} failed for pid/sku {}".format(mmucommand, pidpath))
        # 
        json_cmd='jq < {}'.format(output_file)
        logging.info("executing {} for pid/sku {}".format(json_cmd, pidpath))
        try:
            rc = duthost.shell(json_cmd)
            print_rc(json_cmd, rc)
        except:
            pytest.fail("{} for {} failed for pid/sku {}".format(json_cmd, mmucommand, pidpath))


@pytest.mark.parametrize("raw_pid_sku", pid_sku)
@pytest.mark.parametrize("mmucommand", ["buffers.json.j2", "qos.json.j2"])
def test_mmu_config(duthosts, raw_pid_sku, mmucommand):
    for duthost in duthosts:
        if duthost.facts["asic_type"] != "cisco-8000":
            pytest.skip("Test is only supported for cisco-8000")
        run_mmu_config(duthost, raw_pid_sku, mmucommand)


# apply special config for certain platform(s) and retest the configuration
aiml_pid_sku = [
           {"x86_64-8111_32eh_o-r0": ["Cisco-8111-O32", "Cisco-8111-O64"]},
           {"x86_64-8111_32eh_o-r0": ["Cisco-8111-O62C2"]}
           ]
aiml_special_cfg = {'DEVICE_METADATA|localhost': 
          {"resource_type": "Compute-AI", "type" : "BackEndLeafRouter"} }

class AIML_Config:
  def __init__(self, duthost, aiml_special_cfg, mmucommand):
      for t in (aiml_special_cfg):
          valdict = aiml_special_cfg[t]
          for k in valdict:
              getcmd="redis-cli -n 4 HGET '{}' {}".format(t, k)
              logging.info("executing {} ".format(getcmd))
              try:
                  rc = duthost.shell(getcmd)
                  print_rc(getcmd, rc)
              except:
                  pytest.fail("{} failed ".format(getcmd))
              v_orig=rc['stdout']
              setattr(self, k, v_orig)
              logging.info("key {} saving val {}".format(k, v_orig))
              new_val=valdict[k]
              setcmd="redis-cli -n 4 HSET '{}' {} {}".format(t, k, new_val)
              duthost.shell(setcmd) # first set return an error
              logging.info("executing {} ".format(setcmd))
              try:
                  rc = duthost.shell(setcmd)
                  print_rc(setcmd, rc)
              except:
                  pytest.fail("{} failed error: {}".format(setcmd, rc['stdout']))


  def __del__(duthost, aiml_special_cfg):
      # reset the original config
      for t, v in (aiml_special_cfg):
          v = aiml_special_cfg[t]
          if list(v):
              for k in v:
                  val = getattr(self, k)
                  logging.info("for key {} retrieved val {}, setting".format(k, val))
                  setcmd="redis-cli -n 4 HSET '{}' {} {}".format(t, k, val)
                  logging.info("executing {} ".format(setcmd))
                  try:
                      rc = duthost.shell(setcmd)
                      print_rc(setcmd, rc)
                  except:
                      pytest.fail("{} failed to set original value, error: {}".format(setcmd, rc['stdout']))


@pytest.mark.parametrize("aiml_pid_sku", aiml_pid_sku)
@pytest.mark.parametrize("mmucommand", ["qos.json.j2"])
def test_aiml_qos_config(duthosts, aiml_pid_sku, mmucommand):
    for duthost in duthosts:
        if duthost.facts["asic_type"] != "cisco-8000":
            pytest.skip("Test is only supported for cisco-8000")
        obj = AIML_Config(duthost, aiml_special_cfg, mmucommand)
        run_mmu_config(duthost, aiml_pid_sku, mmucommand)
    # post test run, verified in dut that the type/resource_type are LeafRouter/nil
