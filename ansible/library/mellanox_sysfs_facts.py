#!/usr/bin/python


class MellanoxSysfsModule(object):
    def __init__(self):
        self.instances = []
        self.module = AnsibleModule(
            argument_spec=dict(
                sku_info=dict(required=True, type='dict'),
                collect_broken_link=dict(type='bool', default=True),
                collect_asic=dict(type='bool', default=True),
                collect_fan=dict(type='bool', default=True),
                collect_cpu=dict(type='bool', default=True),
                collect_psu=dict(type='bool', default=True),
                collect_sfp=dict(type='bool', default=True),
            ),
            supports_check_mode=True)

        self.sku_info = self.module.params['sku_info']
        self.collect_broken_link = self.module.params['collect_broken_link']
        self.collect_asic = self.module.params['collect_asic']
        self.collect_fan = self.module.params['collect_fan']
        self.collect_cpu = self.module.params['collect_cpu']
        self.collect_psu = self.module.params['collect_psu']
        self.collect_sfp = self.module.params['collect_sfp']
        self.facts = {}

    def run(self):
        """
            Main method of the class
        """
        if self.collect_broken_link:
            self.collect_broken_link_info()

        if self.collect_asic:
            self.collect_asic_info()

        if self.collect_fan:
            self.collect_fan_info()

        if self.collect_cpu:
            self.collect_cpu_info()

        if self.collect_psu:
            self.collect_psu_info()

        if self.collect_sfp:
            self.collect_sfp_info()

        self.module.exit_json(ansible_facts=self.facts)

    def run_command(self, command):
        try:
            rc, out, err = self.module.run_command(command, executable='/bin/bash', use_unsafe_shell=True)
        except Exception as e:
            self.module.fail_json(msg=str(e))

        if rc != 0:
            self.module.fail_json(msg="Command failed rc=%d, out=%s, err=%s" %
                                      (rc, out, err))
        return out.strip()

    def collect_broken_link_info(self):
        self.facts['broken_link_info'] = self.run_command("find /var/run/hw-management -xtype l")

    def collect_asic_info(self):
        self.facts['asic_temp'] = self.run_command("cat /var/run/hw-management/thermal/asic")

    def collect_fan_info(self):
        fan_count = self.sku_info["fans"]["number"]
        fan_info = {}
        for fan_id in range(1, fan_count + 1):
            single_fan_info = {}
            if self.sku_info["fans"]["hot_swappable"]:
                fan_status = "/var/run/hw-management/thermal/fan{}_status".format(fan_id)
                single_fan_info['fan_status'] = self.run_command("cat %s" % fan_status)

            fan_fault = "/var/run/hw-management/thermal/fan{}_fault".format(fan_id)
            single_fan_info['fan_fault'] = self.run_command("cat %s" % fan_fault)

            fan_min = "/var/run/hw-management/thermal/fan{}_min".format(fan_id)
            single_fan_info['fan_min'] = self.run_command("cat %s" % fan_min)

            fan_max = "/var/run/hw-management/thermal/fan{}_max".format(fan_id)
            single_fan_info['fan_max'] = self.run_command("cat %s" % fan_max)

            fan_speed_set = "/var/run/hw-management/thermal/fan{}_speed_set".format(fan_id)
            single_fan_info['fan_speed_set'] = self.run_command("cat %s" % fan_speed_set)

            fan_speed_get = "/var/run/hw-management/thermal/fan{}_speed_get".format(fan_id)
            single_fan_info['fan_speed_get'] = self.run_command("cat %s" % fan_speed_get)
            fan_info[fan_id] = single_fan_info
        self.facts['fan_info'] = fan_info

    def collect_cpu_info(self):
        cpu_pack_count = self.sku_info["cpu_pack"]["number"]
        if cpu_pack_count > 0:
            cpu_pack_info = dict()
            cpu_pack_info['cpu_pack_temp'] = self.run_command("cat /var/run/hw-management/thermal/cpu_pack")
            cpu_pack_info['cpu_pack_max_temp'] = self.run_command("cat /var/run/hw-management/thermal/cpu_pack_max")
            cpu_pack_info['cpu_crit_max_temp'] = self.run_command("cat /var/run/hw-management/thermal/cpu_pack_crit")
            self.facts['cpu_pack_info'] = cpu_pack_info

        cpu_info = {}
        cpu_core_count = self.sku_info["cpu_cores"]["number"]
        for core_id in range(0, cpu_core_count):
            cpu_core_info = {}
            cpu_core_temp_file = "/var/run/hw-management/thermal/cpu_core{}".format(core_id)
            cpu_core_info['cpu_core_temp'] = self.run_command("cat %s" % cpu_core_temp_file)

            cpu_core_max_temp_file = "/var/run/hw-management/thermal/cpu_core{}_max".format(core_id)
            cpu_core_info['cpu_core_max_temp'] = self.run_command("cat %s" % cpu_core_max_temp_file)

            cpu_core_crit_temp_file = "/var/run/hw-management/thermal/cpu_core{}_crit".format(core_id)
            cpu_core_info['cpu_core_crit_temp'] = self.run_command("cat %s" % cpu_core_crit_temp_file)
            cpu_info[core_id] = cpu_core_info
        self.facts['cpu_info'] = cpu_info

    def collect_psu_info(self):
        if not self.sku_info["psus"]["hot_swappable"]:
            return

        psu_info = {}
        psu_count = self.sku_info["psus"]["number"]
        for psu_id in range(1, psu_count + 1):
            single_psu_info = {}
            psu_status_file = "/var/run/hw-management/thermal/psu{}_status".format(psu_id)
            single_psu_info['psu_status'] = self.run_command("cat %s" % psu_status_file)
            if single_psu_info['psu_status'] == '0':
                continue

            psu_pwr_status_file = "/var/run/hw-management/thermal/psu{}_pwr_status".format(psu_id)
            single_psu_info['psu_pwr_status'] = self.run_command("cat %s" % psu_pwr_status_file)
            if single_psu_info['psu_pwr_status'] == '0':
                continue

            psu_temp_file = "/var/run/hw-management/thermal/psu{}_temp".format(psu_id)
            single_psu_info['psu_temp'] = self.run_command("cat %s" % psu_temp_file)

            psu_max_temp_file = "/var/run/hw-management/thermal/psu{}_temp_max".format(psu_id)
            single_psu_info['psu_max_temp'] = self.run_command("cat %s" % psu_max_temp_file)

            psu_max_temp_alarm_file = "/var/run/hw-management/thermal/psu{}_temp_max_alarm".format(psu_id)
            single_psu_info['psu_max_temp_alarm'] = self.run_command("cat %s" % psu_max_temp_alarm_file)

            psu_fan_speed_get = "/var/run/hw-management/thermal/psu{}_fan1_speed_get".format(psu_id)
            single_psu_info['psu_fan_speed'] = self.run_command("cat %s" % psu_fan_speed_get)
            psu_info[psu_id] = single_psu_info
        self.facts['psu_info'] = psu_info

    def collect_sfp_info(self):
        sfp_count = self.sku_info["ports"]["number"]
        sfp_info = {}
        for sfp_id in range(1, sfp_count + 1):
            sfp_status = {}
            sfp_temp_fault_file = "/var/run/hw-management/thermal/module{}_temp_fault".format(sfp_id)
            sfp_status['temp_fault'] = self.run_command("cat %s" % sfp_temp_fault_file)

            sfp_temp_file = "/var/run/hw-management/thermal/module{}_temp_input".format(sfp_id)
            sfp_status['temp_input'] = self.run_command("cat %s" % sfp_temp_file)

            sfp_temp_crit_file = "/var/run/hw-management/thermal/module{}_temp_crit".format(sfp_id)
            sfp_status['temp_crit'] = self.run_command("cat %s" % sfp_temp_crit_file)

            sfp_temp_emergency_file = "/var/run/hw-management/thermal/module{}_temp_emergency".format(sfp_id)
            sfp_status['temp_emergency'] = self.run_command("cat %s" % sfp_temp_emergency_file)
            sfp_info[sfp_id] = sfp_status
        self.facts['sfp_info'] = sfp_info


def main():
    m = MellanoxSysfsModule()
    m.run()


from ansible.module_utils.basic import *

if __name__ == "__main__":
    main()
