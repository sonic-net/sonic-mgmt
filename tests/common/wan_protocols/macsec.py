import logging

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class MACSecprotocol:
    def __init__(self, device_a, interface_a, device_b, interface_b):
        self.device_a = device_a
        self.interface_a = interface_a
        self.device_b = device_b
        self.interface_b = interface_b

    def validate_macsec_status(self):
        """
        :return: boolean, attributes or failure
        """
        # run show macsec adjacency commands on device a and device b
        macsec_status_a, macsec_attributes_a = self.device_a.get_macsec_connection_status_details(self.interface_a)
        macsec_status_b, macsec_attributes_b = self.device_b.get_macsec_connection_status_details(self.interface_b)
        if macsec_status_a and macsec_status_b:
            if (
                macsec_attributes_a["pre-shared-key"]["ckn"].lower()
                != macsec_attributes_b["pre-shared-key"]["ckn"].lower()
            ):
                return (
                    False,
                    "Pre-shared-key doesn't match {0}  {1}".format(
                        macsec_attributes_a["pre-shared-key"]["ckn"], macsec_attributes_b["pre-shared-key"]["ckn"]
                    ),
                )
            if (
                macsec_attributes_a["fallback-key"]["ckn"].lower()
                != macsec_attributes_b["fallback-key"]["ckn"].lower()
            ):
                return (
                    False,
                    "Pre-shared-key doesn't match {0}  {1}".format(
                        macsec_attributes_a["fallback-key"]["ckn"], macsec_attributes_b["fallback-key"]["ckn"]
                    ),
                )
            return True, str(macsec_attributes_a) + str(macsec_attributes_b)
        else:
            return (
                False,
                "no adjacency found between {0} and {1}: {2} {3}".format(
                    self.interface_a, self.interface_b, macsec_attributes_a, macsec_attributes_b
                ),
            )

    def get_macsec_profile(self, device_handle, interface):
        """
        :param device_handle: device handler needing profile
        :param interface: interface configured for macsec profile
        :return: profile_name value from device
        """
        result, profile_name = device_handle.get_macsec_profile(interface)
        return result, profile_name

    def adjust_rekey_period(self, dut_1, dut_2, rekey_period_value):
        """
        :param dut_1: device_a name
        :param dut_2: device_b name
        :param rekey_period_value: rekey period number to set
        :return:
        """
        if "ibr" in dut_1 or "sw" in dut_1 or "ier" in dut_1 or "icr" in dut_1:
            profile_result, profile_name = self.get_macsec_profile(self.device_a, self.interface_a)
            test_result, test_msg = self.device_a.set_rekey_period(profile_name, rekey_period_value)
            return test_result, test_msg
        if "ibr" in dut_2 or "sw" in dut_2 or "ier" in dut_2 or "icr" in dut_2:
            profile_result, profile_name = self.get_macsec_profile(self.device_b, self.interface_b)
            test_result, test_msg = self.device_b.set_rekey_period(profile_name, rekey_period_value)
            return test_result, test_msg
        else:
            return (
                False,
                "rekey period only adjustable on IBR or SW device, {0} and {1} not permitted".format(
                    self.device_a.devicename, self.device_b.devicename
                ),
            )

    def capture_macsec_status_logs(self, a_expected_logs=[], b_expected_logs=[], a_last_count="10", b_last_count="10"):
        """
        captures logs from device_a and device_b related to macsec
        :param a_expected_logs: device_a optional list of messages expected from test
        :param b_expected_logs: optional list of messages expected from test
        :param a_last_count:
        :param b_last_count:
        :return: boolean, log lists
        """
        status_a, logs_a = self.device_a.get_macsec_status_logs(
            interface=self.interface_a, expected_logs=a_expected_logs, last_count=a_last_count
        )
        status_b, logs_b = self.device_b.get_macsec_status_logs(
            interface=self.interface_b, expected_logs=b_expected_logs, last_count=b_last_count
        )
        if status_a and status_b:
            return True, [logs_a, logs_b]
        else:
            return False, [logs_a, logs_b]

    def change_macsec_key(self, key, key_type):
        """
        changes macsec key on dut_1 to selected key for fallback and primary
        :param dut: device handler object
        :param key: key string plaintext example - c64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64cc64c
        :param key_type: string fallback or primary
        :return: tuple boolean result and string message
        """
        profile_result, profile_name = self.get_macsec_profile(self.device_a, self.interface_a)
        if profile_result:
            test_result, test_msg = self.device_a.set_macsec_key(profile_name, key, key_type, self.interface_a)
            return test_result, test_msg

        else:
            test_msg = f"macsec profile could not be retrieved"
            return False, test_msg

    def validate_macsec_encrypted_pks(self):
        """
        :return: boolean, attributes or failure
        """
        # get macsec encrypted packets result
        validate_res, validate_msg = self.device_a.get_macsec_interface_statistics(self.interface_a)
        return validate_res, validate_msg

    def get_macsec_config(self, interface):
        """
        Get running config from DUT
        :param interface: interface configured for macsec profile
        :return: profile_name value from device
        """
        return self.device_a.get_macsec_config(interface)

    def apply_macsec_interface_config(self, commands):
        """
        disable macsec on dut_1 interfaces
        :param commands: list of command to apply to dut
        :return: tuple boolean result
        """
        return self.device_a.apply_macsec_interface_config(commands)

    def delete_macsec_interface_config(self, interface):
        """
        Delete macsec config from dut_1 interfaces
        :param interface: from which config need to be removed
        :return: boolean
        """
        return self.device_a.delete_macsec_interface_config(interface)
