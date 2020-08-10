import logging
import re

import pytest
import yaml

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.platform_api import chassis, component

from platform_api_test_base import PlatformApiTestBase

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer
    pytest.mark.topology('any')
]

image_list = [
    "current",
    "next"
]

class TestComponentApi(PlatformApiTestBase):
    """Platform API test cases for the Component class"""

    num_components = None

    # This fixture would probably be better scoped at the class level, but
    # it relies on the platform_api_conn fixture, which is scoped at the function
    # level, so we must do the same here to prevent a scope mismatch.
    @pytest.fixture(scope="function", autouse=True)
    def setup(self, platform_api_conn):
        if self.num_components is None:
            try:
                self.num_components = int(chassis.get_num_components(platform_api_conn))
            except:
                pytest.fail("num_components is not an integer")

    #
    # Functions to test methods inherited from DeviceBase class
    #

    def test_get_name(self, duthost, localhost, platform_api_conn):
        if self.num_components == 0:
            pytest.skip("No components found on device")

        for i in range(self.num_components):
            name = component.get_name(platform_api_conn, i)
            if self.expect(name is not None, "Component {}: Unable to retrieve name".format(i)):
                self.expect(isinstance(name, str), "Component {}: Name appears incorrect".format(i))
        self.assert_expectations()

    def test_get_presence(self, duthost, localhost, platform_api_conn):
        if self.num_components == 0:
            pytest.skip("No components found on device")

        for i in range(self.num_components):
            presence = component.get_presence(platform_api_conn, i)
            if self.expect(presence is not None, "Component {}: Unable to retrieve presence".format(i)):
                self.expect(isinstance(presence, bool), "Component {}: Presence appears incorrect".format(i))
                # All components are expected to be present on DuT
                self.expect(presence is True, "Component {} not present".format(i))
        self.assert_expectations()

    def test_get_model(self, duthost, localhost, platform_api_conn):
        if self.num_components == 0:
            pytest.skip("No components found on device")

        for i in range(self.num_components):
            model = component.get_model(platform_api_conn, i)
            if self.expect(model is not None, "Component {}: Unable to retrieve model".format(i)):
                self.expect(isinstance(model, str), "Component {}: Model appears incorrect".format(i))
        self.assert_expectations()

    def test_get_serial(self, duthost, localhost, platform_api_conn):
        if self.num_components == 0:
            pytest.skip("No components found on device")

        for i in range(self.num_components):
            serial = component.get_serial(platform_api_conn, i)
            if self.expect(serial is not None, "Component {}: Unable to retrieve serial number".format(i)):
                self.expect(isinstance(serial, str), "Component {}: Serial number appears incorrect".format(i))
        self.assert_expectations()

    def test_get_status(self, duthost, localhost, platform_api_conn):
        if self.num_components == 0:
            pytest.skip("No components found on device")

        for i in range(self.num_components):
            status = component.get_status(platform_api_conn, i)
            if self.expect(status is not None, "Component {}: Unable to retrieve status".format(i)):
                self.expect(isinstance(status, bool), "Component {}: Status appears incorrect".format(i))
        self.assert_expectations()

    #
    # Functions to test methods defined in ComponentBase class
    #


    def test_get_description(self, duthost, localhost, platform_api_conn):
        if self.num_components == 0:
            pytest.skip("No components found on device")

        for i in range(self.num_components):
            description = component.get_description(platform_api_conn, i)
            if self.expect(description is not None, "Component {}: Failed to retrieve description".format(i)):
                self.expect(isinstance(description, str), "Component {}: Description appears to be incorrect".format(i))
        self.assert_expectations()

    def test_get_firmware_version(self, duthost, localhost, platform_api_conn):
        if self.num_components == 0:
            pytest.skip("No components found on device")

        for i in range(self.num_components):
            fw_version = component.get_firmware_version(platform_api_conn, i)
            if self.expect(fw_version is not None, "Component {}: Failed to retrieve firmware version".format(i)):
                self.expect(isinstance(fw_version, str), "Component {}: Firmware version appears to be incorrect".format(i))
        self.assert_expectations()

    def test_get_available_firmware_version(self, duthost, localhost, platform_api_conn):
        if self.num_components == 0:
            pytest.skip("No components found on device")

        for i in range(self.num_components):
            for image in range(image_list):
                avail_fw_version = component.get_available_firmware_version(platform_api_conn, i, image)
                if self.expect(avail_fw_version is not None, "Component {}: Failed to retrieve available firmware version from image {}".format(i, image)):
                    self.expect(isinstance(avail_fw_version, str), "Component {}: Available Firmware version appears to be incorrect from image {}".format(i, image))
        self.assert_expectations()

    def test_get_firmware_update_notification(self, duthost, localhost, platform_api_conn):
        if self.num_components == 0:
            pytest.skip("No components found on device")

        for i in range(self.num_components):
            for image in range(image_list):
                notif = component.get_firmware_update_notification(platform_api_conn, i, image)
                # Can return "None" if no update required. 
                pytest_assert(isinstance(notif, str), "Component {}: Firmware update notification appears to be incorrect from image {}".format(i, image))

    def test_install_firmware(self, duthost, localhost, platform_api_conn):
        if self.num_components == 0:
            pytest.skip("No components found on device")

        for i in range(self.num_components):
            for image in range(image_list):
                install_status = component.install_firmware(platform_api_conn, i, image)
                if self.expect(install_status is not None, "Component {}: Failed to install firmware from image {}".format(i, image)):
                    self.expect(isinstance(avail_fw_version, bool), "Component {}: Return of Firmware installation appears to be incorrect from image {}".format(i, image))
        self.assert_expectations()


    def test_update_firmware(self, duthost, localhost, platform_api_conn):
        if self.num_components == 0:
            pytest.skip("No components found on device")

        for i in range(self.num_components):
            for image in range(image_list):
                update_status = component.update_firmware(platform_api_conn, i, image)
                if self.expect(update_status is not None, "Component {}: Failed to update firmware from image {}".format(i, image)):
                    self.expect(isinstance(update_status, bool), "Component {}: Return of Firmware update appears to be incorrect from image {}".format(i, image))
        self.assert_expectations()
