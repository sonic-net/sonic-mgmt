"""
Raw PMBus access to a DUT device over i2ctransfer, plus the PMBus command codes,
status bits and LINEAR11 codec tests need to drive it.

Only use this while no kernel driver is bound to the device (for a PDDF device,
after `pddfparse.py --delete-subtree`), otherwise the transfers race the driver.
"""

from tests.common.helpers.assertions import pytest_assert

PMBUS_OPERATION = 0x01
PMBUS_CLEAR_FAULTS = 0x03
PMBUS_IOUT_OC_FAULT_LIMIT = 0x46
PMBUS_IOUT_OC_WARN_LIMIT = 0x4a
PMBUS_STATUS_WORD = 0x79
PMBUS_STATUS_IOUT = 0x7b
PMBUS_READ_IOUT = 0x8c

PMBUS_OPERATION_OFF = 0x00
PMBUS_OPERATION_ON = 0x80

STATUS_WORD_IOUT_OC_FAULT = 1 << 4
STATUS_WORD_OFF = 1 << 6
STATUS_WORD_POWER_GOOD_N = 1 << 11
STATUS_IOUT_OC_FAULT = 1 << 7

LINEAR11_MAX_MANTISSA = 1023


def linear11_exponent(word):
    exponent = (word >> 11) & 0x1f
    return exponent - 32 if exponent > 15 else exponent


def linear11_decode(word):
    mantissa = word & 0x7ff
    if mantissa > 1023:
        mantissa -= 2048
    return mantissa * 2.0 ** linear11_exponent(word)


def linear11_encode(mantissa, exponent):
    return ((exponent & 0x1f) << 11) | (mantissa & 0x7ff)


def linear11_equal(a, b):
    """True if two LINEAR11 words agree to within half a step of the coarser encoding.
    A device may store a written value with a different exponent than it was sent."""
    step = max(2.0 ** linear11_exponent(a), 2.0 ** linear11_exponent(b))
    return abs(linear11_decode(a) - linear11_decode(b)) <= step / 2


class PmbusPsu:
    """PMBus PSU at `addr` on I2C bus `bus`, driven with i2ctransfer on the DUT."""

    def __init__(self, duthost, name, bus, addr):
        self.duthost = duthost
        self.name = name
        self.bus = bus
        self.addr = addr

    def _xfer(self, args):
        cmd = "sudo i2ctransfer -y {} {}".format(self.bus, args)
        res = self.duthost.shell(cmd, module_ignore_errors=True)
        pytest_assert(res['rc'] == 0, "{}: '{}' failed (rc={}): {}{}".format(
            self.name, cmd, res['rc'], res['stdout'], res['stderr']))
        return [int(tok, 16) for tok in res['stdout'].split()]

    def read_byte(self, command):
        return self._xfer("w1@0x{:02x} 0x{:02x} r1".format(self.addr, command))[0]

    def read_word(self, command):
        low, high = self._xfer("w1@0x{:02x} 0x{:02x} r2".format(self.addr, command))
        return low | (high << 8)

    def write_byte(self, command, value):
        self._xfer("w2@0x{:02x} 0x{:02x} 0x{:02x}".format(self.addr, command, value))

    def write_word(self, command, value):
        self._xfer("w3@0x{:02x} 0x{:02x} 0x{:02x} 0x{:02x}".format(
            self.addr, command, value & 0xff, (value >> 8) & 0xff))

    def send_byte(self, command):
        self._xfer("w1@0x{:02x} 0x{:02x}".format(self.addr, command))

    def output_is_up(self):
        return not self.read_word(PMBUS_STATUS_WORD) & (STATUS_WORD_OFF | STATUS_WORD_POWER_GOOD_N)

    def oc_fault_latched(self):
        return bool(self.read_byte(PMBUS_STATUS_IOUT) & STATUS_IOUT_OC_FAULT)
