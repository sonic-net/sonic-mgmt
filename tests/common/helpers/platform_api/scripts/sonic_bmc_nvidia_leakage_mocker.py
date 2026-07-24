#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Mock NVIDIA AST2700 BMC hw-management leakage input readings.

Unlike ``leakage_threshold_test.py`` (which rewrites the thresholds), this tool
leaves the thresholds untouched and instead redirects the ``input`` symlink of a
leakage channel:

    /var/run/hw-management/leakage/<a2d>/<channel>/input
        -> /sys/bus/i2c/devices/27-0049/iio:device0/in_voltage0_raw   (default)

While mocked, ``input`` points at a plain mock file we own, so we can feed the
platform code an arbitrary raw reading. The original link target is saved next
to it (``input.orig``) so it can be restored exactly.

Threshold model (see ``sonic_platform/leakage_sensor.py``):

    scaled = input * scale
    ordering:  lcrit <= crit <= lwarn <= warn <= min <= max
    OK        when scaled in [min,   max]
    CRITICAL  when scaled in [lcrit, crit]
    MINOR     when scaled in [lwarn, warn]
    ERROR     when scaled > max

To place the reading in a band we read the thresholds and back-compute the raw
value (``raw = scaled / scale``).

Usage:
    leakage_input_mock.py list
    leakage_input_mock.py status
    leakage_input_mock.py mock --all        --severity crit
    leakage_input_mock.py mock --sensor 1/1 --severity warn
    leakage_input_mock.py mock --sensor 1/1 --severity error
    leakage_input_mock.py mock --sensor 1/1 --raw 123456   # arbitrary raw value
    leakage_input_mock.py restore --sensor 1/1
    leakage_input_mock.py restore --all

The ``NvidiaBMCLeakageMock`` class is importable and meant to be reused from
tests (point ``leakage_root`` at a fixture tree instead of the real sysfs).
"""

import argparse
import os
import sys

HW_MGMT_ROOT = os.environ.get("HW_MGMT_ROOT", "/var/run/hw-management")
DEFAULT_LEAKAGE_ROOT = os.path.join(HW_MGMT_ROOT, "leakage")

THRESHOLD_FILES = ("scale", "lcrit", "crit", "lwarn", "warn", "min", "max")
SEVERITIES = ("crit", "warn", "error", "ok")


class LeakageMockError(Exception):
    """Raised for mocking errors (missing sensor, unknown severity...)."""


class LeakageMockSensor:
    """A single discovered leakage channel."""

    def __init__(self, a2d_index, channel_index, path, name=None):
        self.a2d_index = a2d_index
        self.channel_index = channel_index
        self.path = path
        self.name = name

    @property
    def id(self):
        return "{}/{}".format(self.a2d_index, self.channel_index)

    @property
    def input_path(self):
        return os.path.join(self.path, "input")


class NvidiaBMCLeakageMock:
    """
    Mock/restore hw-management leakage ``input`` readings by swapping the symlink.

    Thresholds are only ever read (to compute a raw value that lands the scaled
    reading in the requested band); they are never modified. Mocking swaps
    ``input`` to point at ``input.mock`` (our value file) and saves the original
    link target in ``input.orig`` so restore is exact.
    """

    MOCK_SUFFIX = ".mock"
    ORIG_SUFFIX = ".orig"

    def __init__(self, leakage_root=None):
        self.leakage_root = leakage_root or DEFAULT_LEAKAGE_ROOT

    # ---- discovery -------------------------------------------------------

    def discover(self):
        """Return sorted ``LeakageMockSensor`` objects found under the root."""
        if not os.path.isdir(self.leakage_root):
            raise LeakageMockError("leakage root not found: " + self.leakage_root)
        sensors = []
        for a2d in sorted(os.listdir(self.leakage_root)):
            a2d_path = os.path.join(self.leakage_root, a2d)
            if not os.path.isdir(a2d_path):
                continue
            for chan in sorted(os.listdir(a2d_path)):
                chan_path = os.path.join(a2d_path, chan)
                if os.path.lexists(os.path.join(chan_path, "input")):
                    name = self._read_text(os.path.join(chan_path, "channel_name"))
                    sensors.append(LeakageMockSensor(a2d, chan, chan_path, name))
        return sensors

    def get_sensor(self, sensor_id):
        """Return the sensor matching ``sensor_id`` ("<a2d>/<channel>") or raise."""
        wanted = os.path.normpath(sensor_id)
        sensors = self.discover()
        for sensor in sensors:
            if sensor.id == wanted:
                return sensor
        available = ", ".join(s.id for s in sensors) or "<none>"
        raise LeakageMockError(
            "sensor {!r} not found; available: {}".format(sensor_id, available)
        )

    def _resolve(self, sensor):
        return sensor if isinstance(sensor, LeakageMockSensor) else self.get_sensor(sensor)

    # ---- thresholds ------------------------------------------------------

    def read_thresholds(self, sensor):
        """Return a dict of ``scale`` + threshold floats for ``sensor``."""
        sensor = self._resolve(sensor)
        return {n: self._read_float(os.path.join(sensor.path, n)) for n in THRESHOLD_FILES}

    def raw_for_severity(self, thresholds, severity):
        """Back-compute the raw ``input`` value for ``severity`` (raw = scaled/scale)."""
        sev = severity.lower()
        if sev == "crit":
            scaled = (thresholds["lcrit"] + thresholds["crit"]) / 2.0
        elif sev == "warn":
            scaled = (thresholds["lwarn"] + thresholds["warn"]) / 2.0
        elif sev == "ok":
            scaled = (thresholds["min"] + thresholds["max"]) / 2.0
        elif sev == "error":
            span = thresholds["max"] - thresholds["min"]
            scaled = thresholds["max"] + (span if span > 0 else 1.0)
        else:
            raise LeakageMockError("unknown severity: " + severity)
        return scaled / thresholds["scale"]

    # ---- mock / restore --------------------------------------------------

    def is_mocked(self, sensor):
        sensor = self._resolve(sensor)
        return os.path.exists(sensor.input_path + self.ORIG_SUFFIX)

    def mock_sensor(self, sensor, severity=None, raw=None):
        """
        Redirect ``sensor``'s input to a mock file.

        Provide either ``severity`` (crit/warn/error/ok, computed from thresholds)
        or an explicit ``raw`` value. Returns the raw value written.
        """
        sensor = self._resolve(sensor)
        if (severity is None) == (raw is None):
            raise LeakageMockError("provide exactly one of severity or raw")
        if raw is None:
            raw = self.raw_for_severity(self.read_thresholds(sensor), severity)

        input_path = sensor.input_path
        mock_path = input_path + self.MOCK_SUFFIX
        if not self.is_mocked(sensor):
            os.symlink(os.readlink(input_path), input_path + self.ORIG_SUFFIX)
        self._write_value(mock_path, raw)
        self._replace_symlink(input_path, os.path.basename(mock_path))
        return float(raw)

    def restore_sensor(self, sensor):
        """Restore ``sensor``'s original input link. Returns True if it acted."""
        sensor = self._resolve(sensor)
        input_path = sensor.input_path
        orig_path = input_path + self.ORIG_SUFFIX
        if not os.path.exists(orig_path):
            return False
        self._replace_symlink(input_path, os.readlink(orig_path))
        for path in (orig_path, input_path + self.MOCK_SUFFIX):
            if os.path.lexists(path):
                os.remove(path)
        return True

    def mock_all(self, severity=None, raw=None):
        return {s.id: self.mock_sensor(s, severity=severity, raw=raw) for s in self.discover()}

    def restore_all(self):
        return {s.id: self.restore_sensor(s) for s in self.discover()}

    # ---- io helpers ------------------------------------------------------

    @staticmethod
    def _replace_symlink(link_path, target):
        """Atomically point ``link_path`` at ``target`` (no gap for a reader)."""
        tmp = link_path + ".tmp"
        if os.path.lexists(tmp):
            os.remove(tmp)
        os.symlink(target, tmp)
        os.replace(tmp, link_path)

    @staticmethod
    def _write_value(path, value):
        """Atomically write ``value`` so a concurrent reader never sees a partial file."""
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write("{}\n".format(value))
        os.replace(tmp, path)

    @staticmethod
    def _read_text(path):
        try:
            with open(path, "r") as f:
                return f.read().strip()
        except OSError:
            return None

    @staticmethod
    def _read_float(path):
        return float(open(path).read().strip())


# ------------------------------ CLI ---------------------------------------


def _cmd_list(mock, _args):
    for sensor in mock.discover():
        print("{:<8} name={}".format(sensor.id, sensor.name or "<unknown>"))
    return 0


def _cmd_status(mock, _args):
    for sensor in mock.discover():
        thresholds = mock.read_thresholds(sensor)
        scaled = mock._read_float(sensor.input_path) * thresholds["scale"]
        state = "MOCKED" if mock.is_mocked(sensor) else "original"
        print(
            "{:<8} [{}] scaled={:.6f} -> {}".format(
                sensor.id, state, scaled, os.readlink(sensor.input_path)
            )
        )
    return 0


def _select_sensors(mock, args):
    return mock.discover() if args.all else [mock.get_sensor(args.sensor)]


def _cmd_mock(mock, args):
    if (args.severity is None) == (args.raw is None):
        raise LeakageMockError("provide exactly one of --severity or --raw")
    for sensor in _select_sensors(mock, args):
        raw = mock.mock_sensor(sensor, severity=args.severity, raw=args.raw)
        detail = "severity=" + args.severity if args.severity else "raw override"
        print("mocked {:<8} {} -> raw={} ({})".format(sensor.id, detail, raw, sensor.input_path))
    return 0


def _cmd_restore(mock, args):
    for sensor in _select_sensors(mock, args):
        acted = mock.restore_sensor(sensor)
        print("{} {:<8} ({})".format(
            "restored" if acted else "skipped ", sensor.id, sensor.input_path
        ))
    return 0


def _add_target_args(sub):
    group = sub.add_mutually_exclusive_group(required=True)
    group.add_argument("--sensor", metavar="<a2d>/<channel>", help="single sensor, e.g. '1/1'")
    group.add_argument("--all", action="store_true", help="operate on every sensor")


def _build_parser():
    parser = argparse.ArgumentParser(
        description="Mock NVIDIA AST2700 BMC leakage input readings via symlink swap.",
    )
    parser.add_argument(
        "--root",
        default=DEFAULT_LEAKAGE_ROOT,
        help="leakage root dir (default: {})".format(DEFAULT_LEAKAGE_ROOT),
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list discovered leakage sensors")
    sub.add_parser("status", help="show current reading and mock state per sensor")

    mock_p = sub.add_parser("mock", help="redirect input to a mock reading")
    _add_target_args(mock_p)
    mock_p.add_argument("--severity", choices=SEVERITIES, help="band to synthesize from thresholds")
    mock_p.add_argument("--raw", type=float, help="write this raw input value verbatim")

    restore_p = sub.add_parser("restore", help="restore the original input link")
    _add_target_args(restore_p)
    return parser


def main(argv=None):
    args = _build_parser().parse_args(argv)
    mock = NvidiaBMCLeakageMock(leakage_root=args.root)
    handlers = {"list": _cmd_list, "status": _cmd_status, "mock": _cmd_mock, "restore": _cmd_restore}
    try:
        return handlers[args.command](mock, args)
    except LeakageMockError as exc:
        print("ERROR: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
