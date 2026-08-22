import logging
import os
import re
import threading
from datetime import datetime


logger = logging.getLogger(__name__)


class ConsoleCapture:
    """Continuously persist output from an authenticated console connection."""

    def __init__(self, dut_hostname, reboot_type, artifact_dir="./logs/console"):
        self.dut_hostname = dut_hostname
        self.reboot_type = reboot_type
        self.artifact_dir = artifact_dir
        self.artifact_path = None
        self.console = None
        self._file = None
        self._reader = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._open_artifact()

    @staticmethod
    def _safe_name(value):
        safe_value = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value)).strip("._") or "unknown"
        return safe_value[:100]

    def _open_artifact(self):
        try:
            os.makedirs(self.artifact_dir, exist_ok=True)
            while self._file is None:
                timestamp = str(datetime.utcnow()).replace(" ", ".")
                filename = "console.{}.{}.log".format(
                    self._safe_name(self.reboot_type), timestamp)
                self.artifact_path = os.path.abspath(os.path.join(self.artifact_dir, filename))
                try:
                    self._file = open(self.artifact_path, "x", encoding="utf-8")
                except FileExistsError:
                    continue
            self.record_event("console capture artifact created")
            logger.info("Console capture artifact: %s", self.artifact_path)
        except Exception as err:
            if self._file is not None:
                try:
                    self._file.close()
                except Exception as close_err:
                    logger.warning("Unable to close console capture artifact after setup failure: %s", close_err)
            self.artifact_path = None
            self._file = None
            logger.warning("Unable to create console capture artifact: %s", err)

    def _write(self, message):
        if self._file is None:
            return
        timestamp = datetime.utcnow().isoformat(timespec="milliseconds")
        try:
            with self._lock:
                for line in str(message).splitlines() or [""]:
                    self._file.write("{} {}\n".format(timestamp, line))
                self._file.flush()
        except Exception as err:
            logger.warning("Unable to write console capture artifact for %s: %s", self.dut_hostname, err)

    def record_event(self, message):
        self._write("[capture] {}".format(message))

    def start(self, console):
        """Start reading only after the caller has authenticated the console."""
        self.console = console
        if self._file is None:
            return
        self.record_event("authenticated console connected; capture started")
        reader = threading.Thread(
            target=self._read_loop,
            name="console-capture-{}".format(self._safe_name(self.dut_hostname)),
            daemon=True,
        )
        reader.start()
        self._reader = reader

    def _drain_once(self):
        output = self.console.read_channel()
        if output:
            self._write(output)

    def _read_loop(self):
        while not self._stop_event.wait(0.1):
            try:
                self._drain_once()
            except Exception as err:
                self.record_event("console reader stopped after error: {}".format(err))
                logger.warning("Console capture reader failed for %s: %s", self.dut_hostname, err)
                return

    def stop(self):
        """Stop the reader, perform a final drain, and disconnect the console."""
        self._stop_event.set()
        if self._reader is not None:
            self._reader.join(timeout=5)
            if self._reader.is_alive():
                self.record_event("console reader did not stop within 5 seconds")
                logger.warning("Console capture reader did not stop for %s", self.dut_hostname)
        if self.console is not None:
            try:
                self._drain_once()
            except Exception as err:
                self.record_event("final console drain failed: {}".format(err))
            try:
                self.console.disconnect()
                self.record_event("console disconnected")
            except Exception as err:
                self.record_event("console disconnect failed: {}".format(err))
                logger.warning("Console disconnect failed for %s: %s", self.dut_hostname, err)
        if self._file is not None:
            self.record_event("console capture stopped")
            try:
                self._file.close()
            except Exception as err:
                logger.warning("Unable to close console capture artifact for %s: %s", self.dut_hostname, err)
            self._file = None
