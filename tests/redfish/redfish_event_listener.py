"""
Webhook receiver standing in for a rack manager's Redfish event endpoint.

bmcweb POSTs an ``#Event.v1_4_0.Event`` payload to a subscription's
Destination. Every POST is recorded as ``{"path", "peer", "body"}`` -- in
memory and, when an output file is given, as one JSON line per delivery --
so a test can read back exactly what the rack manager received.

Two ways to run it:

* in-process from a test (``EventReceiver(...).start()``) when the BMC can
  reach the sonic-mgmt container;
* as a standalone, stdlib-only script on another host the BMC can reach::

      python3 redfish_event_listener.py --port 18081 --output /tmp/events.jsonl
"""
import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Handler(BaseHTTPRequestHandler):

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            body = {"_raw": raw.decode("utf-8", "replace")}
        self.server.record({"path": self.path, "peer": self.client_address[0], "body": body})
        # bmcweb treats any 2xx as a successful delivery.
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


class EventReceiver(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, host="0.0.0.0", port=0, output=None):
        super().__init__((host, port), _Handler)
        self._lock = threading.Lock()
        self._events = []
        self._output = output

    @property
    def port(self):
        return self.server_address[1]

    def record(self, record):
        with self._lock:
            self._events.append(record)
        if self._output:
            with open(self._output, "a") as f:
                f.write(json.dumps(record) + "\n")

    def events(self):
        with self._lock:
            return list(self._events)

    def start(self):
        threading.Thread(target=self.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.shutdown()
        self.server_close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--output", required=True, help="append one JSON line per received POST")
    args = parser.parse_args(argv)
    EventReceiver(args.bind, args.port, args.output).serve_forever()


if __name__ == "__main__":
    main()
