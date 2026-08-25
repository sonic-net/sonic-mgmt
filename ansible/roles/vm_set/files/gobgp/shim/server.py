"""HTTP front end -- one ExaBGP-compatible server per neighbor port.

Ties the pure pieces together: :mod:`parser` turns the POST body into command
dicts, :class:`~gobgp.shim.translator.NeighborClient` batches them into one
gRPC stream, and GET ``/adj-in`` returns the structured receive view. The wire
contract (per-neighbor port, ``command=``/``commands=`` form-encoding, ``done``/
``error`` text responses) is identical to the ExaBGP ``http_api.py`` it
replaces, so no caller in sonic-mgmt changes.

Each port gets its own app and :class:`NeighborClient`, so neighbours share no
state and a shard adds no cross-port serialization beyond the GIL it already
has. Flask parses the request; the shim owns the body cap and the command
semantics.
"""
import json
import logging
import time

from flask import Flask, Response, request
from werkzeug.exceptions import HTTPException
from werkzeug.serving import WSGIRequestHandler
from werkzeug.serving import make_server as _make_wsgi_server

from . import parser
from .translator import NeighborClient

LOG = logging.getLogger("gobgp_shim")

# Cap on a POST body; announce_routes.py batches 200 commands (~25 KB).
MAX_BODY_BYTES = 16 * 1024 * 1024


def _sanitize(value):
    """Strip CR/LF so untrusted text cannot forge log records."""
    return str(value).replace("\r", " ").replace("\n", " ")


def _reason(exc):
    """Failure category for the response body.

    The full message goes to the shim log; the reply carries only the
    exception type, so a failing route is still attributable without
    returning interpreter detail to the caller.
    """
    return type(exc).__name__


class _RequestHandler(WSGIRequestHandler):
    """Route werkzeug's access and error logs through the shim logger."""

    def log(self, type_, message, *args):
        LOG.debug("%s %s", self.address_string(), _sanitize(message % args))


def _read_body():
    """Return the request body, or ``None`` if it exceeds the cap.

    Reads at most one byte past the cap, so an oversized body is refused
    without ever being buffered -- for both ``Content-Length`` and chunked
    framing, and independently of the werkzeug version. werkzeug's own limit
    sits one byte higher so that overshoot stays visible here: at the cap it
    would truncate the stream silently instead, and old werkzeug ignores the
    limit altogether.
    """
    declared = request.content_length
    if declared is not None and declared > MAX_BODY_BYTES:
        return None
    raw = request.stream.read(MAX_BODY_BYTES + 1)
    if len(raw) > MAX_BODY_BYTES:
        return None
    return raw.decode("utf-8", "replace")


def make_app(client):
    """Build the Flask app that serves one neighbor ``client``."""
    app = Flask("gobgp_shim", static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES + 1

    def _text(code, body):
        return Response(body, status=code, mimetype="text/plain")

    def _reject_too_large():
        LOG.error("[%s:%s] POST body over %d byte cap, rejected",
                  client.name, client.family, MAX_BODY_BYTES)
        return _text(413, "error: request body too large\n")

    @app.errorhandler(413)
    def _too_large(exc):
        return _reject_too_large()

    @app.errorhandler(Exception)
    def _unhandled(exc):
        # Keeps the plain-text error contract, and stops Flask from logging
        # the untrusted request path itself.
        if isinstance(exc, HTTPException):
            return exc
        LOG.error("[%s:%s] %s FAILED: %s", client.name, client.family,
                  _sanitize(request.path), _sanitize(exc))
        return _text(500, "error: %s\n" % _reason(exc))

    @app.post("/", defaults={"path": ""})
    @app.post("/<path:path>")
    def apply_commands(path):
        """Apply every command in the body; 200 iff all of them applied."""
        body = _read_body()
        if body is None:
            return _reject_too_large()
        cmds = parser.commands_from_body(body)
        parsed_list, errors = [], []
        for raw in cmds:
            try:
                parsed_list.append(parser.parse_command(raw))
            except Exception as exc:  # parser degrades to noop; guard anyway
                LOG.error("[%s:%s] parse cmd=%r FAILED: %s", client.name,
                          client.family, _sanitize(raw), _sanitize(exc))
                errors.append("%s: %s" % (raw, _reason(exc)))
        n_add = sum(len(p.get("prefixes", [])) for p in parsed_list
                    if p.get("op") != "noop" and not p.get("is_withdraw"))
        n_del = sum(len(p.get("prefixes", [])) for p in parsed_list
                    if p.get("op") != "noop" and p.get("is_withdraw"))
        t0 = time.time()
        try:
            # best-effort: good routes still apply; failures return as strings.
            errors.extend(client.apply_many(parsed_list))
        except Exception as exc:  # gRPC transport / backend down
            LOG.error("[%s:%s] apply_many FAILED: %s", client.name,
                      client.family, _sanitize(exc))
            errors.append("apply_many: %s" % _reason(exc))
        LOG.info("[%s:%s] POST: %d cmds -> +%d/-%d prefixes in %.2fs (%d err)",
                 client.name, client.family, len(cmds), n_add, n_del,
                 time.time() - t0, len(errors))
        # AddPath is idempotent per NLRI, so retry-on-500 is safe.
        if errors:
            return _text(500, "error\n" + "\n".join(errors))
        return _text(200, "done\n" if parsed_list else "OK\n")

    @app.get("/adj-in", strict_slashes=False)
    def adj_in():
        """Structured ADJ_IN view of the prefixes this neighbor received."""
        return Response(
            json.dumps({"prefixes": client.adj_in_prefixes()}) + "\n",
            mimetype="application/json")

    @app.get("/", defaults={"path": ""})
    @app.get("/<path:path>")
    def liveness(path):
        return _text(200, "OK\n")

    return app


def make_server(port, spec):
    """Create (but do not start) the HTTP server for one neighbor ``port``.

    ``spec`` is one portmap entry: ``{grpc, family, name, self_nexthop}``. The
    socket is bound here so a shard fails fast on a port clash; the caller runs
    ``serve_forever``.
    """
    client = NeighborClient(spec["grpc"], spec["family"], spec.get("name", "?"),
                            spec.get("self_nexthop"))
    try:
        return _make_wsgi_server("0.0.0.0", int(port), make_app(client),
                                 threaded=True, request_handler=_RequestHandler)
    except SystemExit as exc:
        # werkzeug exits the process itself when the socket will not bind;
        # surface it as an error the caller can attribute to this port.
        raise OSError("cannot bind port %s" % port) from exc
