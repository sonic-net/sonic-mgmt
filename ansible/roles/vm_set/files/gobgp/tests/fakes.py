"""gRPC fakes for the shim unit tests (no gobgpd, no network).

:class:`FakeStub` stands in for ``GoBgpServiceStub`` and records what the shim would
have sent, so tests assert on batching / targeting / receive behaviour directly.
"""


class _Namespace(object):
    def __init__(self, **kw):
        self.__dict__.update(kw)


class FakeStub(object):
    """Records ``AddPathStream`` traffic; replays canned ADJ_IN for receive.

    * ``AddPathStream(request_iterator)`` drains the generator and stores every
      ``AddPathStreamRequest`` so tests can count stream calls, request
      messages, and total paths (U4 batching), returning ``None`` like the real
      unary-stream RPC.
    * ``ListPeer`` / ``ListPath`` replay ``adj_in`` keyed by neighbor for U6.
    """

    def __init__(self, peers=None, adj_in=None):
        self.add_calls = []           # list of [AddPathStreamRequest, ...] per call
        self._peers = peers or []
        self._adj_in = adj_in or {}   # {neighbor_address: [prefix, ...]}

    # --- announce/withdraw path ---
    def AddPathStream(self, request_iterator):
        self.add_calls.append(list(request_iterator))
        return None

    @property
    def call_count(self):
        return len(self.add_calls)

    @property
    def request_messages(self):
        return sum(len(reqs) for reqs in self.add_calls)

    @property
    def total_paths(self):
        return sum(len(r.paths) for reqs in self.add_calls for r in reqs)

    def withdraw_flags(self):
        return [p.is_withdraw for reqs in self.add_calls for r in reqs
                for p in r.paths]

    # --- receive path (U6) ---
    def ListPeer(self, req):
        for addr in self._peers:
            yield _Namespace(peer=_Namespace(
                conf=_Namespace(neighbor_address=addr),
                state=_Namespace(neighbor_address=addr)))

    def ListPath(self, req):
        for prefix in self._adj_in.get(req.name, []):
            yield _Namespace(destination=_Namespace(prefix=prefix))
