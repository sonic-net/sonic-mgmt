# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License
import random

from typing import List, Callable, TYPE_CHECKING

from azure.kusto.ingest._resource_manager import _ResourceUri
from azure.storage.queue import QueueServiceClient, QueueClient, QueueMessage, TextBase64DecodePolicy

if TYPE_CHECKING:
    from azure.kusto.ingest.status import StatusMessage


class QueueDetails:
    def __init__(self, name, service):
        self.name = name
        self.service = service

    def __str__(self):
        return "QueueDetails({0.name})".format(self)


class StatusQueue:
    """StatusQueue is a class to simplify access to Kusto status queues (backed by azure storage queues)."""

    def __init__(self, get_queues_func: Callable[[], List[_ResourceUri]], message_cls):
        self.get_queues_func = get_queues_func
        self.message_cls = message_cls

    def _get_queues(self) -> List[QueueClient]:
        return [
            QueueServiceClient(q.account_uri).get_queue_client(queue=q.object_name, message_decode_policy=TextBase64DecodePolicy())
            for q in self.get_queues_func()
        ]

    def is_empty(self) -> bool:
        """Checks if Status queue has any messages"""
        return len(self.peek(1, raw=True)) == 0

    def _deserialize_message(self, m: QueueMessage) -> "StatusMessage":
        """Deserialize a message and return at as `message_cls`
        :param m: original message m.
        """
        return self.message_cls(m.content)

    # TODO: current implementation takes a union top n /  len(queues), which is not ideal,
    #  because the user is not supposed to know that there can be multiple underlying queues
    def peek(self, n=1, raw=False) -> List["StatusMessage"]:
        """Peek status queue
        :param int n: number of messages to return as part of peek.
        :param bool raw: should message content be returned as is (no parsing).
        """

        def _peek_specific_q(_q: QueueClient, _n: int) -> bool:
            has_messages = False
            for m in _q.peek_messages(max_messages=_n):
                if m:
                    has_messages = True
                    result.append(m if raw else self._deserialize_message(m))

                    # short circuit to prevent unneeded work
                    if len(result) == n:
                        return True
            return has_messages

        queues = self._get_queues()
        random.shuffle(queues)

        per_q = int(n / len(queues)) + 1

        result = []

        non_empty_qs = []

        for q in queues:
            if _peek_specific_q(q, per_q):
                non_empty_qs.append(q)

            if len(result) == n:
                return result

        # in-case queues aren't balanced, and we didn't get enough messages, iterate again and this time get all that we can
        for q in non_empty_qs:
            _peek_specific_q(q, n)
            if len(result) == n:
                return result

        # because we ask for n / len(qs) + 1, we might get more message then requests
        return result

    # TODO: current implementation takes a union top n /  len(queues), which is not ideal,
    #  because the user is not supposed to know that there can be multiple underlying queues
    def pop(self, n: int = 1, raw: bool = False, delete: bool = True) -> List["StatusMessage"]:
        """Pop status queue
        :param int n: number of messages to return as part of peek.
        :param bool raw: should message content be returned as is (no parsing).
        :param bool delete: should message be deleted after pop. default is True as this is expected of a q.
        """

        def _pop_specific_q(_q: QueueClient, _n: int) -> bool:
            has_messages = False
            for m in _q.receive_messages(messages_per_page=_n):
                if m:
                    has_messages = True
                    result.append(m if raw else self._deserialize_message(m))
                    if delete:
                        _q.delete_message(m.id, m.pop_receipt)

                    # short circuit to prevent unneeded work
                    if len(result) == n:
                        return True
            return has_messages

        queues = self._get_queues()
        random.shuffle(queues)

        per_q = int(n / len(queues)) + 1

        result = []

        non_empty_qs = []

        for q in queues:
            if _pop_specific_q(q, per_q):
                non_empty_qs.append(q)

            if len(result) == n:
                return result

        # in-case queues aren't balanced, and we didn't get enough messages, iterate again and this time get all that we can
        for q in non_empty_qs:
            _pop_specific_q(q, n)
            if len(result) == n:
                return result

        # because we ask for n / len(qs) + 1, we might get more message then requests
        return result
