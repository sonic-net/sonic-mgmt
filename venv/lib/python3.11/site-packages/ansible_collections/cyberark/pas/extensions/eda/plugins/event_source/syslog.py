"""syslog.py.

An ansible-rulebook event source module for receiving events via a syslog.

Arguments:
---------
    host: The hostname to listen to. Set to 0.0.0.0 to listen on all
          interfaces. Defaults to 127.0.0.1
    port: The TCP port to listen to.  Defaults to 1514

"""
from __future__ import (absolute_import, division, print_function)
import asyncio
import json
import logging
import re
from typing import Any


__metaclass__ = type
BASIC_CEF_HEADER_SIZE = 6


def parse(str_input: str) -> dict[str, str]:  # pylint: disable=unsubscriptable-object
    """Parse a string in CEF format and return a dict with header values and extension data.

    # noqa: DAR201
    # noqa: DAR101
    """
    logger = logging.getLogger()
    # Create the empty dict we'll return later
    values = {}

    # This regex separates the string into the CEF header and the extension
    # data.  Once we do this, it's easier to use other regexes to parse each
    # part.
    header_re = r"((CEF:\d+)([^=\\]+\|){,7})(.*)"

    res = re.search(header_re, str_input)

    if res:
        header = res.group(1)
        extension = res.group(4)

        # Split the header on the "|" char.  Uses a negative lookbehind
        # assertion to ensure we don't accidentally split on escaped chars,
        # though.
        spl = re.split(r"(?<!\\)\|", header)

        # If the input entry had any blanks in the required headers, that's wrong
        # and we should return.  Note we explicitly don't check the last item in the
        # split list becuase the header ends in a '|' which means the last item
        # will always be an empty string (it doesn't exist, but the delimiter does).
        if "" in spl[0:-1]:
            logger.warning("Blank field(s) in CEF header. Is it valid CEF format?")
            return None

        # Since these values are set by their position in the header, it's
        # easy to know which is which.
        values["DeviceVendor"] = spl[1]
        values["DeviceProduct"] = spl[2]
        values["DeviceVersion"] = spl[3]
        values["DeviceEventClassID"] = spl[4]
        values["Name"] = spl[5]
        values["DeviceName"] = spl[5]
        if len(spl) > BASIC_CEF_HEADER_SIZE:
            values["Severity"] = spl[6]
            values["DeviceSeverity"] = spl[6]

        # The first value is actually the CEF version, formatted like
        # "CEF:#".  Ignore anything before that (like a date from a syslog message).
        # We then split on the colon and use the second value as the
        # version number.
        cef_start = spl[0].find("CEF")
        if cef_start == -1:
            return None
        (_, version) = spl[0][cef_start:].split(":")   # pylint: disable=disallowed-name
        values["CEFVersion"] = version

        # The ugly, gnarly regex here finds a single key=value pair,
        # taking into account multiple whitespaces, escaped '=' and '|'
        # chars.  It returns an iterator of tuples.
        spl = re.findall(r"([^=\s]+)=((?:[\\]=|[^=])+)(?:\s|$)", extension)
        for i in spl:
            # Split the tuples and put them into the dictionary
            values[i[0]] = i[1]

        # Process custom field labels
        for key in list(values.keys()):
            # If the key string ends with Label, replace it in the appropriate
            # custom field
            if key[-5:] == "Label":
                customlabel = key[:-5]
                # Find the corresponding customfield and replace with the label
                for customfield in list(values.keys()):
                    if customfield == customlabel:
                        values[values[key]] = values[customfield]
                        del values[customfield]
                        del values[key]
    else:
        # return None if our regex had now output
        return None

    # Now we're done!
    logger.debug("Returning values: %s", str(values))
    return values


class SyslogProtocol(asyncio.DatagramProtocol):
    """Provides Syslog Protocol functionality."""

    def __init__(self, edaqueue: asyncio.Queue) -> None:
        """Init Constructor.

        # noqa: DAR101
        """
        super().__init__()
        self.edaQueue = edaqueue
        self.transport = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        """connection_made: Standard for asyncio.

        # noqa: DAR101
        """
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Any) -> None:  # pylint: disable=unsubscriptable-object
        """datagram_received: Standard method for protocol.

        # noqa: DAR101
        """
        asyncio.get_event_loop().create_task(self.datagram_received_async(data, addr))

    async def datagram_received_async(self, indata: Any, addr: Any) -> None:
        """datagram_received_async: Standard method for protocol.

        # noqa: DAR101
        """
        # Syslog event data received, and processed for EDA
        logger = logging.getLogger()
        rcvdata = indata.decode()
        logger.info("Received Syslog message: %s - addr: %s", rcvdata, addr)
        data = parse(rcvdata)

        if data is None:
            # if not CEF, we will try JSON load of the text from first curly brace
            try:
                value = rcvdata[rcvdata.index("{"):len(rcvdata)]
                data = json.loads(value)
            except json.decoder.JSONDecodeError:
                logger.exception("JSON Decode Error")
                data = rcvdata
            except UnicodeError:
                logger.exception("UnicodeError")

        if data:
            queue = self.edaQueue
            await queue.put({"cyberark": data})


async def main(queue: asyncio.Queue, args: dict[str, Any]) -> None:  # pylint: disable=unsubscriptable-object
    """Perform main functionality.

    # noqa: DAR101
    """
    logger = logging.getLogger()

    _ = asyncio.get_event_loop()   # pylint: disable=disallowed-name
    host = args.get("host") or "0.0.0.0"
    port = args.get("port") or 1514
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(   # pylint: disable=disallowed-name
        lambda: SyslogProtocol(queue),
        local_addr=((host, port)))
    logger.info("Starting cyberark.pas.syslog [Host=%s, port=%s]", host, port)
    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        transport.close()


if __name__ == "__main__":

    class MockQueue:
        """simple mock queue."""

        async def put(self, event: Any) -> None:
            """put: Put method.

            # noqa: DAR101
            """

    asyncio.run(main(MockQueue(), {}))
