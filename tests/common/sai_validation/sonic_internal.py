import logging
import queue
import threading

from tests.common.sai_validation import client as gnmi_client


logger = logging.getLogger(__name__)


def run_subscription(key_pattern: str,
                     gnmi_conn,
                     origin: str,
                     mode: int,
                     recursive: bool,
                     stop_event: threading.Event,
                     event_queue: queue.Queue):

    logger.debug(f'run_subscription: {key_pattern}, origin={origin}, mode={mode}')
    gnmi_client.subscribe_gnmi(stub=gnmi_conn, paths=[key_pattern],
                               subscription_mode=mode,
                               origin=origin,
                               watch_subtrees=recursive,
                               stop_event=stop_event,
                               event_queue=event_queue)
