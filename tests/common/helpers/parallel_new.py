import concurrent.futures
import logging
import traceback
from datetime import datetime
from typing import Callable, List, Any, Dict, Optional

import pytest

logger = logging.getLogger(__name__)


def _wrap_target(target: Callable, node: Any, *args, **kwargs):
    try:
        kwargs = kwargs.copy()
        kwargs['node'] = node
        return target(*args, **kwargs)
    except Exception as e:
        return {
            'node': str(node),
            'exception': str(e),
            'traceback': traceback.format_exc()
        }


def parallel_run(
        target: Callable,
        args: tuple,
        kwargs: dict,
        nodes: List[Any],
        timeout: Optional[int] = None,
        concurrent_tasks: int = 24
) -> Dict:
    start_time = datetime.now()
    logger.info(f"[chunangli]Running '{target.__name__}' on {len(nodes)} nodes with timeout={timeout}")

    results = {}
    errors = []

    with concurrent.futures.ProcessPoolExecutor(max_workers=concurrent_tasks) as executor:
        future_to_node = {
            executor.submit(_wrap_target, target, node, *args, **kwargs): node
            for node in nodes
        }

        try:
            for future in concurrent.futures.as_completed(future_to_node, timeout=timeout):
                node = future_to_node[future]
                result = future.result()
                if isinstance(result, dict) and 'exception' in result:
                    errors.append(result)
                    results[str(node)] = {'failed': True}
                else:
                    results[str(node)] = result
        except concurrent.futures.TimeoutError:
            logger.error("Timeout reached. Cancelling unfinished tasks.")
            for future in future_to_node:
                future.cancel()
            raise RuntimeError("Parallel run timed out.")

    if errors:
        for err in errors:
            logger.error(f"Error on node {err['node']}:\n{err['exception']}\n{err['traceback']}")
        # raise RuntimeError(f"{len(errors)} task(s) failed during parallel run.")
        logger.info("[chunangli] pytest fail since errors catched.")
        pytest.fail(errors)

    end_time = datetime.now()
    logger.info(f"[chunangli]Completed in {(end_time - start_time).total_seconds()} seconds")

    return results
