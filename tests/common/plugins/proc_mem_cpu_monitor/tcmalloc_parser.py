# -*- coding: utf-8 -*-
"""Parse FRR ``show tcmalloc stats`` output from the BGP docker."""
from __future__ import annotations

import re
from typing import Any, Dict, List

_BLOCK_HEADER = re.compile(r"^tcmalloc statistics for (\w+):", re.MULTILINE)
_HEAP_SIZE = re.compile(r"^generic\.heap_size:\s*(\d+)\s*$", re.MULTILINE)
_PAGEHEAP_FREE = re.compile(r"^tcmalloc\.pageheap_free_bytes:\s*(\d+)\s*$", re.MULTILINE)


def parse_tcmalloc_stats(stdout: str) -> List[Dict[str, Any]]:
    """
    Parse ``vtysh -c "show tcmalloc stats"`` output.

    Returns one dict per daemon block with keys:
        process, heap_size_bytes, pageheap_free_bytes
    """
    if not stdout or not stdout.strip():
        return []

    text = stdout.strip()
    if not text.startswith("tcmalloc statistics for "):
        idx = text.find("\ntcmalloc statistics for ")
        if idx >= 0:
            text = text[idx + 1 :]  # noqa: E203

    parts = re.split(r"(?=^tcmalloc statistics for \w+:)", text, flags=re.MULTILINE)
    rows: List[Dict[str, Any]] = []
    for block in parts:
        block = block.strip()
        if not block:
            continue
        hdr = _BLOCK_HEADER.search(block)
        if not hdr:
            continue
        heap_m = _HEAP_SIZE.search(block)
        free_m = _PAGEHEAP_FREE.search(block)
        if heap_m is None or free_m is None:
            continue
        rows.append(
            {
                "process": hdr.group(1),
                "heap_size_bytes": int(heap_m.group(1)),
                "pageheap_free_bytes": int(free_m.group(1)),
            }
        )
    return rows
