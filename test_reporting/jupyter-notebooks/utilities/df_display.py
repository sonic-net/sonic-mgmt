from __future__ import annotations

from typing import Optional

import pandas as pd
from IPython.display import HTML

_DEFAULT_STYLE = """
<style>
  .scrollwrap {
    width: 100%;
    max-width: 100%;
    overflow-x: auto;
    overflow-y: auto;
    max-height: 420px;          /* vertical scroll */
    border: 1px solid #444;
    border-radius: 6px;
  }
  .scrollwrap table {
    border-collapse: collapse;
    width: max-content;         /* allow wider-than-cell tables */
    min-width: 100%;
  }
  .scrollwrap th, .scrollwrap td {
    padding: 6px 10px;
    border-bottom: 1px solid #333;
    white-space: nowrap;        /* one-line cells; horizontal scroll */
    text-align: left;
    vertical-align: top;
  }
  .scrollwrap thead th {
    position: sticky;
    top: 0;
    background: #1e1e1e;
    z-index: 1;
  }
</style>
"""


def scrollable_table(
    df: pd.DataFrame,
    *,
    max_rows: Optional[int] = 50,
    max_height_px: int = 420,
    escape: bool = True,
    show_index: bool = False,
) -> HTML:
    """
    Render a DataFrame as a scrollable HTML table (horizontal + vertical scroll).

    - Uses df.to_html() to avoid VS Code's DataFrame grid viewer.
    - max_rows: show first N rows (None => all rows)
    - max_height_px: vertical scroll container height
    - escape: True => HTML-escape cell values (safer). Set False only if you trust content.
    """
    if df is None:
        return HTML("<i>None</i>")

    if max_rows is not None:
        df = df.head(max_rows)

    # Ensure predictable string rendering for object columns (esp. long messages)
    df = df.copy()
    for c in df.columns:
        if df[c].dtype == "object":
            df[c] = df[c].astype(str)

    table_html = df.to_html(index=show_index, escape=escape)

    style = _DEFAULT_STYLE.replace("max-height: 420px", f"max-height: {int(max_height_px)}px")
    return HTML(f"""
    {style}
    <div class="scrollwrap">
      {table_html}
    </div>
    """)
