"""CSV parsing for Windows event, Sysmon, PowerShell and firewall exports."""
from __future__ import annotations

import io

import pandas as pd

from parser.normalizer import normalize_record

_FORMAT_OF = {
    "windows_csv": "windows_csv",
    "sysmon_csv": "sysmon_csv",
    "powershell_csv": "powershell_csv",
    "firewall_csv": "firewall_csv",
}


def parse_csv(content: bytes, fmt: str, file_hash: str, max_rows: int) -> tuple[list[dict], int]:
    """Parse CSV bytes -> (normalized events, malformed_row_count). Never raises."""
    text = None
    for enc in ("utf-8", "latin-1"):
        try:
            text = content.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        return [], 0

    try:
        df = pd.read_csv(io.StringIO(text), dtype=str, on_bad_lines="skip",
                         keep_default_na=False, nrows=max_rows)
    except pd.errors.ParserError:
        return [], 0

    events, malformed = [], 0
    for i, (_, row) in enumerate(df.iterrows(), start=2):  # +1 for header
        record = {k: v for k, v in row.to_dict().items() if str(v).strip() != ""}
        raw = ",".join(str(v) for v in record.values())
        try:
            events.append(normalize_record(record, _FORMAT_OF[fmt], file_hash, i, raw))
        except Exception:
            malformed += 1
    return events, malformed
