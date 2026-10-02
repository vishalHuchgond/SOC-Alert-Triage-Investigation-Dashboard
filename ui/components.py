"""Reusable UI components. Every untrusted value is escaped before rendering."""
from __future__ import annotations

from html import escape

from utils.sanitize import escape_html

SEV_COLORS = {"critical": "#DC2626", "high": "#EF4444", "medium": "#F59E0B", "low": "#22C55E"}


def badge(text: str, kind: str | None = None) -> str:
    t = escape_html(text)
    cls = (kind or str(text)).lower().replace(" ", "-").replace("_", "-")
    return f'<span class="badge badge-{cls}">{t}</span>'


def severity_badge(severity: str | None) -> str:
    return badge(severity or "low", (severity or "low").lower())


def status_badge(status: str | None) -> str:
    return badge(status or "New", (status or "New").lower())


def verdict_badge(verdict: str | None) -> str:
    if not verdict:
        return '<span class="soc-muted">Pending</span>'
    kind = {"True Positive": "tp", "False Positive": "fp", "Benign": "benign"}.get(verdict, "info")
    return badge(verdict, kind)


def risk_indicator(score: int | None, band: str | None = None) -> str:
    score = int(score or 0)
    band = band or ("critical" if score >= 90 else "high" if score >= 70
                    else "medium" if score >= 40 else "low")
    color = SEV_COLORS.get(band, "#38BDF8")
    return (f'<div class="risk-bar"><div class="risk-fill" style="width:{min(score,100)}%;'
            f'background:{color}"></div></div>'
            f'<span style="color:{color};font-weight:600">{score}/100 {escape_html(band.upper())}</span>')


def card(title: str, body_html: str) -> str:
    return f'<div class="soc-card"><h3>{escape_html(title)}</h3>{body_html}</div>'


def kv_table(pairs: list[tuple[str, object]]) -> str:
    rows = "".join(
        f"<tr><td style='color:#94A3B8;width:220px'>{escape_html(k)}</td>"
        f"<td>{escape_html(v) if v not in (None, '') else '<span class=soc-muted>-</span>'}</td></tr>"
        for k, v in pairs)
    return f"<table style='width:100%;border-collapse:collapse'>{rows}</table>"


def timeline_html(entries: list[dict]) -> str:
    items = []
    for e in entries:
        desc = escape_html(e.get("description", ""))
        items.append(
            f'<div class="timeline-item"><div class="t-type">{escape_html(e.get("entry_type", ""))}</div>'
            f'<div class="t-time">{escape_html(e.get("event_time") or e.get("recorded_at") or "")}'
            f'{" &middot; recorded " + escape_html(e.get("recorded_at", "")) if e.get("event_time") else ""}</div>'
            f"<div>{desc}</div></div>")
    return "".join(items) or '<div class="empty-state">No timeline entries yet.</div>'


def empty_state(title: str, message: str) -> None:
    import streamlit as st
    st.markdown(f'<div class="empty-state"><h3>{escape_html(title)}</h3>'
                f"<p>{escape_html(message)}</p></div>", unsafe_allow_html=True)


def error_banner(message: str) -> None:
    import streamlit as st
    st.markdown(f'<div class="error-banner">{escape_html(message)}</div>', unsafe_allow_html=True)


def ok_banner(message: str) -> None:
    import streamlit as st
    st.markdown(f'<div class="ok-banner">{escape_html(message)}</div>', unsafe_allow_html=True)


def system_status_html(db_ok: bool, vt_available: bool, vt_configured: bool) -> str:
    vt_color = "dot-ok" if vt_configured else "dot-warn"
    vt_text = "Threat Intel: VirusTotal" if vt_configured else "Threat Intel: local watchlist only"
    return (
        f'<div class="soc-card"><h3>System Status</h3>'
        f'<div><span class="status-dot dot-ok"></span>Detection Engine Online</div>'
        f'<div><span class="status-dot {"dot-ok" if db_ok else "dot-bad"}"></span>'
        f'{"Database Connected" if db_ok else "Database Unavailable"}</div>'
        f'<div><span class="status-dot {vt_color}"></span>{escape_html(vt_text)}</div></div>')


def require_db(store) -> bool:
    import streamlit as st
    if not store.ping():
        error_banner("Database unavailable. Start MongoDB (docker compose up -d mongo) "
                     "and check MONGO_URI in Settings/.env.")
        return False
    return True
