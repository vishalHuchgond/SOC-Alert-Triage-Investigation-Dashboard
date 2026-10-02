"""Global dark enterprise SOC theme, injected once from app.py."""
from __future__ import annotations

CSS = """
<style>
:root {
  --bg: #0B1120; --bg2: #111827; --card: #172033; --border: #263247;
  --accent: #38BDF8; --success: #22C55E; --warning: #F59E0B;
  --danger: #EF4444; --critical: #DC2626; --text: #F8FAFC; --muted: #94A3B8;
}
.stApp { background-color: var(--bg); color: var(--text); }
section[data-testid="stSidebar"] { background-color: var(--bg2); border-right: 1px solid var(--border); }
section[data-testid="stSidebar"] .stMarkdown, section[data-testid="stSidebar"] label,
section[data-testid="stSidebar"] { color: var(--text); }
h1, h2, h3 { color: var(--text); font-weight: 600; letter-spacing: 0.2px; }
h1 { font-size: 1.5rem; border-bottom: 1px solid var(--border); padding-bottom: 0.4rem; }
p, li, label, .stMarkdown { color: #CBD5E1; }

div[data-testid="stMetric"] {
  background-color: var(--card); border: 1px solid var(--border);
  border-radius: 10px; padding: 14px 16px; box-shadow: 0 2px 8px rgba(0,0,0,0.35);
}
div[data-testid="stMetric"] label { color: var(--muted) !important; font-size: 0.8rem; }
div[data-testid="stMetric"] div[data-testid="stMetricValue"] { color: var(--text); font-size: 1.6rem; }

.soc-card {
  background-color: var(--card); border: 1px solid var(--border);
  border-radius: 10px; padding: 16px 18px; margin-bottom: 12px;
  box-shadow: 0 2px 8px rgba(0,0,0,0.35);
}
.soc-card h3 { margin-top: 0; font-size: 1rem; color: var(--accent); }
.soc-muted { color: var(--muted); font-size: 0.85rem; }

.badge {
  display: inline-block; padding: 2px 10px; border-radius: 10px;
  font-size: 0.75rem; font-weight: 600; color: #fff; letter-spacing: 0.3px;
}
.badge-critical { background: var(--critical); }
.badge-high { background: var(--danger); }
.badge-medium { background: var(--warning); color: #111; }
.badge-low { background: var(--success); }
.badge-info { background: var(--accent); color: #06202e; }
.badge-new { background: var(--accent); color: #06202e; }
.badge-investigating { background: var(--warning); color: #111; }
.badge-resolved, .badge-contained { background: var(--success); }
.badge-closed { background: #64748B; }
.badge-tp { background: var(--danger); }
.badge-fp { background: var(--success); }
.badge-benign { background: #64748B; }

.risk-bar { height: 8px; border-radius: 4px; background: var(--border); overflow: hidden; margin: 6px 0 2px; }
.risk-fill { height: 100%; border-radius: 4px; }

.timeline-item {
  border-left: 2px solid var(--border); padding: 4px 0 12px 16px; position: relative; margin-left: 8px;
}
.timeline-item::before {
  content: ""; position: absolute; left: -6px; top: 8px; width: 10px; height: 10px;
  border-radius: 50%; background: var(--accent);
}
.timeline-item .t-time { color: var(--muted); font-size: 0.78rem; }
.timeline-item .t-type { color: var(--accent); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.5px; }

.status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
.dot-ok { background: var(--success); } .dot-bad { background: var(--danger); } .dot-warn { background: var(--warning); }

.empty-state {
  border: 1px dashed var(--border); border-radius: 10px; padding: 32px;
  text-align: center; color: var(--muted); background: var(--bg2);
}
.error-banner {
  background: rgba(220,38,38,0.12); border: 1px solid var(--critical);
  color: #FCA5A5; border-radius: 8px; padding: 12px 16px; margin-bottom: 12px;
}
.ok-banner {
  background: rgba(34,197,94,0.10); border: 1px solid var(--success);
  color: #86EFAC; border-radius: 8px; padding: 12px 16px; margin-bottom: 12px;
}
div[data-testid="stDataFrame"] { border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
.stButton > button {
  background-color: var(--card); color: var(--text); border: 1px solid var(--border);
  border-radius: 8px;
}
.stButton > button:hover { border-color: var(--accent); color: var(--accent); }
.sample-tag {
  display: inline-block; background: var(--warning); color: #111; font-size: 0.7rem;
  font-weight: 700; padding: 1px 8px; border-radius: 4px; letter-spacing: 0.5px;
}
</style>
"""


def inject_css() -> None:
    import streamlit as st
    st.markdown(CSS, unsafe_allow_html=True)
