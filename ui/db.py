"""Streamlit-cached MongoDB store handle."""
from __future__ import annotations

import streamlit as st

from database.mongodb import MongoStore


@st.cache_resource
def get_store() -> MongoStore:
    try:
        return MongoStore().init()
    except Exception:
        return MongoStore()
