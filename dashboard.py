# dashboard.py
import json
from pathlib import Path

import streamlit as st
import matplotlib.pyplot as plt
import networkx as nx


def load_json(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


st.set_page_config(page_title="Deep Guard Dashboard", layout="wide")
st.title("Deep Guard — Android APK Threat Dashboard")

# -----------------------------
# Inputs
# -----------------------------
with st.sidebar:
    st.header("Inputs")
    ev_path = st.text_input("evidence.json", "out/evidence.json")
    interp_path = st.text_input("interpretation.json", "out/interpretation.json")
    prof_path = st.text_input("threat_profile.json", "out/threat_profile.json")

# -----------------------------
# Load
# -----------------------------
try:
    ev = load_json(ev_path)
    interp = load_json(interp_path)
    prof = load_json(prof_path)
except Exception as e:
    st.error(f"Failed to load input files: {e}")
    st.stop()

e = ev.get("evidence", {})
apk = e.get("apk.info", {})
manifest = e.get("static.manifest", {})

# -----------------------------
# Overview
# -----------------------------
st.subheader("Overview")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Package", apk.get("package_name", "-"))
c2.metric("Version", apk.get("version_name", "-"))
c3.metric("min/target SDK", f"{apk.get('min_sdk','-')}/{apk.get('target_sdk','-')}")
c4.metric("Confidence", prof.get("threat_profile", {}).get("confidence", "-"))

# -----------------------------
# Risk Heatmap (Permissions)
# -----------------------------
st.subheader("Permission Risk Heatmap")

rs = manifest.get("risk_summary", {})
counts = rs.get("counts", {})

fig1 = plt.figure()
plt.bar(["High", "Medium"], [counts.get("high", 0), counts.get("medium", 0)])
plt.title("Permission Risk Distribution")
st.pyplot(fig1)

# -----------------------------
# MITRE Network Graph
# -----------------------------
st.subheader("MITRE ATT&CK Network Graph")

G = nx.Graph()
mitre = interp.get("mitre_mapping", [])

for m in mitre:
    tid = m.get("technique_id", "T????")
    tech = f"{tid}\n{m.get('technique','')}"
    src = m.get("evidence", {}).get("type", "evidence")
    G.add_edge(tech, src)

if G.nodes:
    fig2 = plt.figure(figsize=(10, 6))
    pos = nx.spring_layout(G, seed=42)
    nx.draw(G, pos, with_labels=True, font_size=8)
    st.pyplot(fig2)
else:
    st.info("No MITRE data available.")

# -----------------------------
# Report Download
# -----------------------------
st.subheader("Reports")

pdf_path = Path("out/report.pdf")
md_path = Path("out/report.md")

if pdf_path.exists():
    with open(pdf_path, "rb") as f:
        st.download_button(
            "📄 Download Executive Report (PDF)",
            f,
            file_name="DeepGuard_Report.pdf",
            mime="application/pdf",
        )
elif md_path.exists():
    st.info("PDF not found yet. Markdown report exists.")
else:
    st.warning("No report available yet.")
