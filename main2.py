# main_full_fixed.py
import streamlit as st
import pandas as pd
from modules.db_handler import fetch_logs_from_db, clear_all_logs
from modules.log_ingestion import fetch_windows_event_logs, parse_json_logs, store_logs
from modules.rule_engine import load_rules, apply_rules, detect_chains
from modules.anomaly_detection import detect_anomalies
from modules.search import perform_json_query, perform_keyword_search
from modules import lay_view, offense_manager, llm_assistant, threat_matcher
from pymongo import MongoClient

st.set_page_config(page_title="Unified SIEM Tool", layout="wide")
st.title("🛡️ Unified Python SIEM Tool")

menu = st.sidebar.radio("Menu", ["Upload Logs", "Analyze Logs", "Threat Intelligence", "Offense Tracker", "Layman View", "Search Logs"])

# -------------------- Upload Logs --------------------
if menu == "Upload Logs":
    st.subheader("📥 Upload or Collect Logs")
    mode = st.radio("Log Source", ["Collect from System", "Upload JSON File"])
    if mode == "Collect from System":
        log_type = st.selectbox("Select Log Type", ["System", "Application", "Security"])
        if st.button("Fetch Logs"):
            logs = fetch_windows_event_logs(log_type)
            store_logs(logs, source="siem")
    elif mode == "Upload JSON File":
        json_file = st.file_uploader("Upload Log File", type=["json", "txt", "log"])
        if json_file:
            logs = parse_json_logs(json_file)
            store_logs(logs, source="external")

# -------------------- Analyze Logs --------------------
elif menu == "Analyze Logs":
    st.subheader("📊 Analyze Logs")
    source = st.radio("Log Source", ["siem", "external"])
    logs = fetch_logs_from_db(source)
    if logs:
        df_logs = pd.DataFrame(logs)
        st.markdown("### 🧾 Available Log Fields")
        st.write(df_logs.columns.tolist())

        st.dataframe(df_logs.head(50), use_container_width=True)
        detection_mode = st.radio("Detection Mode", ["Rule-Based", "Behavior-Based"])

        if detection_mode == "Rule-Based":
            from modules.rule_engine import load_rules, apply_rules, detect_chains
            rule_file = st.file_uploader("Upload Rules JSON File", type=["json"])
            if rule_file:
                rules, chain_rules, threshold_overrides = load_rules(rule_file, st)
                apply_rules(df_logs, rules, source, threshold_overrides, st)
                detect_chains(df_logs, chain_rules, st)

        elif detection_mode == "Behavior-Based":
            threshold = st.slider("Z-Score Threshold", 1.0, 5.0, 3.0, step=0.1)
            detect_anomalies(logs, threshold, st)

        st.subheader("🧠 AI Insights")
        alert_logs = [log for log in logs if log.get("alert") or log.get("rule_triggered") or log.get("anomaly_score")]
        if alert_logs:
            insights = llm_assistant.generate_insight_from_logs(alert_logs[:50])
            st.text_area("AI Summary (Alerts Only)", insights, height=200)
        else:
            st.info("No alerts detected for AI analysis.")

# -------------------- Threat Intelligence --------------------
elif menu == "Threat Intelligence":
    st.subheader("🔍 Threat Intelligence Feeds")
    feed_file = st.file_uploader("Upload IOC Feed (JSON/CSV)", type=["json", "csv", "txt"])
    if feed_file:
        try:
            iocs = threat_matcher.load_ioc_feed(feed_file)
            threat_matcher.update_ioc_store(iocs)
            st.success("IOC feed loaded.")
        except Exception as e:
            st.error(str(e))

    if st.button("Load Sample AlienVault Feed"):
        try:
            import requests
            response = requests.get("https://raw.githubusercontent.com/cs-uob/alienvault-reputation-data/master/reputation.data")
            lines = response.text.splitlines()
            iocs = {"ips": set(), "domains": set(), "hashes": set()}
            for line in lines:
                if line.strip() and not line.startswith("#"):
                    parts = line.split("\t")
                    if parts:
                        iocs["ips"].add(parts[0].strip())
            threat_matcher.update_ioc_store(iocs)
            st.success("AlienVault feed loaded.")
            st.write("Sample IOCs:", list(iocs["ips"])[:10])
        except Exception as e:
            st.error(f"Feed load error: {e}")

    source = st.radio("Select Log Source", ["siem", "external"])
    logs = fetch_logs_from_db(source)
    if logs:
        alerts = threat_matcher.ioc_match_analysis(logs)
        threat_matcher.render_ioc_alerts(alerts, st)
    else:
        st.warning("No logs to match against.")

# -------------------- Offense Tracker --------------------
elif menu == "Offense Tracker":
    st.subheader("🛡️ Offense Tracker")
    logs = fetch_logs_from_db("siem") + fetch_logs_from_db("external")
    offenses = offense_manager.list_offenses()

    if st.button("Create Sample Offense"):
        offense_manager.create_offense(
            name="Test Brute Force Attack",
            related_logs=[{"event_id": 4625, "message": "Failed login attempt"}],
            notes="Example offense"
        )
        st.success("Sample offense created.")

    if offenses:
        for off in offenses:
            with st.expander(f"🛡️ {off['name']} [{off['status']}] — {off['id'][:8]}"):
                st.write(f"Created: {off['created_at']}")
                st.write(f"Assigned to: {off['assigned_to'] or 'Unassigned'}")
                st.write(f"Notes: {off['notes']}")

                new_status = st.selectbox("Status", ["Open", "Investigating", "Closed"], index=["Open", "Investigating", "Closed"].index(off["status"]), key=f"status_{off['id']}")
                new_user = st.text_input("Assign To", value=off["assigned_to"], key=f"analyst_{off['id']}")
                new_notes = st.text_area("Notes", value=off["notes"], key=f"notes_{off['id']}")

                if st.button(f"Update {off['id']}", key=f"update_{off['id']}"):
                    offense_manager.update_offense(off["id"], new_status, new_user, new_notes)
                    st.success("Offense updated.")

                st.json(off["logs"])
                if st.button(f"🧠 AI Insight for {off['id']}", key=f"ai_{off['id']}"):
                    insight = llm_assistant.generate_insight_from_logs(off["logs"])
                    st.text_area("AI Summary", insight, height=200, key=f"summary_{off['id']}")
    else:
        st.info("No offenses found.")

# -------------------- Layman View --------------------
elif menu == "Layman View":
    st.subheader("📋 Layman View")
    lay_logs = fetch_logs_from_db("lay")
    if lay_logs:
        for log in lay_logs:
            st.markdown(f"- {log.get('summary', '[No Summary]')}")
        st.success(f"{len(lay_logs)} layman logs loaded.")

        if st.button("🧠 AI Insights from Layman Logs"):
            insight = llm_assistant.generate_insight_from_logs(lay_logs[:50])
            st.text_area("Layman AI Summary", insight, height=200)
    else:
        st.warning("No layman logs found.")

# -------------------- Search Logs --------------------
elif menu == "Search Logs":
    st.subheader("🔎 Search Logs")
    db = st.radio("Source", ["siem", "external", "lay"])
    mode = st.radio("Mode", ["Structured JSON Query", "Keyword Search"])
    if mode == "Structured JSON Query":
        perform_json_query(db, st)
    elif mode == "Keyword Search":
        perform_keyword_search(db, st)

# -------------------- Admin Tools --------------------
st.sidebar.subheader("🧹 Admin Tools")
if st.sidebar.button("Clear All Logs"):
    clear_all_logs(st)

if st.sidebar.button("Clear Layman Logs"):
    client = MongoClient("mongodb://localhost:27017/")
    client["lay"]["logs"].delete_many({})
    st.sidebar.success("Layman logs cleared.")

if st.sidebar.button("Generate Layman View"):
    count = lay_view.generate_layman_view()
    st.sidebar.success(f"{count} layman logs generated.")
