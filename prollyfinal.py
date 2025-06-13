import streamlit as st
from pymongo import MongoClient
import pandas as pd
import json
import re   
from datetime import datetime, timedelta
import win32evtlog
from collections import defaultdict

# -------------------- MongoDB Setup ---------------------
MONGO_URI = "mongodb://localhost:27017/"
client = MongoClient(MONGO_URI)

# -------------------- Load Rules ------------------------
def load_rules(rule_file):
    try:    
        return json.load(rule_file)
    except Exception as e:
        st.error(f"Failed to load rules: {e}")
        return []

# -------------------- Parse Windows Event Logs -----------
def fetch_windows_event_logs(log_type="System", max_events=100):
    server = 'localhost'
    hand = win32evtlog.OpenEventLog(server, log_type)
    total = win32evtlog.GetNumberOfEventLogRecords(hand)
    logs = []
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(hand, flags, 0)

    for event in events[:max_events]:
        try:
            log = {
                "source": event.SourceName,
                "event_id": event.EventID,
                "category": event.EventCategory,
                "time_generated": event.TimeGenerated.Format(),
                "event_type": event.EventType,
                "message": str(event.StringInserts),
            }
            log["timestamp"] = log["time_generated"]
            logs.append(log)
        except Exception as e:
            print(f"Failed to parse event: {e}")
    return logs

# ------------------ Parse JSON Logs ----------------------
def parse_json_logs(uploaded_file):
    content = uploaded_file.read()
    try:
        logs = json.loads(content)
        if isinstance(logs, dict): logs = [logs]
    except:
        lines = content.decode("utf-8").splitlines()
        logs = [json.loads(line) if line.startswith("{") else {"raw": line} for line in lines]
    for log in logs:
        if "timestamp" not in log:
            log["timestamp"] = datetime.utcnow().isoformat()
    return logs

# ------------------ Store/Retrieve -----------------------
def store_logs(logs, source="siem"):
    if not logs:
        return
    db = client[source]
    collection = db["logs"]
    collection.insert_many(logs)
    st.success(f"{len(logs)} logs stored in '{source}.logs'")

def fetch_logs_from_db(source="siem"):
    db = client[source]
    return list(db["logs"].find({}, {"_id": 0}))

# -------------------- Rule Matching ----------------------
def match_rules(logs, rules):
    alerts = []
    for log in logs:
        for rule in rules:
            match = True
            for key, value in rule["match"].items():
                if key not in log or not re.search(value, str(log[key]), re.IGNORECASE):
                    match = False
                    break
            if match:
                alerts.append({
                    "timestamp": log.get("timestamp", "N/A"),
                    "alert": rule["name"],
                    "description": rule.get("description", ""),
                    "log": log
                })
    return alerts

# ------------------ Behavior-Based Anomaly Detection ------------------
def extract_feature_matrix(logs, feature="hour"):
    df = pd.DataFrame(logs)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce', utc=True)
    df = df.dropna(subset=["timestamp"])
    df["hour"] = df["timestamp"].dt.hour
    counts = df["hour"].value_counts().sort_index()
    full_range = pd.Series([0]*24, index=range(24))
    full_range.update(counts)
    return full_range

def calculate_z_scores(data_series):
    mean = data_series.mean()
    std = data_series.std()
    if std == 0: std = 1e-6
    return (data_series - mean) / std

def detect_anomalies(logs, z_threshold=3):
    freq_series = extract_feature_matrix(logs)
    z_scores = calculate_z_scores(freq_series)
    anomalies = z_scores[abs(z_scores) > z_threshold]
    return anomalies, freq_series, z_scores

# -------------------- Rule Engine: Matching, Threshold, Grouping, Alerts ------------------

def parse_time_window(window_str):
    units = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
    try:
        num = int(window_str[:-1])
        unit = units[window_str[-1]]
    except Exception:
        raise ValueError(f"Invalid time window format: {window_str}")
    return timedelta(**{unit: num})

def filter_time_window(df, col, window_str):
    now = pd.Timestamp.utcnow()
    delta = parse_time_window(window_str)
    window_start = now - delta
    df[col] = pd.to_datetime(df[col], utc=True, errors='coerce')
    filtered_df = df[df[col] >= window_start]
    return filtered_df

def apply_match_pattern(df, pattern):
    for k, v in pattern.items():
        if k not in df.columns:
            return pd.DataFrame()
        df = df[df[k].astype(str) == str(v)]
        if df.empty:
            return df
    return df

def group_and_aggregate(df, group_by, threshold):
    if isinstance(group_by, str):
        group_by = [group_by]
    grouped = df.groupby(group_by).size().reset_index(name="count")
    filtered_grouped = grouped[grouped["count"] >= threshold]
    return filtered_grouped

def display_alert(st, rule, count, group_val=None):
    group_info = f"\n🧍 Group: `{group_val}`" if group_val else ""
    severity = rule.get("action", {}).get("severity", "medium")
    message = rule.get("action", {}).get("message", "")
    stride = rule.get("stride", "Unknown")
    dread = rule.get("dread", {})
    dread_score = sum(dread.values()) / 5 if dread else "N/A"

    st.error(f"""
🚨 **{rule['name']}**  
🆔 Rule ID: `{rule['rule_id']}`  
🔥 Severity: **{severity}**  
💬 {message}  
🧮 Count: **{count}**{group_info}  
🛡 STRIDE: `{stride}`  
📊 DREAD Score: `{dread_score}`
""")

def apply_rules(df, rules, log_source, threshold_overrides):
    st.subheader("⚠️ Alerts")
    alerts_found = False

    for rule in rules:
        if rule.get("log_source") != log_source:
            continue

        df_copy = df.copy()
        df_copy = apply_match_pattern(df_copy, rule.get("match_pattern", {}))
        if df_copy.empty:
            continue

        if "time_window" in rule:
            df_copy = filter_time_window(df_copy, "timestamp", rule["time_window"])
            if df_copy.empty:
                continue

        threshold = threshold_overrides.get(rule["rule_id"], rule.get("threshold", 1))

        if "group_by" in rule:
            grouped_df = group_and_aggregate(df_copy, rule["group_by"], threshold)
            for _, row in grouped_df.iterrows():
                count = row["count"]
                group_cols = rule["group_by"] if isinstance(rule["group_by"], list) else [rule["group_by"]]
                group_val = ", ".join(str(row[col]) for col in group_cols)
                display_alert(st, rule, count, group_val)
                alerts_found = True
        else:
            if len(df_copy) >= threshold:
                display_alert(st, rule, len(df_copy))
                alerts_found = True

    if not alerts_found:
        st.success("✅ No alerts triggered.")

# ------------------- Chain of Events Detection -----------------------

def detect_chains(df, chain_rules):
    st.subheader("🔗 Chain of Events Alerts")
    chains_triggered = False
    for chain in chain_rules:
        chain_name = chain.get("name", "Unnamed Chain")
        events = chain.get("events", [])
        min_occurrences = chain.get("min_occurrences", 1)
        matched = True
        for evt in events:
            matched_df = apply_match_pattern(df, evt)
            if matched_df.empty:
                matched = False
                break
        if matched:
            st.warning(f"⚠️ Chain Alert: **{chain_name}** triggered by sequence of matching events.")
            chains_triggered = True
    if not chains_triggered:
        st.success("✅ No chain of event alerts triggered.")

# -------------------- Streamlit UI ----------------------
st.set_page_config(page_title="Unified SIEM Tool", layout="wide")
st.title("\U0001F6E1️ Unified Python SIEM Tool (EVTX + JSON + MongoDB + Anomaly)")

menu = st.sidebar.radio("Menu", ["Upload Logs", "Analyze Logs", "Search Logs"])

# ------------------- Uploading Logs ---------------------
if menu == "Upload Logs":
    st.subheader("\U0001F4E5 Upload or Collect Logs")
    mode = st.radio("Select Log Source", ["Collect from System", "Upload JSON File"])

    if mode == "Collect from System":
        log_choice = st.selectbox("Choose Log Type", ["System", "Application", "Security"])
        if st.button("Fetch Logs"):
            logs = fetch_windows_event_logs(log_choice)
            store_logs(logs, source="siem")

    elif mode == "Upload JSON File":
        json_file = st.file_uploader("Upload JSON/TXT/LOG", type=["json", "log", "txt"])
        if json_file:
            logs = parse_json_logs(json_file)
            store_logs(logs, source="external")

# -------------------- Analyze Logs ----------------------
elif menu == "Analyze Logs":
    st.subheader("\U0001F4CA Analyze Logs from MongoDB")
    source_db = st.radio("Select Log Source to Analyze", ["siem", "external"])
    logs = fetch_logs_from_db(source_db)
    st.write(f"Total logs in '{source_db}.logs': {len(logs)}")

    if logs:
        df_logs = pd.DataFrame(logs)
        st.dataframe(df_logs.head(100), use_container_width=True)

        detection_mode = st.radio("Select Detection Mode", ["Rule-Based", "Behavior-Based"])

        if detection_mode == "Rule-Based":
            rule_file = st.file_uploader("Upload Rules JSON File", type=["json"])
            if rule_file:
                rule_data = load_rules(rule_file)
                rules = rule_data.get("rules", []) if isinstance(rule_data, dict) else rule_data
                chain_rules = rule_data.get("chains", []) if isinstance(rule_data, dict) else []

                threshold_overrides = {}
                st.sidebar.header("Rule Threshold Overrides")
                for rule in rules:
                    if "threshold" in rule:
                        default = rule["threshold"]
                        threshold_overrides[rule["rule_id"]] = st.sidebar.slider(
                            f"{rule['name']} (ID: {rule['rule_id']})",
                            min_value=1,
                            max_value=20,
                            value=default,
                            step=1
                        )
                log_type_guess = st.selectbox("Select Log Source Type for Rules", ["auth_logs", "network_logs", "siem_logs"])
                apply_rules(df_logs, rules, log_type_guess, threshold_overrides)
                detect_chains(df_logs, chain_rules)

        elif detection_mode == "Behavior-Based":
            st.subheader("\U0001F4C8 Behavioral Anomaly Detection (Z-score)")
            
            z_threshold = st.slider("Z-score Threshold", min_value=1.0, max_value=5.0, value=3.0, step=0.1)

            anomalies, freq, z_scores = detect_anomalies(logs, z_threshold)

            st.write("Log counts by hour (UTC):")
            st.bar_chart(freq)

            st.write("Z-scores by hour:")
            st.bar_chart(z_scores)

            if not anomalies.empty:
                st.error(f"Anomalies detected at hours: {list(anomalies.index)}")
                for hour, score in anomalies.items():
                    st.write(f"Hour {hour}: Z-score = {score:.2f}")
                
                df_logs["timestamp"] = pd.to_datetime(df_logs["timestamp"], errors='coerce', utc=True)
                df_anomalous_logs = df_logs[df_logs["timestamp"].dt.hour.isin(anomalies.index)]

                st.subheader("🚨 Logs During Anomalous Hours")
                if not df_anomalous_logs.empty:
                    st.dataframe(df_anomalous_logs, use_container_width=True)
                else:
                    st.info("No logs found during anomalous hours.")
            else:
                st.success("✅ No behavioral anomalies detected.")

# -------------------- Search Logs -----------------------
elif menu == "Search Logs":
    st.subheader("\U0001F50D Search Logs in MongoDB")
    search_db = st.radio("Select Log Source", ["siem", "external"])
    db = client[search_db]
    collection = db["logs"]

    search_mode = st.radio("Search Mode", ["Structured JSON Query", "Keyword Search"])

    if search_mode == "Structured JSON Query":
        query = st.text_area("Enter MongoDB query as JSON", value='{}')
        if st.button("Search JSON"):
            try:
                query_dict = json.loads(query)
                results = list(collection.find(query_dict, {"_id": 0}))
                if results:
                    st.success(f"Found {len(results)} matching logs.")
                    df_results = pd.DataFrame(results)
                    st.dataframe(df_results, use_container_width=True)
                else:
                    st.warning("No matching logs found.")
            except Exception as e:
                st.error(f"Invalid query: {e}")

    elif search_mode == "Keyword Search":
        keyword = st.text_input("Enter keyword to search in logs:")
        if st.button("Search Keyword"):
            if keyword.strip() == "":
                st.warning("Please enter a keyword.")
            else:
                regex = {"$regex": keyword, "$options": "i"}
                or_query = [{"message": regex}, {"source": regex}, {"event_id": regex}]
                results = list(collection.find({"$or": or_query}, {"_id": 0}))
                if results:
                    st.success(f"Found {len(results)} matching logs.")
                    df_results = pd.DataFrame(results)
                    st.dataframe(df_results, use_container_width=True)
                else:
                    st.warning("No logs matched that keyword.")


# -------------------- Admin Tools -----------------------
st.sidebar.subheader("🧹 Admin Tools")

if st.sidebar.button("Clear All Logs"):
    try:
        client["siem"]["logs"].delete_many({})
        client["external"]["logs"].delete_many({})
        st.sidebar.success("Cleared logs in 'siem.logs' and 'external.logs'")
    except Exception as e:
        st.sidebar.error(f"Failed to clear logs: {e}")
