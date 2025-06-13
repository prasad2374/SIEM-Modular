import json
from datetime import datetime
import win32evtlog
from pymongo import MongoClient
import streamlit as st

MONGO_URI = "mongodb://localhost:27017/"
client = MongoClient(MONGO_URI)

def fetch_windows_event_logs(log_type="System", max_events=100):
    server = 'localhost'
    hand = win32evtlog.OpenEventLog(server, log_type)
    events = win32evtlog.ReadEventLog(
        hand,
        win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
        0
    )

    logs = []
    for event in events[:max_events]:
        try:
            log = {
                "source": event.SourceName,
                "event_id": event.EventID,
                "category": event.EventCategory,
                "time_generated": event.TimeGenerated.Format(),
                "event_type": event.EventType,
                "message": str(event.StringInserts),
                "timestamp": event.TimeGenerated.Format()
            }
            logs.append(log)
        except Exception as e:
            print(f"Failed to parse event: {e}")
    return logs

def parse_json_logs(uploaded_file):
    content = uploaded_file.read()
    try:
        logs = json.loads(content)
        if isinstance(logs, dict):
            logs = [logs]
    except:
        lines = content.decode("utf-8").splitlines()
        logs = [json.loads(line) if line.startswith("{") else {"raw": line} for line in lines]
    for log in logs:
        if "timestamp" not in log:
            log["timestamp"] = datetime.utcnow().isoformat()
    return logs

def store_logs(logs, source="siem"):
    if not logs:
        return
    db = client[source]
    collection = db["logs"]
    collection.insert_many(logs)
    st.success(f"{len(logs)} logs stored in '{source}.logs'")