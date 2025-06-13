import json
import re
import pandas as pd

# Global in-memory IOC store (can be extended to MongoDB)
IOC_FEEDS = {
    "ips": set(),
    "domains": set(),
    "hashes": set()
}

def load_ioc_feed(uploaded_file):
    try:
        content = uploaded_file.read().decode("utf-8")
        if uploaded_file.name.endswith(".json"):
            data = json.loads(content)
            return {
                "ips": set(data.get("ips", [])),
                "domains": set(data.get("domains", [])),
                "hashes": set(data.get("hashes", []))
            }
        else:  # Assume CSV-style format: type,value
            lines = content.strip().split("\n")
            iocs = {"ips": set(), "domains": set(), "hashes": set()}
            for line in lines:
                if "," in line:
                    ioc_type, value = line.split(",", 1)
                    if ioc_type in iocs:
                        iocs[ioc_type].add(value.strip())
            return iocs
    except Exception as e:
        raise ValueError(f"Error loading IOC feed: {e}")

def update_ioc_store(new_iocs):
    for key in IOC_FEEDS:
        IOC_FEEDS[key].update(new_iocs.get(key, set()))

def match_log_against_iocs(log):
    matched = []
    log_str = json.dumps(log).lower()
    for ip in IOC_FEEDS["ips"]:
        if ip in log_str:
            matched.append(("IP", ip))
    for dom in IOC_FEEDS["domains"]:
        if dom in log_str:
            matched.append(("Domain", dom))
    for hsh in IOC_FEEDS["hashes"]:
        if hsh in log_str:
            matched.append(("Hash", hsh))
    return matched

def ioc_match_analysis(logs):
    alerts = []
    for log in logs:
        matches = match_log_against_iocs(log)
        if matches:
            alerts.append({
                "timestamp": log.get("timestamp", "N/A"),
                "log": log,
                "matches": matches
            })
    return alerts

def render_ioc_alerts(alerts, st):
    if not alerts:
        st.success("✅ No IOC matches found in current logs.")
        return

    st.subheader("🚨 IOC Matches Detected")
    for alert in alerts:
        st.error(f"Match at {alert['timestamp']} with IOCs: {', '.join(f'{t}:{v}' for t, v in alert['matches'])}")
        st.json(alert["log"])