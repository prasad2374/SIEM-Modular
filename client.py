import requests
import json
import win32evtlog
import time
import socket

def fetch_windows_event_logs(log_type="System", max_events=50):
    server = 'localhost'
    try:
        hand = win32evtlog.OpenEventLog(server, log_type)
        events = win32evtlog.ReadEventLog(
            hand,
            win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
            0
        )
    except Exception as e:
        print(f"Error opening log '{log_type}': {e}")
        return []

    logs = []
    for event in events[:max_events]:
        try:
            log = {
                "log_type": log_type,
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
            print(f"Failed to parse {log_type} event: {e}")
    return logs

def send_logs():
    SERVER_URL = "http://192.168.136.146:5000/upload_log"  # Replace with actual server IP
    hostname = socket.gethostname()

    system_logs = fetch_windows_event_logs("System", 50)
    application_logs = fetch_windows_event_logs("Application", 50)
    security_logs = fetch_windows_event_logs("Security", 50)

    all_logs = system_logs + application_logs + security_logs

    log_data = {
        "device_id": hostname,
        "logs": all_logs
    }

    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(SERVER_URL, data=json.dumps(log_data), headers=headers)
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Logs sent: {len(all_logs)}")
        print("Server response:", response.text)
    except requests.exceptions.RequestException as e:
        print("Failed to send logs:", e)

# Main loop
if __name__ == "__main__":
    print("Starting log collector. Press Ctrl+C to stop.")
    try:
        while True:
            send_logs()
            time.sleep(60)  # Wait 1 minute
    except KeyboardInterrupt:
        print("\nLog collection stopped by user.")
