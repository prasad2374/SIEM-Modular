from flask import Flask, request, jsonify
from pymongo import MongoClient
from datetime import datetime

app = Flask(__name__)

# MongoDB Setup
client = MongoClient("mongodb://localhost:27017/")
db = client["siem"]
collection = db["logs"]

@app.route("/upload_log", methods=["POST"])
def upload_log():
    data = request.get_json()

    if not data or 'device_id' not in data or 'logs' not in data:
        return jsonify({"status": "error", "message": "Invalid data"}), 400

    parsed_logs = []
    for event in data['logs']:
        try:
            log = {
                "device_id": data['device_id'],
                "source": event.get("source"),
                "event_id": event.get("event_id"),
                "category": event.get("category"),
                "time_generated": event.get("time_generated"),
                "event_type": event.get("event_type"),
                "message": event.get("message"),
                "timestamp": event.get("timestamp", datetime.utcnow().isoformat())
            }
            parsed_logs.append(log)
        except Exception as e:
            print(f"Failed to parse event: {e}")

    if parsed_logs:
        collection.insert_many(parsed_logs)
        return jsonify({"status": "success", "message": f"{len(parsed_logs)} logs stored successfully"}), 200
    else:
        return jsonify({"status": "error", "message": "No valid logs parsed"}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
