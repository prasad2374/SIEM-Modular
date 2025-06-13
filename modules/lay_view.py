from pymongo import MongoClient
from datetime import datetime

MONGO_URI = "mongodb://localhost:27017/"
client = MongoClient(MONGO_URI)

def construct_layman_sentence(log):
    time = log.get("time_generated", "unknown time")
    source = log.get("source", "unknown source")
    event_id = log.get("event_id", "unknown ID")
    event_type = log.get("event_type", "unknown type")
    category = log.get("category", "unknown category")
    message = log.get("message", "no reason provided")

    result = "failure" if "fail" in str(message).lower() else "success"

    sentence = (
        f"[{time}] | someone from {source} log tried {event_type} ({event_id}) "
        f"in category {category} resulting in {result} due to {message}."
    )

    return {
        "summary": sentence,
        "timestamp": log.get("timestamp", time),
        "Original ID": str(log.get("_id", "")),
        "Processed At": datetime.utcnow().isoformat()
    }

def generate_layman_view():
    siem_logs = client["siem"]["logs"].find()
    layman_logs = [construct_layman_sentence(log) for log in siem_logs]
    if layman_logs:
        client["lay"]["logs"].delete_many({})
        client["lay"]["logs"].insert_many(layman_logs)
    return len(layman_logs)
