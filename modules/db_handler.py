from pymongo import MongoClient

MONGO_URI = "mongodb://localhost:27017/"
client = MongoClient(MONGO_URI)

def fetch_logs_from_db(source="siem"):
    db = client[source]
    return list(db["logs"].find({}, {"_id": 0}))

def clear_all_logs(st):
    try:
        client["siem"]["logs"].delete_many({})
        client["external"]["logs"].delete_many({})
        st.success("Cleared logs in 'siem.logs' and 'external.logs'")
    except Exception as e:
        st.error(f"Failed to clear logs: {e}")
