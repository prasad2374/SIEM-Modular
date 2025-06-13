import json
import pandas as pd
from pymongo import MongoClient

MONGO_URI = "mongodb://localhost:27017/"
client = MongoClient(MONGO_URI)

def perform_json_query(search_db, st):
    db = client[search_db]
    collection = db["logs"]
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

def perform_keyword_search(search_db, st):
    db = client[search_db]
    collection = db["logs"]
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
