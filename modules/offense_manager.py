import uuid
from datetime import datetime

# In-memory offense list (can later be persisted in DB)
OFFENSES = []

def create_offense(name, related_logs, assigned_to="", status="Open", notes=""):
    offense = {
        "id": str(uuid.uuid4()),
        "name": name,
        "created_at": datetime.utcnow().isoformat(),
        "status": status,
        "assigned_to": assigned_to,
        "notes": notes,
        "logs": related_logs,
    }
    OFFENSES.append(offense)
    return offense

def list_offenses():
    return OFFENSES

def update_offense(offense_id, status=None, assigned_to=None, notes=None):
    for offense in OFFENSES:
        if offense["id"] == offense_id:
            if status:
                offense["status"] = status
            if assigned_to is not None:
                offense["assigned_to"] = assigned_to
            if notes is not None:
                offense["notes"] = notes
            return offense
    return None

def get_offense_by_id(offense_id):
    for offense in OFFENSES:
        if offense["id"] == offense_id:
            return offense
    return None