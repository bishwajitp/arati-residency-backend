from datetime import datetime, timezone, date

from bson import ObjectId


def to_serializable(v):
    if isinstance(v, ObjectId):
        return str(v)
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    return v


def compute_changes(before, after):
    b = before or {}
    a = after or {}
    fields = set(b.keys()) | set(a.keys())
    fields.discard("_id")
    fields.discard("password")
    changes = []
    for field in sorted(fields):
        old = to_serializable(b.get(field))
        new = to_serializable(a.get(field))
        if old != new:
            changes.append({"field": field, "old": old, "new": new})
    return changes


async def log_audit(db, *, screen, action, entity, entity_id, changes, user):
    await db.audit_logs.insert_one(
        {
            "screen": screen,
            "action": action,  # create | update | delete
            "entity": entity,
            "entity_id": entity_id,
            "changes": changes,
            "user_id": str(user["_id"]) if user else None,
            "username": user.get("username") if user else None,
            "timestamp": datetime.now(timezone.utc),
        }
    )