from datetime import datetime, timedelta, timezone
from typing import List, Optional

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import audit
from auth import create_token, get_current_user, hash_password, require_admin, verify_password
from database import get_db
from schemas import (
    Collection,
    CollectionIn,
    Contact,
    ContactIn,
    Event,
    EventIn,
    Expense,
    ExpenseIn,
    Flat,
    FlatDetailsUpdate,
    FlatIn,
    LoginIn,
    ProfileUpdate,
    RoleUpdate,
    SignupIn,
    SettingsIn,
    Token,
    User,
)

app = FastAPI(title="Arati Residency Maintenance API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def serialize_id(doc):
    if doc is None:
        return None
    doc["id"] = str(doc["_id"])
    del doc["_id"]
    return doc


@app.on_event("startup")
async def startup():
    db = get_db()
    await db.flats.create_index("flat_no", unique=True)
    await db.users.create_index("username", unique=True)
    await db.collections.create_index([("month", 1), ("flat_id", 1)], unique=True)


# -------------------------- Auth --------------------------

@app.post("/api/auth/signup", response_model=Token, status_code=201)
async def signup(data: SignupIn):
    db = get_db()
    if data.type not in ("owner", "tenant"):
        raise HTTPException(400, "Type must be 'owner' or 'tenant'")

    # Validate flat against available flats.
    valid_flat_nos = {f["flat_no"] for f in await db.flats.find().to_list(length=100)}
    if data.flat not in valid_flat_nos:
        raise HTTPException(400, "Selected flat is not available")

    # Unique phone.
    if await db.users.find_one({"phone": data.phone.strip()}):
        raise HTTPException(400, "Phone number is already registered")

    user_count = await db.users.count_documents({})
    role = "superadmin" if user_count == 0 else "user"
    user = {
        "username": data.username.strip(),
        "password": hash_password(data.password),
        "name": data.name.strip(),
        "phone": data.phone.strip(),
        "flat": data.flat.strip(),
        "type": data.type,
        "role": role,
    }
    try:
        result = await db.users.insert_one(user)
    except Exception:
        raise HTTPException(400, "Username already taken")
    token = create_token(str(result.inserted_id), role)
    return Token(access_token=token, role=role, name=user["name"])


@app.post("/api/auth/login", response_model=Token)
async def login(data: LoginIn):
    db = get_db()
    user = await db.users.find_one({"username": data.username.strip()})
    if user is None or not verify_password(data.password, user["password"]):
        raise HTTPException(401, "Invalid username or password")
    token = create_token(str(user["_id"]), user["role"])
    return Token(access_token=token, role=user["role"], name=user["name"])


@app.get("/api/auth/me", response_model=User)
async def me(user: dict = Depends(get_current_user)):
    return serialize_id(user)


@app.put("/api/auth/profile", response_model=User)
async def update_profile(data: ProfileUpdate, user: dict = Depends(get_current_user)):
    db = get_db()
    updates = {
        "name": data.name.strip(),
        "phone": data.phone.strip(),
        "flat": data.flat.strip(),
    }
    if data.new_password:
        if not data.current_password or not verify_password(data.current_password, user.get("password", "")):
            raise HTTPException(400, "Current password is incorrect")
        updates["password"] = hash_password(data.new_password)
    before = await db.users.find_one({"_id": user["_id"]})
    await db.users.update_one({"_id": user["_id"]}, {"$set": updates})
    fresh = await db.users.find_one({"_id": user["_id"]})
    await audit.log_audit(
        db,
        screen="Profiles",
        action="update",
        entity="user",
        entity_id=str(user["_id"]),
        changes=audit.compute_changes(before, fresh),
        user=user,
    )
    return serialize_id(fresh)


@app.get("/api/auth/flat", response_model=Flat)
async def get_my_flat(user: dict = Depends(get_current_user)):
    db = get_db()
    flat = await db.flats.find_one({"flat_no": user.get("flat")})
    if not flat:
        raise HTTPException(404, "Flat not found")
    return serialize_id(flat)


@app.put("/api/auth/flat", response_model=Flat)
async def update_my_flat(data: FlatDetailsUpdate, user: dict = Depends(get_current_user)):
    db = get_db()
    flat = await db.flats.find_one({"flat_no": user.get("flat")})
    if not flat:
        raise HTTPException(404, "Flat not found")
    updates = {
        "owner_name": data.owner_name.strip(),
        "owner_number": data.owner_number.strip(),
        "tenant_name": data.tenant_name.strip(),
        "tenant_number": data.tenant_number.strip(),
    }
    before = dict(flat)
    await db.flats.update_one({"_id": flat["_id"]}, {"$set": updates})
    fresh = await db.flats.find_one({"_id": flat["_id"]})
    await audit.log_audit(
        db, screen="Profiles", action="update", entity="flat",
        entity_id=str(flat["_id"]), changes=audit.compute_changes(before, fresh), user=user,
    )
    return serialize_id(fresh)


# --------------------- User Management ------------------

def serialize_user(doc):
    doc = serialize_id(doc)
    doc.pop("password", None)
    return doc


@app.get("/api/users", response_model=List[User])
async def list_users(user: dict = Depends(require_admin)):
    db = get_db()
    docs = await db.users.find().sort("name", 1).to_list(length=200)
    return [serialize_user(d) for d in docs]


@app.put("/api/users/{user_id}/role", response_model=User)
async def update_user_role(user_id: str, data: RoleUpdate, user: dict = Depends(require_admin)):
    if data.role not in ("superadmin", "admin", "user"):
        raise HTTPException(400, "Role must be 'superadmin', 'admin' or 'user'")
    db = get_db()
    try:
        oid = ObjectId(user_id)
    except InvalidId:
        raise HTTPException(400, "Invalid user id")
    target = await db.users.find_one({"_id": oid})
    if target is None:
        raise HTTPException(404, "User not found")

    current_role = user.get("role")

    # Nobody can modify a superadmin except another superadmin.
    if target.get("role") == "superadmin" and current_role != "superadmin":
        raise HTTPException(403, "You cannot modify a Super Admin")

    if current_role == "admin":
        # Admin cannot change their own role (prevents lock-out).
        if str(target["_id"]) == str(user["_id"]):
            raise HTTPException(403, "You cannot change your own role")
        # Admin can only toggle between member and admin, and never create superadmin.
        if data.role == "superadmin" or target.get("role") == "superadmin":
            raise HTTPException(403, "Only a Super Admin can manage Super Admin roles")

    await db.users.update_one({"_id": oid}, {"$set": {"role": data.role}})
    fresh = await db.users.find_one({"_id": oid})
    await audit.log_audit(
        db,
        screen="User Management",
        action="update",
        entity="user",
        entity_id=str(oid),
        changes=audit.compute_changes(target, fresh),
        user=user,
    )
    return serialize_user(fresh)


@app.get("/api/public/flats")
async def public_flats():
    db = get_db()
    flats = await db.flats.find().sort("flat_no", 1).to_list(length=100)
    return {"flats": [f["flat_no"] for f in flats]}


# ------------------------ Settings -----------------------

@app.get("/api/settings")
async def get_settings(user: dict = Depends(get_current_user)):
    db = get_db()
    doc = await db.settings.find_one({"_id": "global"})
    return {"monthly_maintenance": doc.get("monthly_maintenance", 0) if doc else 0}


@app.put("/api/settings")
async def update_settings(data: SettingsIn, user: dict = Depends(require_admin)):
    db = get_db()
    before = await db.settings.find_one({"_id": "global"})
    await db.settings.update_one(
        {"_id": "global"},
        {"$set": {"monthly_maintenance": data.monthly_maintenance}},
        upsert=True,
    )
    after = await db.settings.find_one({"_id": "global"})
    await audit.log_audit(
        db,
        screen="Settings",
        action="update",
        entity="settings",
        entity_id="global",
        changes=audit.compute_changes(before, after),
        user=user,
    )
    return {"monthly_maintenance": data.monthly_maintenance}


# ------------------------ Audit Log ----------------------

@app.get("/api/audit")
async def get_audit_log(
    screen: Optional[str] = None,
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    action: Optional[str] = None,
    entity: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    page: int = 1,
    limit: int = 20,
    user: dict = Depends(require_admin),
):
    db = get_db()
    query = {}
    if screen:
        query["screen"] = screen
    if user_id:
        query["user_id"] = user_id
    if username:
        query["username"] = username
    if action:
        query["action"] = action
    if entity:
        query["entity"] = entity
    ts_q = {}
    if start_date:
        try:
            ts_q["$gte"] = datetime.fromisoformat(start_date + "T00:00:00").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    if end_date:
        try:
            ts_q["$lt"] = datetime.fromisoformat(end_date + "T00:00:00").replace(tzinfo=timezone.utc) + timedelta(days=1)
        except ValueError:
            pass
    if ts_q:
        query["timestamp"] = ts_q
    page = max(1, page)
    limit = min(max(1, limit), 100)
    total = await db.audit_logs.count_documents(query)
    docs = (
        await db.audit_logs.find(query)
        .sort("timestamp", -1)
        .skip((page - 1) * limit)
        .limit(limit)
        .to_list(length=limit)
    )
    out = []
    for d in docs:
        d["id"] = str(d["_id"])
        d.pop("_id", None)
        if d.get("timestamp"):
            d["timestamp"] = d["timestamp"].isoformat()
        out.append(d)
    return {
        "logs": out,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": max(1, -(-total // limit)),
        "screens": await db.audit_logs.distinct("screen"),
        "users": await db.audit_logs.distinct("username"),
        "actions": await db.audit_logs.distinct("action"),
        "entities": await db.audit_logs.distinct("entity"),
    }


# ------------------------ Events -------------------------

@app.get("/api/events", response_model=List[Event])
async def list_events(user: dict = Depends(get_current_user)):
    db = get_db()
    today = datetime.now().strftime("%Y-%m-%d")
    docs = (
        await db.events.find({"$or": [{"date": {"$gte": today}}, {"date": None}]})
        .sort("date", 1)
        .to_list(length=200)
    )
    return [serialize_id(d) for d in docs]


@app.post("/api/events", response_model=Event, status_code=201)
async def create_event(event: EventIn, user: dict = Depends(require_admin)):
    db = get_db()
    doc = event.model_dump()
    result = await db.events.insert_one(doc)
    doc["_id"] = result.inserted_id
    await audit.log_audit(
        db, screen="Upcoming Events", action="create", entity="event",
        entity_id=str(result.inserted_id), changes=audit.compute_changes(None, doc), user=user,
    )
    return serialize_id(doc)


@app.put("/api/events/{event_id}", response_model=Event)
async def update_event(event_id: str, event: EventIn, user: dict = Depends(require_admin)):
    db = get_db()
    try:
        oid = ObjectId(event_id)
    except InvalidId:
        raise HTTPException(400, "Invalid event id")
    data = event.model_dump()
    before = await db.events.find_one({"_id": oid})
    result = await db.events.update_one({"_id": oid}, {"$set": data})
    if result.matched_count == 0:
        raise HTTPException(404, "Event not found")
    doc = await db.events.find_one({"_id": oid})
    await audit.log_audit(
        db, screen="Upcoming Events", action="update", entity="event",
        entity_id=str(oid), changes=audit.compute_changes(before, doc), user=user,
    )
    return serialize_id(doc)


@app.delete("/api/events/{event_id}", status_code=204)
async def delete_event(event_id: str, user: dict = Depends(require_admin)):
    db = get_db()
    try:
        oid = ObjectId(event_id)
    except InvalidId:
        raise HTTPException(400, "Invalid event id")
    before = await db.events.find_one({"_id": oid})
    await db.events.delete_one({"_id": oid})
    if before:
        await audit.log_audit(
            db, screen="Upcoming Events", action="delete", entity="event",
            entity_id=str(oid), changes=audit.compute_changes(before, None), user=user,
        )
    return None


# ------------------------ Contacts -----------------------

@app.get("/api/contacts", response_model=List[Contact])
async def list_contacts(user: dict = Depends(get_current_user)):
    db = get_db()
    docs = await db.contacts.find().sort("name", 1).to_list(length=200)
    return [serialize_id(d) for d in docs]


@app.post("/api/contacts", response_model=Contact, status_code=201)
async def create_contact(contact: ContactIn, user: dict = Depends(require_admin)):
    db = get_db()
    doc = contact.model_dump()
    result = await db.contacts.insert_one(doc)
    doc["_id"] = result.inserted_id
    await audit.log_audit(
        db, screen="Important Contacts", action="create", entity="contact",
        entity_id=str(result.inserted_id), changes=audit.compute_changes(None, doc), user=user,
    )
    return serialize_id(doc)


@app.put("/api/contacts/{contact_id}", response_model=Contact)
async def update_contact(contact_id: str, contact: ContactIn, user: dict = Depends(require_admin)):
    db = get_db()
    try:
        oid = ObjectId(contact_id)
    except InvalidId:
        raise HTTPException(400, "Invalid contact id")
    data = contact.model_dump()
    before = await db.contacts.find_one({"_id": oid})
    result = await db.contacts.update_one({"_id": oid}, {"$set": data})
    if result.matched_count == 0:
        raise HTTPException(404, "Contact not found")
    doc = await db.contacts.find_one({"_id": oid})
    await audit.log_audit(
        db, screen="Important Contacts", action="update", entity="contact",
        entity_id=str(oid), changes=audit.compute_changes(before, doc), user=user,
    )
    return serialize_id(doc)


@app.delete("/api/contacts/{contact_id}", status_code=204)
async def delete_contact(contact_id: str, user: dict = Depends(require_admin)):
    db = get_db()
    try:
        oid = ObjectId(contact_id)
    except InvalidId:
        raise HTTPException(400, "Invalid contact id")
    before = await db.contacts.find_one({"_id": oid})
    await db.contacts.delete_one({"_id": oid})
    if before:
        await audit.log_audit(
            db, screen="Important Contacts", action="delete", entity="contact",
            entity_id=str(oid), changes=audit.compute_changes(before, None), user=user,
        )
    return None


# ------------------------- Flats -------------------------

@app.get("/api/flats", response_model=List[Flat])
async def list_flats(user: dict = Depends(get_current_user)):
    db = get_db()
    docs = await db.flats.find().sort("flat_no", 1).to_list(length=100)
    return [serialize_id(d) for d in docs]


@app.post("/api/flats", response_model=Flat, status_code=201)
async def create_flat(flat: FlatIn, user: dict = Depends(require_admin)):
    db = get_db()
    doc = flat.model_dump()
    try:
        result = await db.flats.insert_one(doc)
    except Exception:
        raise HTTPException(400, "Flat number already exists")
    doc["_id"] = result.inserted_id
    await audit.log_audit(
        db, screen="Flat Management", action="create", entity="flat",
        entity_id=str(result.inserted_id), changes=audit.compute_changes(None, doc), user=user,
    )
    return serialize_id(doc)


@app.put("/api/flats/{flat_id}", response_model=Flat)
async def update_flat(flat_id: str, flat: FlatIn, user: dict = Depends(require_admin)):
    db = get_db()
    try:
        oid = ObjectId(flat_id)
    except InvalidId:
        raise HTTPException(400, "Invalid flat id")
    data = flat.model_dump()
    before = await db.flats.find_one({"_id": oid})
    try:
        result = await db.flats.update_one({"_id": oid}, {"$set": data})
    except Exception:
        raise HTTPException(400, "Flat number already exists")
    if result.matched_count == 0:
        raise HTTPException(404, "Flat not found")
    doc = await db.flats.find_one({"_id": oid})
    await audit.log_audit(
        db, screen="Flat Management", action="update", entity="flat",
        entity_id=str(oid), changes=audit.compute_changes(before, doc), user=user,
    )
    return serialize_id(doc)


@app.delete("/api/flats/{flat_id}", status_code=204)
async def delete_flat(flat_id: str, user: dict = Depends(require_admin)):
    raise HTTPException(405, "Flats cannot be deleted")


# ---------------------- Collections ----------------------

def compute_ledger(collections, monthly):
    """Compute a running per-flat ledger across months.

    Each month is due `monthly`. Payments clear carried-forward arrears first,
    then the current month. The running balance is carried forward.
    """
    if not collections:
        return {"entries": [], "arrears": 0.0}
    by_month = {c["month"]: c for c in collections}
    months = sorted(by_month.keys())
    y, m = int(months[0][:4]), int(months[0][5:7])
    endy, endm = int(months[-1][:4]), int(months[-1][5:7])
    seq = []
    while (y, m) <= (endy, endm):
        seq.append(f"{y:04d}-{m:02d}")
        m += 1
        if m == 13:
            m, y = 1, y + 1
    arrears = 0.0
    entries = []
    for mon in seq:
        c = by_month.get(mon)
        due = float(monthly)
        paid = float(c["amount"]) if c else 0.0
        arrears_before = arrears
        towards_arrears = min(paid, arrears)
        arrears -= towards_arrears
        towards_current = min(paid - towards_arrears, due)
        shortfall = due - towards_current
        arrears += shortfall
        arrears_after = arrears
        if shortfall == 0 and arrears_after == 0:
            status = "Paid"
        elif paid == 0 and towards_arrears == 0:
            status = "Pending"
        else:
            status = "Partial"
        entries.append(
            {
                "month": mon,
                "due": round(due, 2),
                "paid": round(paid, 2),
                "paid_date": (c or {}).get("paid_date"),
                "mode": (c or {}).get("mode", ""),
                "arrears_before": round(arrears_before, 2),
                "towards_arrears": round(towards_arrears, 2),
                "shortfall": round(shortfall, 2),
                "arrears_after": round(arrears_after, 2),
                "status": status,
                "cleared_arrears": towards_arrears > 0,
                "is_defaulter": arrears_after > 0,
            }
        )
    return {"entries": entries, "arrears": round(arrears, 2)}


@app.get("/api/maintenance-ledger")
async def all_flats_ledger(user: dict = Depends(require_admin)):
    db = get_db()
    settings = await db.settings.find_one({"_id": "global"})
    monthly = settings.get("monthly_maintenance", 0) if settings else 0
    flats = await db.flats.find().to_list(length=100)
    collections = await db.collections.find().to_list(length=100000)
    by_flat = {}
    for c in collections:
        by_flat.setdefault(c["flat_id"], []).append(c)
    overview = []
    total_arrears = 0.0
    defaulter_count = 0
    for flat in flats:
        fid = str(flat["_id"])
        ledger = compute_ledger(by_flat.get(fid, []), monthly)
        entries = ledger["entries"]
        overview.append(
            {
                "flat": serialize_id(flat),
                "arrears": ledger["arrears"],
                "is_defaulter": ledger["arrears"] > 0,
                "defaulted_months": sum(1 for e in entries if e["is_defaulter"]),
                "paid_months": sum(1 for e in entries if e["status"] == "Paid"),
                "partial_months": sum(1 for e in entries if e["status"] == "Partial"),
                "latest_month": entries[-1]["month"] if entries else None,
            }
        )
        total_arrears += ledger["arrears"]
        if ledger["arrears"] > 0:
            defaulter_count += 1
    return {
        "monthly": monthly,
        "total_arrears": round(total_arrears, 2),
        "defaulter_count": defaulter_count,
        "flats": overview,
    }


@app.get("/api/maintenance-ledger/{flat_id}")
async def flat_ledger(flat_id: str, user: dict = Depends(require_admin)):
    db = get_db()
    try:
        oid = ObjectId(flat_id)
    except InvalidId:
        raise HTTPException(400, "Invalid flat id")
    flat = await db.flats.find_one({"_id": oid})
    if not flat:
        raise HTTPException(404, "Flat not found")
    settings = await db.settings.find_one({"_id": "global"})
    monthly = settings.get("monthly_maintenance", 0) if settings else 0
    collections = await db.collections.find({"flat_id": flat_id}).to_list(length=1000)
    ledger = compute_ledger(collections, monthly)
    return {"flat": serialize_id(flat), "monthly": monthly, **ledger}


@app.get("/api/collections/flat/{flat_id}", response_model=List[Collection])
async def flat_collection_history(flat_id: str, user: dict = Depends(get_current_user)):
    db = get_db()
    try:
        ObjectId(flat_id)
    except InvalidId:
        raise HTTPException(400, "Invalid flat id")
    docs = await db.collections.find({"flat_id": flat_id}).sort("month", 1).to_list(length=1000)
    return [serialize_id(d) for d in docs]


@app.get("/api/collections/{month}", response_model=List[Collection])
async def list_collections(month: str, user: dict = Depends(get_current_user)):
    db = get_db()
    docs = await db.collections.find({"month": month}).to_list(length=100)
    return [serialize_id(d) for d in docs]


@app.post("/api/collections", response_model=Collection, status_code=201)
async def create_collection(coll: CollectionIn, user: dict = Depends(require_admin)):
    db = get_db()
    doc = coll.model_dump()
    result = await db.collections.insert_one(doc)
    doc["_id"] = result.inserted_id
    await audit.log_audit(
        db, screen="Maintenance", action="create", entity="collection",
        entity_id=str(result.inserted_id), changes=audit.compute_changes(None, doc), user=user,
    )
    return serialize_id(doc)


@app.put("/api/collections/{collection_id}", response_model=Collection)
async def update_collection(collection_id: str, coll: CollectionIn, user: dict = Depends(require_admin)):
    db = get_db()
    try:
        oid = ObjectId(collection_id)
    except InvalidId:
        raise HTTPException(400, "Invalid collection id")
    data = coll.model_dump()
    before = await db.collections.find_one({"_id": oid})
    result = await db.collections.update_one({"_id": oid}, {"$set": data})
    if result.matched_count == 0:
        raise HTTPException(404, "Collection not found")
    doc = await db.collections.find_one({"_id": oid})
    await audit.log_audit(
        db, screen="Maintenance", action="update", entity="collection",
        entity_id=str(oid), changes=audit.compute_changes(before, doc), user=user,
    )
    return serialize_id(doc)


@app.delete("/api/collections/{collection_id}", status_code=204)
async def delete_collection(collection_id: str, user: dict = Depends(require_admin)):
    db = get_db()
    try:
        oid = ObjectId(collection_id)
    except InvalidId:
        raise HTTPException(400, "Invalid collection id")
    before = await db.collections.find_one({"_id": oid})
    await db.collections.delete_one({"_id": oid})
    if before:
        await audit.log_audit(
            db, screen="Maintenance", action="delete", entity="collection",
            entity_id=str(oid), changes=audit.compute_changes(before, None), user=user,
        )
    return None


@app.post("/api/collections/bulk", status_code=200)
async def bulk_create_collections(month: str, payload: dict = Body(...), user: dict = Depends(require_admin)):
    db = get_db()
    flat_ids = payload["flat_ids"]
    flats = await db.flats.find({"_id": {"$in": [ObjectId(f) for f in flat_ids]}}).to_list(length=100)
    existing = await db.collections.find({"month": month}).to_list(length=100)
    existing_flat_ids = {c["flat_id"] for c in existing}
    created = 0
    for flat in flats:
        fid = str(flat["_id"])
        if fid in existing_flat_ids:
            continue
        await db.collections.insert_one({
            "flat_id": fid,
            "month": month,
            "amount": 0,
            "mode": "",
            "comments": "",
            "paid_date": None,
        })
        created += 1
    if created:
        await audit.log_audit(
            db, screen="Maintenance", action="create", entity="collection",
            entity_id=None,
            changes=[{"field": "flat_ids", "old": None, "new": payload["flat_ids"]}],
            user=user,
        )
    return {"created": created}


# ------------------------ Expenses -----------------------

@app.get("/api/expenses/{month}", response_model=List[Expense])
async def list_expenses(month: str, user: dict = Depends(get_current_user)):
    db = get_db()
    docs = await db.expenses.find({"month": month}).sort("date", 1).to_list(length=100)
    return [serialize_id(d) for d in docs]


@app.post("/api/expenses", response_model=Expense, status_code=201)
async def create_expense(exp: ExpenseIn, user: dict = Depends(require_admin)):
    db = get_db()
    doc = exp.model_dump()
    result = await db.expenses.insert_one(doc)
    doc["_id"] = result.inserted_id
    await audit.log_audit(
        db, screen="Maintenance", action="create", entity="expense",
        entity_id=str(result.inserted_id), changes=audit.compute_changes(None, doc), user=user,
    )
    return serialize_id(doc)


@app.put("/api/expenses/{expense_id}", response_model=Expense)
async def update_expense(expense_id: str, exp: ExpenseIn, user: dict = Depends(require_admin)):
    db = get_db()
    try:
        oid = ObjectId(expense_id)
    except InvalidId:
        raise HTTPException(400, "Invalid expense id")
    data = exp.model_dump()
    before = await db.expenses.find_one({"_id": oid})
    result = await db.expenses.update_one({"_id": oid}, {"$set": data})
    if result.matched_count == 0:
        raise HTTPException(404, "Expense not found")
    doc = await db.expenses.find_one({"_id": oid})
    await audit.log_audit(
        db, screen="Maintenance", action="update", entity="expense",
        entity_id=str(oid), changes=audit.compute_changes(before, doc), user=user,
    )
    return serialize_id(doc)


@app.delete("/api/expenses/{expense_id}", status_code=204)
async def delete_expense(expense_id: str, user: dict = Depends(require_admin)):
    db = get_db()
    try:
        oid = ObjectId(expense_id)
    except InvalidId:
        raise HTTPException(400, "Invalid expense id")
    before = await db.expenses.find_one({"_id": oid})
    await db.expenses.delete_one({"_id": oid})
    if before:
        await audit.log_audit(
            db, screen="Maintenance", action="delete", entity="expense",
            entity_id=str(oid), changes=audit.compute_changes(before, None), user=user,
        )
    return None


# ------------------------ Summary ------------------------

@app.get("/api/summary/{month}")
async def month_summary(month: str, user: dict = Depends(get_current_user)):
    from collections import defaultdict

    db = get_db()
    collections = await db.collections.find().to_list(length=100000)
    expenses = await db.expenses.find().to_list(length=100000)

    # Income is attributed to the month the money was actually received.
    income_by_month = defaultdict(float)
    current_collection = 0.0
    additional_income = 0.0
    for c in collections:
        pd = c.get("paid_date")
        if not pd:
            continue
        paid_month = pd.strftime("%Y-%m") if hasattr(pd, "strftime") else str(pd)[:7]
        income_by_month[paid_month] += c["amount"]
        cmonth = c.get("month", "")
        if cmonth == month and paid_month == month:
            current_collection += c["amount"]
        elif cmonth < month and paid_month == month:
            additional_income += c["amount"]

    expense_by_month = defaultdict(float)
    expense_by_cat_by_month = defaultdict(lambda: defaultdict(float))
    for e in expenses:
        em = e.get("month", "")
        expense_by_month[em] += e["amount"]
        expense_by_cat_by_month[em][e.get("category", "")] += e["amount"]

    # Last month balance = cumulative surplus/deficit from all earlier months.
    last_month_balance = 0.0
    for m, inc in income_by_month.items():
        if m < month:
            last_month_balance += inc - expense_by_month.get(m, 0.0)

    expenses_current = dict(expense_by_cat_by_month.get(month, {}))
    total_expense = expense_by_month.get(month, 0.0)

    total_income = current_collection + additional_income + last_month_balance

    return {
        "month": month,
        "total_flats": await db.flats.count_documents({}),
        "current_collection": current_collection,
        "additional_income": additional_income,
        "last_month_balance": last_month_balance,
        "total_income": total_income,
        "expenses": expenses_current,
        "total_expense": total_expense,
        "balance": total_income - total_expense,
    }


@app.get("/api/expense-categories")
async def expense_categories(user: dict = Depends(get_current_user)):
    db = get_db()
    cats = await db.expenses.distinct("category")
    return {"categories": [c for c in cats if c]}


@app.get("/api/health")
async def health():
    return {"status": "ok"}