from pydantic import BaseModel, Field
from typing import Optional


class FlatIn(BaseModel):
    flat_no: str
    owner_name: str = ""
    tenant_name: str = ""
    owner_number: str = ""
    tenant_number: str = ""


class SettingsIn(BaseModel):
    monthly_maintenance: float


class Flat(FlatIn):
    id: Optional[str] = None


class CollectionIn(BaseModel):
    flat_id: str
    month: str  # YYYY-MM
    amount: float
    mode: str = ""  # cash | online
    comments: str = ""
    paid_date: Optional[str] = None


class Collection(CollectionIn):
    id: Optional[str] = None
    paid: bool = True


class ExpenseIn(BaseModel):
    month: str  # YYYY-MM
    category: str  # security | sweeper | electric | misc
    amount: float
    description: str = ""
    date: Optional[str] = None


class Expense(ExpenseIn):
    id: Optional[str] = None


class SignupIn(BaseModel):
    username: str
    password: str
    name: str
    phone: str
    flat: str
    type: str = "owner"  # owner | tenant


class LoginIn(BaseModel):
    username: str
    password: str


class User(BaseModel):
    id: Optional[str] = None
    username: str
    name: str
    phone: str
    flat: str
    type: str = "owner"  # owner | tenant
    role: str = "user"  # superadmin | admin | user


class ProfileUpdate(BaseModel):
    name: str
    phone: str
    flat: str
    current_password: Optional[str] = None
    new_password: Optional[str] = None


class FlatDetailsUpdate(BaseModel):
    owner_name: str = ""
    owner_number: str = ""
    tenant_name: str = ""
    tenant_number: str = ""


class RoleUpdate(BaseModel):
    role: str  # admin | user


class EventIn(BaseModel):
    title: str
    date: Optional[str] = None
    description: str = ""


class Event(EventIn):
    id: Optional[str] = None


class ContactIn(BaseModel):
    name: str
    role: str = ""
    phone: str = ""
    flat: str = ""


class Contact(ContactIn):
    id: Optional[str] = None


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    name: str
