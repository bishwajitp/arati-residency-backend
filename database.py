import os

from motor.motor_asyncio import AsyncIOMotorClient

from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "arati-residency")

client = AsyncIOMotorClient(MONGO_URI)
db = client[MONGO_DB]


def get_db():
    return db
