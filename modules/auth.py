"""
Authentication Module
Handles user registration, login, and API key management via MongoDB
"""

import secrets
import datetime
import os
import bcrypt
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URI   = os.getenv("MONGO_URI", "")
DB_NAME     = "Soc_Analizer"
COLLECTION  = "Soc_Users"

client = None
db = None
users = None
DB_CONNECTED = False

try:
    if not MONGO_URI:
        raise ValueError("MONGO_URI environment variable is not set")
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db     = client[DB_NAME]
    users  = db[COLLECTION]
    client.server_info()
    DB_CONNECTED = True
except Exception as e:
    DB_CONNECTED = False
    print(f"MongoDB connection failed: {e}")


def register_user(username: str, email: str, password: str):
    if not DB_CONNECTED:
        return False, "Database not connected"
    if users.find_one({"email": email.lower()}):
        return False, "Email already registered"
    if users.find_one({"username": username}):
        return False, "Username already taken"

    api_key = "soc-" + secrets.token_hex(24)
    hashed = bcrypt.hashpw(password[:72].encode(), bcrypt.gensalt())
    users.insert_one({
        "username":   username,
        "email":      email.lower(),
        "password":   hashed,
        "api_key":    api_key,
        "created_at": datetime.datetime.utcnow(),
        "requests":   0,
    })
    return True, api_key


def login_user(email: str, password: str):
    if not DB_CONNECTED:
        return False, "Database not connected", None
    user = users.find_one({"email": email.lower()})
    if not user:
        return False, "Email not found", None
    if not bcrypt.checkpw(password[:72].encode(), user["password"]):
        return False, "Wrong password", None
    return True, "Login successful", user


def get_user_by_api_key(api_key: str):
    if not DB_CONNECTED:
        return None
    return users.find_one({"api_key": api_key})


def regenerate_api_key(email: str) -> str:
    if not DB_CONNECTED:
        return ""
    new_key = "soc-" + secrets.token_hex(24)
    users.update_one({"email": email.lower()}, {"$set": {"api_key": new_key}})
    return new_key


def increment_request_count(api_key: str):
    if not DB_CONNECTED:
        return
    users.update_one({"api_key": api_key}, {"$inc": {"requests": 1}})
