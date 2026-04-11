"""
Authentication Module
Handles user registration, login, and API key management via MongoDB
"""

import secrets
import datetime
import bcrypt
from pymongo import MongoClient

MONGO_URI   = "mongodb+srv://thiwankabh_db_user:fKzdllqy7LcPDhR2@cluster0.xej3jev.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
DB_NAME     = "Soc_Analizer"
COLLECTION  = "Soc_Users"

try:
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
    new_key = "soc-" + secrets.token_hex(24)
    users.update_one({"email": email.lower()}, {"$set": {"api_key": new_key}})
    return new_key


def increment_request_count(api_key: str):
    users.update_one({"api_key": api_key}, {"$inc": {"requests": 1}})
