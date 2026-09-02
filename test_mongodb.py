import os

import certifi

uri = os.getenv("MONGO_DB_URL") or os.getenv("MONGODB_URL_KEY")

if not uri:
    raise SystemExit("Set MONGO_DB_URL or MONGODB_URL_KEY before testing MongoDB.")

try:
    from pymongo.mongo_client import MongoClient
except ImportError:
    raise SystemExit("Install dependencies with `python -m pip install -r requirements.txt` before testing MongoDB.")

# Create a new client and connect to the server
client = MongoClient(uri, tlsCAFile=certifi.where())

# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)
