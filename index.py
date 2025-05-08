from flask import Flask, request, jsonify
import jwt
from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import pymongo
from flask_cors import CORS, cross_origin
import os
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

# jwt_secret = os.environ.get(
#     "jwt_secret",
# )
# db_password = os.environ.get(
#     "db_password",
# )
# db_user = os.getenv(
#     "db_user",
# )
jwt_secret="new_secret"
db_password="jd0OMZpHGQKuDAVM"
db_user="user1"

uri = f"mongodb+srv://{db_user}:{db_password}@cluster0.3rlu3lj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
print(uri)

# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi("1"))

# Send a ping to confirm a successful connection
try:
    client.admin.command("ping")
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

mydb = client["notes"]
mycol = mydb["Users"]
print(list(mycol.find({})))


def check_token(token):
    try:
        decoded = jwt.decode(token, jwt_secret, algorithms=["HS256"])
        print(decoded)
        return decoded
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False


app = Flask(__name__)
cors = CORS(
    app,
    supports_credentials=True,
    origins="*",
)


# @app.after_request
# def after_request(response):
#     response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")  # list all needed headers
#     response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT") 
#     response.headers.add("Access-Control-Allow-Origin", "*")
    # response.headers.add("Access-Control-Allow-Credentials", "true")
    # response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
   
    # return response

@app.route("/")
@cross_origin()
def index():
    return "Hello, World!"

@app.route("/register", methods=["POST"])
@cross_origin()
def register():

    name = request.get_json()["name"]
    password = request.get_json()["password"]
    print(name, password,'hello')
    if not (name and password):
        return jsonify({"message": "Please provide all fields."}), 400
    existing_user = mycol.find_one({"name": name})
    if existing_user:
        print("User already exists. Please login.")
        return jsonify({"message": "User already exists. Please login."}), 400
    
    hashed_password = generate_password_hash(password)
    user_id = str(uuid.uuid4())
    new_user = {
        "name": name,
        "password": hashed_password,
        "user_id": user_id,
        "notes": [],
    }
    mycol.insert_one(new_user)
    return jsonify({"message": "User registered successfully."}), 201


@app.route("/login", methods=["POST"])
@cross_origin()
def login():
    print(request.data)
    name = request.get_json()["name"]
    password = request.get_json()["password"]
    print(name, password)
    user = mycol.find_one({"name": name})
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"message": "Invalid credentials."}), 401
    print("c pass")
    token = jwt.encode(
        {
            "name": user["name"],
            "exp": datetime.now(tz=timezone.utc) + timedelta(days=7),
        },
        jwt_secret,
        algorithm="HS256",
    )
    print(token)
    return jsonify({"token": token}), 200


@app.route("/save-notes", methods=["POST"])
@cross_origin()
def save():
    data = request.get_json()
    print(data)
    token = data["token"]
    note = data["notes"]
    if not (token and note):
        return jsonify({"message": "Please provide all fields."}), 400
    jwt_data = check_token(token)
    if not jwt_data:
        return jsonify({"message": "Invalid token."}), 401
    name = jwt_data["name"]
    user = mycol.find_one({"name": name})
    if not user:
        return jsonify({"message": "User not found."}), 404
    mycol.update_one(
        {"name": name},
        {"$set": {"notes": note}},
    )
    return jsonify({"message": "Note saved successfully."}), 200


@app.route("/get-notes", methods=["POST"])
@cross_origin()
def get_notes():
    print(request.data)
    data = request.get_json()
    token = data["token"]
    if not (token):
        return jsonify({"message": "Please provide all fields."}), 400
    jwt_data = check_token(token)
    if not jwt_data:
        return jsonify({"message": "Invalid token."}), 401
    name = jwt_data["name"]
    user = mycol.find_one({"name": name})
    print(user)
    if not user:
        return jsonify({"message": "User not found."}), 404
    notes = user.get("notes", [])
    return jsonify(notes)


app.run()
