from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from bson.json_util import dumps
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import os
import datetime
from functools import wraps

app = Flask(__name__)
app.config["MONGO_URI"] = "mongodb://jwtMongo:27017/myDatabase"  # Adjust as needed
app.config["SECRET_KEY"] = "unsafe_secret"  # Change to your secret key
app.config["TOKEN_EXPIRATION_MINUTES"] = 5  # Add this line
app.config["TOKEN_EXPIRATION_SECONDS"] = 30

mongo = PyMongo(app)

# JWT token decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = mongo.db.users.find_one({'_id': ObjectId(data['user_id'])})
        except:
            return jsonify({'message': 'Token is invalid!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/login', methods=['POST'])
def login_user():
    auth = request.json
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Could not verify'}), 401
    user = mongo.db.users.find_one({'username': auth['username']})
    if not user:
        return jsonify({'message': 'User not found'}), 401
    if check_password_hash(user['password'], auth['password']):
        token_expiration_min = datetime.timedelta(minutes=app.config["TOKEN_EXPIRATION_MINUTES"])
        token_expiration_sec = datetime.timedelta(seconds=app.config["TOKEN_EXPIRATION_SECONDS"])
        token = jwt.encode({
            'user_id': str(user['_id']),
            'exp': datetime.datetime.utcnow() + token_expiration_min  # Configure expiration time here
        }, app.config['SECRET_KEY'])
        print("Current Time:", datetime.datetime.utcnow().timestamp())
        return jsonify({'token': token})
    return jsonify({'message': 'Password is wrong'}), 403

# CRUD Operations for a resource, e.g., items
@app.route('/item', methods=['POST'])
@token_required
def add_item(current_user):
    print("Current Time:", datetime.datetime.utcnow().timestamp())
    data = request.json
    if not data:
        return jsonify({"message": "No input data provided"}), 400
    try:
        item_id = mongo.db.items.insert_one(data).inserted_id
        return jsonify({'message': 'Item added', 'id': str(item_id)}), 201
    except Exception as e:
        return jsonify({"message": str(e)}), 500

@app.route('/item/<id>', methods=['GET'])
@token_required
def get_item(current_user, id):
    print("Current Time:", datetime.datetime.utcnow().timestamp())
    item = mongo.db.items.find_one({'_id': ObjectId(id)})
    if item:
        return dumps(item), 200
    else:
        return jsonify({'message': 'Item not found'}), 404

@app.route('/item/<id>', methods=['PUT'])
@token_required
def update_item(current_user, id):
    print("Current Time:", datetime.datetime.utcnow().timestamp())
    data = request.json
    if not data:
        return jsonify({"message": "No input data provided"}), 400
    try:
        mongo.db.items.update_one({'_id': ObjectId(id)}, {"$set": data})
        return jsonify({'message': 'Item updated'}), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500

@app.route('/item/<id>', methods=['DELETE'])
@token_required
def delete_item(current_user, id):
    print("Current Time:", datetime.datetime.utcnow().timestamp())
    try:
        mongo.db.items.delete_one({'_id': ObjectId(id)})
        return jsonify({'message': 'Item deleted'}), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500

@app.route('/register', methods=['POST'])
def register_user():
    print("Current Time:", datetime.datetime.utcnow().timestamp())
    # Parse request data
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Missing username or password'}), 400

    # Check if user already exists
    if mongo.db.users.find_one({'username': username}):
        return jsonify({'message': 'User already exists'}), 409

    # Hash password
    hashed_password = generate_password_hash(password)

    # Save user to database
    mongo.db.users.insert_one({'username': username, 'password': hashed_password})

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/user/delete/<username>', methods=['DELETE'])
@token_required
def delete_user_by_username(current_user, username):
    # Optional: Check if the current_user is allowed to delete the specified user
    # This could involve checking if current_user is an admin or if current_user's username matches the username to delete

    try:
        result = mongo.db.users.delete_one({'username': username})
        if result.deleted_count > 0:
            return jsonify({'message': 'User deleted successfully'}), 200
        else:
            return jsonify({'message': 'User not found'}), 404
    except Exception as e:
        return jsonify({"message": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
