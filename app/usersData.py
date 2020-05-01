from flask import request, jsonify, make_response
from app import app
from config import client, SECRET_KEY
import uuid
import jwt
import datetime
from functools import wraps
from flask_bcrypt import Bcrypt
import json


bcrypt = Bcrypt()

# Select the database
db = client.tarang
# Select the users collection
collection = db.users
# Select the profile collection
profile = db.userProfile

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None
        auth_header = request.headers.get('Authorization')

        if auth_header:
            token = auth_header.split(" ")[1]

        if not token:
            return jsonify({'message': 'a valid token is missing'})

        try:
            data = jwt.decode(token, SECRET_KEY)
            current_user = collection.find({'public_id': data['public_id']})
        except:
            return jsonify({'message': 'token is invalid'})


            return f(current_user, *args, **kwargs)
    return decorator

@app.route("/")
def get_initial_response():
    """Welcome message"""
    # Message to the user
    message = {
        'apiVersion': 'v1.0',
        'status': '200',
        'message': 'Welcome to the Tarang API v1.0'
    }
    # Making the message looks good
    resp = jsonify(message)
    # Returning the object
    return resp

@app.route('/api/v1/register', methods=['GET', 'POST'])
def signup_user():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    new_user = {}
    new_user['public_id'] = str(uuid.uuid4())
    new_user['username'] = data['username']
    new_user['email'] = data['email']
    new_user['password'] = hashed_password
    new_user['role'] = 1
    record_created = collection.insert(new_user)

    return jsonify({'message': 'registered successfully'})


@app.route('/api/v1/login', methods=['GET', 'POST'])
def login_user():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})

    user = collection.find_one({'username': auth.username})
    print(user['password'])

    if bcrypt.check_password_hash(user['password'], auth.password):
        token = jwt.encode(
            {'public_id': user['public_id'], 'exp': datetime.datetime.utcnow() +
             datetime.timedelta(minutes=30)},
            SECRET_KEY)
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('could not verify', 401, {'WWW.Authentication': 'Basic realm: "login required"'})


@app.route('/api/v1/user', methods=['GET'])
def get_all_users():
    users = collection.find()

    result = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user['public_id']
        user_data['username'] = user['username']
        user_data['email'] = user['email']
        user_data['role'] = user['role']

        result.append(user_data)

    return jsonify({'users': result})

@app.route("/api/v1/user/<user_id>", methods=['GET'])
@token_required
def update_user(user_id):
    data = request.get_json()
    print(user_id)
    # Updating the user
    records_updated = profile.update_one({"public_d": user_id}, data)

    # Check if resource is updated
    if records_updated.modified_count > 0:
        # Prepare the response as resource is updated successfully
        return "", 200
    else:
        # Bad request as the resource is not available to update
        # Add message for debugging purpose
        return "", 404


@app.errorhandler(404)
def page_not_found(e):
    """Send message to the user with notFound 404 status."""
    # Message to the user
    message = {
        "err":
            {
                "msg": "This route is currently not supported. Please refer API documentation."
            }
    }
    # Making the message looks good
    resp = jsonify(message)
    # Sending OK response
    resp.status_code = 404
    # Returning the object
    return resp
