from flask import Flask, request, jsonify, make_response
import jwt
import datetime

app = Flask(__name__)

SECRET_KEY = 'secret_key' # generate with random for production
REFRESH_SECRET_KEY = 'refresh_secret_key' # generate with random for production


# user_id : username if unique
# expiration : should be between 15mn and 1h
def generate_jwt(user_id, expiration):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.now(datetime.timezone.utc) + expiration # Warning : keep ntp on time
    } 
    print(payload['exp'])
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256') # could be 512 
    return token

# user_id = username if unique
def generate_refresh_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)  # Refresh token valid for 7 days
    }
    token = jwt.encode(payload, REFRESH_SECRET_KEY, algorithm='HS256') # could be 512
    return token

# token = jwt token
# secret_key = MASTER SECRET
def decode_jwt(token, secret_key):
    try:
        payload = jwt.decode(token, secret_key, algorithms=['HS256']) # could be 512, should match generate_refresh and generate_jwt
        #print(datetime.datetime.fromtimestamp((payload['exp'])))
        #print(datetime.datetime.now())
        #print(datetime.timedelta(seconds=10))
        #print( datetime.datetime.now() + datetime.timedelta(seconds=10))
        #print(datetime.datetime.fromtimestamp(payload.exp).time())
        return payload
    except jwt.ExpiredSignatureError: # exp is reach
        print("exp")
        return None
    except jwt.InvalidTokenError: # signature validation
        return None

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username') # or it could be a pre shared secret (like API KEY, it is better if it is used by a program)
    password = data.get('password')
    
    if username == 'user' and password == 'password': # should be a call in a user database
        access_token = generate_jwt(user_id=1, expiration=datetime.timedelta(seconds=10))  # 15-minutes expiry to 60-minutes, user_id should be database, we can use role instead
        refresh_token = generate_refresh_token(user_id=1)
        response = make_response(jsonify({'access_token': access_token}))
        response.set_cookie('refresh_token', refresh_token, httponly=True)
        return response
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/refresh', methods=['POST'])
def refresh():
    refresh_token = request.cookies.get('refresh_token')
    if not refresh_token:
        return jsonify({'message': 'Refresh token is missing'}), 401

    payload = decode_jwt(refresh_token, REFRESH_SECRET_KEY)
    if not payload:
        return jsonify({'message': 'Invalid or expired refresh token'}), 401

    new_access_token = generate_jwt(user_id=payload['user_id'], expiration=datetime.timedelta(minutes=15))
    return jsonify({'access_token': new_access_token})

@app.route('/protected', methods=['GET'])
def protected():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'message': 'Token is missing'}), 401

    token = auth_header.split(" ")[1]
    payload = decode_jwt(token, SECRET_KEY)
    if not payload:
        return jsonify({'message': 'Token is invalid or expired'}), 401

    return jsonify({'message': 'Protected endpoint accessed', 'user_id': payload['user_id']})

if __name__ == '__main__':
    app.run(debug=True)