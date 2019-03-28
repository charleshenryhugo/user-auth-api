# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# [START gae_python37_app]
from flask import Flask
from flask import request
from flask import json
import base64
import re

# If `entrypoint` is not defined in app.yaml, App Engine will look for an app
# called `app` in `main.py`.
app = Flask(__name__)

# user list (To be stored into DB)
user_list = {
    'TaroYamada': {
        'password': "PaSSwd4TY",
        'nickname': "たろー",
        'comment': "僕は元気です"
    }
}


@app.route('/')
def hello():
    """Return a friendly HTTP greeting."""
    return make_resp(200, {'message': 'hello world'})


@app.route('/signup/', methods=['POST'])
def signup():
    try:
        body = request.json
        user_id = body['user_id']
        pwd = body['password']
    except:
        return make_resp(400, { 'message': 'valid user_id and password are both necessary'})

    # user_id already exists
    if user_id in user_list:
        data = {
            "message": "Account creation failed",
            "cause": "already same user_id is used"
        }
        return make_resp(400, data)

    # validate user_id
    if len(user_id) < 6 or len(user_id) > 20:
        data = {
            "message": "Account creation failed",
            "cause": "user_id is too short or too long"
        }
        return make_resp(400, data)

    # validate password
    validata_pwd_msg = validate_pwd(pwd)
    if not validata_pwd_msg == 'VALID':
        data = {
            "message": "Account creation failed",
            "cause": validata_pwd_msg
        }
        return make_resp(400, data)

    # add new user with blank comment
    user_list[user_id] = {
        'password': pwd,
        'nickname': user_id,
        'comment': ''
    }
    data = {
        "message": "Account successfully created",
        "user": {
            "user_id": user_id,
            "nickname": user_list[user_id]['nickname'],
        }
    }
    return make_resp(200, data)


@app.route('/users/', methods=['GET'])
def get_user():
    user_id = str(request.args.get('user_id'))
    status_code = authenticate_user(user_id)
    if 404 == status_code:
        return make_resp(404, { "message": "No User found" })
    elif 401 == status_code:
        return make_resp(401, { "message": "Authentication Faild" })

    # auth success, return user details
    data = {
        "message": "User details by user_id",
        "user": {
            "user_id": user_id,
            "nickname": user_list[user_id]['nickname'],
        }
    }
    if user_list[user_id]['comment'] != '':
        data['user']['comment'] = user_list[user_id]['comment']
    
    return make_resp(200, data)


@app.route('/users/', methods=['PATCH'])
def patch_user():
    user_id = str(request.args.get('user_id'))
    status_code = authenticate_user(user_id)
    if 404 == status_code: 
        return make_resp(404, { "message": "No User found" })
    elif 401 == status_code: 
        return make_resp(401, { "message": "Authentication Faild" })
    
    # parse PATCH Body
    body = request.json
    if body == None:
        return make_resp(400, { 'message': 'unparsable json body'})

    if 'password' in body:
        return make_resp(400, { 'message': 'password is not changable'})
    
    data = {
        'message': 'User details updated successfully',
        'user': {
            'user_id': user_id,
        }
    }
    if 'comment' in body:
        user_list[user_id]['comment'] = body['comment']
        data['user']['comment'] = user_list[user_id]['comment']
    
    if 'nickname' in body:
        user_list[user_id]['nickname'] = body['nickname']
        data['user']['nickname'] = user_list[user_id]['nickname']

    return make_resp(200, data)

@app.route('/users/', methods=['DELETE'])
def delete_user():
    user_id = str(request.args.get('user_id'))
    status_code = authenticate_user(user_id)
    if 404 == status_code: 
        return make_resp(404, { "message": "No User found" })
    elif 401 == status_code: 
        return make_resp(401, { "message": "Authentication Faild" })

    try:
        user_list.pop(user_id)
    except:
        return make_resp(400, { "message": "deletion Faild" })
    
    data = {
        'message': 'User deleted successfully',
        'user': {
            'user_id': user_id,
        }
    }
    return make_resp(200, data)

# authenticate user_id and password
def authenticate_user(user_id):
    # user not found
    if user_id not in user_list:
        return 404

    # parse base64 encoded {user_id} + ':' + {password}
    user_id_pwd_b64 = request.headers.get('Basic')
    try:
        user_id_pwd = base64ToStr(user_id_pwd_b64).strip().split(':')
    except:
        return 401

    # user_id doesn't match
    if not user_id_pwd[0] == user_id:
        return 401

    # password doesn't match
    if not user_id_pwd[1] == user_list[user_id]['password']:
        return 401
    
    return 200

# validate password
def validate_pwd(pwd):
    if len(pwd) < 8:
        return 'password too short'
    elif len(pwd) > 20:
        return 'password too long'
    elif not re.search("[a-z]",pwd):
        return 'password needs at least one character from a~z'
    elif not re.search("[0-9]",pwd):
        return 'password needs at least one digit from 0~9'
    elif not re.search("[A-Z]",pwd):
        return 'password needs at least one character from A~Z'
    elif re.search("\s",pwd):
        return 'password should not contain any space'
    elif not all(ord(c) < 128 for c in pwd):
        return 'password should only contain ascii characters'
    else:
        return 'VALID'

# build json response
def make_resp(status, data):
    resp = app.response_class(
        response=json.dumps(data),
        status=status,
        mimetype='application/json'
    )
    return resp

# decode base64 encoded string
def strToBase64(s):
    return base64.b64encode(s.encode('utf-8'))

def base64ToStr(b):
    return base64.b64decode(b).decode('utf-8')

if __name__ == '__main__':
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    app.run(host='127.0.0.1', port=8080, debug=True)
# [END gae_python37_app]
