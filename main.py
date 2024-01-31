from dotenv import load_dotenv
import os
import base64
from flask import Flask, url_for,redirect, request, session, render_template
from requests import post, get
import json
import random
import string
from urllib.parse import urlencode
from hashlib import sha256
'''
python -m flask --app main run
python -m flask --app main run --debug
http://127.0.0.1:5000
'''
app = Flask(__name__)
load_dotenv()

APP_SECRET_KEY = os.getenv("APP_SECRET_KEY")
app.secret_key = APP_SECRET_KEY
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
AUTH_BASE64 = str(base64.b64encode((str(CLIENT_ID)+":"+str(CLIENT_SECRET)).encode("utf-8")), "utf-8")
print(CLIENT_ID,CLIENT_SECRET)
REDIRECT_URI = "http://127.0.0.1:5000/callback"


    
@app.route('/')
def index():
    return render_template("home.html")

@app.route("/login")
def login():
    # state = ''.join(random.choices(string.ascii_uppercase + string.digits, k=64))
    codeVerifier = ''.join(random.choices(string.ascii_uppercase + string.digits, k=64))
    session["codeVerifier"] = codeVerifier
    #The line under is messed up, need to edit out certain characters out for it to always work
    codeChallenge = base64.b64encode(sha256(codeVerifier.encode('utf-8')).digest())[:-1]
    scope = "user-read-private user-read-email user-top-read user-follow-read"
    link = 'https://accounts.spotify.com/authorize?'
    auth_url = link + urlencode({
        'response_type': 'code',
        'client_id' : CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': scope,
        # 'show_dialog': True,
        # 'state': state
        "code_challenge_method": 'S256',
        "code_challenge": codeChallenge
    })
    return redirect(auth_url)

@app.route('/callback')
def callback():
    codeVerifier = session.get("codeVerifier")
    code = request.args["code"]
    # state = request.args["state"]
    url = 'https://accounts.spotify.com/api/token'
    headers = {
        'Authorization': 'Basic ' + AUTH_BASE64,
        'Content-Type': "application/x-www-form-urlencoded"
    }
    data = {
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code',
        "code_verifier": codeVerifier,
        }
    result = post(url, headers=headers, data=data)
    if result.status_code == 200:
        json_result = json.loads(result.content)
        session["access_token"] = json_result["access_token"]
        session["refresh_token"] = json_result["refresh_token"]
        profile = getProfile()
        return render_template('home.html', name=profile["display_name"])
    json_result = json.loads(result.content)
    return render_template('home.html', name=result.content)

@app.route('/tracks')
def tracks():
    access_token = session.get("access_token")
    headers = get_auth_token(access_token)
    url = 'https://api.spotify.com/v1/me/top/tracks?time_range=long_term&limit=10'
    result = get(url, headers=headers)
    json_result = enumerate(json.loads(result.content)["items"])
    return render_template('tracks.html', result=json_result)


def get_auth_token(token): # get(url, headers=headers) where header is auth_token(token)
    auth_token = {'Authorization': 'Bearer ' + token}
    return auth_token

def get_refresh_token():
    refreshToken = session.get("refresh_token")
    url = "https://accounts.spotify.com/api/token"
    headers = {
        'Authorization': 'Basic ' + AUTH_BASE64,
        'Content-Type': 'application/x-www-form-urlencoded'}
    data ={
        "grant_type": 'refresh_token',
        "refresh_token": refreshToken,
        "client_id": CLIENT_ID
    }
    result = post(url, headers=headers, data=data)
    return result.content
    
def getProfile():
    accessToken = session.get("access_token")
    headers = get_auth_token(accessToken)
    url = 'https://api.spotify.com/v1/me'
    result = get(url, headers=headers)
    
    return json.loads(result.content)

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
