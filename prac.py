from dotenv import load_dotenv
import os
import base64
from flask import Flask, url_for,redirect, request, session, render_template
from requests import post, get
import json
import random
import string
from urllib.parse import urlencode
'''
urlencode({'pram1': 'foo', 'param2': 'bar'})
output: 'pram1=foo&param2=bar'
'''
'''
python -m flask --app prac run
python -m flask --app prac run --debug
http://127.0.0.1:5000
http://127.0.0.1:5000/login
'''
app = Flask(__name__)
load_dotenv()

APP_SECRET_KEY = os.getenv("APP_SECRET_KEY")
app.secret_key = APP_SECRET_KEY
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
AUTH_BASE64 = str(base64.b64encode((CLIENT_ID+":"+CLIENT_SECRET).encode("utf-8")), "utf-8")
print(CLIENT_ID,CLIENT_SECRET)
REDIRECT_URI = "http://127.0.0.1:5000/callback"

def getProfile(accessToken):
    headers = get_auth_token(accessToken)
    url = 'https://api.spotify.com/v1/me'
    result = get(url, headers=headers)
    
    return json.loads(result.content)
    # return result.content
    
@app.route('/')
def index():
    return render_template("home.html")

@app.route('/tracks')
def tracks():
    access_token = session.get("access_token")
    headers = get_auth_token(access_token)
    url = 'https://api.spotify.com/v1/me/top/tracks?time_range=long_term&limit=10'
    result = get(url, headers=headers)
    json_result = enumerate(json.loads(result.content)["items"])
    # for idx, track in json_result:
    #     print(f"{idx+1}. {track['name']} by {track['artists'][0]['name']}")
    return render_template('tracks.html', result=json_result)

@app.route('/callback')
def callback():
    code = request.args["code"]
    state = request.args["state"]
    url = 'https://accounts.spotify.com/api/token'
    headers = {
        'Authorization': 'Basic ' + AUTH_BASE64,
        'Content-Type': "application/x-www-form-urlencoded"
    }
    data = {
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code'
        }
    result = post(url, headers=headers, data=data)
    access_token = json.loads(result.content)["access_token"]
    session["access_token"] = access_token
    # session["refresh_token"] = get_auth_token(access_token)
    profile = getProfile(access_token)
    return render_template('home.html', name=profile["display_name"])
    
    

@app.route("/login")
def login():
    state = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
    scope = "user-read-private user-read-email user-top-read user-follow-read"
    link = 'https://accounts.spotify.com/authorize?'
    auth_url = link + urlencode({
        'response_type': 'code',
        'client_id' : CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': scope,
        # 'show_dialog': True,
        'state': state
    })
    return redirect(auth_url)
    
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
        "refresh_token": get_auth_token(session.get("access_token")),
        "client_id": CLIENT_ID
    }
    result = post(url, headers=headers, data=data)
    return result.content
    json_result = json.loads(result.content)
    return json_result
    
    
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
    
