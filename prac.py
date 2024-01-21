from dotenv import load_dotenv
import os
import base64
from flask import Flask, url_for, session, redirect, request
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


client_id = os.getenv("CLIENT_ID")
client_secret = os.getenv("CLIENT_SECRET")
print(client_id,client_secret)

def getProfile(accessToken):
    headers = get_auth_token(accessToken)
    url = 'https://api.spotify.com/v1/me'
    result = get(url, headers=headers)
    
    return json.loads(result.content)
    # return result.content
    
@app.route('/')
def index():
    return "testing"

@app.route('/callback')
def callback():
    code = request.args["code"]
    state = request.args["state"]
    auth_string = client_id+":"+client_secret
    auth_bytes = auth_string.encode("utf-8")
    auth_base64 = str(base64.b64encode(auth_bytes), "utf-8")
    url = 'https://accounts.spotify.com/api/token'
    headers = {
        'Authorization': 'Basic ' + auth_base64,
        'Content-Type': "application/x-www-form-urlencoded"
    }
    redirect_uri = "http://127.0.0.1:5000/callback"
    data = {
        'code': code,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code'
        }
    result = post(url, headers=headers, data=data)
    access_token = json.loads(result.content)["access_token"]
    profile = getProfile(access_token)
    return profile
    
    

@app.route("/login")
def login():
    state = ''.join(random.choices(string.ascii_uppercase + string.digits, k=16))
    scope = "user-read-private user-read-email"
    redirect_uri = "http://127.0.0.1:5000/callback"
    link = 'https://accounts.spotify.com/authorize?'
    auth_url = link + urlencode({
        'response_type': 'code',
        'client_id' : client_id,
        'redirect_uri': redirect_uri,
        'scope': scope,
        'show_dialog': True,
        'state': state
    })
    print(auth_url)
    return redirect(auth_url)
    

def get_token():
    auth_string = client_id+":"+client_secret
    auth_bytes = auth_string.encode("utf-8")
    auth_base64 = str(base64.b64encode(auth_bytes), "utf-8")
    url = 'https://accounts.spotify.com/api/token'
    headers = {
        'Authorization': 'Basic ' + auth_base64,
        'Content-Type': "application/x-www-form-urlencoded"
    }
    data = {'grant_type': 'client_credentials'}
    result = post(url,headers=headers, data=data)
    list = json.loads(result.content)
    token = list["access_token"]
    return token

def get_auth_token(token): # get(url, headers=headers) where header is auth_token(token)
    auth_token = {'Authorization': 'Bearer ' + token}
    return auth_token

def get_artist(token, name):
    headers = get_auth_token(token)
    url = f"https://api.spotify.com/v1/search"
    query = f"?q={name}&type=artist&market=US&limit=1"
    query_url = url+query
    result = get(query_url,headers=headers)
    json_result = json.loads(result.content)["artists"]["items"]
    return json_result[0]

def get_artist_name(token, id):
    headers = get_auth_token(token)
    url = f"https://api.spotify.com/v1/artists/{id}"
    result = get(url, headers=headers)
    json_result = json.loads(result.content)["name"]
    return json_result

def artist_top_tracks(token, id):
    headers = get_auth_token(token)
    url = f"https://api.spotify.com/v1/artists/{id}/top-tracks?market=US"
    result = get(url, headers=headers)
    json_result = json.loads(result.content)["tracks"]
    return json_result

    

def main():
    token = get_token()
    # artist = get_artist(token, "Circa Survive")
    # artist_id = artist['id']
    # print(get_artist_name(token, artist_id))
    # songs = artist_top_tracks(token, artist_id)
    # for idx, song in enumerate(songs):
    #     print(f"{idx+1}. {song['name']}")
    # get_user(token)
    
    

'''
Lines 11-13

In summary, this code is creating a base64-encoded string that 
represents the combination of client_id and client_secret in a 
specific format. This string is often used for HTTP Basic 
Authentication when making requests to APIs that 
require authentication using client credentials. 
The resulting auth_base64 can be used as the value for the
Authorization header in an HTTP request.
'''
