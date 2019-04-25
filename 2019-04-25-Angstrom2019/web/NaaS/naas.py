
from flask import Flask, jsonify, request
app = Flask(__name__)

from bs4 import BeautifulSoup as bs

import random
import os
import binascii
import base64
import json

status = {}

def setup():
	random.seed(os.urandom(256))
	url = os.environ.get("URL")
	hits = status["hits"] if "hits" in status else 0
	return {"url": url, "hits": hits}

status = setup()

def get_nonces():
	while True: yield str(base64.b64encode(binascii.unhexlify(hex(random.getrandbits(128))[2:].zfill(32))), encoding="ascii")

@app.route('/nonceify', methods=["POST"])
def nonceify():
	status["hits"] += 1
	soup = bs(request.data, 'html.parser')
	csp = "script-src"
	for script, nonce in zip(soup.findAll('script'), get_nonces()):
		script["nonce"] = nonce
		csp += " 'nonce-" + nonce + "'"
	csp += ";"
	return jsonify({"html": str(soup), "csp": csp})

@app.route('/status', methods=["GET"])
def get_status():
	global status
	status = setup()
	status["hits"] += 1
	return jsonify(status)

@app.route("/")
def home():
	return """<pre>
Welcome to:
  _   _              _____ 
 | \\ | |            / ____|
 |  \\| | __ _  __ _| (___  
 | . ` |/ _` |/ _` |\\___ \\ 
 | |\\  | (_| | (_| |____) |
 |_| \\_|\\__,_|\\__,_|_____/ 
                           
Nonces as a Service!

We add nonces to your HTML and give you a CSP header all in one handy API call.

To get information about our service, such as the URL and number of hits we've gotten, use the GET /status route.

To get your nonceified HTML and a CSP header, use the POST /nonceify route.

Also, we're open source! Check out the source code below:

""" + open("naas.py").read().replace("<", "<").replace(">", ">") + "</pre>"