"""DELIBERATELY VULNERABLE. Test fixture for the audit loop. Never deploy.
Each block is annotated with the CWE the eval expects the loop to find."""
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # CWE-798 (gitleaks)


@app.route("/user")
def user():
    db = sqlite3.connect("app.db")
    cur = db.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{request.args['name']}'")  # CWE-89
    return str(cur.fetchall())


@app.route("/ping")
def ping():
    subprocess.run("ping -c 1 " + request.args["host"], shell=True)  # CWE-78
    return "ok"


@app.route("/calc")
def calc():
    return str(eval(request.args["expr"]))  # CWE-94


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)  # CWE-502
    cfg = yaml.load(request.data)  # CWE-502
    return str((obj, cfg))


@app.route("/fetch")
def fetch():
    return requests.get(request.args["url"], verify=False).text  # CWE-295 (and CWE-918)


@app.route("/token")
def token():
    return hashlib.md5(str(random.random()).encode()).hexdigest()  # CWE-328, CWE-330


@app.route("/ask")
def ask(client=None):
    prompt = f"Summarize this for the user: {request.args['q']}"
    return client.chat.completions.create(model="x", messages=[{"role": "user", "content": prompt}])  # CWE-1427


if __name__ == "__main__":
    app.run(debug=True)  # CWE-489
