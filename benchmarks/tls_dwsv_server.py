import json
import os
from flask import Flask, jsonify

app = Flask(__name__)

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROOF_F = os.path.join(BASE, "owner", "proofs.json")
PUBKEY_F = os.path.join(BASE, "owner", "owner_pubkey.pem")

with open(PROOF_F, "r", encoding="utf-8") as f:
    PROOFS = json.load(f)

@app.route("/")
def index():
    return "ok"

@app.route("/get_proof/<sub>")
def get_proof(sub):
    if sub in PROOFS:
        return jsonify({"status": "ok", "data": PROOFS[sub]})
    return jsonify({"status": "error", "msg": "subdomain not authorized"}), 404

@app.route("/pubkey")
def pubkey():
    if os.path.exists(PUBKEY_F):
        with open(PUBKEY_F, "r", encoding="utf-8") as f:
            return jsonify({"status": "ok", "pubkey": f.read()})
    return jsonify({"status": "error", "msg": "no pubkey"}), 404

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8444,
        ssl_context=("certs/wildcard.crt", "certs/wildcard.key"),
        debug=False
    )
