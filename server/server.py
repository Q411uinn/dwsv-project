import json
from flask import Flask, jsonify
import os

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
proof_path = os.path.join(BASE_DIR, "..", "owner", "proofs.json")

with open(proof_path) as f:
    proofs = json.load(f)

@app.route("/get_proof/<sub>")
def get_proof(sub):
    if sub in proofs:
        return jsonify({
            "status": "ok",
            "proof": proofs[sub]
        })
    else:
        return jsonify({
            "status": "error",
            "msg": "no proof"
        })


if __name__ == "__main__":
    app.run(port=5000)
