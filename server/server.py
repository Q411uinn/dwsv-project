"""
server/server.py  —  证明服务器

改动说明（相比原版）：
1. 返回完整增强证明结构 Pi（含 sub/root/epoch/ts/sigma）
2. 新增 /pubkey 端点，供客户端获取验签公钥
3. 启动时验证 proofs.json 可读
"""
import json, os
from flask import Flask, jsonify

app     = Flask(__name__)
BASE    = os.path.dirname(os.path.abspath(__file__))
PROOF_F = os.path.join(BASE, "..", "owner", "proofs.json")
PUBKEY_F= os.path.join(BASE, "..", "owner", "owner_pubkey.pem")

with open(PROOF_F) as f:
    PROOFS = json.load(f)


@app.route("/get_proof/<sub>")
def get_proof(sub):
    if sub in PROOFS:
        return jsonify({"status": "ok", "data": PROOFS[sub]})
    return jsonify({"status": "error", "msg": "subdomain not authorized"}), 404


@app.route("/pubkey")
def pubkey():
    if os.path.exists(PUBKEY_F):
        with open(PUBKEY_F) as f:
            return jsonify({"status": "ok", "pubkey": f.read()})
    return jsonify({"status": "error", "msg": "no pubkey"}), 404


@app.route("/health")
def health():
    return jsonify({"status": "ok", "subdomains": list(PROOFS.keys())})


if __name__ == "__main__":
    app.run(port=5000, debug=False)

