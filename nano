import os
import sys
import time
import json
import statistics
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from merkle.merkle_tree import verify_proof
from client.client_verify import verify_sigma
from cryptography.hazmat.primitives import serialization

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_F = os.path.join(BASE, "last_root.txt")

URL = "https://www.example.test:8444/"
PROOF_URL = "https://www.example.test:8444/get_proof/www"
PUBKEY_URL = "https://www.example.test:8444/pubkey"

REPEAT = 50
DELTA = 600

total_times = []
https_times = []
proof_fetch_times = []
verify_times = []

def load_dns_state():
    with open(STATE_F, "r", encoding="utf-8") as f:
        return json.load(f)

def get_pubkey():
    r = requests.get(PUBKEY_URL, verify=False, timeout=5)
    r.raise_for_status()
    pem = r.json()["pubkey"]
    return serialization.load_pem_public_key(pem.encode())

for _ in range(REPEAT):
    t_total = time.perf_counter()

    # Step 0: 普通 HTTPS 请求，模拟通配符 TLS 连接
    t0 = time.perf_counter()
    r = requests.get(URL, verify=False, timeout=5)
    r.raise_for_status()
    https_times.append((time.perf_counter() - t0) * 1000)

    # Step 1: 获取 DWSV proof
    t0 = time.perf_counter()
    proof_resp = requests.get(PROOF_URL, verify=False, timeout=5)
    proof_resp.raise_for_status()
    pi = proof_resp.json()["data"]
    proof_fetch_times.append((time.perf_counter() - t0) * 1000)

    # Step 2: 本地验证
    t0 = time.perf_counter()

    dns_state = load_dns_state()
    trusted_root = dns_state["root"]
    trusted_epoch = dns_state["epoch"]

    # epoch 检查
    if pi.get("epoch") != trusted_epoch:
        raise RuntimeError("epoch mismatch")

    # timestamp 检查
    now = int(time.time())
    ts = pi.get("ts", 0)
    if not (now - DELTA <= ts <= now + 5):
        raise RuntimeError("timestamp expired")

    # 签名验证
    pubkey = get_pubkey()
    if not verify_sigma(pubkey, pi):
        raise RuntimeError("signature invalid")

    # Merkle 路径验证
    proof = [(int(d), h) for d, h in pi["proof"]]
    if not verify_proof("www", proof, trusted_root):
        raise RuntimeError("merkle proof invalid")

    verify_times.append((time.perf_counter() - t0) * 1000)

    total_times.append((time.perf_counter() - t_total) * 1000)

print("通配符 HTTPS + DWSV 授权验证")
print(f"https request avg(ms): {statistics.mean(https_times):.3f}")
print(f"proof fetch avg(ms):   {statistics.mean(proof_fetch_times):.3f}")
print(f"local verify avg(ms):  {statistics.mean(verify_times):.3f}")
print(f"total avg(ms):         {statistics.mean(total_times):.3f}")
print(f"total median(ms):      {statistics.median(total_times):.3f}")
print(f"total std(ms):         {statistics.pstdev(total_times):.3f}")
