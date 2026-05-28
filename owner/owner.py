"""
owner/owner.py  —  域名所有者模块

改动说明（相比原版）：
1. 生成增强证明结构 Pi = {proof, sub, root, epoch, ts, sigma}
   其中 sigma = ECDSA.sign(sub || proof_hex || root || epoch || ts)
2. epoch 从 last_root.txt 读取并递增，实现前向安全性
3. proofs.json 存储完整增强结构，供 server 按需分发
4. generate_zone 格式更新，TXT 记录含 epoch 和 ts 字段
"""
import os, json, csv, time, hashlib, subprocess
from datetime import datetime
from merkle.merkle_tree import MerkleTree
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

ZONE_FILE   = "/etc/bind/db.example.com"
DOMAIN      = "example.com"
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
SUBS_FILE   = os.path.join(BASE_DIR, "subs.txt")
PROOF_FILE  = os.path.join(BASE_DIR, "proofs.json")
KEY_FILE    = os.path.join(BASE_DIR, "owner_key.pem")
PUBKEY_FILE = os.path.join(BASE_DIR, "owner_pubkey.pem")
STATE_FILE  = os.path.join(BASE_DIR, "..", "last_root.txt")
LOG_DIR     = os.path.join(BASE_DIR, "..", "logs")
ROOT_LOG_CSV  = os.path.join(LOG_DIR, "root_changes.csv")
ROOT_LOG_JSON = os.path.join(LOG_DIR, "root_changes.json")
DEFAULT_SUBS  = ["www", "api", "mail", "internal"]
os.makedirs(LOG_DIR, exist_ok=True)


# ── 密钥管理 ──────────────────────────────────────────────────────────────
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))
    with open(PUBKEY_FILE, "wb") as f:
        f.write(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return key


# ── 子域列表 ──────────────────────────────────────────────────────────────
def load_subs():
    if not os.path.exists(SUBS_FILE):
        return DEFAULT_SUBS
    with open(SUBS_FILE) as f:
        subs = [l.strip() for l in f if l.strip()]
    return subs or DEFAULT_SUBS


# ── Epoch 管理 ────────────────────────────────────────────────────────────
def load_epoch() -> int:
    if not os.path.exists(STATE_FILE):
        return 0
    with open(STATE_FILE) as f:
        try:
            data = json.load(f)
            return int(data.get("epoch", 0))
        except Exception:
            return 0


def save_state(root: str, epoch: int):
    with open(STATE_FILE, "w") as f:
        json.dump({"root": root, "epoch": epoch}, f)


# ── 签名工具 ──────────────────────────────────────────────────────────────
def sign_message(key, message: str) -> str:
    sig = key.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
    return sig.hex()


def proof_to_hex(proof: list) -> str:
    """将 proof list 序列化为确定性字符串，用于签名"""
    return "|".join(f"{d}:{h}" for d, h in proof)


# ── 生成增强证明结构 ──────────────────────────────────────────────────────
def generate_enhanced_proofs(subs: list, key) -> tuple:
    tree  = MerkleTree(subs)
    root  = tree.get_root()
    epoch = load_epoch() + 1
    ts    = int(time.time())

    enhanced = {}
    for i, sub in enumerate(subs):
        proof     = tree.get_proof(i)
        proof_hex = proof_to_hex(proof)
        msg       = f"{sub}|{proof_hex}|{root}|{epoch}|{ts}"
        sigma     = sign_message(key, msg)
        enhanced[sub] = {
            "proof":  proof,
            "sub":    sub,
            "root":   root,
            "epoch":  epoch,
            "ts":     ts,
            "sigma":  sigma
        }
    return root, epoch, ts, enhanced


# ── DNS Zone 生成 ─────────────────────────────────────────────────────────
def generate_zone(root: str, epoch: int, ts: int) -> str:
    return f"""$TTL 3600
@   IN  SOA ns1.{DOMAIN}. admin.{DOMAIN}. (
        2026032601 3600 1800 604800 86400 )
@       IN  NS      ns1.{DOMAIN}.
ns1     IN  A       127.0.0.1
_auth   IN  TXT     "v=DWSV1; c={root}; epoch={epoch}; ts={ts}"

$INCLUDE "/etc/bind/Kexample.com.+008+08047.key"
$INCLUDE "/etc/bind/Kexample.com.+008+38305.key"
"""


# ── 日志 ──────────────────────────────────────────────────────────────────
def log_root_change(root: str, epoch: int):
    entry = {"timestamp": datetime.now().isoformat(),
             "root": root, "epoch": epoch}
    with open(ROOT_LOG_CSV, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=entry.keys())
        if f.tell() == 0:
            w.writeheader()
        w.writerow(entry)
    data = []
    if os.path.exists(ROOT_LOG_JSON):
        with open(ROOT_LOG_JSON) as f:
            data = json.load(f)
    data.append(entry)
    with open(ROOT_LOG_JSON, "w") as f:
        json.dump(data, f, indent=2)


# ── 主流程 ────────────────────────────────────────────────────────────────
def main():
    key   = load_or_create_key()
    subs  = load_subs()
    root, epoch, ts, enhanced = generate_enhanced_proofs(subs, key)

    with open(PROOF_FILE, "w") as f:
        json.dump(enhanced, f, indent=2)

    print(f"Merkle Root : {root}")
    print(f"Epoch       : {epoch}")
    print(f"Timestamp   : {ts}")
    print(f"proofs.json 已更新（含 sigma）")

    zone = generate_zone(root, epoch, ts)
    try:
        with open("db.example.com.tmp", "w") as f:
            f.write(zone)
        subprocess.run(["sudo", "mv", "db.example.com.tmp", ZONE_FILE], check=True)
        subprocess.run(["sudo", "dnssec-signzone", "-K", "/etc/bind",
                        "-o", DOMAIN, ZONE_FILE], check=True)
        subprocess.run(["sudo", "systemctl", "restart", "bind9"], check=True)
        save_state(root, epoch)
        log_root_change(root, epoch)
        print("DNS 更新完成")
    except Exception as e:
        print(f"DNS 更新跳过（非 BIND 环境）: {e}")
        save_state(root, epoch)

if __name__ == "__main__":
    main()
