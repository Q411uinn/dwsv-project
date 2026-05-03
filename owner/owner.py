import os
import subprocess
from merkle.merkle_tree import MerkleTree
from datetime import datetime
import json
import csv

ZONE_FILE = "/etc/bind/db.example.com"
ROOT_FILE = "last_root.txt"
DOMAIN = "example.com"
SUBS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "subs.txt")
DEFAULT_SUBS = ["www", "api", "mail", "internal"]

# 日志路径
LOG_DIR = "logs"
ROOT_LOG_CSV = os.path.join(LOG_DIR, "root_changes.csv")
ROOT_LOG_JSON = os.path.join(LOG_DIR, "root_changes.json")
os.makedirs(LOG_DIR, exist_ok=True)

# ========================
# 读取子域列表
# ========================
def load_subs():
    if not os.path.exists(SUBS_FILE):
        print(f"⚠️ {SUBS_FILE} 不存在，使用默认子域列表")
        return DEFAULT_SUBS
    with open(SUBS_FILE, "r") as f:
        subs = [line.strip() for line in f if line.strip()]
    return subs if subs else DEFAULT_SUBS

# ========================
# 生成 Merkle + proof
# ========================
def generate_merkle(subs):
    tree = MerkleTree(subs)
    root = tree.get_root()
    proofs = {sub: tree.get_proof(i) for i, sub in enumerate(subs)}
    return root, proofs

# ========================
# 检测 root 是否变化
# ========================
def root_changed(new_root):
    if not os.path.exists(ROOT_FILE):
        return True
    with open(ROOT_FILE, "r") as f:
        old_root = f.read().strip()
    return old_root != new_root

def save_root(root):
    with open(ROOT_FILE, "w") as f:
        f.write(root)

# ========================
# root 变化日志
# ========================
def log_root_change(new_root):
    timestamp = datetime.now().isoformat()
    log_entry = {"timestamp": timestamp, "root": new_root}

    # CSV 日志
    file_exists = os.path.exists(ROOT_LOG_CSV)
    with open(ROOT_LOG_CSV, mode="a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=log_entry.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(log_entry)

    # JSON 日志
    if os.path.exists(ROOT_LOG_JSON):
        with open(ROOT_LOG_JSON, "r") as f:
            data = json.load(f)
    else:
        data = []
    data.append(log_entry)
    with open(ROOT_LOG_JSON, "w") as f:
        json.dump(data, f, indent=2)

# ========================
# 生成 zone
# ========================
def generate_zone(root, proofs, subs):
    zone = f"""$TTL 3600
@   IN  SOA ns1.{DOMAIN}. admin.{DOMAIN}. (
        2026032601
        3600
        1800
        604800
        86400
)
@       IN  NS      ns1.{DOMAIN}.
ns1     IN  A       127.0.0.1
_auth   IN TXT "v=1; c={root}; policy=enforced"
"""
    #注释掉 proof 发布（避免 DNS TXT 超长）
    #for sub in subs:
        #proof_items = [f"{d}:{h}" for d, h in proofs[sub]]
        #zone += f'{sub} IN TXT "proof={",".join(proof_items)}"\n'

    zone += """
$INCLUDE "/etc/bind/Kexample.com.+008+05836.key"
$INCLUDE "/etc/bind/Kexample.com.+008+22681.key"
"""
    return zone

# ========================
# 写 zone + DNSSEC + reload
# ========================
def write_zone(zone_text):
    with open("db.example.com.tmp", "w") as f:
        f.write(zone_text)
    subprocess.run(["sudo", "mv", "db.example.com.tmp", ZONE_FILE], check=True)

def sign_zone():
    subprocess.run(["sudo", "dnssec-signzone", "-K", "/etc/bind", "-o", DOMAIN, ZONE_FILE], check=True)

def reload_bind():
    subprocess.run(["sudo", "systemctl", "restart", "bind9"], check=True)

# ========================
# 主流程
# ========================
def main():
    subs = load_subs()
    root, proofs = generate_merkle(subs)
    # 保存 proofs.json（供 server 使用）
    proof_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proofs.json")

    with open(proof_path, "w") as f:
        json.dump(proofs, f, indent=2)

    print("📦 proofs.json 已更新")
    print("🌳 Merkle Root:", root)

    if root_changed(root):
        print("⚠️ Root 变化，更新 DNS...")
        zone = generate_zone(root, proofs, subs)
        try:
            write_zone(zone)
            sign_zone()
            reload_bind()
            save_root(root)
            log_root_change(root)  # 新增日志
            print("✅ DNS 更新完成，root 已记录到日志")
        except Exception as e:
            print(f"❌ 更新失败: {e}")
    else:
        print("✅ Root 未变化，跳过更新")

if __name__ == "__main__":
    main()
