import os
import subprocess
from merkle.merkle_tree import MerkleTree

ZONE_FILE = "/etc/bind/db.example.com"
ROOT_FILE = "last_root.txt"
DOMAIN = "example.com"

SUBS = ["www", "api", "mail", "internal"]


# ========================
# 1. 生成 Merkle
# ========================
def generate_merkle():
    tree = MerkleTree(SUBS)
    root = tree.get_root()

    proofs = {}
    for i, sub in enumerate(SUBS):
        proofs[sub] = tree.get_proof(i)

    return root, proofs


# ========================
# 2. 检测 root 是否变化
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
# 3. 生成 zone
# ========================
def generate_zone(root, proofs):
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

    for sub in SUBS:
        proof_items = [f"{d}:{h}" for d, h in proofs[sub]]
        zone += f'{sub} IN TXT "proof={",".join(proof_items)}"\n'

    zone += """
$INCLUDE "/etc/bind/Kexample.com.+008+05836.key"
$INCLUDE "/etc/bind/Kexample.com.+008+22681.key"
"""

    return zone


# ========================
# 4. 写入 zone
# ========================
def write_zone(zone_text):
    print("✍️ 写入 zone 文件...")
    with open("db.example.com.tmp", "w") as f:
        f.write(zone_text)

    subprocess.run(["sudo", "mv", "db.example.com.tmp", ZONE_FILE], check=True)


# ========================
# 5. DNSSEC 签名
# ========================
def sign_zone():
    print("🔐 DNSSEC 签名...")
    subprocess.run([
        "sudo",
        "dnssec-signzone",
        "-K", "/etc/bind",
        "-o", DOMAIN,
        ZONE_FILE
    ], check=True)


# ========================
# 6. reload BIND
# ========================
def reload_bind():
    print("🔄 重载 BIND9...")
    subprocess.run(["sudo", "systemctl", "restart", "bind9"], check=True)


# ========================
# 7. 客户端验证
# ========================
def run_client_verify():
    print("🧪 客户端验证...")
    subprocess.run(["python", "-m", "client.client_verify"], check=True)


# ========================
# 主流程（升级版）
# ========================
def main():
    root, proofs = generate_merkle()
    print("🌳 New Root:", root)

    if not root_changed(root):
        print("✅ Root 未变化，跳过更新")
        return

    print("⚠️ Root 发生变化，更新 DNS...")

    zone = generate_zone(root, proofs)
    write_zone(zone)
    sign_zone()
    reload_bind()

    save_root(root)

    run_client_verify()

    print("🎉 全流程完成！")


if __name__ == "__main__":
    main()

