#!/usr/bin/env python3
import hashlib
import datetime
import shutil

# -----------------------------
# Merkle Tree 工具
# -----------------------------
def hash_leaf(data):
    return hashlib.sha256(data.encode()).hexdigest()

def hash_node(left, right):
    return hashlib.sha256((left + right).encode()).hexdigest()

class MerkleTree:
    def __init__(self, leaves):
        self.leaves = [hash_leaf(l) for l in leaves]
        self.levels = []
        self.build_tree()

    def build_tree(self):
        nodes = self.leaves[:]
        self.levels.append(nodes)
        while len(nodes) > 1:
            if len(nodes) % 2 != 0:
                nodes.append(nodes[-1])
            parents = []
            for i in range(0, len(nodes), 2):
                parents.append(hash_node(nodes[i], nodes[i+1]))
            self.levels.append(parents)
            nodes = parents

    def get_root(self):
        return self.levels[-1][0]

    def get_proof(self, index):
        proof = []
        for level in self.levels[:-1]:
            if index % 2 == 0:
                sibling = level[index + 1] if index + 1 < len(level) else level[index]
            else:
                sibling = level[index - 1]
            proof.append(sibling)
            index //= 2
        return proof

# -----------------------------
# 更新 db.example.com
# -----------------------------
DB_FILE = "/etc/bind/db.example.com"
BACKUP_FILE = f"/etc/bind/db.example.com.bak_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"

# 子域列表
subdomains = ["www", "api", "mail", "internal"]

# 生成 Merkle Tree
tree = MerkleTree(subdomains)
root = tree.get_root()
proofs = {sub: tree.get_proof(i) for i, sub in enumerate(subdomains)}

# 备份原文件
shutil.copyfile(DB_FILE, BACKUP_FILE)
print(f"备份原文件到 {BACKUP_FILE}")

# 读取原文件，替换 TXT 记录
with open(DB_FILE, "r") as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if line.startswith("_auth"):
        # 替换 root
        new_lines.append(f'_auth    IN TXT "v=1; c={root}; policy=enforced"\n')
    elif any(line.startswith(sd) for sd in subdomains):
        # 替换 proof
        sd = line.split()[0]
        proof_str = ",".join(proofs[sd])
        new_lines.append(f'{sd}    IN TXT "proof={proof_str}"\n')
    elif line.strip().endswith("; Serial"):
        # 自动递增 SOA Serial
        parts = line.strip().split()
        old_serial = int(parts[0])
        new_serial = old_serial + 1
        parts[0] = str(new_serial)
        new_lines.append(" ".join(parts) + "\n")
    else:
        new_lines.append(line)

# 写回文件
with open(DB_FILE, "w") as f:
    f.writelines(new_lines)

print(f"✅ db.example.com 更新完成，root={root}")
print("请执行: sudo rndc reload example.com 让 BIND9 生效")

