"""
attacks/fake_proof_attack.py  —  安全性实验：攻击场景模拟

覆盖三类攻击（对应论文第 4 章）：
1. 直接伪造 proof 路径攻击（G2：防伪造性）
2. 路径拼接攻击（G2：路径完整性）
3. 跨 epoch 重放攻击（G4：前向安全性）
"""
import json, os, time, random
from merkle.merkle_tree import MerkleTree, verify_proof, hash_node, hash_leaf

BASE     = os.path.dirname(os.path.abspath(__file__))
PROOF_F  = os.path.join(BASE, "..", "owner", "proofs.json")
STATE_F  = os.path.join(BASE, "..", "last_root.txt")


def load_state():
    with open(STATE_F) as f:
        return json.load(f)

def load_proofs():
    with open(PROOF_F) as f:
        return json.load(f)

def random_hash():
    return hash_node(str(random.random()), str(random.random()))


# ── 攻击 1：直接伪造 proof 路径 ───────────────────────────────────────────
def attack_fake_proof(root: str, target: str = "evil", depth: int = 4):
    print(f"\n[攻击1] 直接伪造 proof 路径  target={target}")
    fake_proof = [(random.randint(0,1), random_hash()) for _ in range(depth)]
    result = verify_proof(target, fake_proof, root)
    print(f"  伪造 proof 验证结果: {result}  (预期: False)")
    assert not result, "FAIL: 伪造 proof 通过了验证！"
    print("  PASS: 伪造攻击被成功拦截")
    return not result


# ── 攻击 2：路径拼接攻击 ──────────────────────────────────────────────────
def attack_path_splicing(root: str, proofs: dict, target: str = "evil"):
    print(f"\n[攻击2] 路径拼接攻击  target={target}")
    # 从两个合法 proof 中拼接节点
    keys = list(proofs.keys())
    if len(keys) < 2:
        print("  SKIP: proof 数量不足")
        return True
    p1 = [(int(d), h) for d, h in proofs[keys[0]]["proof"]]
    p2 = [(int(d), h) for d, h in proofs[keys[1]]["proof"]]
    spliced = p1[: len(p1)//2] + p2[len(p2)//2 :]
    result = verify_proof(target, spliced, root)
    print(f"  拼接 proof 验证结果: {result}  (预期: False)")
    assert not result, "FAIL: 路径拼接攻击通过了验证！"
    print("  PASS: 路径拼接攻击被成功拦截")
    return not result


# ── 攻击 3：跨 epoch 重放攻击 ────────────────────────────────────────────
def attack_epoch_replay(proofs: dict, first_sub: str):
    print(f"\n[攻击3] 跨 epoch 重放攻击  sub={first_sub}")
    old_epoch = proofs[first_sub]["epoch"]

    # 模拟 epoch 更新：重建 Merkle 树（新增一个子域触发变化）
    subs_file = os.path.join(BASE, "..", "owner", "subs.txt")
    with open(subs_file) as f:
        subs = [l.strip() for l in f if l.strip()]

    new_subs = subs + ["extra_new"]
    new_tree = MerkleTree(new_subs)
    new_root = new_tree.get_root()

    # 用旧 proof 对新 root 验证
    old_proof = [(int(d), h) for d, h in proofs[first_sub]["proof"]]
    result = verify_proof(first_sub, old_proof, new_root)
    print(f"  旧 proof 在新 root 下验证结果: {result}  (预期: False)")
    assert not result, "FAIL: 跨 epoch 重放攻击通过了验证！"
    print("  PASS: 跨 epoch 重放攻击被成功拦截")
    return not result


def main():
    print("=" * 55)
    print("  DWSV 安全性实验：攻击场景模拟")
    print("=" * 55)

    state  = load_state()
    proofs = load_proofs()
    root   = state["root"]
    subs   = list(proofs.keys())

    r1 = attack_fake_proof(root, target="evil", depth=len(proofs[subs[0]]["proof"]))
    r2 = attack_path_splicing(root, proofs, target="evil")
    r3 = attack_epoch_replay(proofs, first_sub=subs[0])

    print("\n" + "=" * 55)
    all_pass = r1 and r2 and r3
    print(f"  总结: {'全部攻击被拦截 ✓' if all_pass else '存在安全漏洞 ✗'}")
    print("=" * 55)


if __name__ == "__main__":
    main()

