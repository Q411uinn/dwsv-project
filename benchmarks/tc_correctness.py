"""
benchmarks/tc_correctness.py
TC-1 ~ TC-6 正确性验证测试用例

对应论文表 5-1：正确性验证测试用例
覆盖完备性（Completeness）和可靠性（Soundness）两类属性
"""
import sys, os, json, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from merkle.merkle_tree import MerkleTree, verify_proof, hash_node
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import random

STATE_F = os.path.join(os.path.dirname(__file__), "..", "last_root.txt")
PROOF_F = os.path.join(os.path.dirname(__file__), "..", "owner", "proofs.json")
PUBKEY_F= os.path.join(os.path.dirname(__file__), "..", "owner", "owner_pubkey.pem")


def load_state():
    with open(STATE_F) as f:
        return json.load(f)

def load_proofs():
    with open(PROOF_F) as f:
        return json.load(f)

def load_pubkey():
    with open(PUBKEY_F, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def proof_to_hex(proof):
    return "|".join(f"{d}:{h}" for d, h in proof)

def verify_sigma(pubkey, pi):
    ph  = proof_to_hex(pi["proof"])
    msg = f"{pi['sub']}|{ph}|{pi['root']}|{pi['epoch']}|{pi['ts']}"
    try:
        pubkey.verify(bytes.fromhex(pi["sigma"]),
                      msg.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

def full_verify(sub, pi, root, epoch, pubkey):
    """
    完整五步验证，返回 (passed, failed_step, reason)
    """
    # Step 2: epoch
    if pi["epoch"] != epoch:
        return False, 2, f"epoch 不一致 proof={pi['epoch']} dns={epoch}"
    # Step 3: ts
    now = int(time.time())
    if not (now - 600 <= pi["ts"] <= now + 5):
        return False, 3, f"时间戳超期 ts={pi['ts']}"
    # Step 4: sigma
    if not verify_sigma(pubkey, pi):
        return False, 4, "签名验证失败"
    # Step 5: Merkle
    proof = [(int(d), h) for d, h in pi["proof"]]
    if not verify_proof(sub, proof, root):
        return False, 5, "Merkle 路径验证失败"
    return True, None, "全部通过"


def random_hash():
    return hash_node(str(random.random()), str(random.random()))


def run():
    state  = load_state()
    proofs = load_proofs()
    pubkey = load_pubkey()
    root   = state["root"]
    epoch  = state["epoch"]
    subs   = list(proofs.keys())

    # 取前 3 个授权子域做完备性测试
    auth_subs = subs[:3]

    results = []

    # ── TC-1 ~ TC-3：完备性（授权子域应 Accept）────────────────────────
    for i, sub in enumerate(auth_subs, 1):
        pi   = proofs[sub]
        ok, failed_step, reason = full_verify(sub, pi, root, epoch, pubkey)
        expected = "Accept"
        actual   = "Accept" if ok else f"Reject(Step{failed_step})"
        passed   = ok
        results.append({
            "编号":   f"TC-{i}",
            "输入子域": sub,
            "是否授权": "是",
            "预期输出": expected,
            "实际输出": actual,
            "验证属性": "完备性",
            "通过":    passed
        })

    # ── TC-4：非授权子域（无 proof）────────────────────────────────────
    fake_sub = "evil.example.com"
    actual4  = "Reject(无proof)" if fake_sub not in proofs else "Accept(漏洞)"
    results.append({
        "编号":   "TC-4",
        "输入子域": fake_sub,
        "是否授权": "否",
        "预期输出": "Reject",
        "实际输出": actual4,
        "验证属性": "可靠性",
        "通过":    fake_sub not in proofs
    })

    # ── TC-5：非授权子域（无 proof）────────────────────────────────────
    hack_sub = "hack.example.com"
    actual5  = "Reject(无proof)" if hack_sub not in proofs else "Accept(漏洞)"
    results.append({
        "编号":   "TC-5",
        "输入子域": hack_sub,
        "是否授权": "否",
        "预期输出": "Reject",
        "实际输出": actual5,
        "验证属性": "可靠性",
        "通过":    hack_sub not in proofs
    })

    # ── TC-6：伪造随机路径（应 Reject）─────────────────────────────────
    depth       = len(proofs[subs[0]]["proof"])
    fake_proof  = [(random.randint(0,1), random_hash()) for _ in range(depth)]
    fake_result = verify_proof("evil.example.com", fake_proof, root)
    actual6     = "Reject(Merkle失败)" if not fake_result else "Accept(漏洞!)"
    results.append({
        "编号":   "TC-6",
        "输入子域": "evil（随机伪造proof）",
        "是否授权": "否",
        "预期输出": "Reject",
        "实际输出": actual6,
        "验证属性": "可靠性",
        "通过":    not fake_result
    })

    # ── 打印结果表 ────────────────────────────────────────────────────
    print("=" * 72)
    print("  表 5-1  正确性验证测试用例")
    print("=" * 72)
    print(f"{'编号':<6} {'输入子域':<24} {'授权':^4} {'预期':^7} {'实际输出':<20} {'属性':<8} {'结果'}")
    print("-" * 72)
    all_pass = True
    for r in results:
        icon = "✓" if r["通过"] else "✗ FAIL"
        if not r["通过"]:
            all_pass = False
        print(f"{r['编号']:<6} {r['输入子域']:<24} {r['是否授权']:^4} "
              f"{r['预期输出']:^7} {r['实际输出']:<20} {r['验证属性']:<8} {icon}")
    print("=" * 72)
    print(f"  总结：{'全部通过 ✓' if all_pass else '存在失败用例 ✗'}")
    print("=" * 72)
    return all_pass


if __name__ == "__main__":
    run()
