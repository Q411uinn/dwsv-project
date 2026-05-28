"""
benchmarks/ts_boundary.py
时间戳边界条件测试

对应论文 §3.2（目标 G3：防重放性）和 §3.9.5（Step 3 时间戳有效性检查）：
验证 ts ∈ [t_now - Δ, t_now] 的边界条件均正确生效
Δ = 600 秒（10 分钟）
"""
import sys, os, json, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from merkle.merkle_tree import verify_proof
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

STATE_F  = os.path.join(os.path.dirname(__file__), "..", "last_root.txt")
PROOF_F  = os.path.join(os.path.dirname(__file__), "..", "owner", "proofs.json")
KEY_F    = os.path.join(os.path.dirname(__file__), "..", "owner", "owner_key.pem")
PUBKEY_F = os.path.join(os.path.dirname(__file__), "..", "owner", "owner_pubkey.pem")

DELTA = 600   # 时间戳容忍窗口（秒）


def load_all():
    with open(STATE_F)  as f: state  = json.load(f)
    with open(PROOF_F)  as f: proofs = json.load(f)
    with open(KEY_F,    "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    with open(PUBKEY_F, "rb") as f:
        pubkey = serialization.load_pem_public_key(f.read())
    return state, proofs, key, pubkey


def proof_to_hex(proof):
    return "|".join(f"{d}:{h}" for d, h in proof)


def make_pi(sub, proof, root, epoch, ts, key):
    """用指定 ts 重新签名，构造一个增强证明结构"""
    ph  = proof_to_hex(proof)
    msg = f"{sub}|{ph}|{root}|{epoch}|{ts}".encode()
    sig = key.sign(msg, ec.ECDSA(hashes.SHA256()))
    return {
        "proof": proof,
        "sub":   sub,
        "root":  root,
        "epoch": epoch,
        "ts":    ts,
        "sigma": sig.hex()
    }


def step3_check(pi: dict) -> bool:
    """Step 3：时间戳有效性检查"""
    now = int(time.time())
    ts  = pi["ts"]
    return now - DELTA <= ts <= now + 5


def step4_check(pi: dict, pubkey) -> bool:
    """Step 4：签名合法性验证"""
    ph  = proof_to_hex(pi["proof"])
    msg = f"{pi['sub']}|{ph}|{pi['root']}|{pi['epoch']}|{pi['ts']}".encode()
    try:
        pubkey.verify(bytes.fromhex(pi["sigma"]), msg, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def step5_check(pi: dict, root: str) -> bool:
    """Step 5：Merkle 路径验证"""
    proof = [(int(d), h) for d, h in pi["proof"]]
    return verify_proof(pi["sub"], proof, root)


def run():
    state, proofs, key, pubkey = load_all()
    root  = state["root"]
    epoch = state["epoch"]
    sub   = list(proofs.keys())[0]
    proof = proofs[sub]["proof"]
    now   = int(time.time())

    # 定义边界测试用例
    cases = [
        # (描述, ts偏移量, 预期Step3结果, 说明)
        ("ts = now（当前时刻）",         0,        True,  "窗口内，应通过"),
        ("ts = now - 300（5分钟前）",   -300,      True,  "窗口内，应通过"),
        ("ts = now - 599（窗口边界内）",-599,      True,  "窗口内边界，应通过"),
        ("ts = now - 600（恰好边界）",  -600,      True,  "窗口边界，应通过"),
        ("ts = now - 601（超出1秒）",   -601,      False, "超出窗口，应拒绝"),
        ("ts = now - 3600（1小时前）",  -3600,     False, "超时重放，应拒绝"),
        ("ts = now + 10（未来时间戳）",  10,        False, "未来时间戳，应拒绝"),
        ("ts = now + 100（未来时间戳）", 100,       False, "未来时间戳，应拒绝"),
    ]

    print("=" * 72)
    print("  时间戳边界条件测试（Step 3，Δ=600s）")
    print("=" * 72)
    print(f"{'用例描述':<34} {'预期':^5} {'Step3':^7} {'Step4':^7} {'Step5':^7} {'结果'}")
    print("-" * 72)

    all_pass = True
    for desc, offset, expected_step3, note in cases:
        ts = now + offset
        pi = make_pi(sub, proof, root, epoch, ts, key)

        s3 = step3_check(pi)
        # 只有 Step3 通过才继续验证后续步骤
        s4 = step4_check(pi, pubkey) if s3 else None
        s5 = step5_check(pi, root)   if s3 else None

        # 整体 valid = s3 and s4 and s5
        valid    = s3 and (s4 is not False) and (s5 is not False)
        expected = expected_step3   # 主要验证 Step3 是否按预期工作
        correct  = (s3 == expected)
        if not correct:
            all_pass = False

        s3_str = "通过" if s3        else "拒绝"
        s4_str = "通过" if s4        else ("拒绝" if s4 is False else "跳过")
        s5_str = "通过" if s5        else ("拒绝" if s5 is False else "跳过")
        icon   = "✓" if correct else "✗ FAIL"

        print(f"{desc:<34} {'通过' if expected else '拒绝':^5} "
              f"{s3_str:^7} {s4_str:^7} {s5_str:^7} {icon}")

    print("=" * 72)
    print(f"  总结：{'全部边界条件符合预期 ✓' if all_pass else '存在边界条件异常 ✗'}")
    print("  说明：Step3 拒绝时，后续步骤跳过（fail-closed 策略）")
    print("=" * 72)


if __name__ == "__main__":
    run()
