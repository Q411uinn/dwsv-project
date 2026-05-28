"""
benchmarks/performance_test.py  —  性能评估主模块

测试指标（对应论文第 5 章表 5-3、5-4）：
1. Merkle 树构建时间（随子域规模 n 变化）
2. 单次路径验证时间（随 n 变化）
3. 签名生成与验证时间
4. 端对端单次连接总开销
各项重复 REPEAT 次取均值，输出表格形式。
"""
import time, os, json, sys, statistics
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from merkle.merkle_tree import MerkleTree, verify_proof
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

SERVER  = "http://127.0.0.1:5000"
REPEAT  = 50
STATE_F = os.path.join(os.path.dirname(__file__), "..", "last_root.txt")
PROOF_F = os.path.join(os.path.dirname(__file__), "..", "owner", "proofs.json")


def ms(seconds: float) -> float:
    return seconds * 1000


def mean_ms(times: list) -> float:
    return statistics.mean(times) * 1000


def load_state():
    with open(STATE_F) as f:
        return json.load(f)


def load_proofs():
    with open(PROOF_F) as f:
        return json.load(f)


def get_server_proof(sub: str):
    r = requests.get(f"{SERVER}/get_proof/{sub}", timeout=3)
    if r.status_code != 200:
        return None
    d = r.json()
    return d.get("data") if d.get("status") == "ok" else None


# ── 测试 1：Merkle 树构建时间 vs n ────────────────────────────────────────
def bench_tree_build(sizes=(8, 16, 64, 256, 1024)):
    print("\n── 测试1：Merkle 树构建时间（ms）─────────────────")
    print(f"{'n':>6}  {'k=⌈log₂n⌉':>10}  {'均值(ms)':>10}  {'最小(ms)':>10}")
    for n in sizes:
        subs = [f"sub{i}" for i in range(n)]
        times = []
        for _ in range(REPEAT):
            t0 = time.perf_counter()
            tree = MerkleTree(subs)
            times.append(time.perf_counter() - t0)
        import math
        k = math.ceil(math.log2(n)) if n > 1 else 1
        print(f"{n:>6}  {k:>10}  {mean_ms(times):>10.3f}  {min(times)*1000:>10.3f}")


# ── 测试 2：单次路径验证时间 vs n ────────────────────────────────────────
def bench_verify(sizes=(8, 16, 64, 256, 1024)):
    print("\n── 测试2：单次 Merkle 路径验证时间（ms）─────────")
    print(f"{'n':>6}  {'k':>4}  {'均值(ms)':>10}  {'最小(ms)':>10}")
    for n in sizes:
        subs = [f"sub{i}" for i in range(n)]
        tree = MerkleTree(subs)
        root = tree.get_root()
        proof = tree.get_proof(0)
        times = []
        for _ in range(REPEAT):
            t0 = time.perf_counter()
            verify_proof("sub0", proof, root)
            times.append(time.perf_counter() - t0)
        import math
        k = math.ceil(math.log2(n)) if n > 1 else 1
        print(f"{n:>6}  {k:>4}  {mean_ms(times):>10.4f}  {min(times)*1000:>10.4f}")


# ── 测试 3：签名生成与验证时间 ───────────────────────────────────────────
def bench_signature():
    print("\n── 测试3：ECDSA-P256 签名生成与验证时间（ms）───")
    key    = ec.generate_private_key(ec.SECP256R1())
    pubkey = key.public_key()
    msg    = b"sub0|proof_hex|root|1|1700000000"

    sign_times, verify_times = [], []
    for _ in range(REPEAT):
        t0 = time.perf_counter()
        sig = key.sign(msg, ec.ECDSA(hashes.SHA256()))
        sign_times.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        pubkey.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        verify_times.append(time.perf_counter() - t0)

    print(f"  签名生成均值: {mean_ms(sign_times):.3f} ms")
    print(f"  签名验证均值: {mean_ms(verify_times):.3f} ms")


# ── 测试 4：端对端单次连接总开销（需要 server 运行）────────────────────
def bench_e2e(sub: str = "sub0"):
    print(f"\n── 测试4：端对端单次连接开销（sub={sub}，重复{REPEAT}次）")
    try:
        state  = load_state()
        pubkey_pem = requests.get(f"{SERVER}/pubkey", timeout=3).json()["pubkey"]
        pubkey = serialization.load_pem_public_key(pubkey_pem.encode())
    except Exception as e:
        print(f"  Server 未运行，跳过端对端测试: {e}")
        return

    root  = state["root"]
    epoch = state["epoch"]

    times = {"dns": [], "proof_fetch": [], "verify": [], "total": []}
    for _ in range(REPEAT):
        t_total = time.perf_counter()

        # Step 1: DNS（模拟读取本地状态）
        t0 = time.perf_counter()
        s  = load_state()
        times["dns"].append(time.perf_counter() - t0)

        # Step 2-3: 从 server 获取 proof
        t0 = time.perf_counter()
        pi = get_server_proof(sub)
        times["proof_fetch"].append(time.perf_counter() - t0)

        if pi is None:
            print(f"  {sub} 无 proof，跳过")
            return

        # Step 4-5: 本地验证
        t0 = time.perf_counter()
        proof = [(int(d), h) for d, h in pi["proof"]]
        verify_proof(sub, proof, root)
        times["verify"].append(time.perf_counter() - t0)

        times["total"].append(time.perf_counter() - t_total)

    print(f"  DNS 状态读取   : {mean_ms(times['dns']):.3f} ms")
    print(f"  Proof 获取     : {mean_ms(times['proof_fetch']):.3f} ms")
    print(f"  本地验证       : {mean_ms(times['verify']):.4f} ms")
    print(f"  单次连接总计   : {mean_ms(times['total']):.3f} ms")


# ── 测试 5：算法层总开销（纯计算，无网络）───────────────────────────────
def bench_algo_only():
    print(f"\n── 测试5：算法层纯计算开销（无网络，重复{REPEAT}次）")
    subs  = [f"sub{i}" for i in range(16)]
    tree  = MerkleTree(subs)
    root  = tree.get_root()
    proof = tree.get_proof(0)
    key   = ec.generate_private_key(ec.SECP256R1())
    pubkey= key.public_key()
    msg   = b"sub0|proof_hex|root|1|1700000000"

    times = []
    for _ in range(REPEAT):
        t0 = time.perf_counter()
        # Merkle 验证
        verify_proof("sub0", proof, root)
        # 签名验证
        sig = key.sign(msg, ec.ECDSA(hashes.SHA256()))
        pubkey.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        times.append(time.perf_counter() - t0)

    print(f"  Merkle验证 + 签名验证均值: {mean_ms(times):.3f} ms")
    print(f"  （即 DWSV 引入的算法层额外开销）")


def main():
    print("=" * 55)
    print("  DWSV 性能评估")
    print("=" * 55)
    bench_tree_build()
    bench_verify()
    bench_signature()
    bench_e2e()
    bench_algo_only()
    print("\n" + "=" * 55)
    print("  测试完成")
    print("=" * 55)


if __name__ == "__main__":
    main()

