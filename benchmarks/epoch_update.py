"""
benchmarks/epoch_update.py
Epoch 更新开销测试

对应论文 §3.6.3 和 §3.8.2：
每次 epoch 更新需要重建 Merkle 树 + 为所有子域生成新 proof + 签名
测试该操作的总耗时，验证不同更新频率（按日/周）在实际规模下是否可行
"""
import sys, os, json, time, statistics
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from merkle.merkle_tree import MerkleTree
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

REPEAT = 20   # 每个规模重复次数


def proof_to_hex(proof):
    return "|".join(f"{d}:{h}" for d, h in proof)


def epoch_update_cost(n: int, key) -> dict:
    """
    模拟一次完整的 epoch 更新：
    1. 重建 Merkle 树（O(n) 哈希）
    2. 生成 n 条 proof（每条 O(log n) 哈希）
    3. 对每条 proof 签名（n 次 ECDSA 签名）
    """
    subs  = [f"sub{i}" for i in range(n)]
    epoch = 1
    ts    = int(time.time())

    times = {"build": [], "proof_gen": [], "sign": [], "total": []}

    for _ in range(REPEAT):
        t_total = time.perf_counter()

        # 1. 重建 Merkle 树
        t0 = time.perf_counter()
        tree = MerkleTree(subs)
        root = tree.get_root()
        times["build"].append(time.perf_counter() - t0)

        # 2. 生成所有 proof
        t0 = time.perf_counter()
        all_proofs = {sub: tree.get_proof(i) for i, sub in enumerate(subs)}
        times["proof_gen"].append(time.perf_counter() - t0)

        # 3. 对所有 proof 签名
        t0 = time.perf_counter()
        for sub, proof in all_proofs.items():
            ph  = proof_to_hex(proof)
            msg = f"{sub}|{ph}|{root}|{epoch}|{ts}".encode()
            key.sign(msg, ec.ECDSA(hashes.SHA256()))
        times["sign"].append(time.perf_counter() - t0)

        times["total"].append(time.perf_counter() - t_total)

    def ms(lst):
        return statistics.mean(lst) * 1000

    return {
        "n":         n,
        "build_ms":  ms(times["build"]),
        "proof_ms":  ms(times["proof_gen"]),
        "sign_ms":   ms(times["sign"]),
        "total_ms":  ms(times["total"])
    }


def run():
    key   = ec.generate_private_key(ec.SECP256R1())
    sizes = [16, 64, 256, 1024]

    print("=" * 72)
    print("  Epoch 更新开销（对应论文 §3.8.2 前向安全性设计）")
    print(f"  （每个规模重复 {REPEAT} 次取均值）")
    print("=" * 72)
    print(f"{'n':>6}  {'树构建(ms)':>11}  {'proof生成(ms)':>13}  "
          f"{'签名(ms)':>9}  {'总计(ms)':>9}  {'可行更新频率'}")
    print("-" * 72)

    for n in sizes:
        r = epoch_update_cost(n, key)

        # 判断更新频率可行性
        t = r["total_ms"]
        if t < 100:
            freq = "秒级触发可行"
        elif t < 1000:
            freq = "分钟级触发可行"
        elif t < 10000:
            freq = "小时级触发可行"
        else:
            freq = "建议按日更新"

        print(f"{r['n']:>6}  {r['build_ms']:>11.2f}  {r['proof_ms']:>13.2f}  "
              f"{r['sign_ms']:>9.2f}  {r['total_ms']:>9.2f}  {freq}")

    print("=" * 72)
    print("  说明：")
    print("  - 树构建：O(n) 哈希操作")
    print("  - proof生成：n × O(log n) 哈希操作")
    print("  - 签名：n 次 ECDSA-P256 签名（最耗时，约 0.2ms/次）")
    print("  - epoch 更新在 Owner 侧离线执行，不影响在线握手性能")
    print("=" * 72)


if __name__ == "__main__":
    run()
