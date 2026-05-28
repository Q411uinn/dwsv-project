"""
benchmarks/proof_size.py
Proof 大小量化测试

对应论文 §3.7：证明 proof 长度为 O(log n)，
传输开销远小于 TLS 证书，满足在线实时传输需求
"""
import sys, os, json, math
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from merkle.merkle_tree import MerkleTree

# TLS 证书典型大小（字节），用作对比基准
TLS_CERT_BYTES = 2500   # 约 2.5 KB，典型 2048-bit RSA 证书链


def measure_proof_size(n: int):
    """
    构建 n 个子域的 Merkle 树，测量 proof 的原始结构大小和序列化大小
    """
    subs  = [f"sub{i}" for i in range(n)]
    tree  = MerkleTree(subs)
    proof = tree.get_proof(0)   # 取第 0 个叶节点的 proof

    k = len(proof)              # 路径深度 = ⌈log₂n⌉

    # 原始结构：list of (int, 64-char hex)
    # 每个节点 = 1 字节方向 + 32 字节哈希 = 33 字节（二进制）
    raw_bytes = k * (1 + 32)

    # JSON 序列化大小（实际网络传输时的大小）
    serialized = json.dumps(proof)
    json_bytes  = len(serialized.encode("utf-8"))

    # 增强结构 Π 额外字段：sub(max 64) + root(64) + epoch(4) + ts(8) + sigma(~72)
    pi_overhead = 64 + 64 + 4 + 8 + 72
    pi_total    = json_bytes + pi_overhead

    return {
        "n":          n,
        "k":          k,
        "raw_bytes":  raw_bytes,
        "json_bytes": json_bytes,
        "pi_bytes":   pi_total
    }


def run():
    sizes = [8, 16, 64, 256, 1024, 4096]

    print("=" * 72)
    print("  Proof 大小量化（对应论文 §3.7）")
    print("=" * 72)
    print(f"{'n':>6}  {'k=⌈log₂n⌉':>10}  {'二进制(B)':>10}  "
          f"{'JSON(B)':>8}  {'Π总计(B)':>9}  {'vs TLS证书':>10}")
    print("-" * 72)

    for n in sizes:
        r = measure_proof_size(n)
        ratio = r["pi_bytes"] / TLS_CERT_BYTES
        print(f"{r['n']:>6}  {r['k']:>10}  {r['raw_bytes']:>10}  "
              f"{r['json_bytes']:>8}  {r['pi_bytes']:>9}  "
              f"{ratio:>9.1%}")

    print("=" * 72)
    print(f"  参考：典型 TLS 证书大小约 {TLS_CERT_BYTES} 字节（2.5 KB）")
    print("  Proof 大小随 n 对数增长，n=1024 时仍远小于 TLS 证书")
    print("=" * 72)

    # 额外：计算单次 proof 在典型网络下的传输时间
    print("\n  不同网络条件下 n=1024 的 proof 传输时间估算：")
    n1024 = measure_proof_size(1024)
    bits  = n1024["pi_bytes"] * 8
    for label, bps in [("4G（10 Mbps）", 10e6),
                       ("宽带（100 Mbps）", 100e6),
                       ("本地回环（1 Gbps）", 1e9)]:
        ms = bits / bps * 1000
        print(f"    {label:<22}: {ms:.4f} ms")


if __name__ == "__main__":
    run()
