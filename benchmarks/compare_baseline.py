import time
from dns_module.dns_query import query_txt, query_proof
from merkle.merkle_tree import verify_proof

TARGET = "www"

# -------------------------
# baseline（无验证）
# -------------------------
def baseline():
    start = time.time()

    # 模拟普通 DNS 查询
    query_txt("_auth.example.com")  # 用这个代替 A 查询即可

    end = time.time()
    return end - start


# -------------------------
# DWSV 流程
# -------------------------
def dwsv():
    start = time.time()

    # 1. root
    txt = query_txt("_auth.example.com")
    root = txt[0]

    # 2. proof
    proof = query_proof(TARGET)

    # 3. verify
    verify_proof(TARGET, proof, root)

    end = time.time()
    return end - start
    
    
def test_single_connection(sub):
    start = time.time()

    txt = query_txt("_auth.example.com")
    root = extract_root(txt)

    proof = get_proof_from_server(sub)
    verify_proof(sub, proof, root)

    end = time.time()

    print(f"单次连接耗时: {(end - start)*1000:.2f} ms")
    

# -------------------------
# 多次测试
# -------------------------
def run_test(n=50):
    base_times = []
    dwsv_times = []

    for _ in range(n):
        base_times.append(baseline())
        dwsv_times.append(dwsv())

    avg_base = sum(base_times) / n
    avg_dwsv = sum(dwsv_times) / n
    
    print("===== 性能对比 =====")
    print(f"Baseline 平均耗时: {avg_base:.6f}s")
    print(f"DWSV 平均耗时:     {avg_dwsv:.6f}s")
    print(f"额外开销:         {avg_dwsv - avg_base:.6f}s")
    
    print("\n单次连接测试：")
    test_single_connection("sub0")
    
if __name__ == "__main__":
    run_test()
