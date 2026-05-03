import time
import os
import requests
from dns_module.dns_query import query_txt
from merkle.merkle_tree import verify_proof

# ========================
# 路径处理（关键）
# ========================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SUBS_PATH = os.path.join(BASE_DIR, "..", "owner", "subs.txt")


# ========================
# 读取子域列表
# ========================
def load_subs():
    if not os.path.exists(SUBS_PATH):
        print("⚠️ subs.txt 不存在，使用默认子域")
        return ["www", "api", "mail", "internal"]

    with open(SUBS_PATH, "r") as f:
        subs = [line.strip() for line in f if line.strip()]

    return subs


# ========================
# 从 server 获取 proof
# ========================
def get_proof_from_server(sub):
    url = f"http://127.0.0.1:5000/get_proof/{sub}"

    try:
        r = requests.get(url, timeout=2)

        if r.status_code != 200:
            print(f"{sub}: ❌ server返回 {r.status_code}")
            return None

        data = r.json()

        if data.get("status") != "ok":
            print(f"{sub}: ❌ server无proof")
            return None

        return data.get("proof")

    except Exception as e:
        print(f"{sub}: ❌ 请求异常 {e}")
        return None


# ========================
# 提取 root
# ========================
def extract_root(txt_record):
    if not txt_record:
        return None

    txt = txt_record[0].strip('"')

    for p in txt.split(";"):
        if "c=" in p:
            return p.split("=")[1].strip()

    return None


# ========================
# DNS 测试
# ========================
def test_dns_time():
    start = time.time()
    txt = query_txt("_auth.example.com")
    end = time.time()
    return (end - start) * 1000, txt


# ========================
# 验证耗时
# ========================
def test_verify_time(sub, root):
    proof = get_proof_from_server(sub)

    if proof is None:
        return None

    start = time.time()
    valid = verify_proof(sub, proof, root)
    end = time.time()

    return (end - start) * 1000, valid
# ========================
# 验证耗时(all)
# ========================
def test_all_verify_time(subs, root):
    start = time.time()

    success = 0
    fail = 0

    for sub in subs:
        proof = get_proof_from_server(sub)

        if proof is None:
            fail += 1
            continue

        valid = verify_proof(sub, proof, root)

        if valid:
            success += 1
        else:
            fail += 1

    end = time.time()

    return (end - start) * 1000, success, fail
# ========================
# 端到端耗时
# ========================
def test_total_time(sub):
    start = time.time()

    txt = query_txt("_auth.example.com")
    root = extract_root(txt)

    proof = get_proof_from_server(sub)

    if proof is None:
        return None, False

    valid = verify_proof(sub, proof, root)

    end = time.time()

    return (end - start) * 1000, valid
# ========================
# 端到端耗时(all)
# ========================
def test_all_total_time(subs):
    start = time.time()

    txt = query_txt("_auth.example.com")
    root = extract_root(txt)

    success = 0
    fail = 0

    for sub in subs:
        proof = get_proof_from_server(sub)

        if proof is None:
            fail += 1
            continue

        valid = verify_proof(sub, proof, root)

        if valid:
            success += 1
        else:
            fail += 1

    end = time.time()

    return (end - start) * 1000, success, fail

def test_single_connection(sub):
    start = time.time()

    txt = query_txt("_auth.example.com")
    root = extract_root(txt)

    proof = get_proof_from_server(sub)
    verify_proof(sub, proof, root)

    end = time.time()

    print(f"单次连接耗时: {(end - start)*1000:.2f} ms")
    

# ========================
# 主函数
# ========================
def main():
    subs = load_subs()

    print("====== 性能测试开始 ======\n")
    
    print("\n单次连接测试：")
    test_single_connection("sub0")
    
    # 1️⃣ DNS 查询
    dns_time, txt = test_dns_time()
    root = extract_root(txt)

    print(f"DNS 查询耗时: {dns_time:.2f} ms\n")

    # 2️⃣ Merkle 总验证
    verify_time, success, fail = test_all_verify_time(subs, root)

    print("Merkle 验证总耗时:")
    print(f"总耗时: {verify_time:.2f} ms")
    print(f"成功: {success} | 失败: {fail}\n")

    # 3️⃣ 端到端
    total_time, success, fail = test_all_total_time(subs)

    print("端到端总耗时:")
    print(f"总耗时: {total_time:.2f} ms")
    print(f"成功: {success} | 失败: {fail}")
    
if __name__ == "__main__":
    main()
