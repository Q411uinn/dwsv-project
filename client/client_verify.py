import os
import csv
import json
import requests
from datetime import datetime
#from dns_module.dns_query import query_txt
from merkle.merkle_tree import verify_proof
from client.dnssec_chain_verify import verify_txt_with_dnssec

# 日志路径
LOG_DIR = "logs"
CSV_LOG = os.path.join(LOG_DIR, "verification_log.csv")
JSON_LOG = os.path.join(LOG_DIR, "verification_log.json")
os.makedirs(LOG_DIR, exist_ok=True)

def extract_root(txt_record):
    """从 _auth TXT 记录中提取 Merkle Root"""
    if not txt_record:
        return None
    txt = txt_record[0].strip('"')
    parts = txt.split(";")
    for p in parts:
        if "c=" in p:
            return p.split("=")[1].strip()
    return None

def log_result(log_entry):
    """写入 CSV 和 JSON 日志"""
    # CSV
    file_exists = os.path.exists(CSV_LOG)
    with open(CSV_LOG, mode="a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=log_entry.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(log_entry)
    # JSON
    if os.path.exists(JSON_LOG):
        with open(JSON_LOG, "r") as f:
            data = json.load(f)
    else:
        data = []
    data.append(log_entry)
    with open(JSON_LOG, "w") as f:
        json.dump(data, f, indent=2)

def get_proof_from_server(sub):
    url = f"http://127.0.0.1:5000/get_proof/{sub}"
    r = requests.get(url)

    if r.status_code != 200:
        return None

    data = r.json()
    if data["status"] != "ok":
        return None

    return data["proof"]

def parse_proof(proof):
    return [(int(x.split(":")[0]), x.split(":")[1]) for x in proof]
    
def main():
    subs = ["www", "api", "mail", "internal","newsub","fake"]  # 可按需更新
    timestamp = datetime.now().isoformat()

    # 1️⃣ 获取 root
    try:
       rrset = verify_txt_with_dnssec("_auth.example.com", "example.com")
       if rrset is None:
          raise ValueError("❌ DNSSEC 验证失败")
       txt = [r.to_text() for r in rrset]
       root = extract_root(txt)
       if not root:
           raise ValueError("⚠️ TXT 中无法解析 root")
    except Exception as e:
        print(f"❌ 查询 _auth TXT 失败: {e}")
        # 记录日志并退出
        log_result({
            "timestamp": timestamp,
            "subdomain": "ALL",
            "status": "auth_query_failed",
            "root": None,
            "error": str(e)
        })
        return

    print("Root:", root, "\n")
    
    e = None
    
    # 2️⃣ 循环验证各子域
    for sub in subs:
        try:
            proof = get_proof_from_server(sub)
            if proof is None:
                print(f"❌ {sub} proof 缺失")
                status = "missing_proof"
            else:
                parsed_proof = parse_proof(proof)
                valid = verify_proof(sub, parsed_proof, root)
                if valid:
                    print(f"✅ {sub} 验证成功（合法子域）")
                    status = "valid"
                else:
                    print(f"❌ {sub} 验证失败（拦截攻击）")
                    status = "invalid"
        except Exception as e:
            print(f"❌ {sub} 验证异常: {e}")
            status = "verification_error"

        # 写入日志
        log_entry = {
            "timestamp": timestamp,
            "subdomain": sub,
            "status": status,
            "root": root,
            "error": str(e) if 'e' in locals() else None
        }
        log_result(log_entry)

if __name__ == "__main__":
    main()
