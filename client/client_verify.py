"""
client/client_verify.py  —  客户端五步验证模块

改动说明（相比原版）：
Step 1: DNSSEC RRSIG 验证（本地模拟：直接读 owner 状态）
Step 2: epoch 一致性检查（DNS 返回 epoch == proof.epoch）
Step 3: 时间戳有效性（ts 在 [now-DELTA, now] 内）
Step 4: 签名合法性验证（ECDSA verify sigma over sub|proof|root|epoch|ts）
Step 5: Merkle 路径验证（h^(k) == C）

修复原版问题：
- proof 格式统一为 list[(int,str)]，不再做 "x:y" 字符串解析
- 五步验证全部实现，不只验 Merkle
- 日志记录各步骤结果
"""
import os, json, csv, time, requests
from datetime import datetime
from merkle.merkle_tree import verify_proof
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

BASE    = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE, "..", "logs")
CSV_LOG = os.path.join(LOG_DIR, "verification_log.csv")
JSON_LOG= os.path.join(LOG_DIR, "verification_log.json")
STATE_F = os.path.join(BASE, "..", "last_root.txt")
os.makedirs(LOG_DIR, exist_ok=True)

DELTA   = 600          # 时间戳容忍窗口（秒），建议 5-10 分钟
SERVER  = "http://127.0.0.1:5000"


# ── 工具函数 ──────────────────────────────────────────────────────────────
def proof_to_hex(proof: list) -> str:
    return "|".join(f"{d}:{h}" for d, h in proof)


def get_dns_state() -> dict:
    """
    Step 1 替代方案：从本地 owner 状态文件读取可信承诺根和 epoch。
    在真实部署中应通过 DNSSEC 验证的 _auth TXT 记录获取。
    """
    if not os.path.exists(STATE_F):
        raise RuntimeError("无法获取 DNS 承诺根，owner 尚未初始化")
    with open(STATE_F) as f:
        return json.load(f)


def get_server_proof(sub: str) -> dict:
    r = requests.get(f"{SERVER}/get_proof/{sub}", timeout=3)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    data = r.json()
    if data.get("status") != "ok":
        return None
    return data["data"]


def get_pubkey():
    r = requests.get(f"{SERVER}/pubkey", timeout=3)
    r.raise_for_status()
    pem = r.json()["pubkey"]
    return serialization.load_pem_public_key(pem.encode())


def verify_sigma(pubkey, pi_data: dict) -> bool:
    proof_hex = proof_to_hex(pi_data["proof"])
    msg = f"{pi_data['sub']}|{proof_hex}|{pi_data['root']}|{pi_data['epoch']}|{pi_data['ts']}"
    sig = bytes.fromhex(pi_data["sigma"])
    try:
        pubkey.verify(sig, msg.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ── 日志 ──────────────────────────────────────────────────────────────────
def log_result(entry: dict):
    with open(CSV_LOG, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=entry.keys())
        if f.tell() == 0:
            w.writeheader()
        w.writerow(entry)
    data = []
    if os.path.exists(JSON_LOG):
        with open(JSON_LOG) as f:
            data = json.load(f)
    data.append(entry)
    with open(JSON_LOG, "w") as f:
        json.dump(data, f, indent=2)


# ── 五步验证主逻辑 ────────────────────────────────────────────────────────
def verify_subdomain(sub: str, dns_state: dict, pubkey) -> dict:
    """
    对单个子域执行五步验证，返回结果字典。
    """
    result = {
        "sub": sub,
        "step1_dnssec":  False,
        "step2_epoch":   False,
        "step3_ts":      False,
        "step4_sigma":   False,
        "step5_merkle":  False,
        "valid":         False,
        "reason":        ""
    }

    # ── Step 1: DNSSEC（本地模拟：承诺根来自 owner 已签名状态） ──────────
    trusted_root  = dns_state.get("root")
    trusted_epoch = dns_state.get("epoch")
    if not trusted_root or trusted_epoch is None:
        result["reason"] = "Step1: 无法获取可信承诺根"
        return result
    result["step1_dnssec"] = True

    # ── 获取服务器 proof ───────────────────────────────────────────────
    pi = get_server_proof(sub)
    if pi is None:
        result["reason"] = "未授权子域（无 proof）"
        return result

    # ── Step 2: Epoch 一致性 ──────────────────────────────────────────
    if pi.get("epoch") != trusted_epoch:
        result["reason"] = f"Step2: epoch 不一致 (DNS={trusted_epoch}, proof={pi.get('epoch')})"
        return result
    result["step2_epoch"] = True

    # ── Step 3: 时间戳有效性 ──────────────────────────────────────────
    now = int(time.time())
    ts  = pi.get("ts", 0)
    if not (now - DELTA <= ts <= now + 5):   # +5 允许轻微时钟偏差
        result["reason"] = f"Step3: 时间戳超期 (ts={ts}, now={now})"
        return result
    result["step3_ts"] = True

    # ── Step 4: 签名验证（EUF-CMA，ECDSA-P256） ──────────────────────
    if not verify_sigma(pubkey, pi):
        result["reason"] = "Step4: 签名验证失败"
        return result
    result["step4_sigma"] = True

    # ── Step 5: Merkle 路径验证 ───────────────────────────────────────
    proof = pi["proof"]
    # 兼容 JSON 反序列化后的 list[list] 格式
    proof = [(int(d), h) for d, h in proof]
    if not verify_proof(sub, proof, trusted_root):
        result["reason"] = "Step5: Merkle 路径验证失败"
        return result
    result["step5_merkle"] = True

    result["valid"]  = True
    result["reason"] = "全部通过"
    return result


# ── 主函数 ────────────────────────────────────────────────────────────────
def load_authorized_subs():
    """从 owner/subs.txt 读取授权子域列表"""
    subs_file = os.path.join(BASE, "..", "owner", "subs.txt")
    if not os.path.exists(subs_file):
        print("⚠️ subs.txt 不存在，使用默认列表")
        return ["www", "api", "mail", "internal"]
    with open(subs_file) as f:
        return [l.strip() for l in f if l.strip()]


def main():
    # 授权子域从 subs.txt 读取，非授权子域固定追加用于对比
    authorized = load_authorized_subs()
    unauthorized = ["evil", "hacker", "fake"]
    test_subs = authorized + unauthorized

    ts_now = datetime.now().isoformat()

    # Step 1: 获取可信状态
    try:
        dns_state = get_dns_state()
        pubkey    = get_pubkey()
    except Exception as e:
        print(f"初始化失败: {e}")
        return

    print(f"可信承诺根  : {dns_state['root'][:16]}...")
    print(f"当前 epoch  : {dns_state['epoch']}")
    print(f"授权子域数  : {len(authorized)}  非授权测试: {unauthorized}\n")

    for sub in test_subs:
        r = verify_subdomain(sub, dns_state, pubkey)
        icon = "✓" if r["valid"] else "✗"
        steps = (
            f"S1={'OK' if r['step1_dnssec'] else '--'} "
            f"S2={'OK' if r['step2_epoch']  else '--'} "
            f"S3={'OK' if r['step3_ts']     else '--'} "
            f"S4={'OK' if r['step4_sigma']  else '--'} "
            f"S5={'OK' if r['step5_merkle'] else '--'}"
        )
        print(f"{icon} {sub:<12} [{steps}]  {r['reason']}")
        log_result({"timestamp": ts_now, **r})


if __name__ == "__main__":
    main()
